import http from "node:http";

import { loadConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { generateImage } from "../services/image-generation.js";
import { getMultimediaRateLimiter } from "../services/multimedia-rate-limit.js";
import { textToSpeech } from "../services/tts.js";

const logger = getChildLogger({ module: "relay-capabilities" });

const DEFAULT_BODY_LIMIT = 262144;
const DEFAULT_PROMPT_LIMIT = 8000;
const DEFAULT_TTS_LIMIT = 4000;
const MAX_INFLIGHT = 4;

type CapabilityServerOptions = {
	port?: number;
	host?: string;
};

type ImageRequest = {
	prompt: string;
	size?: "auto" | "1024x1024" | "1536x1024" | "1024x1536";
	quality?: "low" | "medium" | "high";
};

type TTSRequest = {
	text: string;
	voice?: "alloy" | "echo" | "fable" | "onyx" | "nova" | "shimmer";
	speed?: number;
	voiceMessage?: boolean;
};

function writeJson(res: http.ServerResponse, status: number, payload: unknown): void {
	const body = JSON.stringify(payload);
	res.writeHead(status, {
		"Content-Type": "application/json; charset=utf-8",
		"Content-Length": Buffer.byteLength(body),
	});
	res.end(body);
}

function parseBody(req: http.IncomingMessage, maxBytes: number): Promise<string> {
	return new Promise((resolve, reject) => {
		const chunks: Buffer[] = [];
		let received = 0;

		req.on("data", (chunk: Buffer) => {
			received += chunk.length;
			if (received > maxBytes) {
				reject(new Error("Body too large"));
				req.destroy();
				return;
			}
			chunks.push(chunk);
		});

		req.on("end", () => {
			resolve(Buffer.concat(chunks).toString("utf-8"));
		});

		req.on("error", reject);
	});
}

function resolveImagePolicy(request: ImageRequest) {
	const config = loadConfig();
	const imageConfig = config.imageGeneration;
	const allowedSizes: ImageRequest["size"][] = ["auto", "1024x1024", "1536x1024", "1024x1536"];
	const allowedQualities: ImageRequest["quality"][] = ["low", "medium", "high"];

	const size =
		imageConfig?.size && imageConfig.size !== "auto"
			? imageConfig.size
			: allowedSizes.includes(request.size ?? "auto")
				? (request.size ?? imageConfig?.size ?? "1024x1024")
				: (imageConfig?.size ?? "1024x1024");

	const quality = imageConfig?.quality
		? imageConfig.quality
		: allowedQualities.includes(request.quality ?? "medium")
			? (request.quality ?? "medium")
			: "medium";

	return { size, quality };
}

function resolveTtsPolicy(request: TTSRequest) {
	const config = loadConfig();
	const ttsConfig = config.tts;
	const allowedVoices: TTSRequest["voice"][] = [
		"alloy",
		"echo",
		"fable",
		"onyx",
		"nova",
		"shimmer",
	];

	const voice = ttsConfig?.voice ?? "alloy";
	const speed = ttsConfig?.speed ?? 1.0;
	const voiceMessage = Boolean(request.voiceMessage);

	const requestedVoice = request.voice ?? voice;
	const safeVoice = allowedVoices.includes(requestedVoice) ? requestedVoice : voice;

	return { voice: safeVoice, speed, voiceMessage };
}

export function startCapabilityServer(options: CapabilityServerOptions = {}): http.Server {
	const port = options.port ?? Number(process.env.TELCLAUDE_CAPABILITIES_PORT ?? 8790);
	const host = options.host ?? "0.0.0.0";

	const bodyLimit = Number(process.env.TELCLAUDE_CAP_BODY_LIMIT ?? DEFAULT_BODY_LIMIT);
	const promptLimit = Number(process.env.TELCLAUDE_CAP_PROMPT_LIMIT ?? DEFAULT_PROMPT_LIMIT);
	const ttsLimit = Number(process.env.TELCLAUDE_CAP_TTS_LIMIT ?? DEFAULT_TTS_LIMIT);

	let inFlight = 0;

	const server = http.createServer(async (req, res) => {
		if (!req.url) {
			writeJson(res, 400, { error: "Missing request URL." });
			return;
		}

		if (req.method === "GET" && req.url === "/health") {
			writeJson(res, 200, { ok: true });
			return;
		}

		if (req.method !== "POST") {
			writeJson(res, 405, { error: "Method not allowed." });
			return;
		}

		if (inFlight >= MAX_INFLIGHT) {
			writeJson(res, 429, { error: "Too many in-flight requests." });
			return;
		}

		const contentType = req.headers["content-type"] ?? "";
		if (!contentType.includes("application/json")) {
			writeJson(res, 415, { error: "Content-Type must be application/json." });
			return;
		}

		inFlight += 1;

		try {
			const body = await parseBody(req, bodyLimit);
			const parsed = JSON.parse(body) as ImageRequest & TTSRequest;

			if (req.url === "/v1/image.generate") {
				if (!parsed.prompt || typeof parsed.prompt !== "string") {
					writeJson(res, 400, { error: "Missing prompt." });
					return;
				}
				if (parsed.prompt.length > promptLimit) {
					writeJson(res, 413, { error: "Prompt too long." });
					return;
				}

				const rateLimiter = getMultimediaRateLimiter();
				const config = loadConfig();
				const rateConfig = {
					maxPerHourPerUser: config.imageGeneration?.maxPerHourPerUser ?? 10,
					maxPerDayPerUser: config.imageGeneration?.maxPerDayPerUser ?? 50,
				};
				const limitResult = rateLimiter.checkLimit("image_generation", "agent", rateConfig);
				if (!limitResult.allowed) {
					writeJson(res, 429, { error: limitResult.reason ?? "Rate limited." });
					return;
				}

				const policy = resolveImagePolicy(parsed);
				const result = await generateImage(parsed.prompt, {
					userId: "agent",
					size: policy.size,
					quality: policy.quality,
				});

				writeJson(res, 200, {
					path: result.path,
					bytes: result.sizeBytes,
					model: result.model,
					quality: result.quality,
				});
				return;
			}

			if (req.url === "/v1/tts.speak") {
				if (!parsed.text || typeof parsed.text !== "string") {
					writeJson(res, 400, { error: "Missing text." });
					return;
				}
				if (parsed.text.length > ttsLimit) {
					writeJson(res, 413, { error: "Text too long." });
					return;
				}

				const rateLimiter = getMultimediaRateLimiter();
				const config = loadConfig();
				const rateConfig = {
					maxPerHourPerUser: config.tts?.maxPerHourPerUser ?? 30,
					maxPerDayPerUser: config.tts?.maxPerDayPerUser ?? 100,
				};
				const limitResult = rateLimiter.checkLimit("tts", "agent", rateConfig);
				if (!limitResult.allowed) {
					writeJson(res, 429, { error: limitResult.reason ?? "Rate limited." });
					return;
				}

				const policy = resolveTtsPolicy(parsed);
				const result = await textToSpeech(parsed.text, {
					userId: "agent",
					voice: policy.voice,
					speed: policy.speed,
					voiceMessage: policy.voiceMessage,
				});

				writeJson(res, 200, {
					path: result.path,
					bytes: result.sizeBytes,
					format: result.format,
					voice: result.voice,
					speed: result.speed,
				});
				return;
			}

			writeJson(res, 404, { error: "Not found." });
		} catch (err) {
			logger.error({ error: String(err) }, "capability request failed");
			if (String(err).includes("Body too large")) {
				writeJson(res, 413, { error: "Request body too large." });
			} else {
				writeJson(res, 500, { error: "Capability request failed." });
			}
		} finally {
			inFlight = Math.max(0, inFlight - 1);
		}
	});

	server.listen(port, host, () => {
		logger.info({ host, port }, "capability server listening");
	});

	return server;
}
