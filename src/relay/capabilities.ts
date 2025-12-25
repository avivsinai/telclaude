import fs from "node:fs";
import http from "node:http";
import path from "node:path";

import { loadConfig } from "../config/config.js";
import { verifyInternalAuth } from "../internal-auth.js";
import { getChildLogger } from "../logging.js";
import { getMediaInboxDirSync, getMediaOutboxDirSync } from "../media/store.js";
import { generateImage } from "../services/image-generation.js";
import { getMultimediaRateLimiter } from "../services/multimedia-rate-limit.js";
import { transcribeAudio } from "../services/transcription.js";
import { textToSpeech } from "../services/tts.js";

const logger = getChildLogger({ module: "relay-capabilities" });

const DEFAULT_BODY_LIMIT = 262144;
const DEFAULT_PROMPT_LIMIT = 8000;
const DEFAULT_TTS_LIMIT = 4000;
const DEFAULT_PATH_LIMIT = 4096;
const MAX_INFLIGHT = 4;
const DEFAULT_TRANSCRIPTION_LIMITS = { maxPerHourPerUser: 20, maxPerDayPerUser: 50 };

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

type TranscriptionRequest = {
	path: string;
	language?: string;
	model?: string;
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
	const defaultSpeed = ttsConfig?.speed ?? 1.0;
	const voiceMessage = Boolean(request.voiceMessage);

	const requestedVoice = request.voice ?? voice;
	const safeVoice = allowedVoices.includes(requestedVoice) ? requestedVoice : voice;
	const requestedSpeed = typeof request.speed === "number" ? request.speed : undefined;
	const safeSpeed = Number.isFinite(requestedSpeed)
		? Math.min(4.0, Math.max(0.25, requestedSpeed as number))
		: defaultSpeed;

	return { voice: safeVoice, speed: safeSpeed, voiceMessage };
}

function resolveMediaPath(inputPath: string): string | null {
	const absolutePath = path.isAbsolute(inputPath)
		? inputPath
		: path.resolve(process.cwd(), inputPath);

	let realPath: string;
	try {
		const stat = fs.lstatSync(absolutePath);
		if (stat.isSymbolicLink()) {
			return null;
		}
		realPath = fs.realpathSync(absolutePath);
	} catch {
		return null;
	}

	const roots = [getMediaInboxDirSync(), getMediaOutboxDirSync()].map((root) => {
		try {
			return fs.realpathSync(root);
		} catch {
			return path.resolve(root);
		}
	});

	if (!roots.some((root) => realPath === root || realPath.startsWith(root + path.sep))) {
		return null;
	}

	try {
		const stat = fs.lstatSync(realPath);
		if (!stat.isFile()) {
			return null;
		}
	} catch {
		return null;
	}

	return realPath;
}

export function startCapabilityServer(options: CapabilityServerOptions = {}): http.Server {
	const port = options.port ?? Number(process.env.TELCLAUDE_CAPABILITIES_PORT ?? 8790);
	const host = options.host ?? "0.0.0.0";

	const bodyLimit = Number(process.env.TELCLAUDE_CAP_BODY_LIMIT ?? DEFAULT_BODY_LIMIT);
	const promptLimit = Number(process.env.TELCLAUDE_CAP_PROMPT_LIMIT ?? DEFAULT_PROMPT_LIMIT);
	const ttsLimit = Number(process.env.TELCLAUDE_CAP_TTS_LIMIT ?? DEFAULT_TTS_LIMIT);
	const pathLimit = Number(process.env.TELCLAUDE_CAP_PATH_LIMIT ?? DEFAULT_PATH_LIMIT);

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
			const authResult = verifyInternalAuth(req, body);
			if (!authResult.ok) {
				logger.warn(
					{ reason: authResult.reason, url: req.url },
					"capability request failed internal auth",
				);
				writeJson(res, authResult.status, { error: authResult.error });
				return;
			}
			const parsed = JSON.parse(body) as ImageRequest & TTSRequest & TranscriptionRequest;

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

			if (req.url === "/v1/transcribe") {
				const typed = parsed as TranscriptionRequest;
				if (!typed.path || typeof typed.path !== "string") {
					writeJson(res, 400, { error: "Missing path." });
					return;
				}
				if (typed.path.length > pathLimit) {
					writeJson(res, 413, { error: "Path too long." });
					return;
				}

				const resolvedPath = resolveMediaPath(typed.path);
				if (!resolvedPath) {
					writeJson(res, 400, { error: "Invalid media path." });
					return;
				}

				const rateLimiter = getMultimediaRateLimiter();
				const limitResult = rateLimiter.checkLimit(
					"transcription",
					"agent",
					DEFAULT_TRANSCRIPTION_LIMITS,
				);
				if (!limitResult.allowed) {
					writeJson(res, 429, { error: limitResult.reason ?? "Rate limited." });
					return;
				}

				const result = await transcribeAudio(resolvedPath, {
					useRelay: false,
					language: typed.language,
					model: typed.model,
				});

				rateLimiter.consume("transcription", "agent");

				writeJson(res, 200, {
					text: result.text,
					language: result.language,
					durationSeconds: result.durationSeconds,
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
