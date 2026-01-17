import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";

import { loadConfig } from "../config/config.js";
import { verifyInternalAuth } from "../internal-auth.js";
import { getChildLogger } from "../logging.js";
import { getMediaInboxDirSync, getMediaOutboxDirSync } from "../media/store.js";
import { validateProviderBaseUrl } from "../providers/provider-validation.js";
import { getSandboxMode } from "../sandbox/index.js";
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
const MAX_ATTACHMENT_SIZE = 20 * 1024 * 1024;
const DEFAULT_ATTACHMENT_TIMEOUT_MS = 15_000;

type CapabilityServerOptions = {
	port?: number;
	host?: string;
};

type ImageRequest = {
	prompt: string;
	size?: "auto" | "1024x1024" | "1536x1024" | "1024x1536";
	quality?: "low" | "medium" | "high";
	userId?: string;
};

type TTSRequest = {
	text: string;
	voice?: "alloy" | "echo" | "fable" | "onyx" | "nova" | "shimmer";
	speed?: number;
	voiceMessage?: boolean;
	userId?: string;
};

type TranscriptionRequest = {
	path: string;
	language?: string;
	model?: string;
	userId?: string;
};

type AttachmentFetchRequest = {
	providerId: string;
	attachmentId: string;
	filename?: string;
	mimeType?: string;
	size?: number;
	inlineBase64?: string;
	userId?: string;
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

function parseUserId(input: unknown): { userId?: string; error?: string } {
	if (input === undefined || input === null) {
		return {};
	}
	if (typeof input !== "string") {
		return { error: "Invalid userId." };
	}
	const trimmed = input.trim();
	if (!trimmed) {
		return {};
	}
	if (trimmed.length > 128) {
		return { error: "userId too long." };
	}
	return { userId: trimmed };
}

const MIME_EXTENSION_MAP: Record<string, string> = {
	"application/pdf": ".pdf",
	"image/png": ".png",
	"image/jpeg": ".jpg",
	"image/jpg": ".jpg",
	"image/webp": ".webp",
};

function sanitizeFilename(input?: string): string {
	if (!input || typeof input !== "string") {
		return "attachment";
	}
	const base = path.basename(input.trim());
	const normalized = base.replace(/[^a-zA-Z0-9._-]+/g, "_").replace(/^_+|_+$/g, "");
	if (!normalized || normalized === "." || normalized === "..") {
		return "attachment";
	}
	return normalized;
}

function buildAttachmentFilename(filename?: string, mimeType?: string): string {
	const safe = sanitizeFilename(filename);
	const extFromName = path.extname(safe);
	const fallbackExt = mimeType ? MIME_EXTENSION_MAP[mimeType] ?? "" : "";
	const ext = extFromName || fallbackExt;
	const stem = (extFromName ? safe.slice(0, -extFromName.length) : safe) || "attachment";
	const suffix = `${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
	const truncatedStem = stem.slice(0, 80);
	return `${truncatedStem}-${suffix}${ext}`;
}

async function ensureDocumentsDir(): Promise<string> {
	const outboxRoot = getMediaOutboxDirSync();
	const documentsDir = path.join(outboxRoot, "documents");
	await fs.promises.mkdir(documentsDir, { recursive: true, mode: 0o700 });
	return documentsDir;
}

async function writeAttachmentBuffer(buffer: Buffer, filepath: string): Promise<void> {
	await fs.promises.writeFile(filepath, buffer, { mode: 0o600 });
}

async function streamAttachmentToFile(response: Response, filepath: string): Promise<number> {
	const contentLength = response.headers.get("content-length");
	if (contentLength) {
		const size = Number.parseInt(contentLength, 10);
		if (Number.isFinite(size) && size > MAX_ATTACHMENT_SIZE) {
			throw new Error("File too large");
		}
	}

	const body = response.body;
	if (!body) {
		throw new Error("Response has no body");
	}

	let totalBytes = 0;
	const sizeChecker = new TransformStream<Uint8Array>({
		transform(chunk, controller) {
			totalBytes += chunk.byteLength;
			if (totalBytes > MAX_ATTACHMENT_SIZE) {
				controller.error(new Error("File too large"));
				return;
			}
			controller.enqueue(chunk);
		},
	});

	const webStream = body.pipeThrough(sizeChecker);
	const nodeStream = Readable.fromWeb(webStream as import("stream/web").ReadableStream);
	const writeStream = fs.createWriteStream(filepath, { mode: 0o600 });

	try {
		await pipeline(nodeStream, writeStream);
	} catch (err) {
		try {
			await fs.promises.unlink(filepath);
		} catch {
			// Ignore cleanup failures
		}
		throw err;
	}

	return totalBytes;
}

export function startCapabilityServer(options: CapabilityServerOptions = {}): http.Server {
	const port = options.port ?? Number(process.env.TELCLAUDE_CAPABILITIES_PORT ?? 8790);
	const host = options.host ?? (getSandboxMode() === "docker" ? "0.0.0.0" : "127.0.0.1");

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
			const parsed = JSON.parse(body) as ImageRequest &
				TTSRequest &
				TranscriptionRequest &
				AttachmentFetchRequest;
			const userIdResult = parseUserId(parsed.userId);
			if (userIdResult.error) {
				writeJson(res, 400, { error: userIdResult.error });
				return;
			}
			const userId = userIdResult.userId;
			const rateLimitUserId = userId ?? "agent";

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
				const limitResult = rateLimiter.checkLimit("image_generation", rateLimitUserId, rateConfig);
				if (!limitResult.allowed) {
					writeJson(res, 429, { error: limitResult.reason ?? "Rate limited." });
					return;
				}

				const policy = resolveImagePolicy(parsed);
				const result = await generateImage(parsed.prompt, {
					userId,
					skipRateLimit: true,
					size: policy.size,
					quality: policy.quality,
				});

				rateLimiter.consume("image_generation", rateLimitUserId);

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
				const limitResult = rateLimiter.checkLimit("tts", rateLimitUserId, rateConfig);
				if (!limitResult.allowed) {
					writeJson(res, 429, { error: limitResult.reason ?? "Rate limited." });
					return;
				}

				const policy = resolveTtsPolicy(parsed);
				const result = await textToSpeech(parsed.text, {
					userId,
					skipRateLimit: true,
					voice: policy.voice,
					speed: policy.speed,
					voiceMessage: policy.voiceMessage,
				});

				rateLimiter.consume("tts", rateLimitUserId);

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
					rateLimitUserId,
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

				rateLimiter.consume("transcription", rateLimitUserId);

				writeJson(res, 200, {
					text: result.text,
					language: result.language,
					durationSeconds: result.durationSeconds,
				});
				return;
			}

			if (req.url === "/v1/attachment/fetch") {
				const typed = parsed as AttachmentFetchRequest;
				const providerId = typeof typed.providerId === "string" ? typed.providerId.trim() : "";
				if (!providerId) {
					writeJson(res, 400, { status: "error", error: "Provider not found" });
					return;
				}

				const attachmentId =
					typeof typed.attachmentId === "string" ? typed.attachmentId.trim() : "";
				if (!attachmentId) {
					writeJson(res, 400, { status: "error", error: "Missing attachment id" });
					return;
				}

				const size = typed.size;
				if (size !== undefined) {
					if (typeof size !== "number" || !Number.isFinite(size) || size < 0) {
						writeJson(res, 400, { status: "error", error: "Invalid size" });
						return;
					}
					if (size > MAX_ATTACHMENT_SIZE) {
						writeJson(res, 413, { status: "error", error: "File too large" });
						return;
					}
				}

				const config = loadConfig();
				const provider = config.providers?.find((entry) => entry.id === providerId);
				if (!provider) {
					writeJson(res, 404, { status: "error", error: "Provider not found" });
					return;
				}

				const safeFilename = buildAttachmentFilename(typed.filename, typed.mimeType);
				const documentsDir = await ensureDocumentsDir();
				const filepath = path.join(documentsDir, safeFilename);

				if (typed.inlineBase64 !== undefined) {
					if (typeof typed.inlineBase64 !== "string") {
						writeJson(res, 400, { status: "error", error: "Invalid inlineBase64" });
						return;
					}
					const inline = typed.inlineBase64.trim();
					if (!inline) {
						writeJson(res, 400, { status: "error", error: "Invalid inlineBase64" });
						return;
					}
					if (!/^[A-Za-z0-9+/=]+$/.test(inline)) {
						writeJson(res, 400, { status: "error", error: "Invalid inlineBase64" });
						return;
					}

					const buffer = Buffer.from(inline, "base64");
					if (buffer.length === 0) {
						writeJson(res, 400, { status: "error", error: "Invalid inlineBase64" });
						return;
					}
					if (buffer.length > MAX_ATTACHMENT_SIZE) {
						writeJson(res, 413, { status: "error", error: "File too large" });
						return;
					}

					try {
						await writeAttachmentBuffer(buffer, filepath);
					} catch (err) {
						logger.error({ error: String(err) }, "failed to write inline attachment");
						writeJson(res, 500, { status: "error", error: "Fetch failed" });
						return;
					}

					writeJson(res, 200, { status: "ok", path: filepath });
					return;
				}

				let fetchUrl: URL;
				try {
					const { url: base } = await validateProviderBaseUrl(provider.baseUrl);
					fetchUrl = new URL(`/v1/attachment/${encodeURIComponent(attachmentId)}`, base);
				} catch (err) {
					logger.warn({ providerId, error: String(err) }, "invalid provider URL");
					writeJson(res, 400, { status: "error", error: "Provider not found" });
					return;
				}

				const controller = new AbortController();
				const timeout = setTimeout(() => controller.abort(), DEFAULT_ATTACHMENT_TIMEOUT_MS);
				let response: Response;
				try {
					response = await fetch(fetchUrl.toString(), {
						method: "GET",
						headers: {
							accept: "*/*",
						},
						signal: controller.signal,
					});
				} catch (err) {
					const reason = err instanceof Error ? err.message : String(err);
					logger.warn({ providerId, error: reason }, "attachment fetch failed");
					writeJson(res, 502, { status: "error", error: "Fetch failed" });
					return;
				} finally {
					clearTimeout(timeout);
				}

				if (!response.ok) {
					logger.warn(
						{ providerId, status: response.status, statusText: response.statusText },
						"attachment fetch response not ok",
					);
					writeJson(res, 502, { status: "error", error: "Fetch failed" });
					return;
				}

				try {
					await streamAttachmentToFile(response, filepath);
				} catch (err) {
					const reason = err instanceof Error ? err.message : String(err);
					logger.warn({ providerId, error: reason }, "attachment stream failed");
					if (String(reason).toLowerCase().includes("too large")) {
						writeJson(res, 413, { status: "error", error: "File too large" });
						return;
					}
					writeJson(res, 502, { status: "error", error: "Fetch failed" });
					return;
				}

				writeJson(res, 200, { status: "ok", path: filepath });
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
