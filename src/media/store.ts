import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";

import { getChildLogger } from "../logging.js";

const logger = getChildLogger({ module: "media-store" });
const MEDIA_DIR = path.join(os.tmpdir(), "telclaude", "media");

// Maximum media file size (20MB - Telegram bot API limit)
const MAX_MEDIA_SIZE = 20 * 1024 * 1024;

export type SavedMedia = {
	path: string;
	contentType: string;
};

/**
 * Save a buffer to a temporary file and return its path.
 */
export async function saveMediaBuffer(buffer: Buffer, mimeType?: string): Promise<SavedMedia> {
	await fs.promises.mkdir(MEDIA_DIR, { recursive: true });

	const ext = mimeToExtension(mimeType);
	const hash = crypto.createHash("sha256").update(buffer).digest("hex").slice(0, 16);
	const filename = `${Date.now()}-${hash}${ext}`;
	const filepath = path.join(MEDIA_DIR, filename);

	await fs.promises.writeFile(filepath, buffer);

	return {
		path: filepath,
		contentType: mimeType ?? "application/octet-stream",
	};
}

/**
 * Stream a response body directly to a temporary file.
 * Prevents OOM by not loading entire file into memory.
 *
 * @param response - Fetch response with body to stream
 * @param mimeType - MIME type for the file extension
 * @returns Path to saved file, or throws on error/size exceeded
 */
export async function saveMediaStream(response: Response, mimeType?: string): Promise<SavedMedia> {
	await fs.promises.mkdir(MEDIA_DIR, { recursive: true });

	// Check content-length header for size limit
	const contentLength = response.headers.get("content-length");
	if (contentLength) {
		const size = Number.parseInt(contentLength, 10);
		if (size > MAX_MEDIA_SIZE) {
			throw new Error(`Media too large: ${size} bytes (max ${MAX_MEDIA_SIZE})`);
		}
	}

	const ext = mimeToExtension(mimeType);
	const randomId = crypto.randomBytes(8).toString("hex");
	const filename = `${Date.now()}-${randomId}${ext}`;
	const filepath = path.join(MEDIA_DIR, filename);

	// Get the response body as a web stream
	const body = response.body;
	if (!body) {
		throw new Error("Response has no body");
	}

	// Track size during streaming
	let totalBytes = 0;
	const sizeChecker = new TransformStream<Uint8Array>({
		transform(chunk, controller) {
			totalBytes += chunk.byteLength;
			if (totalBytes > MAX_MEDIA_SIZE) {
				controller.error(new Error(`Media too large: exceeded ${MAX_MEDIA_SIZE} bytes`));
				return;
			}
			controller.enqueue(chunk);
		},
	});

	// Convert web stream to Node stream for fs.createWriteStream
	const webStream = body.pipeThrough(sizeChecker);
	const nodeStream = Readable.fromWeb(webStream as import("stream/web").ReadableStream);
	const writeStream = fs.createWriteStream(filepath);

	try {
		await pipeline(nodeStream, writeStream);
		logger.debug({ filepath, bytes: totalBytes }, "media streamed to file");
	} catch (err) {
		// Clean up partial file on error
		try {
			await fs.promises.unlink(filepath);
		} catch {
			// Ignore cleanup errors
		}
		throw err;
	}

	return {
		path: filepath,
		contentType: mimeType ?? "application/octet-stream",
	};
}

/**
 * Get file extension from MIME type.
 */
function mimeToExtension(mime?: string): string {
	if (!mime) return "";
	const mapping: Record<string, string> = {
		"image/jpeg": ".jpg",
		"image/png": ".png",
		"image/gif": ".gif",
		"image/webp": ".webp",
		"audio/ogg": ".ogg",
		"audio/mpeg": ".mp3",
		"audio/mp4": ".m4a",
		"video/mp4": ".mp4",
		"video/webm": ".webm",
		"application/pdf": ".pdf",
		"text/plain": ".txt",
	};
	return mapping[mime] ?? "";
}

/**
 * Clean up old media files.
 */
export async function cleanupOldMedia(maxAgeMs: number = 24 * 60 * 60 * 1000): Promise<number> {
	try {
		const files = await fs.promises.readdir(MEDIA_DIR);
		const now = Date.now();
		let cleaned = 0;

		for (const file of files) {
			const filepath = path.join(MEDIA_DIR, file);
			try {
				const stat = await fs.promises.stat(filepath);
				if (now - stat.mtimeMs > maxAgeMs) {
					await fs.promises.unlink(filepath);
					cleaned++;
				}
			} catch {
				// Ignore individual file errors
			}
		}

		return cleaned;
	} catch {
		return 0;
	}
}
