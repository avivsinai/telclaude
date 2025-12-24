import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";

import { getChildLogger } from "../logging.js";

const logger = getChildLogger({ module: "media-store" });

// Store media in workspace so Claude can read it.
// ~/.telclaude is blocked by sandbox, so we use a hidden dir in workspace instead.
// In Docker: /workspace/.telclaude-media
// Native: <cwd>/.telclaude-media
const WORKSPACE = process.env.TELCLAUDE_WORKSPACE ?? process.cwd();
const MEDIA_ROOT = path.join(WORKSPACE, ".telclaude-media");

/** Media categories for organized storage */
export type MediaCategory =
	| "incoming" // Received from Telegram
	| "generated" // AI-generated images
	| "tts" // Text-to-speech audio (sent as audio file)
	| "voice" // Voice messages (OGG/Opus for Telegram voice display)
	| "video-frames"; // Extracted video frames

// Maximum media file size (20MB - Telegram bot API limit)
const MAX_MEDIA_SIZE = 20 * 1024 * 1024;

export type SavedMedia = {
	path: string;
	contentType: string;
};

/**
 * Get the media directory path for a category.
 * Creates the directory if it doesn't exist.
 */
export async function getMediaDir(category?: MediaCategory): Promise<string> {
	const dir = category ? path.join(MEDIA_ROOT, category) : MEDIA_ROOT;
	await fs.promises.mkdir(dir, { recursive: true, mode: 0o700 });
	return dir;
}

/**
 * Get the media root directory path (synchronous, for module initialization).
 */
export function getMediaRootSync(): string {
	return MEDIA_ROOT;
}

/**
 * Save a buffer to a file in the specified category.
 *
 * @param buffer - Data to save
 * @param options - Save options
 * @returns Saved media info with path
 */
export async function saveMediaBuffer(
	buffer: Buffer,
	options?: {
		mimeType?: string;
		category?: MediaCategory;
		/** Custom filename (without extension) */
		filename?: string;
		/** Custom extension (with dot) */
		extension?: string;
	},
): Promise<SavedMedia> {
	const dir = await getMediaDir(options?.category);
	const mimeType = options?.mimeType;

	const ext = options?.extension ?? mimeToExtension(mimeType);
	const hash = crypto.createHash("sha256").update(buffer).digest("hex").slice(0, 16);
	const basename = options?.filename ?? `${Date.now()}-${hash}`;
	const filename = `${basename}${ext}`;
	const filepath = path.join(dir, filename);

	await fs.promises.writeFile(filepath, buffer, { mode: 0o600 });

	logger.debug({ filepath, bytes: buffer.length, category: options?.category }, "media saved");

	return {
		path: filepath,
		contentType: mimeType ?? "application/octet-stream",
	};
}

/**
 * Stream a response body directly to a file.
 * Prevents OOM by not loading entire file into memory.
 *
 * @param response - Fetch response with body to stream
 * @param options - Save options
 * @returns Path to saved file, or throws on error/size exceeded
 */
export async function saveMediaStream(
	response: Response,
	options?: {
		mimeType?: string;
		category?: MediaCategory;
	},
): Promise<SavedMedia> {
	const dir = await getMediaDir(options?.category);
	const mimeType = options?.mimeType;

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
	const filepath = path.join(dir, filename);

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
	const writeStream = fs.createWriteStream(filepath, { mode: 0o600 });

	try {
		await pipeline(nodeStream, writeStream);
		logger.debug({ filepath, bytes: totalBytes, category: options?.category }, "media streamed");
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
 * Create a unique subdirectory within a category.
 * Useful for video frames where multiple files belong together.
 *
 * @param category - Media category
 * @param prefix - Optional prefix for the directory name
 * @returns Path to the created subdirectory
 */
export async function createMediaSubdir(category: MediaCategory, prefix?: string): Promise<string> {
	const parentDir = await getMediaDir(category);
	const hash = crypto.randomBytes(8).toString("hex");
	const dirname = prefix ? `${Date.now()}-${prefix}-${hash}` : `${Date.now()}-${hash}`;
	const subdirPath = path.join(parentDir, dirname);

	await fs.promises.mkdir(subdirPath, { recursive: true, mode: 0o700 });

	return subdirPath;
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
 * Clean up old media files across all categories or a specific one.
 *
 * @param maxAgeMs - Maximum age of files to keep (default: 24 hours)
 * @param category - Optional category to clean (cleans all if not specified)
 * @param recursive - Whether to recurse into subdirectories (defaults to true only when no category)
 * @returns Number of files/directories cleaned
 */
export async function cleanupOldMedia(
	maxAgeMs: number = 24 * 60 * 60 * 1000,
	category?: MediaCategory,
	recursive?: boolean,
): Promise<number> {
	const targetDir = category ? path.join(MEDIA_ROOT, category) : MEDIA_ROOT;

	try {
		const shouldRecurse = recursive ?? !category;
		return await cleanupDirectory(targetDir, maxAgeMs, shouldRecurse);
	} catch {
		return 0;
	}
}

/**
 * Recursively clean up old files and directories.
 */
async function cleanupDirectory(
	dir: string,
	maxAgeMs: number,
	recursive: boolean,
): Promise<number> {
	const now = Date.now();
	let cleaned = 0;

	try {
		const entries = await fs.promises.readdir(dir, { withFileTypes: true });

		for (const entry of entries) {
			const entryPath = path.join(dir, entry.name);

			try {
				const stat = await fs.promises.stat(entryPath);

				if (entry.isDirectory()) {
					if (recursive) {
						// Recursively clean subdirectories
						cleaned += await cleanupDirectory(entryPath, maxAgeMs, true);

						// Remove empty directories older than maxAge
						const remaining = await fs.promises.readdir(entryPath);
						if (remaining.length === 0 && now - stat.mtimeMs > maxAgeMs) {
							await fs.promises.rmdir(entryPath);
							cleaned++;
						}
					}
				} else if (now - stat.mtimeMs > maxAgeMs) {
					await fs.promises.unlink(entryPath);
					cleaned++;
				}
			} catch {
				// Ignore individual entry errors
			}
		}
	} catch {
		// Ignore directory read errors
	}

	return cleaned;
}

/**
 * Remove a specific media file or directory.
 */
export async function removeMedia(mediaPath: string): Promise<void> {
	try {
		const stat = await fs.promises.stat(mediaPath);
		if (stat.isDirectory()) {
			await fs.promises.rm(mediaPath, { recursive: true, force: true });
		} else {
			await fs.promises.unlink(mediaPath);
		}
	} catch {
		// Ignore removal errors
	}
}
