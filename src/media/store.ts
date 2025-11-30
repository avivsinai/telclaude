import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const MEDIA_DIR = path.join(os.tmpdir(), "telclaude", "media");

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
