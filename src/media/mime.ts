/**
 * Binary MIME type detection using magic bytes.
 * Adopted from clawdis approach for robust file type detection.
 */

import fs from "node:fs";

/**
 * Magic byte signatures for common file formats.
 * Format: [offset, bytes, mimeType]
 */
const MAGIC_SIGNATURES: Array<[number, Uint8Array | string, string]> = [
	// Images
	[0, new Uint8Array([0xff, 0xd8, 0xff]), "image/jpeg"],
	[0, new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), "image/png"],
	[0, new Uint8Array([0x47, 0x49, 0x46, 0x38, 0x37, 0x61]), "image/gif"], // GIF87a
	[0, new Uint8Array([0x47, 0x49, 0x46, 0x38, 0x39, 0x61]), "image/gif"], // GIF89a
	[0, "RIFF", "image/webp"], // WebP (check for WEBP at offset 8)

	// Audio
	[0, new Uint8Array([0x4f, 0x67, 0x67, 0x53]), "audio/ogg"], // OggS
	[0, new Uint8Array([0x49, 0x44, 0x33]), "audio/mpeg"], // ID3 (MP3 with tags)
	[0, new Uint8Array([0xff, 0xfb]), "audio/mpeg"], // MP3 frame sync
	[0, new Uint8Array([0xff, 0xfa]), "audio/mpeg"], // MP3 frame sync
	[0, new Uint8Array([0xff, 0xf3]), "audio/mpeg"], // MP3 frame sync
	[0, new Uint8Array([0xff, 0xf2]), "audio/mpeg"], // MP3 frame sync
	[0, new Uint8Array([0x66, 0x4c, 0x61, 0x43]), "audio/flac"], // fLaC
	[0, "FORM", "audio/aiff"], // AIFF
	[0, "RIFF", "audio/wav"], // WAV (check for WAVE at offset 8)

	// Video
	// MP4/M4A/MOV - ftyp box at start
	[4, new Uint8Array([0x66, 0x74, 0x79, 0x70]), "video/mp4"],
	[0, new Uint8Array([0x1a, 0x45, 0xdf, 0xa3]), "video/webm"], // EBML header (WebM/MKV)

	// Documents
	[0, new Uint8Array([0x25, 0x50, 0x44, 0x46]), "application/pdf"], // %PDF
];

/**
 * Detect MIME type from binary file content using magic bytes.
 *
 * @param buffer - First bytes of the file (at least 16 bytes recommended)
 * @returns Detected MIME type or undefined if unknown
 */
export function detectMimeFromBytes(buffer: Buffer | Uint8Array): string | undefined {
	if (buffer.length < 4) return undefined;

	for (const [offset, signature, mimeType] of MAGIC_SIGNATURES) {
		if (
			offset + (typeof signature === "string" ? signature.length : signature.length) >
			buffer.length
		) {
			continue;
		}

		let match = true;
		if (typeof signature === "string") {
			// String comparison
			for (let i = 0; i < signature.length; i++) {
				if (buffer[offset + i] !== signature.charCodeAt(i)) {
					match = false;
					break;
				}
			}
		} else {
			// Byte array comparison
			for (let i = 0; i < signature.length; i++) {
				if (buffer[offset + i] !== signature[i]) {
					match = false;
					break;
				}
			}
		}

		if (match) {
			// Special handling for RIFF containers (WebP, WAV)
			if (mimeType === "image/webp" || mimeType === "audio/wav") {
				if (buffer.length >= 12) {
					const fourCC = String.fromCharCode(buffer[8], buffer[9], buffer[10], buffer[11]);
					if (fourCC === "WEBP") return "image/webp";
					if (fourCC === "WAVE") return "audio/wav";
					if (fourCC === "AVI ") return "video/avi";
				}
				continue; // Not a match, keep searching
			}

			// Special handling for M4A vs MP4
			// IMPORTANT: Only "M4A " (with trailing space) is audio. "mp41", "mp42" are video brands.
			if (mimeType === "video/mp4" && buffer.length >= 12) {
				// Check ftyp brand at offset 8
				const brand = String.fromCharCode(buffer[8], buffer[9], buffer[10], buffer[11]);
				// Audio-only M4A container (note the trailing space in "M4A ")
				if (brand === "M4A ") {
					return "audio/mp4";
				}
				// Video containers (mp41, mp42, isom, iso2, avc1 are all video brands)
				if (
					brand === "isom" ||
					brand === "iso2" ||
					brand === "avc1" ||
					brand === "mp41" ||
					brand === "mp42" ||
					brand === "mp71"
				) {
					return "video/mp4";
				}
				if (brand === "qt  ") {
					return "video/quicktime";
				}
			}

			return mimeType;
		}
	}

	return undefined;
}

/**
 * Detect MIME type from a file path.
 * Reads first 256 bytes for detection.
 *
 * @param filePath - Path to the file
 * @returns Detected MIME type or undefined if unknown
 */
export async function detectMimeFromFile(filePath: string): Promise<string | undefined> {
	const fd = await fs.promises.open(filePath, "r");
	try {
		const buffer = Buffer.alloc(256);
		await fd.read(buffer, 0, 256, 0);
		return detectMimeFromBytes(buffer);
	} finally {
		await fd.close();
	}
}

/**
 * Check if a MIME type represents an image.
 */
export function isImageMime(mime?: string): boolean {
	if (!mime) return false;
	return mime.startsWith("image/");
}

/**
 * Check if a MIME type represents audio.
 */
export function isAudioMime(mime?: string): boolean {
	if (!mime) return false;
	return mime.startsWith("audio/");
}

/**
 * Check if a MIME type represents video.
 */
export function isVideoMime(mime?: string): boolean {
	if (!mime) return false;
	return mime.startsWith("video/");
}

/**
 * Check if a MIME type represents a document that can be read as text.
 */
export function isTextDocumentMime(mime?: string): boolean {
	if (!mime) return false;
	const textTypes = [
		"text/plain",
		"text/markdown",
		"text/csv",
		"text/html",
		"text/css",
		"text/javascript",
		"application/json",
		"application/xml",
		"application/javascript",
	];
	return textTypes.includes(mime) || mime.startsWith("text/");
}

/**
 * Check if data looks binary (non-text).
 * Uses sampling to detect null bytes and high control chars.
 */
export function isBinaryContent(buffer: Buffer): boolean {
	const sampleSize = Math.min(buffer.length, 8192);
	let nullCount = 0;
	let controlCount = 0;

	for (let i = 0; i < sampleSize; i++) {
		const byte = buffer[i];
		if (byte === 0) nullCount++;
		// Control chars except common whitespace (tab, newline, carriage return)
		if (byte < 32 && byte !== 9 && byte !== 10 && byte !== 13) {
			controlCount++;
		}
	}

	// If more than 10% null bytes or 30% control chars, likely binary
	return nullCount / sampleSize > 0.1 || controlCount / sampleSize > 0.3;
}
