export type AttachmentContentSniffResult =
	| { readonly ok: true; readonly mediaType: string }
	| { readonly ok: false; readonly reason: "empty" | "unsupported" };

const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] as const;

/** Identify the small Phase-0 media allowlist from bytes, never caller metadata. */
export function sniffAttachmentContent(bytes: Uint8Array): AttachmentContentSniffResult {
	if (bytes.byteLength === 0) return { ok: false, reason: "empty" };
	if (startsWithAscii(bytes, "%PDF-")) return { ok: true, mediaType: "application/pdf" };
	if (startsWith(bytes, PNG_SIGNATURE)) return { ok: true, mediaType: "image/png" };
	if (startsWith(bytes, [0xff, 0xd8, 0xff])) return { ok: true, mediaType: "image/jpeg" };
	if (startsWithAscii(bytes, "GIF87a") || startsWithAscii(bytes, "GIF89a")) {
		return { ok: true, mediaType: "image/gif" };
	}
	if (isRiff(bytes, "WEBP")) return { ok: true, mediaType: "image/webp" };
	if (startsWithAscii(bytes, "OggS")) return { ok: true, mediaType: "audio/ogg" };
	if (isRiff(bytes, "WAVE")) return { ok: true, mediaType: "audio/wav" };
	if (startsWithAscii(bytes, "ID3") || isMp3Frame(bytes)) {
		return { ok: true, mediaType: "audio/mpeg" };
	}
	if (isIsoBaseMediaAudio(bytes)) return { ok: true, mediaType: "audio/mp4" };
	return { ok: false, reason: "unsupported" };
}

export function normalizeSuppliedMediaType(value: string): string {
	const base = value.split(";", 1)[0]?.trim().toLowerCase() ?? "";
	if (base === "image/jpg") return "image/jpeg";
	if (base === "audio/x-wav" || base === "audio/wave") return "audio/wav";
	if (base === "audio/mp3") return "audio/mpeg";
	if (base === "audio/mp4a-latm" || base === "audio/m4a") return "audio/mp4";
	return base;
}

function startsWith(bytes: Uint8Array, signature: readonly number[]): boolean {
	if (bytes.byteLength < signature.length) return false;
	return signature.every((value, index) => bytes[index] === value);
}

function startsWithAscii(bytes: Uint8Array, signature: string): boolean {
	return startsWith(
		bytes,
		[...signature].map((character) => character.charCodeAt(0)),
	);
}

function isRiff(bytes: Uint8Array, kind: "WEBP" | "WAVE"): boolean {
	return startsWithAscii(bytes, "RIFF") && asciiAt(bytes, 8, kind);
}

function isMp3Frame(bytes: Uint8Array): boolean {
	if (bytes.byteLength < 2) return false;
	return bytes[0] === 0xff && ((bytes[1] ?? 0) & 0xe0) === 0xe0;
}

function isIsoBaseMediaAudio(bytes: Uint8Array): boolean {
	if (!asciiAt(bytes, 4, "ftyp")) return false;
	const brand = ascii(bytes, 8, 4);
	return brand === "M4A " || brand === "M4B ";
}

function asciiAt(bytes: Uint8Array, offset: number, expected: string): boolean {
	return ascii(bytes, offset, expected.length) === expected;
}

function ascii(bytes: Uint8Array, offset: number, length: number): string {
	if (bytes.byteLength < offset + length) return "";
	return String.fromCharCode(...bytes.slice(offset, offset + length));
}
