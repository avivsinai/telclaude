import { describe, expect, it } from "vitest";
import { sniffAttachmentContent } from "../../src/relay/attachment-content-sniffer.js";

describe("attachment content sniffer", () => {
	it.each([
		["PDF", bytes("%PDF-1.7\n"), "application/pdf"],
		["PNG", new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), "image/png"],
		["JPEG", new Uint8Array([0xff, 0xd8, 0xff, 0xe0]), "image/jpeg"],
		["WebP", riff("WEBP"), "image/webp"],
		["Ogg", bytes("OggS\0\0\0\0"), "audio/ogg"],
		["WAV", riff("WAVE"), "audio/wav"],
		["MP3", bytes("ID3\u0004\0\0"), "audio/mpeg"],
	] as const)("detects %s from bytes", (_label, input, expected) => {
		expect(sniffAttachmentContent(input)).toEqual({ ok: true, mediaType: expected });
	});

	it("fails closed for empty and unknown input", () => {
		expect(sniffAttachmentContent(new Uint8Array())).toEqual({
			ok: false,
			reason: "empty",
		});
		expect(sniffAttachmentContent(bytes("plain but untrusted"))).toEqual({
			ok: false,
			reason: "unsupported",
		});
		expect(
			sniffAttachmentContent(new Uint8Array([0, 0, 0, 16, ...bytes("ftypisom"), 0, 0, 0, 0])),
		).toEqual({ ok: false, reason: "unsupported" });
	});
});

function bytes(value: string): Uint8Array {
	return new TextEncoder().encode(value);
}

function riff(kind: "WEBP" | "WAVE"): Uint8Array {
	return new Uint8Array([0x52, 0x49, 0x46, 0x46, 0, 0, 0, 0, ...new TextEncoder().encode(kind)]);
}
