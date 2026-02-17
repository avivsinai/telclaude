import { describe, expect, it } from "vitest";
import {
	containsHomoglyphs,
	detectHomoglyphs,
	foldHomoglyphs,
} from "../../src/security/homoglyphs.js";

describe("homoglyphs", () => {
	it("containsHomoglyphs is stable across repeated calls", () => {
		const text = `hello\uFF01 world`;

		expect(containsHomoglyphs(text)).toBe(true);
		expect(containsHomoglyphs(text)).toBe(true);
		expect(containsHomoglyphs(text)).toBe(true);
	});

	it("foldHomoglyphs normalizes fullwidth and strips zero-width chars", () => {
		const text = `safe\u200B text \uFF3Bpayload\uFF3D`;
		const folded = foldHomoglyphs(text);

		expect(folded).toBe("safe text [payload]");
	});

	it("detectHomoglyphs returns unique matches", () => {
		const text = `\uFF41\uFF41\uFF42`;
		const detected = detectHomoglyphs(text);

		expect(detected.map((d) => d.original)).toEqual(["\uFF41", "\uFF42"]);
		expect(detected.map((d) => d.replacement)).toEqual(["a", "b"]);
	});
});
