import { describe, expect, it } from "vitest";

import { normalizeInboundBody } from "../../src/telegram/inbound.js";

describe("normalizeInboundBody", () => {
	it("folds homoglyphs and strips zero-width characters", () => {
		const input = "Ｈｅｌｌｏ\u200B Ｗｏｒｌｄ";
		const result = normalizeInboundBody(input);

		expect(result.normalized).toBe("Hello World");
		expect(result.changed).toBe(true);
		expect(result.hadHomoglyphs).toBe(true);
		expect(result.hadZeroWidth).toBe(true);
	});

	it("preserves raw command body while providing normalized variant", () => {
		const raw = "/approve\u200B 123456";
		const result = normalizeInboundBody(raw);

		// Raw command parsing still sees the original string.
		expect(raw.startsWith("/approve ")).toBe(false);
		// Normalized body restores canonical command spacing.
		expect(result.normalized.startsWith("/approve ")).toBe(true);
	});

	it("returns unchanged for already clean input", () => {
		const input = "normal message";
		const result = normalizeInboundBody(input);

		expect(result.normalized).toBe(input);
		expect(result.changed).toBe(false);
		expect(result.hadHomoglyphs).toBe(false);
		expect(result.hadZeroWidth).toBe(false);
	});
});
