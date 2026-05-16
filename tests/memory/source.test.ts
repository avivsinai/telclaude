import { describe, expect, it } from "vitest";

import {
	isTelegramMemorySource,
	telegramMemorySource,
	validateMemorySource,
} from "../../src/memory/source.js";

describe("memory source validation", () => {
	it("accepts social and telegram profile sources", () => {
		expect(validateMemorySource("social")).toBeNull();
		expect(validateMemorySource("telegram:default")).toBeNull();
		expect(validateMemorySource("telegram:engineer")).toBeNull();
	});

	it("rejects legacy bare telegram for new writes", () => {
		expect(validateMemorySource("telegram")).toMatch(/telegram:<profile-id>/i);
	});

	it("rejects invalid telegram profile ids", () => {
		expect(validateMemorySource("telegram:")).toMatch(/profile id/i);
		expect(validateMemorySource("telegram:UPPERCASE")).toMatch(/profile id/i);
		expect(validateMemorySource("telegram:with_underscore")).toMatch(/profile id/i);
	});

	it("builds telegram memory source strings from profile ids", () => {
		expect(telegramMemorySource()).toBe("telegram:default");
		expect(telegramMemorySource("engineer")).toBe("telegram:engineer");
		expect(() => telegramMemorySource("UPPERCASE")).toThrow(/invalid/i);
	});

	it("recognizes legacy and namespaced telegram sources for read-side family checks", () => {
		expect(isTelegramMemorySource("telegram")).toBe(true);
		expect(isTelegramMemorySource("telegram:default")).toBe(true);
		expect(isTelegramMemorySource("telegram:engineer")).toBe(true);
		expect(isTelegramMemorySource("social")).toBe(false);
	});
});
