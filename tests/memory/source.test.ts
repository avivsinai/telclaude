import { describe, expect, it } from "vitest";

import {
	householdMemorySource,
	isHouseholdMemorySource,
	isTelegramMemorySource,
	memorySourceFamily,
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

	it("builds and validates opaque household binding memory sources", () => {
		expect(householdMemorySource("parent-a")).toBe("household:parent-a");
		expect(isHouseholdMemorySource("household:parent-a")).toBe(true);
		expect(memorySourceFamily("household:parent-a")).toBe("household");
		expect(validateMemorySource("household:parent-a")).toBeNull();
		expect(validateMemorySource("household:123456789")).toMatch(/opaque|binding|household/i);
		expect(() => householdMemorySource("123456789")).toThrow(/opaque|binding|household/i);
		expect(isHouseholdMemorySource("household:UPPERCASE")).toBe(false);
	});
});
