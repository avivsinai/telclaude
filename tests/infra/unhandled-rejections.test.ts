import { describe, expect, it, vi } from "vitest";

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({
		debug: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
	}),
}));

import { categorize } from "../../src/infra/unhandled-rejections.js";

describe("infra/unhandled-rejections categorize", () => {
	it("classifies fatal errors from out-of-memory and assertion patterns", () => {
		expect(categorize(new Error("JavaScript heap out of memory"))).toBe("fatal");
		expect(categorize(new Error("Assertion failed: invariant broken"))).toBe("fatal");
	});

	it("classifies config errors from configuration patterns", () => {
		expect(categorize(new Error("TELCLAUDE_AGENT_URL is not configured"))).toBe("config");
		expect(categorize(new Error("missing required env var: TELEGRAM_BOT_TOKEN"))).toBe("config");
	});

	it("classifies transient network errors", () => {
		expect(categorize({ code: "ECONNRESET", message: "socket hang up" })).toBe("transient");
	});

	it("classifies abort errors", () => {
		expect(categorize({ name: "AbortError", message: "This operation was aborted" })).toBe("abort");
	});

	it("falls back to unknown for unmatched errors", () => {
		expect(categorize(new Error("unexpected runtime failure"))).toBe("unknown");
	});
});
