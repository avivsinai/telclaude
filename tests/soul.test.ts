import { beforeEach, describe, expect, it, vi } from "vitest";

const readFileSyncImpl = vi.hoisted(() => vi.fn());

vi.mock("node:fs", () => ({
	default: { readFileSync: readFileSyncImpl },
	readFileSync: readFileSyncImpl,
}));

describe("loadSoul", () => {
	beforeEach(() => {
		readFileSyncImpl.mockReset();
		// Reset module cache so the internal `cached` variable is fresh
		vi.resetModules();
	});

	it("reads from /app/docs/soul.md first (Docker path)", async () => {
		readFileSyncImpl.mockImplementation((p: string) => {
			if (p.startsWith("/app/")) return "  docker soul content  ";
			throw new Error("ENOENT");
		});

		const { loadSoul } = await import("../src/soul.js");
		const result = loadSoul();
		expect(result).toBe("docker soul content");
		expect(readFileSyncImpl).toHaveBeenCalledWith("/app/docs/soul.md", "utf-8");
	});

	it("falls back to cwd when /app path fails", async () => {
		readFileSyncImpl.mockImplementation((p: string) => {
			if (p.startsWith("/app/")) throw new Error("ENOENT");
			return "native soul content";
		});

		const { loadSoul } = await import("../src/soul.js");
		const result = loadSoul();
		expect(result).toBe("native soul content");
		// Should have tried /app first, then cwd
		expect(readFileSyncImpl).toHaveBeenCalledTimes(2);
	});

	it("trims whitespace from loaded content", async () => {
		readFileSyncImpl.mockImplementation((p: string) => {
			if (p.startsWith("/app/")) return "\n  soul with whitespace  \n\n";
			throw new Error("ENOENT");
		});

		const { loadSoul } = await import("../src/soul.js");
		expect(loadSoul()).toBe("soul with whitespace");
	});

	it("returns empty string when no file is found", async () => {
		readFileSyncImpl.mockImplementation(() => {
			throw new Error("ENOENT");
		});

		const { loadSoul } = await import("../src/soul.js");
		expect(loadSoul()).toBe("");
	});

	it("caches result after first read", async () => {
		readFileSyncImpl.mockImplementation((p: string) => {
			if (p.startsWith("/app/")) return "cached content";
			throw new Error("ENOENT");
		});

		const { loadSoul } = await import("../src/soul.js");
		loadSoul();
		loadSoul();
		// readFileSync should only be called once (first load) — second call uses cache
		expect(readFileSyncImpl).toHaveBeenCalledTimes(1);
	});
});
