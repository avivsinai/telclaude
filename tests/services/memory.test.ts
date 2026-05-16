import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;
const ORIGINAL_TELCLAUDE_CONFIG = process.env.TELCLAUDE_CONFIG;

describe("memory service", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-memory-service-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		const configPath = path.join(tempDir, "telclaude.json");
		fs.writeFileSync(
			configPath,
			JSON.stringify({ profiles: [{ id: "engineer", label: "Engineer" }] }),
		);
		process.env.TELCLAUDE_CONFIG = configPath;
		vi.resetModules();
		const { resetConfigCache } = await import("../../src/config/config.js");
		const { resetDatabase } = await import("../../src/storage/db.js");
		resetConfigCache();
		resetDatabase();
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
		if (ORIGINAL_TELCLAUDE_CONFIG === undefined) {
			delete process.env.TELCLAUDE_CONFIG;
		} else {
			process.env.TELCLAUDE_CONFIG = ORIGINAL_TELCLAUDE_CONFIG;
		}
	});

	it("scopes local memory reads to the chat active profile", async () => {
		const { setChatActiveProfileId } = await import("../../src/config/sessions.js");
		const { createEntries } = await import("../../src/memory/store.js");
		const { readMemory, resolveLocalTelegramMemoryProfileId } = await import(
			"../../src/services/memory.js"
		);
		setChatActiveProfileId(123, "engineer");
		createEntries(
			[{ id: "default-fact", category: "profile", content: "Default fact", chatId: "123" }],
			"telegram:default",
			100,
		);
		createEntries(
			[{ id: "engineer-fact", category: "profile", content: "Engineer fact", chatId: "123" }],
			"telegram:engineer",
			101,
		);

		const result = await readMemory({ chatId: "123", categories: ["profile"] });

		expect(resolveLocalTelegramMemoryProfileId("123")).toBe("engineer");
		expect(result.entries.map((entry) => entry.id)).toEqual(["engineer-fact"]);
		expect(result.entries[0]?._provenance.source).toBe("telegram:engineer");
	});
});
