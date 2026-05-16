import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let captureTelegramTurnMemory: typeof import("../../src/memory/telegram-capture.js").captureTelegramTurnMemory;
let getEpisodes: typeof import("../../src/memory/archive.js").getEpisodes;
let getEntries: typeof import("../../src/memory/store.js").getEntries;
let resetDatabase: typeof import("../../src/storage/db.js").resetDatabase;

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("telegram memory capture", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-memory-capture-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;

		vi.resetModules();
		({ resetDatabase } = await import("../../src/storage/db.js"));
		resetDatabase();
		({ captureTelegramTurnMemory } = await import("../../src/memory/telegram-capture.js"));
		({ getEpisodes } = await import("../../src/memory/archive.js"));
		({ getEntries } = await import("../../src/memory/store.js"));
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("writes captured entries and episodes to the active profile source", () => {
		captureTelegramTurnMemory({
			chatId: "123",
			sessionKey: "session-123",
			sessionId: "sdk-123",
			userText: "Please remember that my preferred editor is Zed.",
			assistantText: "Remembered.",
			profileId: "engineer",
			createdAt: 100,
		});

		const entries = getEntries({ sources: ["telegram:engineer"], order: "asc" });
		const episodes = getEpisodes({ source: "telegram:engineer", scopeKey: "tg:123" });
		expect(entries).toHaveLength(1);
		expect(entries[0]._provenance).toMatchObject({
			source: "telegram:engineer",
			chatId: "123",
		});
		expect(episodes).toHaveLength(1);
		expect(episodes[0]).toMatchObject({
			source: "telegram:engineer",
			chatId: "123",
			sessionKey: "session-123",
			sessionId: "sdk-123",
		});
	});
});
