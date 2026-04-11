import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let buildTelegramMemoryBundle: typeof import("../../src/memory/telegram-memory.js").buildTelegramMemoryBundle;
let createEntries: typeof import("../../src/memory/store.js").createEntries;
let recordEpisode: typeof import("../../src/memory/archive.js").recordEpisode;
let resetDatabase: typeof import("../../src/storage/db.js").resetDatabase;

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("telegram memory bundle", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-memory-bundle-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;

		vi.resetModules();
		({ resetDatabase } = await import("../../src/storage/db.js"));
		resetDatabase();
		({ buildTelegramMemoryBundle } = await import("../../src/memory/telegram-memory.js"));
		({ createEntries } = await import("../../src/memory/store.js"));
		({ recordEpisode } = await import("../../src/memory/archive.js"));
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("combines trusted telegram memory with scoped shared history and excludes social data", () => {
		createEntries(
			[
				{ id: "tg-profile", category: "profile", content: "Aviv is building telclaude", chatId: "1" },
				{ id: "tg-thread", category: "threads", content: "Working on relay-owned memory overhaul", chatId: "1" },
			],
			"telegram",
			100,
		);
		createEntries(
			[{ id: "social-profile", category: "profile", content: "Public social profile" }],
			"social",
			101,
		);
		recordEpisode({
			source: "telegram",
			scopeKey: "tg:1",
			chatId: "1",
			userText: "We need to fix the OAuth vault refresh problem",
			assistantText: "The stale vault secret caused invalid_grant errors.",
			createdAt: Date.now() - 20_000,
		});
		recordEpisode({
			source: "social",
			scopeKey: "social:moltbook",
			userText: "This should stay in public scope",
			assistantText: "Social archive only.",
			createdAt: Date.now() - 10_000,
		});

		const bundle = buildTelegramMemoryBundle({
			chatId: "1",
			query: "oauth invalid_grant vault refresh",
			includeRecentHistory: true,
		});

		expect(bundle.stableEntries.map((entry) => entry.id)).toContain("tg-profile");
		expect(bundle.stableEntries.map((entry) => entry.id)).toContain("tg-thread");
		expect(bundle.stableEntries.map((entry) => entry.id)).not.toContain("social-profile");
		expect(bundle.promptContext).toContain("telegram_memory_bundle");
		expect(bundle.promptContext).toContain("invalid_grant");
		expect(bundle.promptContext).not.toContain("Public social profile");
		expect(bundle.compiledMemoryMd).toContain("relay-owned memory overhaul");
		expect(bundle.compiledMemoryMd).toContain("Recent Shared History");
	});
});
