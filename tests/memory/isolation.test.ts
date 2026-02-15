import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let createEntries: typeof import("../../src/memory/store.js").createEntries;
let getEntries: typeof import("../../src/memory/store.js").getEntries;
let resetDatabase: typeof import("../../src/storage/db.js").resetDatabase;
let buildTelegramMemoryContext: typeof import("../../src/memory/telegram-context.js").buildTelegramMemoryContext;

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("memory isolation", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-iso-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;

		vi.resetModules();
		({ resetDatabase } = await import("../../src/storage/db.js"));
		resetDatabase();
		({ createEntries, getEntries } = await import("../../src/memory/store.js"));
		({ buildTelegramMemoryContext } = await import("../../src/memory/telegram-context.js"));
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("social query never includes telegram entries", () => {
		createEntries(
			[{ id: "tg-1", category: "profile", content: "telegram private data" }],
			"telegram",
		);
		createEntries(
			[{ id: "social-1", category: "profile", content: "social public data" }],
			"social",
		);

		// Query as social agent would (source: "social")
		const socialEntries = getEntries({
			sources: ["social"],
			trust: ["trusted", "untrusted"],
		});

		const ids = socialEntries.map((e) => e.id);
		expect(ids).toContain("social-1");
		expect(ids).not.toContain("tg-1");
	});

	it("telegram context never includes social entries", () => {
		createEntries(
			[{ id: "tg-2", category: "profile", content: "telegram data" }],
			"telegram",
		);
		createEntries(
			[{ id: "social-2", category: "profile", content: "social data" }],
			"social",
		);

		const context = buildTelegramMemoryContext();
		expect(context).not.toBeNull();
		expect(context).toContain("telegram data");
		expect(context).not.toContain("social data");
	});

	it("telegram context returns only telegram-sourced entries", () => {
		createEntries(
			[{ id: "tg-3", category: "interests", content: "likes coding" }],
			"telegram",
		);
		createEntries(
			[
				{ id: "soc-3a", category: "interests", content: "social interest A" },
				{ id: "soc-3b", category: "interests", content: "social interest B" },
			],
			"social",
		);

		const telegramEntries = getEntries({
			sources: ["telegram"],
			trust: ["trusted"],
			categories: ["profile", "interests", "meta"],
		});

		// All entries should be telegram-sourced
		for (const entry of telegramEntries) {
			expect(entry._provenance.source).toBe("telegram");
		}
		expect(telegramEntries).toHaveLength(1);
		expect(telegramEntries[0].id).toBe("tg-3");
	});

	it("social entries are isolated from telegram", () => {
		// Unified social source — all social services write as "social"
		createEntries(
			[
				{ id: "soc-4a", category: "profile", content: "social profile data" },
				{ id: "soc-4b", category: "interests", content: "social interests" },
			],
			"social",
		);
		createEntries(
			[{ id: "tg-4", category: "profile", content: "private telegram data" }],
			"telegram",
		);

		// Social entries should not appear in telegram queries
		const telegramEntries = getEntries({
			sources: ["telegram"],
			trust: ["trusted"],
		});
		const telegramIds = telegramEntries.map((e) => e.id);
		expect(telegramIds).toContain("tg-4");
		expect(telegramIds).not.toContain("soc-4a");
		expect(telegramIds).not.toContain("soc-4b");
	});

	it("quarantine and promote are telegram-only operations", async () => {
		const { createQuarantinedEntry, promoteEntryTrust } = await import(
			"../../src/memory/store.js"
		);

		// Create a quarantined entry from telegram
		const entry = createQuarantinedEntry(
			{ id: "q-1", category: "posts", content: "post idea" },
			"telegram",
			"chat-123",
		);
		expect(entry._provenance.source).toBe("telegram");
		expect(entry._provenance.trust).toBe("quarantined");

		// Promote it
		const result = promoteEntryTrust("q-1", "chat-123");
		expect(result.ok).toBe(true);

		// Verify it's now trusted with telegram source
		const entries = getEntries({
			sources: ["telegram"],
			trust: ["trusted"],
			categories: ["posts"],
		});
		expect(entries.some((e) => e.id === "q-1")).toBe(true);
	});
});
