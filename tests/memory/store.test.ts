import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let createEntries: typeof import("../../src/memory/store.js").createEntries;
let getEntries: typeof import("../../src/memory/store.js").getEntries;
let promoteEntryTrust: typeof import("../../src/memory/store.js").promoteEntryTrust;
let resetDatabase: typeof import("../../src/storage/db.js").resetDatabase;

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("memory store", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-mem-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;

		vi.resetModules();
		({ resetDatabase } = await import("../../src/storage/db.js"));
		resetDatabase();
		({ createEntries, getEntries, promoteEntryTrust } = await import("../../src/memory/store.js"));
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("assigns trust based on source", () => {
		createEntries(
			[
				{ id: "entry-telegram", category: "profile", content: "from telegram" },
			],
			"telegram",
			1,
		);
		createEntries(
			[{ id: "entry-moltbook", category: "profile", content: "from moltbook" }],
			"moltbook",
			2,
		);

		const entries = getEntries({ order: "asc" });
		const telegramEntry = entries.find((entry) => entry.id === "entry-telegram");
		const moltbookEntry = entries.find((entry) => entry.id === "entry-moltbook");

		expect(telegramEntry?._provenance.trust).toBe("trusted");
		expect(moltbookEntry?._provenance.trust).toBe("untrusted");
	});

	it("filters entries by category/source/trust", () => {
		createEntries(
			[
				{ id: "profile-1", category: "profile", content: "trusted" },
				{ id: "threads-1", category: "threads", content: "trusted" },
			],
			"telegram",
			10,
		);
		createEntries(
			[{ id: "profile-2", category: "profile", content: "untrusted" }],
			"moltbook",
			11,
		);

		const profiles = getEntries({ categories: ["profile"], order: "asc" });
		expect(profiles).toHaveLength(2);

		const untrusted = getEntries({ trust: ["untrusted"], order: "asc" });
		expect(untrusted).toHaveLength(1);
		expect(untrusted[0].id).toBe("profile-2");

		const telegramOnly = getEntries({ sources: ["telegram"], order: "asc" });
		expect(telegramOnly).toHaveLength(2);
	});

	it("promotes untrusted entries to trusted", () => {
		createEntries(
			[{ id: "entry-1", category: "meta", content: "needs review" }],
			"moltbook",
			20,
		);

		expect(promoteEntryTrust("entry-1", "admin")).toBe(true);
		const updated = getEntries({ order: "asc" })[0];
		expect(updated._provenance.trust).toBe("trusted");
		expect(updated._provenance.promotedBy).toBe("admin");
		expect(updated._provenance.promotedAt).toBeTypeOf("number");
	});

	it("rejects duplicate entry ids", () => {
		createEntries(
			[{ id: "dup-1", category: "profile", content: "first" }],
			"telegram",
			30,
		);

		expect(() =>
			createEntries(
				[{ id: "dup-1", category: "profile", content: "second" }],
				"telegram",
				31,
			),
		).toThrow(/already exists/i);
	});
});
