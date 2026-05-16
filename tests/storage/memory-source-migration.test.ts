import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("memory source migration", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-memory-source-migration-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		vi.resetModules();
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("moves legacy bare telegram rows to telegram:default at schema init", async () => {
		const { closeDb, getDb, resetDatabase } = await import("../../src/storage/db.js");
		resetDatabase();
		const db = getDb();
		db.prepare(
			`INSERT INTO memory_entries
			 (id, category, content, source, trust, created_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
		).run("entry-legacy", "profile", "legacy entry", "telegram", "trusted", 10);
		db.prepare(
			`INSERT INTO memory_episodes
			 (id, source, scope_key, user_text, assistant_text, summary, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		).run(
			"episode-legacy",
			"telegram",
			"tg:1",
			"legacy user",
			"legacy assistant",
			"legacy summary",
			20,
		);

		closeDb();
		const migrated = getDb();
		expect(
			migrated.prepare("SELECT source FROM memory_entries WHERE id = ?").get("entry-legacy"),
		).toEqual({ source: "telegram:default" });
		expect(
			migrated.prepare("SELECT source FROM memory_episodes WHERE id = ?").get("episode-legacy"),
		).toEqual({ source: "telegram:default" });

		closeDb();
		const reopened = getDb();
		expect(
			reopened
				.prepare("SELECT COUNT(*) AS count FROM memory_entries WHERE source = 'telegram'")
				.get(),
		).toEqual({ count: 0 });
		expect(
			reopened
				.prepare("SELECT COUNT(*) AS count FROM memory_episodes WHERE source = 'telegram'")
				.get(),
		).toEqual({ count: 0 });
	});
});
