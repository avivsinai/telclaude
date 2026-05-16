import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("storage cleanup", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-storage-cleanup-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		vi.resetModules();
		const { resetDatabase } = await import("../../src/storage/db.js");
		resetDatabase();
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("prunes skill invocation telemetry older than one year", async () => {
		const now = Date.now();
		const { cleanupExpired, getDb } = await import("../../src/storage/db.js");
		const { recordSkillInvocation } = await import("../../src/storage/skill-telemetry.js");

		await recordSkillInvocation({
			sessionKey: "old",
			skillName: "stale-helper",
			decision: "allow",
			source: "telegram",
			createdAt: now - 366 * 24 * 60 * 60 * 1000,
		});
		await recordSkillInvocation({
			sessionKey: "fresh",
			skillName: "fresh-helper",
			decision: "allow",
			source: "telegram",
			createdAt: now,
		});

		const result = cleanupExpired();

		expect(result.skillInvocations).toBe(1);
		expect(getDb().prepare("SELECT COUNT(*) AS count FROM skill_invocations").get()).toMatchObject({
			count: 1,
		});
	});
});
