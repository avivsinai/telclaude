import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("curator collectors", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-curator-collect-"));
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

	it("flags agent-prompt cron jobs without storing raw prompt text", async () => {
		const { addCronJob } = await import("../../src/cron/store.js");
		const { runCuratorScan } = await import("../../src/curator/actions.js");
		const { listCuratorItems } = await import("../../src/curator/store.js");
		const now = Date.parse("2026-02-21T10:00:00.000Z");
		const secretPrompt = "Summarize using token ghp_abcdefghijklmnopqrstuvwxyz1234567890";

		addCronJob(
			{
				id: "cron-risky",
				name: "risky digest ghp_abcdefghijklmnopqrstuvwxyz1234567890",
				schedule: { kind: "every", everyMs: 60_000 },
				action: { kind: "agent-prompt", prompt: secretPrompt },
			},
			now,
		);

		const result = runCuratorScan();
		const items = listCuratorItems({ status: "open" });
		const serialized = JSON.stringify(items);

		expect(result.createdOrUpdated).toBe(1);
		expect(items).toHaveLength(1);
		expect(items[0].kind).toBe("cron_hardening");
		expect(items[0].evidence).toMatchObject({
			jobId: "cron-risky",
			hasAllowedSkills: false,
			hasPreprocess: false,
		});
		expect(serialized).not.toContain(secretPrompt);
		expect(serialized).not.toContain("ghp_abcdefghijklmnopqrstuvwxyz1234567890");
	});

	it("does not flag scheduled prompts that already have explicit allowed skills", async () => {
		const { addCronJob } = await import("../../src/cron/store.js");
		const { runCuratorScan } = await import("../../src/curator/actions.js");
		const { listCuratorItems } = await import("../../src/curator/store.js");
		const now = Date.parse("2026-02-21T10:00:00.000Z");

		addCronJob(
			{
				id: "cron-hardened",
				name: "safe digest",
				schedule: { kind: "every", everyMs: 60_000 },
				action: {
					kind: "agent-prompt",
					prompt: "summarize local status",
					allowedSkills: ["summarize"],
				},
			},
			now,
		);

		const result = runCuratorScan();
		expect(result.createdOrUpdated).toBe(0);
		expect(listCuratorItems({ status: "open" })).toHaveLength(0);
	});
});
