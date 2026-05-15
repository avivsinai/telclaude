import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("curator store", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-curator-"));
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

	it("dedupes open items by fingerprint", async () => {
		const { listCuratorItems, upsertCuratorItem } = await import("../../src/curator/store.js");

		const first = upsertCuratorItem(
			{
				fingerprint: "cron:job-1:v1",
				kind: "cron_hardening",
				severity: "medium",
				source: "cron",
				title: "First title",
				summary: "First summary",
				entityRef: "cron:job-1",
				proposedAction: { type: "manual" },
				evidence: { jobId: "job-1" },
			},
			1_000,
		);
		const second = upsertCuratorItem(
			{
				fingerprint: "cron:job-1:v1",
				kind: "cron_hardening",
				severity: "high",
				source: "cron",
				title: "Second title",
				summary: "Second summary",
				entityRef: "cron:job-1",
				proposedAction: { type: "manual" },
				evidence: { jobId: "job-1", changed: true },
			},
			2_000,
		);

		expect(second.id).toBe(first.id);
		expect(second.shortId).toBe(first.shortId);
		expect(second.title).toBe("Second title");
		expect(second.severity).toBe("high");
		expect(listCuratorItems({ status: "open" })).toHaveLength(1);
	});

	it("accepts and rejects open items only", async () => {
		const { decideCuratorItem, upsertCuratorItem } = await import("../../src/curator/store.js");
		const item = upsertCuratorItem({
			fingerprint: "cron:job-2:v1",
			kind: "cron_hardening",
			severity: "medium",
			source: "cron",
			title: "Cron hardening",
			summary: "Needs explicit skills",
			entityRef: "cron:job-2",
			proposedAction: { type: "manual" },
			evidence: { jobId: "job-2" },
		});

		const accepted = decideCuratorItem({
			id: item.shortId,
			status: "accepted",
			actor: "cli:test",
			nowMs: 3_000,
		});
		expect(accepted?.status).toBe("accepted");
		expect(accepted?.decidedBy).toBe("cli:test");

		const rejected = decideCuratorItem({
			id: item.shortId,
			status: "rejected",
			actor: "cli:test",
			nowMs: 4_000,
		});
		expect(rejected?.status).toBe("accepted");
	});

	it("redacts secrets inside stored JSON evidence", async () => {
		const { upsertCuratorItem } = await import("../../src/curator/store.js");

		const item = upsertCuratorItem({
			fingerprint: "cron:job-3:v1",
			kind: "cron_hardening",
			severity: "high",
			source: "cron",
			title: "Cron hardening",
			summary: "Needs review",
			entityRef: "cron:job-3",
			proposedAction: {
				type: "manual",
				command: "fix ghp_abcdefghijklmnopqrstuvwxyz1234567890",
			},
			evidence: {
				jobId: "job-3",
				nested: { value: "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890" },
			},
		});
		const serialized = JSON.stringify(item);

		expect(serialized).toContain("[REDACTED:github_pat]");
		expect(serialized).toContain("[REDACTED:openai_api_key]");
		expect(serialized).not.toContain("ghp_abcdefghijklmnopqrstuvwxyz1234567890");
		expect(serialized).not.toContain("sk-proj-abcdefghijklmnopqrstuvwxyz1234567890");
	});
});
