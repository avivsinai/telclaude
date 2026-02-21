import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("cron store", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-cron-"));
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

	it("adds and lists cron jobs", async () => {
		const { addCronJob, listCronJobs } = await import("../../src/cron/store.js");
		const now = Date.parse("2026-02-21T10:00:00.000Z");

		const job = addCronJob(
			{
				name: "every minute",
				schedule: { kind: "every", everyMs: 60_000 },
				action: { kind: "social-heartbeat", serviceId: "xtwitter" },
			},
			now,
		);

		expect(job.id).toMatch(/^cron-/);
		const jobs = listCronJobs({ includeDisabled: true });
		expect(jobs).toHaveLength(1);
		expect(jobs[0].name).toBe("every minute");
		expect(jobs[0].nextRunAtMs).toBe(now + 60_000);
	});

	it("claims and completes due jobs", async () => {
		const { addCronJob, claimDueCronJobs, completeClaimedCronJob, getCronJob } = await import(
			"../../src/cron/store.js"
		);
		const now = Date.parse("2026-02-21T10:00:00.000Z");

		addCronJob(
			{
				id: "job-1",
				name: "job",
				schedule: { kind: "every", everyMs: 60_000 },
				action: { kind: "private-heartbeat" },
			},
			now,
		);

		const claimed = claimDueCronJobs(now + 60_000, 10);
		expect(claimed).toHaveLength(1);
		expect(claimed[0].id).toBe("job-1");

		completeClaimedCronJob({
			job: claimed[0],
			startedAtMs: now + 60_000,
			finishedAtMs: now + 61_000,
			status: "success",
			message: "ok",
		});

		const updated = getCronJob("job-1");
		expect(updated?.running).toBe(false);
		expect(updated?.lastStatus).toBe("success");
		expect(updated?.nextRunAtMs).toBe(now + 121_000);
	});

	it("computes cron coverage for social and private jobs", async () => {
		const { addCronJob, getCronCoverage } = await import("../../src/cron/store.js");
		const now = Date.parse("2026-02-21T10:00:00.000Z");

		addCronJob(
			{
				name: "all social",
				schedule: { kind: "every", everyMs: 60_000 },
				action: { kind: "social-heartbeat" },
			},
			now,
		);
		addCronJob(
			{
				name: "private",
				schedule: { kind: "every", everyMs: 60_000 },
				action: { kind: "private-heartbeat" },
			},
			now,
		);

		const coverage = getCronCoverage();
		expect(coverage.allSocial).toBe(true);
		expect(coverage.hasPrivateHeartbeat).toBe(true);
	});
});
