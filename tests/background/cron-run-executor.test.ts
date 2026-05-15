import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

async function settle(ms = 50): Promise<void> {
	await new Promise((resolve) => setTimeout(resolve, ms));
}

describe("background cron-run executor", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-cron-run-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		vi.resetModules();
		const { resetConfigPath, setConfigPath } = await import("../../src/config/path.js");
		const { resetConfigCache } = await import("../../src/config/config.js");
		resetConfigPath();
		resetConfigCache();
		const configPath = path.join(tempDir, "telclaude.json");
		fs.writeFileSync(configPath, JSON.stringify({ cron: { timeoutSeconds: 5 } }));
		setConfigPath(configPath);
		const { resetDatabase } = await import("../../src/storage/db.js");
		resetDatabase();
	});

	afterEach(async () => {
		const { resetConfigPath } = await import("../../src/config/path.js");
		const { resetConfigCache } = await import("../../src/config/config.js");
		resetConfigCache();
		resetConfigPath();
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("runs the target cron job through the background runner", async () => {
		const { addCronJob, listCronRuns } = await import("../../src/cron/store.js");
		const { createJob, getJob, startBackgroundRunner } = await import(
			"../../src/background/index.js"
		);
		addCronJob({
			id: "curator-webhook",
			name: "curator",
			schedule: { kind: "every", everyMs: 60_000 },
			action: { kind: "curator-scan" },
		});
		const backgroundJob = createJob({
			title: "webhook",
			userId: "webhook:build",
			tier: "WRITE_LOCAL",
			payload: {
				kind: "cron-run",
				jobId: "curator-webhook",
				webhook: {
					slug: "build",
					bodyHash: "a".repeat(64),
				},
			},
		});

		const handle = startBackgroundRunner({ pollIntervalMs: 10, defaultTimeoutMs: 5_000 });
		await handle.tick();
		await settle(100);
		handle.stop();

		const final = getJob(backgroundJob.id);
		expect(final?.status).toBe("completed");
		expect(final?.result?.message).toMatch(/curator scan updated/);

		const runs = listCronRuns("curator-webhook", 1);
		expect(runs).toHaveLength(1);
		expect(runs[0].status).toBe("success");
	});

	it("refuses cron-run targets that were mutated into social actions", async () => {
		const { addCronJob, listCronRuns } = await import("../../src/cron/store.js");
		const { getDb } = await import("../../src/storage/db.js");
		const { createJob, getJob, startBackgroundRunner } = await import(
			"../../src/background/index.js"
		);
		addCronJob({
			id: "curator-webhook",
			name: "curator",
			schedule: { kind: "every", everyMs: 60_000 },
			action: { kind: "curator-scan" },
		});
		const backgroundJob = createJob({
			title: "webhook",
			userId: "webhook:build",
			tier: "WRITE_LOCAL",
			payload: {
				kind: "cron-run",
				jobId: "curator-webhook",
				webhook: {
					slug: "build",
					bodyHash: "a".repeat(64),
				},
			},
		});
		getDb()
			.prepare(
				`UPDATE cron_jobs
				 SET action_kind = 'social-heartbeat',
				     action_service_id = 'xtwitter',
				     action_prompt = NULL
				 WHERE id = 'curator-webhook'`,
			)
			.run();

		const handle = startBackgroundRunner({ pollIntervalMs: 10, defaultTimeoutMs: 5_000 });
		await handle.tick();
		await settle(100);
		handle.stop();

		const final = getJob(backgroundJob.id);
		expect(final?.status).toBe("failed");
		expect(final?.error).toContain("target_cron_job_social_not_allowed");
		expect(listCronRuns("curator-webhook", 1)).toHaveLength(0);
	});
});
