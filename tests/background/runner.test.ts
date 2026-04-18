import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

async function settle(ms = 30): Promise<void> {
	await new Promise((resolve) => setTimeout(resolve, ms));
}

describe("background runner", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-bg-runner-"));
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

	it("spawns + completes a noop job and fires the completion hook once", async () => {
		const { createJob, startBackgroundRunner, getJob } = await import(
			"../../src/background/index.js"
		);
		const completed: string[] = [];

		const job = createJob({
			title: "noop",
			userId: "u",
			tier: "WRITE_LOCAL",
			payload: { kind: "noop", message: "all ok" },
		});

		const handle = startBackgroundRunner({
			pollIntervalMs: 10,
			onCompleted: ({ job }) => {
				completed.push(`${job.shortId}:${job.status}`);
			},
		});

		// Drive a tick explicitly; then wait briefly.
		await handle.tick();
		await settle(50);
		handle.stop();

		const finalJob = getJob(job.id);
		expect(finalJob?.status).toBe("completed");
		expect(finalJob?.result?.message).toBe("all ok");
		expect(completed).toHaveLength(1);
		expect(completed[0]).toBe(`${job.shortId}:completed`);
	});

	it("surfaces failures via the completion card (error preserved)", async () => {
		const { createJob, startBackgroundRunner, getJob } = await import(
			"../../src/background/index.js"
		);
		const failures: string[] = [];

		const job = createJob({
			title: "boom",
			userId: "u",
			tier: "WRITE_LOCAL",
			payload: { kind: "noop", fail: true, message: "intentional failure" },
		});

		const handle = startBackgroundRunner({
			pollIntervalMs: 10,
			onCompleted: ({ job }) => {
				if (job.status === "failed") failures.push(job.error ?? "<no-error>");
			},
		});
		await handle.tick();
		await settle(50);
		handle.stop();

		const final = getJob(job.id);
		expect(final?.status).toBe("failed");
		expect(final?.error).toBe("intentional failure");
		expect(failures).toEqual(["intentional failure"]);
	});

	it("respects operator cancellation after a job is running", async () => {
		const { cancelJob, createJob, startBackgroundRunner, getJob } = await import(
			"../../src/background/index.js"
		);

		const job = createJob({
			title: "slow",
			userId: "u",
			tier: "WRITE_LOCAL",
			payload: { kind: "noop", delayMs: 200, message: "slow ok" },
		});

		const handle = startBackgroundRunner({
			pollIntervalMs: 10,
		});

		// Let the runner claim it.
		await handle.tick();
		await settle(10);

		const { transitioned } = cancelJob(job.id);
		expect(transitioned).toBe(true);

		// Wait for executor to drain; cancellation should win.
		await settle(400);
		handle.stop();

		const final = getJob(job.id);
		expect(final?.status).toBe("cancelled");
	});

	it("enforces tier gating: READ_ONLY cannot be queued via the spawn guard", async () => {
		// The CLI `resolveTier` + `ensureCanSpawn` live in src/commands/background.ts.
		// Exercising through require() keeps the tier check close to its shipping shape.
		const { ensureCanSpawn } = await import("./_helpers/tier.js");
		expect(() => ensureCanSpawn("READ_ONLY")).toThrowError(/READ_ONLY/);
		expect(() => ensureCanSpawn("WRITE_LOCAL")).not.toThrow();
		expect(() => ensureCanSpawn("SOCIAL")).not.toThrow();
		expect(() => ensureCanSpawn("FULL_ACCESS")).not.toThrow();
	});
});

describe("restart recovery", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-bg-restart-"));
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

	it("marks in-flight jobs interrupted and leaves queued jobs pickable for the new runner", async () => {
		const {
			claimQueuedJobs,
			createJob,
			getJob,
			handleStartupInterruptions,
			startBackgroundRunner,
		} = await import("../../src/background/index.js");

		// Simulate a previous relay process that claimed but never completed.
		const stuck = createJob({
			title: "stuck",
			userId: "u",
			tier: "WRITE_LOCAL",
			payload: { kind: "noop" },
		});
		claimQueuedJobs();
		expect(getJob(stuck.id)?.status).toBe("running");

		// And a queued job that survived the crash.
		const pending = createJob({
			title: "pending",
			userId: "u",
			tier: "WRITE_LOCAL",
			payload: { kind: "noop", message: "recovered" },
		});

		// Restart path.
		const interrupted = await handleStartupInterruptions();
		expect(interrupted.map((j) => j.id)).toEqual([stuck.id]);
		expect(getJob(stuck.id)?.status).toBe("interrupted");

		const handle = startBackgroundRunner({ pollIntervalMs: 10 });
		await handle.tick();
		await settle(50);
		handle.stop();

		expect(getJob(pending.id)?.status).toBe("completed");
	});
});
