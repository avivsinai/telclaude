import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("background job store", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-bg-"));
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

	it("creates a queued job, returns it with a short id, and stores the payload", async () => {
		const { createJob, getJob } = await import("../../src/background/index.js");
		const job = createJob({
			title: "nightly backup",
			description: "run rsync",
			userId: "user-1",
			chatId: 12345,
			threadId: 7,
			tier: "WRITE_LOCAL",
			payload: { kind: "command", command: "echo hi" },
		});

		expect(job.id).toMatch(/^bg-/);
		expect(job.shortId).toMatch(/^[a-f0-9]{8}$/);
		expect(job.status).toBe("queued");
		expect(job.chatId).toBe(12345);
		expect(job.threadId).toBe(7);
		expect(job.tier).toBe("WRITE_LOCAL");
		expect(job.payload.kind).toBe("command");
		expect(job.startedAtMs).toBeNull();

		const fromDb = getJob(job.id);
		expect(fromDb).not.toBeNull();
		expect(fromDb?.shortId).toBe(job.shortId);
	});

	it("rejects invalid payload shapes", async () => {
		const { createJob } = await import("../../src/background/index.js");
		expect(() =>
			createJob({
				title: "bad",
				userId: "user",
				tier: "WRITE_LOCAL",
				// @ts-expect-error intentionally invalid
				payload: { kind: "unknown" },
			}),
		).toThrow();
	});

	it("claims queued jobs atomically and transitions them to running", async () => {
		const { claimQueuedJobs, createJob, getJob } = await import("../../src/background/index.js");
		createJob({
			title: "one",
			userId: "u",
			tier: "WRITE_LOCAL",
			payload: { kind: "noop" },
		});
		createJob({
			title: "two",
			userId: "u",
			tier: "WRITE_LOCAL",
			payload: { kind: "noop" },
		});

		const claimed = claimQueuedJobs(Date.now(), 5);
		expect(claimed).toHaveLength(2);
		for (const j of claimed) {
			expect(j.status).toBe("running");
			expect(j.startedAtMs).not.toBeNull();
			const fresh = getJob(j.id);
			expect(fresh?.status).toBe("running");
		}

		const second = claimQueuedJobs(Date.now(), 5);
		expect(second).toHaveLength(0);
	});

	it("completes a running job and stores the result", async () => {
		const { claimQueuedJobs, completeJob, createJob } = await import(
			"../../src/background/index.js"
		);
		const created = createJob({
			title: "x",
			userId: "u",
			tier: "WRITE_LOCAL",
			payload: { kind: "noop" },
		});
		claimQueuedJobs();

		const { job, transitioned } = completeJob({
			jobId: created.id,
			status: "completed",
			result: { message: "ok", exitCode: 0 },
		});

		expect(transitioned).toBe(true);
		expect(job?.status).toBe("completed");
		expect(job?.result?.message).toBe("ok");
		expect(job?.completedAtMs).not.toBeNull();
	});

	it("cancels a queued job and respects terminal state afterwards", async () => {
		const { cancelJob, completeJob, createJob, getJob } = await import(
			"../../src/background/index.js"
		);
		const created = createJob({
			title: "x",
			userId: "u",
			tier: "WRITE_LOCAL",
			payload: { kind: "noop" },
		});

		const cancel = cancelJob(created.id);
		expect(cancel.transitioned).toBe(true);
		expect(cancel.job?.status).toBe("cancelled");
		expect(cancel.job?.cancelledAtMs).not.toBeNull();

		// Completing after cancel should no-op.
		const after = completeJob({ jobId: created.id, status: "completed" });
		expect(after.transitioned).toBe(false);
		expect(getJob(created.id)?.status).toBe("cancelled");
	});

	it("marks running jobs as interrupted on startup", async () => {
		const { claimQueuedJobs, createJob, getJob, markInterruptedOnStartup } = await import(
			"../../src/background/index.js"
		);

		const created = createJob({
			title: "x",
			userId: "u",
			tier: "WRITE_LOCAL",
			payload: { kind: "noop" },
		});
		claimQueuedJobs();
		expect(getJob(created.id)?.status).toBe("running");

		const interrupted = markInterruptedOnStartup();
		expect(interrupted).toHaveLength(1);
		expect(interrupted[0].id).toBe(created.id);
		expect(interrupted[0].status).toBe("interrupted");
		expect(getJob(created.id)?.error).toContain("restart");
	});

	it("lists jobs with since / status / chat filters", async () => {
		const { createJob, listJobs, completeJob, claimQueuedJobs } = await import(
			"../../src/background/index.js"
		);
		const t0 = Date.now();
		const a = createJob({
			title: "a",
			userId: "u",
			chatId: 1,
			tier: "WRITE_LOCAL",
			payload: { kind: "noop" },
		});
		const b = createJob({
			title: "b",
			userId: "u",
			chatId: 2,
			tier: "WRITE_LOCAL",
			payload: { kind: "noop" },
		});
		claimQueuedJobs();
		completeJob({ jobId: a.id, status: "completed", result: { message: "ok" } });

		expect(listJobs({ limit: 10 })).toHaveLength(2);
		expect(listJobs({ statuses: ["completed"] })).toHaveLength(1);
		expect(listJobs({ chatId: 2 })).toHaveLength(1);
		expect(listJobs({ sinceMs: t0 - 1 })).toHaveLength(2);
		expect(listJobs({ sinceMs: Date.now() + 10_000 })).toHaveLength(0);

		// Ensure list is deterministic with chat filter.
		expect(listJobs({ chatId: 2 })[0].shortId).toBe(b.shortId);
	});

	it("prunes terminal jobs older than cutoff", async () => {
		const { createJob, pruneOldJobs, listJobs, cancelJob } = await import(
			"../../src/background/index.js"
		);
		const j = createJob({
			title: "x",
			userId: "u",
			tier: "WRITE_LOCAL",
			payload: { kind: "noop" },
		});
		cancelJob(j.id);
		expect(listJobs({})).toHaveLength(1);

		// Cutoff in the far future prunes everything terminal.
		const pruned = pruneOldJobs(Date.now() + 1_000);
		expect(pruned).toBe(1);
		expect(listJobs({})).toHaveLength(0);
	});

	it("tracks active job count for /system integration", async () => {
		const { claimQueuedJobs, completeJob, createJob, getActiveJobCount } = await import(
			"../../src/background/index.js"
		);

		expect(getActiveJobCount()).toBe(0);

		const a = createJob({
			title: "a",
			userId: "u",
			tier: "WRITE_LOCAL",
			payload: { kind: "noop" },
		});
		expect(getActiveJobCount()).toBe(1); // queued

		claimQueuedJobs();
		expect(getActiveJobCount()).toBe(1); // running

		completeJob({ jobId: a.id, status: "completed", result: { message: "ok" } });
		expect(getActiveJobCount()).toBe(0); // terminal
	});
});
