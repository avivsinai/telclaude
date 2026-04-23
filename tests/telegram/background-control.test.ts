import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let claimQueuedJobs: typeof import("../../src/background/index.js").claimQueuedJobs;
let createJob: typeof import("../../src/background/index.js").createJob;
let getJob: typeof import("../../src/background/index.js").getJob;
let resetDatabase: typeof import("../../src/storage/db.js").resetDatabase;
let stopActiveWorkCommand: typeof import("../../src/telegram/control-command-actions.js").stopActiveWorkCommand;

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("telegram background control", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-bg-control-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;

		vi.resetModules();
		({ resetDatabase } = await import("../../src/storage/db.js"));
		resetDatabase();
		({ claimQueuedJobs, createJob, getJob } = await import("../../src/background/index.js"));
		({ stopActiveWorkCommand } = await import("../../src/telegram/control-command-actions.js"));
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("cancels active background jobs scoped to the current chat topic", async () => {
		const queued = createJob({
			title: "queued job",
			userId: "tg:100",
			chatId: 100,
			threadId: 7,
			tier: "WRITE_LOCAL",
			payload: { kind: "noop" },
		});
		const running = createJob({
			title: "running job",
			userId: "tg:100",
			chatId: 100,
			threadId: 7,
			tier: "WRITE_LOCAL",
			payload: { kind: "noop" },
		});
		const otherThread = createJob({
			title: "other topic",
			userId: "tg:100",
			chatId: 100,
			threadId: 8,
			tier: "WRITE_LOCAL",
			payload: { kind: "noop" },
		});
		claimQueuedJobs(Date.now(), 1);

		const sendMessage = vi.fn(async () => ({ message_id: 1 }));
		const result = await stopActiveWorkCommand({ sendMessage } as any, {
			chatId: 100,
			threadId: 7,
		});

		expect(result.callbackText).toBe("Stopped 2 background jobs");
		expect(sendMessage).toHaveBeenCalledWith(
			100,
			expect.stringContaining("Stopped 2 background jobs"),
			{ message_thread_id: 7 },
		);
		expect(sendMessage.mock.calls[0]?.[1]).toContain(queued.shortId);
		expect(sendMessage.mock.calls[0]?.[1]).toContain(running.shortId);
		expect(sendMessage.mock.calls[0]?.[1]).not.toContain(otherThread.shortId);
		expect(getJob(queued.id)?.status).toBe("cancelled");
		expect(getJob(running.id)?.status).toBe("cancelled");
		expect(getJob(otherThread.id)?.status).toBe("queued");
	});

	it("explains the supported stop surface when there is nothing active", async () => {
		const sendMessage = vi.fn(async () => ({ message_id: 1 }));
		const result = await stopActiveWorkCommand({ sendMessage } as any, {
			chatId: 100,
		});

		expect(result.callbackAlert).toBe(true);
		expect(result.callbackText).toBe("No supported active work");
		expect(sendMessage.mock.calls[0]?.[1]).toContain("queued/running background jobs");
		expect(sendMessage.mock.calls[0]?.[1]).toContain("in-flight agent replies");
	});
});
