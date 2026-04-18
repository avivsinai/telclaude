import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("completion notification routing", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-bg-notif-"));
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

	it("sends a BackgroundJobCard to the originating chat when an Api is provided", async () => {
		const { createJob, emitCompletionNotification } = await import(
			"../../src/background/index.js"
		);
		const { getActiveCardsByEntity } = await import("../../src/telegram/cards/store.js");
		const { registerAllCardRenderers } = await import(
			"../../src/telegram/cards/renderers/index.js"
		);
		registerAllCardRenderers();

		const job = createJob({
			title: "finish me",
			userId: "u",
			chatId: 42,
			tier: "WRITE_LOCAL",
			payload: { kind: "noop", message: "ok" },
		});
		// Flip the job into a terminal-style record — notifier reads from the job, not the DB.
		const terminalJob = {
			...job,
			status: "completed" as const,
			result: { message: "done", stdout: "some output", exitCode: 0 },
			startedAtMs: Date.now() - 1_000,
			completedAtMs: Date.now(),
		};

		const fakeApi = {
			sendMessage: vi.fn(async () => ({ message_id: 100 })),
			editMessageText: vi.fn(async () => true),
		};

		await emitCompletionNotification(terminalJob, {
			// biome-ignore lint/suspicious/noExplicitAny: test fake
			api: fakeApi as any,
		});

		expect(fakeApi.sendMessage).toHaveBeenCalledTimes(1);
		const [chatId, text, options] = fakeApi.sendMessage.mock.calls[0] as [
			number,
			string,
			Record<string, unknown>,
		];
		expect(chatId).toBe(42);
		expect(text).toContain("finish me");
		expect(text).toContain(terminalJob.shortId);
		expect(options.parse_mode).toBe("MarkdownV2");

		const cards = getActiveCardsByEntity({
			kind: (await import("../../src/telegram/cards/types.js")).CardKind.BackgroundJob,
			chatId: 42,
			entityRef: `bg:${terminalJob.shortId}`,
		});
		expect(cards).toHaveLength(1);
	});

	it("silently drops when neither chat nor admin fallback is available and no bot token is set", async () => {
		// Loaded config has no bot token; getAdminChatIds returns empty in an empty DB.
		const { createJob, emitCompletionNotification } = await import(
			"../../src/background/index.js"
		);

		const job = createJob({
			title: "orphan",
			userId: "u",
			chatId: null,
			tier: "WRITE_LOCAL",
			payload: { kind: "noop" },
		});

		// This should NOT throw — the notifier is best-effort.
		await expect(emitCompletionNotification(job, {})).resolves.toBeUndefined();
	});

	it("surfaces failures via the card path too (error shows)", async () => {
		const { createJob, emitCompletionNotification } = await import(
			"../../src/background/index.js"
		);
		const { registerAllCardRenderers } = await import(
			"../../src/telegram/cards/renderers/index.js"
		);
		registerAllCardRenderers();

		const job = createJob({
			title: "oops",
			userId: "u",
			chatId: 99,
			tier: "WRITE_LOCAL",
			payload: { kind: "noop", fail: true },
		});

		const fakeApi = {
			sendMessage: vi.fn(async () => ({ message_id: 7 })),
			editMessageText: vi.fn(async () => true),
		};

		await emitCompletionNotification(
			{
				...job,
				status: "failed",
				error: "bad things happened",
				completedAtMs: Date.now(),
			},
			// biome-ignore lint/suspicious/noExplicitAny: test fake
			{ api: fakeApi as any },
		);

		const [, text] = fakeApi.sendMessage.mock.calls[0] as [number, string, unknown];
		expect(text).toContain("bad things happened");
	});
});
