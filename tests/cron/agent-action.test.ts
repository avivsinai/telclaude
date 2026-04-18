import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("scheduled agent cron action", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-cron-agent-"));
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

	it("resolves home delivery and sends the agent output to Telegram", async () => {
		const { setHomeTarget } = await import("../../src/config/sessions.js");
		const { executeScheduledAgentPromptAction } = await import("../../src/cron/agent-action.js");

		setHomeTarget("alice", { chatId: 123, threadId: 9 }, 1_000);

		const executeLocal = vi.fn(async function* () {
			yield { type: "text", content: "Top story is..." } as const;
			yield {
				type: "done",
				result: {
					response: "Top story is...",
					success: true,
					costUsd: 0,
					numTurns: 1,
					durationMs: 1,
				},
			} as const;
		});
		const sendMessage = vi.fn(async () => ({ success: true, messageId: 42 }));

		const result = await executeScheduledAgentPromptAction(
			{
				id: "cron-1",
				name: "weekday hn",
				enabled: true,
				running: false,
				ownerId: "alice",
				deliveryTarget: { kind: "home" },
				schedule: { kind: "cron", expr: "0 9 * * 1-5" },
				action: { kind: "agent-prompt", prompt: "check HN and post here" },
				nextRunAtMs: null,
				lastRunAtMs: null,
				lastStatus: null,
				lastError: null,
				createdAtMs: 0,
				updatedAtMs: 0,
			},
			{
				telegram: { botToken: "token" },
				cron: { timeoutSeconds: 30 },
				security: {},
			} as never,
			new AbortController().signal,
			{
				executeLocal,
				sendMessage,
			},
		);

		expect(result.ok).toBe(true);
		expect(sendMessage).toHaveBeenCalledWith(
			expect.objectContaining({
				token: "token",
				chatId: 123,
				messageThreadId: 9,
				text: "Top story is...",
			}),
		);
	});

	it("fails cleanly when home delivery is requested without a stored home target", async () => {
		const { executeScheduledAgentPromptAction } = await import("../../src/cron/agent-action.js");

		const result = await executeScheduledAgentPromptAction(
			{
				id: "cron-2",
				name: "weekday hn",
				enabled: true,
				running: false,
				ownerId: "alice",
				deliveryTarget: { kind: "home" },
				schedule: { kind: "cron", expr: "0 9 * * 1-5" },
				action: { kind: "agent-prompt", prompt: "check HN and post here" },
				nextRunAtMs: null,
				lastRunAtMs: null,
				lastStatus: null,
				lastError: null,
				createdAtMs: 0,
				updatedAtMs: 0,
			},
			{
				telegram: { botToken: "token" },
				cron: { timeoutSeconds: 30 },
				security: {},
			} as never,
			new AbortController().signal,
		);

		expect(result.ok).toBe(false);
		expect(result.message).toContain("Run /sethome");
	});
});
