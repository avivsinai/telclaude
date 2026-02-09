import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Hoisted mutable stubs
const replies: string[] = [];
const sessionStore: any[] = [];

const executePooledQueryImpl = vi.hoisted(() => vi.fn());

vi.mock("../../src/sdk/client.js", () => ({
	executePooledQuery: (...args: unknown[]) => executePooledQueryImpl(...args),
}));

vi.mock("../../src/config/sessions.js", () => ({
	deriveSessionKey: () => "session-1",
	getSession: () => null,
	setSession: (key: string, entry: unknown) => sessionStore.push({ key, entry }),
	deleteSession: vi.fn(),
	DEFAULT_IDLE_MINUTES: 60,
}));

const redactors = vi.hoisted(() => [] as Array<{
	processChunk: ReturnType<typeof vi.fn>;
	flush: ReturnType<typeof vi.fn>;
	getStats: ReturnType<typeof vi.fn>;
}>);

vi.mock("../../src/security/streaming-redactor.js", () => ({
	createStreamingRedactor: () => {
		const inst = {
			processChunk: vi.fn((text: string) => text.replace(/secret/gi, "[REDACTED]")),
			flush: vi.fn(() => ""),
			getStats: vi.fn(() => ({ secretsRedacted: 1, patternsMatched: ["secret"] })),
		};
		redactors.push(inst);
		return inst;
	},
}));

vi.mock("../../src/security/fast-path.js", () => ({
	checkInfrastructureSecrets: () => ({ blocked: false, patterns: [] as string[] }),
}));

vi.mock("../../src/memory/telegram-context.js", () => ({
	buildTelegramMemoryContext: () => null,
}));

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		debug: vi.fn(),
	}),
}));

import { __test as autoReplyTest } from "../../src/telegram/auto-reply.js";

const makeMsg = () => ({
	chatId: 123,
	body: "please respond",
	id: "msg-1",
	sendComposing: vi.fn(),
	reply: vi.fn(async (text: string) => {
		replies.push(text);
	}),
});

const baseCtx = () => ({
	msg: makeMsg(),
	prompt: "please respond",
	mediaPath: undefined,
	mediaFilePath: undefined,
	mediaType: undefined,
	from: "user",
	to: "bot",
	username: "alice",
	tier: "WRITE_LOCAL" as const,
	config: {
		inbound: { reply: { enabled: true, timeoutSeconds: 60 } },
		sdk: { betas: [] },
	},
	observerClassification: "OK",
	observerConfidence: 0.1,
	requestId: "req-1",
	recentlySent: new Set<string>(),
	auditLogger: { log: vi.fn(async () => {}) },
});

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("auto-reply executeAndReply", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-autoreply-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		vi.resetModules();
		// Re-import to get fresh database
		const { resetDatabase } = await import("../../src/storage/db.js");
		resetDatabase();
	});

	afterEach(() => {
		replies.length = 0;
		sessionStore.length = 0;
		redactors.length = 0;
		executePooledQueryImpl.mockReset();
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("streams text through redactor and replies with sanitized output", async () => {
		// Stream a text chunk followed by done
		executePooledQueryImpl.mockReturnValueOnce(
			(async function* () {
				yield { type: "text", content: "secret data" };
				yield {
					type: "done",
					result: {
						response: "",
						success: true,
						error: undefined,
						costUsd: 0.1,
						numTurns: 1,
						durationMs: 5,
					},
				};
			})(),
		);

		const ctx = baseCtx();
		await autoReplyTest.executeAndReply(ctx as never);

		expect(replies).toEqual(["[REDACTED] data"]);
		expect(sessionStore[0].entry.systemSent).toBe(true);
		expect(ctx.auditLogger.log).toHaveBeenCalledWith(
			expect.objectContaining({ outcome: "success", costUsd: 0.1 }),
		);
	});

	it("uses fallback redaction when no streaming chunks are returned", async () => {
		executePooledQueryImpl.mockReturnValueOnce(
			(async function* () {
				yield {
					type: "done",
					result: {
						response: "secret fallback",
						success: true,
						error: undefined,
						costUsd: 0.2,
						numTurns: 1,
						durationMs: 3,
					},
				};
			})(),
		);

		const ctx = baseCtx();
		await autoReplyTest.executeAndReply(ctx as never);

		expect(replies).toEqual(["[REDACTED] fallback"]);
		// Second redactor (fallback) should have processed the response
		expect(redactors[1]?.processChunk).toHaveBeenCalledWith("secret fallback");
	});
});

describe("auto-reply control commands", () => {
	it("rejects /link in group chats", async () => {
		const msg = {
			chatId: 999,
			chatType: "group" as const,
			username: "group-user",
			reply: vi.fn(async () => {}),
		} as any;

		const auditLogger = { log: vi.fn(async () => {}) } as any;

		await autoReplyTest.handleLinkCommand(msg, "ABCD-1234", auditLogger);

		expect(msg.reply).toHaveBeenCalledWith(
			"For security, `/link` is only allowed in a private chat. Please DM the bot.",
		);
		expect(auditLogger.log).toHaveBeenCalledWith(
			expect.objectContaining({ errorType: "identity_link_group_rejected" }),
		);
	});
});
