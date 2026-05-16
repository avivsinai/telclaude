import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { listJobs } from "../../src/background/index.js";
import { resetDatabase } from "../../src/storage/db.js";

// Hoisted mutable stubs
const replies: string[] = [];
const sessionStore: Array<{ key: string; entry: unknown }> = [];

const executePooledQueryImpl = vi.hoisted(() => vi.fn());
const getChatModelPreferenceImpl = vi.hoisted(() => vi.fn(() => null));
const activeProfileState = vi.hoisted(() => ({ profileId: null as string | null }));
const loggerImpl = vi.hoisted(() => ({
	info: vi.fn(),
	warn: vi.fn(),
	error: vi.fn(),
	debug: vi.fn(),
}));

vi.mock("../../src/sdk/client.js", () => ({
	executePooledQuery: (...args: unknown[]) => executePooledQueryImpl(...args),
}));

vi.mock("../../src/config/sessions.js", () => ({
	deriveSessionKey: () => "session-1",
	getSession: () => null,
	setSession: (key: string, entry: unknown) => sessionStore.push({ key, entry }),
	deleteSession: vi.fn(),
	getChatActiveProfileId: () => activeProfileState.profileId,
	setChatActiveProfileId: (_chatId: number, profileId: string) => {
		activeProfileState.profileId = profileId;
	},
	clearChatActiveProfileId: () => {
		const hadProfile = activeProfileState.profileId !== null;
		activeProfileState.profileId = null;
		return hadProfile;
	},
	DEFAULT_IDLE_MINUTES: 60,
}));

vi.mock("../../src/config/model-preferences.js", () => ({
	getChatModelPreference: (...args: Parameters<typeof getChatModelPreferenceImpl>) =>
		getChatModelPreferenceImpl(...args),
	clearChatModelPreference: vi.fn(() => true),
}));

const redactors = vi.hoisted(
	() =>
		[] as Array<{
			processChunk: ReturnType<typeof vi.fn>;
			flush: ReturnType<typeof vi.fn>;
			getStats: ReturnType<typeof vi.fn>;
		}>,
);

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

vi.mock("../../src/memory/telegram-memory.js", () => ({
	buildTelegramMemoryBundle: () => ({
		stableEntries: [],
		recentEpisodes: [],
		relevantEpisodes: [],
		promptContext: null,
		compiledMemoryMd: "# Compiled Memory\n",
	}),
	buildTelegramMemoryPolicyPrompt: () => "<memory-policy />",
}));

vi.mock("../../src/memory/telegram-capture.js", () => ({
	captureTelegramTurnMemory: vi.fn(),
}));

vi.mock("../../src/telegram/system-context.js", () => ({
	buildSystemInfoContext: () => null,
}));

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => loggerImpl,
}));

import { __test as autoReplyTest } from "../../src/telegram/auto-reply.js";
import { registerAllCardRenderers } from "../../src/telegram/cards/renderers/index.js";
import { matchTelegramControlCommand } from "../../src/telegram/control-commands.js";

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
		getChatModelPreferenceImpl.mockReset();
		getChatModelPreferenceImpl.mockReturnValue(null);
		activeProfileState.profileId = null;
		loggerImpl.info.mockReset();
		loggerImpl.warn.mockReset();
		loggerImpl.error.mockReset();
		loggerImpl.debug.mockReset();
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

	it("passes the chat's Anthropic model preference into session execution", async () => {
		getChatModelPreferenceImpl.mockReturnValue({
			chatId: 123,
			providerId: "anthropic",
			modelId: "claude-sonnet-4-5-20250929",
		});
		executePooledQueryImpl.mockReturnValueOnce(
			(async function* () {
				yield {
					type: "done",
					result: {
						response: "ok",
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

		expect(executePooledQueryImpl).toHaveBeenCalledWith(
			"please respond",
			expect.objectContaining({ model: "claude-sonnet-4-5-20250929" }),
		);
	});

	it("ignores catalog-only model preferences during session execution", async () => {
		getChatModelPreferenceImpl.mockReturnValue({
			chatId: 123,
			providerId: "openai",
			modelId: "gpt-5",
		});
		executePooledQueryImpl.mockReturnValueOnce(
			(async function* () {
				yield {
					type: "done",
					result: {
						response: "ok",
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

		expect(executePooledQueryImpl).toHaveBeenCalledWith(
			"please respond",
			expect.objectContaining({ model: undefined }),
		);
	});

	it("applies active profile model, skill allowlist, and soul overlay", async () => {
		activeProfileState.profileId = "engineer";
		executePooledQueryImpl.mockReturnValueOnce(
			(async function* () {
				yield {
					type: "done",
					result: {
						response: "ok",
						success: true,
						error: undefined,
						costUsd: 0.2,
						numTurns: 1,
						durationMs: 3,
					},
				};
			})(),
		);

		const ctx = {
			...baseCtx(),
			config: {
				...baseCtx().config,
				profiles: [
					{
						id: "engineer",
						label: "Engineer",
						soulPath: "docs/soul.md",
						allowedSkills: ["integration-test"],
						defaultModel: {
							providerId: "anthropic",
							modelId: "claude-haiku-4-5-20251001",
						},
					},
				],
			},
		};
		await autoReplyTest.executeAndReply(ctx as never);

		expect(executePooledQueryImpl).toHaveBeenCalledWith(
			"please respond",
			expect.objectContaining({
				model: "claude-haiku-4-5-20251001",
				allowedSkills: ["integration-test"],
				systemPromptAppend: expect.stringContaining('<profile-soul id="engineer"'),
			}),
		);
	});

	it("switches profiles and logs the transition", async () => {
		const msg = { ...makeMsg(), senderId: 555 };
		await autoReplyTest.handleProfileSwitchCommand(msg as never, "engineer", {
			...baseCtx().config,
			security: { permissions: { users: { "123": { tier: "WRITE_LOCAL" } } } },
			profiles: [{ id: "engineer", label: "Engineer" }],
		} as never);

		expect(activeProfileState.profileId).toBe("engineer");
		expect(replies[0]).toContain("Profile switched to Engineer");
		expect(loggerImpl.info).toHaveBeenCalledWith(
			expect.objectContaining({
				chatId: 123,
				fromProfileId: "default",
				toProfileId: "engineer",
				actor: "555",
			}),
			"profile switched",
		);
	});
});

describe("auto-reply control commands", () => {
	it("rejects /link in group chats", async () => {
		const msg = {
			chatId: 999,
			chatType: "group" as const,
			username: "group-user",
			reply: vi.fn(async () => {}),
		} as Parameters<typeof autoReplyTest.handleLinkCommand>[0];

		const auditLogger = { log: vi.fn(async () => {}) } as Parameters<
			typeof autoReplyTest.handleLinkCommand
		>[2];

		await autoReplyTest.handleLinkCommand(msg, "ABCD-1234", auditLogger);

		expect(msg.reply).toHaveBeenCalledWith(
			"For security, `/link` is only allowed in a private chat. Please DM the bot.",
		);
		expect(auditLogger.log).toHaveBeenCalledWith(
			expect.objectContaining({ errorType: "identity_link_group_rejected" }),
		);
	});

	it("uses raw body for command parsing and normalized body for processing", () => {
		const msg = {
			body: "/approve\u200B 123456",
			normalizedBody: "/approve 123456",
		} as Parameters<typeof autoReplyTest.resolveCommandBody>[0];

		expect(autoReplyTest.resolveCommandBody(msg)).toBe("/approve\u200B 123456");
		expect(autoReplyTest.resolveProcessingBody(msg)).toBe("/approve 123456");
	});

	it("dispatches /codex as a background job without entering the Claude session", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-autoreply-codex-"));
		const previousDataDir = process.env.TELCLAUDE_DATA_DIR;
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		try {
			executePooledQueryImpl.mockReset();
			resetDatabase();
			registerAllCardRenderers();

			const match = matchTelegramControlCommand("/codex inspect the latest diff");
			expect(match?.command.id).toBe("codex");

			const api = { sendMessage: vi.fn(async () => ({ message_id: 1 })) };
			await autoReplyTest.dispatchTelegramControlCommand(
				match as never,
				{
					bot: { api },
					msg: { ...makeMsg(), body: "/codex inspect the latest diff", senderId: 555 },
					cfg: {
						security: { permissions: { users: { "123": { tier: "WRITE_LOCAL" } } } },
					},
					auditLogger: { log: vi.fn(async () => {}) },
					recentlySent: new Set<string>(),
					requestId: "req-codex",
				} as never,
			);

			expect(executePooledQueryImpl).not.toHaveBeenCalled();
			const [job] = listJobs();
			expect(job?.payload).toMatchObject({
				kind: "codex-work-unit",
				prompt: "inspect the latest diff",
				sandbox: "read-only",
			});
		} finally {
			fs.rmSync(tempDir, { recursive: true, force: true });
			if (previousDataDir === undefined) {
				delete process.env.TELCLAUDE_DATA_DIR;
			} else {
				process.env.TELCLAUDE_DATA_DIR = previousDataDir;
			}
		}
	});
});
