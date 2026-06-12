import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { listJobs } from "../../src/background/index.js";
import { getMostRecentPendingPlanApproval } from "../../src/security/approvals.js";
import { resetDatabase } from "../../src/storage/db.js";

// Hoisted mutable stubs
const replies: string[] = [];
const sessionStore: Array<{ key: string; entry: unknown }> = [];

const executeHermesQueryImpl = vi.hoisted(() => vi.fn());
const clearHermesSessionMappingImpl = vi.hoisted(() => vi.fn(() => 0));
const getChatModelPreferenceImpl = vi.hoisted(() => vi.fn(() => null));
const getSessionImpl = vi.hoisted(() => vi.fn(() => null));
const deleteSessionImpl = vi.hoisted(() => vi.fn());
const activeProfileState = vi.hoisted(() => ({ profileId: null as string | null }));
const buildTelegramMemoryBundleImpl = vi.hoisted(() =>
	vi.fn(() => ({
		stableEntries: [],
		recentEpisodes: [],
		relevantEpisodes: [],
		promptContext: null,
		compiledMemoryMd: "# Compiled Memory\n",
	})),
);
const captureTelegramTurnMemoryImpl = vi.hoisted(() => vi.fn());
const loggerImpl = vi.hoisted(() => ({
	info: vi.fn(),
	warn: vi.fn(),
	error: vi.fn(),
	debug: vi.fn(),
}));

vi.mock("../../src/hermes/private-execute.js", () => ({
	executeHermesQuery: (...args: unknown[]) => executeHermesQueryImpl(...args),
}));

vi.mock("../../src/hermes/session-map.js", () => ({
	clearHermesSessionMapping: (...args: unknown[]) => clearHermesSessionMappingImpl(...args),
}));

vi.mock("../../src/config/sessions.js", () => ({
	deriveSessionKey: () => "session-1",
	getSession: (...args: unknown[]) => getSessionImpl(...args),
	setSession: (key: string, entry: unknown) => sessionStore.push({ key, entry }),
	deleteSession: (...args: unknown[]) => deleteSessionImpl(...args),
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
	buildTelegramMemoryBundle: (...args: Parameters<typeof buildTelegramMemoryBundleImpl>) =>
		buildTelegramMemoryBundleImpl(...args),
	buildTelegramMemoryPolicyPrompt: () => "<memory-policy />",
}));

vi.mock("../../src/memory/telegram-capture.js", () => ({
	captureTelegramTurnMemory: (...args: Parameters<typeof captureTelegramTurnMemoryImpl>) =>
		captureTelegramTurnMemoryImpl(...args),
}));

vi.mock("../../src/telegram/system-context.js", () => ({
	buildSystemInfoContext: () => null,
}));

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => loggerImpl,
}));

import { createRelayConversationStore } from "../../src/hermes/relay-conversation-store.js";
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
		buildTelegramMemoryBundleImpl.mockClear();
		captureTelegramTurnMemoryImpl.mockClear();
		activeProfileState.profileId = null;
		// Re-import to get fresh database
		const { resetDatabase } = await import("../../src/storage/db.js");
		resetDatabase();
	});

	afterEach(() => {
		replies.length = 0;
		sessionStore.length = 0;
		redactors.length = 0;
		executeHermesQueryImpl.mockReset();
		clearHermesSessionMappingImpl.mockReset();
		clearHermesSessionMappingImpl.mockReturnValue(0);
		getSessionImpl.mockReset();
		getSessionImpl.mockReturnValue(null);
		deleteSessionImpl.mockReset();
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
		executeHermesQueryImpl.mockReturnValueOnce(
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
		executeHermesQueryImpl.mockReturnValueOnce(
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
		executeHermesQueryImpl.mockReturnValueOnce(
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

		expect(executeHermesQueryImpl).toHaveBeenCalledWith(
			"please respond",
			expect.objectContaining({ model: "claude-sonnet-4-5-20250929" }),
		);
	});

	it("routes Telegram replies through Hermes with tier, identity, and memory", async () => {
		executeHermesQueryImpl.mockReturnValueOnce(
			(async function* () {
				yield {
					type: "done",
					result: {
						response: "hermes ok",
						success: true,
						error: undefined,
						costUsd: 0,
						numTurns: 1,
						durationMs: 3,
					},
				};
			})(),
		);

		const ctx = {
			...baseCtx(),
			msg: { ...makeMsg(), senderId: 456, messageThreadId: 789 },
		};
		await autoReplyTest.executeAndReply(ctx as never);

		expect(executeHermesQueryImpl).toHaveBeenCalledWith(
			"please respond",
			expect.objectContaining({
				cwd: expect.any(String),
				tier: "WRITE_LOCAL",
				poolKey: "session-1",
				telclaudeSessionId: expect.any(String),
				profileId: "default",
				enableSkills: true,
				timeoutMs: 60_000,
				userId: "123",
				chatId: 123,
				actorId: 456,
				threadId: 789,
				compiledMemoryMd: "# Compiled Memory\n",
				systemPromptAppend: expect.stringContaining('<chat-context chat-id="123" />'),
				mcpAuthority: { providerScopes: [] },
			}),
		);
		expect(replies).toEqual(["hermes ok"]);
	});

	it("passes configured provider scopes and MCP-only provider instructions to Hermes", async () => {
		executeHermesQueryImpl.mockReturnValueOnce(
			(async function* () {
				yield {
					type: "done",
					result: {
						response: "hermes ok",
						success: true,
						error: undefined,
						costUsd: 0,
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
				hermes: {
					privateRuntime: {
						providerScopes: ["google", "bank"],
						capabilityScopes: ["web.search", "web.fetch"],
					},
				},
			},
		};
		await autoReplyTest.executeAndReply(ctx as never);

		expect(executeHermesQueryImpl).toHaveBeenCalledWith(
			"please respond",
			expect.objectContaining({
				mcpAuthority: {
					providerScopes: ["bank", "google"],
					capabilityScopes: ["web.fetch", "web.search"],
				},
				systemPromptAppend: expect.stringContaining("tc_provider_read"),
			}),
		);
		const options = executeHermesQueryImpl.mock.calls[0]?.[1] as {
			systemPromptAppend?: string;
		};
		expect(options.systemPromptAppend).toContain("Granted provider scopes: bank, google");
		expect(options.systemPromptAppend).toContain("Granted capability scopes: web.fetch, web.search");
		expect(options.systemPromptAppend).toContain("Do not call provider hostnames");
		expect(options.systemPromptAppend).toContain("supersedes any legacy external-provider");
	});

	it("passes relay-minted Telegram turn refs only through Hermes MCP authority", async () => {
		executeHermesQueryImpl.mockReturnValueOnce(
			(async function* () {
				yield {
					type: "done",
					result: {
						response: "hermes ok",
						success: true,
						error: undefined,
						costUsd: 0,
						numTurns: 1,
						durationMs: 3,
					},
				};
			})(),
		);

		const ctx = {
			...baseCtx(),
			msg: { ...makeMsg(), senderId: 456, messageThreadId: 789 },
			mcpConversationStore: createRelayConversationStore(),
		};
		await autoReplyTest.executeAndReply(ctx as never);

		const [prompt, options] = executeHermesQueryImpl.mock.calls[0] as [
			string,
			{
				mcpAuthority?: { turnConversationRef?: string; providerScopes?: readonly string[] };
				systemPromptAppend?: string;
			},
		];
		const turnConversationRef = options.mcpAuthority?.turnConversationRef;

		expect(turnConversationRef).toBeDefined();
		expect(options.mcpAuthority?.providerScopes).toEqual([]);
		if (!turnConversationRef) throw new Error("expected Hermes MCP turnConversationRef");
		expect(turnConversationRef).toMatch(/^turn_[0-9a-f]{32}$/);
		const turn = ctx.mcpConversationStore.inspectInboundTurn(turnConversationRef);
		expect(turn).not.toBeNull();
		const conversation = turn
			? ctx.mcpConversationStore.resolveAuthorized(turn.conversationToken)
			: null;
		expect(conversation).toMatchObject({
			channel: "social",
			conversationId: "telegram:123",
			threadId: "telegram:123:thread:789",
			profileId: "default",
			mcpDomain: "private",
			humanPairingProvenance: true,
			authorizationScopes: ["message:reply", "telegram:reply"],
		});
		expect(conversation?.members.find((member) => member.actorId === "456")?.scopes).toContain(
			"message:reply",
		);
		expect(prompt).toBe("please respond");
		expect(prompt).not.toContain(turnConversationRef);
		expect(options.systemPromptAppend ?? "").not.toContain(turnConversationRef);
		expect(JSON.stringify(replies)).not.toContain(turnConversationRef);
	});

	it("ignores catalog-only model preferences during session execution", async () => {
		getChatModelPreferenceImpl.mockReturnValue({
			chatId: 123,
			providerId: "openai",
			modelId: "gpt-5",
		});
		executeHermesQueryImpl.mockReturnValueOnce(
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

		expect(executeHermesQueryImpl).toHaveBeenCalledWith(
			"please respond",
			expect.objectContaining({ model: undefined }),
		);
	});

	it("applies active profile model, skill allowlist, and soul overlay", async () => {
		activeProfileState.profileId = "engineer";
		executeHermesQueryImpl.mockReturnValueOnce(
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
						allowedSkills: ["telegram-reply"],
						defaultModel: {
							providerId: "anthropic",
							modelId: "claude-haiku-4-5-20251001",
						},
					},
				],
			},
		};
		await autoReplyTest.executeAndReply(ctx as never);

		expect(executeHermesQueryImpl).toHaveBeenCalledWith(
			"please respond",
			expect.objectContaining({
				model: "claude-haiku-4-5-20251001",
				allowedSkills: ["telegram-reply"],
				systemPromptAppend: expect.stringContaining('<profile-soul id="engineer"'),
			}),
		);
		expect(buildTelegramMemoryBundleImpl).toHaveBeenCalledWith(
			expect.objectContaining({ chatId: "123", profileId: "engineer" }),
		);
		expect(captureTelegramTurnMemoryImpl).toHaveBeenCalledWith(
			expect.objectContaining({ chatId: "123", profileId: "engineer" }),
		);
	});

	it("clears the Hermes session mapping when a Telegram session resets", async () => {
		getSessionImpl.mockReturnValueOnce({
			sessionId: "old-telclaude-session",
			updatedAt: Date.now(),
			systemSent: true,
		});
		executeHermesQueryImpl.mockReturnValueOnce(
			(async function* () {
				yield {
					type: "done",
					result: {
						response: "fresh",
						success: true,
						error: undefined,
						costUsd: 0,
						numTurns: 1,
						durationMs: 3,
					},
				};
			})(),
		);

		const ctx = {
			...baseCtx(),
			msg: { ...makeMsg(), body: "/fresh please" },
			prompt: "/fresh please",
			config: {
				...baseCtx().config,
				inbound: {
					reply: {
						enabled: true,
						timeoutSeconds: 60,
						session: {
							scope: "per-sender",
							idleMinutes: 60,
							resetTriggers: ["/fresh"],
						},
					},
				},
			},
		};

		await autoReplyTest.executeAndReply(ctx as never);

		expect(deleteSessionImpl).toHaveBeenCalledWith("session-1");
		expect(clearHermesSessionMappingImpl).toHaveBeenCalledWith("session-1");
		expect(executeHermesQueryImpl).toHaveBeenCalledWith(
			"/fresh please",
			expect.objectContaining({ resumeSessionId: undefined }),
		);
	});

	it("redacts plan-phase output before Telegram display and approval storage", async () => {
		executeHermesQueryImpl.mockReturnValueOnce(
			(async function* () {
				yield { type: "text", content: "Plan: use secret token" };
				yield {
					type: "done",
					result: {
						response: "",
						success: true,
						error: undefined,
						costUsd: 0,
						numTurns: 1,
						durationMs: 3,
					},
				};
			})(),
		);

		await autoReplyTest.executePlanPhase(
			makeMsg() as never,
			baseCtx().config as never,
			{
				nonce: "approval-1",
				requestId: "req-plan",
				chatId: 123,
				createdAt: Date.now(),
				expiresAt: Date.now() + 60_000,
				tier: "FULL_ACCESS",
				body: "please do the risky thing",
				from: "user",
				to: "bot",
				messageId: "msg-plan",
				observerClassification: "WARN",
				observerConfidence: 0.9,
			} as never,
			{ log: vi.fn(async () => {}) } as never,
		);

		const stored = getMostRecentPendingPlanApproval(123);
		expect(replies[0]).toContain("Plan: use [REDACTED] token");
		expect(replies[0]).not.toContain("secret");
		expect(stored?.planText).toBe("Plan: use [REDACTED] token");
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
			executeHermesQueryImpl.mockReset();
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

			expect(executeHermesQueryImpl).not.toHaveBeenCalled();
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
