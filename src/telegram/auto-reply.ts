import crypto from "node:crypto";
import { run } from "@grammyjs/runner";
import type { Bot } from "grammy";

import type { TemplateContext } from "../auto-reply/templating.js";
import { type PermissionTier, type TelclaudeConfig, loadConfig } from "../config/config.js";
import {
	DEFAULT_IDLE_MINUTES,
	type SessionEntry,
	deleteSession,
	deriveSessionKey,
	getSession,
	setSession,
} from "../config/sessions.js";
import { getChildLogger } from "../logging.js";
import type { RuntimeEnv } from "../runtime.js";
import { executeQueryStream } from "../sdk/client.js";
import {
	type PendingApproval,
	cleanupExpiredApprovals,
	consumeApproval,
	createApproval,
	denyApproval,
	formatApprovalRequest,
	requiresApproval,
} from "../security/approvals.js";
import { type AuditLogger, createAuditLogger } from "../security/audit.js";
import { consumeLinkCode, getIdentityLink } from "../security/linking.js";
import { type SecurityObserver, createObserver } from "../security/observer.js";
import { getUserPermissionTier } from "../security/permissions.js";
import { type RateLimiter, createRateLimiter } from "../security/rate-limit.js";
import type { SecurityClassification } from "../security/types.js";
import { cleanupExpired } from "../storage/db.js";

import { createTelegramBot } from "./client.js";
import { monitorTelegramInbox } from "./inbound.js";
import { computeBackoff, resolveReconnectPolicy, sleepWithAbort } from "./reconnect.js";
import type { TelegramInboundMessage, TelegramMediaType } from "./types.js";

const logger = getChildLogger({ module: "telegram-auto-reply" });

/**
 * Context for executing a message and sending the response.
 */
type ExecutionContext = {
	msg: TelegramInboundMessage;
	prompt: string;
	mediaPath?: string;
	mediaType?: TelegramMediaType;
	from: string;
	to: string;
	username?: string;
	tier: PermissionTier;
	config: TelclaudeConfig;
	observerClassification: SecurityClassification;
	observerConfidence: number;
	requestId: string;
	recentlySent: Set<string>;
	auditLogger: AuditLogger;
};

/**
 * Execute a query via Claude SDK and send the response.
 */
async function executeAndReply(ctx: ExecutionContext): Promise<void> {
	const {
		msg,
		prompt,
		tier,
		config,
		requestId,
		observerClassification,
		observerConfidence,
		recentlySent,
		auditLogger,
	} = ctx;

	const userId = String(msg.chatId);
	const startTime = Date.now();

	const replyConfig = config.inbound?.reply;
	if (!replyConfig?.enabled) {
		logger.debug("reply not enabled, skipping");
		return;
	}

	await msg.sendComposing();

	// Session handling with SQLite
	const sessionConfig = replyConfig.session;
	const scope = sessionConfig?.scope ?? "per-sender";
	const idleMinutes = sessionConfig?.idleMinutes ?? DEFAULT_IDLE_MINUTES;
	const resetTriggers = sessionConfig?.resetTriggers ?? ["/new"];
	const timeoutSeconds = replyConfig.timeoutSeconds ?? 600; // Default 10 minutes

	const sessionKey = deriveSessionKey(scope, { From: ctx.from });
	const existingSession = getSession(sessionKey);
	const now = Date.now();

	// Check for reset triggers or idle timeout
	const shouldReset =
		resetTriggers.some((t) => msg.body.trim().toLowerCase().startsWith(t.toLowerCase())) ||
		(existingSession && now - existingSession.updatedAt > idleMinutes * 60 * 1000);

	let sessionEntry: SessionEntry;
	let isNewSession: boolean;
	if (!existingSession || shouldReset) {
		sessionEntry = {
			sessionId: crypto.randomUUID(),
			updatedAt: now,
			systemSent: false,
		};
		isNewSession = true;

		// Delete old session if resetting
		if (existingSession && shouldReset) {
			deleteSession(sessionKey);
		}
	} else {
		sessionEntry = existingSession;
		isNewSession = false;
	}

	const templatingCtx: TemplateContext = {
		Body: msg.body,
		BodyStripped: msg.body.trim(),
		From: ctx.from,
		To: ctx.to,
		MessageId: msg.id,
		MediaPath: ctx.mediaPath,
		MediaUrl: msg.mediaUrl,
		MediaType: ctx.mediaType,
		Username: ctx.username,
		SessionId: sessionEntry.sessionId,
		IsNewSession: isNewSession ? "true" : "false",
	};

	// Typing indicator refresh
	const typingInterval = (replyConfig.typingIntervalSeconds ?? 8) * 1000;
	const typingTimer = setInterval(() => {
		msg.sendComposing().catch(() => {});
	}, typingInterval);

	try {
		const queryPrompt = templatingCtx.BodyStripped ?? prompt;
		let responseText = "";

		// Execute with session resume for conversation continuity and timeout
		for await (const chunk of executeQueryStream(queryPrompt, {
			cwd: process.cwd(),
			tier,
			resumeSessionId: isNewSession ? undefined : sessionEntry.sessionId,
			enableSkills: tier !== "READ_ONLY",
			timeoutMs: timeoutSeconds * 1000,
		})) {
			if (chunk.type === "text") {
				responseText += chunk.content;
			} else if (chunk.type === "done") {
				if (!chunk.result.success) {
					const errorMsg = chunk.result.error?.includes("aborted")
						? "Request timed out. Please try again with a simpler request."
						: `Request failed: ${chunk.result.error ?? "Unknown error"}`;

					logger.warn({ requestId, error: chunk.result.error }, "SDK query failed");
					await msg.reply(errorMsg);
					await auditLogger.log({
						timestamp: new Date(),
						requestId,
						telegramUserId: userId,
						telegramUsername: ctx.username,
						chatId: msg.chatId,
						messagePreview: msg.body.slice(0, 100),
						observerClassification,
						observerConfidence,
						permissionTier: tier,
						executionTimeMs: chunk.result.durationMs,
						outcome: chunk.result.error?.includes("aborted") ? "timeout" : "error",
						errorType: chunk.result.error ?? "sdk_error",
					});
					return;
				}

				const finalResponse = responseText || chunk.result.response;

				if (finalResponse) {
					await msg.reply(finalResponse);

					recentlySent.add(finalResponse);
					setTimeout(() => recentlySent.delete(finalResponse), 30000);

					// Update session in SQLite
					sessionEntry.updatedAt = Date.now();
					sessionEntry.systemSent = true;
					setSession(sessionKey, sessionEntry);
				}

				await auditLogger.log({
					timestamp: new Date(),
					requestId,
					telegramUserId: userId,
					telegramUsername: ctx.username,
					chatId: msg.chatId,
					messagePreview: msg.body.slice(0, 100),
					observerClassification,
					observerConfidence,
					permissionTier: tier,
					executionTimeMs: chunk.result.durationMs,
					outcome: "success",
					costUsd: chunk.result.costUsd,
				});
			}
		}
	} catch (err) {
		logger.error({ requestId, error: String(err) }, "reply failed");
		await auditLogger.log({
			timestamp: new Date(),
			requestId,
			telegramUserId: userId,
			telegramUsername: ctx.username,
			chatId: msg.chatId,
			messagePreview: msg.body.slice(0, 100),
			observerClassification,
			observerConfidence,
			permissionTier: tier,
			executionTimeMs: Date.now() - startTime,
			outcome: "error",
			errorType: String(err),
		});

		await msg.reply("An error occurred while processing your request. Please try again.");
	} finally {
		clearInterval(typingTimer);
	}
}

export type MonitorOptions = {
	verbose: boolean;
	keepAlive?: boolean;
	abortSignal?: AbortSignal;
};

/**
 * Main monitoring loop for Telegram with auto-reply.
 */
export async function monitorTelegramProvider(
	options: MonitorOptions,
	_runtime?: RuntimeEnv,
): Promise<void> {
	const { verbose, keepAlive = true, abortSignal } = options;
	const cfg = loadConfig();
	const reconnectPolicy = resolveReconnectPolicy(cfg);

	const observer = createObserver({
		enabled: cfg.security?.observer?.enabled ?? true,
		maxLatencyMs: cfg.security?.observer?.maxLatencyMs ?? 2000,
		dangerThreshold: cfg.security?.observer?.dangerThreshold ?? 0.7,
		fallbackOnTimeout: cfg.security?.observer?.fallbackOnTimeout ?? "block",
		cwd: process.cwd(),
	});

	const rateLimiter = createRateLimiter(cfg.security);
	const auditLogger = createAuditLogger({
		enabled: cfg.security?.audit?.enabled ?? true,
		logFile: cfg.security?.audit?.logFile,
	});

	const recentlySent = new Set<string>();

	let reconnectAttempts = 0;

	while (true) {
		if (abortSignal?.aborted) break;

		try {
			const token = process.env.TELEGRAM_BOT_TOKEN;
			if (!token) throw new Error("TELEGRAM_BOT_TOKEN not set");

			const { bot, botInfo } = await createTelegramBot({ token, verbose });

			logger.info({ botId: botInfo.id, username: botInfo.username }, "connected to Telegram");

			const { close, onClose } = await monitorTelegramInbox({
				bot,
				botInfo,
				verbose,
				allowedChats: cfg.telegram?.allowedChats,
				onMessage: async (msg) => {
					await handleInboundMessage(
						msg,
						bot,
						cfg,
						observer,
						rateLimiter,
						auditLogger,
						recentlySent,
					);
				},
			});

			const runner = run(bot);

			// Periodic cleanup of expired entries in SQLite
			const cleanupInterval = setInterval(() => {
				cleanupExpiredApprovals();
				cleanupExpired();
			}, 60_000);

			logger.info("Listening for Telegram messages. Ctrl+C to stop.");

			reconnectAttempts = 0;

			const closeReason = await Promise.race([
				onClose,
				abortSignal
					? new Promise<"aborted">((resolve) =>
							abortSignal.addEventListener("abort", () => resolve("aborted")),
						)
					: new Promise<never>(() => {}),
			]);

			clearInterval(cleanupInterval);
			runner.stop();
			await close();

			if (closeReason === "aborted" || abortSignal?.aborted) {
				logger.info("monitor aborted by signal");
				break;
			}

			if (!keepAlive) break;

			reconnectAttempts++;
			if (reconnectPolicy.maxAttempts > 0 && reconnectAttempts >= reconnectPolicy.maxAttempts) {
				throw new Error(`Max reconnect attempts (${reconnectPolicy.maxAttempts}) reached`);
			}

			const delay = computeBackoff(reconnectPolicy, reconnectAttempts);
			logger.info({ delay, attempt: reconnectAttempts }, "reconnecting");
			await sleepWithAbort(delay, abortSignal);
		} catch (err) {
			logger.error({ error: String(err) }, "monitor error");

			if (!keepAlive) throw err;

			reconnectAttempts++;
			if (reconnectPolicy.maxAttempts > 0 && reconnectAttempts >= reconnectPolicy.maxAttempts) {
				throw new Error(
					`Max reconnect attempts (${reconnectPolicy.maxAttempts}) reached: ${String(err)}`,
				);
			}

			const delay = computeBackoff(reconnectPolicy, reconnectAttempts);
			logger.error({ error: String(err), delay }, "reconnecting after error");
			await sleepWithAbort(delay, abortSignal);
		}
	}
}

/**
 * Handle an inbound message with security checks and auto-reply.
 */
async function handleInboundMessage(
	msg: TelegramInboundMessage,
	_bot: Bot,
	cfg: TelclaudeConfig,
	observer: SecurityObserver,
	rateLimiter: RateLimiter,
	auditLogger: AuditLogger,
	recentlySent: Set<string>,
): Promise<void> {
	const requestId = `req_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`;
	const userId = String(msg.chatId);

	// ══════════════════════════════════════════════════════════════════════════
	// CONTROL PLANE COMMANDS - Intercepted BEFORE any other processing
	// ══════════════════════════════════════════════════════════════════════════

	const trimmedBody = msg.body.trim();

	if (trimmedBody.startsWith("/link ")) {
		const code = trimmedBody.split(/\s+/)[1]?.trim();
		await handleLinkCommand(msg, code, auditLogger);
		return;
	}

	if (trimmedBody.startsWith("/approve ")) {
		const nonce = trimmedBody.split(/\s+/)[1]?.trim();
		await handleApproveCommand(msg, nonce, cfg, auditLogger, recentlySent);
		return;
	}

	if (trimmedBody.startsWith("/deny ")) {
		const nonce = trimmedBody.split(/\s+/)[1]?.trim();
		await handleDenyCommand(msg, nonce, auditLogger);
		return;
	}

	if (trimmedBody === "/unlink") {
		const { removeIdentityLink } = await import("../security/linking.js");
		const removed = removeIdentityLink(msg.chatId);
		if (removed) {
			await msg.reply("Identity link removed for this chat.");
		} else {
			await msg.reply("No identity link found for this chat.");
		}
		return;
	}

	if (trimmedBody === "/whoami") {
		const link = getIdentityLink(msg.chatId);
		if (link) {
			await msg.reply(
				`This chat is linked to local user: *${link.localUserId}*\n` +
					`Linked: ${new Date(link.linkedAt).toLocaleString()}`,
			);
		} else {
			await msg.reply(
				"This chat is not linked to any local user.\n" +
					"Use `telclaude link <user-id>` on your machine to generate a link code.",
			);
		}
		return;
	}

	// ══════════════════════════════════════════════════════════════════════════
	// DATA PLANE - Regular messages through security checks to Claude
	// ══════════════════════════════════════════════════════════════════════════

	if (recentlySent.has(msg.body)) {
		recentlySent.delete(msg.body);
		logger.debug({ msgId: msg.id }, "echo detected, skipping");
		return;
	}

	const tier = getUserPermissionTier(msg.chatId, cfg.security);

	const rateLimitResult = await rateLimiter.checkLimit(userId, tier);
	if (!rateLimitResult.allowed) {
		logger.info({ userId, tier }, "rate limited");
		await auditLogger.logRateLimited(userId, msg.chatId, tier);
		await msg.reply(
			`Rate limit exceeded. Please wait ${Math.ceil(rateLimitResult.resetMs / 1000)} seconds.`,
		);
		return;
	}

	const observerResult = await observer.analyze(msg.body, {
		permissionTier: tier,
	});

	if (requiresApproval(tier, observerResult.classification, observerResult.confidence)) {
		const nonce = createApproval({
			requestId,
			chatId: msg.chatId,
			tier,
			body: msg.body,
			mediaPath: msg.mediaPath,
			mediaUrl: msg.mediaUrl,
			mediaType: msg.mediaType,
			username: msg.username,
			from: msg.from,
			to: msg.to,
			messageId: msg.id,
			observerClassification: observerResult.classification,
			observerConfidence: observerResult.confidence,
			observerReason: observerResult.reason,
		});

		const approvalMessage = formatApprovalRequest({
			nonce,
			requestId,
			chatId: msg.chatId,
			createdAt: Date.now(),
			expiresAt: Date.now() + 5 * 60 * 1000,
			tier,
			body: msg.body,
			mediaPath: msg.mediaPath,
			mediaUrl: msg.mediaUrl,
			mediaType: msg.mediaType,
			username: msg.username,
			from: msg.from,
			to: msg.to,
			messageId: msg.id,
			observerClassification: observerResult.classification,
			observerConfidence: observerResult.confidence,
			observerReason: observerResult.reason,
		});

		await msg.reply(approvalMessage);

		await auditLogger.log({
			timestamp: new Date(),
			requestId,
			telegramUserId: userId,
			telegramUsername: msg.username,
			chatId: msg.chatId,
			messagePreview: msg.body.slice(0, 100),
			observerClassification: observerResult.classification,
			observerConfidence: observerResult.confidence,
			permissionTier: tier,
			outcome: "blocked",
			errorType: `pending_approval:${nonce}`,
		});

		logger.info(
			{ requestId, nonce, tier, classification: observerResult.classification },
			"request requires approval",
		);
		return;
	}

	if (observerResult.classification === "WARN") {
		logger.info({ userId, reason: observerResult.reason }, "message flagged with warning");
	}

	await executeAndReply({
		msg,
		prompt: msg.body.trim(),
		mediaPath: msg.mediaPath,
		mediaType: msg.mediaType,
		from: msg.from,
		to: msg.to,
		username: msg.username,
		tier,
		config: cfg,
		observerClassification: observerResult.classification,
		observerConfidence: observerResult.confidence,
		requestId,
		recentlySent,
		auditLogger,
	});
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONTROL PLANE COMMAND HANDLERS
// ═══════════════════════════════════════════════════════════════════════════════

async function handleLinkCommand(
	msg: TelegramInboundMessage,
	code: string | undefined,
	auditLogger: AuditLogger,
): Promise<void> {
	if (!code) {
		await msg.reply(
			"Usage: `/link <code>`\n\n" +
				"Generate a link code on your machine with:\n" +
				"`telclaude link <your-user-id>`",
		);
		return;
	}

	const result = consumeLinkCode(code, msg.chatId, msg.username ?? String(msg.chatId));

	if (!result.success) {
		await msg.reply(`${result.error}`);
		return;
	}

	await msg.reply(
		`*Identity linked successfully!*\n\nThis chat is now linked to local user: *${result.data.localUserId}*\n\nYou can verify with \`/whoami\` or unlink with \`/unlink\`.`,
	);

	await auditLogger.log({
		timestamp: new Date(),
		requestId: `link_${Date.now()}`,
		telegramUserId: String(msg.chatId),
		telegramUsername: msg.username,
		chatId: msg.chatId,
		messagePreview: "(identity link)",
		permissionTier: "READ_ONLY",
		outcome: "success",
		errorType: `identity_linked:${result.data.localUserId}`,
	});
}

async function handleApproveCommand(
	msg: TelegramInboundMessage,
	nonce: string | undefined,
	cfg: TelclaudeConfig,
	auditLogger: AuditLogger,
	recentlySent: Set<string>,
): Promise<void> {
	if (!nonce) {
		await msg.reply("Usage: `/approve <code>`");
		return;
	}

	const result = consumeApproval(nonce, msg.chatId);

	if (!result.success) {
		await msg.reply(`${result.error}`);
		return;
	}

	await msg.reply("Request approved. Processing...");

	const approval = result.data;
	const approvedMsg: TelegramInboundMessage = {
		...msg,
		body: approval.body,
		mediaPath: approval.mediaPath,
		mediaUrl: approval.mediaUrl,
		mediaType: approval.mediaType,
		from: approval.from,
		to: approval.to,
		id: approval.messageId,
	};

	await executeApprovedRequest(approvedMsg, cfg, approval, auditLogger, recentlySent);
}

async function handleDenyCommand(
	msg: TelegramInboundMessage,
	nonce: string | undefined,
	auditLogger: AuditLogger,
): Promise<void> {
	if (!nonce) {
		await msg.reply("Usage: `/deny <code>`");
		return;
	}

	const result = denyApproval(nonce, msg.chatId);

	if (!result.success) {
		await msg.reply(`${result.error}`);
		return;
	}

	await msg.reply("Request denied.");

	const entry = result.data;
	await auditLogger.log({
		timestamp: new Date(),
		requestId: entry.requestId,
		telegramUserId: String(msg.chatId),
		telegramUsername: msg.username,
		chatId: msg.chatId,
		messagePreview: entry.body.slice(0, 100),
		observerClassification: entry.observerClassification,
		observerConfidence: entry.observerConfidence,
		permissionTier: entry.tier,
		outcome: "blocked",
		errorType: "user_denied",
	});
}

async function executeApprovedRequest(
	msg: TelegramInboundMessage,
	cfg: TelclaudeConfig,
	approval: PendingApproval,
	auditLogger: AuditLogger,
	recentlySent: Set<string>,
): Promise<void> {
	await executeAndReply({
		msg,
		prompt: msg.body.trim(),
		mediaPath: approval.mediaPath,
		mediaType: approval.mediaType,
		from: approval.from,
		to: approval.to,
		username: approval.username,
		tier: approval.tier,
		config: cfg,
		observerClassification: approval.observerClassification,
		observerConfidence: approval.observerConfidence,
		requestId: approval.requestId,
		recentlySent,
		auditLogger,
	});
}
