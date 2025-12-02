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
	consumeMostRecentApproval,
	createApproval,
	denyApproval,
	formatApprovalRequest,
	getMostRecentPendingApproval,
	requiresApproval,
} from "../security/approvals.js";
import { type AuditLogger, createAuditLogger } from "../security/audit.js";
import { consumeLinkCode, getIdentityLink } from "../security/linking.js";
import { type SecurityObserver, createObserver } from "../security/observer.js";
import { getUserPermissionTier } from "../security/permissions.js";
import { type RateLimiter, createRateLimiter } from "../security/rate-limit.js";
import { disableTOTP, hasTOTP, setupTOTP, verifyTOTP } from "../security/totp.js";
import type { SecurityClassification } from "../security/types.js";
import { cleanupExpired } from "../storage/db.js";

import { createTelegramBot } from "./client.js";
import { monitorTelegramInbox } from "./inbound.js";
import { computeBackoff, resolveReconnectPolicy, sleepWithAbort } from "./reconnect.js";
import type { TelegramInboundMessage, TelegramMediaType } from "./types.js";

const logger = getChildLogger({ module: "telegram-auto-reply" });

// Rate limiting for control commands (prevent brute-force on /approve)
// Stricter than regular rate limits: 5 attempts per minute per user
const controlCommandAttempts = new Map<string, { count: number; windowStart: number }>();
const CONTROL_COMMAND_LIMIT = 5;
const CONTROL_COMMAND_WINDOW_MS = 60_000;

function checkControlCommandRateLimit(userId: string): boolean {
	const now = Date.now();
	const entry = controlCommandAttempts.get(userId);

	if (!entry || now - entry.windowStart > CONTROL_COMMAND_WINDOW_MS) {
		// New window
		controlCommandAttempts.set(userId, { count: 1, windowStart: now });
		return true;
	}

	if (entry.count >= CONTROL_COMMAND_LIMIT) {
		return false;
	}

	entry.count++;
	return true;
}

// Session locks to prevent race conditions on rapid messages
const sessionLocks = new Map<string, Promise<void>>();

async function withSessionLock<T>(sessionKey: string, fn: () => Promise<T>): Promise<T> {
	// Wait for any existing operation on this session
	const existingLock = sessionLocks.get(sessionKey);
	if (existingLock) {
		await existingLock;
	}

	// Create a new lock for our operation
	let resolve: (() => void) | undefined;
	const lock = new Promise<void>((r) => {
		resolve = r;
	});
	sessionLocks.set(sessionKey, lock);

	try {
		return await fn();
	} finally {
		if (resolve) resolve();
		// Only delete if we're still the current lock
		if (sessionLocks.get(sessionKey) === lock) {
			sessionLocks.delete(sessionKey);
		}
	}
}

// Input sanitization patterns
// biome-ignore lint/suspicious/noControlCharactersInRegex: intentional null byte detection for security
const NULL_BYTE_PATTERN = /\x00/;
const LONG_LINE_PATTERN = /[^\s]{10000,}/;

function sanitizeInput(input: string): { valid: boolean; sanitized: string; reason?: string } {
	// Check for null bytes (can cause issues in string processing)
	if (NULL_BYTE_PATTERN.test(input)) {
		return { valid: false, sanitized: "", reason: "Malformed input detected" };
	}

	// Check for extremely long lines without spaces (potential DoS)
	if (LONG_LINE_PATTERN.test(input)) {
		return { valid: false, sanitized: "", reason: "Malformed input detected" };
	}

	// Limit total length to prevent memory issues (100KB is generous for a chat message)
	if (input.length > 100_000) {
		return { valid: false, sanitized: "", reason: "Message too long" };
	}

	return { valid: true, sanitized: input };
}

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
 *
 * Uses session locking to prevent race conditions when multiple messages
 * arrive rapidly for the same session.
 */
async function executeAndReply(ctx: ExecutionContext): Promise<void> {
	const { msg, config } = ctx;

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

	// Use session lock to prevent race conditions on rapid messages
	await withSessionLock(sessionKey, async () => {
		await executeWithSession(ctx, sessionKey, {
			userId,
			startTime,
			idleMinutes,
			resetTriggers,
			timeoutSeconds,
		});
	});
}

/**
 * Internal session-locked execution.
 */
async function executeWithSession(
	ctx: ExecutionContext,
	sessionKey: string,
	opts: {
		userId: string;
		startTime: number;
		idleMinutes: number;
		resetTriggers: string[];
		timeoutSeconds: number;
	},
): Promise<void> {
	const {
		msg,
		tier,
		requestId,
		observerClassification,
		observerConfidence,
		recentlySent,
		auditLogger,
	} = ctx;
	const { userId, startTime, idleMinutes, resetTriggers, timeoutSeconds } = opts;
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
	const replyConfig = ctx.config.inbound?.reply;
	const typingInterval = (replyConfig?.typingIntervalSeconds ?? 8) * 1000;
	const typingTimer = setInterval(() => {
		msg.sendComposing().catch(() => {});
	}, typingInterval);

	try {
		const queryPrompt = templatingCtx.BodyStripped ?? ctx.prompt;
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
			const errorStr = String(err);
			logger.error({ error: errorStr }, "monitor error");

			// Fatal errors that should not retry - exit immediately
			if (
				errorStr.includes("401") ||
				errorStr.includes("Unauthorized") ||
				errorStr.includes("invalid token") ||
				errorStr.includes("bot token")
			) {
				logger.fatal("Invalid or revoked Telegram bot token. Exiting.");
				process.exit(1);
			}

			if (!keepAlive) throw err;

			reconnectAttempts++;
			if (reconnectPolicy.maxAttempts > 0 && reconnectAttempts >= reconnectPolicy.maxAttempts) {
				throw new Error(
					`Max reconnect attempts (${reconnectPolicy.maxAttempts}) reached: ${errorStr}`,
				);
			}

			const delay = computeBackoff(reconnectPolicy, reconnectAttempts);
			logger.error({ error: errorStr, delay }, "reconnecting after error");
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

	// Rate limit control commands to prevent brute-force attacks
	const isControlCommand =
		trimmedBody.startsWith("/link ") ||
		trimmedBody.startsWith("/approve ") ||
		trimmedBody.startsWith("/deny ");

	if (isControlCommand && !checkControlCommandRateLimit(userId)) {
		logger.warn({ userId }, "control command rate limited");
		await msg.reply("Too many attempts. Please wait a minute before trying again.");
		return;
	}

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
	// 2FA COMMANDS
	// ══════════════════════════════════════════════════════════════════════════

	if (trimmedBody === "/setup-2fa") {
		await handleSetup2FA(msg);
		return;
	}

	if (trimmedBody.startsWith("/verify-2fa ")) {
		const code = trimmedBody.split(/\s+/)[1]?.trim();
		await handleVerify2FA(msg, code);
		return;
	}

	if (trimmedBody === "/disable-2fa") {
		await handleDisable2FA(msg);
		return;
	}

	if (trimmedBody === "/deny") {
		// Deny without nonce - deny the most recent pending approval
		await handleDenyMostRecent(msg, auditLogger);
		return;
	}

	// Check for TOTP code (6 digits) - for approving with 2FA
	// Only intercept if there's actually a pending approval; otherwise let normal
	// 6-digit messages fall through to the data plane
	if (/^\d{6}$/.test(trimmedBody) && getMostRecentPendingApproval(msg.chatId)) {
		const totpCheck = await hasTOTP(msg.chatId);
		if (totpCheck.hasTOTP) {
			await handleTOTPApproval(msg, trimmedBody, cfg, auditLogger, recentlySent);
			return;
		}
		// Fail closed if daemon is unavailable - don't let the message fall through
		if ("error" in totpCheck) {
			logger.error(
				{ chatId: msg.chatId, error: totpCheck.error },
				"TOTP daemon unavailable during approval verification",
			);
			await msg.reply(
				"⚠️ Cannot verify TOTP code - security service unavailable.\n\n" +
					"The TOTP daemon is not running. Your pending approval cannot be processed.\n" +
					"Please contact an administrator or use `/deny` to cancel the request.",
			);
			return;
		}
		// No TOTP configured for this user - let 6-digit message fall through to data plane
	}

	// ══════════════════════════════════════════════════════════════════════════
	// DATA PLANE - Regular messages through security checks to Claude
	// ══════════════════════════════════════════════════════════════════════════

	// Input sanitization - reject malformed messages early
	const sanitized = sanitizeInput(msg.body);
	if (!sanitized.valid) {
		logger.warn({ userId, reason: sanitized.reason }, "malformed input rejected");
		await msg.reply(`Message rejected: ${sanitized.reason}`);
		return;
	}

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
		// Create approval and get timing info to ensure display matches actual expiry
		const { nonce, createdAt, expiresAt } = createApproval({
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

		// Use the actual timing from createApproval to avoid TTL mismatch
		// Check TOTP status - fail closed if daemon is unavailable
		const totpCheck = await hasTOTP(msg.chatId);
		if ("error" in totpCheck) {
			// TOTP daemon is unavailable - fail closed to prevent bypass
			// Remove the pending approval since we can't process it securely
			logger.error(
				{ chatId: msg.chatId, error: totpCheck.error },
				"TOTP daemon unavailable - blocking request",
			);
			await msg.reply(
				"⚠️ Security service unavailable. Cannot process this request.\n\n" +
					"The TOTP daemon is not running. Please contact an administrator or try again later.",
			);
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
				errorType: "totp_daemon_unavailable",
			});
			return;
		}

		const userHasTOTP = totpCheck.hasTOTP;
		const approvalMessage = formatApprovalRequest(
			{
				nonce,
				requestId,
				chatId: msg.chatId,
				createdAt,
				expiresAt,
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
			},
			userHasTOTP,
		);

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

// ═══════════════════════════════════════════════════════════════════════════════
// 2FA COMMAND HANDLERS
// ═══════════════════════════════════════════════════════════════════════════════

async function handleSetup2FA(msg: TelegramInboundMessage): Promise<void> {
	const result = await setupTOTP(msg.chatId, msg.username);

	if (!result.success) {
		await msg.reply(result.error);
		return;
	}

	// The URI can be used to generate a QR code, but for now we'll provide manual entry
	// Extract the secret from the URI for manual entry
	const secretMatch = result.uri.match(/secret=([A-Z2-7]+)/);
	const secret = secretMatch?.[1] ?? "";

	await msg.reply(
		`*Setting up Two-Factor Authentication*\n\n1. Open Google Authenticator (or any TOTP app)\n2. Add a new account manually:\n   - Name: \`Telclaude\`\n   - Secret: \`${secret}\`\n   - Type: Time-based\n\n3. Enter the 6-digit code to verify:\n   \`/verify-2fa <code>\``,
	);
}

async function handleVerify2FA(
	msg: TelegramInboundMessage,
	code: string | undefined,
): Promise<void> {
	if (!code) {
		await msg.reply("Usage: `/verify-2fa <6-digit-code>`");
		return;
	}

	if (!/^\d{6}$/.test(code)) {
		await msg.reply("Please enter a valid 6-digit code.");
		return;
	}

	const valid = await verifyTOTP(msg.chatId, code);

	if (!valid) {
		await msg.reply(
			"Invalid code. Please try again with the current code from your authenticator.",
		);
		return;
	}

	await msg.reply(
		"*2FA enabled successfully!*\n\n" +
			"From now on, when approval is required, simply reply with your 6-digit authenticator code.\n\n" +
			"To disable 2FA: `/disable-2fa`",
	);
}

async function handleDisable2FA(msg: TelegramInboundMessage): Promise<void> {
	const removed = await disableTOTP(msg.chatId);

	if (removed) {
		await msg.reply("2FA has been disabled for this chat.");
	} else {
		await msg.reply("2FA was not enabled for this chat.");
	}
}

async function handleDenyMostRecent(
	msg: TelegramInboundMessage,
	auditLogger: AuditLogger,
): Promise<void> {
	const approval = getMostRecentPendingApproval(msg.chatId);

	if (!approval) {
		await msg.reply("No pending approval found.");
		return;
	}

	// Use denyApproval with the nonce
	const result = denyApproval(approval.nonce, msg.chatId);

	if (!result.success) {
		await msg.reply(result.error);
		return;
	}

	await msg.reply("Request denied.");

	await auditLogger.log({
		timestamp: new Date(),
		requestId: approval.requestId,
		telegramUserId: String(msg.chatId),
		telegramUsername: msg.username,
		chatId: msg.chatId,
		messagePreview: approval.body.slice(0, 100),
		observerClassification: approval.observerClassification,
		observerConfidence: approval.observerConfidence,
		permissionTier: approval.tier,
		outcome: "blocked",
		errorType: "user_denied",
	});
}

async function handleTOTPApproval(
	msg: TelegramInboundMessage,
	code: string,
	cfg: TelclaudeConfig,
	auditLogger: AuditLogger,
	recentlySent: Set<string>,
): Promise<void> {
	// Check if there's a pending approval
	const approval = getMostRecentPendingApproval(msg.chatId);

	if (!approval) {
		// No pending approval - this might just be a random 6-digit message
		// Don't respond to avoid confusion
		return;
	}

	// Verify the TOTP code
	if (!(await verifyTOTP(msg.chatId, code))) {
		await msg.reply(
			"Invalid code. Please try again with the current code from your authenticator.",
		);
		return;
	}

	// Consume the approval
	const result = consumeMostRecentApproval(msg.chatId);

	if (!result.success) {
		await msg.reply(result.error);
		return;
	}

	await msg.reply("Request approved. Processing...");

	const approvedApproval = result.data;
	const approvedMsg: TelegramInboundMessage = {
		...msg,
		body: approvedApproval.body,
		mediaPath: approvedApproval.mediaPath,
		mediaUrl: approvedApproval.mediaUrl,
		mediaType: approvedApproval.mediaType,
		from: approvedApproval.from,
		to: approvedApproval.to,
		id: approvedApproval.messageId,
	};

	await executeApprovedRequest(approvedMsg, cfg, approvedApproval, auditLogger, recentlySent);
}
