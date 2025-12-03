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
import { readEnv } from "../env.js";
import { getChildLogger } from "../logging.js";
import type { RuntimeEnv } from "../runtime.js";
import { executePooledQuery } from "../sdk/client.js";
import { getSessionManager } from "../sdk/session-manager.js";
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
import { checkInfrastructureSecrets } from "../security/fast-path.js";
import { consumeLinkCode, getIdentityLink } from "../security/linking.js";
import { type SecurityObserver, createObserver } from "../security/observer.js";
import { getUserPermissionTier } from "../security/permissions.js";
import { type RateLimiter, createRateLimiter } from "../security/rate-limit.js";
import {
	createTOTPSession,
	hasTOTPSession,
	invalidateTOTPSessionForChat,
} from "../security/totp-session.js";
import { disableTOTP, hasTOTP, verifyTOTP } from "../security/totp.js";
import type { SecurityClassification } from "../security/types.js";
import { getDb } from "../storage/db.js";
import { cleanupExpired } from "../storage/db.js";

import { createTelegramBot } from "./client.js";
import { monitorTelegramInbox } from "./inbound.js";
import { computeBackoff, resolveReconnectPolicy, sleepWithAbort } from "./reconnect.js";
import type { TelegramInboundMessage, TelegramMediaType } from "./types.js";

const logger = getChildLogger({ module: "telegram-auto-reply" });

/**
 * Generate a key for the recentlySent set.
 * Includes chatId to prevent cross-chat collisions where the same message
 * text in different chats could be incorrectly filtered.
 */
function makeRecentSentKey(chatId: number, body: string): string {
	return `${chatId}:${body}`;
}

// Rate limiting for control commands (prevent brute-force on /approve)
// Stricter than regular rate limits: 5 attempts per minute per user
// SECURITY: Now SQLite-backed for persistence across restarts
const CONTROL_COMMAND_LIMIT = 5;
const CONTROL_COMMAND_WINDOW_MS = 60_000;

function checkControlCommandRateLimit(userId: string): boolean {
	const db = getDb();
	const now = Date.now();
	const windowStart = Math.floor(now / CONTROL_COMMAND_WINDOW_MS) * CONTROL_COMMAND_WINDOW_MS;

	try {
		// Use transaction for atomicity
		const result = db.transaction(() => {
			// Get current count for this window
			const row = db
				.prepare(
					"SELECT points FROM rate_limits WHERE limiter_type = ? AND key = ? AND window_start = ?",
				)
				.get("control_command", userId, windowStart) as { points: number } | undefined;

			const currentCount = row?.points ?? 0;

			if (currentCount >= CONTROL_COMMAND_LIMIT) {
				return false;
			}

			// Increment counter
			db.prepare(
				`INSERT INTO rate_limits (limiter_type, key, window_start, points)
				 VALUES (?, ?, ?, 1)
				 ON CONFLICT(limiter_type, key, window_start)
				 DO UPDATE SET points = points + 1`,
			).run("control_command", userId, windowStart);

			return true;
		})();

		return result;
	} catch (err) {
		// FAIL CLOSED: On error, block the request
		logger.error(
			{ error: String(err), userId },
			"control command rate limit check failed - blocking",
		);
		return false;
	}
}

// Session locks to prevent race conditions on rapid messages
// Track both the promise and metadata for better diagnostics
type SessionLockEntry = {
	promise: Promise<void>;
	acquiredAt: number;
	requestId?: string;
};
const sessionLocks = new Map<string, SessionLockEntry>();

// Maximum time to wait for an existing lock (prevents deadlocks)
const SESSION_LOCK_TIMEOUT_MS = 120_000; // 2 minutes

async function withSessionLock<T>(
	sessionKey: string,
	fn: () => Promise<T>,
	requestId?: string,
): Promise<T> {
	// Wait for any existing operation on this session (with timeout)
	const existingLock = sessionLocks.get(sessionKey);
	if (existingLock) {
		const waitStartedAt = Date.now();
		const timeoutPromise = new Promise<"timeout">((resolve) =>
			setTimeout(() => resolve("timeout"), SESSION_LOCK_TIMEOUT_MS),
		);
		const result = await Promise.race([
			existingLock.promise.then(() => "done" as const),
			timeoutPromise,
		]);
		if (result === "timeout") {
			const lockHeldFor = Date.now() - existingLock.acquiredAt;
			logger.warn(
				{
					sessionKey,
					waitingRequestId: requestId,
					holdingRequestId: existingLock.requestId,
					lockHeldForMs: lockHeldFor,
					timeoutMs: SESSION_LOCK_TIMEOUT_MS,
				},
				"session lock timeout - previous operation may be stuck, forcing release",
			);
			// Remove the stuck lock to allow this operation to proceed
			sessionLocks.delete(sessionKey);
		} else {
			const waitedMs = Date.now() - waitStartedAt;
			if (waitedMs > 5000) {
				// Log if we had to wait more than 5 seconds
				logger.info({ sessionKey, requestId, waitedMs }, "session lock acquired after waiting");
			}
		}
	}

	// Create a new lock for our operation
	let resolve: (() => void) | undefined;
	const lock = new Promise<void>((r) => {
		resolve = r;
	});
	const lockEntry: SessionLockEntry = {
		promise: lock,
		acquiredAt: Date.now(),
		requestId,
	};
	sessionLocks.set(sessionKey, lockEntry);

	try {
		return await fn();
	} finally {
		if (resolve) resolve();
		// Only delete if we're still the current lock
		if (sessionLocks.get(sessionKey) === lockEntry) {
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
	console.log("[DEBUG] Inside executeAndReply");
	const { msg, config } = ctx;

	const userId = String(msg.chatId);
	const startTime = Date.now();

	const replyConfig = config.inbound?.reply;
	console.log(`[DEBUG] replyConfig.enabled=${replyConfig?.enabled}`);
	if (!replyConfig?.enabled) {
		logger.debug("reply not enabled, skipping");
		return;
	}

	console.log("[DEBUG] Sending composing indicator...");
	await msg.sendComposing();
	console.log("[DEBUG] Composing indicator sent");

	// Session handling with SQLite
	const sessionConfig = replyConfig.session;
	const scope = sessionConfig?.scope ?? "per-sender";
	const idleMinutes = sessionConfig?.idleMinutes ?? DEFAULT_IDLE_MINUTES;
	const resetTriggers = sessionConfig?.resetTriggers ?? ["/new"];
	const timeoutSeconds = replyConfig.timeoutSeconds ?? 600; // Default 10 minutes

	const sessionKey = deriveSessionKey(scope, { From: ctx.from });

	// Use session lock to prevent race conditions on rapid messages
	console.log(`[DEBUG] Acquiring session lock for: ${sessionKey}`);
	await withSessionLock(
		sessionKey,
		async () => {
			console.log("[DEBUG] Session lock acquired, calling executeWithSession");
			await executeWithSession(ctx, sessionKey, {
				userId,
				startTime,
				idleMinutes,
				resetTriggers,
				timeoutSeconds,
			});
			console.log("[DEBUG] executeWithSession completed");
		},
		ctx.requestId,
	);
	console.log("[DEBUG] Session lock released");
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
	console.log("[DEBUG] Inside executeWithSession");
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
	console.log(`[DEBUG] existingSession=${existingSession ? "exists" : "null"}, tier=${tier}`);
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

		console.log(
			`[DEBUG] About to call executePooledQuery with prompt: "${queryPrompt.slice(0, 50)}..."`,
		);
		// Execute with V2 session pool for connection reuse and timeout
		for await (const chunk of executePooledQuery(queryPrompt, {
			cwd: process.cwd(),
			tier,
			poolKey: sessionKey,
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
					// Add to recentlySent BEFORE sending to prevent echo race condition
					const recentKey = makeRecentSentKey(msg.chatId, finalResponse);
					recentlySent.add(recentKey);
					setTimeout(() => recentlySent.delete(recentKey), 30000);

					await msg.reply(finalResponse);

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
			const env = readEnv();
			const token = env.telegramBotToken;

			console.log("Connecting to Telegram...");
			const { bot, botInfo } = await createTelegramBot({ token, verbose });
			console.log(`Connected as @${botInfo.username}`);

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
			console.log("[DEBUG] Runner started, polling should be active");

			// Log runner errors
			runner.task()?.catch((err) => {
				console.error("[DEBUG] Runner task error:", err);
			});

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
	console.log(`[DEBUG] handleInboundMessage called for: "${msg.body}"`);
	const requestId = `req_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`;
	const userId = String(msg.chatId);
	console.log(`[DEBUG] requestId=${requestId}, userId=${userId}`);

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

	if (trimmedBody === "/2fa-logout") {
		await handleLogout2FA(msg);
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
	// SESSION RESET COMMANDS
	// ══════════════════════════════════════════════════════════════════════════

	if (trimmedBody === "/new" || trimmedBody === "/reset") {
		// Session key is tg:{chatId} for per-sender scope
		const sessionKey = `tg:${msg.chatId}`;

		// Clear the session from config/sessions (SQLite)
		deleteSession(sessionKey);

		// Clear the session from SDK session manager (in-memory)
		getSessionManager().clearSession(sessionKey);

		logger.info({ chatId: msg.chatId, sessionKey }, "session reset via control command");
		await msg.reply("Session reset. Starting fresh conversation.");
		return;
	}

	// ══════════════════════════════════════════════════════════════════════════
	// DATA PLANE - Regular messages through security checks to Claude
	// ══════════════════════════════════════════════════════════════════════════
	console.log("[DEBUG] Reached data plane section");

	// Input sanitization - reject malformed messages early
	const sanitized = sanitizeInput(msg.body);
	console.log(`[DEBUG] Sanitization result: valid=${sanitized.valid}`);
	if (!sanitized.valid) {
		logger.warn({ userId, reason: sanitized.reason }, "malformed input rejected");
		await msg.reply(`Message rejected: ${sanitized.reason}`);
		return;
	}

	// ══════════════════════════════════════════════════════════════════════════
	// INFRASTRUCTURE SECRET CHECK - NON-OVERRIDABLE
	// ══════════════════════════════════════════════════════════════════════════
	// SECURITY: Check for infrastructure secrets BEFORE any approval logic.
	// These are NEVER allowed to be sent to Claude - no approval can bypass this.
	const infraSecretCheck = checkInfrastructureSecrets(msg.body);
	if (infraSecretCheck.blocked) {
		logger.error(
			{
				userId,
				chatId: msg.chatId,
				patterns: infraSecretCheck.patterns,
			},
			"BLOCKED: Infrastructure secrets detected - NON-OVERRIDABLE",
		);
		await msg.reply(
			"Message blocked: Contains infrastructure secrets (bot tokens, API keys, or private keys).\n\n" +
				"This is a security measure that CANNOT be overridden. These secrets must never be sent to the AI agent.\n\n" +
				"If you need to work with credentials, store them in environment variables or config files instead of pasting them directly.",
		);
		await auditLogger.log({
			timestamp: new Date(),
			requestId,
			telegramUserId: userId,
			telegramUsername: msg.username,
			chatId: msg.chatId,
			messagePreview: "[REDACTED - infrastructure secrets]",
			permissionTier: getUserPermissionTier(msg.chatId, cfg.security),
			outcome: "blocked",
			errorType: `infrastructure_secrets:${infraSecretCheck.patterns.join(",")}`,
		});
		return;
	}

	const recentKey = makeRecentSentKey(msg.chatId, msg.body);
	if (recentlySent.has(recentKey)) {
		recentlySent.delete(recentKey);
		logger.debug({ msgId: msg.id }, "echo detected, skipping");
		return;
	}

	const tier = getUserPermissionTier(msg.chatId, cfg.security);
	console.log(`[DEBUG] Permission tier: ${tier}`);

	console.log("[DEBUG] Checking rate limit...");
	const rateLimitResult = await rateLimiter.checkLimit(userId, tier);
	console.log(`[DEBUG] Rate limit result: allowed=${rateLimitResult.allowed}`);
	if (!rateLimitResult.allowed) {
		logger.info({ userId, tier }, "rate limited");
		await auditLogger.logRateLimited(userId, msg.chatId, tier);
		await msg.reply(
			`Rate limit exceeded. Please wait ${Math.ceil(rateLimitResult.resetMs / 1000)} seconds.`,
		);
		return;
	}

	console.log("[DEBUG] Calling observer.analyze...");
	const observerResult = await observer.analyze(msg.body, {
		permissionTier: tier,
	});
	console.log(
		`[DEBUG] Observer result: classification=${observerResult.classification}, confidence=${observerResult.confidence}`,
	);

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
		// Check if user has a valid TOTP session ("remember me" feature)
		// If they do, show nonce-based approval instead of requiring TOTP
		const hasValidSession = hasTOTPSession(msg.chatId);
		const requireTOTPVerification = userHasTOTP && !hasValidSession;

		if (hasValidSession) {
			logger.debug({ chatId: msg.chatId }, "valid TOTP session found, using nonce-based approval");
		}

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
			requireTOTPVerification,
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

	console.log("[DEBUG] About to call executeAndReply...");
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

/**
 * Order of permission tiers from least to most permissive.
 * Used to enforce "least privilege" at execution time.
 */
const TIER_ORDER: Record<PermissionTier, number> = {
	READ_ONLY: 0,
	WRITE_SAFE: 1,
	FULL_ACCESS: 2,
};

/**
 * Get the more restrictive of two permission tiers.
 */
function minTier(a: PermissionTier, b: PermissionTier): PermissionTier {
	return TIER_ORDER[a] <= TIER_ORDER[b] ? a : b;
}

/**
 * Maximum age of an approval before we reject it at execution time.
 * This prevents stale approvals from being executed long after they were granted.
 */
const MAX_APPROVAL_AGE_MS = 10 * 60 * 1000; // 10 minutes

async function executeApprovedRequest(
	msg: TelegramInboundMessage,
	cfg: TelclaudeConfig,
	approval: PendingApproval,
	auditLogger: AuditLogger,
	recentlySent: Set<string>,
): Promise<void> {
	// SECURITY: Freshness check at execution time
	// Even though the approval was valid when consumed, we re-validate:
	// 1. Check approval age (prevent stale execution)
	// 2. Re-check current permissions (use least privilege)

	const now = Date.now();
	const approvalAge = now - approval.createdAt;

	// Reject if approval is too old
	if (approvalAge > MAX_APPROVAL_AGE_MS) {
		logger.warn(
			{
				requestId: approval.requestId,
				approvalAge: Math.round(approvalAge / 1000),
				maxAge: Math.round(MAX_APPROVAL_AGE_MS / 1000),
			},
			"stale approval rejected at execution time",
		);
		await msg.reply("This approval has become stale. Please submit your request again.");
		await auditLogger.log({
			timestamp: new Date(),
			requestId: approval.requestId,
			telegramUserId: String(msg.chatId),
			telegramUsername: approval.username,
			chatId: msg.chatId,
			messagePreview: approval.body.slice(0, 100),
			observerClassification: approval.observerClassification,
			observerConfidence: approval.observerConfidence,
			permissionTier: approval.tier,
			outcome: "blocked",
			errorType: "stale_approval",
		});
		return;
	}

	// Get current tier and use the more restrictive of stored vs current
	// This prevents privilege escalation if user's permissions were reduced
	const currentTier = getUserPermissionTier(msg.chatId, cfg.security);
	const effectiveTier = minTier(approval.tier, currentTier);

	if (effectiveTier !== approval.tier) {
		logger.info(
			{
				requestId: approval.requestId,
				originalTier: approval.tier,
				currentTier,
				effectiveTier,
			},
			"tier downgraded at execution time due to permission change",
		);
	}

	await executeAndReply({
		msg,
		prompt: msg.body.trim(),
		mediaPath: approval.mediaPath,
		mediaType: approval.mediaType,
		from: approval.from,
		to: approval.to,
		username: approval.username,
		tier: effectiveTier,
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
	// SECURITY: TOTP secrets must NOT be sent via Telegram.
	// Sending secrets over Telegram means anyone with chat history access can
	// recreate the TOTP device, completely defeating the purpose of 2FA.
	//
	// Instead, direct users to set up 2FA via CLI where the secret is displayed locally.

	const link = getIdentityLink(msg.chatId);
	if (!link) {
		await msg.reply(
			"You must link your identity first before setting up 2FA.\n\n" +
				"Ask an admin to run `telclaude link <user-id>` to generate a link code.",
		);
		return;
	}

	await msg.reply(
		"*Setting up Two-Factor Authentication*\n\n" +
			"For security reasons, TOTP secrets cannot be sent via Telegram " +
			"(anyone with access to chat history could recreate your 2FA device).\n\n" +
			"*To set up 2FA:*\n" +
			"1. Run this command on your local machine:\n" +
			"   `telclaude totp-setup`\n\n" +
			"2. Scan the QR code or enter the secret in your authenticator app\n\n" +
			"3. The CLI will verify your setup automatically\n\n" +
			"Once configured, you can approve requests by simply entering your 6-digit code.",
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
			"After you verify once, your session will be remembered for a while so you won't need to enter the code again for subsequent approvals.\n\n" +
			"Commands:\n" +
			"• `/2fa-logout` - End your session early\n" +
			"• `/disable-2fa` - Disable 2FA completely",
	);
}

async function handleDisable2FA(msg: TelegramInboundMessage): Promise<void> {
	const removed = await disableTOTP(msg.chatId);

	if (removed) {
		// Also invalidate any active TOTP session
		invalidateTOTPSessionForChat(msg.chatId);
		await msg.reply("2FA has been disabled for this chat.");
	} else {
		await msg.reply("2FA was not enabled for this chat.");
	}
}

async function handleLogout2FA(msg: TelegramInboundMessage): Promise<void> {
	const removed = invalidateTOTPSessionForChat(msg.chatId);

	if (removed) {
		await msg.reply("2FA session ended. You will need to verify TOTP for the next approval.");
	} else {
		await msg.reply("No active 2FA session found.");
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

	// Create a TOTP session after successful verification ("remember me" feature)
	const link = getIdentityLink(msg.chatId);
	if (link) {
		const sessionTtlMinutes = cfg.security?.totp?.sessionTtlMinutes ?? 240; // Default 4 hours
		const sessionTtlMs = sessionTtlMinutes * 60 * 1000;
		createTOTPSession(link.localUserId, sessionTtlMs);
		logger.info(
			{ chatId: msg.chatId, localUserId: link.localUserId, ttlMinutes: sessionTtlMinutes },
			"TOTP session created after successful verification",
		);
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
