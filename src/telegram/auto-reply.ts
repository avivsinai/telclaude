import crypto from "node:crypto";
import { run } from "@grammyjs/runner";
import type { Bot } from "grammy";

import { runCommandReply } from "../auto-reply/command-reply.js";
import type { TemplateContext } from "../auto-reply/templating.js";
import { type TelclaudeConfig, loadConfig } from "../config/config.js";
import {
	DEFAULT_IDLE_MINUTES,
	type SessionEntry,
	deriveSessionKey,
	loadSessionStore,
	resolveStorePath,
	saveSessionStore,
} from "../config/sessions.js";
import { getChildLogger } from "../logging.js";
import { runCommandWithTimeout } from "../process/exec.js";
import type { RuntimeEnv } from "../runtime.js";
import { type AuditLogger, createAuditLogger } from "../security/audit.js";
import { type SecurityObserver, createObserver } from "../security/observer.js";
import { getClaudeFlagsForTier, getUserPermissionTier } from "../security/permissions.js";
import { type RateLimiter, createRateLimiter } from "../security/rate-limit.js";

import { createTelegramBot } from "./client.js";
import { monitorTelegramInbox } from "./inbound.js";
import { computeBackoff, resolveReconnectPolicy, sleepWithAbort } from "./reconnect.js";
import type { TelegramInboundMessage } from "./types.js";

const logger = getChildLogger({ module: "telegram-auto-reply" });

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

	// Initialize security components
	const observer = createObserver({
		enabled: cfg.security?.observer?.enabled ?? true,
		maxLatencyMs: cfg.security?.observer?.maxLatencyMs ?? 2000,
		dangerThreshold: cfg.security?.observer?.dangerThreshold ?? 0.7,
		fallbackOnTimeout: cfg.security?.observer?.fallbackOnTimeout ?? "block",
		apiKey: process.env.ANTHROPIC_API_KEY,
	});

	const rateLimiter = createRateLimiter(cfg.security);
	const auditLogger = createAuditLogger({
		enabled: cfg.security?.audit?.enabled ?? true,
		logFile: cfg.security?.audit?.logFile,
	});

	// Track recently sent messages for echo detection
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

			// Start the bot
			const runner = run(bot);

			console.log("Listening for Telegram messages. Ctrl+C to stop.");

			// Reset reconnect attempts on successful connection
			reconnectAttempts = 0;

			// Wait for close or abort
			const closeReason = await Promise.race([
				onClose,
				abortSignal
					? new Promise<"aborted">((resolve) =>
							abortSignal.addEventListener("abort", () => resolve("aborted")),
						)
					: new Promise<never>(() => {}),
			]);

			// Stop the bot
			runner.stop();
			await close();

			if (closeReason === "aborted" || abortSignal?.aborted) {
				logger.info("monitor aborted by signal");
				break;
			}

			// Handle reconnection
			if (!keepAlive) break;

			reconnectAttempts++;
			if (reconnectPolicy.maxAttempts > 0 && reconnectAttempts >= reconnectPolicy.maxAttempts) {
				throw new Error(`Max reconnect attempts (${reconnectPolicy.maxAttempts}) reached`);
			}

			const delay = computeBackoff(reconnectPolicy, reconnectAttempts);
			console.log(`Reconnecting in ${delay}ms (attempt ${reconnectAttempts})...`);
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
			console.error(`Error: ${err}. Reconnecting in ${delay}ms...`);
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
	const startTime = Date.now();

	// Echo detection - skip if we sent this message
	if (recentlySent.has(msg.body)) {
		recentlySent.delete(msg.body);
		logger.debug({ msgId: msg.id }, "echo detected, skipping");
		return;
	}

	// Get user's permission tier
	const tier = getUserPermissionTier(msg.chatId, cfg.security);

	// Check rate limits
	const rateLimitResult = await rateLimiter.checkLimit(userId, tier);
	if (!rateLimitResult.allowed) {
		logger.info({ userId, tier }, "rate limited");
		await auditLogger.logRateLimited(userId, msg.chatId, tier);
		await msg.reply(
			`Rate limit exceeded. Please wait ${Math.ceil(rateLimitResult.resetMs / 1000)} seconds.`,
		);
		return;
	}

	// Security observer check
	const observerResult = await observer.analyze(msg.body, {
		permissionTier: tier,
	});

	if (observerResult.classification === "BLOCK") {
		logger.warn({ userId, reason: observerResult.reason }, "message blocked by security observer");
		await auditLogger.logBlocked(
			{
				timestamp: new Date(),
				requestId,
				telegramUserId: userId,
				telegramUsername: msg.username,
				chatId: msg.chatId,
				messagePreview: msg.body.slice(0, 100),
				observerClassification: observerResult.classification,
				observerConfidence: observerResult.confidence,
				permissionTier: tier,
			},
			observerResult.reason ?? "Blocked by security observer",
		);
		await msg.reply(
			`This request was blocked for security reasons. ${observerResult.reason ? `Reason: ${observerResult.reason}` : ""}`,
		);
		return;
	}

	if (observerResult.classification === "WARN") {
		logger.info({ userId, reason: observerResult.reason }, "message flagged with warning");
	}

	// Get reply configuration
	const replyConfig = cfg.inbound?.reply;
	if (!replyConfig || replyConfig.mode !== "command" || !replyConfig.command?.length) {
		logger.debug("no reply config, skipping");
		return;
	}

	// Send typing indicator
	await msg.sendComposing();

	// Session handling
	const sessionConfig = replyConfig.session;
	const storePath = resolveStorePath(sessionConfig?.store);
	const store = loadSessionStore(storePath);
	const scope = sessionConfig?.scope ?? "per-sender";
	const idleMinutes = sessionConfig?.idleMinutes ?? DEFAULT_IDLE_MINUTES;
	const resetTriggers = sessionConfig?.resetTriggers ?? ["/new"];

	const sessionKey = deriveSessionKey(scope, { From: msg.from });
	const existingSession = store[sessionKey];
	const now = Date.now();

	// Check for reset triggers
	const shouldReset =
		resetTriggers.some((t) => msg.body.trim().toLowerCase().startsWith(t.toLowerCase())) ||
		(existingSession && now - existingSession.updatedAt > idleMinutes * 60 * 1000);

	let sessionEntry: SessionEntry;
	let isNewSession: boolean;
	let isFirstTurnInSession: boolean;

	if (!existingSession || shouldReset) {
		sessionEntry = {
			sessionId: crypto.randomUUID(),
			updatedAt: now,
			systemSent: false,
		};
		isNewSession = true;
		isFirstTurnInSession = true;
	} else {
		sessionEntry = existingSession;
		isNewSession = false;
		isFirstTurnInSession = false;
	}

	// Build template context
	const templatingCtx: TemplateContext = {
		Body: msg.body,
		BodyStripped: msg.body.trim(),
		From: msg.from,
		To: msg.to,
		MessageId: msg.id,
		MediaPath: msg.mediaPath,
		MediaUrl: msg.mediaUrl,
		MediaType: msg.mediaType,
		Username: msg.username,
		SessionId: sessionEntry.sessionId,
		IsNewSession: isNewSession ? "true" : "false",
	};

	// Get Claude flags for tier
	const tierFlags = getClaudeFlagsForTier(tier);

	// Modify command to include tier restrictions
	const modifiedCommand = [...(replyConfig.command ?? [])];
	if (tier !== "FULL_ACCESS" && modifiedCommand.length > 0) {
		// Insert tier flags after the command name
		modifiedCommand.splice(1, 0, ...tierFlags);
	}

	const timeoutSeconds = replyConfig.timeoutSeconds ?? 600;
	const timeoutMs = timeoutSeconds * 1000;

	// Set up typing indicator refresh
	const typingInterval = (replyConfig.typingIntervalSeconds ?? 8) * 1000;
	const typingTimer = setInterval(() => {
		msg.sendComposing().catch(() => {});
	}, typingInterval);

	try {
		const result = await runCommandReply({
			reply: { ...replyConfig, mode: "command", command: modifiedCommand },
			templatingCtx,
			sendSystemOnce: sessionConfig?.sendSystemOnce ?? false,
			isNewSession,
			isFirstTurnInSession,
			systemSent: sessionEntry.systemSent ?? false,
			timeoutMs,
			timeoutSeconds,
			commandRunner: runCommandWithTimeout,
		});

		// Check if command failed (non-zero exit or killed)
		const commandFailed =
			result.meta?.exitCode !== undefined && result.meta.exitCode !== 0 && !result.payload?.text;
		const commandKilled = result.meta?.killed && !result.payload?.text;

		if (commandFailed || commandKilled) {
			// Command failed - notify user and log as error
			const exitInfo = result.meta?.exitCode
				? `exit code ${result.meta.exitCode}`
				: result.meta?.signal
					? `signal ${result.meta.signal}`
					: "unknown error";
			logger.warn(
				{ requestId, exitCode: result.meta?.exitCode, signal: result.meta?.signal },
				"command failed",
			);
			await msg.reply(`Command failed (${exitInfo}). Please try again or rephrase your request.`);
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
				executionTimeMs: Date.now() - startTime,
				outcome: "error",
				errorType: `command_failed:${exitInfo}`,
			});
			return;
		}

		if (result.payload?.text || result.payload?.mediaUrl) {
			// Send reply
			if (result.payload.mediaUrl) {
				await msg.sendMedia({
					type: "document",
					source: result.payload.mediaUrl,
					caption: result.payload.text,
				});
			} else if (result.payload.text) {
				await msg.reply(result.payload.text);
			}

			// Track for echo detection
			if (result.payload?.text) {
				const textToTrack = result.payload.text;
				recentlySent.add(textToTrack);
				// Clean up after 30 seconds
				setTimeout(() => recentlySent.delete(textToTrack), 30000);
			}

			// Update session
			sessionEntry.updatedAt = Date.now();
			sessionEntry.systemSent = true;
			store[sessionKey] = sessionEntry;
			await saveSessionStore(storePath, store);
		}

		// Log audit entry
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
			executionTimeMs: Date.now() - startTime,
			outcome: "success",
		});
	} catch (err) {
		logger.error({ requestId, error: String(err) }, "reply failed");
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
			executionTimeMs: Date.now() - startTime,
			outcome: "error",
			errorType: String(err),
		});

		await msg.reply("An error occurred while processing your request. Please try again.");
	} finally {
		clearInterval(typingTimer);
	}
}
