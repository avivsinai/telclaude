import type { Bot, Context } from "grammy";

import { getChildLogger } from "../logging.js";
import { saveMediaStream } from "../media/store.js";
import { hasAdmin } from "../security/admin-claim.js";
import { type SecretFilterConfig, filterOutputWithConfig } from "../security/output-filter.js";
import { chatIdToString, normalizeTelegramId } from "../utils.js";
import { SECRET_BLOCKED_MESSAGE, convertAndSendMessage, sendMediaToChat } from "./outbound.js";
import { sanitizeAndSplitResponse } from "./sanitize.js";
import {
	type BotInfo,
	type TelegramInboundMessage,
	type TelegramListenerCloseReason,
	type TelegramMediaPayload,
	buildPushName,
	getFileIdFromMessage,
	getMediaTypeFromMessage,
	getMimeTypeFromMessage,
} from "./types.js";

export type InboxMonitorOptions = {
	bot: Bot;
	botInfo: BotInfo;
	verbose: boolean;
	dryRun?: boolean;
	onMessage: (msg: TelegramInboundMessage) => Promise<void>;
	allowedChats?: (number | string)[];
	secretFilterConfig?: SecretFilterConfig;
};

export type InboxMonitorHandle = {
	close: () => Promise<void>;
	onClose: Promise<TelegramListenerCloseReason>;
};

/**
 * Monitor incoming Telegram messages.
 */
export async function monitorTelegramInbox(
	options: InboxMonitorOptions,
): Promise<InboxMonitorHandle> {
	const {
		bot,
		botInfo,
		verbose,
		dryRun = false,
		onMessage,
		allowedChats,
		secretFilterConfig,
	} = options;
	const logger = getChildLogger({ module: "telegram-inbound" });
	const seen = new Set<string>();

	let onCloseResolve: ((reason: TelegramListenerCloseReason) => void) | null = null;
	const onClose = new Promise<TelegramListenerCloseReason>((resolve) => {
		onCloseResolve = resolve;
	});

	const botIdStr = chatIdToString(botInfo.id);

	// Helper to check if chat is allowed
	// SECURITY: Fails CLOSED - if no allowedChats configured, deny ALL
	// NOTE: allowedChats is REQUIRED even for bootstrap - this prevents random
	// users from claiming admin by messaging the bot before it's configured.
	const isChatAllowed = (chatId: number, chatType: string): boolean => {
		const normalizedChatId = normalizeTelegramId(chatId) ?? String(chatId);

		// First check: ALWAYS require allowedChats to be configured
		if (!allowedChats || allowedChats.length === 0) {
			// SECURITY: Empty allowedChats = deny all (fail closed)
			// This prevents accidental exposure if config is missing
			logger.warn(
				{ chatId },
				"DENIED: No allowedChats configured - denying all chats for security",
			);
			return false;
		}

		// Check if chat is in the allowlist
		const isInAllowlist = allowedChats.some((allowed) => {
			const normalizedAllowed = normalizeTelegramId(allowed);
			if (normalizedAllowed && normalizedChatId) {
				return normalizedAllowed === normalizedChatId;
			}
			if (typeof allowed === "number") return allowed === chatId;
			return String(allowed) === String(chatId);
		});

		if (!isInAllowlist) {
			// Chat not in allowlist - check if this is bootstrap scenario
			// Even during bootstrap, we require allowedChats to prevent random users
			// from claiming admin
			if (!hasAdmin() && chatType === "private") {
				logger.warn(
					{ chatId },
					"BOOTSTRAP DENIED: Private chat not in allowedChats. " +
						"Add your chat ID to allowedChats in config to enable admin claim.",
				);
			}
			return false;
		}

		// Chat is in allowlist - log bootstrap mode if applicable
		if (!hasAdmin() && chatType === "private") {
			logger.info(
				{ chatId },
				"BOOTSTRAP: Allowing private message for admin claim (chat in allowedChats)",
			);
		}

		return true;
	};

	// Helper to build inbound message
	const buildInboundMessage = async (
		ctx: Context,
		isEdited = false,
	): Promise<TelegramInboundMessage | null> => {
		const message = isEdited ? ctx.editedMessage : ctx.message;
		if (!message) return null;

		const chat = message.chat;
		const from = message.from;

		if (!isChatAllowed(chat.id, chat.type)) {
			if (verbose) {
				logger.debug({ chatId: chat.id }, "message from non-allowed chat, ignoring");
			}

			// Reduce surface area: immediately leave unauthorized group/supergroup/channel
			if (["group", "supergroup", "channel"].includes(chat.type)) {
				try {
					await bot.api.leaveChat(chat.id);
					logger.info({ chatId: chat.id, chatType: chat.type }, "left unauthorized chat");
				} catch (err) {
					logger.warn({ chatId: chat.id, error: String(err) }, "failed to leave chat");
				}
			}
			return null;
		}

		const chatId = chatIdToString(chat.id);
		const body = message.text || message.caption || "";

		// Download media if present
		let mediaPath: string | undefined;
		const mediaType = getMediaTypeFromMessage(message);
		let mediaFilePath: string | undefined;
		let mediaFileId: string | undefined;
		let mimeType = getMimeTypeFromMessage(message);

		const fileId = getFileIdFromMessage(message);
		if (fileId) {
			try {
				const file = await bot.api.getFile(fileId);
				if (file.file_path) {
					mediaFilePath = file.file_path;
					mediaFileId = fileId;
					const downloadUrl = `https://api.telegram.org/file/bot${bot.token}/${file.file_path}`;
					const response = await fetch(downloadUrl);
					if (!response.ok) {
						throw new Error(`HTTP ${response.status}: ${response.statusText}`);
					}
					// Stream directly to file to prevent OOM on large files
					const saved = await saveMediaStream(response, { mimeType, category: "incoming" });
					mediaPath = saved.path;
					mimeType = saved.contentType;
				}
			} catch (err) {
				logger.warn({ fileId, error: String(err) }, "failed to download media");
			}
		}

		const inboundMsg: TelegramInboundMessage = {
			id: String(message.message_id),
			chatId: chat.id,
			senderId: from?.id,
			from: chatId,
			to: botIdStr,
			body,
			pushName: from ? buildPushName(from) : undefined,
			username: from?.username,
			chatType: chat.type as "private" | "group" | "supergroup" | "channel",
			timestamp: message.date * 1000,
			isEdited,
			editedTimestamp: isEdited && message.edit_date ? message.edit_date * 1000 : undefined,
			replyToMessageId: message.reply_to_message?.message_id,
			mediaPath,
			mediaType,
			mediaFilePath,
			mediaFileId,
			mimeType,
			sendComposing: async () => {
				if (dryRun) {
					logger.debug({ chatId: chat.id }, "dry-run: would send typing action");
					return;
				}
				await bot.api.sendChatAction(chat.id, "typing");
			},
			reply: async (text: string, options?: { useMarkdown?: boolean }) => {
				// SECURITY: Filter for secret exfiltration BEFORE any processing
				// This is the last line of defense - ALL outbound text MUST pass through this
				// Use config-aware filtering to include additional patterns and entropy detection
				const filterResult = filterOutputWithConfig(text, secretFilterConfig);
				if (filterResult.blocked) {
					logger.error(
						{
							chatId: chat.id,
							matchCount: filterResult.matches.length,
							patterns: filterResult.matches.map((m) => m.pattern),
						},
						"BLOCKED: Secret exfiltration attempt detected in reply",
					);
					if (dryRun) {
						logger.warn(
							{ chatId: chat.id },
							"dry-run: reply blocked by secret filter; would send blocked notification",
						);
						return;
					}
					// Send blocked notification instead of the secret-containing message
					await bot.api.sendMessage(chat.id, SECRET_BLOCKED_MESSAGE);
					return;
				}

				// Sanitize and split response into Telegram-safe chunks
				const chunks = sanitizeAndSplitResponse(text);

				if (dryRun) {
					logger.info(
						{
							chatId: chat.id,
							useMarkdown: options?.useMarkdown ?? false,
							chunkCount: chunks.length,
							preview: chunks[0]?.slice(0, 200),
						},
						"dry-run: would send reply",
					);
					return;
				}

				// Send each chunk as a separate message with MarkdownV2 conversion
				for (let i = 0; i < chunks.length; i++) {
					const chunk = chunks[i];
					if (options?.useMarkdown) {
						// Legacy Markdown for system messages that are pre-formatted
						await bot.api.sendMessage(chat.id, chunk, { parse_mode: "Markdown" });
					} else {
						// Convert Claude's markdown to Telegram MarkdownV2
						await convertAndSendMessage(bot.api, chat.id, chunk, {
							replyToMessageId: i === 0 ? message.message_id : undefined,
						});
					}
				}
			},
			sendMedia: async (payload: TelegramMediaPayload) => {
				if (dryRun) {
					logger.info(
						{
							chatId: chat.id,
							type: payload.type,
							caption: "caption" in payload ? payload.caption?.slice(0, 200) : undefined,
						},
						"dry-run: would send media",
					);
					return;
				}
				await sendMediaToChat(bot.api, chat.id, payload);
			},
			raw: message,
		};

		return inboundMsg;
	};

	// Handle text messages
	logger.debug("registering message:text handler");
	bot.on("message:text", async (ctx) => {
		logger.debug(
			{ chatId: ctx.chat.id, messageId: ctx.message.message_id },
			"received text message",
		);
		const msgId = `${ctx.chat.id}:${ctx.message.message_id}`;
		if (seen.has(msgId)) return;
		seen.add(msgId);

		// Clean up old entries (keep last 1000)
		if (seen.size > 1000) {
			const entries = Array.from(seen);
			for (let i = 0; i < entries.length - 1000; i++) {
				seen.delete(entries[i]);
			}
		}

		const msg = await buildInboundMessage(ctx, false);
		if (!msg) return;

		try {
			await onMessage(msg);
		} catch (err) {
			logger.error({ msgId, error: String(err) }, "message handler failed");
		}
	});

	// Handle media messages
	bot.on(
		["message:photo", "message:document", "message:voice", "message:video", "message:audio"],
		async (ctx) => {
			const msgId = `${ctx.chat.id}:${ctx.message.message_id}`;
			if (seen.has(msgId)) return;
			seen.add(msgId);

			const msg = await buildInboundMessage(ctx, false);
			if (!msg) return;

			try {
				await onMessage(msg);
			} catch (err) {
				logger.error({ msgId, error: String(err) }, "media message handler failed");
			}
		},
	);

	// Handle edited messages
	bot.on("edited_message:text", async (ctx) => {
		const msg = await buildInboundMessage(ctx, true);
		if (!msg) return;

		try {
			await onMessage(msg);
		} catch (err) {
			logger.error({ error: String(err) }, "edited message handler failed");
		}
	});

	return {
		close: async () => {
			await bot.stop();
			onCloseResolve?.({ isTokenRevoked: false });
		},
		onClose,
	};
}
