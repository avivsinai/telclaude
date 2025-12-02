import type { Bot, Context } from "grammy";

import { getChildLogger } from "../logging.js";
import { saveMediaStream } from "../media/store.js";
import { chatIdToString } from "../utils.js";
import { sendMediaToChat } from "./outbound.js";
import { sanitizeClaudeResponse } from "./sanitize.js";
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
	onMessage: (msg: TelegramInboundMessage) => Promise<void>;
	allowedChats?: (number | string)[];
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
	const { bot, botInfo, verbose, onMessage, allowedChats } = options;
	const logger = getChildLogger({ module: "telegram-inbound" });
	const seen = new Set<string>();

	let onCloseResolve: ((reason: TelegramListenerCloseReason) => void) | null = null;
	const onClose = new Promise<TelegramListenerCloseReason>((resolve) => {
		onCloseResolve = resolve;
	});

	const botIdStr = chatIdToString(botInfo.id);

	// Helper to check if chat is allowed
	const isChatAllowed = (chatId: number): boolean => {
		if (!allowedChats?.length) return true;
		return allowedChats.some((allowed) => {
			if (typeof allowed === "number") return allowed === chatId;
			return String(allowed) === String(chatId);
		});
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

		if (!isChatAllowed(chat.id)) {
			if (verbose) {
				logger.debug({ chatId: chat.id }, "message from non-allowed chat, ignoring");
			}
			return null;
		}

		const chatId = chatIdToString(chat.id);
		const body = message.text || message.caption || "";

		// Download media if present
		let mediaPath: string | undefined;
		const mediaType = getMediaTypeFromMessage(message);
		let mediaUrl: string | undefined;
		let mimeType = getMimeTypeFromMessage(message);

		const fileId = getFileIdFromMessage(message);
		if (fileId) {
			try {
				const file = await bot.api.getFile(fileId);
				if (file.file_path) {
					mediaUrl = `https://api.telegram.org/file/bot${bot.token}/${file.file_path}`;
					const response = await fetch(mediaUrl);
					if (!response.ok) {
						throw new Error(`HTTP ${response.status}: ${response.statusText}`);
					}
					// Stream directly to file to prevent OOM on large files
					const saved = await saveMediaStream(response, mimeType);
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
			from: chatId,
			to: botIdStr,
			body,
			pushName: from ? buildPushName(from) : undefined,
			username: from?.username,
			timestamp: message.date * 1000,
			isEdited,
			editedTimestamp: isEdited && message.edit_date ? message.edit_date * 1000 : undefined,
			replyToMessageId: message.reply_to_message?.message_id,
			mediaPath,
			mediaType,
			mediaUrl,
			mimeType,
			sendComposing: async () => {
				await bot.api.sendChatAction(chat.id, "typing");
			},
			reply: async (text: string, options?: { useMarkdown?: boolean }) => {
				// Default to plain text for safety (prevents markdown injection)
				// Sanitize all responses to remove dangerous characters
				const sanitized = sanitizeClaudeResponse(text);
				if (options?.useMarkdown) {
					// Only use markdown when explicitly requested (for system messages)
					await bot.api.sendMessage(chat.id, sanitized, { parse_mode: "Markdown" });
				} else {
					// Plain text - no injection possible
					await bot.api.sendMessage(chat.id, sanitized);
				}
			},
			sendMedia: async (payload: TelegramMediaPayload) => {
				await sendMediaToChat(bot.api, chat.id, payload);
			},
			raw: message,
		};

		return inboundMsg;
	};

	// Handle text messages
	bot.on("message:text", async (ctx) => {
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
