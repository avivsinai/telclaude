import fs from "node:fs";
import path from "node:path";
import type { Api, Bot } from "grammy";
import { InputFile } from "grammy";
import type { Message } from "grammy/types";

import { getChildLogger } from "../logging.js";
import { stringToChatId } from "../utils.js";
import type { TelegramMediaPayload } from "./types.js";

export type SendMessageOptions = {
	verbose?: boolean;
	mediaUrl?: string;
	mediaPath?: string;
	parseMode?: "Markdown" | "HTML" | "MarkdownV2";
	replyToMessageId?: number;
};

export type SendResult = {
	messageId: string;
	chatId: number;
};

/**
 * Send a message to a Telegram chat.
 */
export async function sendMessageTelegram(
	bot: Bot,
	to: string | number,
	body: string,
	options: SendMessageOptions = {},
): Promise<SendResult> {
	const logger = getChildLogger({ module: "telegram-outbound" });
	const chatId = typeof to === "number" ? to : stringToChatId(to);

	// Send typing indicator
	try {
		await bot.api.sendChatAction(chatId, "typing");
	} catch {
		// Non-fatal
	}

	// Handle media
	const mediaSource = options.mediaPath ?? options.mediaUrl;
	if (mediaSource) {
		const payload = inferMediaPayload(mediaSource, body);
		const result = await sendMediaToChat(bot.api, chatId, payload);
		logger.info({ chatId, messageId: result.message_id, hasMedia: true }, "sent message");
		return { messageId: String(result.message_id), chatId };
	}

	// Send text message
	const result = await bot.api.sendMessage(chatId, body, {
		parse_mode: options.parseMode ?? "Markdown",
		reply_to_message_id: options.replyToMessageId,
	});

	logger.info({ chatId, messageId: result.message_id }, "sent message");
	return { messageId: String(result.message_id), chatId };
}

/**
 * Infer media payload type from file path or URL.
 */
function inferMediaPayload(source: string, caption?: string): TelegramMediaPayload {
	const ext = path.extname(source).toLowerCase();

	if ([".jpg", ".jpeg", ".png", ".gif", ".webp"].includes(ext)) {
		return { type: "photo", source, caption };
	}
	if ([".mp4", ".webm", ".mov", ".avi"].includes(ext)) {
		return { type: "video", source, caption };
	}
	if ([".mp3", ".m4a", ".wav", ".flac"].includes(ext)) {
		return { type: "audio", source, caption };
	}
	if ([".ogg", ".oga"].includes(ext)) {
		return { type: "voice", source, caption };
	}
	if ([".webp", ".tgs"].includes(ext) && !caption) {
		return { type: "sticker", source };
	}

	return { type: "document", source, caption };
}

/**
 * Send media payload to a chat.
 */
export async function sendMediaToChat(
	api: Api,
	chatId: number,
	payload: TelegramMediaPayload,
): Promise<Message> {
	const source = createInputFile(payload.source);

	switch (payload.type) {
		case "photo":
			return api.sendPhoto(chatId, source, { caption: payload.caption });
		case "document":
			return api.sendDocument(chatId, source, { caption: payload.caption });
		case "voice":
			return api.sendVoice(chatId, source, { caption: payload.caption });
		case "video":
			return api.sendVideo(chatId, source, { caption: payload.caption });
		case "audio":
			return api.sendAudio(chatId, source, {
				caption: payload.caption,
				title: payload.title,
				performer: payload.performer,
			});
		case "sticker":
			return api.sendSticker(chatId, source);
		case "animation":
			return api.sendAnimation(chatId, source, { caption: payload.caption });
		default:
			throw new Error(`Unsupported media type: ${(payload as { type: string }).type}`);
	}
}

/**
 * Create InputFile from source (path, URL, or buffer).
 */
export function createInputFile(source: string | Buffer): InputFile {
	if (Buffer.isBuffer(source)) {
		return new InputFile(source);
	}

	// URL
	if (source.startsWith("http://") || source.startsWith("https://")) {
		return new InputFile({ url: source });
	}

	// Local file path
	const absolutePath = path.isAbsolute(source) ? source : path.resolve(source);
	if (fs.existsSync(absolutePath)) {
		return new InputFile(absolutePath);
	}

	// Assume it's a file_id
	return new InputFile(source);
}

/**
 * Send typing indicator (chat action).
 */
export async function sendTypingIndicator(bot: Bot, chatId: number): Promise<void> {
	await bot.api.sendChatAction(chatId, "typing");
}

/**
 * Get bot info.
 */
export async function getBotInfo(bot: Bot) {
	return bot.api.getMe();
}

/**
 * Send a message using just a token (creates temporary bot instance).
 */
export type SendTelegramMessageOptions = {
	token: string;
	chatId: number;
	text?: string;
	mediaPath?: string;
	caption?: string;
};

export type SendTelegramMessageResult = {
	success: boolean;
	messageId?: number;
	error?: string;
};

export async function sendTelegramMessage(
	options: SendTelegramMessageOptions,
): Promise<SendTelegramMessageResult> {
	const { Bot } = await import("grammy");
	const bot = new Bot(options.token);

	try {
		if (options.mediaPath) {
			const payload = inferMediaPayload(options.mediaPath, options.caption ?? options.text);
			const result = await sendMediaToChat(
				bot.api,
				options.chatId,
				payload as TelegramMediaPayload,
			);
			return { success: true, messageId: result.message_id };
		}

		if (options.text) {
			const result = await bot.api.sendMessage(options.chatId, options.text);
			return { success: true, messageId: result.message_id };
		}

		return { success: false, error: "No text or media provided" };
	} catch (err) {
		return { success: false, error: String(err) };
	}
}
