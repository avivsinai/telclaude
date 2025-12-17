import fs from "node:fs";
import path from "node:path";
import type { Api, Bot, Context } from "grammy";
import { InputFile } from "grammy";
import type { Message } from "grammy/types";

import { getChildLogger } from "../logging.js";
import { type FilterResult, filterOutput } from "../security/output-filter.js";
import { stringToChatId } from "../utils.js";
import { sanitizeAndSplitResponse, stripMarkdown } from "./sanitize.js";
import type { TelegramMediaPayload } from "./types.js";

const logger = getChildLogger({ module: "telegram-outbound" });

// ═══════════════════════════════════════════════════════════════════════════════
// Output Filter Integration
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Error thrown when output contains detected secrets.
 */
export class SecretExfiltrationBlockedError extends Error {
	constructor(public readonly filterResult: FilterResult) {
		super(`Output blocked: detected ${filterResult.matches.length} potential secret(s)`);
		this.name = "SecretExfiltrationBlockedError";
	}
}

/**
 * Filter text before sending. Throws if secrets detected.
 *
 * SECURITY: This is the last line of defense against secret exfiltration.
 * All outbound text MUST pass through this filter.
 */
function filterBeforeSend(text: string): void {
	const result = filterOutput(text);
	if (result.blocked) {
		logger.error(
			{
				matchCount: result.matches.length,
				patterns: result.matches.map((m) => m.pattern),
			},
			"BLOCKED: Secret exfiltration attempt detected in outbound message",
		);
		throw new SecretExfiltrationBlockedError(result);
	}
}

/**
 * Replacement message sent when original is blocked.
 * Exported so inbound replies can stay consistent.
 */
export const SECRET_BLOCKED_MESSAGE =
	"⚠️ Response blocked by security filter.\n\n" +
	"The response contained what appears to be sensitive credentials " +
	"(API keys, tokens, or private keys). This is a security measure to " +
	"prevent accidental exposure of secrets.\n\n" +
	"If you need to work with credentials, ensure they are not included " +
	"in the response text.";

export type SendMessageOptions = {
	verbose?: boolean;
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
 * Long messages are automatically split into multiple messages.
 *
 * SECURITY: All text is filtered for secrets before sending.
 */
export async function sendMessageTelegram(
	bot: Bot,
	to: string | number,
	body: string,
	options: SendMessageOptions = {},
): Promise<SendResult> {
	const chatId = typeof to === "number" ? to : stringToChatId(to);

	// SECURITY: Filter output for secrets
	try {
		filterBeforeSend(body);
	} catch (err) {
		if (err instanceof SecretExfiltrationBlockedError) {
			// Send blocked notification instead
			const result = await bot.api.sendMessage(chatId, SECRET_BLOCKED_MESSAGE);
			logger.warn(
				{ chatId, messageId: result.message_id },
				"sent blocked notification (secrets detected)",
			);
			return { messageId: String(result.message_id), chatId };
		}
		throw err;
	}

	// Send typing indicator
	try {
		await bot.api.sendChatAction(chatId, "typing");
	} catch {
		// Non-fatal
	}

	// Handle media
	const mediaSource = options.mediaPath;
	if (mediaSource) {
		const chunks = sanitizeAndSplitResponse(options.parseMode ? body : stripMarkdown(body));
		const payload = inferMediaPayload(mediaSource, chunks[0]); // Use first chunk as caption
		const result = await sendMediaToChat(bot.api, chatId, payload);
		// Send remaining chunks as follow-up messages
		for (let i = 1; i < chunks.length; i++) {
			await bot.api.sendMessage(chatId, chunks[i], {
				parse_mode: options.parseMode,
			});
		}
		logger.info({ chatId, messageId: result.message_id, hasMedia: true }, "sent message");
		return { messageId: String(result.message_id), chatId };
	}

	// Sanitize and split text into chunks
	const chunks = sanitizeAndSplitResponse(options.parseMode ? body : stripMarkdown(body));

	// Send each chunk
	let lastResult: { message_id: number } | undefined;
	for (let i = 0; i < chunks.length; i++) {
		lastResult = await bot.api.sendMessage(chatId, chunks[i], {
			parse_mode: options.parseMode,
			reply_to_message_id: i === 0 ? options.replyToMessageId : undefined,
		});
	}

	logger.info(
		{ chatId, messageId: lastResult?.message_id, chunkCount: chunks.length },
		"sent message",
	);
	return { messageId: String(lastResult?.message_id ?? 0), chatId };
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
 * Maximum file size to scan for secrets (10 MB).
 * Files larger than this are not scanned to avoid memory issues.
 */
const MAX_FILE_SCAN_SIZE = 10 * 1024 * 1024;

/**
 * Scan file content for secrets before sending.
 * Returns true if the file is safe to send, false if secrets detected.
 */
function scanFileForSecrets(source: string | Buffer): { safe: boolean; reason?: string } {
	try {
		let content: string;

		const isProbablyText = (text: string): boolean => {
			if (!text.length) return true;
			const printable = text.split("").filter((c) => {
				const code = c.charCodeAt(0);
				return (
					code === 9 || // tab
					code === 10 || // lf
					code === 13 || // cr
					(code >= 32 && code <= 126)
				);
			}).length;
			return printable / text.length > 0.8;
		};

		if (Buffer.isBuffer(source)) {
			// Scan buffer content
			if (source.length > MAX_FILE_SCAN_SIZE) {
				logger.warn({ size: source.length }, "file too large to scan for secrets");
				return { safe: true }; // Allow but log warning
			}
			const text = source.toString("utf-8");
			if (!isProbablyText(text)) {
				logger.debug("buffer appears binary; skipping secret scan");
				return { safe: true };
			}
			content = text;
		} else if (!source.startsWith("http://") && !source.startsWith("https://")) {
			// Local file path - read and scan
			const absolutePath = path.isAbsolute(source) ? source : path.resolve(source);
			if (!fs.existsSync(absolutePath)) {
				return { safe: true }; // File doesn't exist yet, let Telegram handle the error
			}

			const stats = fs.statSync(absolutePath);
			if (stats.size > MAX_FILE_SCAN_SIZE) {
				logger.warn({ path: absolutePath, size: stats.size }, "file too large to scan for secrets");
				return { safe: true }; // Allow but log warning
			}
			const buf = fs.readFileSync(absolutePath);
			const text = buf.toString("utf-8");
			if (!isProbablyText(text)) {
				logger.debug({ path: absolutePath }, "file appears binary; skipping secret scan");
				return { safe: true };
			}
			content = text;
		} else {
			// URL - still check the URL string for obvious secrets, but avoid downloading
			const filterResult = filterOutput(source);
			if (filterResult.blocked) {
				logger.error(
					{ source, patterns: filterResult.matches.map((m) => m.pattern) },
					"BLOCKED: Secret-looking data detected in media URL",
				);
				return {
					safe: false,
					reason: `URL contains sensitive data: ${filterResult.matches.map((m) => m.pattern).join(", ")}`,
				};
			}

			logger.debug({ source }, "skipping content scan for remote URL (no download)");
			return { safe: true };
		}

		// Filter file content
		const filterResult = filterOutput(content);
		if (filterResult.blocked) {
			logger.error(
				{
					matchCount: filterResult.matches.length,
					patterns: filterResult.matches.map((m) => m.pattern),
				},
				"BLOCKED: Secret detected in file content",
			);
			return {
				safe: false,
				reason: `File contains sensitive data: ${filterResult.matches.map((m) => m.pattern).join(", ")}`,
			};
		}

		return { safe: true };
	} catch (err) {
		// If we can't read the file (binary, permission, etc.), allow it
		// The sandbox should have already prevented access to truly sensitive files
		logger.debug({ error: String(err) }, "could not scan file content (may be binary)");
		return { safe: true };
	}
}

/**
 * Send media payload to a chat.
 *
 * SECURITY: All captions AND file contents are filtered for secret exfiltration before sending.
 */
export async function sendMediaToChat(
	api: Api,
	chatId: number,
	payload: TelegramMediaPayload,
): Promise<Message> {
	// SECURITY: Scan file content for secrets before sending
	const fileScan = scanFileForSecrets(payload.source);
	if (!fileScan.safe) {
		logger.error(
			{ chatId, reason: fileScan.reason },
			"BLOCKED: File contains secrets, not sending",
		);
		// Send a blocked notification instead of the file
		return api.sendMessage(
			chatId,
			"⚠️ File blocked by security filter.\n\n" +
				"The file appears to contain sensitive credentials (API keys, tokens, or private keys). " +
				"This is a security measure to prevent accidental exposure of secrets.",
		);
	}

	// SECURITY: Filter caption for secrets before sending
	// Note: sticker type doesn't have caption, so we check if it exists
	let safeCaption: string | undefined;
	if ("caption" in payload && payload.caption) {
		const filterResult = filterOutput(payload.caption);
		if (filterResult.blocked) {
			logger.error(
				{
					chatId,
					matchCount: filterResult.matches.length,
					patterns: filterResult.matches.map((m) => m.pattern),
				},
				"BLOCKED: Secret exfiltration attempt detected in media caption",
			);
			// Replace caption with blocked message, but still send the media
			safeCaption = "[Caption blocked - contained sensitive data]";
		} else {
			safeCaption = payload.caption;
		}
	}

	const source = createInputFile(payload.source);

	switch (payload.type) {
		case "photo":
			return api.sendPhoto(chatId, source, { caption: safeCaption });
		case "document":
			return api.sendDocument(chatId, source, { caption: safeCaption });
		case "voice":
			return api.sendVoice(chatId, source, { caption: safeCaption });
		case "video":
			return api.sendVideo(chatId, source, { caption: safeCaption });
		case "audio":
			return api.sendAudio(chatId, source, {
				caption: safeCaption,
				title: payload.title,
				performer: payload.performer,
			});
		case "sticker":
			return api.sendSticker(chatId, source);
		case "animation":
			return api.sendAnimation(chatId, source, { caption: safeCaption });
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
		// SECURITY: Filter all text output
		const textToFilter = options.text ?? options.caption;
		if (textToFilter) {
			try {
				filterBeforeSend(textToFilter);
			} catch (err) {
				if (err instanceof SecretExfiltrationBlockedError) {
					const result = await bot.api.sendMessage(options.chatId, SECRET_BLOCKED_MESSAGE);
					return { success: true, messageId: result.message_id };
				}
				throw err;
			}
		}

		if (options.mediaPath) {
			const payload = inferMediaPayload(options.mediaPath, options.caption ?? options.text);
			const result = await sendMediaToChat(bot.api, options.chatId, payload);
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

// ═══════════════════════════════════════════════════════════════════════════════
// Secure Reply Layer
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Secure layer for ctx.reply() that filters output for secrets.
 * Long messages are automatically split into multiple messages.
 *
 * SECURITY: Use this instead of ctx.reply() to ensure all outbound
 * messages are filtered for secret exfiltration.
 *
 * @param ctx - grammY context
 * @param text - Message text to send
 * @param options - Optional reply parameters
 * @returns Last message result or blocked notification
 */
export async function safeReply(
	ctx: Context,
	text: string,
	options?: Parameters<Context["reply"]>[1],
): Promise<Message> {
	// SECURITY: Filter output for secrets
	try {
		filterBeforeSend(text);
	} catch (err) {
		if (err instanceof SecretExfiltrationBlockedError) {
			logger.warn(
				{ chatId: ctx.chat?.id, patterns: err.filterResult.matches.map((m) => m.pattern) },
				"BLOCKED: Secret detected in reply, sending blocked notification",
			);
			return ctx.reply(SECRET_BLOCKED_MESSAGE);
		}
		throw err;
	}

	// Sanitize and split into chunks
	const chunks = sanitizeAndSplitResponse(text);

	// Send each chunk
	let lastResult: Message | undefined;
	for (const chunk of chunks) {
		lastResult = await ctx.reply(chunk, options);
	}

	// chunks is always non-empty, so lastResult is always set
	if (!lastResult) {
		throw new Error("No message chunks to send");
	}
	return lastResult;
}

/**
 * Re-export filter utilities for use in other modules.
 */
export { filterOutput, type FilterResult } from "../security/output-filter.js";
