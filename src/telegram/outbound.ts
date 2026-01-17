import fs from "node:fs";
import path from "node:path";
import type { Api, Bot, Context } from "grammy";
import { InputFile } from "grammy";
import type { Message } from "grammy/types";
import { convert as convertToTelegramMarkdown } from "telegram-markdown-v2";

import { getChildLogger } from "../logging.js";
import {
	type FilterResult,
	filterOutput,
	filterOutputWithConfig,
	redactSecrets,
	redactSecretsWithConfig,
	type SecretFilterConfig,
} from "../security/output-filter.js";
import { recordBotMessage } from "../storage/reactions.js";
import { stringToChatId } from "../utils.js";
import { sanitizeAndSplitResponse } from "./sanitize.js";
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
function filterBeforeSend(text: string, secretFilterConfig?: SecretFilterConfig): void {
	const result = secretFilterConfig
		? filterOutputWithConfig(text, secretFilterConfig)
		: filterOutput(text);
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
	secretFilterConfig?: SecretFilterConfig;
};

export type SendResult = {
	messageId: string;
	chatId: number;
};

/**
 * Send a message with MarkdownV2, falling back to plain text on parse errors.
 *
 * Telegram rejects malformed markdown (e.g., unclosed bold tags from LLM output),
 * so we catch parse errors and retry without formatting. This is the recommended
 * approach per Telegram Bot API best practices.
 *
 * @see https://core.telegram.org/bots/api#markdownv2-style
 */
async function sendWithMarkdownFallback(
	api: Api,
	chatId: number,
	formattedText: string,
	rawText: string,
	parseMode: "Markdown" | "HTML" | "MarkdownV2",
	replyToMessageId?: number,
): Promise<Message> {
	try {
		return await api.sendMessage(chatId, formattedText, {
			parse_mode: parseMode,
			reply_to_message_id: replyToMessageId,
		});
	} catch (err) {
		const errStr = String(err);
		if (errStr.includes("can't parse entities") || errStr.includes("Bad Request")) {
			logger.warn({ chatId, error: errStr }, "MarkdownV2 parse failed, falling back to plain text");
			return api.sendMessage(chatId, rawText, {
				reply_to_message_id: replyToMessageId,
			});
		}
		throw err;
	}
}

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
		filterBeforeSend(body, options.secretFilterConfig);
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

	const effectiveParseMode = options.parseMode ?? "MarkdownV2";
	// Convert to MarkdownV2 unless caller explicitly wants HTML or legacy Markdown.
	// For those modes, caller is responsible for proper formatting/escaping.
	const shouldConvertMarkdown = options.parseMode !== "HTML" && options.parseMode !== "Markdown";

	// Split BEFORE markdown conversion to avoid breaking escape sequences mid-chunk.
	// Each chunk is then converted independently to ensure valid MarkdownV2.
	const rawChunks = sanitizeAndSplitResponse(body);
	const formattedChunks = shouldConvertMarkdown
		? rawChunks.map((chunk) => convertToTelegramMarkdown(chunk))
		: rawChunks;

	// Handle media
	const mediaSource = options.mediaPath;
	if (mediaSource) {
		const payload = inferMediaPayload(mediaSource, formattedChunks[0]); // Use first chunk as caption
		// Note: sendMediaToChat already calls recordBotMessage internally
		const result = await sendMediaToChat(
			bot.api,
			chatId,
			payload,
			effectiveParseMode,
			options.secretFilterConfig,
		);
		// Send remaining chunks as follow-up messages
		for (let i = 1; i < formattedChunks.length; i++) {
			const followUp = await sendWithMarkdownFallback(
				bot.api,
				chatId,
				formattedChunks[i],
				rawChunks[i],
				effectiveParseMode,
			);
			recordBotMessage(chatId, followUp.message_id);
		}
		logger.info({ chatId, messageId: result.message_id, hasMedia: true }, "sent message");
		return { messageId: String(result.message_id), chatId };
	}

	// Send each chunk
	let lastResult: { message_id: number } | undefined;
	for (let i = 0; i < formattedChunks.length; i++) {
		lastResult = await sendWithMarkdownFallback(
			bot.api,
			chatId,
			formattedChunks[i],
			rawChunks[i],
			effectiveParseMode,
			i === 0 ? options.replyToMessageId : undefined,
		);
		// Track for reaction context
		recordBotMessage(chatId, lastResult.message_id);
	}

	logger.info(
		{ chatId, messageId: lastResult?.message_id, chunkCount: formattedChunks.length },
		"sent message",
	);
	return { messageId: String(lastResult?.message_id ?? 0), chatId };
}

/**
 * Convert text to MarkdownV2 and send as a single message.
 * Used by inbound.ts reply function to ensure consistent markdown handling.
 *
 * Falls back to plain text if Telegram rejects the MarkdownV2 formatting
 * (e.g., unclosed bold/italic tags from Claude's response).
 *
 * @param api - Telegram Bot API instance
 * @param chatId - Target chat ID
 * @param text - Text to convert and send (already sanitized and split)
 * @param options - Optional parse mode override and reply settings
 */
export async function convertAndSendMessage(
	api: Api,
	chatId: number,
	text: string,
	options?: {
		parseMode?: "Markdown" | "HTML" | "MarkdownV2";
		replyToMessageId?: number;
		secretFilterConfig?: SecretFilterConfig;
	},
): Promise<Message> {
	// SECURITY: Filter output for secrets
	try {
		filterBeforeSend(text, options?.secretFilterConfig);
	} catch (err) {
		if (err instanceof SecretExfiltrationBlockedError) {
			logger.warn(
				{ chatId, patterns: err.filterResult.matches.map((m) => m.pattern) },
				"BLOCKED: Secret detected in outbound message, sending blocked notification",
			);
			return api.sendMessage(chatId, SECRET_BLOCKED_MESSAGE, {
				reply_to_message_id: options?.replyToMessageId,
			});
		}
		throw err;
	}

	const parseMode = options?.parseMode ?? "MarkdownV2";
	// Convert to MarkdownV2 unless caller explicitly wants HTML or legacy Markdown
	const shouldConvert = parseMode === "MarkdownV2";
	const convertedText = shouldConvert ? convertToTelegramMarkdown(text) : text;

	const result = await sendWithMarkdownFallback(
		api,
		chatId,
		convertedText,
		text,
		parseMode,
		options?.replyToMessageId,
	);
	// Track for reaction context
	recordBotMessage(chatId, result.message_id);
	return result;
}

/**
 * Infer media payload type from file path or URL.
 * Handles URLs with querystrings by extracting pathname first.
 */
function inferMediaPayload(source: string, caption?: string): TelegramMediaPayload {
	// For URLs, extract pathname to get correct extension (ignore querystring)
	let pathForExt = source;
	if (source.startsWith("http://") || source.startsWith("https://")) {
		try {
			pathForExt = new URL(source).pathname;
		} catch {
			// If URL parsing fails, use original source
		}
	}
	const ext = path.extname(pathForExt).toLowerCase();

	if ([".jpg", ".jpeg", ".png", ".gif", ".webp"].includes(ext)) {
		return { type: "photo", source, caption };
	}
	if ([".mp4", ".webm", ".mov", ".avi"].includes(ext)) {
		return { type: "video", source, caption };
	}
	// Audio formats including AAC and Opus (TTS supports these)
	if ([".mp3", ".m4a", ".wav", ".flac", ".aac", ".opus"].includes(ext)) {
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
 * Check if a buffer is likely text (not binary).
 * Uses efficient sampling and handles UTF-8 properly.
 */
function isProbablyText(buf: Buffer): boolean {
	if (buf.length === 0) return true;

	// Sample up to 8KB for performance on large files
	const sampleSize = Math.min(buf.length, 8192);
	let nullCount = 0;
	let controlCount = 0;

	for (let i = 0; i < sampleSize; i++) {
		const byte = buf[i];
		// Null bytes are strong indicator of binary
		if (byte === 0) {
			nullCount++;
			// More than 1% null bytes = definitely binary
			if (nullCount > sampleSize * 0.01) return false;
		}
		// Count non-text control characters (0x00-0x08, 0x0E-0x1F except common ones)
		// Excludes: tab(9), lf(10), cr(13), and allows UTF-8 continuation bytes (0x80-0xFF)
		if (byte < 9 || (byte > 13 && byte < 32 && byte !== 27)) {
			controlCount++;
		}
	}

	// If more than 10% are problematic control chars, likely binary
	return controlCount / sampleSize < 0.1;
}

/**
 * Scan file content for secrets before sending.
 * Returns true if the file is safe to send, false if secrets detected.
 *
 * Uses async I/O to avoid blocking the event loop on large files.
 */
function redactForLog(text: string, secretFilterConfig?: SecretFilterConfig): string {
	return secretFilterConfig
		? redactSecretsWithConfig(text, secretFilterConfig)
		: redactSecrets(text);
}

async function scanFileForSecrets(
	source: string | Buffer,
	secretFilterConfig?: SecretFilterConfig,
): Promise<{ safe: boolean; reason?: string }> {
	try {
		let content: string;

		if (Buffer.isBuffer(source)) {
			// Scan buffer content
			if (source.length > MAX_FILE_SCAN_SIZE) {
				logger.warn({ size: source.length }, "file too large to scan for secrets");
				return { safe: true }; // Allow but log warning
			}
			// Check binary before converting to string (more efficient)
			if (!isProbablyText(source)) {
				logger.debug("buffer appears binary; skipping secret scan");
				return { safe: true };
			}
			content = source.toString("utf-8");
		} else if (!source.startsWith("http://") && !source.startsWith("https://")) {
			// Local file path - read and scan (async to avoid blocking event loop)
			const absolutePath = path.isAbsolute(source) ? source : path.resolve(source);
			try {
				await fs.promises.access(absolutePath, fs.constants.R_OK);
			} catch {
				return { safe: true }; // File doesn't exist or not readable, let Telegram handle the error
			}

			const stats = await fs.promises.stat(absolutePath);
			if (stats.size > MAX_FILE_SCAN_SIZE) {
				logger.warn({ path: absolutePath, size: stats.size }, "file too large to scan for secrets");
				return { safe: true }; // Allow but log warning
			}
			const buf = await fs.promises.readFile(absolutePath);
			// Check binary before converting to string (more efficient)
			if (!isProbablyText(buf)) {
				logger.debug({ path: absolutePath }, "file appears binary; skipping secret scan");
				return { safe: true };
			}
			content = buf.toString("utf-8");
		} else {
			// URL - still check the URL string for obvious secrets, but avoid downloading
			const filterResult = secretFilterConfig
				? filterOutputWithConfig(source, secretFilterConfig)
				: filterOutput(source);
			if (filterResult.blocked) {
				logger.error(
					{
						source: redactForLog(source, secretFilterConfig),
						patterns: filterResult.matches.map((m) => m.pattern),
					},
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
		const filterResult = secretFilterConfig
			? filterOutputWithConfig(content, secretFilterConfig)
			: filterOutput(content);
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
	parseMode?: "Markdown" | "MarkdownV2" | "HTML",
	secretFilterConfig?: SecretFilterConfig,
): Promise<Message> {
	// SECURITY: Scan file content for secrets before sending (async to avoid blocking)
	const fileScan = await scanFileForSecrets(payload.source, secretFilterConfig);
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
		const filterResult = secretFilterConfig
			? filterOutputWithConfig(payload.caption, secretFilterConfig)
			: filterOutput(payload.caption);
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

	let result: Message;
	switch (payload.type) {
		case "photo":
			result = await api.sendPhoto(chatId, source, { caption: safeCaption, parse_mode: parseMode });
			break;
		case "document":
			result = await api.sendDocument(chatId, source, {
				caption: safeCaption,
				parse_mode: parseMode,
			});
			break;
		case "voice":
			result = await api.sendVoice(chatId, source, { caption: safeCaption, parse_mode: parseMode });
			break;
		case "video":
			result = await api.sendVideo(chatId, source, { caption: safeCaption, parse_mode: parseMode });
			break;
		case "audio":
			result = await api.sendAudio(chatId, source, {
				caption: safeCaption,
				parse_mode: parseMode,
				title: payload.title,
				performer: payload.performer,
			});
			break;
		case "sticker":
			result = await api.sendSticker(chatId, source);
			break;
		case "animation":
			result = await api.sendAnimation(chatId, source, {
				caption: safeCaption,
				parse_mode: parseMode,
			});
			break;
		default:
			throw new Error(`Unsupported media type: ${(payload as { type: string }).type}`);
	}

	// Track for reaction context
	recordBotMessage(chatId, result.message_id);
	return result;
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
	secretFilterConfig?: SecretFilterConfig;
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
		// SECURITY: Filter BOTH text AND caption for secrets (not just one)
		if (options.text) {
			try {
				filterBeforeSend(options.text, options.secretFilterConfig);
			} catch (err) {
				if (err instanceof SecretExfiltrationBlockedError) {
					const result = await bot.api.sendMessage(options.chatId, SECRET_BLOCKED_MESSAGE);
					return { success: true, messageId: result.message_id };
				}
				throw err;
			}
		}
		if (options.caption) {
			try {
				filterBeforeSend(options.caption, options.secretFilterConfig);
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
			const result = await sendMediaToChat(
				bot.api,
				options.chatId,
				payload,
				undefined,
				options.secretFilterConfig,
			);
			return { success: true, messageId: result.message_id };
		}

		if (options.text) {
			// Split and convert long text to handle Telegram's message limit
			const chunks = sanitizeAndSplitResponse(options.text);
			const convertedChunks = chunks.map((chunk) => convertToTelegramMarkdown(chunk));

			let lastResult: { message_id: number } | undefined;
			for (const chunk of convertedChunks) {
				lastResult = await bot.api.sendMessage(options.chatId, chunk, {
					parse_mode: "MarkdownV2",
				});
			}
			return { success: true, messageId: lastResult?.message_id };
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
	secretFilterConfig?: SecretFilterConfig,
): Promise<Message> {
	// SECURITY: Filter output for secrets
	try {
		filterBeforeSend(text, secretFilterConfig);
	} catch (err) {
		if (err instanceof SecretExfiltrationBlockedError) {
			logger.warn(
				{
					chatId: ctx.chat?.id,
					patterns: err.filterResult.matches.map((m) => m.pattern),
				},
				"BLOCKED: Secret detected in reply, sending blocked notification",
			);
			return ctx.reply(SECRET_BLOCKED_MESSAGE);
		}
		throw err;
	}

	const parseMode = options?.parse_mode;
	// Convert to MarkdownV2 unless caller explicitly wants HTML or legacy Markdown.
	const shouldConvertMarkdown = parseMode !== "HTML" && parseMode !== "Markdown";
	const effectiveParseMode = parseMode ?? ("MarkdownV2" as const);

	// Split BEFORE markdown conversion to avoid breaking escape sequences mid-chunk.
	// Each chunk is then converted independently to ensure valid MarkdownV2.
	const rawChunks = sanitizeAndSplitResponse(text);
	const chunks = shouldConvertMarkdown
		? rawChunks.map((chunk) => convertToTelegramMarkdown(chunk))
		: rawChunks;

	// Send each chunk. Only set reply_to_message_id on first chunk to avoid
	// all chunks being marked as replies (matching sendMessageTelegram behavior).
	let lastResult: Message | undefined;
	for (let i = 0; i < chunks.length; i++) {
		const chunkOptions = {
			...options,
			parse_mode: effectiveParseMode,
			// Only reply to original message on first chunk
			reply_to_message_id: i === 0 ? options?.reply_to_message_id : undefined,
		};
		lastResult = await ctx.reply(chunks[i], chunkOptions);
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
export { type FilterResult, filterOutput } from "../security/output-filter.js";
