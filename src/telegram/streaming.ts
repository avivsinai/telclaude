/**
 * Telegram Streaming Response Manager
 *
 * Provides real-time streaming of Claude responses to Telegram using editMessageText.
 *
 * Best practices implemented (per Telegram docs and grammY guidelines):
 * - Debounced updates (1.5s minimum interval) to avoid rate limits
 * - Uses grammY's auto-retry transformer for 429 error handling
 * - Graceful fallback from MarkdownV2 to plain text on parse errors
 * - Handles "message is not modified" errors silently
 * - Shows typing indicator during generation gaps
 * - Inline keyboards for post-response actions
 *
 * Rate limits reference (Telegram Bot API FAQ):
 * - Global: ~30 requests/second
 * - Per-chat: ~20 messages/minute in groups
 * - editMessageText shares limits with sendMessage
 *
 * @see https://core.telegram.org/bots/faq#my-bot-is-hitting-limits-how-do-i-avoid-this
 * @see https://grammy.dev/plugins/auto-retry
 */

import type { Api } from "grammy";
import { InlineKeyboard } from "grammy";
import type { Message } from "grammy/types";
import { convert as convertToTelegramMarkdown } from "telegram-markdown-v2";

import { getChildLogger } from "../logging.js";
import type { SecretFilterConfig } from "../security/output-filter.js";
import { filterOutput, filterOutputWithConfig } from "../security/output-filter.js";
import { recordBotMessage } from "../storage/reactions.js";
import { sanitizeAndSplitResponse } from "./sanitize.js";

const logger = getChildLogger({ module: "telegram-streaming" });

/**
 * Streaming configuration options.
 */
export interface StreamingConfig {
	/**
	 * Minimum interval between message edits in milliseconds.
	 * Telegram rate limits: ~30 req/s global, 20 msg/min per chat.
	 * Default: 1500ms (safe for most use cases)
	 */
	minUpdateIntervalMs?: number;

	/**
	 * Maximum interval between updates.
	 * Forces an update even with minimal changes to show progress.
	 * Default: 5000ms
	 */
	maxUpdateIntervalMs?: number;

	/**
	 * Minimum characters accumulated before triggering an update.
	 * Prevents rapid updates on token-by-token streaming.
	 * Default: 50 characters
	 */
	minCharsForUpdate?: number;

	/**
	 * Initial message shown while waiting for first tokens.
	 * Default: "🤔 Thinking..."
	 */
	initialMessage?: string;

	/**
	 * Show inline keyboard after response completes.
	 * Default: true
	 */
	showInlineKeyboard?: boolean;

	/**
	 * Secret filter configuration for output filtering.
	 */
	secretFilterConfig?: SecretFilterConfig;

	/**
	 * Show typing indicator between updates.
	 * Provides feedback during long generation gaps.
	 * Default: true
	 */
	showTypingIndicator?: boolean;
}

const DEFAULT_CONFIG: Required<Omit<StreamingConfig, "secretFilterConfig">> = {
	minUpdateIntervalMs: 1500,
	maxUpdateIntervalMs: 5000,
	minCharsForUpdate: 50,
	initialMessage: "🤔 Thinking...",
	showInlineKeyboard: false, // Disabled by default - can be noisy on mobile
	showTypingIndicator: true,
};

/**
 * Creates the default inline keyboard for responses.
 * Full version with all actions.
 */
export function createResponseKeyboard(): InlineKeyboard {
	return new InlineKeyboard()
		.text("🔄 New", "action:new")
		.text("🔊 Read Aloud", "action:tts")
		.row()
		.text("❓ Help", "action:help");
}

/**
 * Creates a compact inline keyboard for responses.
 * Single row, icon-only for mobile-friendly display.
 */
export function createCompactKeyboard(): InlineKeyboard {
	return new InlineKeyboard()
		.text("🔄", "action:new")
		.text("🔊", "action:tts")
		.text("❓", "action:help");
}

/**
 * Streaming response manager for a single message.
 *
 * Handles the lifecycle of a streaming response:
 * 1. start() - Sends initial "Thinking..." message
 * 2. append() - Accumulates content with debounced updates
 * 3. finish() - Finalizes with complete response and keyboard
 *
 * @example
 * ```typescript
 * const streamer = new StreamingResponse(api, chatId);
 * await streamer.start();
 *
 * for await (const chunk of claudeResponse) {
 *   await streamer.append(chunk.content);
 * }
 *
 * await streamer.finish();
 * ```
 */
export class StreamingResponse {
	private readonly api: Api;
	private readonly chatId: number;
	private readonly config: Required<Omit<StreamingConfig, "secretFilterConfig">> & {
		secretFilterConfig?: SecretFilterConfig;
	};

	private messageId: number | null = null;
	private content = "";
	private lastUpdateTime = 0;
	private lastSentContent = "";
	private pendingUpdate: NodeJS.Timeout | null = null;
	private isFinished = false;
	private updatePromise: Promise<void> | null = null;
	private typingInterval: NodeJS.Timeout | null = null;
	private consecutiveErrors = 0;
	private useMarkdown = true; // Fall back to plain text after parse errors

	constructor(api: Api, chatId: number, config: StreamingConfig = {}) {
		this.api = api;
		this.chatId = chatId;
		this.config = { ...DEFAULT_CONFIG, ...config };
	}

	/**
	 * Start the streaming response by sending the initial message.
	 * Also starts a typing indicator interval if configured.
	 */
	async start(): Promise<Message> {
		const message = await this.api.sendMessage(this.chatId, this.config.initialMessage);
		this.messageId = message.message_id;
		this.lastUpdateTime = Date.now();

		// Track for reaction context
		recordBotMessage(this.chatId, message.message_id);

		// Start typing indicator if enabled
		if (this.config.showTypingIndicator) {
			this.startTypingIndicator();
		}

		logger.debug({ chatId: this.chatId, messageId: this.messageId }, "streaming response started");
		return message;
	}

	/**
	 * Start periodic typing indicator.
	 * Telegram's "typing" action lasts 5 seconds, so we refresh every 4s.
	 */
	private startTypingIndicator(): void {
		this.typingInterval = setInterval(() => {
			if (!this.isFinished) {
				this.api.sendChatAction(this.chatId, "typing").catch(() => {
					// Ignore typing indicator errors
				});
			}
		}, 4000);
	}

	/**
	 * Stop the typing indicator.
	 */
	private stopTypingIndicator(): void {
		if (this.typingInterval) {
			clearInterval(this.typingInterval);
			this.typingInterval = null;
		}
	}

	/**
	 * Append content to the streaming response.
	 * Updates are debounced to avoid rate limits.
	 */
	async append(chunk: string): Promise<void> {
		if (this.isFinished) {
			logger.warn({ chatId: this.chatId }, "attempted to append to finished stream");
			return;
		}

		this.content += chunk;
		await this.scheduleUpdate();
	}

	/**
	 * Get the current accumulated content.
	 */
	getContent(): string {
		return this.content;
	}

	/**
	 * Get the message ID of the streaming message.
	 */
	getMessageId(): number | null {
		return this.messageId;
	}

	/**
	 * Schedule a debounced update to Telegram.
	 * Implements intelligent batching to minimize API calls.
	 */
	private async scheduleUpdate(): Promise<void> {
		const now = Date.now();
		const timeSinceLastUpdate = now - this.lastUpdateTime;
		const contentDelta = this.content.length - this.lastSentContent.length;

		// Determine if we should update now
		const shouldUpdateNow =
			timeSinceLastUpdate >= this.config.minUpdateIntervalMs &&
			contentDelta >= this.config.minCharsForUpdate;

		const mustUpdateNow =
			timeSinceLastUpdate >= this.config.maxUpdateIntervalMs && contentDelta > 0;

		if (shouldUpdateNow || mustUpdateNow) {
			// Cancel any pending scheduled update
			if (this.pendingUpdate) {
				clearTimeout(this.pendingUpdate);
				this.pendingUpdate = null;
			}

			// Wait for any in-flight update before sending another
			if (this.updatePromise) {
				await this.updatePromise;
			}

			this.updatePromise = this.doUpdate();
			await this.updatePromise;
			this.updatePromise = null;
		} else if (!this.pendingUpdate) {
			// Schedule a future update
			const delay = Math.max(this.config.minUpdateIntervalMs - timeSinceLastUpdate, 100);
			this.pendingUpdate = setTimeout(() => {
				this.pendingUpdate = null;
				this.scheduleUpdate().catch((err) => {
					logger.error({ error: String(err) }, "scheduled update failed");
				});
			}, delay);
		}
	}

	/**
	 * Perform the actual message edit.
	 * Handles rate limits, parse errors, and "message not modified" gracefully.
	 */
	private async doUpdate(): Promise<void> {
		if (!this.messageId || this.content === this.lastSentContent) {
			return;
		}

		// Filter content for secrets (during streaming, we just check - don't block)
		const filterResult = this.config.secretFilterConfig
			? filterOutputWithConfig(this.content, this.config.secretFilterConfig)
			: filterOutput(this.content);

		if (filterResult.blocked) {
			logger.debug(
				{ chatId: this.chatId },
				"secrets detected during streaming, will handle on finish",
			);
		}

		// Truncate for Telegram's 4096 char limit
		// Keep the end of the content (most recent) if truncating
		let displayContent = this.content;
		if (displayContent.length > 3900) {
			displayContent = `...\n${displayContent.slice(-3850)}`;
		}

		// Add streaming indicator
		const streamingContent = `${displayContent}\n\n⏳ _generating..._`;

		try {
			// Convert to MarkdownV2 if we haven't fallen back to plain text
			let textToSend: string;
			let parseMode: "MarkdownV2" | undefined;

			if (this.useMarkdown) {
				textToSend = convertToTelegramMarkdown(streamingContent);
				parseMode = "MarkdownV2";
			} else {
				textToSend = `${displayContent}\n\n⏳ generating...`;
				parseMode = undefined;
			}

			await this.api.editMessageText(this.chatId, this.messageId, textToSend, {
				parse_mode: parseMode,
			});

			this.lastSentContent = this.content;
			this.lastUpdateTime = Date.now();
			this.consecutiveErrors = 0; // Reset error counter on success

			logger.debug(
				{
					chatId: this.chatId,
					messageId: this.messageId,
					contentLength: this.content.length,
				},
				"streaming update sent",
			);
		} catch (err) {
			await this.handleUpdateError(err, displayContent);
		}
	}

	/**
	 * Handle errors during message update.
	 * Implements graceful degradation and backoff strategies.
	 */
	private async handleUpdateError(err: unknown, displayContent: string): Promise<void> {
		const errStr = String(err);
		this.consecutiveErrors++;

		// Rate limit: 429 Too Many Requests
		// grammY's auto-retry should handle this, but we add defensive logic
		if (errStr.includes("429") || errStr.includes("Too Many Requests")) {
			const retryAfter = this.parseRetryAfter(errStr);
			logger.warn(
				{ chatId: this.chatId, retryAfter, errors: this.consecutiveErrors },
				"rate limited, increasing interval",
			);

			// Increase minimum interval (capped at 10s)
			this.config.minUpdateIntervalMs = Math.min(this.config.minUpdateIntervalMs * 1.5, 10000);
			return;
		}

		// "Message is not modified" - content hasn't changed meaningfully
		if (errStr.includes("message is not modified")) {
			// This is expected when content hasn't visually changed - ignore silently
			return;
		}

		// Parse error - markdown formatting issue
		if (errStr.includes("can't parse entities") || errStr.includes("Bad Request")) {
			logger.warn(
				{ chatId: this.chatId, error: errStr },
				"markdown parse error, falling back to plain text",
			);

			this.useMarkdown = false;

			// Retry immediately with plain text
			if (this.messageId) {
				try {
					await this.api.editMessageText(
						this.chatId,
						this.messageId,
						`${displayContent}\n\n⏳ generating...`,
					);
					this.lastSentContent = this.content;
					this.lastUpdateTime = Date.now();
				} catch (fallbackErr) {
					logger.error({ error: String(fallbackErr) }, "plain text fallback also failed");
				}
			}
			return;
		}

		// Unknown error
		logger.error(
			{ error: errStr, chatId: this.chatId, errors: this.consecutiveErrors },
			"streaming update failed",
		);

		// If we have too many consecutive errors, stop streaming updates
		// (we'll still send the final message)
		if (this.consecutiveErrors >= 3) {
			logger.warn(
				{ chatId: this.chatId },
				"too many consecutive errors, pausing streaming updates",
			);
			this.config.minUpdateIntervalMs = 30000; // Effectively pause updates
		}
	}

	/**
	 * Parse retry-after value from rate limit error.
	 */
	private parseRetryAfter(errStr: string): number {
		const match = errStr.match(/retry after (\d+)/i);
		return match ? Number.parseInt(match[1], 10) * 1000 : 5000;
	}

	/**
	 * Finish the streaming response with final content and optional keyboard.
	 *
	 * @param options.keyboard - Custom keyboard, or null to disable
	 * @returns The final message, or null if sending failed
	 */
	async finish(options?: { keyboard?: InlineKeyboard | null }): Promise<Message | null> {
		this.isFinished = true;
		this.stopTypingIndicator();

		// Cancel any pending update
		if (this.pendingUpdate) {
			clearTimeout(this.pendingUpdate);
			this.pendingUpdate = null;
		}

		// Wait for any in-flight update
		if (this.updatePromise) {
			await this.updatePromise;
		}

		if (!this.messageId) {
			logger.warn({ chatId: this.chatId }, "cannot finish stream - no message ID");
			return null;
		}

		// Filter final content for secrets
		const filterResult = this.config.secretFilterConfig
			? filterOutputWithConfig(this.content, this.config.secretFilterConfig)
			: filterOutput(this.content);

		let finalContent = this.content;
		if (filterResult.blocked) {
			finalContent =
				"⚠️ Response blocked by security filter.\n\n" +
				"The response contained what appears to be sensitive credentials.";
			logger.warn(
				{ chatId: this.chatId, patterns: filterResult.matches.map((m) => m.pattern) },
				"secrets detected in final streaming content",
			);
		}

		// Handle empty content
		if (!finalContent.trim()) {
			finalContent = "_(No response generated)_";
		}

		// Split for Telegram's message limit
		const chunks = sanitizeAndSplitResponse(finalContent);

		// Determine keyboard to use
		const keyboard =
			options?.keyboard !== null && this.config.showInlineKeyboard
				? (options?.keyboard ?? createCompactKeyboard())
				: undefined;

		try {
			// First chunk replaces the streaming message
			const firstChunk = chunks[0];
			let textToSend: string;
			let parseMode: "MarkdownV2" | undefined;

			if (this.useMarkdown) {
				textToSend = convertToTelegramMarkdown(firstChunk);
				parseMode = "MarkdownV2";
			} else {
				textToSend = firstChunk;
				parseMode = undefined;
			}

			const result = await this.api.editMessageText(this.chatId, this.messageId, textToSend, {
				parse_mode: parseMode,
				reply_markup: chunks.length === 1 ? keyboard : undefined,
			});

			// Additional chunks are sent as new messages
			let lastResult: Message = result as Message;
			for (let i = 1; i < chunks.length; i++) {
				const chunk = chunks[i];
				const isLast = i === chunks.length - 1;

				const chunkText = this.useMarkdown ? convertToTelegramMarkdown(chunk) : chunk;

				lastResult = await this.api.sendMessage(this.chatId, chunkText, {
					parse_mode: this.useMarkdown ? "MarkdownV2" : undefined,
					reply_markup: isLast ? keyboard : undefined,
				});
				// Track for reaction context
				recordBotMessage(this.chatId, lastResult.message_id);
			}

			logger.info(
				{
					chatId: this.chatId,
					messageId: this.messageId,
					contentLength: finalContent.length,
					chunks: chunks.length,
					usedMarkdown: this.useMarkdown,
				},
				"streaming response finished",
			);

			return lastResult;
		} catch (err) {
			return this.handleFinishError(err, chunks, keyboard);
		}
	}

	/**
	 * Handle errors during finish.
	 * Attempts plain text fallback.
	 */
	private async handleFinishError(
		err: unknown,
		chunks: string[],
		keyboard?: InlineKeyboard,
	): Promise<Message | null> {
		const errStr = String(err);

		// Try plain text fallback
		if (
			this.useMarkdown &&
			(errStr.includes("can't parse entities") || errStr.includes("Bad Request"))
		) {
			logger.warn({ error: errStr }, "markdown parse error on finish, retrying with plain text");

			if (this.messageId) {
				try {
					const result = await this.api.editMessageText(this.chatId, this.messageId, chunks[0], {
						reply_markup: chunks.length === 1 ? keyboard : undefined,
					});

					let lastResult: Message = result as Message;
					for (let i = 1; i < chunks.length; i++) {
						const isLast = i === chunks.length - 1;
						lastResult = await this.api.sendMessage(this.chatId, chunks[i], {
							reply_markup: isLast ? keyboard : undefined,
						});
						// Track for reaction context
						recordBotMessage(this.chatId, lastResult.message_id);
					}
					return lastResult;
				} catch (fallbackErr) {
					logger.error({ error: String(fallbackErr) }, "plain text finish also failed");
				}
			}
		}

		logger.error({ error: errStr }, "streaming finish failed");
		return null;
	}

	/**
	 * Abort the streaming response (e.g., on error or timeout).
	 *
	 * @param errorMessage - Message to display (default: generic error)
	 */
	async abort(errorMessage?: string): Promise<void> {
		this.isFinished = true;
		this.stopTypingIndicator();

		if (this.pendingUpdate) {
			clearTimeout(this.pendingUpdate);
			this.pendingUpdate = null;
		}

		if (this.updatePromise) {
			await this.updatePromise;
		}

		if (!this.messageId) {
			return;
		}

		const message = errorMessage ?? "❌ An error occurred while generating the response.";

		try {
			await this.api.editMessageText(this.chatId, this.messageId, message);
			logger.info({ chatId: this.chatId }, "streaming response aborted");
		} catch (err) {
			logger.error({ error: String(err) }, "failed to abort streaming message");
		}
	}
}

/**
 * Create a streaming response helper.
 *
 * This is the recommended way to create a StreamingResponse instance.
 *
 * @example
 * ```typescript
 * const streamer = createStreamingResponse(bot.api, chatId, {
 *   minUpdateIntervalMs: 2000,  // Slower updates for busy chats
 *   showInlineKeyboard: true,
 * });
 * ```
 */
export function createStreamingResponse(
	api: Api,
	chatId: number,
	config?: StreamingConfig,
): StreamingResponse {
	return new StreamingResponse(api, chatId, config);
}
