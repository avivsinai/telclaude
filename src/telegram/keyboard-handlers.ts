/**
 * Inline Keyboard Callback Handlers
 *
 * Handles button presses from inline keyboards attached to responses.
 * Uses grammY's callback query handling with proper answer acknowledgment.
 */

import type { Bot, CallbackQueryContext, Context } from "grammy";
import { getChildLogger } from "../logging.js";
import type { TelclaudeConfig } from "../config/config.js";
import { deleteSession, deriveSessionKey } from "../config/sessions.js";
import { getSessionManager } from "../sdk/session-manager.js";

const logger = getChildLogger({ module: "keyboard-handlers" });

/**
 * Callback data format: "action:<action_name>"
 */
export type KeyboardAction = "new" | "copy" | "tts" | "help";

/**
 * Parse callback data into action name.
 */
export function parseCallbackData(data: string): KeyboardAction | null {
	if (!data.startsWith("action:")) {
		return null;
	}
	const action = data.slice(7);
	if (["new", "copy", "tts", "help"].includes(action)) {
		return action as KeyboardAction;
	}
	return null;
}

/**
 * Register callback query handlers for inline keyboard buttons.
 * Should be called during bot setup, before starting polling.
 */
export function registerKeyboardHandlers(bot: Bot, _config: TelclaudeConfig): void {
	// Handle "New Session" button
	bot.callbackQuery(/^action:new$/, async (ctx) => {
		const chatId = ctx.chat?.id;
		if (!chatId) {
			await ctx.answerCallbackQuery({ text: "Chat not found" });
			return;
		}

		await handleNewSession(ctx, chatId);
	});

	// Handle "Copy" button
	bot.callbackQuery(/^action:copy$/, async (ctx) => {
		await ctx.answerCallbackQuery({
			text: "Long-press the message to copy",
			show_alert: true,
		});
	});

	// Handle "TTS" button
	bot.callbackQuery(/^action:tts$/, async (ctx) => {
		const chatId = ctx.chat?.id;
		if (!chatId) {
			await ctx.answerCallbackQuery({ text: "Chat not found" });
			return;
		}

		await handleTTS(ctx, chatId);
	});

	// Handle "Help" button
	bot.callbackQuery(/^action:help$/, async (ctx) => {
		await handleHelp(ctx);
	});

	// Catch-all for unknown callback queries (grammY best practice)
	bot.on("callback_query:data", async (ctx) => {
		logger.debug({ data: ctx.callbackQuery.data }, "unhandled callback query");
		await ctx.answerCallbackQuery();
	});

	logger.debug("keyboard handlers registered");
}

/**
 * Handle "New Session" button press.
 */
async function handleNewSession(ctx: CallbackQueryContext<Context>, chatId: number): Promise<void> {
	const sessionKey = deriveSessionKey("per-sender", { From: `tg:${chatId}` });

	// Clear the session from config/sessions (SQLite)
	deleteSession(sessionKey);

	// Clear the session from SDK session manager (in-memory)
	getSessionManager().clearSession(sessionKey);

	logger.info({ chatId, sessionKey }, "session reset via keyboard button");

	await ctx.answerCallbackQuery({ text: "✅ Session reset" });

	// Send confirmation message
	await ctx.reply("🔄 Session reset. Starting fresh conversation.");
}

/**
 * Handle "Read Aloud" (TTS) button press.
 * Queues the response for text-to-speech conversion.
 */
async function handleTTS(ctx: CallbackQueryContext<Context>, chatId: number): Promise<void> {
	const message = ctx.callbackQuery.message;
	if (!message || !("text" in message)) {
		await ctx.answerCallbackQuery({ text: "No text to read" });
		return;
	}

	const text = message.text;
	if (!text || text.length < 5) {
		await ctx.answerCallbackQuery({ text: "Message too short" });
		return;
	}

	// Check for OpenAI availability
	const { getOpenAIKey } = await import("../services/openai-client.js");
	const apiKey = await getOpenAIKey();
	if (!apiKey) {
		await ctx.answerCallbackQuery({
			text: "TTS not configured. Run: telclaude setup-openai",
			show_alert: true,
		});
		return;
	}

	await ctx.answerCallbackQuery({ text: "🔊 Generating..." });

	try {
		const { textToSpeech } = await import("../services/tts.js");
		const { InputFile } = await import("grammy");

		// Truncate for TTS (OpenAI limit)
		const ttsText = text.slice(0, 4000);

		const result = await textToSpeech(ttsText, {
			voice: "alloy",
			voiceMessage: true, // OGG/Opus format for Telegram voice
		});

		await ctx.replyWithVoice(new InputFile(result.path));

		logger.info(
			{ chatId, textLength: ttsText.length, duration: result.estimatedDurationSeconds },
			"TTS audio sent via keyboard",
		);
	} catch (err) {
		logger.error({ error: String(err) }, "TTS via keyboard failed");
		await ctx.reply("❌ Audio generation failed.");
	}
}

/**
 * Handle "Help" button press.
 */
async function handleHelp(ctx: CallbackQueryContext<Context>): Promise<void> {
	const helpText = `*Quick Commands*

🔄 /new \\- Start fresh conversation
❓ /whoami \\- Show your identity

*Media*
📷 Send images for analysis
🎤 Send voice for transcription

*Buttons*
🔄 Reset session
🔊 Read aloud \\(TTS\\)

_Long\\-press messages to copy_`;

	await ctx.answerCallbackQuery();
	await ctx.reply(helpText, { parse_mode: "MarkdownV2" });
}
