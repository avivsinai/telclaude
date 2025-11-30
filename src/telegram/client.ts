import { Bot, GrammyError, HttpError } from "grammy";
import { autoRetry } from "@grammyjs/auto-retry";
import { getChildLogger } from "../logging.js";
import type { BotInfo } from "./types.js";

export type TelegramBotOptions = {
	token: string;
	verbose?: boolean;
};

export type TelegramBotInstance = {
	bot: Bot;
	botInfo: BotInfo;
};

/**
 * Create and configure a Telegram bot instance.
 */
export async function createTelegramBot(
	options: TelegramBotOptions,
): Promise<TelegramBotInstance> {
	const logger = getChildLogger({ module: "telegram-client" });

	const bot = new Bot(options.token);

	// Auto-retry on rate limits (429) and network errors
	bot.api.config.use(
		autoRetry({
			maxRetryAttempts: 5,
			maxDelaySeconds: 60,
			rethrowInternalServerErrors: false,
		}),
	);

	// Error handling
	bot.catch((err) => {
		const ctx = err.ctx;
		const error = err.error;

		if (error instanceof GrammyError) {
			logger.error(
				{
					updateId: ctx.update.update_id,
					description: error.description,
					code: error.error_code,
				},
				"Grammy error",
			);
		} else if (error instanceof HttpError) {
			logger.error(
				{
					updateId: ctx.update.update_id,
					error: String(error),
				},
				"HTTP error",
			);
		} else {
			logger.error(
				{
					updateId: ctx.update.update_id,
					error: String(error),
				},
				"Unknown error",
			);
		}
	});

	// Get bot info to confirm token validity
	const me = await bot.api.getMe();
	logger.info({ botId: me.id, username: me.username }, "bot authenticated");

	return { bot, botInfo: me };
}

/**
 * Validate a bot token by attempting to get bot info.
 */
export async function validateBotToken(token: string): Promise<BotInfo | null> {
	try {
		const bot = new Bot(token);
		const me = await bot.api.getMe();
		return me;
	} catch {
		return null;
	}
}

/**
 * Format bot info for display.
 */
export function formatBotInfo(botInfo: BotInfo): string {
	const parts = [`Bot: ${botInfo.first_name}`];
	if (botInfo.username) {
		parts.push(`(@${botInfo.username})`);
	}
	parts.push(`[ID: ${botInfo.id}]`);
	return parts.join(" ");
}
