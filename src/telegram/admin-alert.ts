/**
 * Admin alert module for sending notifications to admin chats.
 *
 * Used by CLI commands and background tasks to notify admins of issues.
 */

import { loadConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { getDb } from "../storage/db.js";
import { normalizeTelegramId, stringToChatId } from "../utils.js";

const logger = getChildLogger({ module: "admin-alert" });

export interface AdminAlert {
	level: "info" | "warn" | "error";
	title: string;
	message: string;
}

type AdminAlertOptions = {
	/** Optional fallback recipients when no explicit admin links are configured. */
	fallbackChats?: Array<number | string>;
};

/**
 * Get all chat IDs that are linked to the "admin" identity.
 */
function getAdminChatIds(): number[] {
	const db = getDb();
	const rows = db
		.prepare("SELECT chat_id FROM identity_links WHERE local_user_id = ?")
		.all("admin") as Array<{ chat_id: number }>;
	return rows.map((r) => r.chat_id);
}

function normalizeChatIds(values?: Array<number | string>): number[] {
	const normalized = new Set<number>();
	if (!Array.isArray(values)) {
		return [];
	}

	for (const value of values) {
		const parsed = normalizeTelegramId(value);
		if (!parsed) {
			continue;
		}
		const chatId = stringToChatId(parsed);
		if (!Number.isNaN(chatId)) {
			normalized.add(chatId);
		}
	}

	return Array.from(normalized);
}

function resolveRecipientChatIds(
	cfg: { telegram?: { allowedChats?: Array<number | string> } } = {},
): number[] {
	const adminChatIds = getAdminChatIds();
	if (adminChatIds.length > 0) {
		return Array.from(new Set(adminChatIds));
	}

	const fallback = normalizeChatIds(cfg.telegram?.allowedChats);
	return Array.from(new Set(fallback));
}

/**
 * Send an alert to all admin chats.
 *
 * Requires the bot to be configured and running (or at least have a valid token).
 * If called from CLI without a running bot, creates a new bot instance temporarily.
 */
export async function sendAdminAlert(
	alert: AdminAlert,
	options?: AdminAlertOptions,
): Promise<void> {
	const cfg = loadConfig();
	const botToken = cfg.telegram?.botToken ?? process.env.TELEGRAM_BOT_TOKEN;

	if (!botToken) {
		logger.warn("No bot token configured, cannot send admin alert");
		throw new Error("No bot token configured");
	}

	const adminChatIds = options
		? resolveRecipientChatIds({ telegram: { allowedChats: options.fallbackChats } })
		: getAdminChatIds();
	if (adminChatIds.length === 0) {
		logger.warn("No admin chats found, cannot send alert");
		throw new Error("No admin chats configured");
	}

	const emoji = alert.level === "error" ? "🚨" : alert.level === "warn" ? "⚠️" : "ℹ️";
	const text = `${emoji} *${escapeMarkdown(alert.title)}*\n\n${escapeMarkdown(alert.message)}`;

	// Send to each admin chat
	const errors: Error[] = [];
	for (const chatId of adminChatIds) {
		try {
			await sendTelegramMessage(botToken, chatId, text);
			logger.info({ chatId, title: alert.title }, "sent admin alert");
		} catch (err) {
			logger.warn({ chatId, error: String(err) }, "failed to send admin alert");
			errors.push(err instanceof Error ? err : new Error(String(err)));
		}
	}

	// If all sends failed, throw
	if (errors.length === adminChatIds.length) {
		throw new Error(`Failed to send alert to any admin: ${errors[0].message}`);
	}
}

/**
 * Send a message via Telegram Bot API directly (without grammy).
 * Used when the bot instance isn't running.
 */
async function sendTelegramMessage(botToken: string, chatId: number, text: string): Promise<void> {
	const url = `https://api.telegram.org/bot${botToken}/sendMessage`;

	const response = await fetch(url, {
		method: "POST",
		headers: {
			"content-type": "application/json",
		},
		body: JSON.stringify({
			chat_id: chatId,
			text,
			parse_mode: "MarkdownV2",
		}),
	});

	if (!response.ok) {
		const body = await response.text();
		throw new Error(`Telegram API error: ${response.status} ${body}`);
	}
}

/**
 * Escape text for MarkdownV2 format.
 */
function escapeMarkdown(text: string): string {
	// MarkdownV2 requires escaping these characters
	return text.replace(/([_*[\]()~`>#+\-=|{}.!\\])/g, "\\$1");
}
