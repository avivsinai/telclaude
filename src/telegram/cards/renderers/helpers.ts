import { InlineKeyboard } from "grammy";
import { buildCallbackToken } from "../callback-tokens.js";
import type { CardInstance, CardKind, CardRenderResult } from "../types.js";

/**
 * Telegram MarkdownV2 special characters that must be escaped.
 */
const TELEGRAM_SPECIAL_CHARS = /([_*[\]()~`>#+\-=|{}.!\\])/g;

export function esc(text: string): string {
	return text.replace(TELEGRAM_SPECIAL_CHARS, "\\$1");
}

/**
 * Build a callback_data token for a card button.
 */
export function btn(card: CardInstance, action: string): string {
	return buildCallbackToken({
		shortId: card.shortId,
		action,
		revision: card.revision,
	});
}

/**
 * Build a standard consumed/expired/superseded terminal render.
 * Returns null if the card is still active (caller should render normally).
 */
export function renderTerminalState<K extends CardKind>(
	card: CardInstance<K>,
	title: string,
): CardRenderResult | null {
	if (card.status === "active") return null;

	const statusLabel =
		card.status === "consumed" ? "Completed" : card.status === "expired" ? "Expired" : "Superseded";

	const emoji =
		card.status === "consumed" ? "\u2705" : card.status === "expired" ? "\u23F0" : "\uD83D\uDEAB";

	return {
		text: `${emoji} *${esc(title)}*\n\n_${esc(statusLabel)}_`,
		parseMode: "MarkdownV2",
		keyboard: null,
	};
}

/**
 * Create a new InlineKeyboard. Convenience re-export so renderers
 * don't all need to import grammy directly.
 */
export function keyboard(): InlineKeyboard {
	return new InlineKeyboard();
}
