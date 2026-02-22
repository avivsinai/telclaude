/**
 * Sanitize notification content before sending via Telegram admin alerts.
 *
 * SECURITY: Never include raw LLM output in notifications — only metadata.
 * This prevents prompt injection from social content propagating to admin chats.
 */

import { MAX_NOTIFICATION_LENGTH } from "./constants.js";

// Telegram MarkdownV2 special characters
const TELEGRAM_SPECIAL_CHARS = /([_*[\]()~`>#+\-=|{}.!\\])/g;

/**
 * Sanitize a string for safe inclusion in Telegram notifications.
 *
 * - Strips markdown formatting
 * - Removes URLs
 * - Limits length
 * - Escapes Telegram-special characters
 */
export function sanitizeNotificationText(text: string): string {
	let sanitized = text
		// Remove markdown links [text](url)
		.replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
		// Remove bare URLs
		.replace(/https?:\/\/\S+/g, "")
		// Remove markdown formatting markers
		.replace(/[*_~`#]/g, "")
		// Collapse multiple spaces/newlines
		.replace(/\s+/g, " ")
		.trim();

	// Enforce length limit
	if (sanitized.length > MAX_NOTIFICATION_LENGTH) {
		sanitized = `${sanitized.slice(0, MAX_NOTIFICATION_LENGTH - 3)}...`;
	}

	return sanitized;
}

/**
 * Escape text for Telegram MarkdownV2 format.
 */
export function escapeMarkdownV2(text: string): string {
	return text.replace(TELEGRAM_SPECIAL_CHARS, "\\$1");
}

/**
 * Format a heartbeat summary for admin notification.
 * Only includes metadata — no raw LLM output or social content.
 */
export function formatHeartbeatNotification(
	serviceId: string,
	summary: {
		notificationsProcessed?: number;
		proactivePosted?: boolean;
		autonomousActed?: boolean;
		autonomousSummary?: string;
	},
): string {
	const parts: string[] = [];

	if (summary.notificationsProcessed && summary.notificationsProcessed > 0) {
		parts.push(`${summary.notificationsProcessed} notification(s) processed`);
	}
	if (summary.proactivePosted) {
		parts.push("proactive post created");
	}
	if (summary.autonomousActed) {
		const detail = summary.autonomousSummary
			? sanitizeNotificationText(summary.autonomousSummary)
			: "activity completed";
		parts.push(`autonomous: ${detail}`);
	}

	if (parts.length === 0) {
		return `${serviceId}: no activity`;
	}

	return `${serviceId}: ${parts.join("; ")}`;
}

/**
 * Determine whether a heartbeat result warrants a notification.
 */
export function shouldNotifyOnHeartbeat(
	policy: "always" | "activity" | "never",
	hadActivity: boolean,
): boolean {
	switch (policy) {
		case "always":
			return true;
		case "never":
			return false;
		case "activity":
			return hadActivity;
	}
}
