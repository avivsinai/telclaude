/**
 * Banned chats management.
 *
 * Provides functions to ban/unban chats and check ban status.
 * Banned chats are completely blocked from using the bot.
 *
 * SECURITY: Ban operations should only be available via CLI (requires machine access).
 * This prevents an attacker with Telegram+TOTP access from unbanning themselves.
 */

import { getChildLogger } from "../logging.js";
import { getDb } from "../storage/db.js";

const logger = getChildLogger({ module: "banned-chats" });

/**
 * Banned chat record.
 */
export type BannedChat = {
	chatId: number;
	bannedAt: number;
	bannedBy: string;
	reason?: string;
};

/**
 * Check if a chat is banned.
 */
export function isChatBanned(chatId: number): boolean {
	const db = getDb();
	const row = db.prepare("SELECT 1 FROM banned_chats WHERE chat_id = ?").get(chatId);
	return !!row;
}

/**
 * Get ban details for a chat.
 * Returns null if not banned.
 */
export function getBanDetails(chatId: number): BannedChat | null {
	const db = getDb();
	type Row = {
		chat_id: number;
		banned_at: number;
		banned_by: string;
		reason: string | null;
	};
	const row = db.prepare("SELECT * FROM banned_chats WHERE chat_id = ?").get(chatId) as
		| Row
		| undefined;

	if (!row) return null;

	return {
		chatId: row.chat_id,
		bannedAt: row.banned_at,
		bannedBy: row.banned_by,
		reason: row.reason ?? undefined,
	};
}

/**
 * Ban a chat.
 *
 * @param chatId - The chat to ban
 * @param bannedBy - Who issued the ban (e.g., "cli:admin", "system")
 * @param reason - Optional reason for the ban
 * @returns true if newly banned, false if already banned
 */
export function banChat(chatId: number, bannedBy: string, reason?: string): boolean {
	const db = getDb();
	const now = Date.now();

	// Check if already banned
	if (isChatBanned(chatId)) {
		logger.info({ chatId, bannedBy }, "chat already banned");
		return false;
	}

	db.prepare(
		`INSERT INTO banned_chats (chat_id, banned_at, banned_by, reason)
		 VALUES (?, ?, ?, ?)`,
	).run(chatId, now, bannedBy, reason ?? null);

	logger.warn({ chatId, bannedBy, reason }, "chat banned");
	return true;
}

/**
 * Unban a chat.
 *
 * @param chatId - The chat to unban
 * @returns true if was banned and now unbanned, false if wasn't banned
 */
export function unbanChat(chatId: number): boolean {
	const db = getDb();
	const result = db.prepare("DELETE FROM banned_chats WHERE chat_id = ?").run(chatId);

	if (result.changes > 0) {
		logger.warn({ chatId }, "chat unbanned");
		return true;
	}

	return false;
}

/**
 * List all banned chats.
 */
export function listBannedChats(): BannedChat[] {
	const db = getDb();
	type Row = {
		chat_id: number;
		banned_at: number;
		banned_by: string;
		reason: string | null;
	};
	const rows = db.prepare("SELECT * FROM banned_chats ORDER BY banned_at DESC").all() as Row[];

	return rows.map((row) => ({
		chatId: row.chat_id,
		bannedAt: row.banned_at,
		bannedBy: row.banned_by,
		reason: row.reason ?? undefined,
	}));
}

/**
 * Get count of banned chats.
 */
export function getBannedChatCount(): number {
	const db = getDb();
	const row = db.prepare("SELECT COUNT(*) as count FROM banned_chats").get() as { count: number };
	return row.count;
}
