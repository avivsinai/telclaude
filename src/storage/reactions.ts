/**
 * Storage layer for message reactions.
 *
 * Tracks bot outbound messages and user reactions to them,
 * enabling reaction context in subsequent conversations.
 */

import { getChildLogger } from "../logging.js";
import { getDb } from "./db.js";

const logger = getChildLogger({ module: "storage-reactions" });

export type StoredReaction = {
	chatId: number;
	messageId: number;
	userId: number;
	emoji: string;
	reactedAt: number;
};

export type ReactionSummary = {
	messageId: number;
	reactions: Array<{ emoji: string; count: number; userIds: number[] }>;
};

/**
 * Record a bot outbound message for reaction tracking.
 * Call this after successfully sending a message.
 */
export function recordBotMessage(chatId: number, messageId: number): void {
	const db = getDb();
	try {
		db.prepare(
			`INSERT OR REPLACE INTO bot_messages (chat_id, message_id, sent_at)
			 VALUES (?, ?, ?)`,
		).run(chatId, messageId, Date.now());
		logger.debug({ chatId, messageId }, "recorded bot message for reaction tracking");
	} catch (err) {
		logger.warn({ chatId, messageId, error: String(err) }, "failed to record bot message");
	}
}

/**
 * Check if a message was sent by the bot (eligible for reaction tracking).
 */
export function isBotMessage(chatId: number, messageId: number): boolean {
	const db = getDb();
	const row = db
		.prepare("SELECT 1 FROM bot_messages WHERE chat_id = ? AND message_id = ?")
		.get(chatId, messageId);
	return !!row;
}

/**
 * Store a reaction on a bot message.
 * Replaces any existing reaction from the same user with the same emoji.
 */
export function storeReaction(
	chatId: number,
	messageId: number,
	userId: number,
	emoji: string,
): void {
	const db = getDb();
	try {
		db.prepare(
			`INSERT OR REPLACE INTO message_reactions (chat_id, message_id, user_id, emoji, reacted_at)
			 VALUES (?, ?, ?, ?, ?)`,
		).run(chatId, messageId, userId, emoji, Date.now());
		logger.debug({ chatId, messageId, userId, emoji }, "stored reaction");
	} catch (err) {
		logger.warn(
			{ chatId, messageId, userId, emoji, error: String(err) },
			"failed to store reaction",
		);
	}
}

/**
 * Remove a reaction from a bot message.
 */
export function removeReaction(
	chatId: number,
	messageId: number,
	userId: number,
	emoji: string,
): void {
	const db = getDb();
	try {
		db.prepare(
			`DELETE FROM message_reactions
			 WHERE chat_id = ? AND message_id = ? AND user_id = ? AND emoji = ?`,
		).run(chatId, messageId, userId, emoji);
		logger.debug({ chatId, messageId, userId, emoji }, "removed reaction");
	} catch (err) {
		logger.warn(
			{ chatId, messageId, userId, emoji, error: String(err) },
			"failed to remove reaction",
		);
	}
}

/**
 * Get all reactions for a specific message.
 */
export function getReactionsForMessage(chatId: number, messageId: number): StoredReaction[] {
	const db = getDb();
	const rows = db
		.prepare(
			`SELECT chat_id, message_id, user_id, emoji, reacted_at
			 FROM message_reactions
			 WHERE chat_id = ? AND message_id = ?
			 ORDER BY reacted_at ASC`,
		)
		.all(chatId, messageId) as Array<{
		chat_id: number;
		message_id: number;
		user_id: number;
		emoji: string;
		reacted_at: number;
	}>;

	return rows.map((row) => ({
		chatId: row.chat_id,
		messageId: row.message_id,
		userId: row.user_id,
		emoji: row.emoji,
		reactedAt: row.reacted_at,
	}));
}

/**
 * Get reaction summaries for recent bot messages in a chat.
 * Returns up to `limit` most recent messages that have reactions.
 */
export function getRecentReactions(chatId: number, limit = 5): ReactionSummary[] {
	const db = getDb();

	// Single JOIN query instead of N+1: fetch reactions for recent reacted-to messages
	const rows = db
		.prepare(
			`SELECT mr.message_id, mr.user_id, mr.emoji, mr.reacted_at
			 FROM message_reactions mr
			 INNER JOIN bot_messages bm ON bm.chat_id = mr.chat_id AND bm.message_id = mr.message_id
			 WHERE mr.chat_id = ?
			   AND bm.message_id IN (
				 SELECT DISTINCT bm2.message_id
				 FROM bot_messages bm2
				 INNER JOIN message_reactions mr2 ON bm2.chat_id = mr2.chat_id AND bm2.message_id = mr2.message_id
				 WHERE bm2.chat_id = ?
				 ORDER BY bm2.sent_at DESC
				 LIMIT ?
			   )
			 ORDER BY bm.sent_at DESC, mr.reacted_at ASC`,
		)
		.all(chatId, chatId, limit) as Array<{
		message_id: number;
		user_id: number;
		emoji: string;
		reacted_at: number;
	}>;

	if (rows.length === 0) {
		return [];
	}

	// Group by message, then by emoji
	const byMessage = new Map<number, Map<string, { count: number; userIds: number[] }>>();
	for (const row of rows) {
		let emojiMap = byMessage.get(row.message_id);
		if (!emojiMap) {
			emojiMap = new Map();
			byMessage.set(row.message_id, emojiMap);
		}
		const existing = emojiMap.get(row.emoji);
		if (existing) {
			existing.count++;
			existing.userIds.push(row.user_id);
		} else {
			emojiMap.set(row.emoji, { count: 1, userIds: [row.user_id] });
		}
	}

	const summaries: ReactionSummary[] = [];
	for (const [messageId, emojiMap] of byMessage) {
		summaries.push({
			messageId,
			reactions: Array.from(emojiMap.entries()).map(([emoji, data]) => ({
				emoji,
				count: data.count,
				userIds: data.userIds,
			})),
		});
	}

	return summaries;
}

/**
 * Format reaction summaries as context string for the LLM.
 * Returns null if no reactions to report.
 */
export function formatReactionContext(summaries: ReactionSummary[]): string | null {
	if (summaries.length === 0) {
		return null;
	}

	const lines: string[] = ["Recent reactions to your messages:"];

	for (const summary of summaries) {
		const reactionStr = summary.reactions
			.map((r) => `${r.emoji}${r.count > 1 ? `(×${r.count})` : ""}`)
			.join(" ");
		lines.push(`- Message #${summary.messageId}: ${reactionStr}`);
	}

	return lines.join("\n");
}
