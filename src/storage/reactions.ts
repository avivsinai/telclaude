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

	// Get recent bot messages that have at least one reaction
	const messages = db
		.prepare(
			`SELECT DISTINCT bm.message_id
			 FROM bot_messages bm
			 INNER JOIN message_reactions mr ON bm.chat_id = mr.chat_id AND bm.message_id = mr.message_id
			 WHERE bm.chat_id = ?
			 ORDER BY bm.sent_at DESC
			 LIMIT ?`,
		)
		.all(chatId, limit) as Array<{ message_id: number }>;

	if (messages.length === 0) {
		return [];
	}

	// Get reactions for each message
	const summaries: ReactionSummary[] = [];
	for (const msg of messages) {
		const reactions = getReactionsForMessage(chatId, msg.message_id);
		if (reactions.length > 0) {
			// Group by emoji
			const byEmoji = new Map<string, { count: number; userIds: number[] }>();
			for (const r of reactions) {
				const existing = byEmoji.get(r.emoji);
				if (existing) {
					existing.count++;
					existing.userIds.push(r.userId);
				} else {
					byEmoji.set(r.emoji, { count: 1, userIds: [r.userId] });
				}
			}

			summaries.push({
				messageId: msg.message_id,
				reactions: Array.from(byEmoji.entries()).map(([emoji, data]) => ({
					emoji,
					count: data.count,
					userIds: data.userIds,
				})),
			});
		}
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
