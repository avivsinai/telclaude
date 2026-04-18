/**
 * Session management with SQLite persistence.
 */

import { getChildLogger } from "../logging.js";
import { getIdentityLink } from "../security/linking.js";
import { getDb } from "../storage/db.js";
import type { MsgContext } from "../types/message.js";
import { normalizeTelegramId } from "../utils.js";

const logger = getChildLogger({ module: "sessions" });

export type SessionScope = "per-sender" | "global";

export type SessionEntry = {
	sessionId: string;
	updatedAt: number;
	systemSent?: boolean;
};

export const DEFAULT_RESET_TRIGGER = "/new";
export const DEFAULT_IDLE_MINUTES = 60;

type SessionRow = {
	session_key: string;
	session_id: string;
	updated_at: number;
	system_sent: number;
};

type HomeTargetRow = {
	owner_id: string;
	chat_id: number;
	thread_id: number | null;
	updated_at: number;
};

export type HomeTarget = {
	ownerId: string;
	chatId: number;
	threadId?: number;
	updatedAt: number;
};

function rowToEntry(row: SessionRow): SessionEntry {
	return {
		sessionId: row.session_id,
		updatedAt: row.updated_at,
		systemSent: row.system_sent === 1,
	};
}

function rowToHomeTarget(row: HomeTargetRow): HomeTarget {
	return {
		ownerId: row.owner_id,
		chatId: row.chat_id,
		...(row.thread_id === null ? {} : { threadId: row.thread_id }),
		updatedAt: row.updated_at,
	};
}

export function getSession(sessionKey: string): SessionEntry | null {
	const db = getDb();
	const row = db.prepare("SELECT * FROM sessions WHERE session_key = ?").get(sessionKey) as
		| SessionRow
		| undefined;

	if (!row) return null;
	return rowToEntry(row);
}

export function setSession(sessionKey: string, entry: SessionEntry): void {
	const db = getDb();
	db.prepare(
		`INSERT INTO sessions (session_key, session_id, updated_at, system_sent)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(session_key) DO UPDATE SET
		   session_id = excluded.session_id,
		   updated_at = excluded.updated_at,
		   system_sent = excluded.system_sent`,
	).run(sessionKey, entry.sessionId, entry.updatedAt, entry.systemSent ? 1 : 0);

	logger.debug({ sessionKey, sessionId: entry.sessionId }, "session updated");
}

export function deleteSession(sessionKey: string): boolean {
	const db = getDb();
	const result = db.prepare("DELETE FROM sessions WHERE session_key = ?").run(sessionKey);
	return result.changes > 0;
}

export function getAllSessions(): Record<string, SessionEntry> {
	const db = getDb();
	const rows = db.prepare("SELECT * FROM sessions").all() as SessionRow[];

	const result: Record<string, SessionEntry> = {};
	for (const row of rows) {
		result[row.session_key] = rowToEntry(row);
	}
	return result;
}

export function resolveHomeTargetOwnerId(chatId: number): string {
	const link = getIdentityLink(chatId);
	return link?.localUserId ?? `tg:${chatId}`;
}

export function getHomeTarget(ownerId: string): HomeTarget | null {
	const db = getDb();
	const row = db.prepare("SELECT * FROM home_targets WHERE owner_id = ?").get(ownerId) as
		| HomeTargetRow
		| undefined;

	if (!row) return null;
	return rowToHomeTarget(row);
}

export function getHomeTargetForChat(chatId: number): HomeTarget | null {
	return getHomeTarget(resolveHomeTargetOwnerId(chatId));
}

export function setHomeTarget(
	ownerId: string,
	target: { chatId: number; threadId?: number },
	updatedAt = Date.now(),
): HomeTarget {
	const db = getDb();
	db.prepare(
		`INSERT INTO home_targets (owner_id, chat_id, thread_id, updated_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(owner_id) DO UPDATE SET
		   chat_id = excluded.chat_id,
		   thread_id = excluded.thread_id,
		   updated_at = excluded.updated_at`,
	).run(ownerId, target.chatId, target.threadId ?? null, updatedAt);

	const stored = getHomeTarget(ownerId);
	if (!stored) {
		throw new Error(`Failed to persist home target for ${ownerId}`);
	}
	return stored;
}

export function setHomeTargetForChat(
	chatId: number,
	threadId?: number,
	updatedAt = Date.now(),
): HomeTarget {
	return setHomeTarget(resolveHomeTargetOwnerId(chatId), { chatId, threadId }, updatedAt);
}

export function formatHomeTarget(target: { chatId: number; threadId?: number } | null): string {
	if (!target) {
		return "not set";
	}
	return target.threadId === undefined
		? `chat ${target.chatId}`
		: `chat ${target.chatId} / topic ${target.threadId}`;
}

export function cleanupIdleSessions(idleMinutes: number): number {
	const db = getDb();
	const cutoff = Date.now() - idleMinutes * 60 * 1000;
	const result = db.prepare("DELETE FROM sessions WHERE updated_at < ?").run(cutoff);

	if (result.changes > 0) {
		logger.debug({ cleaned: result.changes, idleMinutes }, "cleaned up idle sessions");
	}

	return result.changes;
}

export function deriveSessionKey(scope: SessionScope, ctx: MsgContext): string {
	if (scope === "global") return "global";
	const from = ctx.From ? normalizeTelegramId(ctx.From) : "";
	return from || "unknown";
}
