/**
 * Session management with SQLite persistence.
 */

import { getChildLogger } from "../logging.js";
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

function rowToEntry(row: SessionRow): SessionEntry {
	return {
		sessionId: row.session_id,
		updatedAt: row.updated_at,
		systemSent: row.system_sent === 1,
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
