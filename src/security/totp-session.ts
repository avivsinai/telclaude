/**
 * TOTP session management with SQLite persistence.
 *
 * Provides "remember me" functionality for TOTP verification.
 * Sessions are scoped per-user (localUserId), not per-chat.
 *
 * After a user verifies TOTP once, the session is remembered for
 * a configurable duration (default: 24 hours). During this time,
 * subsequent messages don't require TOTP re-verification.
 *
 * NOTE: TOTP is used as an identity verification gate, not for approvals.
 * Approvals use nonce-based confirmation only (intent verification).
 */

import { getChildLogger } from "../logging.js";
import { getDb } from "../storage/db.js";
import { getIdentityLink } from "./linking.js";

const logger = getChildLogger({ module: "totp-session" });

// Default TTL: 24 hours (in milliseconds)
const DEFAULT_SESSION_TTL_MS = 24 * 60 * 60 * 1000;

/**
 * A TOTP verification session.
 */
export type TOTPSession = {
	localUserId: string;
	verifiedAt: number;
	expiresAt: number;
};

/**
 * Database row type.
 */
type TOTPSessionRow = {
	local_user_id: string;
	verified_at: number;
	expires_at: number;
};

/**
 * Create or refresh a TOTP session for a user.
 * Called after successful TOTP verification.
 */
export function createTOTPSession(localUserId: string, ttlMs?: number): TOTPSession {
	const db = getDb();
	const now = Date.now();
	const expiresAt = now + (ttlMs ?? DEFAULT_SESSION_TTL_MS);

	db.prepare(
		`INSERT INTO totp_sessions (local_user_id, verified_at, expires_at)
		 VALUES (?, ?, ?)
		 ON CONFLICT(local_user_id) DO UPDATE SET
		   verified_at = excluded.verified_at,
		   expires_at = excluded.expires_at`,
	).run(localUserId, now, expiresAt);

	const ttlMinutes = Math.round((ttlMs ?? DEFAULT_SESSION_TTL_MS) / 60000);
	logger.info({ localUserId, ttlMinutes }, "TOTP session created");

	return {
		localUserId,
		verifiedAt: now,
		expiresAt,
	};
}

/**
 * Get a TOTP session for a user if it exists and is valid.
 * Returns null if no session exists or if it has expired.
 */
export function getTOTPSession(localUserId: string): TOTPSession | null {
	const db = getDb();
	const now = Date.now();

	const row = db.prepare("SELECT * FROM totp_sessions WHERE local_user_id = ?").get(localUserId) as
		| TOTPSessionRow
		| undefined;

	if (!row) return null;

	// Check if expired
	if (row.expires_at < now) {
		// Clean up expired session
		db.prepare("DELETE FROM totp_sessions WHERE local_user_id = ?").run(localUserId);
		logger.debug({ localUserId }, "TOTP session expired");
		return null;
	}

	return {
		localUserId: row.local_user_id,
		verifiedAt: row.verified_at,
		expiresAt: row.expires_at,
	};
}

/**
 * Check if a chat has a valid TOTP session.
 * Looks up the identity link first, then checks for a valid session.
 * This is the primary API for checking session validity.
 */
export function hasTOTPSession(chatId: number): boolean {
	const link = getIdentityLink(chatId);
	if (!link) return false;

	const session = getTOTPSession(link.localUserId);
	return session !== null;
}

/**
 * Get session info for a chat (for display purposes).
 * Returns null if no identity link or no valid session.
 */
export function getTOTPSessionForChat(chatId: number): TOTPSession | null {
	const link = getIdentityLink(chatId);
	if (!link) return null;

	return getTOTPSession(link.localUserId);
}

/**
 * Invalidate a TOTP session for a user.
 * Returns true if a session was removed, false if none existed.
 */
export function invalidateTOTPSession(localUserId: string): boolean {
	const db = getDb();
	const result = db.prepare("DELETE FROM totp_sessions WHERE local_user_id = ?").run(localUserId);

	if (result.changes > 0) {
		logger.info({ localUserId }, "TOTP session invalidated");
		return true;
	}

	return false;
}

/**
 * Invalidate TOTP session for a chat.
 * Looks up the identity link first.
 * Returns true if a session was removed, false if none existed.
 */
export function invalidateTOTPSessionForChat(chatId: number): boolean {
	const link = getIdentityLink(chatId);
	if (!link) return false;

	return invalidateTOTPSession(link.localUserId);
}

/**
 * Clean up expired TOTP sessions.
 * Returns the number of sessions cleaned.
 */
export function cleanupExpiredTOTPSessions(): number {
	const db = getDb();
	const now = Date.now();
	const result = db.prepare("DELETE FROM totp_sessions WHERE expires_at < ?").run(now);

	if (result.changes > 0) {
		logger.debug({ cleaned: result.changes }, "cleaned up expired TOTP sessions");
	}

	return result.changes;
}
