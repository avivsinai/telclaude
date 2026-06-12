/**
 * TOTP session management with SQLite persistence.
 *
 * Provides "remember me" functionality for TOTP verification.
 * Sessions are scoped per-user (localUserId), not per-chat.
 *
 * After a user verifies TOTP once, the session is remembered for
 * a configurable duration (default: 1 week). During this time,
 * subsequent messages don't require TOTP re-verification.
 *
 * Long-lived TOTP sessions are used as an identity verification gate.
 * High-risk side-effect approvals can also require a fresh per-write step-up
 * proof before minting approval tokens; that proof is explicit metadata, not
 * implied by the remembered session alone.
 */

import { getChildLogger } from "../logging.js";
import { getDb } from "../storage/db.js";
import { getIdentityLink } from "./linking.js";

const logger = getChildLogger({ module: "totp-session" });

// Default TTL: 1 week (in milliseconds)
const DEFAULT_SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const DEFAULT_STEP_UP_MAX_AGE_MS = 2 * 60 * 1000;

/**
 * A TOTP verification session.
 */
export type TOTPSession = {
	localUserId: string;
	verifiedAt: number;
	expiresAt: number;
};

export type StepUpVerificationMetadata = {
	/**
	 * Construct only from trusted relay/TOTP verification state, never from model
	 * output or client-supplied request fields.
	 */
	readonly method: "totp";
	readonly actorId: string;
	readonly verifiedAtMs: number;
	readonly expiresAtMs?: number;
	readonly sessionId?: string;
};

export type StepUpVerificationInput = {
	readonly metadata?: StepUpVerificationMetadata;
	readonly requiredActorId: string;
	readonly nowMs?: number;
	readonly maxAgeMs?: number;
};

export type StepUpVerificationResult =
	| {
			readonly ok: true;
			readonly metadata: StepUpVerificationMetadata;
	  }
	| {
			readonly ok: false;
			readonly code: string;
			readonly reason: string;
			readonly retryable: boolean;
	  };

export type StepUpVerification = {
	verify(
		input: StepUpVerificationInput,
	): StepUpVerificationResult | Promise<StepUpVerificationResult>;
};

export const freshTotpStepUpVerification: StepUpVerification = {
	verify: verifyFreshStepUp,
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

export function stepUpMetadataForTOTPSession(input: {
	readonly actorId: string;
	readonly session: TOTPSession;
	readonly sessionId?: string;
}): StepUpVerificationMetadata {
	return {
		method: "totp",
		actorId: requiredStepUpString(input.actorId, "actorId"),
		verifiedAtMs: input.session.verifiedAt,
		expiresAtMs: input.session.expiresAt,
		...(input.sessionId ? { sessionId: requiredStepUpString(input.sessionId, "sessionId") } : {}),
	};
}

export function verifyFreshStepUp(input: StepUpVerificationInput): StepUpVerificationResult {
	const metadata = input.metadata;
	if (!metadata) {
		return stepUpFailure(
			"fresh_step_up_required",
			"fresh TOTP step-up verification is required before minting approval tokens",
			true,
		);
	}
	const nowMs = normalizeStepUpTimestamp(input.nowMs ?? Date.now(), "nowMs");
	const maxAgeMs = normalizeStepUpDuration(
		input.maxAgeMs ?? DEFAULT_STEP_UP_MAX_AGE_MS,
		"maxAgeMs",
	);
	const requiredActorId = requiredStepUpString(input.requiredActorId, "requiredActorId");
	const actorId = requiredStepUpString(metadata.actorId, "metadata.actorId");
	if (actorId !== requiredActorId) {
		return stepUpFailure(
			"fresh_step_up_actor_mismatch",
			"fresh TOTP step-up actor does not match side-effect approver",
			false,
		);
	}
	if (metadata.method !== "totp") {
		return stepUpFailure(
			"fresh_step_up_invalid",
			"fresh step-up verification method is not supported",
			false,
		);
	}
	const verifiedAtMs = normalizeStepUpTimestamp(metadata.verifiedAtMs, "metadata.verifiedAtMs");
	if (verifiedAtMs > nowMs) {
		return stepUpFailure(
			"fresh_step_up_invalid",
			"fresh TOTP step-up verification time is in the future",
			false,
		);
	}
	if (metadata.expiresAtMs !== undefined) {
		const expiresAtMs = normalizeStepUpTimestamp(metadata.expiresAtMs, "metadata.expiresAtMs");
		if (expiresAtMs <= nowMs) {
			return stepUpFailure(
				"fresh_step_up_expired",
				"fresh TOTP step-up verification has expired",
				true,
			);
		}
	}
	if (nowMs - verifiedAtMs > maxAgeMs) {
		return stepUpFailure(
			"fresh_step_up_stale",
			"fresh TOTP step-up verification is too old for this side-effect approval",
			true,
		);
	}
	return { ok: true, metadata };
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

function requiredStepUpString(value: string, field: string): string {
	const trimmed = value.trim();
	if (!trimmed) {
		throw new Error(`${field} is required`);
	}
	return trimmed;
}

function normalizeStepUpTimestamp(value: number, field: string): number {
	if (!Number.isSafeInteger(value) || value < 0) {
		throw new Error(`${field} must be a non-negative integer timestamp`);
	}
	return value;
}

function normalizeStepUpDuration(value: number, field: string): number {
	if (!Number.isSafeInteger(value) || value <= 0 || value > DEFAULT_SESSION_TTL_MS) {
		throw new Error(`${field} must be a positive bounded duration`);
	}
	return value;
}

function stepUpFailure(
	code: string,
	reason: string,
	retryable: boolean,
): Extract<StepUpVerificationResult, { ok: false }> {
	return { ok: false, code, reason, retryable };
}
