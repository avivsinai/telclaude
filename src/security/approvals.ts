import crypto from "node:crypto";
import type { PermissionTier } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { getDb } from "../storage/db.js";
import type { MediaType } from "../types/media.js";
import type { Result, SecurityClassification } from "./types.js";

const logger = getChildLogger({ module: "approvals" });

const DEFAULT_TTL_MS = 5 * 60 * 1000; // 5 minutes

/**
 * A pending approval request.
 */
export type PendingApproval = {
	nonce: string;
	requestId: string;
	chatId: number;
	createdAt: number;
	expiresAt: number;
	tier: PermissionTier;
	body: string;
	mediaPath?: string;
	mediaUrl?: string;
	mediaType?: MediaType;
	username?: string;
	from: string;
	to: string;
	messageId: string;
	observerClassification: SecurityClassification;
	observerConfidence: number;
	observerReason?: string;
};

/**
 * Database row type for approvals.
 */
type ApprovalRow = {
	nonce: string;
	request_id: string;
	chat_id: number;
	created_at: number;
	expires_at: number;
	tier: string;
	body: string;
	media_path: string | null;
	media_url: string | null;
	media_type: string | null;
	username: string | null;
	from_user: string;
	to_user: string;
	message_id: string;
	observer_classification: string;
	observer_confidence: number;
	observer_reason: string | null;
};

/**
 * Convert database row to PendingApproval.
 */
function rowToApproval(row: ApprovalRow): PendingApproval {
	return {
		nonce: row.nonce,
		requestId: row.request_id,
		chatId: row.chat_id,
		createdAt: row.created_at,
		expiresAt: row.expires_at,
		tier: row.tier as PermissionTier,
		body: row.body,
		mediaPath: row.media_path ?? undefined,
		mediaUrl: row.media_url ?? undefined,
		mediaType: row.media_type as MediaType | undefined,
		username: row.username ?? undefined,
		from: row.from_user,
		to: row.to_user,
		messageId: row.message_id,
		observerClassification: row.observer_classification as SecurityClassification,
		observerConfidence: row.observer_confidence,
		observerReason: row.observer_reason ?? undefined,
	};
}

/**
 * Result of creating an approval, includes timing info for display.
 */
export type CreateApprovalResult = {
	nonce: string;
	createdAt: number;
	expiresAt: number;
};

/**
 * Create a new pending approval and return the nonce with timing info.
 *
 * Nonce is 16 hex characters (8 bytes of entropy) to prevent brute-force attacks.
 * With 8 bytes = 2^64 possibilities, and 5-minute TTL, brute-force is infeasible.
 */
export function createApproval(
	entry: Omit<PendingApproval, "nonce" | "createdAt" | "expiresAt">,
	ttlMs: number = DEFAULT_TTL_MS,
): CreateApprovalResult {
	const db = getDb();

	// Generate a random 16-character nonce (8 bytes = 64 bits of entropy)
	// This prevents brute-force attacks even with high request rates
	const nonce = crypto.randomBytes(8).toString("hex").toLowerCase();
	const now = Date.now();
	const expiresAt = now + ttlMs;

	db.prepare(
		`INSERT INTO approvals (
			nonce, request_id, chat_id, created_at, expires_at, tier, body,
			media_path, media_url, media_type, username, from_user, to_user,
			message_id, observer_classification, observer_confidence, observer_reason
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	).run(
		nonce,
		entry.requestId,
		entry.chatId,
		now,
		expiresAt,
		entry.tier,
		entry.body,
		entry.mediaPath ?? null,
		entry.mediaUrl ?? null,
		entry.mediaType ?? null,
		entry.username ?? null,
		entry.from,
		entry.to,
		entry.messageId,
		entry.observerClassification,
		entry.observerConfidence,
		entry.observerReason ?? null,
	);

	logger.info(
		{
			nonce,
			requestId: entry.requestId,
			chatId: entry.chatId,
			tier: entry.tier,
			expiresIn: Math.round(ttlMs / 1000),
		},
		"approval request created",
	);

	return { nonce, createdAt: now, expiresAt };
}

/**
 * Consume an approval if valid.
 * Returns the approval entry if valid, or an error if not found/expired/wrong chat.
 *
 * Uses a transaction for atomicity - prevents race conditions where two concurrent
 * requests could both consume the same approval.
 */
export function consumeApproval(nonce: string, chatId: number): Result<PendingApproval> {
	const db = getDb();

	// Use a transaction for atomic get-and-delete
	const result = db.transaction(() => {
		const row = db.prepare("SELECT * FROM approvals WHERE nonce = ?").get(nonce) as
			| ApprovalRow
			| undefined;

		if (!row) {
			return { success: false as const, error: "No pending approval found for that code." };
		}

		// Verify chat ID matches
		if (row.chat_id !== chatId) {
			logger.warn(
				{ nonce, expectedChatId: row.chat_id, actualChatId: chatId },
				"approval chat mismatch",
			);
			return { success: false as const, error: "This approval code belongs to a different chat." };
		}

		// Check expiry
		if (Date.now() > row.expires_at) {
			// Delete expired entry
			db.prepare("DELETE FROM approvals WHERE nonce = ?").run(nonce);
			logger.warn({ nonce, chatId }, "approval expired");
			return {
				success: false as const,
				error: "This approval has expired. Please retry your request.",
			};
		}

		// Valid - delete and return
		db.prepare("DELETE FROM approvals WHERE nonce = ?").run(nonce);

		logger.info({ nonce, requestId: row.request_id, chatId }, "approval consumed");

		return { success: true as const, data: rowToApproval(row) };
	})();

	return result;
}

/**
 * Deny/cancel an approval.
 */
export function denyApproval(nonce: string, chatId: number): Result<PendingApproval> {
	const db = getDb();

	const result = db.transaction(() => {
		const row = db.prepare("SELECT * FROM approvals WHERE nonce = ?").get(nonce) as
			| ApprovalRow
			| undefined;

		if (!row) {
			return { success: false as const, error: "No pending approval found for that code." };
		}

		if (row.chat_id !== chatId) {
			return { success: false as const, error: "This approval code belongs to a different chat." };
		}

		db.prepare("DELETE FROM approvals WHERE nonce = ?").run(nonce);

		logger.info({ nonce, requestId: row.request_id, chatId }, "approval denied");

		return { success: true as const, data: rowToApproval(row) };
	})();

	return result;
}

/**
 * Get all pending approvals for a chat.
 */
export function getPendingApprovalsForChat(chatId: number): PendingApproval[] {
	const db = getDb();
	const now = Date.now();

	const rows = db
		.prepare("SELECT * FROM approvals WHERE chat_id = ? AND expires_at > ?")
		.all(chatId, now) as ApprovalRow[];

	return rows.map(rowToApproval);
}

/**
 * Clean up expired approvals.
 */
export function cleanupExpiredApprovals(): number {
	const db = getDb();
	const now = Date.now();

	const result = db.prepare("DELETE FROM approvals WHERE expires_at < ?").run(now);

	if (result.changes > 0) {
		logger.debug({ cleaned: result.changes }, "cleaned up expired approvals");
	}

	return result.changes;
}

/**
 * Get the count of pending approvals.
 */
export function getPendingApprovalCount(): number {
	const db = getDb();
	const now = Date.now();

	const row = db.prepare("SELECT COUNT(*) as count FROM approvals WHERE expires_at > ?").get(now) as
		| { count: number }
		| undefined;

	return row?.count ?? 0;
}

/**
 * Determine if a request requires approval based on tier and classification.
 */
export function requiresApproval(
	tier: PermissionTier,
	classification: SecurityClassification,
	confidence: number,
): boolean {
	// FULL_ACCESS always requires approval
	if (tier === "FULL_ACCESS") {
		return true;
	}

	// BLOCK always requires approval (user can override with /approve)
	if (classification === "BLOCK") {
		return true;
	}

	// WARN with WRITE_SAFE requires approval
	if (classification === "WARN" && tier === "WRITE_SAFE") {
		return true;
	}

	// Low confidence warnings should also require approval
	if (classification === "WARN" && confidence < 0.5) {
		return true;
	}

	return false;
}

/**
 * Get the most recent pending approval for a chat.
 * Used when verifying TOTP-based approvals.
 */
export function getMostRecentPendingApproval(chatId: number): PendingApproval | null {
	const db = getDb();
	const now = Date.now();

	const row = db
		.prepare(
			"SELECT * FROM approvals WHERE chat_id = ? AND expires_at > ? ORDER BY created_at DESC LIMIT 1",
		)
		.get(chatId, now) as ApprovalRow | undefined;

	if (!row) {
		return null;
	}

	return rowToApproval(row);
}

/**
 * Consume the most recent pending approval for a chat (for TOTP-based approval).
 */
export function consumeMostRecentApproval(chatId: number): Result<PendingApproval> {
	const db = getDb();

	const result = db.transaction(() => {
		const now = Date.now();
		const row = db
			.prepare(
				"SELECT * FROM approvals WHERE chat_id = ? AND expires_at > ? ORDER BY created_at DESC LIMIT 1",
			)
			.get(chatId, now) as ApprovalRow | undefined;

		if (!row) {
			return { success: false as const, error: "No pending approval found." };
		}

		// Delete it
		db.prepare("DELETE FROM approvals WHERE nonce = ?").run(row.nonce);

		logger.info(
			{ nonce: row.nonce, requestId: row.request_id, chatId },
			"approval consumed via TOTP",
		);

		return { success: true as const, data: rowToApproval(row) };
	})();

	return result;
}

/**
 * Format a pending approval for display to the user.
 */
export function formatApprovalRequest(approval: PendingApproval, hasTOTPEnabled: boolean): string {
	const expiresIn = Math.max(0, Math.round((approval.expiresAt - Date.now()) / 1000));
	const minutes = Math.floor(expiresIn / 60);
	const seconds = expiresIn % 60;
	const timeStr = minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;

	const lines = [
		"*Approval required* for this request:",
		"```",
		approval.body.length > 500 ? `${approval.body.slice(0, 500)}...` : approval.body,
		"```",
		"",
		`*Tier:* ${approval.tier}`,
		`*Observer:* ${approval.observerClassification} (confidence ${approval.observerConfidence.toFixed(2)})`,
	];

	if (approval.observerReason) {
		lines.push(`*Reason:* ${approval.observerReason}`);
	}

	if (hasTOTPEnabled) {
		// TOTP-based approval (secure)
		lines.push(
			"",
			"Reply with your *6-digit authenticator code* to approve.",
			"To deny, reply: `/deny`",
		);
	} else {
		// Nonce-based approval fallback (less secure than TOTP)
		lines.push(
			"",
			"Set up 2FA with `/setup-2fa` for secure approvals.",
			"",
			`To approve, reply: \`/approve ${approval.nonce}\``,
			`To deny, reply: \`/deny ${approval.nonce}\``,
		);
	}

	lines.push("", `_Expires in ${timeStr}_`);

	return lines.join("\n");
}
