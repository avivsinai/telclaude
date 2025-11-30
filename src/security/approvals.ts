import crypto from "node:crypto";
import type { PermissionTier } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { getDb } from "../storage/db.js";
import type { TelegramMediaType } from "../telegram/types.js";
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
	mediaType?: TelegramMediaType;
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
		mediaType: row.media_type as TelegramMediaType | undefined,
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
 * Create a new pending approval and return the nonce.
 */
export function createApproval(
	entry: Omit<PendingApproval, "nonce" | "createdAt" | "expiresAt">,
	ttlMs: number = DEFAULT_TTL_MS,
): string {
	const db = getDb();

	// Generate a random 8-character nonce
	const nonce = crypto.randomBytes(4).toString("hex").toLowerCase();
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

	return nonce;
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
 * Format a pending approval for display to the user.
 */
export function formatApprovalRequest(approval: PendingApproval): string {
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

	lines.push(
		"",
		`To approve, reply: \`/approve ${approval.nonce}\``,
		`To deny, reply: \`/deny ${approval.nonce}\``,
		"",
		`_Expires in ${timeStr}_`,
	);

	return lines.join("\n");
}
