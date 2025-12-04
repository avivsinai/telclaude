/**
 * Admin Claim Flow - V2 Security
 *
 * Implements first-time admin setup for single-user deployments:
 * - First private message triggers claim flow
 * - Only private chats can claim admin (groups rejected)
 * - Requires /approve <code> confirmation within timeout
 * - After claim, prompts for TOTP setup
 *
 * Design principles:
 * - Private-chat-only prevents group channel hijacking
 * - Confirmation code prevents accidental claims
 * - Audit trail for all claim attempts
 */

import crypto from "node:crypto";
import { getChildLogger } from "../logging.js";
import { getDb } from "../storage/db.js";
import type { AuditLogger } from "./audit.js";

const logger = getChildLogger({ module: "admin-claim" });

// ═══════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════

const CLAIM_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes
const CLAIM_CODE_LENGTH = 6; // 6 characters for easy typing

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

export interface PendingAdminClaim {
	code: string;
	chatId: number;
	userId?: number;
	username?: string;
	createdAt: number;
	expiresAt: number;
}

type PendingClaimRow = {
	code: string;
	chat_id: number;
	user_id: number | null;
	username: string | null;
	created_at: number;
	expires_at: number;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Database Schema
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Ensure the pending_admin_claims table exists.
 */
export function ensureAdminClaimTable(): void {
	const db = getDb();
	db.exec(`
		CREATE TABLE IF NOT EXISTS pending_admin_claims (
			code TEXT PRIMARY KEY,
			chat_id INTEGER NOT NULL,
			user_id INTEGER,
			username TEXT,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_pending_admin_claims_chat ON pending_admin_claims(chat_id);
		CREATE INDEX IF NOT EXISTS idx_pending_admin_claims_expires ON pending_admin_claims(expires_at);
	`);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Admin Status Check
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Check if any admin has been claimed yet.
 * Returns true if there's at least one identity link with admin status.
 */
export function hasAdmin(): boolean {
	const db = getDb();
	// Check if any identity links exist - the first linked user is effectively admin
	const row = db.prepare("SELECT COUNT(*) as count FROM identity_links").get() as {
		count: number;
	};
	return row.count > 0;
}

/**
 * Check if a chat is the admin chat.
 */
export function isAdminChat(chatId: number): boolean {
	const db = getDb();
	// The first identity link is considered admin
	// In single-user mode, any linked chat is effectively admin
	const row = db
		.prepare("SELECT chat_id FROM identity_links ORDER BY linked_at ASC LIMIT 1")
		.get() as { chat_id: number } | undefined;
	return row?.chat_id === chatId;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Claim Flow
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Generate a secure claim code.
 */
function generateClaimCode(): string {
	// Use alphanumeric characters for easy typing (no confusing chars like 0/O, 1/l)
	const chars = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
	const bytes = crypto.randomBytes(CLAIM_CODE_LENGTH);
	let code = "";
	for (let i = 0; i < CLAIM_CODE_LENGTH; i++) {
		code += chars[bytes[i] % chars.length];
	}
	return code;
}

/**
 * Start admin claim flow for a chat.
 * Returns the claim code and expiry time.
 */
export function startAdminClaim(
	chatId: number,
	opts?: { userId?: number; username?: string },
): { code: string; expiresAt: number } {
	ensureAdminClaimTable();
	const db = getDb();
	const now = Date.now();
	const expiresAt = now + CLAIM_EXPIRY_MS;
	const code = generateClaimCode();

	// Remove any existing pending claim for this chat
	db.prepare("DELETE FROM pending_admin_claims WHERE chat_id = ?").run(chatId);

	// Insert new pending claim
	db.prepare(
		`INSERT INTO pending_admin_claims (code, chat_id, user_id, username, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
	).run(code, chatId, opts?.userId ?? null, opts?.username ?? null, now, expiresAt);

	logger.info({ chatId, userId: opts?.userId, username: opts?.username }, "admin claim started");

	return { code, expiresAt };
}

/**
 * Verify and consume an admin claim code.
 * Returns success status and error message if failed.
 */
export function consumeAdminClaim(
	code: string,
	chatId: number,
): { success: true; claim: PendingAdminClaim } | { success: false; error: string } {
	ensureAdminClaimTable();
	const db = getDb();
	const now = Date.now();

	// Normalize code (uppercase, strip whitespace)
	const normalizedCode = code.toUpperCase().trim();

	const result = db.transaction(() => {
		// Find the pending claim
		const row = db
			.prepare("SELECT * FROM pending_admin_claims WHERE code = ?")
			.get(normalizedCode) as PendingClaimRow | undefined;

		if (!row) {
			return { success: false as const, error: "Invalid claim code. Please try again." };
		}

		// Check chat ID matches
		if (row.chat_id !== chatId) {
			logger.warn(
				{ code: normalizedCode, expectedChatId: row.chat_id, actualChatId: chatId },
				"admin claim code used in wrong chat",
			);
			return {
				success: false as const,
				error: "This code was generated for a different chat.",
			};
		}

		// Check expiry
		if (row.expires_at < now) {
			db.prepare("DELETE FROM pending_admin_claims WHERE code = ?").run(normalizedCode);
			return {
				success: false as const,
				error: "Claim code has expired. Please send any message to start again.",
			};
		}

		// Consume the claim
		db.prepare("DELETE FROM pending_admin_claims WHERE code = ?").run(normalizedCode);

		const claim: PendingAdminClaim = {
			code: row.code,
			chatId: row.chat_id,
			userId: row.user_id ?? undefined,
			username: row.username ?? undefined,
			createdAt: row.created_at,
			expiresAt: row.expires_at,
		};

		return { success: true as const, claim };
	})();

	return result;
}

/**
 * Complete admin claim by creating identity link.
 */
export function completeAdminClaim(
	chatId: number,
	opts?: { userId?: number; username?: string },
): void {
	const db = getDb();
	const now = Date.now();

	// Create identity link for the admin chat
	// Use "admin" as the local user ID for single-user mode
	const localUserId = "admin";
	const linkedBy = opts?.username ?? String(chatId);

	db.prepare(
		`INSERT INTO identity_links (chat_id, local_user_id, linked_at, linked_by)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(chat_id) DO UPDATE SET
		   local_user_id = excluded.local_user_id,
		   linked_at = excluded.linked_at,
		   linked_by = excluded.linked_by`,
	).run(chatId, localUserId, now, linkedBy);

	logger.info({ chatId, localUserId, linkedBy }, "admin claim completed");
}

/**
 * Get pending admin claim for a chat, if any.
 */
export function getPendingAdminClaim(chatId: number): PendingAdminClaim | null {
	ensureAdminClaimTable();
	const db = getDb();
	const now = Date.now();

	// Clean up expired claims first
	db.prepare("DELETE FROM pending_admin_claims WHERE expires_at < ?").run(now);

	const row = db.prepare("SELECT * FROM pending_admin_claims WHERE chat_id = ?").get(chatId) as
		| PendingClaimRow
		| undefined;

	if (!row) return null;

	return {
		code: row.code,
		chatId: row.chat_id,
		userId: row.user_id ?? undefined,
		username: row.username ?? undefined,
		createdAt: row.created_at,
		expiresAt: row.expires_at,
	};
}

/**
 * Clean up expired admin claims.
 */
export function cleanupExpiredAdminClaims(): number {
	ensureAdminClaimTable();
	const db = getDb();
	const now = Date.now();
	const result = db.prepare("DELETE FROM pending_admin_claims WHERE expires_at < ?").run(now);

	if (result.changes > 0) {
		logger.debug({ cleaned: result.changes }, "cleaned up expired admin claims");
	}

	return result.changes;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Message Formatting
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Format the admin claim prompt message.
 */
export function formatAdminClaimPrompt(code: string, expiresInSeconds: number): string {
	return `🔐 *First-time setup*\n\nTo link this chat as admin, reply with:\n\`/approve ${code}\`\n\nThis code expires in ${Math.ceil(expiresInSeconds / 60)} minutes.\n\n⚠️ If you did NOT initiate this setup, ignore this message.`;
}

/**
 * Format the admin claim success message.
 */
export function formatAdminClaimSuccess(): string {
	return (
		"✅ *Chat linked as admin*\n\n" +
		"This chat now has FULL_ACCESS permissions.\n\n" +
		"⚠️ *TOTP is recommended* to protect against Telegram account hijacking.\n\n" +
		"Set up now? Reply:\n" +
		"• `/setup-2fa` - Set up two-factor authentication\n" +
		"• `/skip-totp` - Skip for now (not recommended)"
	);
}

/**
 * Format the group chat rejection message.
 */
export function formatGroupRejection(): string {
	return (
		"❌ *Admin setup only works in private chats*\n\n" +
		"For security, admin must be set up via direct message to the bot.\n\n" +
		"Please send a direct message to start the admin claim process."
	);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Handler Integration
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Handle the first message when no admin is set up yet.
 * Returns the response message to send, or null if the message should proceed normally.
 *
 * IMPORTANT: If there's already a pending claim for this chat and the message
 * looks like an /approve command, we return handled: false to let the approve
 * handler process it instead of starting a new claim.
 */
export async function handleFirstMessageIfNoAdmin(
	chatId: number,
	chatType: "private" | "group" | "supergroup" | "channel",
	messageBody: string,
	opts?: { userId?: number; username?: string },
	auditLogger?: AuditLogger,
): Promise<{ response: string; handled: true } | { handled: false }> {
	// Check if admin is already set up
	if (hasAdmin()) {
		return { handled: false };
	}

	// Only private chats can claim admin
	if (chatType !== "private") {
		logger.warn({ chatId, chatType }, "group chat attempted admin claim - rejected");

		if (auditLogger) {
			await auditLogger.log({
				timestamp: new Date(),
				requestId: `admin_claim_${Date.now()}`,
				telegramUserId: String(opts?.userId ?? chatId),
				telegramUsername: opts?.username,
				chatId,
				messagePreview: "(admin claim attempt from group)",
				permissionTier: "READ_ONLY",
				outcome: "blocked",
				errorType: "admin_claim_group_rejected",
			});
		}

		return { response: formatGroupRejection(), handled: true };
	}

	// Check if there's already a pending claim for this chat
	const existingClaim = getPendingAdminClaim(chatId);

	// If there's a pending claim AND the message is /approve, let it through
	// so the approve handler can process it
	if (existingClaim && messageBody.trim().toLowerCase().startsWith("/approve")) {
		return { handled: false };
	}

	// Start the claim flow (or restart if there was an existing expired one)
	const { code, expiresAt } = startAdminClaim(chatId, opts);
	const expiresInSeconds = Math.ceil((expiresAt - Date.now()) / 1000);

	if (auditLogger) {
		await auditLogger.log({
			timestamp: new Date(),
			requestId: `admin_claim_${Date.now()}`,
			telegramUserId: String(opts?.userId ?? chatId),
			telegramUsername: opts?.username,
			chatId,
			messagePreview: "(admin claim started)",
			permissionTier: "READ_ONLY",
			outcome: "success",
			errorType: `admin_claim_started:${code}`,
		});
	}

	return { response: formatAdminClaimPrompt(code, expiresInSeconds), handled: true };
}

/**
 * Handle /approve command during admin claim flow.
 * Returns the response message to send, or null if not an admin claim.
 */
export async function handleAdminClaimApproval(
	code: string,
	chatId: number,
	opts?: { userId?: number; username?: string },
	auditLogger?: AuditLogger,
): Promise<{ response: string; success: boolean } | null> {
	// Check if there's a pending admin claim
	const pending = getPendingAdminClaim(chatId);
	if (!pending) {
		return null; // Not an admin claim, let normal /approve handling take over
	}

	// Try to consume the claim
	const result = consumeAdminClaim(code, chatId);

	if (!result.success) {
		if (auditLogger) {
			await auditLogger.log({
				timestamp: new Date(),
				requestId: `admin_claim_${Date.now()}`,
				telegramUserId: String(opts?.userId ?? chatId),
				telegramUsername: opts?.username,
				chatId,
				messagePreview: "(admin claim failed)",
				permissionTier: "READ_ONLY",
				outcome: "blocked",
				errorType: `admin_claim_failed:${result.error}`,
			});
		}
		return { response: result.error, success: false };
	}

	// Complete the claim
	completeAdminClaim(chatId, opts);

	if (auditLogger) {
		await auditLogger.log({
			timestamp: new Date(),
			requestId: `admin_claim_${Date.now()}`,
			telegramUserId: String(opts?.userId ?? chatId),
			telegramUsername: opts?.username,
			chatId,
			messagePreview: "(admin claim completed)",
			permissionTier: "FULL_ACCESS",
			outcome: "success",
			errorType: "admin_claim_completed",
		});
	}

	logger.info({ chatId, username: opts?.username }, "admin claim completed successfully");

	return { response: formatAdminClaimSuccess(), success: true };
}
