/**
 * Identity linking with SQLite persistence.
 *
 * Links Telegram chats to local user identities via out-of-band verification.
 * The flow:
 * 1. Admin generates a link code: `telclaude link tg:123456789`
 * 2. User enters the code in Telegram: `/link ABC1-2345`
 * 3. If valid, their identity is linked and they receive assigned permissions
 */

import crypto from "node:crypto";
import { getChildLogger } from "../logging.js";
import { getDb } from "../storage/db.js";
import type { Result } from "./types.js";

const logger = getChildLogger({ module: "identity-linking" });

const CODE_EXPIRY_MS = 10 * 60 * 1000; // 10 minutes

/**
 * A pending link code awaiting chat verification.
 */
export type PendingLinkCode = {
	code: string;
	localUserId: string;
	createdAt: number;
	expiresAt: number;
};

/**
 * A completed identity link between a Telegram chat and a local user.
 */
export type IdentityLink = {
	chatId: number;
	localUserId: string;
	linkedAt: number;
	linkedBy: string;
};

/**
 * Database row types.
 */
type PendingLinkCodeRow = {
	code: string;
	local_user_id: string;
	created_at: number;
	expires_at: number;
};

type IdentityLinkRow = {
	chat_id: number;
	local_user_id: string;
	linked_at: number;
	linked_by: string;
};

/**
 * Generate a new link code for a local user.
 * Returns the generated code.
 */
export function generateLinkCode(localUserId: string): string {
	const db = getDb();
	const now = Date.now();

	// Generate a random 8-character code (4 bytes = 8 hex chars)
	const code = crypto.randomBytes(4).toString("hex").toUpperCase();

	// Format as XXXX-XXXX for readability
	const formattedCode = `${code.slice(0, 4)}-${code.slice(4)}`;

	db.prepare(
		`INSERT INTO pending_link_codes (code, local_user_id, created_at, expires_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(code) DO UPDATE SET
		   local_user_id = excluded.local_user_id,
		   created_at = excluded.created_at,
		   expires_at = excluded.expires_at`,
	).run(formattedCode, localUserId, now, now + CODE_EXPIRY_MS);

	logger.info({ code: formattedCode, localUserId }, "generated link code");

	return formattedCode;
}

/**
 * Verify and consume a link code, creating an identity link.
 * Returns the local user ID if successful, or an error if invalid/expired.
 */
export function consumeLinkCode(
	code: string,
	chatId: number,
	linkedBy: string,
): Result<{ localUserId: string }> {
	const db = getDb();
	const now = Date.now();

	// Normalize code format (allow with or without dash)
	const normalizedCode = code.toUpperCase().replace(/[^A-F0-9]/g, "");
	const formattedCode =
		normalizedCode.length === 8
			? `${normalizedCode.slice(0, 4)}-${normalizedCode.slice(4)}`
			: code.toUpperCase();

	const result = db.transaction(() => {
		const row = db.prepare("SELECT * FROM pending_link_codes WHERE code = ?").get(formattedCode) as
			| PendingLinkCodeRow
			| undefined;

		if (!row) {
			logger.warn({ code: formattedCode, chatId }, "invalid link code");
			return {
				success: false as const,
				error: "Invalid link code. Please generate a new one with `telclaude link`.",
			};
		}

		if (row.expires_at < now) {
			// Delete expired code
			db.prepare("DELETE FROM pending_link_codes WHERE code = ?").run(formattedCode);
			logger.warn({ code: formattedCode, chatId }, "expired link code");
			return {
				success: false as const,
				error: "Link code has expired. Please generate a new one with `telclaude link`.",
			};
		}

		// Create the identity link (upsert)
		db.prepare(
			`INSERT INTO identity_links (chat_id, local_user_id, linked_at, linked_by)
			 VALUES (?, ?, ?, ?)
			 ON CONFLICT(chat_id) DO UPDATE SET
			   local_user_id = excluded.local_user_id,
			   linked_at = excluded.linked_at,
			   linked_by = excluded.linked_by`,
		).run(chatId, row.local_user_id, now, linkedBy);

		// Remove the consumed code
		db.prepare("DELETE FROM pending_link_codes WHERE code = ?").run(formattedCode);

		logger.info(
			{ code: formattedCode, chatId, localUserId: row.local_user_id, linkedBy },
			"identity link created",
		);

		return { success: true as const, data: { localUserId: row.local_user_id } };
	})();

	return result;
}

/**
 * Get the identity link for a chat, if any.
 */
export function getIdentityLink(chatId: number): IdentityLink | null {
	const db = getDb();
	const row = db.prepare("SELECT * FROM identity_links WHERE chat_id = ?").get(chatId) as
		| IdentityLinkRow
		| undefined;

	if (!row) return null;

	return {
		chatId: row.chat_id,
		localUserId: row.local_user_id,
		linkedAt: row.linked_at,
		linkedBy: row.linked_by,
	};
}

/**
 * Remove an identity link for a chat.
 */
export function removeIdentityLink(chatId: number): boolean {
	const db = getDb();
	const result = db.prepare("DELETE FROM identity_links WHERE chat_id = ?").run(chatId);

	if (result.changes > 0) {
		logger.info({ chatId }, "identity link removed");
		return true;
	}

	return false;
}

/**
 * List all identity links.
 */
export function listIdentityLinks(): IdentityLink[] {
	const db = getDb();
	const rows = db.prepare("SELECT * FROM identity_links").all() as IdentityLinkRow[];

	return rows.map((row) => ({
		chatId: row.chat_id,
		localUserId: row.local_user_id,
		linkedAt: row.linked_at,
		linkedBy: row.linked_by,
	}));
}

/**
 * Check if a chat has a verified identity link.
 */
export function isLinked(chatId: number): boolean {
	return getIdentityLink(chatId) !== null;
}

/**
 * Clean up expired pending link codes.
 */
export function cleanupExpiredCodes(): number {
	const db = getDb();
	const now = Date.now();
	const result = db.prepare("DELETE FROM pending_link_codes WHERE expires_at < ?").run(now);

	if (result.changes > 0) {
		logger.debug({ cleaned: result.changes }, "cleaned up expired link codes");
	}

	return result.changes;
}
