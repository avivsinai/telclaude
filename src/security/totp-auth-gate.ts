/**
 * TOTP Authentication Gate
 *
 * Standalone authentication layer that challenges users with TOTP verification
 * when their session expires. This runs BEFORE any message processing.
 *
 * Flow:
 * 1. Message arrives
 * 2. Check for valid TOTP session (SQLite, no daemon) → if yes, pass
 * 3. Check if user has TOTP configured (via daemon)
 *    - Daemon unavailable + identity link exists → fail closed (block)
 *    - No TOTP configured → pass
 * 4. TOTP configured but no session:
 *    - If message is a 6-digit code → verify, create session, return "verified"
 *    - Else → save message, return "challenge"
 */

import { getChildLogger } from "../logging.js";
import { getDb } from "../storage/db.js";
import type { TelegramMediaType } from "../telegram/types.js";
import { getIdentityLink } from "./linking.js";
import { createTOTPSession, hasTOTPSession } from "./totp-session.js";
import { hasTOTP, verifyTOTP } from "./totp.js";

const logger = getChildLogger({ module: "totp-auth-gate" });

// TTL for pending messages (5 minutes - same as approvals)
const PENDING_MESSAGE_TTL_MS = 5 * 60 * 1000;

/**
 * Pending message saved while awaiting TOTP verification.
 */
export type PendingTOTPMessage = {
	chatId: number;
	messageId: string;
	body: string;
	mediaPath?: string;
	mediaType?: TelegramMediaType;
	mimeType?: string;
	username?: string;
	senderId?: number;
	createdAt: number;
	expiresAt: number;
};

/**
 * Result of the TOTP auth gate check.
 */
export type TOTPAuthGateResult =
	| { status: "pass" } // No TOTP configured or valid session exists
	| { status: "challenge"; message: string } // Session expired, challenge sent
	| { status: "verified"; pendingMessage?: PendingTOTPMessage } // Code verified, replay if message exists
	| { status: "invalid_code"; message: string } // Wrong TOTP code
	| { status: "error"; message: string }; // Daemon unavailable or other error

// Schema is initialized in storage/db.ts (pending_totp_messages table)

/**
 * Save a pending message while waiting for TOTP verification.
 * Only one pending message per chat (latest wins).
 */
export function savePendingTOTPMessage(
	msg: Omit<PendingTOTPMessage, "createdAt" | "expiresAt">,
): void {
	const db = getDb();
	const now = Date.now();
	const expiresAt = now + PENDING_MESSAGE_TTL_MS;

	db.prepare(
		`INSERT INTO pending_totp_messages
		 (chat_id, message_id, body, media_path, media_type, mime_type, username, sender_id, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(chat_id) DO UPDATE SET
		   message_id = excluded.message_id,
		   body = excluded.body,
		   media_path = excluded.media_path,
		   media_type = excluded.media_type,
		   mime_type = excluded.mime_type,
		   username = excluded.username,
		   sender_id = excluded.sender_id,
		   created_at = excluded.created_at,
		   expires_at = excluded.expires_at`,
	).run(
		msg.chatId,
		msg.messageId,
		msg.body,
		msg.mediaPath ?? null,
		msg.mediaType ?? null,
		msg.mimeType ?? null,
		msg.username ?? null,
		msg.senderId ?? null,
		now,
		expiresAt,
	);

	logger.debug({ chatId: msg.chatId }, "saved pending TOTP message");
}

/**
 * Get and consume (delete) a pending message for a chat.
 * Returns null if no pending message or if expired.
 */
export function consumePendingTOTPMessage(chatId: number): PendingTOTPMessage | null {
	const db = getDb();
	const now = Date.now();

	type Row = {
		chat_id: number;
		message_id: string;
		body: string;
		media_path: string | null;
		media_type: string | null;
		mime_type: string | null;
		username: string | null;
		sender_id: number | null;
		created_at: number;
		expires_at: number;
	};

	const row = db
		.prepare("SELECT * FROM pending_totp_messages WHERE chat_id = ? AND expires_at > ?")
		.get(chatId, now) as Row | undefined;

	if (!row) return null;

	// Delete after retrieval
	db.prepare("DELETE FROM pending_totp_messages WHERE chat_id = ?").run(chatId);

	logger.debug({ chatId }, "consumed pending TOTP message");

	return {
		chatId: row.chat_id,
		messageId: row.message_id,
		body: row.body,
		mediaPath: row.media_path ?? undefined,
		mediaType: (row.media_type as TelegramMediaType) ?? undefined,
		mimeType: row.mime_type ?? undefined,
		username: row.username ?? undefined,
		senderId: row.sender_id ?? undefined,
		createdAt: row.created_at,
		expiresAt: row.expires_at,
	};
}

/**
 * Check if there's a pending message for this chat.
 */
export function hasPendingTOTPMessage(chatId: number): boolean {
	const db = getDb();
	const now = Date.now();
	const row = db
		.prepare("SELECT 1 FROM pending_totp_messages WHERE chat_id = ? AND expires_at > ?")
		.get(chatId, now);
	return !!row;
}

/**
 * Clean up expired pending TOTP messages.
 */
export function cleanupExpiredPendingMessages(): number {
	const db = getDb();
	const now = Date.now();
	const result = db.prepare("DELETE FROM pending_totp_messages WHERE expires_at < ?").run(now);
	return result.changes;
}

/**
 * Main TOTP auth gate check.
 *
 * @param chatId - The Telegram chat ID
 * @param messageBody - The message body (to check if it's a TOTP code)
 * @param messageContext - Full message context for saving if needed
 */
export async function checkTOTPAuthGate(
	chatId: number,
	messageBody: string,
	messageContext: Omit<PendingTOTPMessage, "createdAt" | "expiresAt">,
): Promise<TOTPAuthGateResult> {
	try {
		// 1. Check for valid session first (SQLite only, no daemon call)
		// This avoids hitting the daemon on every message for authenticated users
		if (hasTOTPSession(chatId)) {
			return { status: "pass" };
		}

		// 2. No session - check if user has TOTP configured (requires daemon)
		const totpStatus = await hasTOTP(chatId);

		if ("error" in totpStatus) {
			// Daemon unavailable - fail closed.
			// If we got here, the user has an identity link (hasTOTP checks that first),
			// meaning they could have TOTP enabled. We can't verify without the daemon,
			// so we block to respect their security choice.
			logger.warn(
				{ chatId, error: totpStatus.error },
				"TOTP daemon unavailable - blocking message (user has identity link)",
			);
			return {
				status: "error",
				message:
					"⚠️ 2FA service is temporarily unavailable. Please try again in a moment.",
			};
		}

		if (!totpStatus.hasTOTP) {
			// No TOTP configured for this user - pass through
			return { status: "pass" };
		}

		// 3. TOTP configured but no valid session - challenge/verify

		// Session expired or doesn't exist - check if message is a verification code
		const trimmedBody = messageBody.trim();

		if (/^\d{6}$/.test(trimmedBody)) {
			// Message is a 6-digit code - attempt verification
			// verifyTOTP returns a simple boolean (no error distinction)
			const isValid = await verifyTOTP(chatId, trimmedBody);

			if (!isValid) {
				logger.info({ chatId }, "invalid TOTP code at auth gate");
				return {
					status: "invalid_code",
					message: "Invalid 2FA code. Please try again.",
				};
			}

			// Code is valid - create session
			const link = getIdentityLink(chatId);
			if (link) {
				createTOTPSession(link.localUserId);
				logger.info(
					{ chatId, localUserId: link.localUserId },
					"TOTP auth gate passed - session created",
				);
			}

			// Check for and return any pending message
			const pendingMessage = consumePendingTOTPMessage(chatId);
			return {
				status: "verified",
				pendingMessage: pendingMessage ?? undefined,
			};
		}

		// Not a verification code - save message and challenge
		savePendingTOTPMessage(messageContext);

		const ttlMinutes = Math.round(PENDING_MESSAGE_TTL_MS / 60000);
		return {
			status: "challenge",
			message: `🔐 *Session expired*\n\nPlease enter your 6-digit 2FA code to continue.\n\nYour message has been saved and will be processed after verification.\n_(Saved message expires in ${ttlMinutes} minutes)_`,
		};
	} catch (err) {
		logger.error({ chatId, error: String(err) }, "TOTP auth gate failed");
		return {
			status: "error",
			message: "2FA check failed due to an internal error. Please try again.",
		};
	}
}
