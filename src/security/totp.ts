/**
 * TOTP module - uses daemon for secure storage.
 *
 * TOTP is per-user (localUserId), not per-chat.
 * Users must have an identity link before setting up 2FA.
 *
 * This module provides a high-level interface that:
 * 1. Looks up the identity link for a chat
 * 2. Delegates to the TOTP daemon via IPC
 *
 * The daemon stores secrets in the OS keychain, never in SQLite.
 */

import { getChildLogger } from "../logging.js";
import { getTOTPClient, type SetupResult } from "../totp-client/index.js";
import { getIdentityLink } from "./linking.js";

const logger = getChildLogger({ module: "totp" });

/**
 * Result of checking if a chat has TOTP enabled.
 * Distinguishes between "no TOTP" and "daemon unavailable".
 */
export type TOTPCheckResult =
	| { hasTOTP: true }
	| { hasTOTP: false }
	| { hasTOTP: false; error: string };

// ═══════════════════════════════════════════════════════════════════════════════
// Public API (per-chat, requires identity link)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Check if a chat has TOTP 2FA enabled.
 * Requires an identity link - returns { hasTOTP: false } if no link exists.
 * Returns { error } if daemon is unavailable (caller should fail closed).
 */
export async function hasTOTP(chatId: number): Promise<TOTPCheckResult> {
	const link = getIdentityLink(chatId);
	if (!link) {
		logger.debug({ chatId }, "no identity link - TOTP not available");
		return { hasTOTP: false };
	}

	const client = getTOTPClient();
	const result = await client.check(link.localUserId);

	if (result.status === "enabled") {
		return { hasTOTP: true };
	}
	if (result.status === "disabled") {
		return { hasTOTP: false };
	}
	// Daemon unavailable - propagate error so caller can fail closed
	logger.warn({ chatId, error: result.error }, "TOTP daemon unavailable during check");
	return { hasTOTP: false, error: result.error };
}

/**
 * Set up TOTP for a chat.
 * Requires an identity link - returns error if no link exists.
 *
 * Returns the otpauth:// URI for QR code generation.
 */
export async function setupTOTP(chatId: number, label?: string): Promise<SetupResult> {
	const link = getIdentityLink(chatId);
	if (!link) {
		logger.warn({ chatId }, "cannot setup TOTP - no identity link");
		return {
			success: false,
			error:
				"You must link your identity first. Ask an admin to run `telclaude link <user-id>` to generate a link code.",
		};
	}

	const client = getTOTPClient();
	const result = await client.setup(link.localUserId, label ?? link.localUserId);

	if (result.success) {
		logger.info({ chatId, localUserId: link.localUserId }, "TOTP setup initiated");
	}

	return result;
}

/**
 * Verify a TOTP code for a chat.
 * Requires an identity link - returns false if no link exists.
 */
export async function verifyTOTP(chatId: number, code: string): Promise<boolean> {
	const link = getIdentityLink(chatId);
	if (!link) {
		logger.debug({ chatId }, "cannot verify TOTP - no identity link");
		return false;
	}

	const client = getTOTPClient();
	const valid = await client.verify(link.localUserId, code);

	if (valid) {
		logger.debug({ chatId, localUserId: link.localUserId }, "TOTP verified");
	}

	return valid;
}

/**
 * Disable TOTP 2FA for a chat.
 * Requires an identity link - returns false if no link exists.
 */
export async function disableTOTP(chatId: number): Promise<boolean> {
	const link = getIdentityLink(chatId);
	if (!link) {
		logger.debug({ chatId }, "cannot disable TOTP - no identity link");
		return false;
	}

	const client = getTOTPClient();
	const removed = await client.disable(link.localUserId);

	if (removed) {
		logger.info({ chatId, localUserId: link.localUserId }, "TOTP disabled");
	}

	return removed;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Daemon Health Check
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Check if the TOTP daemon is available.
 */
export async function isTOTPDaemonAvailable(): Promise<boolean> {
	const client = getTOTPClient();
	return client.isAvailable();
}
