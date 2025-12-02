/**
 * Keychain wrapper for TOTP secrets using keytar.
 *
 * Uses the OS-native credential storage:
 * - macOS: Keychain
 * - Linux: libsecret (GNOME Keyring / KWallet)
 * - Windows: Credential Vault
 *
 * Secrets are stored per localUserId, not per chatId.
 * This ensures one TOTP secret per user across all their linked chats.
 */

import keytar from "keytar";
import { Secret, TOTP } from "otpauth";
import { getChildLogger } from "../logging.js";

const logger = getChildLogger({ module: "keychain" });

const SERVICE_NAME = "telclaude";
const ISSUER = "Telclaude";

// ═══════════════════════════════════════════════════════════════════════════════
// Low-level Keychain Operations
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Store a TOTP secret in the OS keychain.
 */
export async function storeSecret(localUserId: string, secret: Secret): Promise<void> {
	const account = `totp:${localUserId}`;
	await keytar.setPassword(SERVICE_NAME, account, secret.base32);
	logger.debug({ localUserId }, "stored TOTP secret in keychain");
}

/**
 * Retrieve a TOTP secret from the OS keychain.
 * Returns null if no secret exists for this user.
 */
export async function getSecret(localUserId: string): Promise<Secret | null> {
	const account = `totp:${localUserId}`;
	const base32 = await keytar.getPassword(SERVICE_NAME, account);
	if (!base32) return null;
	return Secret.fromBase32(base32);
}

/**
 * Delete a TOTP secret from the OS keychain.
 */
export async function deleteSecret(localUserId: string): Promise<boolean> {
	const account = `totp:${localUserId}`;
	const deleted = await keytar.deletePassword(SERVICE_NAME, account);
	if (deleted) {
		logger.info({ localUserId }, "deleted TOTP secret from keychain");
	}
	return deleted;
}

/**
 * Check if a user has a TOTP secret configured.
 */
export async function hasSecret(localUserId: string): Promise<boolean> {
	const account = `totp:${localUserId}`;
	const secret = await keytar.getPassword(SERVICE_NAME, account);
	return secret !== null;
}

// ═══════════════════════════════════════════════════════════════════════════════
// High-level TOTP Operations
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Generate a new TOTP secret and store it in the keychain.
 * Returns the otpauth:// URI for QR code generation.
 *
 * If a secret already exists, returns an error.
 */
export async function setupTOTP(
	localUserId: string,
	label?: string,
): Promise<{ success: true; uri: string } | { success: false; error: string }> {
	// Check for existing secret
	if (await hasSecret(localUserId)) {
		return {
			success: false,
			error: "2FA is already enabled for this user. Disable it first to reconfigure.",
		};
	}

	// Generate a new secret (160 bits = 20 bytes, per RFC 6238 recommendation)
	const secret = new Secret({ size: 20 });

	const totp = new TOTP({
		issuer: ISSUER,
		label: label ?? localUserId,
		algorithm: "SHA1", // Google Authenticator only supports SHA1
		digits: 6,
		period: 30,
		secret,
	});

	// Store in keychain
	await storeSecret(localUserId, secret);

	logger.info({ localUserId }, "TOTP setup initiated");

	return {
		success: true,
		uri: totp.toString(),
	};
}

/**
 * Verify a TOTP code for a user.
 * Returns true if the code is valid.
 */
export async function verifyTOTP(localUserId: string, code: string): Promise<boolean> {
	const secret = await getSecret(localUserId);
	if (!secret) {
		logger.debug({ localUserId }, "TOTP verification failed - no secret configured");
		return false;
	}

	const totp = new TOTP({
		issuer: ISSUER,
		algorithm: "SHA1",
		digits: 6,
		period: 30,
		secret,
	});

	// Window of 1 = allows current, previous, and next code (90 seconds total)
	const delta = totp.validate({ token: code, window: 1 });

	if (delta === null) {
		logger.debug({ localUserId }, "TOTP verification failed - invalid code");
		return false;
	}

	logger.debug({ localUserId, delta }, "TOTP verified successfully");
	return true;
}

/**
 * Disable TOTP for a user by removing their secret.
 */
export async function disableTOTP(localUserId: string): Promise<boolean> {
	return deleteSecret(localUserId);
}
