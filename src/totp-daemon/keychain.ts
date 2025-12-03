/**
 * Keychain wrapper for TOTP secrets.
 *
 * Supports multiple storage backends:
 * - keytar (OS keychain) - macOS Keychain, Linux libsecret, Windows Credential Vault
 * - encrypted file - for Docker/headless deployments
 *
 * Backend selection is handled by storage-provider.ts based on environment.
 *
 * Secrets are stored per localUserId, not per chatId.
 * This ensures one TOTP secret per user across all their linked chats.
 */

import { Secret, TOTP } from "otpauth";
import { getChildLogger } from "../logging.js";
import { getStorageProvider, isStorageAvailable } from "./storage-provider.js";

const logger = getChildLogger({ module: "keychain" });

const ISSUER = "Telclaude";

// ═══════════════════════════════════════════════════════════════════════════════
// Low-level Storage Operations
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Store a TOTP secret.
 */
export async function storeSecret(localUserId: string, secret: Secret): Promise<void> {
	const provider = await getStorageProvider();
	await provider.storeSecret(localUserId, secret);
}

/**
 * Retrieve a TOTP secret.
 * Returns null if no secret exists for this user.
 */
export async function getSecret(localUserId: string): Promise<Secret | null> {
	const provider = await getStorageProvider();
	return provider.getSecret(localUserId);
}

/**
 * Delete a TOTP secret.
 */
export async function deleteSecret(localUserId: string): Promise<boolean> {
	const provider = await getStorageProvider();
	return provider.deleteSecret(localUserId);
}

/**
 * Check if a user has a TOTP secret configured.
 */
export async function hasSecret(localUserId: string): Promise<boolean> {
	const provider = await getStorageProvider();
	return provider.hasSecret(localUserId);
}

// ═══════════════════════════════════════════════════════════════════════════════
// High-level TOTP Operations
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Generate a new TOTP secret and store it.
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

	// Store the secret
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

/**
 * Check if TOTP storage is available.
 * Returns true if either keytar or file storage can be used.
 */
export { isStorageAvailable };
