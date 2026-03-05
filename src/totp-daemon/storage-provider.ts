/**
 * Storage provider abstraction for TOTP secrets.
 *
 * Allows switching between:
 * - keytar (OS keychain) - for native deployments
 * - encrypted file - for Docker/headless deployments
 *
 * The provider is selected based on TOTP_STORAGE_BACKEND env var
 * or auto-detected at runtime.
 */

import { join } from "node:path";

import { Secret } from "otpauth";
import { EncryptedFileStore } from "../crypto/encrypted-file-store.js";
import { KeytarStore } from "../crypto/keytar-store.js";
import { getChildLogger } from "../logging.js";

const logger = getChildLogger({ module: "totp-storage" });

// ═══════════════════════════════════════════════════════════════════════════════
// Storage Provider Interface
// ═══════════════════════════════════════════════════════════════════════════════

export interface TOTPStorageProvider {
	readonly name: string;

	/** Store a TOTP secret for a user */
	storeSecret(localUserId: string, secret: Secret): Promise<void>;

	/** Retrieve a TOTP secret for a user (null if not found) */
	getSecret(localUserId: string): Promise<Secret | null>;

	/** Delete a TOTP secret for a user */
	deleteSecret(localUserId: string): Promise<boolean>;

	/** Check if a user has a TOTP secret */
	hasSecret(localUserId: string): Promise<boolean>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Keytar Provider (OS Keychain)
// ═══════════════════════════════════════════════════════════════════════════════

class KeytarProvider implements TOTPStorageProvider {
	readonly name = "keytar";
	private keytarStore = new KeytarStore();

	async storeSecret(localUserId: string, secret: Secret): Promise<void> {
		await this.keytarStore.store(`totp:${localUserId}`, secret.base32);
		logger.debug({ localUserId, provider: this.name }, "stored TOTP secret");
	}

	async getSecret(localUserId: string): Promise<Secret | null> {
		const base32 = await this.keytarStore.get(`totp:${localUserId}`);
		if (!base32) return null;
		return Secret.fromBase32(base32);
	}

	async deleteSecret(localUserId: string): Promise<boolean> {
		const deleted = await this.keytarStore.delete(`totp:${localUserId}`);
		if (deleted) {
			logger.info({ localUserId, provider: this.name }, "deleted TOTP secret");
		}
		return deleted;
	}

	async hasSecret(localUserId: string): Promise<boolean> {
		return this.keytarStore.has(`totp:${localUserId}`);
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Encrypted File Provider (Docker-compatible)
// ═══════════════════════════════════════════════════════════════════════════════

class EncryptedFileProvider implements TOTPStorageProvider {
	readonly name = "encrypted-file";
	private store: EncryptedFileStore;

	constructor(filePath: string, encryptionKey: string) {
		this.store = new EncryptedFileStore(filePath, encryptionKey);
		logger.debug({ filePath, provider: this.name }, "initialized encrypted file provider");
	}

	async storeSecret(localUserId: string, secret: Secret): Promise<void> {
		this.store.store(localUserId, secret.base32);
		logger.debug({ localUserId, provider: this.name }, "stored TOTP secret");
	}

	async getSecret(localUserId: string): Promise<Secret | null> {
		const base32 = this.store.get(localUserId);
		if (!base32) return null;

		try {
			return Secret.fromBase32(base32);
		} catch (err) {
			logger.error({ localUserId, error: String(err) }, "failed to parse TOTP secret");
			return null;
		}
	}

	async deleteSecret(localUserId: string): Promise<boolean> {
		const deleted = this.store.delete(localUserId);
		if (deleted) {
			logger.info({ localUserId, provider: this.name }, "deleted TOTP secret");
		}
		return deleted;
	}

	async hasSecret(localUserId: string): Promise<boolean> {
		return this.store.has(localUserId);
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Provider Factory
// ═══════════════════════════════════════════════════════════════════════════════

let cachedProvider: TOTPStorageProvider | null = null;

/**
 * Get the configured TOTP storage provider.
 *
 * Selection order:
 * 1. TOTP_STORAGE_BACKEND env var ("keytar" or "file")
 * 2. Auto-detect: file if TOTP_ENCRYPTION_KEY is set, otherwise keytar
 *
 * For file backend:
 * - TOTP_ENCRYPTION_KEY (required): Encryption key for secrets
 * - TOTP_SECRETS_FILE (optional): Path to secrets file (default: $TELCLAUDE_DATA_DIR/totp-secrets.json)
 */
export async function getStorageProvider(): Promise<TOTPStorageProvider> {
	if (cachedProvider) return cachedProvider;

	const backend = process.env.TOTP_STORAGE_BACKEND?.toLowerCase();
	const encryptionKey = process.env.TOTP_ENCRYPTION_KEY;

	// Determine which backend to use
	let useFile = false;

	if (backend === "file") {
		useFile = true;
	} else if (backend === "keytar") {
		useFile = false;
	} else if (encryptionKey) {
		// Auto-detect: if encryption key is set, use file backend
		useFile = true;
	}

	if (useFile) {
		if (!encryptionKey) {
			throw new Error(
				"TOTP_ENCRYPTION_KEY environment variable is required for file-based storage. " +
					"Generate a strong key: openssl rand -base64 32",
			);
		}

		const dataDir =
			process.env.TELCLAUDE_DATA_DIR || join(process.env.HOME || "/tmp", ".telclaude");
		const filePath = process.env.TOTP_SECRETS_FILE || join(dataDir, "totp-secrets.json");

		cachedProvider = new EncryptedFileProvider(filePath, encryptionKey);
	} else {
		// Try keytar, but check if it's actually available
		try {
			const provider = new KeytarProvider();
			// Test if keytar works by trying to access it
			await provider.hasSecret("__test__");
			cachedProvider = provider;
		} catch (err) {
			logger.warn(
				{ error: String(err) },
				"keytar not available, falling back to encrypted file storage",
			);

			// Fallback to file storage if keytar fails
			if (!encryptionKey) {
				throw new Error(
					"keytar is not available and TOTP_ENCRYPTION_KEY is not set. " +
						"Either install libsecret-1-dev (Linux) or set TOTP_ENCRYPTION_KEY for file-based storage.",
				);
			}

			const dataDir =
				process.env.TELCLAUDE_DATA_DIR || join(process.env.HOME || "/tmp", ".telclaude");
			const filePath = process.env.TOTP_SECRETS_FILE || join(dataDir, "totp-secrets.json");

			cachedProvider = new EncryptedFileProvider(filePath, encryptionKey);
		}
	}

	logger.info({ provider: cachedProvider.name }, "TOTP storage provider initialized");
	return cachedProvider;
}

/**
 * Check if any storage provider is available.
 */
export async function isStorageAvailable(): Promise<boolean> {
	try {
		await getStorageProvider();
		return true;
	} catch {
		return false;
	}
}
