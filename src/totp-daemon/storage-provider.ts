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

import { Secret } from "otpauth";
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

const SERVICE_NAME = "telclaude";

class KeytarProvider implements TOTPStorageProvider {
	readonly name = "keytar";
	private keytar: typeof import("keytar") | null = null;

	private async getKeytar() {
		if (!this.keytar) {
			try {
				// keytar is a CommonJS module, so dynamic import returns it under .default
				const mod = await import("keytar");
				this.keytar = (mod.default ?? mod) as typeof import("keytar");
			} catch (err) {
				throw new Error(`keytar not available: ${String(err)}`);
			}
		}
		return this.keytar;
	}

	async storeSecret(localUserId: string, secret: Secret): Promise<void> {
		const keytar = await this.getKeytar();
		const account = `totp:${localUserId}`;
		await keytar.setPassword(SERVICE_NAME, account, secret.base32);
		logger.debug({ localUserId, provider: this.name }, "stored TOTP secret");
	}

	async getSecret(localUserId: string): Promise<Secret | null> {
		const keytar = await this.getKeytar();
		const account = `totp:${localUserId}`;
		const base32 = await keytar.getPassword(SERVICE_NAME, account);
		if (!base32) return null;
		return Secret.fromBase32(base32);
	}

	async deleteSecret(localUserId: string): Promise<boolean> {
		const keytar = await this.getKeytar();
		const account = `totp:${localUserId}`;
		const deleted = await keytar.deletePassword(SERVICE_NAME, account);
		if (deleted) {
			logger.info({ localUserId, provider: this.name }, "deleted TOTP secret");
		}
		return deleted;
	}

	async hasSecret(localUserId: string): Promise<boolean> {
		const keytar = await this.getKeytar();
		const account = `totp:${localUserId}`;
		const secret = await keytar.getPassword(SERVICE_NAME, account);
		return secret !== null;
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Encrypted File Provider (Docker-compatible)
// ═══════════════════════════════════════════════════════════════════════════════

import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

interface EncryptedSecrets {
	/** Base64-encoded salt for key derivation (random, stored with file) */
	salt: string;
	secrets: Record<string, EncryptedEntry>;
}

interface EncryptedEntry {
	/** Base64-encoded IV */
	iv: string;
	/** Base64-encoded encrypted data */
	data: string;
	/** Base64-encoded auth tag */
	tag: string;
}

class EncryptedFileProvider implements TOTPStorageProvider {
	readonly name = "encrypted-file";
	private filePath: string;
	private rawKey: string;
	private derivedKey: Buffer | null = null;
	private cachedSalt: Buffer | null = null;

	constructor(filePath: string, encryptionKey: string) {
		this.filePath = filePath;
		this.rawKey = encryptionKey;

		// Ensure directory exists
		const dir = dirname(filePath);
		if (!existsSync(dir)) {
			mkdirSync(dir, { recursive: true, mode: 0o700 });
		}

		logger.debug({ filePath, provider: this.name }, "initialized encrypted file provider");
	}

	/**
	 * Get the derived encryption key.
	 * The salt is stored in the secrets file (generated on first use).
	 * This ensures backups can be restored anywhere with just the encryption key.
	 */
	private getEncryptionKey(secrets: EncryptedSecrets): Buffer {
		const salt = Buffer.from(secrets.salt, "base64");

		// Cache the derived key if salt hasn't changed
		if (this.derivedKey && this.cachedSalt && salt.equals(this.cachedSalt)) {
			return this.derivedKey;
		}

		// Derive a 256-bit key from the provided key using scrypt
		this.derivedKey = scryptSync(this.rawKey, salt, 32);
		this.cachedSalt = salt;
		return this.derivedKey;
	}

	private readSecrets(): EncryptedSecrets {
		if (!existsSync(this.filePath)) {
			// Generate a random salt for new files (16 bytes = 128 bits)
			const salt = randomBytes(16);
			return { salt: salt.toString("base64"), secrets: {} };
		}

		try {
			const content = readFileSync(this.filePath, "utf8");
			return JSON.parse(content) as EncryptedSecrets;
		} catch {
			logger.warn({ filePath: this.filePath }, "failed to read secrets file, starting fresh");
			const salt = randomBytes(16);
			return { salt: salt.toString("base64"), secrets: {} };
		}
	}

	private writeSecrets(secrets: EncryptedSecrets): void {
		const content = JSON.stringify(secrets, null, 2);
		writeFileSync(this.filePath, content, { mode: 0o600 });
	}

	private encrypt(plaintext: string, key: Buffer): EncryptedEntry {
		const iv = randomBytes(12); // 96-bit IV for GCM
		const cipher = createCipheriv("aes-256-gcm", key, iv);

		const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);

		const tag = cipher.getAuthTag();

		return {
			iv: iv.toString("base64"),
			data: encrypted.toString("base64"),
			tag: tag.toString("base64"),
		};
	}

	private decrypt(entry: EncryptedEntry, key: Buffer): string {
		const iv = Buffer.from(entry.iv, "base64");
		const data = Buffer.from(entry.data, "base64");
		const tag = Buffer.from(entry.tag, "base64");

		const decipher = createDecipheriv("aes-256-gcm", key, iv);
		decipher.setAuthTag(tag);

		const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);

		return decrypted.toString("utf8");
	}

	async storeSecret(localUserId: string, secret: Secret): Promise<void> {
		const secrets = this.readSecrets();
		const key = this.getEncryptionKey(secrets);
		secrets.secrets[localUserId] = this.encrypt(secret.base32, key);
		this.writeSecrets(secrets);
		logger.debug({ localUserId, provider: this.name }, "stored TOTP secret");
	}

	async getSecret(localUserId: string): Promise<Secret | null> {
		const secrets = this.readSecrets();
		const entry = secrets.secrets[localUserId];
		if (!entry) return null;

		try {
			const key = this.getEncryptionKey(secrets);
			const base32 = this.decrypt(entry, key);
			return Secret.fromBase32(base32);
		} catch (err) {
			logger.error({ localUserId, error: String(err) }, "failed to decrypt TOTP secret");
			return null;
		}
	}

	async deleteSecret(localUserId: string): Promise<boolean> {
		const secrets = this.readSecrets();
		if (!secrets.secrets[localUserId]) return false;

		delete secrets.secrets[localUserId];
		this.writeSecrets(secrets);
		logger.info({ localUserId, provider: this.name }, "deleted TOTP secret");
		return true;
	}

	async hasSecret(localUserId: string): Promise<boolean> {
		const secrets = this.readSecrets();
		return localUserId in secrets.secrets;
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
