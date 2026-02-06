/**
 * Secure secrets storage using OS keychain.
 *
 * Supports multiple storage backends:
 * - keytar (OS keychain) - macOS Keychain, Linux libsecret, Windows Credential Vault
 * - encrypted file - for Docker/headless deployments
 *
 * Used for storing API keys and other sensitive credentials.
 */

import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { getChildLogger } from "../logging.js";
import { getVaultClient, isVaultAvailable } from "../vault-daemon/client.js";

const logger = getChildLogger({ module: "secrets-keychain" });

const SERVICE_NAME = "telclaude";

// ═══════════════════════════════════════════════════════════════════════════════
// Storage Provider Interface
// ═══════════════════════════════════════════════════════════════════════════════

interface SecretsStorageProvider {
	readonly name: string;

	/** Store a secret */
	store(key: string, value: string): Promise<void>;

	/** Retrieve a secret (null if not found) */
	get(key: string): Promise<string | null>;

	/** Delete a secret */
	delete(key: string): Promise<boolean>;

	/** Check if a secret exists */
	has(key: string): Promise<boolean>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Keytar Provider (OS Keychain)
// ═══════════════════════════════════════════════════════════════════════════════

class KeytarProvider implements SecretsStorageProvider {
	readonly name = "keytar";
	private keytar: typeof import("keytar") | null = null;

	private async getKeytar() {
		if (!this.keytar) {
			try {
				const mod = await import("keytar");
				this.keytar = (mod.default ?? mod) as typeof import("keytar");
			} catch (err) {
				throw new Error(`keytar not available: ${String(err)}`);
			}
		}
		return this.keytar;
	}

	async store(key: string, value: string): Promise<void> {
		const keytar = await this.getKeytar();
		await keytar.setPassword(SERVICE_NAME, key, value);
		logger.debug({ key, provider: this.name }, "stored secret");
	}

	async get(key: string): Promise<string | null> {
		const keytar = await this.getKeytar();
		return keytar.getPassword(SERVICE_NAME, key);
	}

	async delete(key: string): Promise<boolean> {
		const keytar = await this.getKeytar();
		const deleted = await keytar.deletePassword(SERVICE_NAME, key);
		if (deleted) {
			logger.info({ key, provider: this.name }, "deleted secret");
		}
		return deleted;
	}

	async has(key: string): Promise<boolean> {
		const keytar = await this.getKeytar();
		const secret = await keytar.getPassword(SERVICE_NAME, key);
		return secret !== null;
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Encrypted File Provider (Docker-compatible)
// ═══════════════════════════════════════════════════════════════════════════════

interface EncryptedSecrets {
	salt: string;
	secrets: Record<string, EncryptedEntry>;
}

interface EncryptedEntry {
	iv: string;
	data: string;
	tag: string;
}

class EncryptedFileProvider implements SecretsStorageProvider {
	readonly name = "encrypted-file";
	private filePath: string;
	private rawKey: string;
	private derivedKey: Buffer | null = null;
	private cachedSalt: Buffer | null = null;

	constructor(filePath: string, encryptionKey: string) {
		this.filePath = filePath;
		this.rawKey = encryptionKey;

		const dir = dirname(filePath);
		if (!existsSync(dir)) {
			mkdirSync(dir, { recursive: true, mode: 0o700 });
		}

		logger.debug({ filePath, provider: this.name }, "initialized encrypted file provider");
	}

	private getEncryptionKey(secrets: EncryptedSecrets): Buffer {
		const salt = Buffer.from(secrets.salt, "base64");

		if (this.derivedKey && this.cachedSalt && salt.equals(this.cachedSalt)) {
			return this.derivedKey;
		}

		this.derivedKey = scryptSync(this.rawKey, salt, 32);
		this.cachedSalt = salt;
		return this.derivedKey;
	}

	private readSecrets(): EncryptedSecrets {
		if (!existsSync(this.filePath)) {
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
		const iv = randomBytes(12);
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

	async store(key: string, value: string): Promise<void> {
		const secrets = this.readSecrets();
		const encKey = this.getEncryptionKey(secrets);
		secrets.secrets[key] = this.encrypt(value, encKey);
		this.writeSecrets(secrets);
		logger.debug({ key, provider: this.name }, "stored secret");
	}

	async get(key: string): Promise<string | null> {
		const secrets = this.readSecrets();
		const entry = secrets.secrets[key];
		if (!entry) return null;

		try {
			const encKey = this.getEncryptionKey(secrets);
			return this.decrypt(entry, encKey);
		} catch (err) {
			logger.error({ key, error: String(err) }, "failed to decrypt secret");
			return null;
		}
	}

	async delete(key: string): Promise<boolean> {
		const secrets = this.readSecrets();
		if (!secrets.secrets[key]) return false;

		delete secrets.secrets[key];
		this.writeSecrets(secrets);
		logger.info({ key, provider: this.name }, "deleted secret");
		return true;
	}

	async has(key: string): Promise<boolean> {
		const secrets = this.readSecrets();
		return key in secrets.secrets;
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Vault Provider (delegates to vault daemon when available)
// ═══════════════════════════════════════════════════════════════════════════════

class VaultProvider implements SecretsStorageProvider {
	readonly name = "vault";
	private fallback: SecretsStorageProvider;

	constructor(fallback: SecretsStorageProvider) {
		this.fallback = fallback;
		logger.debug({ fallback: fallback.name }, "vault provider initialized with fallback");
	}

	async store(key: string, value: string): Promise<void> {
		try {
			const client = getVaultClient();
			await client.store({
				protocol: "secret",
				target: key,
				credential: { type: "opaque", value },
				label: key,
			});
			logger.debug({ key, provider: this.name }, "stored secret in vault");
			return;
		} catch (err) {
			logger.warn({ key, error: String(err) }, "vault store failed, using fallback");
		}
		await this.fallback.store(key, value);
	}

	async get(key: string): Promise<string | null> {
		try {
			const client = getVaultClient();
			const response = await client.getSecret(key, { timeout: 5000 });
			if (response.ok && response.type === "get-secret") {
				return response.value;
			}
		} catch (err) {
			logger.debug({ key, error: String(err) }, "vault get failed, trying fallback");
		}
		return this.fallback.get(key);
	}

	async delete(key: string): Promise<boolean> {
		let vaultDeleted = false;
		try {
			const client = getVaultClient();
			const response = await client.delete("secret", key);
			vaultDeleted = response.deleted;
		} catch (err) {
			logger.debug({ key, error: String(err) }, "vault delete failed");
		}
		const fallbackDeleted = await this.fallback.delete(key);
		return vaultDeleted || fallbackDeleted;
	}

	async has(key: string): Promise<boolean> {
		try {
			const client = getVaultClient();
			const response = await client.getSecret(key, { timeout: 5000 });
			if (response.ok) return true;
		} catch {
			// Fall through
		}
		return this.fallback.has(key);
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Provider Factory
// ═══════════════════════════════════════════════════════════════════════════════

let cachedProvider: SecretsStorageProvider | null = null;

/**
 * Get the secrets storage provider.
 *
 * Selection order:
 * 1. SECRETS_STORAGE_BACKEND env var ("keytar" or "file")
 * 2. Auto-detect: file if SECRETS_ENCRYPTION_KEY is set, otherwise keytar
 */
async function getStorageProvider(): Promise<SecretsStorageProvider> {
	if (cachedProvider) return cachedProvider;

	const backend = process.env.SECRETS_STORAGE_BACKEND?.toLowerCase();
	const encryptionKey = process.env.SECRETS_ENCRYPTION_KEY;

	let useFile = false;

	if (backend === "file") {
		useFile = true;
	} else if (backend === "keytar") {
		useFile = false;
	} else if (encryptionKey) {
		useFile = true;
	}

	if (useFile) {
		if (!encryptionKey) {
			throw new Error(
				"SECRETS_ENCRYPTION_KEY environment variable is required for file-based storage. " +
					"Generate a strong key: openssl rand -base64 32",
			);
		}

		const dataDir =
			process.env.TELCLAUDE_DATA_DIR || join(process.env.HOME || "/tmp", ".telclaude");
		const filePath = process.env.SECRETS_FILE || join(dataDir, "secrets.json");

		cachedProvider = new EncryptedFileProvider(filePath, encryptionKey);
	} else {
		try {
			const provider = new KeytarProvider();
			await provider.has("__test__");
			cachedProvider = provider;
		} catch (err) {
			logger.warn(
				{ error: String(err) },
				"keytar not available, falling back to encrypted file storage",
			);

			if (!encryptionKey) {
				throw new Error(
					"keytar is not available and SECRETS_ENCRYPTION_KEY is not set. " +
						"Either install libsecret-1-dev (Linux) or set SECRETS_ENCRYPTION_KEY for file-based storage.",
				);
			}

			const dataDir =
				process.env.TELCLAUDE_DATA_DIR || join(process.env.HOME || "/tmp", ".telclaude");
			const filePath = process.env.SECRETS_FILE || join(dataDir, "secrets.json");

			cachedProvider = new EncryptedFileProvider(filePath, encryptionKey);
		}
	}

	// Wrap with vault provider if vault is available
	const baseProvider = cachedProvider;
	try {
		if (await isVaultAvailable()) {
			cachedProvider = new VaultProvider(baseProvider);
			logger.info(
				{ provider: cachedProvider.name, fallback: baseProvider.name },
				"secrets storage provider initialized with vault",
			);
			return cachedProvider;
		}
	} catch {
		// Vault not available, use base provider
	}

	logger.info({ provider: cachedProvider.name }, "secrets storage provider initialized");
	return cachedProvider;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════════════════

/** Secret key constants */
export const SECRET_KEYS = {
	OPENAI_API_KEY: "openai-api-key",
	GIT_CREDENTIALS: "git-credentials",
	GITHUB_APP: "github-app",
	MOLTBOOK_API_KEY: "moltbook-api-key",
} as const;

/** Git credentials structure stored in secrets */
export interface GitCredentials {
	username: string;
	email: string;
	token: string;
}

/**
 * Store a secret in the keychain.
 */
export async function storeSecret(key: string, value: string): Promise<void> {
	const provider = await getStorageProvider();
	await provider.store(key, value);
}

/**
 * Retrieve a secret from the keychain.
 */
export async function getSecret(key: string): Promise<string | null> {
	const provider = await getStorageProvider();
	return provider.get(key);
}

/**
 * Delete a secret from the keychain.
 */
export async function deleteSecret(key: string): Promise<boolean> {
	const provider = await getStorageProvider();
	return provider.delete(key);
}

/**
 * Check if a secret exists in the keychain.
 */
export async function hasSecret(key: string): Promise<boolean> {
	const provider = await getStorageProvider();
	return provider.has(key);
}

/**
 * Check if secrets storage is available.
 */
export async function isSecretsStorageAvailable(): Promise<boolean> {
	try {
		await getStorageProvider();
		return true;
	} catch {
		return false;
	}
}

/**
 * Get the name of the active storage provider.
 */
export async function getStorageProviderName(): Promise<string> {
	const provider = await getStorageProvider();
	return provider.name;
}
