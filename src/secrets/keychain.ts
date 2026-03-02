/**
 * Secure secrets storage using OS keychain.
 *
 * Supports multiple storage backends:
 * - keytar (OS keychain) - macOS Keychain, Linux libsecret, Windows Credential Vault
 * - encrypted file - for Docker/headless deployments
 *
 * Used for storing API keys and other sensitive credentials.
 */

import { join } from "node:path";

import { EncryptedFileStore } from "../crypto/encrypted-file-store.js";
import { KeytarStore } from "../crypto/keytar-store.js";
import { getChildLogger } from "../logging.js";
import { getVaultClient, isVaultAvailable } from "../vault-daemon/client.js";

const logger = getChildLogger({ module: "secrets-keychain" });

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
	private keytarStore = new KeytarStore();

	async store(key: string, value: string): Promise<void> {
		await this.keytarStore.store(key, value);
		logger.debug({ key, provider: this.name }, "stored secret");
	}

	async get(key: string): Promise<string | null> {
		return this.keytarStore.get(key);
	}

	async delete(key: string): Promise<boolean> {
		const deleted = await this.keytarStore.delete(key);
		if (deleted) {
			logger.info({ key, provider: this.name }, "deleted secret");
		}
		return deleted;
	}

	async has(key: string): Promise<boolean> {
		return this.keytarStore.has(key);
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Encrypted File Provider (Docker-compatible)
// ═══════════════════════════════════════════════════════════════════════════════

class EncryptedFileProvider implements SecretsStorageProvider {
	readonly name = "encrypted-file";
	private fileStore: EncryptedFileStore;

	constructor(filePath: string, encryptionKey: string) {
		this.fileStore = new EncryptedFileStore(filePath, encryptionKey);
		logger.debug({ filePath, provider: this.name }, "initialized encrypted file provider");
	}

	async store(key: string, value: string): Promise<void> {
		this.fileStore.store(key, value);
		logger.debug({ key, provider: this.name }, "stored secret");
	}

	async get(key: string): Promise<string | null> {
		return this.fileStore.get(key);
	}

	async delete(key: string): Promise<boolean> {
		const deleted = this.fileStore.delete(key);
		if (deleted) {
			logger.info({ key, provider: this.name }, "deleted secret");
		}
		return deleted;
	}

	async has(key: string): Promise<boolean> {
		return this.fileStore.has(key);
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// No-Op Provider (for vault-only mode)
// ═══════════════════════════════════════════════════════════════════════════════

class NoopProvider implements SecretsStorageProvider {
	readonly name = "noop";
	private readonly initError?: unknown;

	constructor(initError?: unknown) {
		this.initError = initError;
	}

	private getInitErrorSuffix(): string {
		if (!this.initError) return "";
		const msg = this.initError instanceof Error ? this.initError.message : String(this.initError);
		return msg ? ` (fallback init error: ${msg})` : "";
	}

	async store(_key: string, _value: string): Promise<void> {
		throw new Error(
			"No fallback secrets provider configured. Ensure vault is running/accessible" +
				this.getInitErrorSuffix(),
		);
	}

	async get(_key: string): Promise<string | null> {
		return null;
	}

	async delete(_key: string): Promise<boolean> {
		return false;
	}

	async has(_key: string): Promise<boolean> {
		return false;
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

	let baseProvider: SecretsStorageProvider | null = null;
	let baseProviderError: unknown;

	const buildBaseProvider = async (): Promise<SecretsStorageProvider> => {
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

			return new EncryptedFileProvider(filePath, encryptionKey);
		}

		try {
			const provider = new KeytarProvider();
			await provider.has("__test__");
			return provider;
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

			return new EncryptedFileProvider(filePath, encryptionKey);
		}
	};

	try {
		baseProvider = await buildBaseProvider();
	} catch (err) {
		baseProviderError = err;
	}

	// Wrap with vault provider if vault is available. If we can't initialize a base provider
	// (common in Docker where keytar is unavailable and SECRETS_ENCRYPTION_KEY is unset),
	// run in vault-only mode.
	try {
		if (await isVaultAvailable({ timeout: 1000 })) {
			const fallback = baseProvider ?? new NoopProvider(baseProviderError);
			cachedProvider = new VaultProvider(fallback);
			logger.info(
				{ provider: cachedProvider.name, fallback: fallback.name },
				"secrets storage provider initialized with vault",
			);
			return cachedProvider;
		}
	} catch {
		// Vault not available, use base provider
	}

	if (!baseProvider) {
		throw (
			baseProviderError ??
			new Error("Failed to initialize secrets storage provider (and vault is unavailable)")
		);
	}

	cachedProvider = baseProvider;
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
