/**
 * Secure secrets storage.
 *
 * Backends:
 * - vault (the relay credential vault) - the store of record when its socket is
 *   reachable; wraps a base provider it falls back to on RPC failure.
 * - keytar (OS keychain) - base provider for native dev (macOS Keychain, Linux
 *   libsecret, Windows Credential Vault).
 * - noop - base provider when keytar is unavailable (e.g. Docker), so the vault
 *   runs in effectively vault-only mode.
 *
 * Used for storing API keys and other sensitive credentials.
 */

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
		// The vault is the authoritative store. A transport/RPC failure (vs. a
		// clean not-found, which comes back as { ok: true, deleted: false }) means
		// the secret may still live in the vault. Propagate so callers know the
		// revocation did not complete rather than fail open on a deleted fallback.
		let vaultDeleted: boolean;
		try {
			const client = getVaultClient();
			const response = await client.delete("secret", key);
			vaultDeleted = response.deleted;
		} catch (err) {
			// Propagate rather than log-and-continue: the secret may still live in the
			// vault, so the caller must treat revocation as failed. The thrown error
			// already carries the key id + cause for the caller to surface; logging it
			// here too would double-report and needlessly route a secret identifier
			// through a logging sink.
			throw new Error(`vault delete failed for secret "${key}": ${String(err)}`, { cause: err });
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
 * The vault is the store of record. The base provider it wraps (and falls back
 * to on vault RPC failure) is the OS keychain via keytar when available, or a
 * no-op provider otherwise — so a relay without keytar (e.g. Docker) runs in
 * effectively vault-only mode. When the vault is unavailable, keytar is used
 * directly; if neither is available, secret reads return null and writes throw.
 */
async function getStorageProvider(): Promise<SecretsStorageProvider> {
	if (cachedProvider) return cachedProvider;

	let baseProvider: SecretsStorageProvider | null = null;
	let baseProviderError: unknown;

	try {
		const provider = new KeytarProvider();
		await provider.has("__test__");
		baseProvider = provider;
	} catch (err) {
		baseProviderError = err;
		logger.debug({ error: String(err) }, "keytar not available; relying on vault");
	}

	// Wrap with the vault provider when the vault is reachable. If keytar is
	// unavailable (common in Docker), the vault wraps a no-op fallback and runs
	// in effectively vault-only mode.
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
	BRAVE_SEARCH_API_KEY: "brave-search-api-key",
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
