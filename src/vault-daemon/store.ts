/**
 * Credential vault storage.
 *
 * Uses AES-256-GCM encryption with scrypt key derivation.
 * Storage is file-based (Docker-compatible, no OS keychain dependency).
 *
 * Security:
 * - Credentials are encrypted at rest
 * - File permissions set to 0600 (owner only)
 * - Secrets never logged
 */

import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	readFileSync,
	renameSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";

import { getChildLogger } from "../logging.js";
import {
	type Credential,
	type CredentialEntry,
	CredentialEntrySchema,
	type ListEntry,
	makeStorageKey,
	type Protocol,
	parseStorageKey,
} from "./protocol.js";

const logger = getChildLogger({ module: "vault-store" });

// ═══════════════════════════════════════════════════════════════════════════════
// Mutex for Atomic Operations
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Simple promise-based mutex for serializing store operations.
 * Prevents race conditions when multiple requests try to modify the vault.
 */
class Mutex {
	private locked = false;
	private queue: Array<() => void> = [];

	async acquire(): Promise<void> {
		if (!this.locked) {
			this.locked = true;
			return;
		}

		return new Promise((resolve) => {
			this.queue.push(resolve);
		});
	}

	release(): void {
		const next = this.queue.shift();
		if (next) {
			next();
		} else {
			this.locked = false;
		}
	}

	async withLock<T>(fn: () => Promise<T> | T): Promise<T> {
		await this.acquire();
		try {
			return await fn();
		} finally {
			this.release();
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Storage Types
// ═══════════════════════════════════════════════════════════════════════════════

interface EncryptedVault {
	version: 1;
	salt: string;
	entries: Record<string, EncryptedEntry>;
}

interface EncryptedEntry {
	iv: string;
	data: string;
	tag: string;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Vault Store
// ═══════════════════════════════════════════════════════════════════════════════

export interface VaultStoreOptions {
	filePath?: string;
	encryptionKey?: string;
}

export class VaultStore {
	private filePath: string;
	private rawKey: string;
	private derivedKey: Buffer | null = null;
	private cachedSalt: Buffer | null = null;
	private mutex = new Mutex();

	constructor(options: VaultStoreOptions = {}) {
		const dataDir =
			process.env.TELCLAUDE_DATA_DIR || join(process.env.HOME || "/tmp", ".telclaude");

		this.filePath = options.filePath || join(dataDir, "vault.json");
		this.rawKey = options.encryptionKey || process.env.VAULT_ENCRYPTION_KEY || "";

		if (!this.rawKey) {
			throw new Error(
				"VAULT_ENCRYPTION_KEY environment variable is required. " +
					"Generate a strong key: openssl rand -base64 32",
			);
		}

		const dir = dirname(this.filePath);
		if (!existsSync(dir)) {
			mkdirSync(dir, { recursive: true, mode: 0o700 });
		}

		logger.debug({ filePath: this.filePath }, "vault store initialized");
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Public API
	// ═══════════════════════════════════════════════════════════════════════════

	/**
	 * Store a credential entry.
	 * Uses mutex to prevent concurrent modification race conditions.
	 */
	async store(
		protocol: Protocol,
		target: string,
		credential: Credential,
		options: {
			label?: string;
			allowedPaths?: string[];
			rateLimitPerMinute?: number;
			expiresAt?: string;
		} = {},
	): Promise<void> {
		const entry: CredentialEntry = {
			protocol,
			target,
			credential,
			label: options.label,
			allowedPaths: options.allowedPaths,
			rateLimitPerMinute: options.rateLimitPerMinute,
			createdAt: new Date().toISOString(),
			expiresAt: options.expiresAt,
		};

		// Validate the entry before acquiring lock
		CredentialEntrySchema.parse(entry);

		// Acquire lock for read-modify-write cycle
		await this.mutex.withLock(() => {
			const vault = this.readVault();
			const key = makeStorageKey(protocol, target);
			const encKey = this.getEncryptionKey(vault);

			vault.entries[key] = this.encrypt(JSON.stringify(entry), encKey);
			this.writeVault(vault);
		});

		logger.info({ protocol, target, credentialType: credential.type }, "stored credential");
	}

	/**
	 * Get a credential entry.
	 */
	async get(protocol: Protocol, target: string): Promise<CredentialEntry | null> {
		const vault = this.readVault();
		const key = makeStorageKey(protocol, target);
		const encrypted = vault.entries[key];

		if (!encrypted) {
			return null;
		}

		try {
			const encKey = this.getEncryptionKey(vault);
			const decrypted = this.decrypt(encrypted, encKey);
			const entry = JSON.parse(decrypted) as CredentialEntry;

			// Check expiration
			if (entry.expiresAt && new Date(entry.expiresAt) < new Date()) {
				logger.info({ protocol, target }, "credential expired");
				return null;
			}

			return CredentialEntrySchema.parse(entry);
		} catch (err) {
			logger.error({ protocol, target, error: String(err) }, "failed to decrypt credential");
			return null;
		}
	}

	/**
	 * Delete a credential entry.
	 * Uses mutex to prevent concurrent modification race conditions.
	 */
	async delete(protocol: Protocol, target: string): Promise<boolean> {
		// Acquire lock for read-modify-write cycle
		const deleted = await this.mutex.withLock(() => {
			const vault = this.readVault();
			const key = makeStorageKey(protocol, target);

			if (!vault.entries[key]) {
				return false;
			}

			delete vault.entries[key];
			this.writeVault(vault);
			return true;
		});

		if (deleted) {
			logger.info({ protocol, target }, "deleted credential");
		}
		return deleted;
	}

	/**
	 * Check if a credential exists.
	 */
	async has(protocol: Protocol, target: string): Promise<boolean> {
		const vault = this.readVault();
		const key = makeStorageKey(protocol, target);
		return key in vault.entries;
	}

	/**
	 * List all credentials (without exposing secrets).
	 */
	async list(filterProtocol?: Protocol): Promise<ListEntry[]> {
		const vault = this.readVault();
		const encKey = this.getEncryptionKey(vault);
		const entries: ListEntry[] = [];

		for (const [key, encrypted] of Object.entries(vault.entries)) {
			const parsed = parseStorageKey(key);
			if (!parsed) continue;

			// Apply protocol filter
			if (filterProtocol && parsed.protocol !== filterProtocol) {
				continue;
			}

			try {
				const decrypted = this.decrypt(encrypted, encKey);
				const entry = JSON.parse(decrypted) as CredentialEntry;

				entries.push({
					protocol: entry.protocol,
					target: entry.target,
					label: entry.label,
					credentialType: entry.credential.type,
					createdAt: entry.createdAt,
					expiresAt: entry.expiresAt,
				});
			} catch (err) {
				logger.warn({ key, error: String(err) }, "failed to decrypt entry for listing");
			}
		}

		return entries;
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Encryption
	// ═══════════════════════════════════════════════════════════════════════════

	private getEncryptionKey(vault: EncryptedVault): Buffer {
		const salt = Buffer.from(vault.salt, "base64");

		if (this.derivedKey && this.cachedSalt && salt.equals(this.cachedSalt)) {
			return this.derivedKey;
		}

		this.derivedKey = scryptSync(this.rawKey, salt, 32);
		this.cachedSalt = salt;
		return this.derivedKey;
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

	// ═══════════════════════════════════════════════════════════════════════════
	// File I/O
	// ═══════════════════════════════════════════════════════════════════════════

	/**
	 * Ensure a file has the correct permissions (0600).
	 * Returns true if permissions are correct or were corrected.
	 */
	private ensureFilePermissions(filePath: string, logOnCorrection = false): boolean {
		try {
			const stats = statSync(filePath);
			const mode = stats.mode & 0o777;
			if (mode !== 0o600) {
				chmodSync(filePath, 0o600);
				if (logOnCorrection) {
					logger.info({ filePath }, "corrected vault file permissions to 0600");
				}
			}
			return true;
		} catch {
			return false;
		}
	}

	private readVault(): EncryptedVault {
		if (!existsSync(this.filePath)) {
			const salt = randomBytes(16);
			return { version: 1, salt: salt.toString("base64"), entries: {} };
		}

		try {
			const content = readFileSync(this.filePath, "utf8");
			const vault = JSON.parse(content) as EncryptedVault;

			// Validate vault structure
			if (!vault.version || !vault.salt || typeof vault.entries !== "object") {
				throw new Error("Invalid vault structure");
			}

			return vault;
		} catch (err) {
			// SECURITY: Don't silently reset on corruption - fail closed
			// Quarantine the corrupted file for manual recovery
			const backupPath = `${this.filePath}.corrupted.${Date.now()}`;
			try {
				renameSync(this.filePath, backupPath);
				logger.error(
					{ filePath: this.filePath, backupPath, error: String(err) },
					"vault file corrupted, moved to backup - starting fresh",
				);
			} catch {
				logger.error(
					{ filePath: this.filePath, error: String(err) },
					"vault file corrupted and backup failed",
				);
				throw new Error(`Vault file corrupted: ${String(err)}. Manual recovery required.`);
			}

			const salt = randomBytes(16);
			return { version: 1, salt: salt.toString("base64"), entries: {} };
		}
	}

	private writeVault(vault: EncryptedVault): void {
		const content = JSON.stringify(vault, null, 2);

		// SECURITY: Atomic write pattern - write to temp file, then rename.
		// This prevents partial writes if the process crashes mid-write.
		const tempPath = `${this.filePath}.tmp`;

		// Write to temp file with correct permissions
		writeFileSync(tempPath, content, { mode: 0o600 });

		// Ensure temp file has correct permissions before rename
		this.ensureFilePermissions(tempPath);

		// Atomic rename (on POSIX systems)
		renameSync(tempPath, this.filePath);

		// Verify final file permissions
		if (!this.ensureFilePermissions(this.filePath, true)) {
			logger.warn({ filePath: this.filePath }, "failed to verify vault file permissions");
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Singleton
// ═══════════════════════════════════════════════════════════════════════════════

let cachedStore: VaultStore | null = null;

/**
 * Get the vault store singleton.
 */
export function getVaultStore(options?: VaultStoreOptions): VaultStore {
	if (!cachedStore) {
		cachedStore = new VaultStore(options);
	}
	return cachedStore;
}

/**
 * Reset the vault store (for testing).
 */
export function resetVaultStore(): void {
	cachedStore = null;
}
