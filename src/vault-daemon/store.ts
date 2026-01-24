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
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
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

		// Validate the entry
		CredentialEntrySchema.parse(entry);

		const vault = this.readVault();
		const key = makeStorageKey(protocol, target);
		const encKey = this.getEncryptionKey(vault);

		vault.entries[key] = this.encrypt(JSON.stringify(entry), encKey);
		this.writeVault(vault);

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
	 */
	async delete(protocol: Protocol, target: string): Promise<boolean> {
		const vault = this.readVault();
		const key = makeStorageKey(protocol, target);

		if (!vault.entries[key]) {
			return false;
		}

		delete vault.entries[key];
		this.writeVault(vault);

		logger.info({ protocol, target }, "deleted credential");
		return true;
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
				const { renameSync } = require("node:fs");
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
		writeFileSync(this.filePath, content, { mode: 0o600 });

		// SECURITY: Ensure permissions are correct even if file existed with wrong perms
		const { chmodSync, statSync } = require("node:fs");
		try {
			const stats = statSync(this.filePath);
			const mode = stats.mode & 0o777;
			if (mode !== 0o600) {
				chmodSync(this.filePath, 0o600);
				logger.info({ filePath: this.filePath }, "corrected vault file permissions to 0600");
			}
		} catch (err) {
			logger.warn(
				{ filePath: this.filePath, error: String(err) },
				"failed to verify vault file permissions",
			);
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
