/**
 * Shared AES-256-GCM encrypted file store.
 *
 * Provides a key-value store backed by an encrypted JSON file.
 * Used by both TOTP storage and secrets keychain.
 *
 * Security properties:
 * - AES-256-GCM with 12-byte random IV per entry
 * - scrypt key derivation (32-byte output) with per-file 16-byte random salt
 * - Base64 encoding for storage
 * - 0o700 directory permissions, 0o600 file permissions
 */

import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

interface EncryptedEntry {
	/** Base64-encoded IV */
	iv: string;
	/** Base64-encoded encrypted data */
	data: string;
	/** Base64-encoded auth tag */
	tag: string;
}

interface EncryptedFileData {
	/** Base64-encoded salt for key derivation (random, stored with file) */
	salt: string;
	secrets: Record<string, EncryptedEntry>;
}

export class EncryptedFileStore {
	private readonly filePath: string;
	private readonly rawKey: string;
	private derivedKey: Buffer | null = null;
	private cachedSalt: Buffer | null = null;

	constructor(filePath: string, encryptionKey: string) {
		this.filePath = filePath;
		this.rawKey = encryptionKey;

		const dir = dirname(filePath);
		if (!existsSync(dir)) {
			mkdirSync(dir, { recursive: true, mode: 0o700 });
		}
	}

	/**
	 * Get the derived encryption key.
	 * The salt is stored in the secrets file (generated on first use).
	 * This ensures backups can be restored anywhere with just the encryption key.
	 */
	private getEncryptionKey(fileData: EncryptedFileData): Buffer {
		const salt = Buffer.from(fileData.salt, "base64");

		if (this.derivedKey && this.cachedSalt && salt.equals(this.cachedSalt)) {
			return this.derivedKey;
		}

		this.derivedKey = scryptSync(this.rawKey, salt, 32);
		this.cachedSalt = salt;
		return this.derivedKey;
	}

	private readFile(): EncryptedFileData {
		if (!existsSync(this.filePath)) {
			const salt = randomBytes(16);
			return { salt: salt.toString("base64"), secrets: {} };
		}

		try {
			const content = readFileSync(this.filePath, "utf8");
			return JSON.parse(content) as EncryptedFileData;
		} catch {
			const salt = randomBytes(16);
			return { salt: salt.toString("base64"), secrets: {} };
		}
	}

	private writeFile(fileData: EncryptedFileData): void {
		const content = JSON.stringify(fileData, null, 2);
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

	/** Store a value under the given key. */
	store(key: string, value: string): void {
		const fileData = this.readFile();
		const encKey = this.getEncryptionKey(fileData);
		fileData.secrets[key] = this.encrypt(value, encKey);
		this.writeFile(fileData);
	}

	/** Retrieve a value by key (null if not found or decryption fails). */
	get(key: string): string | null {
		const fileData = this.readFile();
		const entry = fileData.secrets[key];
		if (!entry) return null;

		try {
			const encKey = this.getEncryptionKey(fileData);
			return this.decrypt(entry, encKey);
		} catch {
			return null;
		}
	}

	/** Delete a value by key. Returns true if it existed. */
	delete(key: string): boolean {
		const fileData = this.readFile();
		if (!fileData.secrets[key]) return false;

		delete fileData.secrets[key];
		this.writeFile(fileData);
		return true;
	}

	/** Check if a key exists. */
	has(key: string): boolean {
		const fileData = this.readFile();
		return key in fileData.secrets;
	}
}
