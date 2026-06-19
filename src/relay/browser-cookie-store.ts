/**
 * Relay-owned encrypted browser session store (S2 persistent logins).
 *
 * Holds, per operator browser session, the Playwright `storageState` (cookies +
 * per-origin localStorage) plus the M1 login-origin set learned at one-time
 * human session-capture. The store is RELAY-ONLY and encrypted at rest
 * (AES-256-GCM, scrypt-derived key, per-record IV). The contained tc-browser
 * never persists these — the broker decrypts a single session relay-side and
 * hydrates it into an ephemeral browser context that is discarded after the
 * browse (M6); the model never sees cookies, only redacted page text.
 *
 * A session is keyed by a server-resolved `sessionRef` (the relay names it; the
 * model cannot). Listing returns metadata only — never the storageState.
 */

import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { getChildLogger } from "../logging.js";
import { buildBrowserOriginScope } from "./browser-connect-contract.js";

const logger = getChildLogger({ module: "browser-cookie-store" });

export const BROWSER_COOKIE_STORE_KEY_ENV = "TELCLAUDE_BROWSER_COOKIE_STORE_KEY";
export const BROWSER_COOKIE_STORE_FILE = "browser-sessions.json";

/** Minimum key length — a 32-char key (e.g. `openssl rand -base64 32`) at full entropy. */
const BROWSER_COOKIE_STORE_MIN_KEY_LENGTH = 32;
/** scrypt cost: harden the at-rest KDF above the Node default (N=2^14). Derived once + cached. */
const BROWSER_COOKIE_STORE_SCRYPT_PARAMS = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

/** A captured browser session: the cookies + origin scope for one logged-in domain. */
export interface BrowserSessionRecord {
	readonly sessionRef: string;
	/** Registrable domain this session is logged into. */
	readonly domain: string;
	/** M1 login-origin set (registrable domains) the cookie-bearing context may egress to. */
	readonly originScope: readonly string[];
	/** Opaque Playwright storageState (cookies + per-origin localStorage). Relay-only. */
	readonly storageState: unknown;
	readonly createdAt: number;
	/** Operator actor who captured the session (audit). */
	readonly capturedBy: string;
}

/** Session metadata without the storageState — safe to surface to an operator. */
export interface BrowserSessionMeta {
	readonly sessionRef: string;
	readonly domain: string;
	readonly originScope: readonly string[];
	readonly createdAt: number;
	readonly capturedBy: string;
}

interface EncryptedRecord {
	readonly iv: string;
	readonly data: string;
	readonly tag: string;
}

interface CookieStoreFile {
	readonly salt: string;
	readonly sessions: Record<string, EncryptedRecord>;
}

export class BrowserCookieStore {
	private readonly filePath: string;
	private readonly rawKey: string;
	private derivedKey: Buffer | null = null;
	private cachedSalt: Buffer | null = null;

	constructor(filePath: string, encryptionKey: string) {
		// The store holds live login cookies; a weak/typed key makes offline brute
		// force feasible if the file ever leaks. Require a high-entropy key.
		if (encryptionKey.trim().length < BROWSER_COOKIE_STORE_MIN_KEY_LENGTH) {
			throw new Error(
				`browser cookie store requires an encryption key of at least ${BROWSER_COOKIE_STORE_MIN_KEY_LENGTH} chars (e.g. openssl rand -base64 32)`,
			);
		}
		this.filePath = filePath;
		this.rawKey = encryptionKey;
		const dir = dirname(filePath);
		if (!existsSync(dir)) {
			mkdirSync(dir, { recursive: true, mode: 0o700 });
		}
	}

	/** Store (or replace) a captured session. originScope is normalized; domain must be in it. */
	putSession(record: BrowserSessionRecord): void {
		const sessionRef = record.sessionRef.trim();
		const domain = record.domain.trim().toLowerCase();
		if (!sessionRef || !domain) {
			throw new Error("browser session requires sessionRef and domain");
		}
		const originScope = buildBrowserOriginScope([domain, ...record.originScope]);
		if (originScope.length === 0) {
			throw new Error("browser session requires a non-empty origin scope");
		}
		const stored: BrowserSessionRecord = {
			sessionRef,
			domain,
			originScope,
			storageState: record.storageState,
			createdAt: record.createdAt,
			capturedBy: record.capturedBy,
		};
		const file = this.readFile();
		const key = this.getKey(file);
		const next: CookieStoreFile = {
			salt: file.salt,
			sessions: {
				...file.sessions,
				[sessionRef]: this.encrypt(JSON.stringify(stored), key, sessionRef),
			},
		};
		this.writeFile(next);
	}

	/** Decrypt and return a session, or null if absent / undecryptable. */
	getSession(sessionRef: string): BrowserSessionRecord | null {
		const file = this.readFile();
		const ref = sessionRef.trim();
		const entry = file.sessions[ref];
		if (!entry) return null;
		try {
			return JSON.parse(this.decrypt(entry, this.getKey(file), ref)) as BrowserSessionRecord;
		} catch {
			logger.warn(
				{ sessionRef: ref },
				"browser session record failed to decrypt (wrong key or tampered)",
			);
			return null;
		}
	}

	/** List session metadata (never the storageState). */
	listSessions(): BrowserSessionMeta[] {
		const file = this.readFile();
		const key = this.getKey(file);
		const out: BrowserSessionMeta[] = [];
		for (const [ref, entry] of Object.entries(file.sessions)) {
			try {
				const r = JSON.parse(this.decrypt(entry, key, ref)) as BrowserSessionRecord;
				out.push({
					sessionRef: r.sessionRef,
					domain: r.domain,
					originScope: r.originScope,
					createdAt: r.createdAt,
					capturedBy: r.capturedBy,
				});
			} catch {
				// Skip (fail-closed) undecryptable rows rather than failing the whole listing.
				logger.warn({ sessionRef: ref }, "skipping undecryptable browser session row");
			}
		}
		return out.sort((a, b) => b.createdAt - a.createdAt);
	}

	/** Delete a session. Returns true if it existed. */
	deleteSession(sessionRef: string): boolean {
		const file = this.readFile();
		const ref = sessionRef.trim();
		if (!file.sessions[ref]) return false;
		const { [ref]: _removed, ...rest } = file.sessions;
		this.writeFile({ salt: file.salt, sessions: rest });
		return true;
	}

	private getKey(file: CookieStoreFile): Buffer {
		const salt = Buffer.from(file.salt, "base64");
		if (this.derivedKey && this.cachedSalt?.equals(salt)) return this.derivedKey;
		this.derivedKey = scryptSync(this.rawKey, salt, 32, BROWSER_COOKIE_STORE_SCRYPT_PARAMS);
		this.cachedSalt = salt;
		return this.derivedKey;
	}

	// `aad` (the sessionRef the record is filed under) is bound as AES-GCM
	// additional authenticated data, so the ref→blob mapping is tamper-evident:
	// swapping or relabelling records on disk fails the auth tag rather than
	// silently returning another session's cookies under the wrong key.
	private encrypt(plaintext: string, key: Buffer, aad: string): EncryptedRecord {
		const iv = randomBytes(12);
		const cipher = createCipheriv("aes-256-gcm", key, iv);
		cipher.setAAD(Buffer.from(aad, "utf8"));
		const data = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
		return {
			iv: iv.toString("base64"),
			data: data.toString("base64"),
			tag: cipher.getAuthTag().toString("base64"),
		};
	}

	private decrypt(entry: EncryptedRecord, key: Buffer, aad: string): string {
		const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(entry.iv, "base64"));
		decipher.setAAD(Buffer.from(aad, "utf8"));
		decipher.setAuthTag(Buffer.from(entry.tag, "base64"));
		return Buffer.concat([
			decipher.update(Buffer.from(entry.data, "base64")),
			decipher.final(),
		]).toString("utf8");
	}

	private readFile(): CookieStoreFile {
		if (!existsSync(this.filePath)) {
			return { salt: randomBytes(16).toString("base64"), sessions: {} };
		}
		try {
			const file = JSON.parse(readFileSync(this.filePath, "utf8")) as CookieStoreFile;
			if (!file.salt || typeof file.sessions !== "object") {
				throw new Error("invalid cookie store structure");
			}
			return file;
		} catch (err) {
			// Quarantine a corrupt store rather than silently destroying captured
			// sessions on the next write; fail closed if even the backup fails.
			const backup = `${this.filePath}.corrupted.${randomBytes(4).toString("hex")}`;
			try {
				renameSync(this.filePath, backup);
				logger.error({ backup, error: String(err) }, "cookie store corrupted, quarantined");
			} catch {
				throw new Error(`browser cookie store corrupted: ${String(err)}; manual recovery required`);
			}
			return { salt: randomBytes(16).toString("base64"), sessions: {} };
		}
	}

	private writeFile(file: CookieStoreFile): void {
		writeFileSync(this.filePath, JSON.stringify(file), { mode: 0o600 });
	}
}

/**
 * Construct the relay-owned cookie store from the environment, or null when the
 * encryption key is unset — M2 is then off and browsing is cookie-less only. The
 * store file lives under the relay data dir; the key never leaves the relay.
 */
export function resolveBrowserCookieStore(
	dataDir: string,
	env: NodeJS.ProcessEnv = process.env,
): BrowserCookieStore | null {
	const key = env[BROWSER_COOKIE_STORE_KEY_ENV]?.trim();
	if (!key) return null;
	return new BrowserCookieStore(join(dataDir, BROWSER_COOKIE_STORE_FILE), key);
}
