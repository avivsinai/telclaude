/**
 * DM Pairing Codes (Workstream W4).
 *
 * First-touch access flow for unknown Telegram chats:
 *   1. Stranger DMs the bot → bot replies with one-time pairing code + rate-limit notice.
 *   2. Operator approves via `telclaude pairing approve <code>` or admin-chat command.
 *   3. On approval the (user, chat) pair is added to a durable paired set with a
 *      configured tier (default READ_ONLY) — this is additive to `telegram.allowedChats`.
 *
 * Security properties:
 *   - Code is 8 chars, URL-safe (alphabet excludes ambiguous chars like 0/O, 1/l).
 *   - Code is SHA-256 hashed at rest (never stored as plaintext).
 *   - Code carries an Ed25519 signature over `pairing-v1\n<user_id>:<chat_id>:<code_hash>`.
 *     Signature prevents forged approvals and binds codes to the issuing relay.
 *     Domain-separated from `approval-v1` / `session-v1` to prevent cross-use.
 *   - Signer defaults to a module-level Ed25519 keypair persisted at
 *     `~/.telclaude/pairing-keypair.json` (0600); can be overridden for tests.
 *   - Rate limits: 1 code per 10 min per user, max 3 pending codes per user,
 *     5 failed approval attempts → 1 hour lockout, codes expire in 1 hour.
 *   - Approval consumption is atomic inside a SQLite transaction.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { PermissionTier } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { getDb } from "../storage/db.js";
import { CONFIG_DIR } from "../utils.js";
import type { Result } from "./types.js";

const logger = getChildLogger({ module: "pairing" });

// ═══════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════

/** Code expiry (1 hour per spec). */
export const CODE_EXPIRY_MS = 60 * 60 * 1000;

/** Per-user rate limit between code emissions (1 per 10 min per spec). */
export const EMIT_COOLDOWN_MS = 10 * 60 * 1000;

/** Maximum pending (unapproved, unexpired) codes per user. */
export const MAX_PENDING_PER_USER = 3;

/** Failed approval attempts threshold before per-user lockout. */
export const MAX_FAILED_ATTEMPTS = 5;

/** Per-user lockout duration once the attempts threshold is hit (1 hour). */
export const LOCKOUT_MS = 60 * 60 * 1000;

/** Domain-separation prefix for signatures (distinct from approval-v1/session-v1). */
export const SIGNING_PREFIX = "pairing-v1";

/** Default tier granted on approval unless overridden. */
export const DEFAULT_PAIRED_TIER: PermissionTier = "READ_ONLY";

/**
 * URL-safe alphabet excluding ambiguous characters (0/O, 1/l/I, etc.).
 * 32-character alphabet → log2(32) = 5 bits per char → 8 chars = 40 bits of entropy.
 */
const CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const CODE_LENGTH = 8;

// ═══════════════════════════════════════════════════════════════════════════════
// Signer abstraction (defaults to in-process Ed25519 key; injectable for tests)
// ═══════════════════════════════════════════════════════════════════════════════

export interface PairingSigner {
	/** Sign `<prefix>\n<payload>`; returns a base64url signature. */
	sign(payload: string): Promise<string>;
	/** Verify a base64url signature over `<prefix>\n<payload>`; returns a verdict. */
	verify(payload: string, signature: string): Promise<boolean>;
}

const KEYPAIR_PATH = path.join(CONFIG_DIR, "pairing-keypair.json");

type StoredKeypair = {
	privateKeyPem: string;
	publicKeyPem: string;
};

let cachedSigner: PairingSigner | null = null;

/**
 * Read or create the persistent Ed25519 keypair used to sign pairing codes.
 * Written with 0600 perms, inside CONFIG_DIR (already 0700).
 */
function loadOrCreateKeypair(): StoredKeypair {
	if (fs.existsSync(KEYPAIR_PATH)) {
		try {
			const raw = fs.readFileSync(KEYPAIR_PATH, "utf8");
			const parsed = JSON.parse(raw) as StoredKeypair;
			if (parsed.privateKeyPem && parsed.publicKeyPem) {
				return parsed;
			}
			logger.warn({ path: KEYPAIR_PATH }, "pairing keypair corrupt; regenerating");
		} catch (err) {
			logger.warn(
				{ path: KEYPAIR_PATH, error: String(err) },
				"failed to read pairing keypair; regenerating",
			);
		}
	}

	fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });

	const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519", {
		privateKeyEncoding: { type: "pkcs8", format: "pem" },
		publicKeyEncoding: { type: "spki", format: "pem" },
	});

	const stored: StoredKeypair = {
		privateKeyPem: privateKey.toString(),
		publicKeyPem: publicKey.toString(),
	};

	fs.writeFileSync(KEYPAIR_PATH, JSON.stringify(stored), { mode: 0o600 });
	try {
		fs.chmodSync(KEYPAIR_PATH, 0o600);
	} catch {
		logger.warn({ path: KEYPAIR_PATH }, "could not set keypair file perms to 0600");
	}

	logger.info({ path: KEYPAIR_PATH }, "pairing keypair generated");
	return stored;
}

/**
 * Build an in-process Ed25519 signer over `pairing-v1\n<payload>`.
 */
export function createLocalPairingSigner(keypair?: StoredKeypair): PairingSigner {
	const kp = keypair ?? loadOrCreateKeypair();
	const privateKey = crypto.createPrivateKey(kp.privateKeyPem);
	const publicKey = crypto.createPublicKey(kp.publicKeyPem);

	return {
		async sign(payload: string): Promise<string> {
			const msg = Buffer.from(`${SIGNING_PREFIX}\n${payload}`, "utf8");
			const sig = crypto.sign(null, msg, privateKey);
			return sig.toString("base64url");
		},
		async verify(payload: string, signature: string): Promise<boolean> {
			try {
				const msg = Buffer.from(`${SIGNING_PREFIX}\n${payload}`, "utf8");
				const sig = Buffer.from(signature, "base64url");
				return crypto.verify(null, msg, publicKey, sig);
			} catch {
				return false;
			}
		},
	};
}

/**
 * Get the default signer (cached across calls).
 * Tests can override via `setPairingSigner`.
 */
export function getPairingSigner(): PairingSigner {
	if (!cachedSigner) {
		cachedSigner = createLocalPairingSigner();
	}
	return cachedSigner;
}

/**
 * Override the default signer. Intended for tests and custom deployments
 * that want to route signing through the vault daemon or another backend.
 */
export function setPairingSigner(signer: PairingSigner | null): void {
	cachedSigner = signer;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Types & row mapping
// ═══════════════════════════════════════════════════════════════════════════════

export type PairingStatus = "pending" | "approved" | "revoked" | "expired";

export type PairingRequest = {
	codeHash: string;
	userId: number;
	chatId: number;
	username?: string;
	tier: PermissionTier;
	status: PairingStatus;
	attempts: number;
	createdAt: number;
	expiresAt: number;
	approvedAt?: number;
	approvedBy?: string;
	signature: string;
};

type PairingRow = {
	code_hash: string;
	user_id: number;
	chat_id: number;
	username: string | null;
	tier: string;
	status: string;
	attempts: number;
	created_at: number;
	expires_at: number;
	approved_at: number | null;
	approved_by: string | null;
	signature: string;
};

function rowToRequest(row: PairingRow): PairingRequest {
	return {
		codeHash: row.code_hash,
		userId: row.user_id,
		chatId: row.chat_id,
		username: row.username ?? undefined,
		tier: row.tier as PermissionTier,
		status: row.status as PairingStatus,
		attempts: row.attempts,
		createdAt: row.created_at,
		expiresAt: row.expires_at,
		approvedAt: row.approved_at ?? undefined,
		approvedBy: row.approved_by ?? undefined,
		signature: row.signature,
	};
}

/**
 * Durable record of (user, chat) pairs that were approved via the pairing flow.
 * These augment `telegram.allowedChats` at runtime without requiring a config edit.
 */
export type PairedChat = {
	chatId: number;
	userId: number;
	tier: PermissionTier;
	pairedAt: number;
	approvedBy: string;
	username?: string;
};

type PairedChatRow = {
	chat_id: number;
	user_id: number;
	tier: string;
	paired_at: number;
	approved_by: string;
	username: string | null;
};

function rowToPaired(row: PairedChatRow): PairedChat {
	return {
		chatId: row.chat_id,
		userId: row.user_id,
		tier: row.tier as PermissionTier,
		pairedAt: row.paired_at,
		approvedBy: row.approved_by,
		username: row.username ?? undefined,
	};
}

// ═══════════════════════════════════════════════════════════════════════════════
// Code generation & hashing
// ═══════════════════════════════════════════════════════════════════════════════

function generateCode(): string {
	const bytes = crypto.randomBytes(CODE_LENGTH);
	let code = "";
	for (let i = 0; i < CODE_LENGTH; i++) {
		code += CODE_ALPHABET[bytes[i] % CODE_ALPHABET.length];
	}
	return code;
}

/**
 * Normalize a user-provided code: strip whitespace, uppercase, remove dashes
 * (operators may type `ABCD-EFGH` even though we emit without dashes).
 */
export function normalizeCode(raw: string): string {
	return raw
		.trim()
		.toUpperCase()
		.replace(/[^A-Z0-9]/g, "");
}

function hashCode(code: string): string {
	return crypto.createHash("sha256").update(code, "utf8").digest("hex");
}

function signingPayloadFor(userId: number, chatId: number, codeHash: string): string {
	return `${userId}:${chatId}:${codeHash}`;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Rate-limit / lockout helpers
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Result of a rate-limit check for a given user.
 */
export type PairingRateCheck =
	| { allowed: true }
	| {
			allowed: false;
			reason: "cooldown" | "pending_limit" | "lockout";
			/** Milliseconds until the user may try again. */
			retryAfterMs: number;
	  };

/**
 * Check whether the user may receive a new pairing code right now.
 * Enforces:
 *   - `EMIT_COOLDOWN_MS` between code emissions (1 per 10 min per user).
 *   - `MAX_PENDING_PER_USER` pending codes per user (3).
 *   - `LOCKOUT_MS` if failed attempts threshold reached.
 */
export function checkPairingRate(userId: number, now: number = Date.now()): PairingRateCheck {
	const db = getDb();

	const lockout = db
		.prepare("SELECT locked_until FROM pairing_lockouts WHERE user_id = ?")
		.get(userId) as { locked_until: number } | undefined;

	if (lockout && lockout.locked_until > now) {
		return {
			allowed: false,
			reason: "lockout",
			retryAfterMs: lockout.locked_until - now,
		};
	}

	// Most recent pending request for this user (cooldown).
	const recent = db
		.prepare(
			`SELECT created_at FROM pairing_requests
			 WHERE user_id = ? AND status = 'pending'
			 ORDER BY created_at DESC LIMIT 1`,
		)
		.get(userId) as { created_at: number } | undefined;

	if (recent && now - recent.created_at < EMIT_COOLDOWN_MS) {
		return {
			allowed: false,
			reason: "cooldown",
			retryAfterMs: EMIT_COOLDOWN_MS - (now - recent.created_at),
		};
	}

	const pendingCount = db
		.prepare(
			`SELECT COUNT(*) as c FROM pairing_requests
			 WHERE user_id = ? AND status = 'pending' AND expires_at > ?`,
		)
		.get(userId, now) as { c: number };

	if (pendingCount.c >= MAX_PENDING_PER_USER) {
		// Find the earliest expiry among the pending set to give a useful hint.
		const earliest = db
			.prepare(
				`SELECT MIN(expires_at) as m FROM pairing_requests
				 WHERE user_id = ? AND status = 'pending' AND expires_at > ?`,
			)
			.get(userId, now) as { m: number | null };
		return {
			allowed: false,
			reason: "pending_limit",
			retryAfterMs: Math.max(0, (earliest.m ?? now) - now),
		};
	}

	return { allowed: true };
}

function bumpFailedAttempts(userId: number, now: number = Date.now()): number {
	const db = getDb();
	return db.transaction(() => {
		db.prepare(
			`INSERT INTO pairing_failed_attempts (user_id, attempts, last_attempt_at)
			 VALUES (?, 1, ?)
			 ON CONFLICT(user_id) DO UPDATE SET
			   attempts = attempts + 1,
			   last_attempt_at = excluded.last_attempt_at`,
		).run(userId, now);

		const row = db
			.prepare("SELECT attempts FROM pairing_failed_attempts WHERE user_id = ?")
			.get(userId) as { attempts: number };

		if (row.attempts >= MAX_FAILED_ATTEMPTS) {
			db.prepare(
				`INSERT INTO pairing_lockouts (user_id, locked_until)
				 VALUES (?, ?)
				 ON CONFLICT(user_id) DO UPDATE SET locked_until = excluded.locked_until`,
			).run(userId, now + LOCKOUT_MS);
			logger.warn(
				{ userId, attempts: row.attempts },
				"pairing lockout engaged after failed attempts",
			);
		}

		return row.attempts;
	})();
}

function clearFailedAttempts(userId: number): void {
	const db = getDb();
	db.transaction(() => {
		db.prepare("DELETE FROM pairing_failed_attempts WHERE user_id = ?").run(userId);
		db.prepare("DELETE FROM pairing_lockouts WHERE user_id = ?").run(userId);
	})();
}

// ═══════════════════════════════════════════════════════════════════════════════
// Create / approve / revoke
// ═══════════════════════════════════════════════════════════════════════════════

export type CreatePairingInput = {
	userId: number;
	chatId: number;
	username?: string;
	tier?: PermissionTier;
};

export type CreatePairingResult = {
	/** User-facing code (e.g. `ABCDEFGH`). */
	code: string;
	expiresAt: number;
	createdAt: number;
};

/**
 * Create a new pairing request for a user.
 * Call `checkPairingRate` first; this function does NOT enforce rate limits by itself,
 * so CLI-driven issuance (admin-side) can bypass operator-facing throttles if needed.
 */
export async function createPairingCode(
	input: CreatePairingInput,
	signer: PairingSigner = getPairingSigner(),
	now: number = Date.now(),
): Promise<CreatePairingResult> {
	const code = generateCode();
	const codeHash = hashCode(code);
	const expiresAt = now + CODE_EXPIRY_MS;
	const tier = input.tier ?? DEFAULT_PAIRED_TIER;

	const payload = signingPayloadFor(input.userId, input.chatId, codeHash);
	const signature = await signer.sign(payload);

	const db = getDb();
	db.prepare(
		`INSERT INTO pairing_requests (
			code_hash, user_id, chat_id, username, tier, status, attempts,
			created_at, expires_at, signature
		) VALUES (?, ?, ?, ?, ?, 'pending', 0, ?, ?, ?)`,
	).run(
		codeHash,
		input.userId,
		input.chatId,
		input.username ?? null,
		tier,
		now,
		expiresAt,
		signature,
	);

	logger.info(
		{
			userId: input.userId,
			chatId: input.chatId,
			tier,
			expiresIn: Math.round(CODE_EXPIRY_MS / 1000),
		},
		"pairing code issued",
	);

	return { code, expiresAt, createdAt: now };
}

/**
 * Approve a pairing code (operator-side).
 *
 * Lookup is by code hash; a wrong code does NOT reveal whether a similar code
 * exists (constant error message, but we still increment attempts on hash miss
 * when we can attribute the attempt to a user — on a pure hash miss we can't,
 * so those attempts are not charged against any user).
 */
export async function approvePairingCode(
	rawCode: string,
	approvedBy: string,
	signer: PairingSigner = getPairingSigner(),
	now: number = Date.now(),
): Promise<Result<{ request: PairingRequest; paired: PairedChat }>> {
	const normalized = normalizeCode(rawCode);

	if (normalized.length !== CODE_LENGTH) {
		return { success: false, error: "Pairing code must be 8 characters." };
	}

	const codeHash = hashCode(normalized);
	const db = getDb();

	const row = db.prepare("SELECT * FROM pairing_requests WHERE code_hash = ?").get(codeHash) as
		| PairingRow
		| undefined;

	if (!row) {
		return { success: false, error: "Unknown pairing code." };
	}

	const request = rowToRequest(row);

	// Enforce lockout even during approval so a brute-force via the CLI fails.
	const lockout = db
		.prepare("SELECT locked_until FROM pairing_lockouts WHERE user_id = ?")
		.get(request.userId) as { locked_until: number } | undefined;
	if (lockout && lockout.locked_until > now) {
		return {
			success: false,
			error: `Pairing for user ${request.userId} is locked out. Try again in ${Math.ceil(
				(lockout.locked_until - now) / 60000,
			)} minute(s).`,
		};
	}

	if (request.status !== "pending") {
		// Approving a non-pending code still counts as a failed attempt — this
		// closes the brute-force loophole where an attacker replays an old code
		// to enumerate valid plaintext without incrementing any counter.
		bumpFailedAttempts(request.userId, now);
		return {
			success: false,
			error: `Pairing code is already ${request.status}.`,
		};
	}

	if (request.expiresAt <= now) {
		// Mark as expired (idempotent) and record the attempt.
		db.prepare(
			"UPDATE pairing_requests SET status = 'expired' WHERE code_hash = ? AND status = 'pending'",
		).run(codeHash);
		bumpFailedAttempts(request.userId, now);
		return { success: false, error: "Pairing code has expired." };
	}

	// Verify the signature before trusting any side of the record.
	const payload = signingPayloadFor(request.userId, request.chatId, request.codeHash);
	const sigOk = await signer.verify(payload, request.signature);
	if (!sigOk) {
		bumpFailedAttempts(request.userId, now);
		logger.error(
			{ userId: request.userId, chatId: request.chatId },
			"pairing signature verification failed; potential DB tampering",
		);
		return { success: false, error: "Pairing code signature invalid." };
	}

	// Atomic approve + insert paired_chat + clear lockout counters.
	let paired: PairedChat | null = null;
	const approvalResult = db.transaction(() => {
		const update = db
			.prepare(
				`UPDATE pairing_requests
				 SET status = 'approved', approved_at = ?, approved_by = ?
				 WHERE code_hash = ? AND status = 'pending'`,
			)
			.run(now, approvedBy, codeHash);

		if (update.changes !== 1) {
			// Race: someone else just approved/revoked the same code.
			return { success: false as const, error: "Pairing code state changed; please retry." };
		}

		db.prepare(
			`INSERT INTO paired_chats (chat_id, user_id, tier, paired_at, approved_by, username)
			 VALUES (?, ?, ?, ?, ?, ?)
			 ON CONFLICT(chat_id) DO UPDATE SET
			   user_id = excluded.user_id,
			   tier = excluded.tier,
			   paired_at = excluded.paired_at,
			   approved_by = excluded.approved_by,
			   username = excluded.username`,
		).run(request.chatId, request.userId, request.tier, now, approvedBy, request.username ?? null);

		const pairedRow = db
			.prepare("SELECT * FROM paired_chats WHERE chat_id = ?")
			.get(request.chatId) as PairedChatRow;
		paired = rowToPaired(pairedRow);

		// Revoke all other pending codes for the same user — principle of least surprise.
		db.prepare(
			`UPDATE pairing_requests SET status = 'revoked'
			 WHERE user_id = ? AND status = 'pending' AND code_hash != ?`,
		).run(request.userId, codeHash);

		return { success: true as const };
	})();

	if (!approvalResult.success) {
		return approvalResult;
	}

	clearFailedAttempts(request.userId);

	logger.info(
		{
			userId: request.userId,
			chatId: request.chatId,
			tier: request.tier,
			approvedBy,
		},
		"pairing approved",
	);

	if (!paired) {
		// Should be unreachable given the transaction above.
		return { success: false, error: "Pairing approved but paired_chats row missing." };
	}

	return {
		success: true,
		data: {
			request: { ...request, status: "approved", approvedAt: now, approvedBy },
			paired,
		},
	};
}

/**
 * Revoke all pending pairing codes for a user.
 * Returns the number of revoked codes.
 */
export function revokePendingForUser(userId: number): number {
	const db = getDb();
	const result = db
		.prepare(
			"UPDATE pairing_requests SET status = 'revoked' WHERE user_id = ? AND status = 'pending'",
		)
		.run(userId);
	if (result.changes > 0) {
		logger.info({ userId, revoked: result.changes }, "pairing codes revoked for user");
	}
	return result.changes;
}

/**
 * Purge expired / unused codes. Returns the number of rows mutated.
 *  - Pending codes with `expires_at < now` → marked `expired`.
 *  - Rows in terminal states (expired/revoked) older than 7 days → deleted.
 */
export function clearExpiredPending(now: number = Date.now()): number {
	const db = getDb();
	const oneWeekAgo = now - 7 * 24 * 60 * 60 * 1000;

	return db.transaction(() => {
		const marked = db
			.prepare(
				"UPDATE pairing_requests SET status = 'expired' WHERE status = 'pending' AND expires_at < ?",
			)
			.run(now);
		const pruned = db
			.prepare(
				`DELETE FROM pairing_requests
				 WHERE status IN ('expired', 'revoked') AND expires_at < ?`,
			)
			.run(oneWeekAgo);
		return marked.changes + pruned.changes;
	})();
}

// ═══════════════════════════════════════════════════════════════════════════════
// Read helpers
// ═══════════════════════════════════════════════════════════════════════════════

export function listPairingRequests(opts?: { status?: PairingStatus }): PairingRequest[] {
	const db = getDb();
	if (opts?.status) {
		const rows = db
			.prepare("SELECT * FROM pairing_requests WHERE status = ? ORDER BY created_at DESC")
			.all(opts.status) as PairingRow[];
		return rows.map(rowToRequest);
	}
	const rows = db
		.prepare("SELECT * FROM pairing_requests ORDER BY created_at DESC")
		.all() as PairingRow[];
	return rows.map(rowToRequest);
}

export function listPairedChats(): PairedChat[] {
	const db = getDb();
	const rows = db
		.prepare("SELECT * FROM paired_chats ORDER BY paired_at DESC")
		.all() as PairedChatRow[];
	return rows.map(rowToPaired);
}

export function getPairedChat(chatId: number): PairedChat | null {
	const db = getDb();
	try {
		const row = db.prepare("SELECT * FROM paired_chats WHERE chat_id = ?").get(chatId) as
			| PairedChatRow
			| undefined;
		return row ? rowToPaired(row) : null;
	} catch (err) {
		// Guard against legacy / test DBs that haven't yet migrated the pairing tables.
		// Production relay startup always runs `initializeSchema`, so this branch is
		// only reached in mocked environments that stand up a minimal DB.
		if (err instanceof Error && /no such table: paired_chats/i.test(err.message)) {
			return null;
		}
		throw err;
	}
}

/**
 * True iff the chat was added via the pairing flow (additive to config allowedChats).
 */
export function isChatPaired(chatId: number): boolean {
	return getPairedChat(chatId) !== null;
}

/**
 * Remove a paired chat (e.g. operator revocation). Returns true if a row was removed.
 */
export function removePairedChat(chatId: number): boolean {
	const db = getDb();
	const result = db.prepare("DELETE FROM paired_chats WHERE chat_id = ?").run(chatId);
	if (result.changes > 0) {
		logger.info({ chatId }, "paired chat removed");
	}
	return result.changes > 0;
}

/**
 * List active lockouts (for operator visibility via `pairing list`).
 */
export function listActiveLockouts(now: number = Date.now()): Array<{
	userId: number;
	lockedUntil: number;
	attempts: number;
}> {
	const db = getDb();
	const rows = db
		.prepare(
			`SELECT l.user_id as user_id, l.locked_until as locked_until,
			        COALESCE(f.attempts, 0) as attempts
			 FROM pairing_lockouts l
			 LEFT JOIN pairing_failed_attempts f ON f.user_id = l.user_id
			 WHERE l.locked_until > ?
			 ORDER BY l.locked_until ASC`,
		)
		.all(now) as Array<{ user_id: number; locked_until: number; attempts: number }>;
	return rows.map((r) => ({
		userId: r.user_id,
		lockedUntil: r.locked_until,
		attempts: r.attempts,
	}));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Operator-facing message
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Format the "here's your pairing code" DM that the bot sends to unknown chats.
 * Kept short because Telegram users skim on mobile.
 */
export function formatPairingPrompt(
	code: string,
	expiresAt: number,
	now: number = Date.now(),
): string {
	const minutes = Math.max(1, Math.round((expiresAt - now) / 60000));
	return [
		"👋 You're not yet approved to use this bot.",
		"",
		`Pairing code: \`${code}\``,
		`(valid for ${minutes} minutes, one per 10 minutes)`,
		"",
		"Ask the operator to run:",
		`\`telclaude pairing approve ${code}\``,
	].join("\n");
}

/**
 * Short rate-limit notice shown on cooldown / pending_limit / lockout.
 */
export function formatPairingRateNotice(
	check: Exclude<PairingRateCheck, { allowed: true }>,
): string {
	const minutes = Math.max(1, Math.round(check.retryAfterMs / 60000));
	switch (check.reason) {
		case "cooldown":
			return `⏳ Please wait ~${minutes} minute(s) before requesting another pairing code.`;
		case "pending_limit":
			return `⏳ You have the maximum pending pairing codes. Ask the operator to approve one, or wait ~${minutes} minute(s) for the oldest to expire.`;
		case "lockout":
			return `🔒 Too many failed pairing attempts. Please retry in ~${minutes} minute(s).`;
	}
}
