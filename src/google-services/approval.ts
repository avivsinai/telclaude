/**
 * Approval token verification for action-type requests.
 *
 * Tokens are Ed25519-signed, domain-separated, and replay-protected.
 * Format: v1.<claims_b64url>.<sig_b64url>
 */

import crypto from "node:crypto";
import path from "node:path";
import Database from "better-sqlite3";
import { ApprovalClaimsSchema, type FetchRequest } from "./types.js";

// ═══════════════════════════════════════════════════════════════════════════════
// Canonical Hash
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Compute canonical hash for request binding.
 * Deterministic JSON serialization (recursive key sort) + SHA-256.
 * Keep in sync with src/relay/approval-token.ts.
 */
export function canonicalHash(input: {
	service: string;
	action: string;
	params: Record<string, unknown>;
	actorUserId: string;
	subjectUserId: string | null;
}): string {
	const canonical = JSON.stringify(sortKeysDeep(input));
	const hash = crypto.createHash("sha256").update(canonical).digest("hex");
	return `sha256:${hash}`;
}

/**
 * Recursively sort object keys for deterministic serialization.
 */
function sortKeysDeep(value: unknown): unknown {
	if (value === null || typeof value !== "object") return value;
	if (Array.isArray(value)) return value.map(sortKeysDeep);
	const sorted: Record<string, unknown> = {};
	for (const key of Object.keys(value as Record<string, unknown>).sort()) {
		sorted[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
	}
	return sorted;
}

// ═══════════════════════════════════════════════════════════════════════════════
// JTI Replay Store
// ═══════════════════════════════════════════════════════════════════════════════

export class JtiStore {
	private db: Database.Database;

	constructor(dataDir: string) {
		const dbPath = path.join(dataDir, "approval_jti.sqlite");
		this.db = new Database(dbPath);
		this.db.pragma("journal_mode = WAL");
		this.db.exec(`
			CREATE TABLE IF NOT EXISTS used_approval_tokens (
				jti TEXT PRIMARY KEY,
				exp INTEGER NOT NULL,
				used_at INTEGER NOT NULL
			)
		`);
		this.insertStmt = this.db.prepare(
			"INSERT INTO used_approval_tokens (jti, exp, used_at) VALUES (?, ?, ?)",
		);
		this.cleanupStmt = this.db.prepare("DELETE FROM used_approval_tokens WHERE exp < ?");
	}

	private insertStmt: Database.Statement;
	private cleanupStmt: Database.Statement;

	/**
	 * Atomically record a JTI as used. Returns false if already used (replay).
	 */
	recordJti(jti: string, exp: number): boolean {
		try {
			this.insertStmt.run(jti, exp, Math.floor(Date.now() / 1000));
			return true;
		} catch {
			// UNIQUE constraint violation = replay
			return false;
		}
	}

	/**
	 * Clean up expired JTI entries.
	 */
	cleanup(): void {
		const now = Math.floor(Date.now() / 1000);
		this.cleanupStmt.run(now);
	}

	close(): void {
		this.db.close();
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Token Verification
// ═══════════════════════════════════════════════════════════════════════════════

export type ApprovalResult = { ok: true } | { ok: false; code: string; message: string };

/**
 * Verify an approval token for an action request.
 *
 * 7-step verification:
 * 1. Parse token format (v1.<claims>.<sig>)
 * 2. Verify Ed25519 signature
 * 3. Validate claims structure
 * 4. Check expiration and TTL
 * 5. Match service + action + actor
 * 6. Verify params hash binding
 * 7. Record JTI for replay prevention
 */
export function verifyApprovalToken(
	token: string,
	request: FetchRequest,
	actorUserId: string,
	verifySignature: (payload: string, signature: string) => boolean,
	jtiStore: JtiStore,
): ApprovalResult {
	// Step 1: Parse token format
	const parts = token.split(".");
	if (parts.length !== 3 || parts[0] !== "v1") {
		return { ok: false, code: "approval_required", message: "Invalid token format" };
	}

	const [, claimsB64, sigB64] = parts;

	// Step 2: Verify signature (domain-separated)
	const valid = verifySignature(claimsB64, sigB64);
	if (!valid) {
		return { ok: false, code: "approval_required", message: "Invalid token signature" };
	}

	// Step 3: Decode and validate claims
	let claimsJson: string;
	try {
		claimsJson = Buffer.from(claimsB64, "base64url").toString("utf-8");
	} catch {
		return { ok: false, code: "approval_required", message: "Invalid token encoding" };
	}

	let rawClaims: unknown;
	try {
		rawClaims = JSON.parse(claimsJson);
	} catch {
		return { ok: false, code: "approval_required", message: "Invalid claims JSON" };
	}

	const claimsResult = ApprovalClaimsSchema.safeParse(rawClaims);
	if (!claimsResult.success) {
		return { ok: false, code: "approval_required", message: "Invalid claims structure" };
	}
	const claims = claimsResult.data;

	// Step 4: Check expiration and TTL
	const now = Math.floor(Date.now() / 1000);
	if (claims.exp <= now) {
		return { ok: false, code: "approval_expired", message: "Token expired" };
	}
	if (claims.exp - claims.iat > 300) {
		return { ok: false, code: "approval_required", message: "Token TTL exceeds maximum (300s)" };
	}

	// Step 5: Match service + action + actor
	if (claims.service !== request.service) {
		return {
			ok: false,
			code: "approval_mismatch",
			message: `Service mismatch: expected ${request.service}, got ${claims.service}`,
		};
	}
	if (claims.action !== request.action) {
		return {
			ok: false,
			code: "approval_mismatch",
			message: `Action mismatch: expected ${request.action}, got ${claims.action}`,
		};
	}
	if (claims.actorUserId !== actorUserId) {
		return { ok: false, code: "approval_mismatch", message: "Actor mismatch" };
	}

	// Step 6: Verify params hash binding
	const expectedHash = canonicalHash({
		service: request.service,
		action: request.action,
		params: request.params,
		actorUserId,
		subjectUserId: claims.subjectUserId,
	});
	if (claims.paramsHash !== expectedHash) {
		return { ok: false, code: "approval_mismatch", message: "Params hash mismatch" };
	}

	// Step 7: Record JTI for replay prevention
	const recorded = jtiStore.recordJti(claims.jti, claims.exp);
	if (!recorded) {
		return { ok: false, code: "approval_replayed", message: "Token already used" };
	}

	return { ok: true };
}
