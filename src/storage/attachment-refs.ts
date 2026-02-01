/**
 * Attachment ref management for provider proxy.
 *
 * Refs are signed tokens that reference stored attachments.
 * They allow Claude to trigger delivery without accessing raw bytes.
 *
 * Ref format: att_<hash>.<expiresAt>.<signature>
 * - hash: 8 chars of SHA256(filepath + actorUserId + createdAt)
 * - expiresAt: Unix timestamp (seconds)
 * - signature: HMAC-SHA256(ref_prefix, secret)
 */

import crypto from "node:crypto";
import { getChildLogger } from "../logging.js";
import { getDb } from "./db.js";

const logger = getChildLogger({ module: "attachment-refs" });

// Default TTL: 15 minutes (configurable via TELCLAUDE_ATTACHMENT_REF_TTL_MS)
const DEFAULT_REF_TTL_MS = 15 * 60 * 1000;

export type AttachmentRef = {
	ref: string;
	actorUserId: string;
	providerId: string;
	filepath: string;
	filename: string;
	mimeType: string | null;
	size: number | null;
	createdAt: number;
	expiresAt: number;
};

type AttachmentRefRow = {
	ref: string;
	actor_user_id: string;
	provider_id: string;
	filepath: string;
	filename: string;
	mime_type: string | null;
	size: number | null;
	created_at: number;
	expires_at: number;
};

function getRefTtlMs(): number {
	const envTtl = process.env.TELCLAUDE_ATTACHMENT_REF_TTL_MS;
	if (envTtl) {
		const parsed = Number.parseInt(envTtl, 10);
		if (Number.isFinite(parsed) && parsed > 0) {
			return parsed;
		}
	}
	return DEFAULT_REF_TTL_MS;
}

function getSigningSecret(): string {
	const secret = process.env.TELEGRAM_RPC_SECRET ?? process.env.TELCLAUDE_INTERNAL_RPC_SECRET;
	if (!secret) {
		throw new Error("TELEGRAM_RPC_SECRET not set (legacy: TELCLAUDE_INTERNAL_RPC_SECRET).");
	}
	return secret;
}

/**
 * Generate a signed ref token.
 *
 * HMAC covers: actorUserId + providerId + filepath + filename + mimeType + expiresAt
 * This prevents forgery and ensures refs are scoped to the original context.
 */
function generateRef(params: {
	actorUserId: string;
	providerId: string;
	filepath: string;
	filename: string;
	mimeType: string | null;
	createdAt: number;
	expiresAt: number;
}): string {
	const { actorUserId, providerId, filepath, filename, mimeType, createdAt, expiresAt } = params;
	const secret = getSigningSecret();

	// Generate hash for uniqueness
	const hashInput = `${filepath}|${actorUserId}|${createdAt}`;
	const hash = crypto.createHash("sha256").update(hashInput).digest("hex").slice(0, 8);

	// Ref prefix (without signature)
	const expiresAtSec = Math.floor(expiresAt / 1000);
	const refPrefix = `att_${hash}.${expiresAtSec}`;

	// HMAC covers all scoped fields
	const signatureInput = [
		refPrefix,
		actorUserId,
		providerId,
		filepath,
		filename,
		mimeType ?? "",
	].join("|");
	const signature = crypto
		.createHmac("sha256", secret)
		.update(signatureInput)
		.digest("hex")
		.slice(0, 16);

	return `${refPrefix}.${signature}`;
}

/**
 * Verify a ref signature against stored metadata.
 */
function verifyRefSignature(ref: string, stored: AttachmentRef): boolean {
	const secret = getSigningSecret();

	// Parse ref
	const parts = ref.split(".");
	if (parts.length !== 3) return false;

	const refPrefix = `${parts[0]}.${parts[1]}`;
	const providedSig = parts[2];

	// Recompute signature
	const signatureInput = [
		refPrefix,
		stored.actorUserId,
		stored.providerId,
		stored.filepath,
		stored.filename,
		stored.mimeType ?? "",
	].join("|");
	const expectedSig = crypto
		.createHmac("sha256", secret)
		.update(signatureInput)
		.digest("hex")
		.slice(0, 16);

	// Timing-safe comparison
	if (providedSig.length !== expectedSig.length) return false;
	return crypto.timingSafeEqual(Buffer.from(providedSig), Buffer.from(expectedSig));
}

/**
 * Create and store a new attachment ref.
 */
export function createAttachmentRef(params: {
	actorUserId: string;
	providerId: string;
	filepath: string;
	filename: string;
	mimeType?: string | null;
	size?: number | null;
}): AttachmentRef {
	const db = getDb();
	const now = Date.now();
	const ttlMs = getRefTtlMs();
	const expiresAt = now + ttlMs;

	const ref = generateRef({
		actorUserId: params.actorUserId,
		providerId: params.providerId,
		filepath: params.filepath,
		filename: params.filename,
		mimeType: params.mimeType ?? null,
		createdAt: now,
		expiresAt,
	});

	db.prepare(
		`INSERT INTO attachment_refs (ref, actor_user_id, provider_id, filepath, filename, mime_type, size, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	).run(
		ref,
		params.actorUserId,
		params.providerId,
		params.filepath,
		params.filename,
		params.mimeType ?? null,
		params.size ?? null,
		now,
		expiresAt,
	);

	logger.debug(
		{
			ref,
			actorUserId: params.actorUserId,
			providerId: params.providerId,
			filename: params.filename,
		},
		"attachment ref created",
	);

	return {
		ref,
		actorUserId: params.actorUserId,
		providerId: params.providerId,
		filepath: params.filepath,
		filename: params.filename,
		mimeType: params.mimeType ?? null,
		size: params.size ?? null,
		createdAt: now,
		expiresAt,
	};
}

/**
 * Get an attachment ref by its token.
 * Returns null if not found or expired.
 */
export function getAttachmentRef(ref: string): AttachmentRef | null {
	const db = getDb();
	const now = Date.now();

	const row = db.prepare("SELECT * FROM attachment_refs WHERE ref = ?").get(ref) as
		| AttachmentRefRow
		| undefined;

	if (!row) {
		logger.debug({ ref }, "attachment ref not found");
		return null;
	}

	if (row.expires_at < now) {
		// Clean up expired ref
		db.prepare("DELETE FROM attachment_refs WHERE ref = ?").run(ref);
		logger.debug({ ref }, "attachment ref expired");
		return null;
	}

	return {
		ref: row.ref,
		actorUserId: row.actor_user_id,
		providerId: row.provider_id,
		filepath: row.filepath,
		filename: row.filename,
		mimeType: row.mime_type,
		size: row.size,
		createdAt: row.created_at,
		expiresAt: row.expires_at,
	};
}

/**
 * Validate and retrieve an attachment ref.
 *
 * Verifies:
 * 1. Ref exists in database
 * 2. Ref is not expired
 * 3. Signature is valid
 * 4. Actor matches (optional strict mode)
 */
export function validateAttachmentRef(
	ref: string,
	options?: { actorUserId?: string },
): { valid: true; attachment: AttachmentRef } | { valid: false; reason: string } {
	const stored = getAttachmentRef(ref);

	if (!stored) {
		return { valid: false, reason: "Attachment not found or expired" };
	}

	// Verify signature
	if (!verifyRefSignature(ref, stored)) {
		logger.warn({ ref }, "attachment ref signature verification failed");
		return { valid: false, reason: "Invalid signature" };
	}

	// Optional: strict actor matching
	if (options?.actorUserId && stored.actorUserId !== options.actorUserId) {
		logger.warn(
			{ ref, expected: options.actorUserId, actual: stored.actorUserId },
			"attachment ref actor mismatch",
		);
		return { valid: false, reason: "Actor mismatch" };
	}

	return { valid: true, attachment: stored };
}

/**
 * Delete an attachment ref.
 */
export function deleteAttachmentRef(ref: string): boolean {
	const db = getDb();
	const result = db.prepare("DELETE FROM attachment_refs WHERE ref = ?").run(ref);
	return result.changes > 0;
}

/**
 * List all refs for a given actor (for debugging/admin).
 */
export function listAttachmentRefsByActor(actorUserId: string): AttachmentRef[] {
	const db = getDb();
	const now = Date.now();

	const rows = db
		.prepare("SELECT * FROM attachment_refs WHERE actor_user_id = ? AND expires_at >= ?")
		.all(actorUserId, now) as AttachmentRefRow[];

	return rows.map((row) => ({
		ref: row.ref,
		actorUserId: row.actor_user_id,
		providerId: row.provider_id,
		filepath: row.filepath,
		filename: row.filename,
		mimeType: row.mime_type,
		size: row.size,
		createdAt: row.created_at,
		expiresAt: row.expires_at,
	}));
}
