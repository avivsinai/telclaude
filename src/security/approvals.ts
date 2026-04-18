import crypto from "node:crypto";
import type { PermissionTier } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { getDb } from "../storage/db.js";
import type { MediaType } from "../types/media.js";
import {
	APPROVAL_SCOPES,
	type ApprovalScope,
	isApprovalScope,
	type RiskTier,
	scopeAllowedForRisk,
} from "./risk-tiers.js";
import type { Result, SecurityClassification } from "./types.js";

const logger = getChildLogger({ module: "approvals" });

const DEFAULT_TTL_MS = 5 * 60 * 1000; // 5 minutes

// Durable "always" allowlist retention. We keep allowlist rows forever in
// principle, but the cleanup job prunes "always" rows that haven't been used
// in 30 days as a hygienic backstop.
const ALLOWLIST_ALWAYS_EXPIRY_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * Re-export risk + scope types so callers can import from a single module.
 */
export type { ApprovalScope, RiskTier };
export { APPROVAL_SCOPES, isApprovalScope, scopeAllowedForRisk };

/**
 * A pending approval request.
 *
 * The optional `riskTier` / `toolKey` fields are populated when the approval
 * is created as part of the W1 graduated-approval flow. Legacy approvals
 * (from the single-button `/approve CODE` path) omit them.
 */
export type PendingApproval = {
	nonce: string;
	requestId: string;
	chatId: number;
	createdAt: number;
	expiresAt: number;
	tier: PermissionTier;
	body: string;
	mediaPath?: string;
	mediaFilePath?: string;
	mediaFileId?: string;
	mediaType?: MediaType;
	username?: string;
	from: string;
	to: string;
	messageId: string;
	observerClassification: SecurityClassification;
	observerConfidence: number;
	observerReason?: string;
	/** W1: risk classification used for scope cap enforcement. */
	riskTier?: RiskTier;
	/** W1: canonical tool identifier used for allowlist keying. */
	toolKey?: string;
	/** W1: session key at creation time; used to scope "session" grants. */
	sessionKey?: string;
};

/**
 * Database row type for approvals.
 */
type ApprovalRow = {
	nonce: string;
	request_id: string;
	chat_id: number;
	created_at: number;
	expires_at: number;
	tier: string;
	body: string;
	media_path: string | null;
	media_file_path: string | null;
	media_file_id: string | null;
	media_type: string | null;
	username: string | null;
	from_user: string;
	to_user: string;
	message_id: string;
	observer_classification: string;
	observer_confidence: number;
	observer_reason: string | null;
	risk_tier: string | null;
	tool_key: string | null;
	session_key: string | null;
};

// ═══════════════════════════════════════════════════════════════════════════════
// GENERIC TABLE HELPERS — shared consume/deny logic for approvals + plan_approvals
// ═══════════════════════════════════════════════════════════════════════════════

type RowBase = {
	nonce: string;
	chat_id: number;
	expires_at: number;
	request_id: string;
};

/**
 * Atomically consume a row from a table: SELECT → validate → DELETE.
 * Shared by consumeApproval and consumePlanApproval.
 */
function consumeFromTable<TRow extends RowBase, T>(
	table: string,
	label: string,
	nonce: string,
	chatId: number,
	mapper: (row: TRow) => T,
): Result<T> {
	const db = getDb();

	return db.transaction(() => {
		const row = db.prepare(`SELECT * FROM ${table} WHERE nonce = ?`).get(nonce) as TRow | undefined;

		if (!row) {
			return { success: false as const, error: `No pending ${label} found for that code.` };
		}

		if (row.chat_id !== chatId) {
			logger.warn(
				{ nonce, expectedChatId: row.chat_id, actualChatId: chatId },
				`${label} chat mismatch`,
			);
			return {
				success: false as const,
				error: "This approval code belongs to a different chat.",
			};
		}

		if (Date.now() > row.expires_at) {
			db.prepare(`DELETE FROM ${table} WHERE nonce = ?`).run(nonce);
			logger.warn({ nonce, chatId }, `${label} expired`);
			return {
				success: false as const,
				error: `This ${label} has expired. Please retry your request.`,
			};
		}

		const deleteResult = db.prepare(`DELETE FROM ${table} WHERE nonce = ?`).run(nonce);
		if (deleteResult.changes !== 1) {
			logger.error(
				{ nonce, chatId, changes: deleteResult.changes },
				`SECURITY: ${label} deletion anomaly - possible race condition`,
			);
			return {
				success: false as const,
				error: `${label} consumption failed - please try again`,
			};
		}

		logger.info({ nonce, requestId: row.request_id, chatId }, `${label} consumed`);

		return { success: true as const, data: mapper(row) };
	})();
}

/**
 * Atomically deny/cancel a row from a table: SELECT → validate chat → DELETE.
 * Shared by denyApproval and denyPlanApproval.
 */
function denyFromTable<TRow extends RowBase, T>(
	table: string,
	label: string,
	nonce: string,
	chatId: number,
	mapper: (row: TRow) => T,
): Result<T> {
	const db = getDb();

	return db.transaction(() => {
		const row = db.prepare(`SELECT * FROM ${table} WHERE nonce = ?`).get(nonce) as TRow | undefined;

		if (!row) {
			return { success: false as const, error: `No pending ${label} found for that code.` };
		}

		if (row.chat_id !== chatId) {
			return {
				success: false as const,
				error: "This approval code belongs to a different chat.",
			};
		}

		db.prepare(`DELETE FROM ${table} WHERE nonce = ?`).run(nonce);

		logger.info({ nonce, requestId: row.request_id, chatId }, `${label} denied`);

		return { success: true as const, data: mapper(row) };
	})();
}

// ═══════════════════════════════════════════════════════════════════════════════
// APPROVAL ROW MAPPING
// ═══════════════════════════════════════════════════════════════════════════════

function rowToApproval(row: ApprovalRow): PendingApproval {
	const rawRisk = row.risk_tier ?? undefined;
	const riskTier: RiskTier | undefined =
		rawRisk === "low" || rawRisk === "medium" || rawRisk === "high" ? rawRisk : undefined;
	return {
		nonce: row.nonce,
		requestId: row.request_id,
		chatId: row.chat_id,
		createdAt: row.created_at,
		expiresAt: row.expires_at,
		tier: row.tier as PermissionTier,
		body: row.body,
		mediaPath: row.media_path ?? undefined,
		mediaFilePath: row.media_file_path ?? undefined,
		mediaFileId: row.media_file_id ?? undefined,
		mediaType: row.media_type as MediaType | undefined,
		username: row.username ?? undefined,
		from: row.from_user,
		to: row.to_user,
		messageId: row.message_id,
		observerClassification: row.observer_classification as SecurityClassification,
		observerConfidence: row.observer_confidence,
		observerReason: row.observer_reason ?? undefined,
		riskTier,
		toolKey: row.tool_key ?? undefined,
		sessionKey: row.session_key ?? undefined,
	};
}

/**
 * Result of creating an approval, includes timing info for display.
 */
export type CreateApprovalResult = {
	nonce: string;
	createdAt: number;
	expiresAt: number;
};

/**
 * Create a new pending approval and return the nonce with timing info.
 *
 * SECURITY: Enforces a single pending approval per chat to prevent race conditions.
 * Any existing pending approvals for the chat are cancelled before creating the new one.
 *
 * Nonce is 16 hex characters (8 bytes of entropy) to prevent brute-force attacks.
 * With 8 bytes = 2^64 possibilities, and 5-minute TTL, brute-force is infeasible.
 */
export function createApproval(
	entry: Omit<PendingApproval, "nonce" | "createdAt" | "expiresAt">,
	ttlMs: number = DEFAULT_TTL_MS,
): CreateApprovalResult {
	const db = getDb();

	// Generate a random 16-character nonce (8 bytes = 64 bits of entropy)
	// This prevents brute-force attacks even with high request rates
	const nonce = crypto.randomBytes(8).toString("hex").toLowerCase();
	const now = Date.now();
	const expiresAt = now + ttlMs;

	// Use a transaction to atomically:
	// 1. Delete any existing pending approvals for this chat (prevent race conditions)
	// 2. Insert the new approval
	db.transaction(() => {
		// SECURITY: Cancel any existing pending approvals for this chat
		// This prevents race conditions where multiple approvals could be pending
		const deleted = db.prepare("DELETE FROM approvals WHERE chat_id = ?").run(entry.chatId);
		if (deleted.changes > 0) {
			logger.warn(
				{ chatId: entry.chatId, cancelledCount: deleted.changes },
				"cancelled existing pending approvals for new request",
			);
		}

		db.prepare(
			`INSERT INTO approvals (
				nonce, request_id, chat_id, created_at, expires_at, tier, body,
				media_path, media_type, media_file_path, media_file_id,
				username, from_user, to_user,
				message_id, observer_classification, observer_confidence, observer_reason,
				risk_tier, tool_key, session_key
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		).run(
			nonce,
			entry.requestId,
			entry.chatId,
			now,
			expiresAt,
			entry.tier,
			entry.body,
			entry.mediaPath ?? null,
			entry.mediaType ?? null,
			entry.mediaFilePath ?? null,
			entry.mediaFileId ?? null,
			entry.username ?? null,
			entry.from,
			entry.to,
			entry.messageId,
			entry.observerClassification,
			entry.observerConfidence,
			entry.observerReason ?? null,
			entry.riskTier ?? null,
			entry.toolKey ?? null,
			entry.sessionKey ?? null,
		);
	})();

	logger.info(
		{
			nonce,
			requestId: entry.requestId,
			chatId: entry.chatId,
			tier: entry.tier,
			expiresIn: Math.round(ttlMs / 1000),
		},
		"approval request created",
	);

	return { nonce, createdAt: now, expiresAt };
}

/**
 * Consume an approval if valid.
 * Returns the approval entry if valid, or an error if not found/expired/wrong chat.
 *
 * Uses a transaction for atomicity - prevents race conditions where two concurrent
 * requests could both consume the same approval.
 */
export function consumeApproval(nonce: string, chatId: number): Result<PendingApproval> {
	return consumeFromTable<ApprovalRow, PendingApproval>(
		"approvals",
		"approval",
		nonce,
		chatId,
		rowToApproval,
	);
}

/**
 * Deny/cancel an approval.
 */
export function denyApproval(nonce: string, chatId: number): Result<PendingApproval> {
	return denyFromTable<ApprovalRow, PendingApproval>(
		"approvals",
		"approval",
		nonce,
		chatId,
		rowToApproval,
	);
}

/**
 * Get all pending approvals for a chat.
 */
export function getPendingApprovalsForChat(chatId: number): PendingApproval[] {
	const db = getDb();
	const now = Date.now();

	const rows = db
		.prepare("SELECT * FROM approvals WHERE chat_id = ? AND expires_at > ?")
		.all(chatId, now) as ApprovalRow[];

	return rows.map(rowToApproval);
}

/**
 * Clean up expired approvals.
 */
export function cleanupExpiredApprovals(): number {
	const db = getDb();
	const now = Date.now();

	const result = db.prepare("DELETE FROM approvals WHERE expires_at < ?").run(now);

	if (result.changes > 0) {
		logger.debug({ cleaned: result.changes }, "cleaned up expired approvals");
	}

	return result.changes;
}

/**
 * Determine if a request requires approval based on tier and classification.
 *
 * @param tier - The user's permission tier
 * @param classification - The security observer's classification
 * @param confidence - The observer's confidence level
 * @param isAdmin - Whether the user is a claimed admin (bypasses FULL_ACCESS approval)
 */
export function requiresApproval(
	tier: PermissionTier,
	classification: SecurityClassification,
	confidence: number,
	isAdmin = false,
): boolean {
	// ADMIN: Claimed admins bypass approval even with FULL_ACCESS tier.
	// The admin claim flow establishes trust, so approvals are redundant for admins.
	// Note: Secret output filtering still applies - admins can't exfiltrate secrets.
	if (isAdmin) {
		return false;
	}

	// FULL_ACCESS always requires approval (for non-admin users)
	if (tier === "FULL_ACCESS") {
		return true;
	}

	// BLOCK always requires approval (user can override with /approve)
	if (classification === "BLOCK") {
		return true;
	}

	// WARN with WRITE_LOCAL requires approval
	if (classification === "WARN" && tier === "WRITE_LOCAL") {
		return true;
	}

	// Low confidence warnings should also require approval
	if (classification === "WARN" && confidence < 0.5) {
		return true;
	}

	return false;
}

// ═══════════════════════════════════════════════════════════════════════════════
// PLAN APPROVALS — Two-phase execution preview for FULL_ACCESS
// ═══════════════════════════════════════════════════════════════════════════════

const DEFAULT_PLAN_TTL_MS = 10 * 60 * 1000; // 10 minutes

/**
 * A pending plan approval (Phase 2 of two-phase execution).
 */
export type PlanApproval = {
	nonce: string;
	requestId: string;
	chatId: number;
	createdAt: number;
	expiresAt: number;
	tier: PermissionTier;
	originalBody: string;
	planText: string;
	sessionKey: string;
	sessionId: string;
	mediaPath?: string;
	mediaFileId?: string;
	mediaType?: MediaType;
	username?: string;
	from: string;
	to: string;
	messageId: string;
	observerClassification: SecurityClassification;
	observerConfidence: number;
	observerReason?: string;
};

/**
 * Database row type for plan_approvals.
 */
type PlanApprovalRow = {
	nonce: string;
	request_id: string;
	chat_id: number;
	created_at: number;
	expires_at: number;
	tier: string;
	original_body: string;
	plan_text: string;
	session_key: string;
	session_id: string;
	media_path: string | null;
	media_file_id: string | null;
	media_type: string | null;
	username: string | null;
	from_user: string;
	to_user: string;
	message_id: string;
	observer_classification: string;
	observer_confidence: number;
	observer_reason: string | null;
};

function rowToPlanApproval(row: PlanApprovalRow): PlanApproval {
	return {
		nonce: row.nonce,
		requestId: row.request_id,
		chatId: row.chat_id,
		createdAt: row.created_at,
		expiresAt: row.expires_at,
		tier: row.tier as PermissionTier,
		originalBody: row.original_body,
		planText: row.plan_text,
		sessionKey: row.session_key,
		sessionId: row.session_id,
		mediaPath: row.media_path ?? undefined,
		mediaFileId: row.media_file_id ?? undefined,
		mediaType: row.media_type as MediaType | undefined,
		username: row.username ?? undefined,
		from: row.from_user,
		to: row.to_user,
		messageId: row.message_id,
		observerClassification: row.observer_classification as SecurityClassification,
		observerConfidence: row.observer_confidence,
		observerReason: row.observer_reason ?? undefined,
	};
}

/**
 * Create a plan approval entry (Phase 1 complete, awaiting Phase 2 approval).
 *
 * SECURITY: Enforces single pending plan approval per chat.
 */
export function createPlanApproval(
	entry: Omit<PlanApproval, "nonce" | "createdAt" | "expiresAt">,
	ttlMs: number = DEFAULT_PLAN_TTL_MS,
): CreateApprovalResult {
	const db = getDb();

	const nonce = crypto.randomBytes(8).toString("hex").toLowerCase();
	const now = Date.now();
	const expiresAt = now + ttlMs;

	db.transaction(() => {
		// Cancel any existing plan approvals for this chat
		const deleted = db.prepare("DELETE FROM plan_approvals WHERE chat_id = ?").run(entry.chatId);
		if (deleted.changes > 0) {
			logger.warn(
				{ chatId: entry.chatId, cancelledCount: deleted.changes },
				"cancelled existing plan approvals for new request",
			);
		}

		db.prepare(
			`INSERT INTO plan_approvals (
				nonce, request_id, chat_id, created_at, expires_at, tier, original_body,
				plan_text, session_key, session_id,
				media_path, media_file_id, media_type,
				username, from_user, to_user,
				message_id, observer_classification, observer_confidence, observer_reason
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		).run(
			nonce,
			entry.requestId,
			entry.chatId,
			now,
			expiresAt,
			entry.tier,
			entry.originalBody,
			entry.planText,
			entry.sessionKey,
			entry.sessionId,
			entry.mediaPath ?? null,
			entry.mediaFileId ?? null,
			entry.mediaType ?? null,
			entry.username ?? null,
			entry.from,
			entry.to,
			entry.messageId,
			entry.observerClassification,
			entry.observerConfidence,
			entry.observerReason ?? null,
		);
	})();

	logger.info(
		{
			nonce,
			requestId: entry.requestId,
			chatId: entry.chatId,
			tier: entry.tier,
			expiresIn: Math.round(ttlMs / 1000),
		},
		"plan approval request created",
	);

	return { nonce, createdAt: now, expiresAt };
}

/**
 * Consume a plan approval if valid.
 * Atomic get-and-delete to prevent race conditions.
 */
export function consumePlanApproval(nonce: string, chatId: number): Result<PlanApproval> {
	return consumeFromTable<PlanApprovalRow, PlanApproval>(
		"plan_approvals",
		"plan approval",
		nonce,
		chatId,
		rowToPlanApproval,
	);
}

/**
 * Deny/cancel a plan approval.
 */
export function denyPlanApproval(nonce: string, chatId: number): Result<PlanApproval> {
	return denyFromTable<PlanApprovalRow, PlanApproval>(
		"plan_approvals",
		"plan approval",
		nonce,
		chatId,
		rowToPlanApproval,
	);
}

/**
 * Get the most recent pending plan approval for a chat.
 * Used for /deny without nonce.
 */
export function getMostRecentPendingPlanApproval(chatId: number): PlanApproval | null {
	const db = getDb();
	const now = Date.now();

	const row = db
		.prepare(
			"SELECT * FROM plan_approvals WHERE chat_id = ? AND expires_at > ? ORDER BY created_at DESC LIMIT 1",
		)
		.get(chatId, now) as PlanApprovalRow | undefined;

	if (!row) return null;
	return rowToPlanApproval(row);
}

/**
 * Format a plan approval request for display to the user.
 * Shows what Claude actually plans to do, not just the user's request.
 */
export function formatPlanApprovalRequest(planApproval: PlanApproval): string {
	const expiresIn = Math.max(0, Math.round((planApproval.expiresAt - Date.now()) / 1000));
	const minutes = Math.floor(expiresIn / 60);
	const seconds = expiresIn % 60;
	const timeStr = minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;

	// Truncate plan for Telegram's 4096 char limit (leave room for formatting)
	const maxPlanLength = 2000;
	const truncatedPlan =
		planApproval.planText.length > maxPlanLength
			? `${planApproval.planText.slice(0, maxPlanLength)}\n\n_(plan truncated)_`
			: planApproval.planText;

	const lines = [
		"*Execution plan preview* — here's what Claude plans to do:",
		"",
		truncatedPlan,
		"",
		`*Tier:* ${planApproval.tier}`,
		"",
		`To approve execution, reply: \`/approve ${planApproval.nonce}\``,
		`To deny, reply: \`/deny ${planApproval.nonce}\``,
		"",
		`_Expires in ${timeStr}_`,
	];

	return lines.join("\n");
}

/**
 * Get the most recent pending approval for a chat.
 * Used for /deny without nonce (denies most recent pending approval).
 */
export function getMostRecentPendingApproval(chatId: number): PendingApproval | null {
	const db = getDb();
	const now = Date.now();

	const row = db
		.prepare(
			"SELECT * FROM approvals WHERE chat_id = ? AND expires_at > ? ORDER BY created_at DESC LIMIT 1",
		)
		.get(chatId, now) as ApprovalRow | undefined;

	if (!row) {
		return null;
	}

	return rowToApproval(row);
}

/**
 * Format a pending approval for display to the user.
 *
 * IMPORTANT: This shows the USER'S REQUEST, not the actual commands Claude will execute.
 * Approvals happen before Claude processes the request, so we can't show tool inputs.
 * The user should understand they're approving based on the request, not specific commands.
 *
 * NOTE: Identity verification is handled by the TOTP auth gate before messages reach here.
 * Approvals are now nonce-only (intent confirmation, not identity verification).
 */
export function formatApprovalRequest(approval: PendingApproval): string {
	const expiresIn = Math.max(0, Math.round((approval.expiresAt - Date.now()) / 1000));
	const minutes = Math.floor(expiresIn / 60);
	const seconds = expiresIn % 60;
	const timeStr = minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;

	const lines = [
		"*Approval required* for this request:",
		"```",
		approval.body.length > 500 ? `${approval.body.slice(0, 500)}...` : approval.body,
		"```",
		"",
		"⚠️ _Note: This shows your request. Claude will decide the actual commands._",
		"",
		`*Tier:* ${approval.tier}`,
		`*Observer:* ${approval.observerClassification} (confidence ${approval.observerConfidence.toFixed(2)})`,
	];

	if (approval.observerReason) {
		lines.push(`*Reason:* ${approval.observerReason}`);
	}

	// Nonce-based approval (identity already verified by TOTP auth gate)
	lines.push(
		"",
		`To approve, reply: \`/approve ${approval.nonce}\``,
		`To deny, reply: \`/deny ${approval.nonce}\``,
	);

	lines.push("", `_Expires in ${timeStr}_`);

	return lines.join("\n");
}

// ═══════════════════════════════════════════════════════════════════════════════
// W1 — GRADUATED APPROVAL ALLOWLIST
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * A row in the per-user approval allowlist. Keyed on
 * (user_id, tool_key, scope) with INSERT OR REPLACE upsert semantics.
 *
 * - `once` rows are consumed (deleted) on first successful lookup.
 * - `session` rows are scoped to the session key they were granted in,
 *   and purged when the session rotates (`revokeSessionAllowlist`).
 * - `always` rows have a 30-day expiry floor; it is refreshed on each use
 *   so an actively-used grant never expires.
 */
export type AllowlistEntry = {
	id: number;
	userId: string;
	tier: PermissionTier;
	toolKey: string;
	scope: ApprovalScope;
	sessionKey: string | null;
	grantedAt: number;
	expiresAt: number | null;
	lastUsedAt: number | null;
	chatId: number;
};

type AllowlistRow = {
	id: number;
	user_id: string;
	tier: string;
	tool_key: string;
	scope: string;
	session_key: string | null;
	granted_at: number;
	expires_at: number | null;
	last_used_at: number | null;
	chat_id: number;
};

function rowToAllowlistEntry(row: AllowlistRow): AllowlistEntry {
	return {
		id: row.id,
		userId: row.user_id,
		tier: row.tier as PermissionTier,
		toolKey: row.tool_key,
		scope: row.scope as ApprovalScope,
		sessionKey: row.session_key,
		grantedAt: row.granted_at,
		expiresAt: row.expires_at,
		lastUsedAt: row.last_used_at,
		chatId: row.chat_id,
	};
}

export type GrantAllowlistInput = {
	userId: string;
	tier: PermissionTier;
	toolKey: string;
	scope: ApprovalScope;
	sessionKey: string | null;
	chatId: number;
	now?: number;
};

/**
 * Upsert an allowlist grant.
 *
 * Tier cap enforcement:
 * - SOCIAL / WRITE_LOCAL tiers cannot record a FULL_ACCESS "always" grant
 *   (the pipeline should catch this before calling).
 * - "always" for high-risk tool_keys is rejected at the caller; this function
 *   trusts its caller on risk tier but validates scope vs. tier.
 */
export function grantAllowlist(input: GrantAllowlistInput): AllowlistEntry {
	if (!isApprovalScope(input.scope)) {
		throw new Error(`grantAllowlist: invalid scope ${String(input.scope)}`);
	}
	if (!input.toolKey || input.toolKey.length > 128) {
		throw new Error("grantAllowlist: toolKey must be a non-empty string <=128 chars");
	}
	if (input.scope === "session" && !input.sessionKey) {
		throw new Error("grantAllowlist: session scope requires sessionKey");
	}

	const db = getDb();
	const now = input.now ?? Date.now();

	// "always" grants get a rolling 30-day expiry floor; "session" inherits
	// the session lifetime (no hard expiry); "once" is effectively 24h max to
	// cover the gap between grant and first use.
	const expiresAt =
		input.scope === "always"
			? now + ALLOWLIST_ALWAYS_EXPIRY_MS
			: input.scope === "once"
				? now + 24 * 60 * 60 * 1000
				: null;

	// Partial unique indexes collapse non-session scopes to one row per
	// (user, tool, scope) and session-scoped rows to one row per
	// (user, tool, session_key). Branch the upsert so concurrent sessions
	// don't overwrite each other's session grants (Wave 2 review fix).
	const upsertTx = db.transaction(() => {
		if (input.scope === "session") {
			db.prepare(
				`DELETE FROM approval_allowlist
				 WHERE user_id = ? AND tool_key = ? AND scope = 'session' AND session_key = ?`,
			).run(input.userId, input.toolKey, input.sessionKey ?? "");
		} else {
			db.prepare(
				`DELETE FROM approval_allowlist
				 WHERE user_id = ? AND tool_key = ? AND scope = ?`,
			).run(input.userId, input.toolKey, input.scope);
		}
		db.prepare(
			`INSERT INTO approval_allowlist (
				user_id, tier, tool_key, scope, session_key, chat_id,
				granted_at, expires_at, last_used_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		).run(
			input.userId,
			input.tier,
			input.toolKey,
			input.scope,
			input.sessionKey ?? null,
			input.chatId,
			now,
			expiresAt,
		);
	});
	upsertTx();

	const row =
		input.scope === "session"
			? (db
					.prepare(
						"SELECT * FROM approval_allowlist WHERE user_id = ? AND tool_key = ? AND scope = 'session' AND session_key = ?",
					)
					.get(input.userId, input.toolKey, input.sessionKey ?? "") as AllowlistRow | undefined)
			: (db
					.prepare(
						"SELECT * FROM approval_allowlist WHERE user_id = ? AND tool_key = ? AND scope = ?",
					)
					.get(input.userId, input.toolKey, input.scope) as AllowlistRow | undefined);

	if (!row) {
		throw new Error("grantAllowlist: insert reported success but row not found");
	}

	logger.info(
		{
			userId: input.userId,
			toolKey: input.toolKey,
			scope: input.scope,
			tier: input.tier,
			sessionKey: input.sessionKey,
			expiresAt,
		},
		"approval allowlist granted",
	);

	return rowToAllowlistEntry(row);
}

export type LookupAllowlistInput = {
	userId: string;
	toolKey: string;
	tier: PermissionTier;
	sessionKey: string | null;
	now?: number;
};

/**
 * Look up an allowlist entry that applies to this (user, tool, tier, session)
 * pair. Returns the strongest applicable scope ("always" > "session" > "once")
 * so the caller can surface audit-friendly information even when multiple
 * grants exist.
 *
 * Side effects:
 * - "once" entries are consumed (deleted) and never survive a lookup.
 * - "session" and "always" entries have `last_used_at` refreshed; "always"
 *   entries also get their expiry pushed forward.
 *
 * Tier cap: the grant tier must be >= the caller's current tier. A grant made
 * at WRITE_LOCAL cannot authorize a FULL_ACCESS call. Ordering:
 * READ_ONLY < WRITE_LOCAL = SOCIAL < FULL_ACCESS.
 */
export function lookupAllowlist(input: LookupAllowlistInput): AllowlistEntry | null {
	const db = getDb();
	const now = input.now ?? Date.now();

	// Fetch all rows for the user+tool, then pick the strongest one whose
	// scope/session/tier constraints still satisfy the caller.
	const rows = db
		.prepare("SELECT * FROM approval_allowlist WHERE user_id = ? AND tool_key = ?")
		.all(input.userId, input.toolKey) as AllowlistRow[];

	if (rows.length === 0) {
		return null;
	}

	// Scope priority: always > session > once. Skip entries that fail tier,
	// session, or expiry checks.
	const priority: Record<ApprovalScope, number> = { always: 3, session: 2, once: 1 };
	const candidates = rows
		.map(rowToAllowlistEntry)
		.filter((entry) => {
			if (!isApprovalScope(entry.scope)) return false;
			if (!tierCovers(entry.tier, input.tier)) return false;
			if (entry.expiresAt !== null && entry.expiresAt < now) return false;
			if (entry.scope === "session") {
				if (!entry.sessionKey || !input.sessionKey) return false;
				return entry.sessionKey === input.sessionKey;
			}
			return true;
		})
		.sort((a, b) => priority[b.scope] - priority[a.scope]);

	if (candidates.length === 0) {
		return null;
	}

	const chosen = candidates[0];

	// Side effect: consume / refresh.
	if (chosen.scope === "once") {
		db.prepare("DELETE FROM approval_allowlist WHERE id = ?").run(chosen.id);
		logger.info(
			{ userId: chosen.userId, toolKey: chosen.toolKey },
			"approval allowlist: once consumed",
		);
	} else if (chosen.scope === "always") {
		const newExpiry = now + ALLOWLIST_ALWAYS_EXPIRY_MS;
		db.prepare("UPDATE approval_allowlist SET last_used_at = ?, expires_at = ? WHERE id = ?").run(
			now,
			newExpiry,
			chosen.id,
		);
		chosen.lastUsedAt = now;
		chosen.expiresAt = newExpiry;
	} else {
		db.prepare("UPDATE approval_allowlist SET last_used_at = ? WHERE id = ?").run(now, chosen.id);
		chosen.lastUsedAt = now;
	}

	return chosen;
}

/**
 * Ordering: READ_ONLY < WRITE_LOCAL = SOCIAL < FULL_ACCESS.
 * Returns true when `grantTier` is at least as permissive as `requestedTier`.
 */
function tierCovers(grantTier: PermissionTier, requestedTier: PermissionTier): boolean {
	const rank: Record<PermissionTier, number> = {
		READ_ONLY: 1,
		WRITE_LOCAL: 2,
		SOCIAL: 2,
		FULL_ACCESS: 3,
	};
	return rank[grantTier] >= rank[requestedTier];
}

/**
 * List all allowlist entries for a user. Used by the CLI and the operator
 * status surface.
 */
export function listAllowlist(options: { userId?: string } = {}): AllowlistEntry[] {
	const db = getDb();
	const rows = options.userId
		? (db
				.prepare("SELECT * FROM approval_allowlist WHERE user_id = ? ORDER BY granted_at DESC")
				.all(options.userId) as AllowlistRow[])
		: (db
				.prepare("SELECT * FROM approval_allowlist ORDER BY granted_at DESC")
				.all() as AllowlistRow[]);
	return rows.map(rowToAllowlistEntry);
}

/**
 * Revoke a single entry by id. Returns true when a row was deleted.
 */
export function revokeAllowlistEntry(id: number): boolean {
	const db = getDb();
	const result = db.prepare("DELETE FROM approval_allowlist WHERE id = ?").run(id);
	if (result.changes > 0) {
		logger.info({ id }, "approval allowlist entry revoked");
	}
	return result.changes > 0;
}

/**
 * Drop every "session" scope grant belonging to a session key — used when a
 * session rotates via `/new` or `/reset`.
 */
export function revokeSessionAllowlist(sessionKey: string): number {
	const db = getDb();
	const result = db
		.prepare("DELETE FROM approval_allowlist WHERE scope = 'session' AND session_key = ?")
		.run(sessionKey);
	if (result.changes > 0) {
		logger.info({ sessionKey, count: result.changes }, "session-scoped allowlist cleared");
	}
	return result.changes;
}

/**
 * Cleanup for the allowlist:
 * - Delete expired rows.
 * - Drop orphan "session" rows whose session_key is unknown to the session
 *   store — we don't cross-query here to stay a pure storage operation; the
 *   caller (cleanupExpired in db.ts) relies on TTL instead.
 */
export function cleanupExpiredAllowlist(now: number = Date.now()): number {
	const db = getDb();
	const result = db
		.prepare("DELETE FROM approval_allowlist WHERE expires_at IS NOT NULL AND expires_at < ?")
		.run(now);
	if (result.changes > 0) {
		logger.debug({ cleaned: result.changes }, "expired allowlist entries cleaned");
	}
	return result.changes;
}
