import crypto from "node:crypto";
import type { PermissionTier } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import type { TelegramMediaType } from "../telegram/types.js";
import type { Result, SecurityClassification } from "./types.js";

const logger = getChildLogger({ module: "approvals" });

const DEFAULT_TTL_MS = 5 * 60 * 1000; // 5 minutes

/**
 * A pending approval request.
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
	mediaUrl?: string;
	mediaType?: TelegramMediaType;
	username?: string;
	from: string;
	to: string;
	messageId: string;
	observerClassification: SecurityClassification;
	observerConfidence: number;
	observerReason?: string;
};

/**
 * In-memory store for pending approvals.
 * For production, consider persisting to disk/redis for restart resilience.
 */
const pendingApprovals = new Map<string, PendingApproval>();

/**
 * Create a new pending approval and return the nonce.
 */
export function createApproval(
	entry: Omit<PendingApproval, "nonce" | "createdAt" | "expiresAt">,
	ttlMs: number = DEFAULT_TTL_MS,
): string {
	// Generate a random 8-character nonce
	const nonce = crypto.randomBytes(4).toString("hex").toLowerCase();
	const now = Date.now();

	const approval: PendingApproval = {
		...entry,
		nonce,
		createdAt: now,
		expiresAt: now + ttlMs,
	};

	pendingApprovals.set(nonce, approval);

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

	return nonce;
}

/**
 * Consume an approval if valid.
 * Returns the approval entry if valid, or an error if not found/expired/wrong chat.
 *
 * NOTE: Atomically removes entry before validation to prevent race conditions
 * where two concurrent requests could both consume the same approval.
 */
export function consumeApproval(nonce: string, chatId: number): Result<PendingApproval> {
	// Atomically get and delete to prevent race conditions
	const entry = pendingApprovals.get(nonce);
	if (!entry) {
		logger.warn({ nonce, chatId }, "approval not found");
		return { success: false, error: "No pending approval found for that code." };
	}

	// Delete immediately to prevent concurrent consumption
	pendingApprovals.delete(nonce);

	// Verify chat ID matches (entry already removed, so no race)
	if (entry.chatId !== chatId) {
		// Re-add the entry since this wasn't a valid consumption attempt
		pendingApprovals.set(nonce, entry);
		logger.warn(
			{ nonce, expectedChatId: entry.chatId, actualChatId: chatId },
			"approval chat mismatch",
		);
		return { success: false, error: "This approval code belongs to a different chat." };
	}

	// Check expiry (entry already removed, so no race)
	if (Date.now() > entry.expiresAt) {
		// Don't re-add expired entries
		logger.warn({ nonce, chatId }, "approval expired");
		return { success: false, error: "This approval has expired. Please retry your request." };
	}

	logger.info({ nonce, requestId: entry.requestId, chatId }, "approval consumed");

	return { success: true, data: entry };
}

/**
 * Deny/cancel an approval.
 */
export function denyApproval(nonce: string, chatId: number): Result<PendingApproval> {
	const entry = pendingApprovals.get(nonce);

	if (!entry) {
		return { success: false, error: "No pending approval found for that code." };
	}

	if (entry.chatId !== chatId) {
		return { success: false, error: "This approval code belongs to a different chat." };
	}

	pendingApprovals.delete(nonce);

	logger.info({ nonce, requestId: entry.requestId, chatId }, "approval denied");

	return { success: true, data: entry };
}

/**
 * Get all pending approvals for a chat.
 */
export function getPendingApprovalsForChat(chatId: number): PendingApproval[] {
	const now = Date.now();
	const results: PendingApproval[] = [];

	for (const entry of pendingApprovals.values()) {
		if (entry.chatId === chatId && entry.expiresAt > now) {
			results.push(entry);
		}
	}

	return results;
}

/**
 * Clean up expired approvals.
 */
export function cleanupExpiredApprovals(): number {
	const now = Date.now();
	let cleaned = 0;

	for (const [nonce, entry] of pendingApprovals.entries()) {
		if (entry.expiresAt < now) {
			pendingApprovals.delete(nonce);
			cleaned++;
		}
	}

	if (cleaned > 0) {
		logger.debug({ cleaned }, "cleaned up expired approvals");
	}

	return cleaned;
}

/**
 * Get the count of pending approvals.
 */
export function getPendingApprovalCount(): number {
	return pendingApprovals.size;
}

/**
 * Determine if a request requires approval based on tier and classification.
 */
export function requiresApproval(
	tier: PermissionTier,
	classification: SecurityClassification,
	confidence: number,
): boolean {
	// FULL_ACCESS always requires approval
	if (tier === "FULL_ACCESS") {
		return true;
	}

	// BLOCK always requires approval (user can override with /approve)
	if (classification === "BLOCK") {
		return true;
	}

	// WARN with WRITE_SAFE requires approval
	if (classification === "WARN" && tier === "WRITE_SAFE") {
		return true;
	}

	// Low confidence warnings should also require approval
	if (classification === "WARN" && confidence < 0.5) {
		return true;
	}

	return false;
}

/**
 * Format a pending approval for display to the user.
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
		`*Tier:* ${approval.tier}`,
		`*Observer:* ${approval.observerClassification} (confidence ${approval.observerConfidence.toFixed(2)})`,
	];

	if (approval.observerReason) {
		lines.push(`*Reason:* ${approval.observerReason}`);
	}

	lines.push(
		"",
		`To approve, reply: \`/approve ${approval.nonce}\``,
		`To deny, reply: \`/deny ${approval.nonce}\``,
		"",
		`_Expires in ${timeStr}_`,
	);

	return lines.join("\n");
}
