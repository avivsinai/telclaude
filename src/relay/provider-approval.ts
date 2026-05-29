/**
 * Provider approval manager — bridges the Telegram /approve flow
 * with provider sidecar action-type requests.
 *
 * Flow:
 * 1. Provider proxy detects approval_required from sidecar
 * 2. Creates a pending approval with serialized request
 * 3. Agent tells user in Telegram (includes nonce)
 * 4. User sends /approve <nonce>
 * 5. This module generates the approval token and replays the request
 * 6. Result returned to Telegram
 */

import crypto from "node:crypto";
import type { VaultClient } from "../vault-daemon/client.js";
import { generateApprovalToken } from "./approval-token.js";
import {
	type ProviderProxyRequest,
	type ProviderProxyResponse,
	proxyProviderRequest,
} from "./provider-proxy.js";

const APPROVAL_TTL_MS = 5 * 60 * 1000; // 5 minutes

interface PendingProviderApproval {
	nonce: string;
	request: ProviderProxyRequest;
	/** Parsed body for token generation */
	parsedBody: { service: string; action: string; params: Record<string, unknown> };
	actorUserId: string;
	createdAt: number;
}

/** In-memory store for pending provider approvals (TTL-enforced) */
const pendingApprovals = new Map<string, PendingProviderApproval>();

/**
 * Create a pending provider approval.
 * Returns nonce for user confirmation.
 */
export function createProviderApproval(
	request: ProviderProxyRequest,
	parsedBody: { service: string; action: string; params: Record<string, unknown> },
	actorUserId: string,
): string {
	// Clean up expired entries
	const now = Date.now();
	for (const [key, entry] of pendingApprovals) {
		if (now - entry.createdAt > APPROVAL_TTL_MS) {
			pendingApprovals.delete(key);
		}
	}

	const nonce = crypto.randomBytes(8).toString("hex");
	pendingApprovals.set(nonce, {
		nonce,
		request,
		parsedBody,
		actorUserId,
		createdAt: now,
	});
	return nonce;
}

/**
 * Consume a pending provider approval: generate token and replay request.
 * Returns null if nonce is invalid/expired, or if the consuming actor is not
 * the actor that triggered the action_required (actor-binding check).
 *
 * `consumingActorUserId` must be derived the same way as the actor stored at
 * creation time (the relay's resolved actor id, i.e.
 * `getIdentityLink(chatId)?.localUserId ?? String(chatId)`), so that a
 * different chat member who learns the nonce cannot approve another actor's
 * queued privileged action.
 */
export async function consumeProviderApproval(
	nonce: string,
	consumingActorUserId: string,
	vaultClient: VaultClient,
): Promise<ProviderProxyResponse | null> {
	const entry = pendingApprovals.get(nonce);
	if (!entry) return null;

	// Check expiry
	if (Date.now() - entry.createdAt > APPROVAL_TTL_MS) {
		pendingApprovals.delete(nonce);
		return null;
	}

	// Actor binding: only the actor that triggered the action_required may
	// approve it. Reject without consuming so the legitimate actor can retry.
	if (consumingActorUserId !== entry.actorUserId) {
		return null;
	}

	// Consume (one-time use)
	pendingApprovals.delete(nonce);

	// Generate approval token
	const token = await generateApprovalToken(
		{
			actorUserId: entry.actorUserId,
			service: entry.parsedBody.service,
			action: entry.parsedBody.action,
			params: entry.parsedBody.params,
			// v1 flow is self-targeted only; delegated subject users are not threaded yet.
			subjectUserId: null,
			approvalNonce: nonce,
		},
		vaultClient,
	);

	// Replay the original request with the approval token
	return proxyProviderRequest({
		...entry.request,
		approvalToken: token,
	});
}

/**
 * Check if a nonce belongs to a pending provider approval.
 */
export function isProviderApproval(nonce: string): boolean {
	const entry = pendingApprovals.get(nonce);
	if (!entry) return false;
	if (Date.now() - entry.createdAt > APPROVAL_TTL_MS) {
		pendingApprovals.delete(nonce);
		return false;
	}
	return true;
}

/**
 * Get human-readable description of a pending approval for Telegram display.
 */
export function describeProviderApproval(nonce: string): string | null {
	const entry = pendingApprovals.get(nonce);
	if (!entry) return null;
	return `${entry.parsedBody.service}.${entry.parsedBody.action}`;
}
