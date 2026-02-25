/**
 * Approval token generation for provider action requests.
 *
 * Generates Ed25519-signed tokens (v1.<claims_b64url>.<sig_b64url>)
 * that the relay passes to sidecars for action-type requests.
 *
 * The agent never sees or handles approval tokens — the relay
 * generates them after user approval and injects them into the
 * proxied request.
 */

import crypto from "node:crypto";
import type { VaultClient } from "../vault-daemon/client.js";

const SIGNING_PREFIX = "approval-v1";
const TOKEN_TTL_SECONDS = 60; // 1 minute — short-lived by design

export interface ApprovalTokenInput {
	/** Actor user ID (e.g., "telegram:123") */
	actorUserId: string;
	/** Service ID (e.g., "gmail") */
	service: string;
	/** Action ID (e.g., "create_draft") */
	action: string;
	/** Request parameters */
	params: Record<string, unknown>;
	/** Subject user ID (null for self-targeted actions) */
	subjectUserId: string | null;
	/** Approval nonce from the approval DB entry */
	approvalNonce: string;
}

/**
 * Generate a signed approval token for an action request.
 *
 * Steps:
 * 1. Build claims with canonical params hash
 * 2. Encode claims as base64url
 * 3. Sign via vault's Ed25519 key (domain-separated)
 * 4. Return v1.<claims>.<sig> token
 */
export async function generateApprovalToken(
	input: ApprovalTokenInput,
	vaultClient: VaultClient,
): Promise<string> {
	const now = Math.floor(Date.now() / 1000);

	const claims = {
		ver: 1,
		iss: "telclaude-vault",
		aud: "google-services",
		iat: now,
		exp: now + TOKEN_TTL_SECONDS,
		jti: `jti-${crypto.randomUUID()}`,
		approvalNonce: input.approvalNonce,
		actorUserId: input.actorUserId,
		providerId: "google",
		service: input.service,
		action: input.action,
		subjectUserId: input.subjectUserId,
		paramsHash: canonicalHash({
			service: input.service,
			action: input.action,
			params: input.params,
			actorUserId: input.actorUserId,
			subjectUserId: input.subjectUserId,
		}),
	};

	const claimsB64 = Buffer.from(JSON.stringify(claims)).toString("base64url");

	// Sign via vault (domain-separated: "approval-v1\n<payload>")
	const signResult = await vaultClient.signPayload(claimsB64, SIGNING_PREFIX);
	if (signResult.type !== "sign-payload" || !signResult.signature) {
		throw new Error("Vault signing failed");
	}

	return `v1.${claimsB64}.${signResult.signature}`;
}

/**
 * Compute canonical hash for request binding.
 * Matches the sidecar's canonicalHash implementation.
 */
function canonicalHash(input: {
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

function sortKeysDeep(value: unknown): unknown {
	if (value === null || typeof value !== "object") return value;
	if (Array.isArray(value)) return value.map(sortKeysDeep);
	const sorted: Record<string, unknown> = {};
	for (const key of Object.keys(value as Record<string, unknown>).sort()) {
		sorted[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
	}
	return sorted;
}
