/**
 * Canonical hash for approval token request binding.
 *
 * Deterministic JSON serialization (recursive key sort) + SHA-256.
 * Used by both the relay (token generation) and the Google services
 * sidecar (token verification) to produce matching params hashes.
 */

import crypto from "node:crypto";

export interface CanonicalHashInput {
	service: string;
	action: string;
	params: Record<string, unknown>;
	actorUserId: string;
	subjectUserId: string | null;
}

/**
 * Compute canonical hash for request binding.
 * Deterministic JSON serialization (recursive key sort) + SHA-256.
 */
export function canonicalHash(input: CanonicalHashInput): string {
	const canonical = JSON.stringify(sortKeysDeep(input));
	const hash = crypto.createHash("sha256").update(canonical).digest("hex");
	return `sha256:${hash}`;
}

/**
 * Recursively sort object keys for deterministic serialization.
 */
export function sortKeysDeep(value: unknown): unknown {
	if (value === null || typeof value !== "object") return value;
	if (Array.isArray(value)) return value.map(sortKeysDeep);
	const sorted: Record<string, unknown> = {};
	for (const key of Object.keys(value as Record<string, unknown>).sort()) {
		sorted[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
	}
	return sorted;
}
