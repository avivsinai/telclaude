/**
 * Security module exports.
 *
 * This module provides defense-in-depth security:
 * - Input filtering (observer, fast-path)
 * - Output filtering (secret exfiltration prevention)
 * - Permission tiers (tool restrictions)
 * - Rate limiting
 * - Audit logging
 */

// Output filter for exfiltration prevention
export {
	filterOutput,
	filterInfrastructureSecrets,
	ChunkBuffer,
	SECRET_PATTERNS,
	type FilterResult,
	type FilterMatch,
	type SecretPattern,
} from "./output-filter.js";

// Re-export other security modules as they exist
export * from "./types.js";
export * from "./fast-path.js";
export * from "./permissions.js";
export * from "./rate-limit.js";
export * from "./audit.js";
export * from "./linking.js";
export * from "./approvals.js";
export * from "./totp-session.js";
