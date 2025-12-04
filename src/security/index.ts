/**
 * Security module exports.
 *
 * V2 SECURITY ARCHITECTURE:
 * This module provides defense-in-depth security with two profiles:
 * - simple (default): Hard enforcement only (sandbox, secret filter, rate limits)
 * - strict (opt-in): Adds soft policy layers (observer, approvals)
 *
 * Layers:
 * - Input filtering (observer, fast-path)
 * - Output filtering (secret exfiltration prevention)
 * - Permission tiers (tool restrictions)
 * - Rate limiting
 * - Audit logging
 * - Streaming redaction
 */

// V2: Security pipeline abstraction
export {
	buildSecurityPipeline,
	type SecurityPipeline,
	type SecurityProfile,
	type MessageContext,
	type SecurityDecision,
	type ExecutionResult,
	type RedactionResult,
	type RedactionEvent,
	type SecretFilterConfig,
	type PipelineConfig,
	calculateEntropy,
	detectHighEntropyBlobs,
} from "./pipeline.js";

// V2: Streaming redactor for chunk boundary handling
export {
	StreamingRedactor,
	createStreamingRedactor,
	processChunks,
	redactStream,
	getLongestPatternLength,
	getPatternNames,
	type RedactionStats,
} from "./streaming-redactor.js";

// Output filter for exfiltration prevention
export {
	filterOutput,
	filterInfrastructureSecrets,
	ChunkBuffer,
	SECRET_PATTERNS,
	CORE_SECRET_PATTERNS,
	redactSecrets,
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

// V2: Admin claim flow for single-user deployments
export {
	hasAdmin,
	isAdminChat,
	startAdminClaim,
	consumeAdminClaim,
	completeAdminClaim,
	getPendingAdminClaim,
	cleanupExpiredAdminClaims,
	handleFirstMessageIfNoAdmin,
	handleAdminClaimApproval,
	formatAdminClaimPrompt,
	formatAdminClaimSuccess,
	formatGroupRejection,
	ensureAdminClaimTable,
	type PendingAdminClaim,
} from "./admin-claim.js";
