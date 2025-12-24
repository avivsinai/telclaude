/**
 * Security module exports.
 *
 * SECURITY ARCHITECTURE:
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

// Admin claim flow for single-user deployments
export {
	cleanupExpiredAdminClaims,
	completeAdminClaim,
	consumeAdminClaim,
	ensureAdminClaimTable,
	formatAdminClaimPrompt,
	formatAdminClaimSuccess,
	formatGroupRejection,
	getPendingAdminClaim,
	handleAdminClaimApproval,
	handleFirstMessageIfNoAdmin,
	hasAdmin,
	isAdminChat,
	type PendingAdminClaim,
	startAdminClaim,
} from "./admin-claim.js";
export * from "./approvals.js";
export * from "./audit.js";
export * from "./fast-path.js";
export * from "./linking.js";
// Output filter for exfiltration prevention
export {
	ChunkBuffer,
	CORE_SECRET_PATTERNS,
	type FilterMatch,
	type FilterResult,
	filterInfrastructureSecrets,
	filterOutput,
	redactSecrets,
	SECRET_PATTERNS,
	type SecretPattern,
} from "./output-filter.js";
export * from "./permissions.js";
// Security pipeline abstraction
export {
	buildSecurityPipeline,
	calculateEntropy,
	detectHighEntropyBlobs,
	type ExecutionResult,
	type MessageContext,
	type PipelineConfig,
	type RedactionEvent,
	type RedactionResult,
	type SecretFilterConfig,
	type SecurityDecision,
	type SecurityPipeline,
	type SecurityProfile,
} from "./pipeline.js";
export * from "./rate-limit.js";
// Streaming redactor for chunk boundary handling
export {
	createStreamingRedactor,
	getLongestPatternLength,
	getPatternNames,
	processChunks,
	type RedactionStats,
	redactStream,
	StreamingRedactor,
} from "./streaming-redactor.js";
export * from "./totp-session.js";
// Re-export other security modules as they exist
export * from "./types.js";
