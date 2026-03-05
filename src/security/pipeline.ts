/**
 * Security Pipeline
 *
 * Two profiles:
 * - simple (default): Hard enforcement only, no approvals, no observer
 * - strict (opt-in): Hard enforcement + soft policy layers
 *
 * Hard enforcement (always on):
 * - Sandbox (FS + Env + Network)
 * - Secret output filter
 * - Auth + TOTP
 * - Rate limiting
 * - Audit logging
 *
 * Soft policy (strict profile only):
 * - Observer (Haiku)
 * - Permission tiers
 * - Approval workflows
 * - Fast-path regex
 */

import type { PermissionTier, SecurityConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import type { AuditLogger } from "./audit.js";
import { checkInfrastructureSecrets } from "./fast-path.js";
import { isAdmin } from "./linking.js";
import {
	calculateEntropy,
	detectHighEntropyBlobs,
	filterOutputWithConfig,
	redactSecretsWithConfig,
	type SecretFilterConfig,
} from "./output-filter.js";
import { getUserPermissionTier } from "./permissions.js";
import type { RateLimiter } from "./rate-limit.js";
import type { ObserverResult, SecurityClassification } from "./types.js";

const logger = getChildLogger({ module: "security-pipeline" });

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

export type SecurityProfile = "simple" | "strict" | "test";

export interface MessageContext {
	chatId: number;
	userId: string;
	username?: string;
	body: string;
	mediaPath?: string;
	requestId: string;
	chatType?: "private" | "group" | "supergroup" | "channel";
}

export interface SecurityDecision {
	action: "allow" | "block" | "approval_required";
	tier: PermissionTier;
	classification?: SecurityClassification;
	confidence?: number;
	reason?: string;
	infraBlocked?: boolean;
	rateLimited?: boolean;
	approvalNonce?: string;
}

export interface ExecutionResult {
	success: boolean;
	response?: string;
	durationMs?: number;
	costUsd?: number;
	error?: string;
}

export interface RedactionResult {
	redacted: string;
	redactions: RedactionEvent[];
}

export interface RedactionEvent {
	patternId: string;
	count: number;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Security Pipeline Interface
// ═══════════════════════════════════════════════════════════════════════════════

export interface SecurityPipeline {
	profile: SecurityProfile;
	beforeExecution(ctx: MessageContext): Promise<SecurityDecision>;
	afterExecution(ctx: MessageContext, result: ExecutionResult): Promise<void>;
	redactOutput(text: string): RedactionResult;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Shared Checks
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Run the three common hard-enforcement checks shared by all non-test pipelines:
 * 1. Infrastructure secret block (NON-OVERRIDABLE)
 * 2. Permission tier lookup
 * 3. Rate limit check
 *
 * Returns a blocking SecurityDecision if any check fails, or `{ tier }` on success.
 */
async function runCommonChecks(
	ctx: MessageContext,
	securityConfig: SecurityConfig | undefined,
	rateLimiter: RateLimiter,
): Promise<{ blocked: SecurityDecision } | { tier: PermissionTier }> {
	// 1. Infrastructure secret check (NON-OVERRIDABLE)
	const infraCheck = checkInfrastructureSecrets(ctx.body);
	if (infraCheck.blocked) {
		logger.error(
			{ chatId: ctx.chatId, patterns: infraCheck.patterns },
			"BLOCKED: Infrastructure secrets - NON-OVERRIDABLE",
		);
		return {
			blocked: {
				action: "block",
				tier: "READ_ONLY",
				reason: "Infrastructure secrets detected (bot tokens, API keys, private keys)",
				infraBlocked: true,
			},
		};
	}

	// 2. Get permission tier
	const tier = getUserPermissionTier(ctx.chatId, securityConfig);

	// 3. Rate limit check
	const rateLimitResult = await rateLimiter.checkLimit(ctx.userId, tier);
	if (!rateLimitResult.allowed) {
		logger.info({ userId: ctx.userId, tier }, "rate limited");
		return {
			blocked: {
				action: "block",
				tier,
				reason: `Rate limit exceeded. Wait ${Math.ceil(rateLimitResult.resetMs / 1000)}s.`,
				rateLimited: true,
			},
		};
	}

	return { tier };
}

/**
 * Redact secrets from text using config, returning structured redaction results.
 * Delegates to output-filter's filterOutputWithConfig (for detection) and
 * redactSecretsWithConfig (for replacement).
 */
function redactWithConfig(text: string, config?: SecretFilterConfig): RedactionResult {
	const filterResult = filterOutputWithConfig(text, config);
	const redactions: RedactionEvent[] = filterResult.matches.map((m) => ({
		patternId: m.pattern,
		count: 1,
	}));
	const redacted = filterResult.blocked ? redactSecretsWithConfig(text, config) : text;
	return { redacted, redactions };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Simple Profile Pipeline
// ═══════════════════════════════════════════════════════════════════════════════

class SimplePipeline implements SecurityPipeline {
	profile: SecurityProfile = "simple";

	constructor(
		private securityConfig: SecurityConfig | undefined,
		private rateLimiter: RateLimiter,
		_auditLogger: AuditLogger, // Accepted for interface consistency; audit logging handled externally
		private secretFilterConfig?: SecretFilterConfig,
	) {}

	async beforeExecution(ctx: MessageContext): Promise<SecurityDecision> {
		const result = await runCommonChecks(ctx, this.securityConfig, this.rateLimiter);
		if ("blocked" in result) return result.blocked;

		// Simple profile: allow everything that passes hard checks
		return {
			action: "allow",
			tier: result.tier,
			classification: "ALLOW",
			confidence: 1.0,
		};
	}

	async afterExecution(_ctx: MessageContext, _result: ExecutionResult): Promise<void> {
		// Audit logging handled externally
	}

	redactOutput(text: string): RedactionResult {
		return redactWithConfig(text, this.secretFilterConfig);
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Strict Profile Pipeline
// ═══════════════════════════════════════════════════════════════════════════════

class StrictPipeline implements SecurityPipeline {
	profile: SecurityProfile = "strict";

	constructor(
		private securityConfig: SecurityConfig | undefined,
		private rateLimiter: RateLimiter,
		private auditLogger: AuditLogger, // Used for flagged-history lookups
		private observer: {
			analyze: (
				message: string,
				context: { permissionTier: PermissionTier; hasFlaggedHistory?: boolean },
			) => Promise<ObserverResult>;
		},
		private requiresApprovalFn: (
			tier: PermissionTier,
			classification: SecurityClassification,
			confidence: number,
			isAdmin: boolean,
		) => boolean,
		private secretFilterConfig?: SecretFilterConfig,
	) {}

	async beforeExecution(ctx: MessageContext): Promise<SecurityDecision> {
		const result = await runCommonChecks(ctx, this.securityConfig, this.rateLimiter);
		if ("blocked" in result) return result.blocked;
		const { tier } = result;

		// 4. Security observer analysis
		let hasFlaggedHistory = false;
		try {
			hasFlaggedHistory = await this.auditLogger.hasFlaggedHistory(ctx.userId);
		} catch (err) {
			logger.warn({ error: String(err), userId: ctx.userId }, "failed to load flagged history");
		}
		const observerResult = await this.observer.analyze(ctx.body, {
			permissionTier: tier,
			hasFlaggedHistory,
		});

		// 5. Check if approval is required
		const admin = isAdmin(ctx.chatId);
		if (
			this.requiresApprovalFn(tier, observerResult.classification, observerResult.confidence, admin)
		) {
			return {
				action: "approval_required",
				tier,
				classification: observerResult.classification,
				confidence: observerResult.confidence,
				reason: observerResult.reason,
			};
		}

		return {
			action: "allow",
			tier,
			classification: observerResult.classification,
			confidence: observerResult.confidence,
			reason: observerResult.reason,
		};
	}

	async afterExecution(_ctx: MessageContext, _result: ExecutionResult): Promise<void> {
		// Audit logging handled externally
	}

	redactOutput(text: string): RedactionResult {
		return redactWithConfig(text, this.secretFilterConfig);
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test Pipeline (No-Op)
// ═══════════════════════════════════════════════════════════════════════════════

class TestPipeline implements SecurityPipeline {
	profile: SecurityProfile = "test";

	async beforeExecution(_ctx: MessageContext): Promise<SecurityDecision> {
		return {
			action: "allow",
			tier: "FULL_ACCESS",
			classification: "ALLOW",
			confidence: 1.0,
		};
	}

	async afterExecution(_ctx: MessageContext, _result: ExecutionResult): Promise<void> {}

	redactOutput(text: string): RedactionResult {
		return { redacted: text, redactions: [] };
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Pipeline Factory
// ═══════════════════════════════════════════════════════════════════════════════

export interface PipelineConfig {
	profile: SecurityProfile;
	securityConfig?: SecurityConfig;
	rateLimiter: RateLimiter;
	auditLogger: AuditLogger;
	secretFilterConfig?: SecretFilterConfig;
}

export async function buildSecurityPipeline(config: PipelineConfig): Promise<SecurityPipeline> {
	const { profile, securityConfig, rateLimiter, auditLogger, secretFilterConfig } = config;

	if (profile === "test") {
		// SECURITY: Test profile has NO security - require explicit opt-in
		const testEnvFlag = process.env.TELCLAUDE_ENABLE_TEST_PROFILE === "1";
		const isProduction = process.env.NODE_ENV === "production";

		if (isProduction && !testEnvFlag) {
			logger.error("test profile requested in production without TELCLAUDE_ENABLE_TEST_PROFILE=1");
			throw new Error(
				"Cannot use test profile in production. " +
					"Set TELCLAUDE_ENABLE_TEST_PROFILE=1 to explicitly enable (DANGEROUS).",
			);
		}

		if (!testEnvFlag) {
			logger.error(
				"test profile requires TELCLAUDE_ENABLE_TEST_PROFILE=1 - " +
					"this disables ALL security enforcement",
			);
			throw new Error(
				"Test profile requires explicit opt-in. " +
					"Set TELCLAUDE_ENABLE_TEST_PROFILE=1 environment variable to enable. " +
					"WARNING: This disables ALL security enforcement!",
			);
		}

		logger.warn("TEST PROFILE ENABLED - NO SECURITY ENFORCEMENT - NEVER USE IN PRODUCTION");
		return new TestPipeline();
	}

	if (profile === "simple") {
		logger.info("using simple profile - hard enforcement only");
		return new SimplePipeline(securityConfig, rateLimiter, auditLogger, secretFilterConfig);
	}

	// Strict profile - lazy load observer and approvals
	logger.info("using strict profile - full security layers");
	const [{ createObserver }, { requiresApproval }] = await Promise.all([
		import("./observer.js"),
		import("./approvals.js"),
	]);

	const observerConfig = securityConfig?.observer ?? {
		enabled: true,
		maxLatencyMs: 2000,
		dangerThreshold: 0.7,
		fallbackOnTimeout: "block" as const,
	};

	const observer = createObserver({
		enabled: observerConfig.enabled ?? true,
		maxLatencyMs: observerConfig.maxLatencyMs ?? 2000,
		dangerThreshold: observerConfig.dangerThreshold ?? 0.7,
		fallbackOnTimeout: observerConfig.fallbackOnTimeout ?? "block",
		cwd: process.cwd(),
	});

	return new StrictPipeline(
		securityConfig,
		rateLimiter,
		auditLogger,
		observer,
		(tier, classification, confidence, admin) =>
			requiresApproval(tier, classification, confidence, admin),
		secretFilterConfig,
	);
}

export { calculateEntropy, detectHighEntropyBlobs };
export type { SecretFilterConfig };
