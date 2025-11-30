import { RateLimiterMemory, type RateLimiterRes } from "rate-limiter-flexible";
import type { PermissionTier, SecurityConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import type { RateLimitResult } from "./types.js";

const logger = getChildLogger({ module: "rate-limit" });

/**
 * Type guard for rate limiter errors.
 */
function isRateLimitError(err: unknown): err is { msBeforeNext?: number } {
	return (
		typeof err === "object" && err !== null && ("msBeforeNext" in err || "remainingPoints" in err)
	);
}

/**
 * Rate limiter configuration.
 */
export type RateLimitConfig = {
	global: {
		perMinute: number;
		perHour: number;
	};
	perUser: {
		perMinute: number;
		perHour: number;
	};
	perTier: Record<PermissionTier, { perMinute: number; perHour: number }>;
};

const DEFAULT_RATE_LIMITS: RateLimitConfig = {
	global: {
		perMinute: 100,
		perHour: 1000,
	},
	perUser: {
		perMinute: 10,
		perHour: 60,
	},
	perTier: {
		READ_ONLY: { perMinute: 20, perHour: 200 },
		WRITE_SAFE: { perMinute: 10, perHour: 100 },
		FULL_ACCESS: { perMinute: 5, perHour: 30 },
	},
};

/**
 * Rate limiter manager with global, per-user, and per-tier enforcement.
 */
export class RateLimiter {
	private globalMinute: RateLimiterMemory;
	private globalHour: RateLimiterMemory;
	private userMinute: RateLimiterMemory;
	private userHour: RateLimiterMemory;
	private tierMinuteLimiters: Map<PermissionTier, RateLimiterMemory>;
	private tierHourLimiters: Map<PermissionTier, RateLimiterMemory>;
	private config: RateLimitConfig;

	constructor(securityConfig?: SecurityConfig) {
		this.config = this.mergeConfig(securityConfig);

		// Global limiters (shared across all users)
		this.globalMinute = new RateLimiterMemory({
			points: this.config.global.perMinute,
			duration: 60,
		});

		this.globalHour = new RateLimiterMemory({
			points: this.config.global.perHour,
			duration: 3600,
		});

		// Per-user limiters (keyed by userId, applies to all users regardless of tier)
		this.userMinute = new RateLimiterMemory({
			points: this.config.perUser.perMinute,
			duration: 60,
		});

		this.userHour = new RateLimiterMemory({
			points: this.config.perUser.perHour,
			duration: 3600,
		});

		// Create per-tier limiters
		this.tierMinuteLimiters = new Map();
		this.tierHourLimiters = new Map();

		for (const tier of ["READ_ONLY", "WRITE_SAFE", "FULL_ACCESS"] as PermissionTier[]) {
			const tierLimits = this.config.perTier[tier];
			this.tierMinuteLimiters.set(
				tier,
				new RateLimiterMemory({
					points: tierLimits.perMinute,
					duration: 60,
				}),
			);
			this.tierHourLimiters.set(
				tier,
				new RateLimiterMemory({
					points: tierLimits.perHour,
					duration: 3600,
				}),
			);
		}
	}

	private mergeConfig(securityConfig?: SecurityConfig): RateLimitConfig {
		const rateLimits = securityConfig?.rateLimits;
		return {
			global: {
				perMinute: rateLimits?.global?.perMinute ?? DEFAULT_RATE_LIMITS.global.perMinute,
				perHour: rateLimits?.global?.perHour ?? DEFAULT_RATE_LIMITS.global.perHour,
			},
			perUser: {
				perMinute: rateLimits?.perUser?.perMinute ?? DEFAULT_RATE_LIMITS.perUser.perMinute,
				perHour: rateLimits?.perUser?.perHour ?? DEFAULT_RATE_LIMITS.perUser.perHour,
			},
			perTier: {
				READ_ONLY: rateLimits?.perTier?.READ_ONLY ?? DEFAULT_RATE_LIMITS.perTier.READ_ONLY,
				WRITE_SAFE: rateLimits?.perTier?.WRITE_SAFE ?? DEFAULT_RATE_LIMITS.perTier.WRITE_SAFE,
				FULL_ACCESS: rateLimits?.perTier?.FULL_ACCESS ?? DEFAULT_RATE_LIMITS.perTier.FULL_ACCESS,
			},
		};
	}

	/**
	 * Check if a request is allowed, enforcing global, per-user, and per-tier limits.
	 * All limits are checked BEFORE any are consumed to prevent race conditions.
	 */
	async checkLimit(userId: string, tier: PermissionTier): Promise<RateLimitResult> {
		try {
			const tierMinuteLimiter = this.tierMinuteLimiters.get(tier);
			const tierHourLimiter = this.tierHourLimiters.get(tier);

			if (!tierMinuteLimiter || !tierHourLimiter) {
				logger.error({ tier }, "missing tier limiter");
				return { allowed: true, remaining: 0, resetMs: 0 };
			}

			// Phase 1: Check all limits without consuming
			const [
				globalMinuteRes,
				globalHourRes,
				userMinuteRes,
				userHourRes,
				tierMinuteRes,
				tierHourRes,
			] = await Promise.all([
				this.globalMinute.get("global"),
				this.globalHour.get("global"),
				this.userMinute.get(userId),
				this.userHour.get(userId),
				tierMinuteLimiter.get(userId),
				tierHourLimiter.get(userId),
			]);

			// Check global limits
			const globalMinuteConsumed = globalMinuteRes?.consumedPoints ?? 0;
			if (globalMinuteConsumed >= this.config.global.perMinute) {
				logger.warn("global minute rate limit hit");
				return { allowed: false, remaining: 0, resetMs: 60000, limitType: "global" };
			}

			const globalHourConsumed = globalHourRes?.consumedPoints ?? 0;
			if (globalHourConsumed >= this.config.global.perHour) {
				logger.warn("global hour rate limit hit");
				return { allowed: false, remaining: 0, resetMs: 3600000, limitType: "global" };
			}

			// Check per-user limits
			const userMinuteConsumed = userMinuteRes?.consumedPoints ?? 0;
			if (userMinuteConsumed >= this.config.perUser.perMinute) {
				logger.info({ userId }, "per-user minute rate limit hit");
				return {
					allowed: false,
					remaining: 0,
					resetMs: userMinuteRes?.msBeforeNext ?? 60000,
					limitType: "user",
				};
			}

			const userHourConsumed = userHourRes?.consumedPoints ?? 0;
			if (userHourConsumed >= this.config.perUser.perHour) {
				logger.info({ userId }, "per-user hour rate limit hit");
				return {
					allowed: false,
					remaining: 0,
					resetMs: userHourRes?.msBeforeNext ?? 3600000,
					limitType: "user",
				};
			}

			// Check tier-specific limits
			const tierLimits = this.config.perTier[tier];
			const tierMinuteConsumed = tierMinuteRes?.consumedPoints ?? 0;
			if (tierMinuteConsumed >= tierLimits.perMinute) {
				logger.info({ userId, tier }, "tier minute rate limit hit");
				return {
					allowed: false,
					remaining: 0,
					resetMs: tierMinuteRes?.msBeforeNext ?? 60000,
					limitType: "tier",
				};
			}

			const tierHourConsumed = tierHourRes?.consumedPoints ?? 0;
			if (tierHourConsumed >= tierLimits.perHour) {
				logger.info({ userId, tier }, "tier hour rate limit hit");
				return {
					allowed: false,
					remaining: 0,
					resetMs: tierHourRes?.msBeforeNext ?? 3600000,
					limitType: "tier",
				};
			}

			// Phase 2: All limits pass - consume all atomically
			const consumeResults = await Promise.allSettled([
				this.globalMinute.consume("global", 1),
				this.globalHour.consume("global", 1),
				this.userMinute.consume(userId, 1),
				this.userHour.consume(userId, 1),
				tierMinuteLimiter.consume(userId, 1),
				tierHourLimiter.consume(userId, 1),
			]);

			// Check if any consumption failed (shouldn't happen but handle gracefully)
			for (const result of consumeResults) {
				if (result.status === "rejected") {
					const err = result.reason as unknown;
					if (isRateLimitError(err)) {
						logger.warn({ userId, tier }, "rate limit hit during consumption phase");
						return {
							allowed: false,
							remaining: 0,
							resetMs: err.msBeforeNext ?? 60000,
							limitType: "tier",
						};
					}
				}
			}

			// Get final tier minute result for remaining calculation
			const finalTierMinute = consumeResults[4];
			let remaining = 0;
			let resetMs = 60000;
			if (finalTierMinute.status === "fulfilled") {
				remaining = Math.max(
					0,
					tierLimits.perMinute - (finalTierMinute.value as RateLimiterRes).consumedPoints,
				);
				resetMs = (finalTierMinute.value as RateLimiterRes).msBeforeNext;
			}

			return {
				allowed: true,
				remaining,
				resetMs,
				limitType: "tier",
			};
		} catch (err) {
			logger.error({ error: String(err) }, "rate limit check error");
			// On error, allow the request but log it
			return { allowed: true, remaining: 0, resetMs: 0 };
		}
	}

	/**
	 * Reset rate limits for a user across all limiters.
	 */
	async resetUser(userId: string): Promise<void> {
		// Reset per-user limiters
		await this.userMinute.delete(userId);
		await this.userHour.delete(userId);

		// Reset per-tier limiters
		for (const limiter of this.tierMinuteLimiters.values()) {
			await limiter.delete(userId);
		}
		for (const limiter of this.tierHourLimiters.values()) {
			await limiter.delete(userId);
		}
	}

	/**
	 * Get current usage for a user across all limit types.
	 */
	async getUserUsage(
		userId: string,
		tier: PermissionTier,
	): Promise<{
		perUser: { minute: number; hour: number };
		perTier: { minute: number; hour: number };
	}> {
		// Per-user usage
		const userMinuteRes = await this.userMinute.get(userId);
		const userHourRes = await this.userHour.get(userId);

		// Per-tier usage
		const tierMinuteLimiter = this.tierMinuteLimiters.get(tier);
		const tierHourLimiter = this.tierHourLimiters.get(tier);

		const tierMinuteRes = await tierMinuteLimiter?.get(userId);
		const tierHourRes = await tierHourLimiter?.get(userId);

		return {
			perUser: {
				minute: userMinuteRes?.consumedPoints ?? 0,
				hour: userHourRes?.consumedPoints ?? 0,
			},
			perTier: {
				minute: tierMinuteRes?.consumedPoints ?? 0,
				hour: tierHourRes?.consumedPoints ?? 0,
			},
		};
	}

	/**
	 * Get the current rate limit configuration.
	 */
	getConfig(): RateLimitConfig {
		return this.config;
	}
}

/**
 * Create a rate limiter from config.
 */
export function createRateLimiter(securityConfig?: SecurityConfig): RateLimiter {
	return new RateLimiter(securityConfig);
}
