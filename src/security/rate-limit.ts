import { RateLimiterMemory } from "rate-limiter-flexible";
import type { PermissionTier, SecurityConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import type { RateLimitResult } from "./types.js";

const logger = getChildLogger({ module: "rate-limit" });

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
 * Rate limiter manager with per-tier enforcement.
 */
export class RateLimiter {
	private globalMinute: RateLimiterMemory;
	private globalHour: RateLimiterMemory;
	private tierMinuteLimiters: Map<PermissionTier, RateLimiterMemory>;
	private tierHourLimiters: Map<PermissionTier, RateLimiterMemory>;
	private config: RateLimitConfig;

	constructor(securityConfig?: SecurityConfig) {
		this.config = this.mergeConfig(securityConfig);

		this.globalMinute = new RateLimiterMemory({
			points: this.config.global.perMinute,
			duration: 60,
		});

		this.globalHour = new RateLimiterMemory({
			points: this.config.global.perHour,
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
	 * Check if a request is allowed, enforcing per-tier limits.
	 */
	async checkLimit(userId: string, tier: PermissionTier): Promise<RateLimitResult> {
		try {
			// Check global limits first
			try {
				await this.globalMinute.consume("global", 1);
			} catch {
				logger.warn("global minute rate limit hit");
				return {
					allowed: false,
					remaining: 0,
					resetMs: 60000,
					limitType: "global",
				};
			}

			try {
				await this.globalHour.consume("global", 1);
			} catch {
				logger.warn("global hour rate limit hit");
				return {
					allowed: false,
					remaining: 0,
					resetMs: 3600000,
					limitType: "global",
				};
			}

			// Check tier-specific user limits
			const tierMinuteLimiter = this.tierMinuteLimiters.get(tier);
			const tierHourLimiter = this.tierHourLimiters.get(tier);

			if (!tierMinuteLimiter || !tierHourLimiter) {
				logger.error({ tier }, "missing tier limiter");
				return { allowed: true, remaining: 0, resetMs: 0 };
			}

			const tierLimits = this.config.perTier[tier];

			try {
				const minuteResult = await tierMinuteLimiter.consume(userId, 1);
				const remaining = Math.max(0, tierLimits.perMinute - minuteResult.consumedPoints);

				// Also check hour limit
				await tierHourLimiter.consume(userId, 1);

				return {
					allowed: true,
					remaining,
					resetMs: minuteResult.msBeforeNext,
					limitType: "user",
				};
			} catch (err) {
				const rateLimitErr = err as { msBeforeNext?: number };
				logger.info({ userId, tier }, "user rate limit hit for tier");
				return {
					allowed: false,
					remaining: 0,
					resetMs: rateLimitErr.msBeforeNext ?? 60000,
					limitType: "user",
				};
			}
		} catch (err) {
			logger.error({ error: String(err) }, "rate limit check error");
			// On error, allow the request but log it
			return {
				allowed: true,
				remaining: 0,
				resetMs: 0,
			};
		}
	}

	/**
	 * Reset rate limits for a user across all tiers.
	 */
	async resetUser(userId: string): Promise<void> {
		for (const limiter of this.tierMinuteLimiters.values()) {
			await limiter.delete(userId);
		}
		for (const limiter of this.tierHourLimiters.values()) {
			await limiter.delete(userId);
		}
	}

	/**
	 * Get current usage for a user in a specific tier.
	 */
	async getUserUsage(
		userId: string,
		tier: PermissionTier,
	): Promise<{ minute: number; hour: number }> {
		const minuteLimiter = this.tierMinuteLimiters.get(tier);
		const hourLimiter = this.tierHourLimiters.get(tier);

		const minuteRes = await minuteLimiter?.get(userId);
		const hourRes = await hourLimiter?.get(userId);

		return {
			minute: minuteRes?.consumedPoints ?? 0,
			hour: hourRes?.consumedPoints ?? 0,
		};
	}
}

/**
 * Create a rate limiter from config.
 */
export function createRateLimiter(securityConfig?: SecurityConfig): RateLimiter {
	return new RateLimiter(securityConfig);
}
