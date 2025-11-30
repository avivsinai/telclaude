import { RateLimiterMemory } from "rate-limiter-flexible";
import type { SecurityConfig, PermissionTier } from "../config/config.js";
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
	perTier?: Partial<Record<PermissionTier, { perMinute: number; perHour: number }>>;
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
 * Rate limiter manager.
 */
export class RateLimiter {
	private globalMinute: RateLimiterMemory;
	private globalHour: RateLimiterMemory;
	private userMinute: RateLimiterMemory;
	private userHour: RateLimiterMemory;
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

		this.userMinute = new RateLimiterMemory({
			points: this.config.perUser.perMinute,
			duration: 60,
		});

		this.userHour = new RateLimiterMemory({
			points: this.config.perUser.perHour,
			duration: 3600,
		});
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
			perTier: DEFAULT_RATE_LIMITS.perTier,
		};
	}

	/**
	 * Check if a request is allowed.
	 */
	async checkLimit(
		userId: string,
		tier: PermissionTier,
	): Promise<RateLimitResult> {
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

			// Check user limits
			const tierLimits = this.config.perTier?.[tier];
			const userMinuteLimit = tierLimits?.perMinute ?? this.config.perUser.perMinute;

			try {
				const minuteResult = await this.userMinute.consume(userId, 1);
				const remaining = Math.max(0, userMinuteLimit - minuteResult.consumedPoints);

				// Also check hour limit
				await this.userHour.consume(userId, 1);

				return {
					allowed: true,
					remaining,
					resetMs: minuteResult.msBeforeNext,
					limitType: "user",
				};
			} catch (err) {
				const rateLimitErr = err as { msBeforeNext?: number };
				logger.info({ userId }, "user rate limit hit");
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
	 * Reset rate limits for a user.
	 */
	async resetUser(userId: string): Promise<void> {
		await this.userMinute.delete(userId);
		await this.userHour.delete(userId);
	}

	/**
	 * Get current usage for a user.
	 */
	async getUserUsage(userId: string): Promise<{ minute: number; hour: number }> {
		const minuteRes = await this.userMinute.get(userId);
		const hourRes = await this.userHour.get(userId);
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
