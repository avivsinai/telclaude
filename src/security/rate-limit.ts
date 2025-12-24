/**
 * SQLite-backed rate limiter with atomic operations.
 *
 * Uses sliding window counters stored in SQLite for persistence across restarts.
 * Fails closed on errors - if rate limiting fails, requests are blocked.
 */

import type { PermissionTier, SecurityConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { getDb } from "../storage/db.js";
import { getUserRateLimitOverride } from "./permissions.js";
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
		WRITE_LOCAL: { perMinute: 10, perHour: 100 },
		FULL_ACCESS: { perMinute: 5, perHour: 30 },
	},
};

// Window durations in milliseconds
const MINUTE_MS = 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Get the start of the current window for a given duration.
 */
function getWindowStart(durationMs: number): number {
	const now = Date.now();
	return Math.floor(now / durationMs) * durationMs;
}

/**
 * Rate limiter manager with global, per-user, and per-tier enforcement.
 * Uses SQLite for persistence and atomic operations.
 */
export class RateLimiter {
	private config: RateLimitConfig;
	private securityConfig?: SecurityConfig;

	constructor(securityConfig?: SecurityConfig) {
		this.config = this.mergeConfig(securityConfig);
		this.securityConfig = securityConfig;
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
				WRITE_LOCAL: rateLimits?.perTier?.WRITE_LOCAL ?? DEFAULT_RATE_LIMITS.perTier.WRITE_LOCAL,
				FULL_ACCESS: rateLimits?.perTier?.FULL_ACCESS ?? DEFAULT_RATE_LIMITS.perTier.FULL_ACCESS,
			},
		};
	}

	/**
	 * Get current points for a limiter/key/window combination.
	 */
	private getPoints(limiterType: string, key: string, windowStart: number): number {
		const db = getDb();
		const row = db
			.prepare(
				"SELECT points FROM rate_limits WHERE limiter_type = ? AND key = ? AND window_start = ?",
			)
			.get(limiterType, key, windowStart) as { points: number } | undefined;
		return row?.points ?? 0;
	}

	/**
	 * Atomically increment points for a limiter/key/window combination.
	 * Returns the new point count.
	 */
	private incrementPoints(limiterType: string, key: string, windowStart: number): number {
		const db = getDb();

		// Use INSERT OR REPLACE with atomic increment
		const result = db.transaction(() => {
			db.prepare(
				`INSERT INTO rate_limits (limiter_type, key, window_start, points)
				 VALUES (?, ?, ?, 1)
				 ON CONFLICT(limiter_type, key, window_start)
				 DO UPDATE SET points = points + 1`,
			).run(limiterType, key, windowStart);

			const row = db
				.prepare(
					"SELECT points FROM rate_limits WHERE limiter_type = ? AND key = ? AND window_start = ?",
				)
				.get(limiterType, key, windowStart) as { points: number };

			return row.points;
		})();

		return result;
	}

	/**
	 * Check if a request is allowed, enforcing global, per-user, and per-tier limits.
	 *
	 * IMPORTANT: Fails closed - if any error occurs, the request is blocked.
	 * This is a security feature to prevent abuse during failures.
	 */
	async checkLimit(userId: string, tier: PermissionTier): Promise<RateLimitResult> {
		try {
			const minuteWindow = getWindowStart(MINUTE_MS);
			const hourWindow = getWindowStart(HOUR_MS);
			const userOverride = getUserRateLimitOverride(userId, this.securityConfig);
			const perUserLimits = {
				perMinute: userOverride?.perMinute ?? this.config.perUser.perMinute,
				perHour: userOverride?.perHour ?? this.config.perUser.perHour,
			};

			// Check all limits before consuming
			// Global minute
			const globalMinutePoints = this.getPoints("global_minute", "global", minuteWindow);
			if (globalMinutePoints >= this.config.global.perMinute) {
				logger.warn("global minute rate limit hit");
				return { allowed: false, remaining: 0, resetMs: MINUTE_MS, limitType: "global" };
			}

			// Global hour
			const globalHourPoints = this.getPoints("global_hour", "global", hourWindow);
			if (globalHourPoints >= this.config.global.perHour) {
				logger.warn("global hour rate limit hit");
				return { allowed: false, remaining: 0, resetMs: HOUR_MS, limitType: "global" };
			}

			// Per-user minute
			const userMinutePoints = this.getPoints("user_minute", userId, minuteWindow);
			if (userMinutePoints >= perUserLimits.perMinute) {
				logger.info({ userId }, "per-user minute rate limit hit");
				return { allowed: false, remaining: 0, resetMs: MINUTE_MS, limitType: "user" };
			}

			// Per-user hour
			const userHourPoints = this.getPoints("user_hour", userId, hourWindow);
			if (userHourPoints >= perUserLimits.perHour) {
				logger.info({ userId }, "per-user hour rate limit hit");
				return { allowed: false, remaining: 0, resetMs: HOUR_MS, limitType: "user" };
			}

			// Per-tier minute
			const tierLimits = this.config.perTier[tier];
			const tierMinutePoints = this.getPoints(`tier_minute_${tier}`, userId, minuteWindow);
			if (tierMinutePoints >= tierLimits.perMinute) {
				logger.info({ userId, tier }, "tier minute rate limit hit");
				return { allowed: false, remaining: 0, resetMs: MINUTE_MS, limitType: "tier" };
			}

			// Per-tier hour
			const tierHourPoints = this.getPoints(`tier_hour_${tier}`, userId, hourWindow);
			if (tierHourPoints >= tierLimits.perHour) {
				logger.info({ userId, tier }, "tier hour rate limit hit");
				return { allowed: false, remaining: 0, resetMs: HOUR_MS, limitType: "tier" };
			}

			// All checks passed - consume points atomically
			const db = getDb();
			db.transaction(() => {
				this.incrementPoints("global_minute", "global", minuteWindow);
				this.incrementPoints("global_hour", "global", hourWindow);
				this.incrementPoints("user_minute", userId, minuteWindow);
				this.incrementPoints("user_hour", userId, hourWindow);
				this.incrementPoints(`tier_minute_${tier}`, userId, minuteWindow);
				this.incrementPoints(`tier_hour_${tier}`, userId, hourWindow);
			})();

			// Calculate remaining based on the most restrictive minute limit (tier vs per-user)
			const effectiveMinuteLimit = Math.min(tierLimits.perMinute, perUserLimits.perMinute);
			const newTierMinutePoints = tierMinutePoints + 1;
			const remaining = Math.max(0, effectiveMinuteLimit - newTierMinutePoints);
			const resetMs = MINUTE_MS - (Date.now() - minuteWindow);

			return {
				allowed: true,
				remaining,
				resetMs,
				limitType: "tier",
			};
		} catch (err) {
			// FAIL CLOSED: On any error, block the request
			logger.error(
				{ error: String(err), userId, tier },
				"rate limit check error - blocking request",
			);
			return {
				allowed: false,
				remaining: 0,
				resetMs: MINUTE_MS,
				limitType: "global",
			};
		}
	}

	/**
	 * Reset rate limits for a user across all limiters.
	 */
	async resetUser(userId: string): Promise<void> {
		const db = getDb();
		db.prepare("DELETE FROM rate_limits WHERE key = ?").run(userId);
		logger.info({ userId }, "rate limits reset for user");
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
		const minuteWindow = getWindowStart(MINUTE_MS);
		const hourWindow = getWindowStart(HOUR_MS);

		return {
			perUser: {
				minute: this.getPoints("user_minute", userId, minuteWindow),
				hour: this.getPoints("user_hour", userId, hourWindow),
			},
			perTier: {
				minute: this.getPoints(`tier_minute_${tier}`, userId, minuteWindow),
				hour: this.getPoints(`tier_hour_${tier}`, userId, hourWindow),
			},
		};
	}

	/**
	 * Get the current rate limit configuration.
	 */
	getConfig(): RateLimitConfig {
		return this.config;
	}

	/**
	 * Clean up old rate limit windows.
	 * Called periodically to prevent database bloat.
	 */
	cleanup(): number {
		const db = getDb();
		const oneHourAgo = Date.now() - HOUR_MS;
		const oneDayAgo = Date.now() - DAY_MS;
		const result = db
			.prepare(
				`DELETE FROM rate_limits
				 WHERE (limiter_type LIKE 'multimedia_%' AND window_start < ?)
				    OR (limiter_type NOT LIKE 'multimedia_%' AND window_start < ?)`,
			)
			.run(oneDayAgo, oneHourAgo);

		if (result.changes > 0) {
			logger.debug({ cleaned: result.changes }, "cleaned old rate limit windows");
		}

		return result.changes;
	}
}

/**
 * Create a rate limiter from config.
 */
export function createRateLimiter(securityConfig?: SecurityConfig): RateLimiter {
	return new RateLimiter(securityConfig);
}
