/**
 * Multimedia feature rate limiter.
 *
 * Enforces per-user limits on costly OpenAI operations (image generation, TTS, etc.)
 * to prevent cost abuse. Uses the same rate_limits table as the security rate limiter.
 */

import { getChildLogger } from "../logging.js";
import { getDb } from "../storage/db.js";

const logger = getChildLogger({ module: "multimedia-rate-limit" });

/** Supported multimedia features for rate limiting */
export type MultimediaFeature =
	| "image_generation"
	| "tts"
	| "transcription"
	| "video_processing"
	| "social_post"
	| "summarize"
	| "token_refresh"
	| "web_fetch"
	| "web_search"
	| "web_browse"
	| "github_read"
	| "skill_request"
	| "household_auto_grant_outbound"
	| `${string}_post`
	| `${string}_reply`
	| `${string}_reply_target`
	| `${string}_follow`
	| `${string}_follow_target`
	| `${string}_unfollow`
	| `${string}_unfollow_target`;

/** Rate limit configuration for a feature */
export type FeatureRateLimitConfig = {
	maxPerMinutePerUser?: number;
	maxPerHourPerUser: number;
	maxPerDayPerUser: number;
};

/** Result of a rate limit check */
export type MultimediaRateLimitResult = {
	allowed: boolean;
	remaining: { minute?: number; hour: number; day: number };
	resetMs: { minute?: number; hour: number; day: number };
	reason?: string;
};

// Window durations in milliseconds
const MINUTE_MS = 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;
type RateLimitWindow = "minute" | "hour" | "day";

function limiterTypeFor(feature: MultimediaFeature, window: RateLimitWindow): string {
	// Window starts can coincide, so the
	// window kind must be part of the persistent key rather than inferred from time.
	return `multimedia_${feature}_${window}`;
}

/**
 * Get the start of the current window for a given duration.
 */
function getWindowStart(durationMs: number, nowMs = Date.now()): number {
	return Math.floor(nowMs / durationMs) * durationMs;
}

/**
 * Multimedia rate limiter for cost control.
 * Uses SQLite for persistence across restarts.
 */
export class MultimediaRateLimiter {
	/**
	 * Get current usage count for a feature/user/window combination.
	 */
	private getPoints(
		feature: MultimediaFeature,
		userId: string,
		window: RateLimitWindow,
		windowStart: number,
	): number {
		const db = getDb();
		const limiterType = limiterTypeFor(feature, window);
		const row = db
			.prepare(
				"SELECT points FROM rate_limits WHERE limiter_type = ? AND key = ? AND window_start = ?",
			)
			.get(limiterType, userId, windowStart) as { points: number } | undefined;
		return row?.points ?? 0;
	}

	/**
	 * Increment usage inside the caller's transaction.
	 * Returns the new count.
	 */
	private incrementPoints(
		feature: MultimediaFeature,
		userId: string,
		window: RateLimitWindow,
		windowStart: number,
	): number {
		const db = getDb();
		const limiterType = limiterTypeFor(feature, window);

		db.prepare(
			`INSERT INTO rate_limits (limiter_type, key, window_start, points)
			 VALUES (?, ?, ?, 1)
			 ON CONFLICT(limiter_type, key, window_start)
			 DO UPDATE SET points = points + 1`,
		).run(limiterType, userId, windowStart);

		const row = db
			.prepare(
				"SELECT points FROM rate_limits WHERE limiter_type = ? AND key = ? AND window_start = ?",
			)
			.get(limiterType, userId, windowStart) as { points: number };
		return row.points;
	}

	/**
	 * Check if a multimedia operation is allowed for a user.
	 * Does NOT consume the point - call consume() separately after successful operation.
	 *
	 * @param feature - The multimedia feature being used
	 * @param userId - User identifier (chat_id or local_user_id)
	 * @param config - Rate limit configuration for this feature
	 */
	checkLimit(
		feature: MultimediaFeature,
		userId: string,
		config: FeatureRateLimitConfig,
		nowMs = Date.now(),
	): MultimediaRateLimitResult {
		try {
			const minuteWindow = getWindowStart(MINUTE_MS, nowMs);
			const hourWindow = getWindowStart(HOUR_MS, nowMs);
			const dayWindow = getWindowStart(DAY_MS, nowMs);

			const minutePoints =
				config.maxPerMinutePerUser === undefined
					? 0
					: this.getPoints(feature, userId, "minute", minuteWindow);
			const hourPoints = this.getPoints(feature, userId, "hour", hourWindow);
			const dayPoints = this.getPoints(feature, userId, "day", dayWindow);

			const minuteRemaining =
				config.maxPerMinutePerUser === undefined
					? undefined
					: Math.max(0, config.maxPerMinutePerUser - minutePoints);
			const hourRemaining = Math.max(0, config.maxPerHourPerUser - hourPoints);
			const dayRemaining = Math.max(0, config.maxPerDayPerUser - dayPoints);

			const minuteResetMs = MINUTE_MS - (nowMs - minuteWindow);
			const hourResetMs = HOUR_MS - (nowMs - hourWindow);
			const dayResetMs = DAY_MS - (nowMs - dayWindow);
			const remaining = {
				...(minuteRemaining === undefined ? {} : { minute: minuteRemaining }),
				hour: hourRemaining,
				day: dayRemaining,
			};
			const resetMs = {
				...(config.maxPerMinutePerUser === undefined ? {} : { minute: minuteResetMs }),
				hour: hourResetMs,
				day: dayResetMs,
			};

			if (config.maxPerMinutePerUser !== undefined && minutePoints >= config.maxPerMinutePerUser) {
				logger.info("multimedia minute rate limit hit");
				return {
					allowed: false,
					remaining: { ...remaining, minute: 0 },
					resetMs,
					reason: `Minute limit reached (${config.maxPerMinutePerUser}/minute). Try again shortly.`,
				};
			}

			// Check hourly limit
			if (hourPoints >= config.maxPerHourPerUser) {
				logger.info("multimedia hourly rate limit hit");
				return {
					allowed: false,
					remaining: { ...remaining, hour: 0 },
					resetMs,
					reason: `Hourly limit reached (${config.maxPerHourPerUser}/hour). Try again in ${Math.ceil(hourResetMs / 60000)} minutes.`,
				};
			}

			// Check daily limit
			if (dayPoints >= config.maxPerDayPerUser) {
				logger.info("multimedia daily rate limit hit");
				return {
					allowed: false,
					remaining: { ...remaining, day: 0 },
					resetMs,
					reason: `Daily limit reached (${config.maxPerDayPerUser}/day). Try again tomorrow.`,
				};
			}

			return {
				allowed: true,
				remaining,
				resetMs,
			};
		} catch {
			// FAIL CLOSED: On any error, block the request
			logger.error("multimedia rate limit check error - blocking");
			return {
				allowed: false,
				remaining: { hour: 0, day: 0 },
				resetMs: { hour: HOUR_MS, day: DAY_MS },
				reason: "Rate limit check failed. Please try again later.",
			};
		}
	}

	/**
	 * Check and consume one point in a single transaction. Unlike consume(),
	 * every storage or exhaustion failure is thrown so security callers fail closed.
	 */
	reserve(feature: MultimediaFeature, userId: string, config: FeatureRateLimitConfig): void {
		try {
			const db = getDb();
			const reservationNowMs = Date.now();
			db.transaction(() => {
				const result = this.checkLimit(feature, userId, config, reservationNowMs);
				if (!result.allowed) {
					throw new Error(result.reason ?? `${feature} rate limit exceeded`);
				}
				if (config.maxPerMinutePerUser !== undefined) {
					this.incrementPoints(
						feature,
						userId,
						"minute",
						getWindowStart(MINUTE_MS, reservationNowMs),
					);
				}
				this.incrementPoints(feature, userId, "hour", getWindowStart(HOUR_MS, reservationNowMs));
				this.incrementPoints(feature, userId, "day", getWindowStart(DAY_MS, reservationNowMs));
			})();
			logger.debug("multimedia rate limit point reserved");
		} catch (err) {
			logger.error("rate limit reservation failed closed");
			throw err;
		}
	}

	/**
	 * Consume a rate limit point after a successful operation.
	 * Call this AFTER the operation succeeds to accurately track usage.
	 */
	consume(feature: MultimediaFeature, userId: string): void {
		try {
			const hourWindow = getWindowStart(HOUR_MS);
			const dayWindow = getWindowStart(DAY_MS);

			const db = getDb();
			db.transaction(() => {
				this.incrementPoints(feature, userId, "hour", hourWindow);
				this.incrementPoints(feature, userId, "day", dayWindow);
			})();

			logger.debug("multimedia rate limit point consumed");
		} catch {
			// Log but don't fail - the operation already succeeded
			logger.error("failed to consume rate limit point");
		}
	}

	/**
	 * Get current usage for a user on a specific feature.
	 */
	getUsage(feature: MultimediaFeature, userId: string): { hour: number; day: number } {
		const hourWindow = getWindowStart(HOUR_MS);
		const dayWindow = getWindowStart(DAY_MS);

		return {
			hour: this.getPoints(feature, userId, "hour", hourWindow),
			day: this.getPoints(feature, userId, "day", dayWindow),
		};
	}

	/**
	 * Reset usage for a user on a specific feature.
	 */
	resetUser(feature: MultimediaFeature, userId: string): void {
		const db = getDb();
		db.prepare("DELETE FROM rate_limits WHERE limiter_type IN (?, ?, ?, ?) AND key = ?").run(
			limiterTypeFor(feature, "minute"),
			limiterTypeFor(feature, "hour"),
			limiterTypeFor(feature, "day"),
			`multimedia_${feature}`,
			userId,
		);
		logger.info("multimedia rate limits reset for user");
	}
}

/**
 * Check rate limit for a multimedia operation.
 * No-ops when userId is absent or skipRateLimit is true.
 * Throws on limit exceeded (fail-closed).
 */
export function enforceRateLimit(
	feature: MultimediaFeature,
	userId: string | undefined,
	config: FeatureRateLimitConfig,
	opts?: { skipRateLimit?: boolean },
): void {
	if (!userId || opts?.skipRateLimit) return;
	const limiter = getMultimediaRateLimiter();
	const result = limiter.checkLimit(feature, userId, config);
	if (!result.allowed) {
		throw new Error(result.reason ?? `${feature} rate limit exceeded`);
	}
}

/**
 * Consume a rate limit point after a successful operation.
 * No-ops when userId is absent or skipRateLimit is true.
 */
export function consumeRateLimit(
	feature: MultimediaFeature,
	userId: string | undefined,
	opts?: { skipRateLimit?: boolean },
): void {
	if (!userId || opts?.skipRateLimit) return;
	getMultimediaRateLimiter().consume(feature, userId);
}

/** Strict atomic rate-limit reservation for security-sensitive callers. */
export function reserveRateLimit(
	feature: MultimediaFeature,
	userId: string,
	config: FeatureRateLimitConfig,
): void {
	getMultimediaRateLimiter().reserve(feature, userId, config);
}

/** Singleton instance */
let instance: MultimediaRateLimiter | null = null;

/**
 * Get the multimedia rate limiter instance.
 */
export function getMultimediaRateLimiter(): MultimediaRateLimiter {
	if (!instance) {
		instance = new MultimediaRateLimiter();
	}
	return instance;
}
