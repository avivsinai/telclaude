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
	| "moltbook_post"
	| "token_refresh";

/** Rate limit configuration for a feature */
export type FeatureRateLimitConfig = {
	maxPerHourPerUser: number;
	maxPerDayPerUser: number;
};

/** Result of a rate limit check */
export type MultimediaRateLimitResult = {
	allowed: boolean;
	remaining: { hour: number; day: number };
	resetMs: { hour: number; day: number };
	reason?: string;
};

// Window durations in milliseconds
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
 * Multimedia rate limiter for cost control.
 * Uses SQLite for persistence across restarts.
 */
export class MultimediaRateLimiter {
	/**
	 * Get current usage count for a feature/user/window combination.
	 */
	private getPoints(feature: MultimediaFeature, userId: string, windowStart: number): number {
		const db = getDb();
		const limiterType = `multimedia_${feature}`;
		const row = db
			.prepare(
				"SELECT points FROM rate_limits WHERE limiter_type = ? AND key = ? AND window_start = ?",
			)
			.get(limiterType, userId, windowStart) as { points: number } | undefined;
		return row?.points ?? 0;
	}

	/**
	 * Atomically increment usage count for a feature/user/window combination.
	 * Returns the new count.
	 */
	private incrementPoints(feature: MultimediaFeature, userId: string, windowStart: number): number {
		const db = getDb();
		const limiterType = `multimedia_${feature}`;

		const result = db.transaction(() => {
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
		})();

		return result;
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
	): MultimediaRateLimitResult {
		try {
			const hourWindow = getWindowStart(HOUR_MS);
			const dayWindow = getWindowStart(DAY_MS);

			const hourPoints = this.getPoints(feature, userId, hourWindow);
			const dayPoints = this.getPoints(feature, userId, dayWindow);

			const hourRemaining = Math.max(0, config.maxPerHourPerUser - hourPoints);
			const dayRemaining = Math.max(0, config.maxPerDayPerUser - dayPoints);

			const hourResetMs = HOUR_MS - (Date.now() - hourWindow);
			const dayResetMs = DAY_MS - (Date.now() - dayWindow);

			// Check hourly limit
			if (hourPoints >= config.maxPerHourPerUser) {
				logger.info(
					{ feature, userId, hourPoints, limit: config.maxPerHourPerUser },
					"multimedia hourly rate limit hit",
				);
				return {
					allowed: false,
					remaining: { hour: 0, day: dayRemaining },
					resetMs: { hour: hourResetMs, day: dayResetMs },
					reason: `Hourly limit reached (${config.maxPerHourPerUser}/hour). Try again in ${Math.ceil(hourResetMs / 60000)} minutes.`,
				};
			}

			// Check daily limit
			if (dayPoints >= config.maxPerDayPerUser) {
				logger.info(
					{ feature, userId, dayPoints, limit: config.maxPerDayPerUser },
					"multimedia daily rate limit hit",
				);
				return {
					allowed: false,
					remaining: { hour: hourRemaining, day: 0 },
					resetMs: { hour: hourResetMs, day: dayResetMs },
					reason: `Daily limit reached (${config.maxPerDayPerUser}/day). Try again tomorrow.`,
				};
			}

			return {
				allowed: true,
				remaining: { hour: hourRemaining, day: dayRemaining },
				resetMs: { hour: hourResetMs, day: dayResetMs },
			};
		} catch (err) {
			// FAIL CLOSED: On any error, block the request
			logger.error(
				{ error: String(err), feature, userId },
				"multimedia rate limit check error - blocking",
			);
			return {
				allowed: false,
				remaining: { hour: 0, day: 0 },
				resetMs: { hour: HOUR_MS, day: DAY_MS },
				reason: "Rate limit check failed. Please try again later.",
			};
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
				this.incrementPoints(feature, userId, hourWindow);
				this.incrementPoints(feature, userId, dayWindow);
			})();

			logger.debug({ feature, userId }, "multimedia rate limit point consumed");
		} catch (err) {
			// Log but don't fail - the operation already succeeded
			logger.error({ error: String(err), feature, userId }, "failed to consume rate limit point");
		}
	}

	/**
	 * Get current usage for a user on a specific feature.
	 */
	getUsage(feature: MultimediaFeature, userId: string): { hour: number; day: number } {
		const hourWindow = getWindowStart(HOUR_MS);
		const dayWindow = getWindowStart(DAY_MS);

		return {
			hour: this.getPoints(feature, userId, hourWindow),
			day: this.getPoints(feature, userId, dayWindow),
		};
	}

	/**
	 * Reset usage for a user on a specific feature.
	 */
	resetUser(feature: MultimediaFeature, userId: string): void {
		const db = getDb();
		const limiterType = `multimedia_${feature}`;
		db.prepare("DELETE FROM rate_limits WHERE limiter_type = ? AND key = ?").run(
			limiterType,
			userId,
		);
		logger.info({ feature, userId }, "multimedia rate limits reset for user");
	}
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
