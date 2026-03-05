/**
 * Shared sliding-window rate limiter used by relay proxy modules.
 *
 * Extracted from anthropic-proxy, git-proxy, and http-credential-proxy
 * which each had identical inline implementations.
 */

type Entry = { count: number; resetAt: number };

export class SlidingWindowRateLimiter {
	private readonly map = new Map<string, Entry>();
	private cleanupTimer: ReturnType<typeof setInterval> | null = null;

	/**
	 * Check if a request is within the rate limit.
	 * Returns true if allowed, false if rate-limited.
	 */
	check(key: string, limitPerMinute: number): boolean {
		const now = Date.now();
		const entry = this.map.get(key);

		if (!entry || entry.resetAt < now) {
			this.map.set(key, { count: 1, resetAt: now + 60_000 });
			return true;
		}

		if (entry.count >= limitPerMinute) {
			return false;
		}

		entry.count++;
		return true;
	}

	/**
	 * Start periodic cleanup of expired entries.
	 * The timer is unref'd so it won't keep the process alive.
	 */
	startCleanup(intervalMs = 5 * 60 * 1000): void {
		if (this.cleanupTimer) return;

		this.cleanupTimer = setInterval(() => {
			const now = Date.now();
			for (const [key, entry] of this.map.entries()) {
				if (entry.resetAt < now) {
					this.map.delete(key);
				}
			}
		}, intervalMs);

		this.cleanupTimer.unref();
	}

	/**
	 * Stop periodic cleanup.
	 */
	stopCleanup(): void {
		if (this.cleanupTimer) {
			clearInterval(this.cleanupTimer);
			this.cleanupTimer = null;
		}
	}
}
