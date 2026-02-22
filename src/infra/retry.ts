import { sleep } from "../utils.js";

export type RetryConfig = {
	/** Maximum number of attempts (including the first). Must be >= 1. */
	maxAttempts: number;
	/** Base delay in milliseconds before the first retry. */
	baseDelayMs: number;
	/** Maximum delay cap in milliseconds. */
	maxDelayMs: number;
	/** Exponential backoff factor. Default: 2. */
	factor: number;
	/** Jitter factor (0–1). Randomizes delay by ±jitter. Default: 0.25. */
	jitter: number;
};

export type RetryOptions = Partial<RetryConfig> & {
	/** Predicate: return true if the error is retryable. Defaults to always-retry. */
	shouldRetry?: (err: unknown, info: RetryInfo) => boolean;
	/** Called before each retry sleep. Useful for logging. */
	onRetry?: (err: unknown, info: RetryInfo) => void;
	/** If the error provides a server-suggested retry delay (ms), use it. */
	retryAfterMs?: (err: unknown) => number | undefined;
	/** Optional label for logging / error messages. */
	label?: string;
};

export type RetryInfo = {
	/** 1-based attempt number that just failed. */
	attempt: number;
	/** Total attempts allowed. */
	maxAttempts: number;
	/** Delay before the next attempt (ms). */
	delayMs: number;
};

const DEFAULT_CONFIG: RetryConfig = {
	maxAttempts: 3,
	baseDelayMs: 1000,
	maxDelayMs: 30_000,
	factor: 2,
	jitter: 0.25,
};

export function resolveRetryConfig(opts?: Partial<RetryConfig>): RetryConfig {
	return {
		maxAttempts: Math.max(1, opts?.maxAttempts ?? DEFAULT_CONFIG.maxAttempts),
		baseDelayMs: Math.max(0, opts?.baseDelayMs ?? DEFAULT_CONFIG.baseDelayMs),
		maxDelayMs: Math.max(0, opts?.maxDelayMs ?? DEFAULT_CONFIG.maxDelayMs),
		factor: Math.max(1, opts?.factor ?? DEFAULT_CONFIG.factor),
		jitter: Math.min(1, Math.max(0, opts?.jitter ?? DEFAULT_CONFIG.jitter)),
	};
}

/**
 * Compute backoff delay for a given attempt (1-based).
 */
export function computeRetryDelay(config: RetryConfig, attempt: number): number {
	const base = config.baseDelayMs * config.factor ** (attempt - 1);
	const capped = Math.min(base, config.maxDelayMs);
	const jitterRange = capped * config.jitter;
	const jitter = (Math.random() - 0.5) * 2 * jitterRange;
	return Math.max(0, Math.round(capped + jitter));
}

/**
 * Retry an async operation with exponential backoff and jitter.
 *
 * @example
 * ```ts
 * const result = await retryAsync(() => fetch(url), {
 *   maxAttempts: 3,
 *   baseDelayMs: 1000,
 *   shouldRetry: (err) => isTransientNetworkError(err),
 *   onRetry: (err, info) => logger.warn({ attempt: info.attempt }, "retrying"),
 * });
 * ```
 */
export async function retryAsync<T>(fn: () => Promise<T>, opts?: RetryOptions): Promise<T> {
	const config = resolveRetryConfig(opts);
	const { shouldRetry, onRetry, retryAfterMs, label } = opts ?? {};

	let lastError: unknown;

	for (let attempt = 1; attempt <= config.maxAttempts; attempt++) {
		try {
			return await fn();
		} catch (err) {
			lastError = err;

			if (attempt >= config.maxAttempts) {
				break;
			}

			const info: RetryInfo = {
				attempt,
				maxAttempts: config.maxAttempts,
				delayMs: 0, // filled below
			};

			if (shouldRetry && !shouldRetry(err, info)) {
				break;
			}

			// Prefer server-suggested delay, fall back to computed backoff
			const serverDelay = retryAfterMs?.(err);
			const delay =
				serverDelay !== undefined && serverDelay > 0
					? Math.min(serverDelay, config.maxDelayMs)
					: computeRetryDelay(config, attempt);
			info.delayMs = delay;

			onRetry?.(err, info);

			if (delay > 0) {
				await sleep(delay);
			}
		}
	}

	const prefix = label ? `${label}: ` : "";
	throw lastError ?? new Error(`${prefix}retryAsync exhausted ${config.maxAttempts} attempts`);
}
