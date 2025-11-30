import type { TelegramConfig } from "../config/config.js";

export type ReconnectPolicy = {
	initialMs: number;
	maxMs: number;
	factor: number;
	jitter: number;
	maxAttempts: number;
};

export const DEFAULT_RECONNECT_POLICY: ReconnectPolicy = {
	initialMs: 1_000,
	maxMs: 60_000,
	factor: 2.0,
	jitter: 0.3,
	maxAttempts: 0, // 0 = unlimited
};

/**
 * Resolve reconnect policy from config.
 */
export function resolveReconnectPolicy(
	config: { telegram?: TelegramConfig },
	overrides?: Partial<ReconnectPolicy>,
): ReconnectPolicy {
	const cfg = config.telegram?.reconnect;
	return {
		initialMs: overrides?.initialMs ?? cfg?.initialMs ?? DEFAULT_RECONNECT_POLICY.initialMs,
		maxMs: overrides?.maxMs ?? cfg?.maxMs ?? DEFAULT_RECONNECT_POLICY.maxMs,
		factor: overrides?.factor ?? cfg?.factor ?? DEFAULT_RECONNECT_POLICY.factor,
		jitter: overrides?.jitter ?? cfg?.jitter ?? DEFAULT_RECONNECT_POLICY.jitter,
		maxAttempts: overrides?.maxAttempts ?? cfg?.maxAttempts ?? DEFAULT_RECONNECT_POLICY.maxAttempts,
	};
}

/**
 * Compute backoff delay for a given attempt.
 */
export function computeBackoff(policy: ReconnectPolicy, attempt: number): number {
	const base = policy.initialMs * policy.factor ** (attempt - 1);
	const capped = Math.min(base, policy.maxMs);
	const jitterRange = capped * policy.jitter;
	const jitter = (Math.random() - 0.5) * 2 * jitterRange;
	return Math.max(0, Math.round(capped + jitter));
}

/**
 * Sleep with optional abort signal.
 */
export function sleepWithAbort(ms: number, signal?: AbortSignal): Promise<void> {
	return new Promise((resolve, reject) => {
		if (signal?.aborted) {
			reject(new Error("Aborted"));
			return;
		}

		const timer = setTimeout(resolve, ms);

		signal?.addEventListener("abort", () => {
			clearTimeout(timer);
			reject(new Error("Aborted"));
		});
	});
}

/**
 * Generate a unique connection ID.
 */
export function newConnectionId(): string {
	return `conn_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}
