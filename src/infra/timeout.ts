/**
 * Timeout utilities for async operations.
 */

export class TimeoutError extends Error {
	constructor(
		message: string,
		public readonly timeoutMs: number,
	) {
		super(message);
		this.name = "TimeoutError";
	}
}

/**
 * Race a promise against a timeout. Rejects with TimeoutError if the
 * timeout fires first.
 *
 * IMPORTANT: The original promise is NOT cancelled — only the race is resolved.
 * If you need cancellation, pass an AbortController and abort it in the caller.
 */
export function withTimeout<T>(promise: Promise<T>, timeoutMs: number, label?: string): Promise<T> {
	if (timeoutMs <= 0 || !Number.isFinite(timeoutMs)) {
		return promise;
	}

	return new Promise<T>((resolve, reject) => {
		let settled = false;

		const timer = setTimeout(() => {
			if (!settled) {
				settled = true;
				reject(
					new TimeoutError(`${label ?? "operation"} timed out after ${timeoutMs}ms`, timeoutMs),
				);
			}
		}, timeoutMs);

		// Prevent the timer from keeping the process alive
		if (typeof timer === "object" && "unref" in timer) {
			timer.unref();
		}

		promise.then(
			(value) => {
				if (!settled) {
					settled = true;
					clearTimeout(timer);
					resolve(value);
				}
			},
			(err) => {
				if (!settled) {
					settled = true;
					clearTimeout(timer);
					reject(err);
				}
			},
		);
	});
}

/**
 * fetch() with an AbortController-based timeout and proper cleanup.
 *
 * Unlike withTimeout(fetch(...)), this actually aborts the underlying
 * HTTP request when the timeout fires, freeing sockets.
 */
export async function fetchWithTimeout(
	url: string | URL,
	init: RequestInit | undefined,
	timeoutMs: number,
): Promise<Response> {
	if (timeoutMs <= 0 || !Number.isFinite(timeoutMs)) {
		return fetch(url, init);
	}

	const controller = new AbortController();

	// Relay external signal if present
	let externalAbortCleanup: (() => void) | undefined;
	const externalSignal = init?.signal;
	if (externalSignal) {
		if (externalSignal.aborted) {
			controller.abort(externalSignal.reason);
		} else {
			const onAbort = () => controller.abort(externalSignal.reason);
			externalSignal.addEventListener("abort", onAbort, { once: true });
			externalAbortCleanup = () => externalSignal.removeEventListener("abort", onAbort);
		}
	}

	const timer = setTimeout(() => {
		controller.abort(new TimeoutError(`fetch timed out after ${timeoutMs}ms`, timeoutMs));
	}, timeoutMs);

	if (typeof timer === "object" && "unref" in timer) {
		timer.unref();
	}

	try {
		return await fetch(url, {
			...init,
			signal: controller.signal,
		});
	} finally {
		clearTimeout(timer);
		externalAbortCleanup?.();
	}
}
