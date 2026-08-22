import { isTransientNetworkError } from "../infra/network-errors.js";

const RETRYABLE_RELAY_STATUSES = new Set([502, 503, 504]);
const DEFAULT_BASE_DELAY_MS = 1_000;
const DEFAULT_MAX_DELAY_MS = 30_000;
const DEFAULT_JITTER = 0.25;

export type WhatsAppInboundForwardRetryInfo = {
	readonly attempt: number;
	readonly delayMs: number;
	readonly status?: number;
};

export type WhatsAppInboundForwardRetryOptions = {
	readonly fetchImpl?: typeof fetch;
	readonly timeoutMs: number;
	readonly signal?: AbortSignal;
	readonly baseDelayMs?: number;
	readonly maxDelayMs?: number;
	readonly jitter?: number;
	readonly onRetry?: (info: WhatsAppInboundForwardRetryInfo) => void;
};

/**
 * Keep one signed inbound event in memory until the relay accepts it.
 * Transport failures are expected while the relay is still starting; 4xx
 * responses are returned to the caller because retrying cannot repair them.
 */
export async function forwardWhatsAppInboundWithRetry(
	url: string,
	init: RequestInit,
	options: WhatsAppInboundForwardRetryOptions,
): Promise<Response> {
	const fetchImpl = options.fetchImpl ?? fetch;
	const baseDelayMs = Math.max(0, options.baseDelayMs ?? DEFAULT_BASE_DELAY_MS);
	const maxDelayMs = Math.max(0, options.maxDelayMs ?? DEFAULT_MAX_DELAY_MS);
	const jitter = Math.min(1, Math.max(0, options.jitter ?? DEFAULT_JITTER));
	let attempt = 0;

	while (true) {
		if (options.signal?.aborted) throw createAbortError();
		attempt += 1;

		let response: Response;
		try {
			response = await fetchImpl(url, {
				...init,
				signal: createAttemptSignal(options.signal, options.timeoutMs),
			});
		} catch (error) {
			if (options.signal?.aborted) throw createAbortError();
			if (!isTransientNetworkError(error)) throw error;
			await waitBeforeRetry(options, {
				attempt,
				delayMs: computeRetryDelay(baseDelayMs, maxDelayMs, jitter, attempt),
			});
			continue;
		}

		if (!RETRYABLE_RELAY_STATUSES.has(response.status)) return response;
		try {
			await response.body?.cancel();
		} catch {
			// The response body is already unusable; the next attempt is still safe.
		}
		await waitBeforeRetry(options, {
			attempt,
			delayMs: computeRetryDelay(baseDelayMs, maxDelayMs, jitter, attempt),
			status: response.status,
		});
	}
}

async function waitBeforeRetry(
	options: WhatsAppInboundForwardRetryOptions,
	info: WhatsAppInboundForwardRetryInfo,
): Promise<void> {
	options.onRetry?.(info);
	await sleepWithAbort(info.delayMs, options.signal);
}

function computeRetryDelay(
	baseDelayMs: number,
	maxDelayMs: number,
	jitter: number,
	attempt: number,
): number {
	const capped = Math.min(maxDelayMs, baseDelayMs * 2 ** (attempt - 1));
	const jitterRange = capped * jitter;
	const withJitter = capped + (Math.random() - 0.5) * 2 * jitterRange;
	return Math.max(0, Math.min(maxDelayMs, Math.round(withJitter)));
}

function createAttemptSignal(signal: AbortSignal | undefined, timeoutMs: number): AbortSignal {
	const timeoutSignal = AbortSignal.timeout(Math.max(1, timeoutMs));
	return signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;
}

function sleepWithAbort(ms: number, signal?: AbortSignal): Promise<void> {
	return new Promise((resolve, reject) => {
		if (signal?.aborted) {
			reject(createAbortError());
			return;
		}

		const timer = setTimeout(() => {
			signal?.removeEventListener("abort", onAbort);
			resolve();
		}, ms);
		timer.unref?.();

		const onAbort = () => {
			clearTimeout(timer);
			signal?.removeEventListener("abort", onAbort);
			reject(createAbortError());
		};
		signal?.addEventListener("abort", onAbort, { once: true });
	});
}

function createAbortError(): Error {
	const error = new Error("WhatsApp inbound forward aborted");
	error.name = "AbortError";
	return error;
}
