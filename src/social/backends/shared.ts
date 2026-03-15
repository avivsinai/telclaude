/**
 * Shared utilities for social backend API clients.
 */

export function safeJsonParse<T = unknown>(text: string): T | null {
	try {
		return JSON.parse(text) as T;
	} catch {
		return null;
	}
}

export type ApiResult<T> =
	| { ok: true; status: number; data: T }
	| { ok: false; status: number; error: string };

export type HttpStatusError = Error & {
	status: number;
	statusCode: number;
};

export function createHttpStatusError(message: string, status: number): HttpStatusError {
	const error = new Error(message) as HttpStatusError;
	error.status = status;
	error.statusCode = status;
	return error;
}

/**
 * Generic social API request handler.
 * Parses JSON, handles errors, returns typed result.
 *
 * @param extractError - Optional custom error extractor for service-specific error shapes.
 *   Receives the parsed payload, the raw response text, and the statusText.
 *   Return null to fall back to the default (raw text or statusText).
 */
export async function socialApiRequest<T>(
	fetchImpl: typeof fetch,
	url: string,
	init: RequestInit,
	extractError?: (payload: unknown, raw: string, statusText: string) => string | null,
): Promise<ApiResult<T>> {
	const response = await fetchImpl(url, init);
	const status = response.status;
	const raw = await response.text();
	const payload = raw ? safeJsonParse(raw) : null;

	if (!response.ok) {
		let error: string;
		const custom = extractError?.(payload, raw, response.statusText);
		if (custom) {
			error = custom;
		} else {
			error = raw || response.statusText;
		}
		return { ok: false, status, error };
	}

	return { ok: true, status, data: payload as T };
}
