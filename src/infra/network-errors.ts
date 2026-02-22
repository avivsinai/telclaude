/**
 * Error classification utilities for network resilience.
 *
 * Provides BFS traversal through error cause chains to detect transient
 * network errors, abort errors, and other recoverable conditions.
 */

/** Error codes that indicate a transient network issue. */
const TRANSIENT_NETWORK_CODES = new Set([
	"ECONNRESET",
	"ECONNREFUSED",
	"ECONNABORTED",
	"ETIMEDOUT",
	"EPIPE",
	"ENETUNREACH",
	"EHOSTUNREACH",
	"EAI_AGAIN",
	"ENOTFOUND",
	"UND_ERR_CONNECT_TIMEOUT",
	"UND_ERR_SOCKET",
	"UND_ERR_HEADERS_TIMEOUT",
	"UND_ERR_BODY_TIMEOUT",
]);

/** Error messages (substrings) that indicate a transient network issue. */
const TRANSIENT_MESSAGE_PATTERNS = [
	"fetch failed",
	"network error",
	"socket hang up",
	"other side closed",
	"terminated",
	"ECONNRESET",
	"ETIMEDOUT",
	"ECONNREFUSED",
	"request to .* failed",
	"client network socket disconnected",
	"write EPIPE",
	"read ECONNRESET",
	"timed out after",
];

/**
 * Collect all error candidates from a (potentially nested) error.
 * BFS through `.cause`, `.reason`, `.errors` to find all relevant error objects.
 */
export function collectErrorCandidates(err: unknown, maxDepth = 5): unknown[] {
	const candidates: unknown[] = [];
	const queue: Array<{ value: unknown; depth: number }> = [{ value: err, depth: 0 }];
	const seen = new WeakSet<object>();

	while (queue.length > 0) {
		const item = queue.shift();
		if (!item) break;
		if (item.depth > maxDepth) continue;

		const val = item.value;
		if (val == null || typeof val !== "object") {
			if (val != null) candidates.push(val);
			continue;
		}

		if (seen.has(val as object)) continue;
		seen.add(val as object);
		candidates.push(val);

		const obj = val as Record<string, unknown>;
		const nextDepth = item.depth + 1;

		if (obj.cause != null) {
			queue.push({ value: obj.cause, depth: nextDepth });
		}
		if (obj.reason != null) {
			queue.push({ value: obj.reason, depth: nextDepth });
		}
		if (Array.isArray(obj.errors)) {
			for (const e of obj.errors) {
				queue.push({ value: e, depth: nextDepth });
			}
		}
	}

	return candidates;
}

/**
 * Check if an error (or any error in its cause chain) is a transient network error.
 * Also classifies TimeoutError as transient (temporary network/server slowness).
 */
export function isTransientNetworkError(err: unknown): boolean {
	const candidates = collectErrorCandidates(err);

	for (const candidate of candidates) {
		if (candidate == null) continue;

		if (typeof candidate === "object") {
			const obj = candidate as Record<string, unknown>;

			// Check error code
			if ("code" in obj) {
				const code = obj.code;
				if (typeof code === "string" && TRANSIENT_NETWORK_CODES.has(code)) {
					return true;
				}
			}

			// TimeoutError from our timeout utility
			if (obj.name === "TimeoutError") {
				return true;
			}
		}

		// Check error message
		const message = extractMessage(candidate);
		if (message && matchesTransientPattern(message)) {
			return true;
		}
	}

	return false;
}

/**
 * Check if an error is an AbortError (expected during shutdown / cancellation).
 */
export function isAbortError(err: unknown): boolean {
	const candidates = collectErrorCandidates(err);

	for (const candidate of candidates) {
		if (candidate == null) continue;

		if (typeof candidate === "object") {
			const obj = candidate as Record<string, unknown>;

			// DOMException AbortError
			if (obj.name === "AbortError") return true;

			// Node.js abort
			if (obj.code === "ABORT_ERR") return true;
		}

		const message = extractMessage(candidate);
		if (message) {
			const lower = message.toLowerCase();
			if (
				lower.includes("this operation was aborted") ||
				lower.includes("the operation was aborted") ||
				lower.includes("signal is aborted")
			) {
				return true;
			}
		}
	}

	return false;
}

/**
 * Check if an error is recoverable (transient network error or abort).
 */
export function isRecoverableError(err: unknown): boolean {
	return isTransientNetworkError(err) || isAbortError(err);
}

/**
 * Safely format an error to a string, avoiding circular references
 * and redacting URLs that might contain tokens.
 */
export function formatErrorSafe(err: unknown, maxLength = 500): string {
	if (err == null) return "unknown error";

	try {
		if (err instanceof Error) {
			let msg = `${err.name}: ${err.message}`;
			if (err.cause) {
				msg += ` [cause: ${formatErrorSafe(err.cause, maxLength / 2)}]`;
			}
			return truncate(redactUrls(msg), maxLength);
		}
		if (typeof err === "string") {
			return truncate(redactUrls(err), maxLength);
		}
		return truncate(redactUrls(String(err)), maxLength);
	} catch {
		return "error (could not format)";
	}
}

function extractMessage(val: unknown): string | null {
	if (typeof val === "string") return val;
	if (val instanceof Error) return val.message;
	if (typeof val === "object" && val !== null && "message" in val) {
		const msg = (val as { message: unknown }).message;
		if (typeof msg === "string") return msg;
	}
	return null;
}

function matchesTransientPattern(message: string): boolean {
	const lower = message.toLowerCase();
	return TRANSIENT_MESSAGE_PATTERNS.some((pattern) => lower.includes(pattern.toLowerCase()));
}

function redactUrls(str: string): string {
	return str.replace(/https?:\/\/[^\s]+/g, "[URL]");
}

function truncate(str: string, maxLength: number): string {
	if (str.length <= maxLength) return str;
	return `${str.slice(0, maxLength - 3)}...`;
}
