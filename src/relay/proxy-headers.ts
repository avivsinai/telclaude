/**
 * Shared response header filtering for relay proxy modules.
 *
 * Extracted from anthropic-proxy, git-proxy, and http-credential-proxy
 * which each had inline sets/arrays of excluded response headers.
 *
 * These headers must be stripped when proxying because:
 * - Hop-by-hop headers (connection, keep-alive, etc.) are per-connection
 * - content-encoding is stripped because fetch() auto-decompresses,
 *   so the body we stream is already decoded
 * - content-length is conditionally stripped when upstream used
 *   content-encoding, since the original compressed length is wrong
 */

import type http from "node:http";

export const EXCLUDED_RESPONSE_HEADERS = new Set([
	"transfer-encoding",
	"connection",
	"keep-alive",
	"content-encoding",
	"proxy-authenticate",
	"proxy-authorization",
	"te",
	"trailer",
	"upgrade",
]);

/**
 * Forward upstream response headers to the client response,
 * filtering out hop-by-hop and decoded headers.
 */
export function forwardResponseHeaders(upstream: Response, res: http.ServerResponse): void {
	const hadContentEncoding = upstream.headers.has("content-encoding");
	upstream.headers.forEach((value, key) => {
		const lower = key.toLowerCase();
		if (EXCLUDED_RESPONSE_HEADERS.has(lower)) return;
		// If upstream used content-encoding, also strip content-length since
		// fetch() auto-decompresses and the original compressed length is wrong.
		if (hadContentEncoding && lower === "content-length") return;
		res.setHeader(key, value);
	});
}
