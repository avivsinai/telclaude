/**
 * Constant-time string/buffer comparison to prevent timing attacks.
 *
 * Wraps crypto.timingSafeEqual with length-safe handling:
 * - Returns false for different lengths without leaking which bytes differ
 * - Normalizes strings to Buffers for comparison
 */

import crypto from "node:crypto";

/**
 * Constant-time comparison of two strings or Buffers.
 * Returns false for mismatched lengths without timing leak.
 */
export function safeEqual(a: string | Buffer, b: string | Buffer): boolean {
	const aBuf = typeof a === "string" ? Buffer.from(a) : a;
	const bBuf = typeof b === "string" ? Buffer.from(b) : b;

	if (aBuf.length !== bBuf.length) {
		// Perform a dummy comparison to avoid leaking length difference via timing
		crypto.timingSafeEqual(aBuf, aBuf);
		return false;
	}

	return crypto.timingSafeEqual(aBuf, bBuf);
}
