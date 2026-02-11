/**
 * PKCE (Proof Key for Code Exchange) challenge generation.
 *
 * RFC 7636: https://tools.ietf.org/html/rfc7636
 * Uses S256 method (SHA-256 hash of verifier).
 */

import { createHash, randomBytes } from "node:crypto";

/**
 * Generate a cryptographically random code verifier.
 * RFC 7636 requires 43-128 characters from the unreserved character set.
 */
export function generateCodeVerifier(length = 64): string {
	if (length < 43 || length > 128) {
		throw new RangeError("Code verifier length must be between 43 and 128");
	}
	return randomBytes(length).toString("base64url").slice(0, length);
}

/**
 * Generate the S256 code challenge from a code verifier.
 * challenge = BASE64URL(SHA256(verifier))
 */
export function generateCodeChallenge(verifier: string): string {
	return createHash("sha256").update(verifier).digest("base64url");
}

/**
 * Generate a PKCE challenge pair (verifier + challenge).
 */
export function generatePKCE(): { codeVerifier: string; codeChallenge: string } {
	const codeVerifier = generateCodeVerifier();
	const codeChallenge = generateCodeChallenge(codeVerifier);
	return { codeVerifier, codeChallenge };
}
