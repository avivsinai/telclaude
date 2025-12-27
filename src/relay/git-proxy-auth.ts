/**
 * Git Proxy Session Token Authentication
 *
 * Provides scoped session tokens for git proxy authentication.
 * These tokens are useless outside our system - they only authenticate
 * with the git proxy, not with GitHub directly.
 *
 * Token format: base64(JSON({ sessionId, createdAt, expiresAt, signature }))
 * Signature: HMAC-SHA256(sessionId + createdAt + expiresAt, secret)
 */

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

import { getChildLogger } from "../logging.js";

const logger = getChildLogger({ module: "git-proxy-auth" });

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

export interface SessionTokenPayload {
	sessionId: string;
	createdAt: number;
	expiresAt: number;
}

interface SessionToken extends SessionTokenPayload {
	signature: string;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Secret Management
// ═══════════════════════════════════════════════════════════════════════════════

// The session secret should be set via environment variable in production.
// If not set, generate a random one (will invalidate tokens on restart).
let sessionSecret: string | null = null;

function getSessionSecret(): string {
	if (sessionSecret) return sessionSecret;

	const envSecret = process.env.TELCLAUDE_GIT_PROXY_SECRET;
	if (envSecret) {
		sessionSecret = envSecret;
		return sessionSecret;
	}

	// Generate random secret (tokens won't persist across restarts)
	sessionSecret = randomBytes(32).toString("hex");
	logger.warn(
		"using randomly generated git proxy secret (tokens will not persist across restarts)",
	);
	return sessionSecret;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Token Operations
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Compute HMAC signature for token data.
 */
function computeSignature(sessionId: string, createdAt: number, expiresAt: number): string {
	const secret = getSessionSecret();
	const data = `${sessionId}:${createdAt}:${expiresAt}`;
	return createHmac("sha256", secret).update(data).digest("hex");
}

/**
 * Generate a new session token.
 *
 * @param sessionId - Unique identifier for the session
 * @param ttlMs - Time to live in milliseconds (default: 1 hour)
 * @returns Base64-encoded token string
 */
export function generateSessionToken(sessionId: string, ttlMs: number = 60 * 60 * 1000): string {
	const now = Date.now();
	const createdAt = now;
	const expiresAt = now + ttlMs;

	const signature = computeSignature(sessionId, createdAt, expiresAt);

	const token: SessionToken = {
		sessionId,
		createdAt,
		expiresAt,
		signature,
	};

	return Buffer.from(JSON.stringify(token)).toString("base64");
}

/**
 * Validate a session token.
 *
 * @param tokenString - Base64-encoded token string
 * @returns Token payload if valid, null if invalid or expired
 */
export function validateSessionToken(tokenString: string): SessionTokenPayload | null {
	try {
		// Decode base64
		const decoded = Buffer.from(tokenString, "base64").toString("utf-8");
		const token = JSON.parse(decoded) as SessionToken;

		// Validate required fields
		if (!token.sessionId || !token.createdAt || !token.expiresAt || !token.signature) {
			logger.debug("invalid token: missing required fields");
			return null;
		}

		// Check expiration
		if (token.expiresAt < Date.now()) {
			logger.debug({ sessionId: token.sessionId }, "token expired");
			return null;
		}

		// Verify signature using timing-safe comparison to prevent timing attacks
		const expectedSignature = computeSignature(token.sessionId, token.createdAt, token.expiresAt);
		const signatureBuf = Buffer.from(token.signature);
		const expectedBuf = Buffer.from(expectedSignature);

		// Lengths must match for timingSafeEqual to work correctly
		if (signatureBuf.length !== expectedBuf.length || !timingSafeEqual(signatureBuf, expectedBuf)) {
			logger.warn({ sessionId: token.sessionId }, "token signature mismatch");
			return null;
		}

		return {
			sessionId: token.sessionId,
			createdAt: token.createdAt,
			expiresAt: token.expiresAt,
		};
	} catch (err) {
		logger.debug({ error: String(err) }, "failed to parse session token");
		return null;
	}
}

/**
 * Generate a unique session ID.
 */
export function generateSessionId(): string {
	return randomBytes(16).toString("hex");
}

/**
 * Decode a token without validating (for debugging).
 * Returns null if token cannot be decoded.
 */
export function decodeToken(tokenString: string): SessionToken | null {
	try {
		const decoded = Buffer.from(tokenString, "base64").toString("utf-8");
		return JSON.parse(decoded) as SessionToken;
	} catch {
		return null;
	}
}
