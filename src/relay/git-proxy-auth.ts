/**
 * Git Proxy Session Token Authentication
 *
 * Provides scoped git proxy authentication tokens. The relay is the only holder
 * of the signing secret; runtimes receive short-lived, peer-bound bearer tokens
 * that name the allowed repositories, operations, and push refs. These tokens
 * authenticate only to the telclaude git proxy, never to GitHub directly.
 *
 * Legacy base64 HMAC session tokens are retained only for explicitly enabled
 * local compatibility (`TELCLAUDE_GIT_PROXY_ALLOW_LEGACY_TOKENS=1`).
 */

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

import { verifySessionToken } from "../internal-auth.js";
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

export type GitProxyPermission = "fetch" | "push";

export interface GitProxyTokenPolicy {
	repositories: string[];
	permissions: GitProxyPermission[];
	allowedRefs: string[];
	deniedRefs: string[];
}

export interface GitProxyTokenPayload extends SessionTokenPayload, GitProxyTokenPolicy {
	version: 1;
	tokenScope: "git";
	peerAddress: string;
	nonce: string;
}

interface SessionToken extends SessionTokenPayload {
	signature: string;
}

export const GIT_PROXY_TOKEN_PREFIX = "tc-git-proxy-v1";

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

function signScopedGitToken(encodedPayload: string, secret: string): string {
	return createHmac("sha256", secret).update(encodedPayload).digest("base64url");
}

function constantTimeEqual(a: string, b: string): boolean {
	const aBuf = Buffer.from(a);
	const bBuf = Buffer.from(b);
	return aBuf.length === bBuf.length && timingSafeEqual(aBuf, bBuf);
}

export function normalizeObservedPeerAddress(value: string | undefined): string | null {
	if (!value) return null;
	const trimmed = value.trim();
	if (!trimmed) return null;
	if (trimmed.startsWith("::ffff:")) return trimmed.slice("::ffff:".length);
	return trimmed;
}

function isSingleLineTokenValue(value: unknown, maxLength: number): value is string {
	return (
		typeof value === "string" &&
		value.trim() === value &&
		value.length > 0 &&
		value.length <= maxLength &&
		!value.includes("\0") &&
		!value.includes("\r") &&
		!value.includes("\n")
	);
}

function isStringArray(value: unknown, maxItems: number, maxItemLength: number): value is string[] {
	return (
		Array.isArray(value) &&
		value.length > 0 &&
		value.length <= maxItems &&
		value.every((item) => isSingleLineTokenValue(item, maxItemLength))
	);
}

function isPermissionArray(value: unknown): value is GitProxyPermission[] {
	return (
		Array.isArray(value) &&
		value.length > 0 &&
		value.length <= 2 &&
		value.every((item) => item === "fetch" || item === "push")
	);
}

function isGitProxyPayload(value: unknown): value is GitProxyTokenPayload {
	if (!value || typeof value !== "object") return false;
	const candidate = value as Partial<GitProxyTokenPayload>;
	return (
		candidate.version === 1 &&
		candidate.tokenScope === "git" &&
		isSingleLineTokenValue(candidate.sessionId, 160) &&
		typeof candidate.createdAt === "number" &&
		Number.isFinite(candidate.createdAt) &&
		typeof candidate.expiresAt === "number" &&
		Number.isFinite(candidate.expiresAt) &&
		isSingleLineTokenValue(candidate.peerAddress, 128) &&
		isSingleLineTokenValue(candidate.nonce, 128) &&
		isStringArray(candidate.repositories, 100, 200) &&
		isPermissionArray(candidate.permissions) &&
		isStringArray(candidate.allowedRefs, 100, 200) &&
		Array.isArray(candidate.deniedRefs) &&
		candidate.deniedRefs.length <= 100 &&
		candidate.deniedRefs.every((item) => isSingleLineTokenValue(item, 200))
	);
}

export function mintGitProxyToken(input: {
	secret: string;
	peerAddress: string;
	sessionId: string;
	repositories: string[];
	permissions: GitProxyPermission[];
	allowedRefs: string[];
	deniedRefs: string[];
	ttlMs: number;
	now?: number;
}): string {
	const now = input.now ?? Date.now();
	const payload: GitProxyTokenPayload = {
		version: 1,
		tokenScope: "git",
		sessionId: input.sessionId,
		createdAt: now,
		expiresAt: now + input.ttlMs,
		peerAddress: normalizeObservedPeerAddress(input.peerAddress) ?? input.peerAddress,
		nonce: randomBytes(16).toString("hex"),
		repositories: input.repositories,
		permissions: input.permissions,
		allowedRefs: input.allowedRefs,
		deniedRefs: input.deniedRefs,
	};
	const encodedPayload = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
	const signature = signScopedGitToken(encodedPayload, input.secret);
	return `${GIT_PROXY_TOKEN_PREFIX}.${encodedPayload}.${signature}`;
}

export function verifyGitProxyToken(
	token: string | null | undefined,
	input: {
		secret: string;
		peerAddress: string | undefined;
		now?: number;
	},
): ({ ok: true } & GitProxyTokenPayload) | { ok: false; reason: string } {
	if (!token) return { ok: false, reason: "missing token" };
	const parts = token.split(".");
	if (parts.length !== 3 || parts[0] !== GIT_PROXY_TOKEN_PREFIX) {
		return { ok: false, reason: "token is not a scoped git proxy token" };
	}
	const [, encodedPayload, signature] = parts as [string, string, string];
	const expectedSignature = signScopedGitToken(encodedPayload, input.secret);
	if (!constantTimeEqual(signature, expectedSignature)) {
		return { ok: false, reason: "signature mismatch" };
	}

	let payload: unknown;
	try {
		payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8"));
	} catch {
		return { ok: false, reason: "payload is not parseable" };
	}
	if (!isGitProxyPayload(payload)) {
		return { ok: false, reason: "payload is invalid" };
	}

	const observedPeerAddress = normalizeObservedPeerAddress(input.peerAddress);
	if (!observedPeerAddress || payload.peerAddress !== observedPeerAddress) {
		return { ok: false, reason: "peer address mismatch" };
	}

	const now = input.now ?? Date.now();
	if (payload.expiresAt <= now) return { ok: false, reason: "token expired" };
	if (payload.createdAt > now + 5_000) return { ok: false, reason: "token issued in the future" };

	return { ok: true, ...payload };
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

/**
 * Validate a session token, supporting both legacy HMAC tokens and v3 Ed25519 tokens.
 * Tries v3 first (if public key available), then falls back to legacy HMAC.
 *
 * @param tokenString - Token string (base64 HMAC or v3:scope:... format)
 * @param publicKeyBase64 - Ed25519 public key for v3 verification (optional)
 * @returns Token payload if valid, null if invalid or expired
 */
export function validateSessionTokenV3(
	tokenString: string,
	publicKeyBase64: string | null,
): SessionTokenPayload | null {
	// Try v3 session token (starts with "v3:")
	if (tokenString.startsWith("v3:") && publicKeyBase64) {
		const result = verifySessionToken(tokenString, publicKeyBase64);
		if (result?.ok) {
			// Map v3 fields to SessionTokenPayload
			const parts = tokenString.split(":");
			const createdAt = Number(parts[3]);
			const expiresAt = Number(parts[4]);
			return {
				sessionId: parts[2] ?? "",
				createdAt,
				expiresAt,
			};
		}
		// v3 token but invalid - don't fall through to HMAC
		return null;
	}

	// Fall back to legacy HMAC validation
	return validateSessionToken(tokenString);
}
