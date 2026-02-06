/**
 * Session Token Manager for relay.
 *
 * Issues Ed25519-signed session tokens to agents. Tokens are verified locally
 * using the public key (no vault roundtrip for verification).
 *
 * Features:
 * - Token issuance via vault's sign-token
 * - Rotation: new token at T-10min, both old+new valid during 5min grace
 * - `/v1/auth/token-exchange`: one-time bootstrap (authenticated with static secret)
 * - `/v1/auth/token-refresh`: proactive refresh before expiry
 * - Auto-strict: after exchange, block v1/v2 for that scope
 */

import crypto from "node:crypto";

import { getChildLogger } from "../logging.js";
import { getVaultClient, isVaultAvailable } from "../vault-daemon/client.js";

const logger = getChildLogger({ module: "token-manager" });

const DEFAULT_TOKEN_TTL_MS = 60 * 60 * 1000; // 1 hour
const ROTATION_GRACE_MS = 5 * 60 * 1000; // 5 min grace for old tokens
const REFRESH_WINDOW_MS = 10 * 60 * 1000; // agent should refresh at T-10min

type IssuedToken = {
	token: string;
	expiresAt: number;
	scope: string;
	sessionId: string;
};

type ScopeState = {
	current: IssuedToken;
	previous?: IssuedToken; // during rotation grace period
	autoStrict: boolean; // v1/v2 blocked after first exchange
};

// ═══════════════════════════════════════════════════════════════════════════════
// Token Manager
// ═══════════════════════════════════════════════════════════════════════════════

let publicKeyCache: string | null = null;
const scopeTokens = new Map<string, ScopeState>();

/**
 * Initialize the token manager. Fetches the Ed25519 public key from vault.
 * Must be called at relay startup.
 */
export async function initTokenManager(): Promise<{ publicKey: string } | null> {
	if (!(await isVaultAvailable())) {
		logger.info("vault not available, session tokens disabled");
		return null;
	}

	try {
		const client = getVaultClient();
		const response = await client.getPublicKey({ timeout: 5000 });
		if (response.ok) {
			publicKeyCache = response.publicKey;
			logger.info("token manager initialized with Ed25519 public key");
			return { publicKey: response.publicKey };
		}
		logger.warn("failed to get public key from vault");
		return null;
	} catch (err) {
		logger.warn({ error: String(err) }, "token manager init failed");
		return null;
	}
}

/**
 * Check if token manager is active (vault available with signing key).
 */
export function isTokenManagerActive(): boolean {
	return publicKeyCache !== null;
}

/**
 * Get the cached public key for local verification.
 */
export function getPublicKey(): string | null {
	return publicKeyCache;
}

/**
 * Issue a new session token for a scope.
 */
export async function issueToken(
	scope: string,
	ttlMs = DEFAULT_TOKEN_TTL_MS,
): Promise<IssuedToken | null> {
	if (!publicKeyCache) return null;

	const sessionId = crypto.randomBytes(16).toString("hex");
	const client = getVaultClient();

	try {
		const response = await client.signToken(scope, sessionId, ttlMs, { timeout: 5000 });
		if (response.type === "sign-token" && response.ok) {
			const issued: IssuedToken = {
				token: response.token,
				expiresAt: response.expiresAt,
				scope,
				sessionId,
			};

			// Track scope state
			const existing = scopeTokens.get(scope);
			if (existing) {
				// Rotation: current becomes previous (grace period)
				scopeTokens.set(scope, {
					current: issued,
					previous: existing.current,
					autoStrict: existing.autoStrict,
				});

				// Clear previous after grace period
				setTimeout(() => {
					const state = scopeTokens.get(scope);
					if (state?.previous?.sessionId === existing.current.sessionId) {
						state.previous = undefined;
					}
				}, ROTATION_GRACE_MS);
			} else {
				scopeTokens.set(scope, { current: issued, autoStrict: false });
			}

			logger.info(
				{ scope, sessionId, expiresAt: response.expiresAt, ttlMs },
				"issued session token",
			);
			return issued;
		}
		return null;
	} catch (err) {
		logger.error({ error: String(err), scope }, "failed to issue token");
		return null;
	}
}

/**
 * Verify a v3 session token locally using the cached public key.
 * No vault roundtrip needed.
 */
export function verifyTokenLocally(token: string): {
	valid: boolean;
	scope?: string;
	sessionId?: string;
	expiresAt?: number;
	error?: string;
} {
	if (!publicKeyCache) {
		return { valid: false, error: "Token manager not initialized" };
	}

	// Parse token: v3:{scope}:{sessionId}:{createdAt}:{expiresAt}:{signature}
	const parts = token.split(":");
	if (parts.length !== 6) {
		return { valid: false, error: "Invalid token format" };
	}

	const [version, scope, sessionId, createdAtStr, expiresAtStr, signatureB64url] = parts;

	if (version !== "v3") {
		return { valid: false, error: `Invalid token version: ${version}` };
	}

	if (!scope || !sessionId || !signatureB64url) {
		return { valid: false, error: "Missing token fields" };
	}

	const expiresAt = Number(expiresAtStr);
	if (!Number.isFinite(expiresAt)) {
		return { valid: false, error: "Invalid expiry" };
	}

	if (expiresAt < Date.now()) {
		return { valid: false, error: "Token expired" };
	}

	// Verify Ed25519 signature
	const payload = `v3:${scope}:${sessionId}:${createdAtStr}:${expiresAtStr}`;
	try {
		const publicKey = Buffer.from(publicKeyCache, "base64");
		const signature = Buffer.from(signatureB64url, "base64url");
		const valid = crypto.verify(
			null,
			Buffer.from(payload),
			{ key: publicKey, format: "der", type: "spki" },
			signature,
		);

		if (!valid) {
			return { valid: false, error: "Invalid signature" };
		}

		return { valid: true, scope, sessionId, expiresAt };
	} catch {
		return { valid: false, error: "Signature verification failed" };
	}
}

/**
 * Check if v1/v2 auth should be blocked for a scope (auto-strict mode).
 */
export function isScopeAutoStrict(scope: string): boolean {
	return scopeTokens.get(scope)?.autoStrict ?? false;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Token Exchange & Refresh Endpoints
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Handle token exchange request.
 * Agent authenticates with static secret (v1/v2) and receives a session token.
 * After successful exchange, auto-strict mode is enabled for the scope.
 */
export async function handleTokenExchange(scope: string): Promise<{
	ok: boolean;
	token?: string;
	expiresAt?: number;
	publicKey?: string;
	refreshWindowMs?: number;
	error?: string;
}> {
	const issued = await issueToken(scope);
	if (!issued) {
		return { ok: false, error: "Token issuance failed" };
	}

	// Enable auto-strict: block v1/v2 for this scope
	const state = scopeTokens.get(scope);
	if (state) {
		state.autoStrict = true;
		logger.info({ scope }, "auto-strict enabled: v1/v2 auth blocked for scope");
	}

	return {
		ok: true,
		token: issued.token,
		expiresAt: issued.expiresAt,
		publicKey: publicKeyCache ?? undefined,
		refreshWindowMs: REFRESH_WINDOW_MS,
	};
}

/**
 * Handle token refresh request.
 * Agent provides current token and receives a new one.
 */
export async function handleTokenRefresh(currentToken: string): Promise<{
	ok: boolean;
	token?: string;
	expiresAt?: number;
	error?: string;
}> {
	const verified = verifyTokenLocally(currentToken);
	if (!verified.valid || !verified.scope) {
		return { ok: false, error: verified.error ?? "Invalid token" };
	}

	const issued = await issueToken(verified.scope);
	if (!issued) {
		return { ok: false, error: "Token refresh failed" };
	}

	logger.info(
		{ scope: verified.scope, oldSessionId: verified.sessionId, newSessionId: issued.sessionId },
		"refreshed session token",
	);

	return {
		ok: true,
		token: issued.token,
		expiresAt: issued.expiresAt,
	};
}
