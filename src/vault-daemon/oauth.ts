/**
 * OAuth2 token refresh handling.
 *
 * The vault sidecar stores refresh tokens and handles token refresh internally.
 * Connectors only see valid access tokens - they never handle refresh logic.
 *
 * NOTE: This module performs outbound HTTP to token endpoints during refresh.
 * In production, the vault container MUST allow egress to OAuth token endpoints.
 *
 * Security:
 * - Refresh tokens stored encrypted in vault
 * - Access tokens cached in memory with expiry
 * - Token refresh happens automatically before expiry
 * - Timeout enforced on token endpoint requests
 */

import { getChildLogger } from "../logging.js";
import type { OAuth2Credential } from "./protocol.js";

const logger = getChildLogger({ module: "vault-oauth" });

/**
 * Sanitize error messages to prevent credential leakage.
 * Removes URLs which may appear in error messages.
 */
function sanitizeError(err: unknown): string {
	const message = String(err);
	// Replace URLs (may contain tokens in query string or reveal token endpoints)
	return message.replace(/https?:\/\/[^\s]+/g, "[URL REDACTED]");
}

// Token endpoint request timeout (30 seconds)
const TOKEN_REQUEST_TIMEOUT_MS = 30 * 1000;

// ═══════════════════════════════════════════════════════════════════════════════
// Token Cache
// ═══════════════════════════════════════════════════════════════════════════════

interface CachedToken {
	accessToken: string;
	expiresAt: number; // Unix timestamp (ms)
}

// In-memory cache of access tokens (keyed by target)
const tokenCache = new Map<string, CachedToken>();

// In-flight refresh deduplication (prevents thundering herd)
// Concurrent requests for the same target share a single refresh operation
const inFlightRefresh = new Map<string, Promise<GetTokenResponse>>();

// Buffer before expiry to refresh (5 minutes)
const EXPIRY_BUFFER_MS = 5 * 60 * 1000;

// ═══════════════════════════════════════════════════════════════════════════════
// Token Refresh Response
// ═══════════════════════════════════════════════════════════════════════════════

interface TokenResponse {
	access_token: string;
	token_type: string;
	expires_in?: number; // seconds
	refresh_token?: string; // Some providers return a new refresh token
	scope?: string;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════════════════

export interface GetTokenResult {
	ok: true;
	token: string;
	expiresAt: number; // Unix timestamp in milliseconds
	newRefreshToken?: string; // Present if provider rotated the refresh token
}

export interface GetTokenError {
	ok: false;
	error: string;
}

export type GetTokenResponse = GetTokenResult | GetTokenError;

/**
 * Get a valid access token for an OAuth2 credential.
 * Handles automatic refresh if the cached token is expired or about to expire.
 *
 * SECURITY: Uses in-flight deduplication to prevent thundering herd - concurrent
 * requests for the same target share a single refresh operation.
 *
 * NOTE: If the provider rotates refresh tokens, the caller MUST persist the
 * new refresh token from the response, otherwise future refreshes will fail.
 *
 * @param target - The target (host) this credential is for (used as cache key)
 * @param credential - The OAuth2 credential with refresh token
 * @returns The current valid access token and its expiry, plus new refresh token if rotated
 */
export async function getAccessToken(
	target: string,
	credential: OAuth2Credential,
): Promise<GetTokenResponse> {
	const now = Date.now();

	// Check cache first
	const cached = tokenCache.get(target);
	if (cached && cached.expiresAt > now + EXPIRY_BUFFER_MS) {
		logger.debug(
			{ target, expiresIn: Math.floor((cached.expiresAt - now) / 1000) },
			"using cached token",
		);
		return {
			ok: true,
			token: cached.accessToken,
			expiresAt: cached.expiresAt,
		};
	}

	// Check if there's already a refresh in progress for this target
	const existingRefresh = inFlightRefresh.get(target);
	if (existingRefresh) {
		logger.debug({ target }, "waiting for in-flight refresh");
		return existingRefresh;
	}

	// Start a new refresh and add it to the in-flight map
	const refreshPromise = doTokenRefresh(target, credential);
	inFlightRefresh.set(target, refreshPromise);

	try {
		return await refreshPromise;
	} finally {
		// Clean up the in-flight entry
		inFlightRefresh.delete(target);
	}
}

/**
 * Internal: Actually perform the token refresh.
 */
async function doTokenRefresh(
	target: string,
	credential: OAuth2Credential,
): Promise<GetTokenResponse> {
	const now = Date.now();
	logger.info({ target }, "refreshing OAuth2 token");

	try {
		const tokenResponse = await refreshToken(credential);

		// Calculate expiry (default 1 hour if not provided)
		const expiresInMs = (tokenResponse.expires_in ?? 3600) * 1000;
		const expiresAt = now + expiresInMs;

		// Cache the token
		tokenCache.set(target, {
			accessToken: tokenResponse.access_token,
			expiresAt,
		});

		// Check for refresh token rotation
		const newRefreshToken = tokenResponse.refresh_token;
		if (newRefreshToken && newRefreshToken !== credential.refreshToken) {
			logger.info({ target }, "OAuth2 provider rotated refresh token");
		}

		logger.info({ target, expiresIn: tokenResponse.expires_in ?? 3600 }, "OAuth2 token refreshed");

		return {
			ok: true,
			token: tokenResponse.access_token,
			expiresAt,
			newRefreshToken: newRefreshToken !== credential.refreshToken ? newRefreshToken : undefined,
		};
	} catch (err) {
		// SECURITY: Sanitize error to prevent URL leakage in logs AND returned errors
		const sanitized = sanitizeError(err);
		logger.error({ target, error: sanitized }, "OAuth2 token refresh failed");
		return {
			ok: false,
			error: `Token refresh failed: ${sanitized}`,
		};
	}
}

/**
 * Invalidate a cached token (e.g., when credential is deleted).
 */
export function invalidateToken(target: string): void {
	tokenCache.delete(target);
	logger.debug({ target }, "invalidated cached token");
}

/**
 * Clear all cached tokens.
 */
export function clearTokenCache(): void {
	tokenCache.clear();
	logger.debug("cleared all cached tokens");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Token Refresh
// ═══════════════════════════════════════════════════════════════════════════════

async function refreshToken(credential: OAuth2Credential): Promise<TokenResponse> {
	const body = new URLSearchParams({
		grant_type: "refresh_token",
		client_id: credential.clientId,
		client_secret: credential.clientSecret,
		refresh_token: credential.refreshToken,
	});

	if (credential.scope) {
		body.set("scope", credential.scope);
	}

	// Use AbortController for timeout
	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), TOKEN_REQUEST_TIMEOUT_MS);

	try {
		const response = await fetch(credential.tokenEndpoint, {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
			},
			body: body.toString(),
			signal: controller.signal,
			// SECURITY: Disable redirects - a redirect from a token endpoint is an error.
			// Following redirects could leak client_secret and refresh_token.
			redirect: "error",
		});

		if (!response.ok) {
			const errorText = await response.text();
			throw new Error(`Token endpoint returned ${response.status}: ${errorText}`);
		}

		const tokenResponse = (await response.json()) as TokenResponse;

		if (!tokenResponse.access_token) {
			throw new Error("Token endpoint did not return access_token");
		}

		return tokenResponse;
	} catch (err) {
		if (err instanceof Error && err.name === "AbortError") {
			throw new Error(`Token endpoint request timed out after ${TOKEN_REQUEST_TIMEOUT_MS}ms`);
		}
		throw err;
	} finally {
		clearTimeout(timeoutId);
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Cleanup Timer
// ═══════════════════════════════════════════════════════════════════════════════

let cleanupTimer: NodeJS.Timeout | null = null;

/**
 * Start the token cache cleanup timer.
 * Removes expired tokens periodically.
 */
export function startCleanupTimer(): void {
	if (cleanupTimer) return;

	cleanupTimer = setInterval(() => {
		const now = Date.now();
		for (const [target, cached] of tokenCache.entries()) {
			if (cached.expiresAt <= now) {
				tokenCache.delete(target);
				logger.debug({ target }, "removed expired token from cache");
			}
		}
	}, 60 * 1000); // Every minute

	cleanupTimer.unref();
}

/**
 * Stop the token cache cleanup timer.
 */
export function stopCleanupTimer(): void {
	if (cleanupTimer) {
		clearInterval(cleanupTimer);
		cleanupTimer = null;
	}
}
