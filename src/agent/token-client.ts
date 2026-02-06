/**
 * Agent-side session token client.
 *
 * Handles:
 * - Bootstrap: exchange static secret for session token at startup
 * - Proactive refresh: schedule refresh at T-10min before expiry
 * - Header injection: provide session token for RPC calls
 * - Fallback: use static secrets if exchange fails
 */

import { buildInternalAuthHeaders, type InternalAuthScope } from "../internal-auth.js";
import { getChildLogger } from "../logging.js";

const logger = getChildLogger({ module: "agent-token-client" });

const DEFAULT_REFRESH_WINDOW_MS = 10 * 60 * 1000; // 10 min before expiry

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

type SessionToken = {
	token: string;
	expiresAt: number;
	scope: string;
	publicKey: string;
};

type ExchangeResponse = {
	ok: boolean;
	token?: string;
	expiresAt?: number;
	publicKey?: string;
	refreshWindowMs?: number;
	error?: string;
};

type RefreshResponse = {
	ok: boolean;
	token?: string;
	expiresAt?: number;
	error?: string;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Token Client
// ═══════════════════════════════════════════════════════════════════════════════

let currentToken: SessionToken | null = null;
let refreshTimer: ReturnType<typeof setTimeout> | null = null;
let refreshWindowMs = DEFAULT_REFRESH_WINDOW_MS;
let _publicKey: string | null = null;

/**
 * Bootstrap: exchange static credentials for a session token.
 * Called at agent startup.
 */
export async function bootstrapSessionToken(
	relayUrl: string,
	scope: InternalAuthScope,
): Promise<boolean> {
	const endpoint = `${relayUrl.replace(/\/+$/, "")}/v1/auth/token-exchange`;
	const body = JSON.stringify({ scope });

	try {
		const response = await fetch(endpoint, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				...buildInternalAuthHeaders("POST", "/v1/auth/token-exchange", body, { scope }),
			},
			body,
		});

		if (!response.ok) {
			const text = await response.text();
			logger.warn({ status: response.status, body: text }, "token exchange failed");
			return false;
		}

		const data = (await response.json()) as ExchangeResponse;
		if (!data.ok || !data.token || !data.expiresAt || !data.publicKey) {
			logger.warn({ error: data.error }, "token exchange returned error");
			return false;
		}

		currentToken = {
			token: data.token,
			expiresAt: data.expiresAt,
			scope,
			publicKey: data.publicKey,
		};
		_publicKey = data.publicKey;

		if (data.refreshWindowMs) {
			refreshWindowMs = data.refreshWindowMs;
		}

		scheduleRefresh(relayUrl);

		logger.info(
			{
				scope,
				expiresAt: data.expiresAt,
				ttlMs: data.expiresAt - Date.now(),
			},
			"session token acquired (Ed25519 v3)",
		);
		return true;
	} catch (err) {
		logger.warn({ error: String(err) }, "token exchange request failed");
		return false;
	}
}

/**
 * Schedule proactive token refresh before expiry.
 */
function scheduleRefresh(relayUrl: string): void {
	if (refreshTimer) {
		clearTimeout(refreshTimer);
		refreshTimer = null;
	}

	if (!currentToken) return;

	const msUntilExpiry = currentToken.expiresAt - Date.now();
	const refreshAt = Math.max(msUntilExpiry - refreshWindowMs, 1000); // min 1s

	refreshTimer = setTimeout(async () => {
		await refreshSessionToken(relayUrl);
	}, refreshAt);

	logger.debug({ refreshInMs: refreshAt, scope: currentToken.scope }, "scheduled token refresh");
}

/**
 * Refresh the current session token.
 */
async function refreshSessionToken(relayUrl: string): Promise<boolean> {
	if (!currentToken) return false;

	const endpoint = `${relayUrl.replace(/\/+$/, "")}/v1/auth/token-refresh`;
	const body = JSON.stringify({ token: currentToken.token });

	try {
		const response = await fetch(endpoint, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"X-Telclaude-Session-Token": currentToken.token,
			},
			body,
		});

		if (!response.ok) {
			logger.warn({ status: response.status }, "token refresh failed");
			return false;
		}

		const data = (await response.json()) as RefreshResponse;
		if (!data.ok || !data.token || !data.expiresAt) {
			logger.warn({ error: data.error }, "token refresh returned error");
			return false;
		}

		currentToken = {
			...currentToken,
			token: data.token,
			expiresAt: data.expiresAt,
		};

		scheduleRefresh(relayUrl);

		logger.info(
			{
				scope: currentToken.scope,
				expiresAt: data.expiresAt,
				ttlMs: data.expiresAt - Date.now(),
			},
			"token refreshed",
		);
		return true;
	} catch (err) {
		logger.warn({ error: String(err) }, "token refresh request failed");
		return false;
	}
}

/**
 * Check response headers for token refresh hints.
 * Called after each RPC response from the relay.
 */
export function checkRefreshHeader(headers: Record<string, string>, relayUrl: string): void {
	const refreshHint = headers["x-telclaude-token-refresh"];
	if (refreshHint === "needed" && currentToken) {
		logger.debug("relay hinted token refresh needed");
		refreshSessionToken(relayUrl).catch((err) => {
			logger.warn({ error: String(err) }, "opportunistic refresh failed");
		});
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Check if we have a valid session token.
 */
export function hasSessionToken(): boolean {
	return currentToken !== null && currentToken.expiresAt > Date.now();
}

/**
 * Get the current session token (or null if not bootstrapped / expired).
 */
export function getSessionToken(): string | null {
	if (!currentToken || currentToken.expiresAt <= Date.now()) {
		return null;
	}
	return currentToken.token;
}

/**
 * Get the Ed25519 public key for verifying relay responses.
 */
export function getPublicKey(): string | null {
	return _publicKey;
}

/**
 * Build auth headers for RPC calls.
 * Uses session token (v3) if available, falls back to static auth (v1/v2).
 */
export function buildRpcAuthHeaders(
	method: string,
	path: string,
	body: string,
	scope: InternalAuthScope,
): Record<string, string> {
	const token = getSessionToken();
	if (token) {
		return {
			"X-Telclaude-Session-Token": token,
			"X-Telclaude-Auth-Type": "session",
		};
	}

	// Fallback to static auth
	return buildInternalAuthHeaders(method, path, body, { scope });
}

/**
 * Clean up refresh timer on shutdown.
 */
export function shutdownTokenClient(): void {
	if (refreshTimer) {
		clearTimeout(refreshTimer);
		refreshTimer = null;
	}
	currentToken = null;
	_publicKey = null;
}
