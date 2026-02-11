/**
 * OAuth2 Authorization Code + PKCE flow orchestrator.
 *
 * Uses `oauth-callback` for the localhost callback server and browser launch.
 * Handles PKCE generation, URL construction, state validation, and token exchange.
 */

import { randomBytes } from "node:crypto";
import { getAuthCode, getRedirectUrl } from "oauth-callback";
import { generatePKCE } from "./pkce.js";
import type { OAuth2ServiceDefinition } from "./registry.js";

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

export interface AuthorizeOptions {
	service: OAuth2ServiceDefinition;
	clientId: string;
	clientSecret: string;
	scopes?: string[];
	port?: number;
	timeout?: number;
	/** If true, don't open browser — caller handles URL display via onAuthUrl */
	noBrowser?: boolean;
	/** Custom browser launcher (default: `open` package) */
	launch?: (url: string) => unknown;
	/** Called with the authorization URL (useful for --no-browser to print it) */
	onAuthUrl?: (url: string) => void;
}

export interface AuthorizeResult {
	accessToken: string;
	refreshToken: string;
	expiresIn: number;
	scope: string;
	userId?: string;
	username?: string;
}

interface TokenEndpointResponse {
	access_token: string;
	refresh_token?: string;
	expires_in: number;
	scope?: string;
	token_type: string;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Flow
// ═══════════════════════════════════════════════════════════════════════════════

const TOKEN_EXCHANGE_TIMEOUT_MS = 30_000;

/**
 * Run the full OAuth2 Authorization Code + PKCE flow.
 *
 * 1. Generate PKCE challenge + random state
 * 2. Build authorization URL
 * 3. Start callback server + open browser (via oauth-callback)
 * 4. Validate state on callback
 * 5. Exchange auth code for tokens
 * 6. Optionally fetch user ID
 */
export async function authorize(options: AuthorizeOptions): Promise<AuthorizeResult> {
	const { service, clientId, clientSecret } = options;
	const scopes = options.scopes ?? service.defaultScopes;
	const port = options.port ?? 3000;
	const timeout = (options.timeout ?? 120) * 1000; // seconds → ms

	// 1. Generate PKCE + state
	const { codeVerifier, codeChallenge } = generatePKCE();
	const state = randomBytes(32).toString("base64url");
	const redirectUri = getRedirectUrl({ port });

	// 2. Build authorization URL
	const authUrl = buildAuthorizationUrl({
		authorizationUrl: service.authorizationUrl,
		clientId,
		redirectUri,
		scopes,
		state,
		codeChallenge,
	});

	// 3. Capture authorization code via callback
	const launcher = await resolveLauncher(options);

	// Notify caller of the authorization URL (for --no-browser to print it)
	options.onAuthUrl?.(authUrl);

	const result = await getAuthCode(
		launcher ? { authorizationUrl: authUrl, launch: launcher, port, timeout } : { port, timeout },
	);

	// oauth-callback throws OAuthError for provider errors (access_denied etc.)
	// so if we get here, result.code should be present
	if (!result.code) {
		throw new Error(result.error_description ?? result.error ?? "No authorization code received");
	}

	// 4. Validate state
	if (result.state !== state) {
		throw new Error("State mismatch — possible CSRF attack. Aborting.");
	}

	// 5. Exchange auth code for tokens
	const tokens = await exchangeCode({
		tokenEndpoint: service.tokenEndpoint,
		code: result.code,
		redirectUri,
		codeVerifier,
		clientId,
		clientSecret,
		confidentialClient: service.confidentialClient,
	});

	if (!tokens.refresh_token) {
		throw new Error(
			"Token endpoint did not return a refresh token. " +
				'Ensure "offline.access" scope is included.',
		);
	}

	// 6. Optionally fetch user ID
	let userId: string | undefined;
	let username: string | undefined;
	if (service.userIdEndpoint) {
		const userInfo = await fetchUserId(
			service.userIdEndpoint,
			tokens.access_token,
			service.userIdJsonPath,
		);
		userId = userInfo.id;
		username = userInfo.username;
	}

	return {
		accessToken: tokens.access_token,
		refreshToken: tokens.refresh_token,
		expiresIn: tokens.expires_in,
		scope: tokens.scope ?? scopes.join(" "),
		userId,
		username,
	};
}

/**
 * Get the redirect URL that must be registered with the OAuth provider.
 */
export function getCallbackUrl(port = 3000): string {
	return getRedirectUrl({ port });
}

// ═══════════════════════════════════════════════════════════════════════════════
// Internals
// ═══════════════════════════════════════════════════════════════════════════════

function buildAuthorizationUrl(params: {
	authorizationUrl: string;
	clientId: string;
	redirectUri: string;
	scopes: string[];
	state: string;
	codeChallenge: string;
}): string {
	const url = new URL(params.authorizationUrl);
	url.searchParams.set("response_type", "code");
	url.searchParams.set("client_id", params.clientId);
	url.searchParams.set("redirect_uri", params.redirectUri);
	url.searchParams.set("scope", params.scopes.join(" "));
	url.searchParams.set("state", params.state);
	url.searchParams.set("code_challenge", params.codeChallenge);
	url.searchParams.set("code_challenge_method", "S256");
	return url.toString();
}

async function resolveLauncher(
	options: AuthorizeOptions,
): Promise<((url: string) => unknown) | null> {
	if (options.noBrowser) return null;
	if (options.launch) return options.launch;

	// Dynamic import of `open` — only needed for CLI usage
	const { default: open } = await import("open");
	return open;
}

async function exchangeCode(params: {
	tokenEndpoint: string;
	code: string;
	redirectUri: string;
	codeVerifier: string;
	clientId: string;
	clientSecret: string;
	confidentialClient: boolean;
}): Promise<TokenEndpointResponse> {
	const body = new URLSearchParams({
		grant_type: "authorization_code",
		code: params.code,
		redirect_uri: params.redirectUri,
		code_verifier: params.codeVerifier,
		client_id: params.clientId,
	});

	// Confidential clients include client_secret in body
	// (matches vault-daemon/oauth.ts token refresh approach)
	if (params.confidentialClient) {
		body.set("client_secret", params.clientSecret);
	}

	const headers: Record<string, string> = {
		"Content-Type": "application/x-www-form-urlencoded",
	};

	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), TOKEN_EXCHANGE_TIMEOUT_MS);

	try {
		const response = await fetch(params.tokenEndpoint, {
			method: "POST",
			headers,
			body: body.toString(),
			signal: controller.signal,
			// SECURITY: Prevent credential leakage on redirects
			redirect: "error",
		});

		if (!response.ok) {
			const errorText = await response.text();
			throw new Error(`Token endpoint returned ${response.status}: ${errorText}`);
		}

		const data = (await response.json()) as TokenEndpointResponse;

		if (!data.access_token) {
			throw new Error("Token endpoint did not return access_token");
		}

		return data;
	} finally {
		clearTimeout(timeoutId);
	}
}

async function fetchUserId(
	endpoint: string,
	accessToken: string,
	jsonPath?: string,
): Promise<{ id?: string; username?: string }> {
	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), 10_000);

	try {
		const response = await fetch(endpoint, {
			headers: { Authorization: `Bearer ${accessToken}` },
			signal: controller.signal,
		});

		if (!response.ok) {
			return {};
		}

		const data = (await response.json()) as Record<string, unknown>;

		// Extract user ID via dot-path (e.g., "data.id")
		const id = resolvePath(data, jsonPath ?? "data.id");
		const username = resolvePath(data, "data.username");

		return {
			id: id != null ? String(id) : undefined,
			username: username != null ? String(username) : undefined,
		};
	} catch {
		// User ID fetch is best-effort — don't fail the whole flow
		return {};
	} finally {
		clearTimeout(timeoutId);
	}
}

function resolvePath(obj: Record<string, unknown>, path: string): unknown {
	let current: unknown = obj;
	for (const key of path.split(".")) {
		if (current == null || typeof current !== "object") return undefined;
		current = (current as Record<string, unknown>)[key];
	}
	return current;
}
