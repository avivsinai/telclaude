import crypto from "node:crypto";
import fs from "node:fs";
import type http from "node:http";
import os from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";

import { getChildLogger } from "../logging.js";
import { getVaultClient, isVaultAvailable } from "../vault-daemon/client.js";

const logger = getChildLogger({ module: "anthropic-proxy" });

const PROXY_PREFIX = "/v1/anthropic-proxy";
const ANTHROPIC_ORIGIN = "https://api.anthropic.com";
const RATE_LIMIT_PER_MINUTE = Number(process.env.TELCLAUDE_ANTHROPIC_PROXY_RPM ?? 120);

// OAuth constants (matches Claude Code CLI flow)
const TOKEN_URL = "https://platform.claude.com/v1/oauth/token";
const CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const OAUTH_SCOPES = "user:inference user:profile user:sessions:claude_code";
const TOKEN_REFRESH_MARGIN_MS = 5 * 60 * 1000; // refresh 5 min before expiry
const OAUTH_BETA_HEADER = "oauth-2025-04-20"; // required for OAuth bearer auth on Anthropic API

type AuthHeader = {
	name: string;
	value: string;
	source: string;
	extraHeaders?: Record<string, string>;
};

const rateLimitMap = new Map<string, { count: number; resetAt: number }>();

function checkRateLimit(key: string, limitPerMinute: number): boolean {
	const now = Date.now();
	const entry = rateLimitMap.get(key);
	if (!entry || entry.resetAt < now) {
		rateLimitMap.set(key, { count: 1, resetAt: now + 60_000 });
		return true;
	}
	if (entry.count >= limitPerMinute) {
		return false;
	}
	entry.count++;
	return true;
}

function normalizeRemoteAddress(remoteAddress?: string | null): string | null {
	if (!remoteAddress) return null;
	if (remoteAddress.startsWith("::ffff:")) {
		return remoteAddress.slice("::ffff:".length);
	}
	return remoteAddress;
}

function isPrivateIp(address: string | null): boolean {
	if (!address) return false;
	if (address === "127.0.0.1" || address === "::1") return true;
	if (address.startsWith("10.")) return true;
	if (address.startsWith("192.168.")) return true;
	const octets = address.split(".");
	if (octets.length === 4) {
		const first = Number.parseInt(octets[0] ?? "", 10);
		const second = Number.parseInt(octets[1] ?? "", 10);
		if (first === 172 && second >= 16 && second <= 31) return true;
		if (first === 100 && second >= 64 && second <= 127) return true; // 100.64.0.0/10 (CGNAT)
		if (first === 169 && second === 254) return true; // link-local
	}
	if (address.startsWith("fc") || address.startsWith("fd")) return true; // IPv6 ULA
	if (address.startsWith("fe80:")) return true; // IPv6 link-local
	return false;
}

type OAuthCredentials = {
	accessToken: string;
	refreshToken: string;
	expiresAt: number;
	scopes?: string[];
};

// In-memory cache of vault OAuth credentials (avoids vault roundtrip per request)
let cachedOAuth: OAuthCredentials | null = null;

// Coalescing lock: when a refresh is in-flight, concurrent callers await the same promise
// instead of racing to refresh (which consumes the single-use refresh token).
let pendingRefresh: Promise<OAuthCredentials | null> | null = null;

function oauthAuthHeader(accessToken: string, source: string): AuthHeader {
	return {
		name: "Authorization",
		value: `Bearer ${accessToken}`,
		source,
		extraHeaders: { "anthropic-beta": OAUTH_BETA_HEADER },
	};
}

/**
 * Read OAuth credentials from vault, refresh if expired, and return as Bearer header.
 * The access token is sent directly as `Authorization: Bearer` (user:inference scope).
 * Refreshed tokens are persisted back to the vault.
 */
async function tryVaultOAuth(): Promise<AuthHeader | null> {
	try {
		if (!(await isVaultAvailable({ timeout: 2000 }))) return null;

		const client = getVaultClient();
		const now = Date.now();

		// Use in-memory cache if token is still valid
		if (cachedOAuth && cachedOAuth.expiresAt > now + TOKEN_REFRESH_MARGIN_MS) {
			return oauthAuthHeader(cachedOAuth.accessToken, "vault-oauth-cached");
		}

		// Read from vault
		const resp = await client.getSecret("anthropic-oauth", { timeout: 5000 });
		if (!resp.ok || resp.type !== "get-secret" || !resp.value) return null;

		let creds: OAuthCredentials;
		try {
			creds = JSON.parse(resp.value) as OAuthCredentials;
		} catch {
			logger.warn("vault secret:anthropic-oauth has invalid JSON");
			return null;
		}

		if (!creds.accessToken || !creds.refreshToken) {
			logger.warn("vault secret:anthropic-oauth missing required fields");
			return null;
		}

		// If token is still valid, cache and return
		if (creds.expiresAt > now + TOKEN_REFRESH_MARGIN_MS) {
			cachedOAuth = creds;
			return oauthAuthHeader(creds.accessToken, "vault-oauth");
		}

		// Token expired — refresh via platform.claude.com.
		// Use a coalescing lock: if another request is already refreshing,
		// await that instead of racing (refresh tokens are single-use).
		if (pendingRefresh) {
			logger.debug("OAuth refresh already in-flight, awaiting");
			try {
				const coalesced = await pendingRefresh;
				if (coalesced) {
					return oauthAuthHeader(coalesced.accessToken, "vault-oauth-coalesced");
				}
			} catch (coalescedErr) {
				logger.warn({ error: String(coalescedErr) }, "Coalesced OAuth refresh threw");
			}
			// Refresh failed or threw for the in-flight caller — fall back to expired token
			return oauthAuthHeader(creds.accessToken, "vault-oauth-expired");
		}

		logger.info(
			{ expiresAt: new Date(creds.expiresAt).toISOString() },
			"OAuth token expired, refreshing",
		);

		const doRefresh = async (): Promise<OAuthCredentials | null> => {
			const refreshResp = await fetch(TOKEN_URL, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					grant_type: "refresh_token",
					refresh_token: creds.refreshToken,
					client_id: process.env.CLAUDE_CODE_OAUTH_CLIENT_ID ?? CLIENT_ID,
					scope: creds.scopes?.join(" ") ?? OAUTH_SCOPES,
				}),
			});

			if (!refreshResp.ok) {
				const errText = await refreshResp.text();
				logger.warn({ status: refreshResp.status, body: errText }, "OAuth token refresh failed");
				return null;
			}

			const data = (await refreshResp.json()) as {
				access_token: string;
				refresh_token?: string;
				expires_in: number;
			};

			const refreshed: OAuthCredentials = {
				accessToken: data.access_token,
				refreshToken: data.refresh_token ?? creds.refreshToken,
				expiresAt: Date.now() + data.expires_in * 1000,
				scopes: creds.scopes,
			};

			// Persist refreshed tokens back to vault
			try {
				await client.store({
					protocol: "secret",
					target: "anthropic-oauth",
					credential: { type: "opaque", value: JSON.stringify(refreshed) },
					label: "Anthropic OAuth (auto-refreshed)",
				});
				logger.info(
					{ expiresAt: new Date(refreshed.expiresAt).toISOString() },
					"OAuth token refreshed and saved to vault",
				);
			} catch (storeErr) {
				logger.warn({ error: String(storeErr) }, "failed to persist refreshed OAuth to vault");
			}

			return refreshed;
		};

		pendingRefresh = doRefresh();
		let refreshed: OAuthCredentials | null;
		try {
			refreshed = await pendingRefresh;
		} finally {
			pendingRefresh = null;
		}

		if (!refreshed) {
			// Refresh failed — try expired token as last resort
			cachedOAuth = creds;
			return oauthAuthHeader(creds.accessToken, "vault-oauth-expired");
		}

		cachedOAuth = refreshed;
		return oauthAuthHeader(refreshed.accessToken, "vault-oauth-refreshed");
	} catch (err) {
		logger.debug({ error: String(err) }, "vault OAuth lookup failed");
		return null;
	}
}

function findOAuthCredentials(obj: Record<string, unknown>): OAuthCredentials | null {
	// Look for claudeAiOauth nested structure (standard claude login format)
	const oauth = obj.claudeAiOauth as Record<string, unknown> | undefined;
	if (oauth?.accessToken && oauth?.refreshToken && typeof oauth.expiresAt === "number") {
		return oauth as unknown as OAuthCredentials;
	}
	// Top-level format
	if (obj.accessToken && obj.refreshToken && typeof obj.expiresAt === "number") {
		return obj as unknown as OAuthCredentials;
	}
	return null;
}

async function buildAuthHeader(): Promise<AuthHeader | null> {
	// 1. Try vault API key (http:api.anthropic.com — for users who store an API key)
	try {
		if (await isVaultAvailable({ timeout: 2000 })) {
			const client = getVaultClient();
			const apiKeyResp = await client.get("http", "api.anthropic.com");
			if (apiKeyResp.ok && apiKeyResp.type === "get" && apiKeyResp.entry) {
				const cred = apiKeyResp.entry.credential;
				if (cred.type === "api-key") {
					return { name: cred.header, value: cred.token, source: "vault" };
				}
				if (cred.type === "bearer") {
					return { name: "Authorization", value: `Bearer ${cred.token}`, source: "vault" };
				}
			}
		}
	} catch (err) {
		logger.debug({ error: String(err) }, "vault API key lookup failed");
	}

	// 2. Try vault OAuth (secret:anthropic-oauth — from `vault import-anthropic`)
	const vaultOAuth = await tryVaultOAuth();
	if (vaultOAuth) return vaultOAuth;

	// 3. Environment variables
	const oauthToken = process.env.CLAUDE_CODE_OAUTH_TOKEN || process.env.ANTHROPIC_AUTH_TOKEN;
	if (oauthToken) {
		return { name: "Authorization", value: `Bearer ${oauthToken}`, source: "env" };
	}

	const apiKey = process.env.ANTHROPIC_API_KEY;
	if (apiKey) {
		return { name: "x-api-key", value: apiKey, source: "env" };
	}

	// 4. Credentials file fallback (dev/native mode, before vault import)
	const authDir = process.env.TELCLAUDE_AUTH_DIR;
	const credentialsCandidates = [
		process.env.CLAUDE_CODE_CREDENTIALS_PATH,
		authDir ? path.join(authDir, ".credentials.json") : null,
		authDir ? path.join(authDir, ".claude", ".credentials.json") : null,
		path.join(process.env.HOME ?? os.homedir(), ".claude", ".credentials.json"),
	].filter((candidate): candidate is string => Boolean(candidate));

	for (const credentialsPath of credentialsCandidates) {
		try {
			const raw = fs.readFileSync(credentialsPath, "utf8");
			const parsed = JSON.parse(raw) as Record<string, unknown>;

			// Try OAuth credentials from file (direct Bearer, with refresh)
			const creds = findOAuthCredentials(parsed);
			if (creds) {
				const now = Date.now();
				if (creds.expiresAt > now + TOKEN_REFRESH_MARGIN_MS) {
					return oauthAuthHeader(creds.accessToken, "file-oauth");
				}
				// Expired — attempt refresh
				try {
					const refreshResp = await fetch(TOKEN_URL, {
						method: "POST",
						headers: { "Content-Type": "application/json" },
						body: JSON.stringify({
							grant_type: "refresh_token",
							refresh_token: creds.refreshToken,
							client_id: process.env.CLAUDE_CODE_OAUTH_CLIENT_ID ?? CLIENT_ID,
							scope: creds.scopes?.join(" ") ?? OAUTH_SCOPES,
						}),
					});
					if (refreshResp.ok) {
						const data = (await refreshResp.json()) as {
							access_token: string;
							refresh_token?: string;
							expires_in: number;
						};
						// Update file
						const updated = {
							...creds,
							accessToken: data.access_token,
							refreshToken: data.refresh_token ?? creds.refreshToken,
							expiresAt: now + data.expires_in * 1000,
						};
						const fileObj = parsed.claudeAiOauth
							? { ...parsed, claudeAiOauth: updated }
							: { ...parsed, ...updated };
						fs.writeFileSync(credentialsPath, JSON.stringify(fileObj), {
							encoding: "utf8",
							mode: 0o600,
						});
						logger.info("OAuth token refreshed (file fallback)");
						return oauthAuthHeader(data.access_token, "file-oauth-refreshed");
					}
				} catch {
					// Refresh failed, try expired token anyway
				}
				return oauthAuthHeader(creds.accessToken, "file-oauth-expired");
			}

			// Non-OAuth: raw token
			const token =
				extractToken(parsed, ["access_token", "accessToken"]) ??
				extractToken(parsed, ["oauth_token", "oauthToken", "token"]);
			if (token) {
				return { name: "Authorization", value: `Bearer ${token}`, source: "file" };
			}
		} catch {
			// Ignore missing/invalid credentials file
		}
	}

	return null;
}

function extractToken(
	value: unknown,
	preferredKeys: string[],
	seen = new Set<unknown>(),
): string | null {
	if (!value || typeof value !== "object" || seen.has(value)) return null;
	seen.add(value);

	const obj = value as Record<string, unknown>;
	for (const key of preferredKeys) {
		const candidate = obj[key];
		if (typeof candidate === "string" && candidate.length > 10) {
			return candidate;
		}
	}

	for (const nested of Object.values(obj)) {
		if (typeof nested === "string") continue;
		const found = extractToken(nested, preferredKeys, seen);
		if (found) return found;
	}

	return null;
}

function sanitizeRequestHeaders(headers: http.IncomingHttpHeaders, authHeader: AuthHeader) {
	const filtered: Record<string, string> = {};
	const blocked = new Set([
		"connection",
		"keep-alive",
		"proxy-authenticate",
		"proxy-authorization",
		"te",
		"trailer",
		"transfer-encoding",
		"upgrade",
		"host",
		"content-length",
		"authorization",
		"x-api-key",
	]);

	for (const [key, value] of Object.entries(headers)) {
		if (!key) continue;
		const lower = key.toLowerCase();
		if (blocked.has(lower)) continue;
		if (value === undefined) continue;
		filtered[key] = Array.isArray(value) ? value.join(",") : value;
	}

	filtered[authHeader.name] = authHeader.value;
	if (authHeader.extraHeaders) {
		for (const [k, v] of Object.entries(authHeader.extraHeaders)) {
			// Merge beta headers (agent may also send anthropic-beta)
			if (k === "anthropic-beta" && filtered["anthropic-beta"]) {
				filtered["anthropic-beta"] = `${filtered["anthropic-beta"]},${v}`;
			} else {
				filtered[k] = v;
			}
		}
	}
	return filtered;
}

function extractBearerToken(headerValue: string | string[] | undefined): string | null {
	if (!headerValue) return null;
	const raw = Array.isArray(headerValue) ? headerValue[0] : headerValue;
	if (!raw) return null;
	const trimmed = raw.trim();
	if (!trimmed) return null;
	const match = trimmed.match(/^Bearer\s+(.+)$/i);
	if (!match) return null;
	return match[1]?.trim() ?? null;
}

/**
 * Extract proxy token from request headers.
 *
 * The Claude SDK may send credentials as either `Authorization: Bearer <token>`
 * or `x-api-key: <token>` depending on the request type. Accept both so that
 * all SDK-initiated requests authenticate successfully against the proxy.
 */
function extractProxyToken(req: http.IncomingMessage): string | null {
	return (
		extractBearerToken(req.headers.authorization) ??
		(req.headers["x-api-key"] as string | undefined)?.trim() ??
		null
	);
}

function constantTimeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	const aBuf = Buffer.from(a, "utf8");
	const bBuf = Buffer.from(b, "utf8");
	return crypto.timingSafeEqual(aBuf, bBuf);
}

export function isAnthropicProxyRequest(url: string): boolean {
	return url === PROXY_PREFIX || url.startsWith(`${PROXY_PREFIX}/`);
}

export async function handleAnthropicProxyRequest(
	req: http.IncomingMessage,
	res: http.ServerResponse,
): Promise<void> {
	const remoteAddress = normalizeRemoteAddress(req.socket.remoteAddress ?? null);
	if (!isPrivateIp(remoteAddress)) {
		logger.warn({ remoteAddress }, "[anthropic-proxy] blocked non-private client");
		res.writeHead(403, { "Content-Type": "application/json" });
		res.end(JSON.stringify({ error: "Forbidden." }));
		return;
	}

	if (RATE_LIMIT_PER_MINUTE > 0 && remoteAddress) {
		if (!checkRateLimit(remoteAddress, RATE_LIMIT_PER_MINUTE)) {
			res.writeHead(429, { "Content-Type": "application/json" });
			res.end(JSON.stringify({ error: "Rate limited." }));
			return;
		}
	}

	const proxyToken = process.env.MOLTBOOK_PROXY_TOKEN;
	if (!proxyToken) {
		logger.warn("[anthropic-proxy] missing MOLTBOOK_PROXY_TOKEN");
		res.writeHead(500, { "Content-Type": "application/json" });
		res.end(JSON.stringify({ error: "Proxy token not configured." }));
		return;
	}

	const incomingToken = extractProxyToken(req);
	if (!incomingToken || !constantTimeEqual(incomingToken, proxyToken)) {
		const authType = req.headers.authorization
			? "bearer"
			: req.headers["x-api-key"]
				? "x-api-key"
				: "none";
		logger.warn(
			{ remoteAddress, method: req.method, url: req.url, authType },
			"[anthropic-proxy] invalid proxy token",
		);
		res.writeHead(401, { "Content-Type": "application/json" });
		res.end(JSON.stringify({ error: "Unauthorized." }));
		return;
	}

	const authHeader = await buildAuthHeader();
	if (!authHeader) {
		logger.warn("[anthropic-proxy] missing Anthropic credentials");
		res.writeHead(500, { "Content-Type": "application/json" });
		res.end(JSON.stringify({ error: "Anthropic credentials not configured." }));
		return;
	}

	const url = req.url ?? "";
	const suffix = url.slice(PROXY_PREFIX.length);
	const targetPath = suffix.length === 0 ? "/" : suffix;
	if (
		targetPath.startsWith("http://") ||
		targetPath.startsWith("https://") ||
		targetPath.startsWith("//")
	) {
		res.writeHead(400, { "Content-Type": "application/json" });
		res.end(JSON.stringify({ error: "Invalid proxy path." }));
		return;
	}

	let decodedPath = targetPath;
	try {
		decodedPath = decodeURIComponent(targetPath);
	} catch {
		res.writeHead(400, { "Content-Type": "application/json" });
		res.end(JSON.stringify({ error: "Invalid proxy path." }));
		return;
	}
	if (decodedPath.includes("..") || decodedPath.includes("\\")) {
		res.writeHead(400, { "Content-Type": "application/json" });
		res.end(JSON.stringify({ error: "Invalid Anthropic API path." }));
		return;
	}

	const normalized = new URL(targetPath, ANTHROPIC_ORIGIN);
	if (normalized.origin !== ANTHROPIC_ORIGIN || !normalized.pathname.startsWith("/v1/")) {
		res.writeHead(400, { "Content-Type": "application/json" });
		res.end(JSON.stringify({ error: "Invalid Anthropic API path." }));
		return;
	}

	const normalizedPath = `${normalized.pathname}${normalized.search}`;
	const targetUrl = `${ANTHROPIC_ORIGIN}${normalizedPath}`;
	const method = req.method ?? "POST";
	const headers = sanitizeRequestHeaders(req.headers, authHeader);

	const hasBody = !["GET", "HEAD"].includes(method.toUpperCase());

	logger.info(
		{ method, path: normalizedPath, authSource: authHeader.source },
		"proxying to Anthropic",
	);
	const webBody = hasBody ? Readable.toWeb(req) : undefined;
	let upstream: Response;
	try {
		upstream = await fetch(targetUrl, {
			method,
			headers,
			body: webBody,
			// Required for streaming request bodies in Node fetch.
			...(hasBody ? { duplex: "half" } : {}),
		});
	} catch (err) {
		logger.warn({ error: String(err) }, "[anthropic-proxy] upstream fetch failed");
		res.writeHead(502, { "Content-Type": "application/json" });
		res.end(JSON.stringify({ error: "Upstream request failed." }));
		return;
	}

	res.statusCode = upstream.status;
	upstream.headers.forEach((value, key) => {
		res.setHeader(key, value);
	});

	if (!upstream.body) {
		res.end();
		return;
	}

	const nodeStream = Readable.fromWeb(upstream.body as import("stream/web").ReadableStream);
	try {
		await pipeline(nodeStream, res);
	} catch (err) {
		logger.warn({ error: String(err) }, "[anthropic-proxy] response stream failed");
		if (!res.headersSent) {
			res.writeHead(502, { "Content-Type": "application/json" });
			res.end(JSON.stringify({ error: "Upstream response failed." }));
		} else {
			res.end();
		}
	}
}
