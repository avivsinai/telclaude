/**
 * HTTP Credential Proxy Server
 *
 * Transparent proxy for HTTP APIs that injects credentials without exposing them to agents.
 * This is the generalization of git-proxy.ts for any HTTP API.
 *
 * Architecture:
 * - Agent calls: http://relay:8792/{host}/{path}
 * - Proxy looks up credential for {host} from vault
 * - Injects authentication (bearer, api-key, basic, oauth2)
 * - Forwards request to https://{host}/{path}
 * - Streams response back to agent
 *
 * Examples:
 * - http://relay:8792/api.openai.com/v1/images/generations
 * - http://relay:8792/api.anthropic.com/v1/messages
 * - http://relay:8792/api.github.com/repos/owner/repo
 *
 * Agent NEVER sees credentials.
 */

import http from "node:http";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";

import { getChildLogger } from "../logging.js";
import { getSandboxMode } from "../sandbox/index.js";
import { sanitizeError } from "../utils.js";
import {
	type CredentialEntry,
	getVaultClient,
	type HttpCredential,
	type OAuth2Credential,
} from "../vault-daemon/index.js";
import { type SessionTokenPayload, validateSessionToken } from "./git-proxy-auth.js";

const logger = getChildLogger({ module: "http-credential-proxy" });

// ═══════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════

// Maximum request body size (10MB - reasonable for most API calls including images)
const MAX_REQUEST_BODY_SIZE = 10 * 1024 * 1024;

// ═══════════════════════════════════════════════════════════════════════════════
// Body Size Limiting
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Transform stream that enforces a maximum body size.
 * Throws an error if the size limit is exceeded.
 */
class SizeLimitingTransform extends Transform {
	private received = 0;
	private readonly maxSize: number;

	constructor(maxSize: number) {
		super();
		this.maxSize = maxSize;
	}

	_transform(
		chunk: Buffer,
		_encoding: BufferEncoding,
		callback: (error?: Error | null, data?: Buffer) => void,
	): void {
		this.received += chunk.length;
		if (this.received > this.maxSize) {
			callback(new Error(`Request body too large (max ${this.maxSize} bytes)`));
			return;
		}
		callback(null, chunk);
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

export interface HttpCredentialProxyConfig {
	port: number;
	host: string;
	rateLimitPerMinute: number;
	vaultSocketPath?: string;
}

interface ParsedProxyUrl {
	host: string;
	path: string;
	query: string;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Rate Limiting
// ═══════════════════════════════════════════════════════════════════════════════

const rateLimitMap = new Map<string, { count: number; resetAt: number }>();

function checkRateLimit(host: string, limitPerMinute: number): boolean {
	const now = Date.now();
	const entry = rateLimitMap.get(host);

	if (!entry || entry.resetAt < now) {
		rateLimitMap.set(host, { count: 1, resetAt: now + 60000 });
		return true;
	}

	if (entry.count >= limitPerMinute) {
		return false;
	}

	entry.count++;
	return true;
}

// Clean up old rate limit entries periodically
let cleanupInterval: NodeJS.Timeout | null = null;

function startCleanupInterval(): void {
	if (cleanupInterval) return;

	cleanupInterval = setInterval(
		() => {
			const now = Date.now();
			for (const [key, entry] of rateLimitMap.entries()) {
				if (entry.resetAt < now) {
					rateLimitMap.delete(key);
				}
			}
		},
		5 * 60 * 1000,
	); // Every 5 minutes

	cleanupInterval.unref();
}

function stopCleanupInterval(): void {
	if (cleanupInterval) {
		clearInterval(cleanupInterval);
		cleanupInterval = null;
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// URL Parsing
// ═══════════════════════════════════════════════════════════════════════════════

// Strict host validation regex:
// - Allows alphanumeric, hyphens, dots
// - Optional port suffix
// - Rejects userinfo (@), whitespace, percent encoding, etc.
const VALID_HOST_REGEX = /^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(:\d{1,5})?$/;

/**
 * Parse a proxy URL into components.
 * Input: /api.openai.com/v1/images/generations?foo=bar
 * Output: { host: "api.openai.com", path: "/v1/images/generations", query: "?foo=bar" }
 */
function parseProxyUrl(url: string): ParsedProxyUrl | null {
	// Remove query string for parsing, but preserve for path
	const [pathPart, queryPart] = url.split("?");
	const query = queryPart ? `?${queryPart}` : "";

	// Expected format: /{host}/{path...}
	// e.g., /api.openai.com/v1/images/generations
	const match = pathPart.match(/^\/([^/]+)(\/.*)$/);
	if (!match) {
		return null;
	}

	const [, host, path] = match;

	// SECURITY: Strict host validation to prevent SSRF via malformed hosts
	// Rejects: userinfo (@), whitespace, percent encoding, invalid chars
	if (!VALID_HOST_REGEX.test(host)) {
		return null;
	}

	// Must have at least one dot (domain) unless it's localhost with port
	if (!host.includes(".") && !host.startsWith("localhost:")) {
		return null;
	}

	// Normalize to lowercase
	return { host: host.toLowerCase(), path, query };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Credential Injection
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Build authentication header(s) for an HTTP credential.
 */
function buildAuthHeaders(credential: HttpCredential): Record<string, string> {
	switch (credential.type) {
		case "bearer":
			return { Authorization: `Bearer ${credential.token}` };

		case "api-key":
			return { [credential.header]: credential.token };

		case "basic": {
			const encoded = Buffer.from(`${credential.username}:${credential.password}`).toString(
				"base64",
			);
			return { Authorization: `Basic ${encoded}` };
		}

		case "query":
			// Query params are handled separately, not via headers
			return {};
	}
}

/**
 * Build query string additions for query-based auth.
 */
function buildAuthQuery(credential: HttpCredential, existingQuery: string): string {
	if (credential.type !== "query") {
		return existingQuery;
	}

	const separator = existingQuery ? "&" : "?";
	return `${existingQuery}${separator}${credential.param}=${encodeURIComponent(credential.token)}`;
}

/**
 * Check if the request path is allowed for this credential.
 */
function isPathAllowed(path: string, allowedPaths?: string[]): boolean {
	if (!allowedPaths || allowedPaths.length === 0) {
		return true;
	}

	return allowedPaths.some((pattern) => {
		try {
			return new RegExp(pattern).test(path);
		} catch {
			return false; // Invalid regex, skip
		}
	});
}

// ═══════════════════════════════════════════════════════════════════════════════
// Request Handling
// ═══════════════════════════════════════════════════════════════════════════════

// Upstream request timeout (60 seconds)
const UPSTREAM_TIMEOUT_MS = 60 * 1000;

// Headers that should not be forwarded between client and upstream
const HOP_BY_HOP_HEADERS = new Set([
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
 * Send an error response if headers haven't been sent yet, otherwise just end.
 */
function sendErrorResponse(res: http.ServerResponse, status: number, message: string): void {
	if (!res.headersSent) {
		res.writeHead(status, { "Content-Type": "text/plain" });
		res.end(message);
	} else {
		res.end();
	}
}

/**
 * Forward a request to the upstream API with authentication.
 *
 * SECURITY: Uses streaming to avoid buffering large request/response bodies.
 * Body size is limited to prevent DoS attacks.
 */
async function proxyRequest(
	req: http.IncomingMessage,
	res: http.ServerResponse,
	parsed: ParsedProxyUrl,
	entry: CredentialEntry,
	session: SessionTokenPayload,
	accessToken?: string, // For OAuth2, the refreshed access token
): Promise<void> {
	// Determine the credential to use for headers
	const credential = entry.credential as HttpCredential | OAuth2Credential;
	let authHeaders: Record<string, string>;
	let queryAddition = "";

	if (credential.type === "oauth2") {
		// Use the provided access token for OAuth2
		if (!accessToken) {
			res.writeHead(500, { "Content-Type": "text/plain" });
			res.end("Internal error: OAuth2 access token not provided");
			return;
		}
		authHeaders = { Authorization: `Bearer ${accessToken}` };
	} else {
		authHeaders = buildAuthHeaders(credential);
		queryAddition = buildAuthQuery(credential, parsed.query);
	}

	// Build upstream URL
	const finalQuery = credential.type === "query" ? queryAddition : parsed.query;
	const upstreamUrl = `https://${parsed.host}${parsed.path}${finalQuery}`;

	// Build headers for upstream request
	const upstreamHeaders: Record<string, string> = {
		Host: parsed.host,
		"User-Agent": "telclaude-http-proxy/1.0",
		...authHeaders,
	};

	// Copy relevant headers from original request
	// NOTE: We intentionally don't forward accept-encoding to let fetch handle
	// compression naturally, avoiding content-encoding mismatches
	const headersToForward = ["content-type", "content-length", "accept", "accept-language"];

	for (const header of headersToForward) {
		const value = req.headers[header];
		if (value) {
			upstreamHeaders[header] = Array.isArray(value) ? value[0] : value;
		}
	}

	// For POST/PUT/PATCH, stream the body through size limiter to upstream
	// SECURITY: Enforce body size limit to prevent DoS attacks
	const hasBody = ["POST", "PUT", "PATCH"].includes(req.method ?? "");
	let requestBody: ReadableStream<Uint8Array> | undefined;
	if (hasBody) {
		const sizeLimiter = new SizeLimitingTransform(MAX_REQUEST_BODY_SIZE);
		// Pipe request through size limiter, then convert to Web ReadableStream
		const limitedStream = req.pipe(sizeLimiter);
		requestBody = Readable.toWeb(limitedStream);
	}

	// Use AbortController for timeout
	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);

	try {
		const upstreamResponse = await fetch(upstreamUrl, {
			method: req.method,
			headers: upstreamHeaders,
			body: requestBody,
			duplex: "half",
			signal: controller.signal,
			// SECURITY: Disable automatic redirects to prevent SSRF bypass.
			// Redirects could send credentials to non-allowlisted hosts.
			redirect: "manual",
		});

		// Log the operation (without sensitive details)
		logger.info(
			{
				sessionId: session.sessionId,
				host: parsed.host,
				path: parsed.path,
				method: req.method,
				status: upstreamResponse.status,
			},
			"http proxy request completed",
		);

		// SECURITY: Log redirects - we don't follow them to prevent SSRF
		if (upstreamResponse.status >= 300 && upstreamResponse.status < 400) {
			const location = upstreamResponse.headers.get("location");
			logger.warn(
				{
					host: parsed.host,
					status: upstreamResponse.status,
					// Log location host only, not full URL (may contain sensitive path)
					redirectHost: location ? new URL(location, upstreamUrl).hostname : undefined,
				},
				"http proxy returning redirect without following (SSRF protection)",
			);
		}

		// Forward response headers, excluding hop-by-hop headers
		upstreamResponse.headers.forEach((value, key) => {
			if (!HOP_BY_HOP_HEADERS.has(key.toLowerCase())) {
				res.setHeader(key, value);
			}
		});

		res.writeHead(upstreamResponse.status);

		// Stream response body with proper backpressure handling
		if (upstreamResponse.body) {
			const nodeStream = Readable.fromWeb(upstreamResponse.body);
			await pipeline(nodeStream, res);
		} else {
			res.end();
		}
	} catch (err) {
		const logContext = { host: parsed.host, sessionId: session.sessionId };

		// Handle timeout
		if (err instanceof Error && err.name === "AbortError") {
			logger.error(logContext, "http proxy upstream request timed out");
			sendErrorResponse(res, 504, "Gateway timeout: upstream request timed out");
			return;
		}

		// Handle body size limit exceeded
		if (err instanceof Error && err.message.includes("Request body too large")) {
			logger.warn(logContext, "http proxy request body too large");
			sendErrorResponse(res, 413, "Request entity too large");
			return;
		}

		// SECURITY: Sanitize error to prevent credential leakage in logs
		logger.error(
			{ ...logContext, error: sanitizeError(err, true) },
			"http proxy upstream request failed",
		);
		sendErrorResponse(res, 502, "Bad gateway: upstream request failed");
	} finally {
		clearTimeout(timeoutId);
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Server
// ═══════════════════════════════════════════════════════════════════════════════

const DEFAULT_CONFIG: HttpCredentialProxyConfig = {
	port: 8792,
	host: "127.0.0.1",
	rateLimitPerMinute: 120,
};

export interface HttpCredentialProxyHandle {
	server: http.Server;
	stop: () => Promise<void>;
}

export function startHttpCredentialProxy(
	config: Partial<HttpCredentialProxyConfig> = {},
): HttpCredentialProxyHandle {
	const finalConfig: HttpCredentialProxyConfig = {
		port: config.port ?? Number(process.env.TELCLAUDE_HTTP_PROXY_PORT ?? DEFAULT_CONFIG.port),
		host: config.host ?? (getSandboxMode() === "docker" ? "0.0.0.0" : DEFAULT_CONFIG.host),
		rateLimitPerMinute: config.rateLimitPerMinute ?? DEFAULT_CONFIG.rateLimitPerMinute,
		vaultSocketPath: config.vaultSocketPath,
	};

	const vaultClient = getVaultClient(
		finalConfig.vaultSocketPath ? { socketPath: finalConfig.vaultSocketPath } : undefined,
	);

	// Start rate limit cleanup
	startCleanupInterval();

	const server = http.createServer(async (req, res) => {
		const url = req.url ?? "";

		// Health check
		if (url === "/health" && req.method === "GET") {
			// Also check vault connectivity
			const vaultOk = await vaultClient.ping();
			const status = vaultOk ? 200 : 503;
			res.writeHead(status, { "Content-Type": "application/json" });
			res.end(JSON.stringify({ ok: vaultOk, service: "http-credential-proxy", vault: vaultOk }));
			return;
		}

		// List configured hosts (for debugging, no secrets)
		// SECURITY: Gated behind env flag to prevent target inventory disclosure
		if (url === "/hosts" && req.method === "GET") {
			if (!process.env.TELCLAUDE_HTTP_PROXY_DEBUG) {
				res.writeHead(404, { "Content-Type": "text/plain" });
				res.end("Not found");
				return;
			}
			try {
				const listResponse = await vaultClient.list("http");
				const hosts = listResponse.entries.map((e) => ({
					host: e.target,
					type: e.credentialType,
					label: e.label,
				}));
				res.writeHead(200, { "Content-Type": "application/json" });
				res.end(JSON.stringify({ hosts }));
			} catch {
				res.writeHead(503, { "Content-Type": "application/json" });
				res.end(JSON.stringify({ error: "Vault unavailable" }));
			}
			return;
		}

		// ══════════════════════════════════════════════════════════════════════════
		// Session Token Validation
		// SECURITY: All proxy requests require valid session token from relay,
		// EXCEPT relay-local requests (127.0.0.1 / ::1) which are trusted.
		// ══════════════════════════════════════════════════════════════════════════
		const remoteAddr = req.socket.remoteAddress ?? "";
		const isLocalhost =
			remoteAddr === "127.0.0.1" || remoteAddr === "::1" || remoteAddr === "::ffff:127.0.0.1";

		let session: SessionTokenPayload;

		if (isLocalhost) {
			// Relay calling its own proxy (e.g. social service API calls) — trusted
			const now = Date.now();
			session = { sessionId: "relay-local", createdAt: now, expiresAt: now + 3600_000 };
		} else {
			const rawSessionHeader = req.headers["x-telclaude-session"];
			// Normalize: header can be string or string[], take first and trim
			const sessionHeader =
				(Array.isArray(rawSessionHeader) ? rawSessionHeader[0] : rawSessionHeader)?.trim() || "";
			if (!sessionHeader) {
				logger.warn({ url }, "http proxy request missing session token");
				res.writeHead(401, { "Content-Type": "text/plain" });
				res.end("Unauthorized: missing session token");
				return;
			}

			const validated = validateSessionToken(sessionHeader);
			if (!validated) {
				logger.warn({ url }, "http proxy request with invalid session token");
				res.writeHead(401, { "Content-Type": "text/plain" });
				res.end("Unauthorized: invalid session token");
				return;
			}
			session = validated;
		}

		// Parse proxy URL
		const parsed = parseProxyUrl(url);
		if (!parsed) {
			res.writeHead(400, { "Content-Type": "text/plain" });
			res.end("Bad request: invalid URL format. Expected /{host}/{path}");
			return;
		}

		// Rate limiting (per session)
		if (!checkRateLimit(session.sessionId, finalConfig.rateLimitPerMinute)) {
			logger.warn(
				{ sessionId: session.sessionId, host: parsed.host },
				"http proxy rate limit exceeded",
			);
			res.writeHead(429, { "Content-Type": "text/plain" });
			res.end("Too many requests");
			return;
		}

		// Look up credential from vault
		let entry: CredentialEntry | null = null;
		let accessToken: string | undefined;

		try {
			const getResponse = await vaultClient.get("http", parsed.host);
			if (!getResponse.ok) {
				logger.warn(
					{ sessionId: session.sessionId, host: parsed.host },
					"no credential configured for host",
				);
				res.writeHead(403, { "Content-Type": "text/plain" });
				res.end(`Forbidden: no credential configured for ${parsed.host}`);
				return;
			}
			entry = getResponse.entry;

			// For OAuth2, get the access token (vault handles refresh)
			if (entry.credential.type === "oauth2") {
				const tokenResponse = await vaultClient.getToken(parsed.host);
				if (!tokenResponse.ok) {
					logger.error(
						{ sessionId: session.sessionId, host: parsed.host, error: tokenResponse.error },
						"OAuth2 token refresh failed",
					);
					res.writeHead(503, { "Content-Type": "text/plain" });
					res.end("Service unavailable: authentication failed");
					return;
				}
				accessToken = tokenResponse.token;
			}
		} catch (err) {
			logger.error(
				{ sessionId: session.sessionId, host: parsed.host, error: String(err) },
				"vault lookup failed",
			);
			res.writeHead(503, { "Content-Type": "text/plain" });
			res.end("Service unavailable: credential store unavailable");
			return;
		}

		// Check path allowlist
		if (!isPathAllowed(parsed.path, entry.allowedPaths)) {
			logger.warn(
				{ sessionId: session.sessionId, host: parsed.host, path: parsed.path },
				"path not in allowlist",
			);
			res.writeHead(403, { "Content-Type": "text/plain" });
			res.end(`Forbidden: path ${parsed.path} not allowed for this credential`);
			return;
		}

		// Check credential-specific rate limit
		if (entry.rateLimitPerMinute) {
			const key = `cred:${parsed.host}`;
			if (!checkRateLimit(key, entry.rateLimitPerMinute)) {
				logger.warn(
					{ sessionId: session.sessionId, host: parsed.host },
					"credential rate limit exceeded",
				);
				res.writeHead(429, { "Content-Type": "text/plain" });
				res.end("Too many requests for this credential");
				return;
			}
		}

		// Proxy the request
		await proxyRequest(req, res, parsed, entry, session, accessToken);
	});

	server.listen(finalConfig.port, finalConfig.host, () => {
		logger.info(
			{ host: finalConfig.host, port: finalConfig.port },
			"http credential proxy listening",
		);
	});

	return {
		server,
		stop: async () => {
			stopCleanupInterval();
			return new Promise((resolve) => {
				server.close(() => resolve());
			});
		},
	};
}

export { parseProxyUrl, buildAuthHeaders, isPathAllowed };
