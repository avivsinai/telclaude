/**
 * Git Proxy Server
 *
 * Transparent proxy for git operations that keeps credentials outside the agent container.
 * Agent's git is configured to route through this proxy, which adds authentication
 * before forwarding requests to GitHub.
 *
 * Architecture:
 * - Agent git → http://relay:8791/github.com/owner/repo.git/...
 * - Proxy validates session token, adds GitHub App token, forwards to GitHub
 * - Agent NEVER sees the real GitHub token
 *
 * Supported git operations:
 * - GET  /{host}/{owner}/{repo}.git/info/refs?service=git-upload-pack (clone/fetch discovery)
 * - GET  /{host}/{owner}/{repo}.git/info/refs?service=git-receive-pack (push discovery)
 * - POST /{host}/{owner}/{repo}.git/git-upload-pack (clone/fetch)
 * - POST /{host}/{owner}/{repo}.git/git-receive-pack (push)
 */

import http from "node:http";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";

import { getChildLogger } from "../logging.js";
import { getSandboxMode } from "../sandbox/index.js";
import { getGitHubAppIdentity, getInstallationToken } from "../services/github-app.js";
import { type SessionTokenPayload, validateSessionToken } from "./git-proxy-auth.js";

const logger = getChildLogger({ module: "git-proxy" });

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

export interface GitProxyConfig {
	port: number;
	host: string;
	allowedHosts: string[];
	rateLimitPerMinute: number;
}

interface ParsedGitUrl {
	host: string;
	owner: string;
	repo: string;
	path: string; // e.g., /info/refs, /git-upload-pack
}

interface GitOperation {
	type: "fetch" | "push" | "unknown";
	repo: string;
	service?: string;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Rate Limiting
// ═══════════════════════════════════════════════════════════════════════════════

const rateLimitMap = new Map<string, { count: number; resetAt: number }>();

function checkRateLimit(sessionId: string, limitPerMinute: number): boolean {
	const now = Date.now();
	const entry = rateLimitMap.get(sessionId);

	if (!entry || entry.resetAt < now) {
		rateLimitMap.set(sessionId, { count: 1, resetAt: now + 60000 });
		return true;
	}

	if (entry.count >= limitPerMinute) {
		return false;
	}

	entry.count++;
	return true;
}

// Clean up old rate limit entries periodically
setInterval(
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

// ═══════════════════════════════════════════════════════════════════════════════
// URL Parsing
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Parse a git proxy URL into components.
 * Input: /github.com/owner/repo.git/info/refs
 * Output: { host: "github.com", owner: "owner", repo: "repo", path: "/info/refs" }
 */
function parseGitUrl(url: string): ParsedGitUrl | null {
	// Remove query string for parsing, but preserve for path
	const [pathPart, queryPart] = url.split("?");
	const query = queryPart ? `?${queryPart}` : "";

	// Expected format: /{host}/{owner}/{repo}.git/{git-path}
	// e.g., /github.com/avivsinai/telclaude.git/info/refs
	const match = pathPart.match(/^\/([^/]+)\/([^/]+)\/([^/]+?)(\.git)?(\/.*)$/);
	if (!match) {
		return null;
	}

	const [, host, owner, repo, , gitPath] = match;
	return {
		host,
		owner,
		repo: repo.replace(/\.git$/, ""),
		path: gitPath + query,
	};
}

/**
 * Determine the git operation type from the request.
 */
function getGitOperation(_method: string, path: string, url: string): GitOperation {
	const parsed = parseGitUrl(url);
	const repo = parsed ? `${parsed.owner}/${parsed.repo}` : "unknown";

	// Check service parameter for info/refs
	const serviceMatch = url.match(/service=git-([a-z-]+)/);
	const service = serviceMatch ? serviceMatch[1] : undefined;

	if (path.includes("git-upload-pack")) {
		return { type: "fetch", repo, service: "upload-pack" };
	}
	if (path.includes("git-receive-pack")) {
		return { type: "push", repo, service: "receive-pack" };
	}
	if (path.includes("/info/refs")) {
		return {
			type: service === "receive-pack" ? "push" : "fetch",
			repo,
			service,
		};
	}

	return { type: "unknown", repo };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Request Handling
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Forward a request to the upstream git server with authentication.
 *
 * SECURITY: Uses streaming to avoid buffering large git operations in memory.
 * Git pushes can be hundreds of megabytes - buffering would cause OOM.
 */
async function proxyRequest(
	req: http.IncomingMessage,
	res: http.ServerResponse,
	parsed: ParsedGitUrl,
	session: SessionTokenPayload,
): Promise<void> {
	// Get GitHub App installation token
	const token = await getInstallationToken();
	if (!token) {
		logger.error("failed to get installation token for git proxy");
		res.writeHead(503, { "Content-Type": "text/plain" });
		res.end("Service unavailable: authentication not configured");
		return;
	}

	// Build upstream URL
	const upstreamUrl = `https://${parsed.host}/${parsed.owner}/${parsed.repo}.git${parsed.path}`;

	// Build headers for upstream request
	// GitHub Git Smart HTTP requires Basic auth with x-access-token as username
	const basicAuth = Buffer.from(`x-access-token:${token}`).toString("base64");
	const upstreamHeaders: Record<string, string> = {
		Host: parsed.host,
		"User-Agent": "telclaude-git-proxy/1.0",
		Authorization: `Basic ${basicAuth}`,
	};

	// Copy relevant headers from original request
	if (req.headers["content-type"]) {
		upstreamHeaders["Content-Type"] = req.headers["content-type"] as string;
	}
	if (req.headers["content-length"]) {
		upstreamHeaders["Content-Length"] = req.headers["content-length"] as string;
	}
	if (req.headers.accept) {
		upstreamHeaders.Accept = req.headers.accept as string;
	}
	if (req.headers["git-protocol"]) {
		upstreamHeaders["Git-Protocol"] = req.headers["git-protocol"] as string;
	}

	// For POST requests, stream the body directly to upstream instead of buffering
	// This is critical for large git pushes that can be hundreds of MB
	const requestBody = req.method === "POST" ? Readable.toWeb(req) : undefined;

	try {
		const upstreamResponse = await fetch(upstreamUrl, {
			method: req.method,
			headers: upstreamHeaders,
			body: requestBody,
			// Required for streaming request body in fetch
			duplex: "half",
		});

		// Log the operation
		const operation = getGitOperation(req.method ?? "GET", parsed.path, req.url ?? "");
		logger.info(
			{
				sessionId: session.sessionId,
				operation: operation.type,
				repo: operation.repo,
				status: upstreamResponse.status,
			},
			"git proxy request completed",
		);

		// Forward response headers, excluding hop-by-hop headers
		upstreamResponse.headers.forEach((value, key) => {
			const lowerKey = key.toLowerCase();
			if (
				!["transfer-encoding", "connection", "keep-alive", "content-encoding"].includes(lowerKey)
			) {
				res.setHeader(key, value);
			}
		});

		res.writeHead(upstreamResponse.status);

		// Stream response body with proper backpressure handling
		if (upstreamResponse.body) {
			// Convert Web ReadableStream to Node.js Readable for pipeline
			const nodeStream = Readable.fromWeb(upstreamResponse.body);
			await pipeline(nodeStream, res);
		} else {
			res.end();
		}
	} catch (err) {
		logger.error({ error: String(err), url: upstreamUrl }, "git proxy upstream request failed");
		// Only send error response if headers haven't been sent
		if (!res.headersSent) {
			res.writeHead(502, { "Content-Type": "text/plain" });
			res.end("Bad gateway: upstream request failed");
		} else {
			res.end();
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Server
// ═══════════════════════════════════════════════════════════════════════════════

const DEFAULT_CONFIG: GitProxyConfig = {
	port: 8791,
	host: "127.0.0.1",
	allowedHosts: ["github.com"],
	rateLimitPerMinute: 60,
};

export function startGitProxyServer(config: Partial<GitProxyConfig> = {}): http.Server {
	const finalConfig: GitProxyConfig = {
		port: config.port ?? Number(process.env.TELCLAUDE_GIT_PROXY_PORT ?? DEFAULT_CONFIG.port),
		host: config.host ?? (getSandboxMode() === "docker" ? "0.0.0.0" : DEFAULT_CONFIG.host),
		allowedHosts: config.allowedHosts ?? DEFAULT_CONFIG.allowedHosts,
		rateLimitPerMinute: config.rateLimitPerMinute ?? DEFAULT_CONFIG.rateLimitPerMinute,
	};

	const server = http.createServer(async (req, res) => {
		const url = req.url ?? "";

		// Health check
		if (url === "/health" && req.method === "GET") {
			res.writeHead(200, { "Content-Type": "application/json" });
			res.end(JSON.stringify({ ok: true, service: "git-proxy" }));
			return;
		}

		// Identity endpoint - returns bot identity for git config
		if (url === "/identity" && req.method === "GET") {
			const identity = await getGitHubAppIdentity();
			if (!identity) {
				res.writeHead(503, { "Content-Type": "application/json" });
				res.end(JSON.stringify({ error: "GitHub App not configured" }));
				return;
			}
			res.writeHead(200, { "Content-Type": "application/json" });
			res.end(JSON.stringify(identity));
			return;
		}

		// Validate session token
		const sessionHeader = req.headers["x-telclaude-session"] as string | undefined;
		if (!sessionHeader) {
			logger.warn({ url }, "git proxy request missing session token");
			res.writeHead(401, { "Content-Type": "text/plain" });
			res.end("Unauthorized: missing session token");
			return;
		}

		const session = validateSessionToken(sessionHeader);
		if (!session) {
			logger.warn({ url }, "git proxy request with invalid session token");
			res.writeHead(401, { "Content-Type": "text/plain" });
			res.end("Unauthorized: invalid session token");
			return;
		}

		// Rate limiting
		if (!checkRateLimit(session.sessionId, finalConfig.rateLimitPerMinute)) {
			logger.warn({ sessionId: session.sessionId }, "git proxy rate limit exceeded");
			res.writeHead(429, { "Content-Type": "text/plain" });
			res.end("Too many requests");
			return;
		}

		// Parse git URL
		const parsed = parseGitUrl(url);
		if (!parsed) {
			logger.warn({ url }, "git proxy invalid URL format");
			res.writeHead(400, { "Content-Type": "text/plain" });
			res.end("Bad request: invalid git URL format");
			return;
		}

		// Validate host is allowed
		if (!finalConfig.allowedHosts.includes(parsed.host)) {
			logger.warn({ host: parsed.host }, "git proxy request to non-allowed host");
			res.writeHead(403, { "Content-Type": "text/plain" });
			res.end(`Forbidden: host ${parsed.host} not allowed`);
			return;
		}

		// Validate method
		if (req.method !== "GET" && req.method !== "POST") {
			res.writeHead(405, { "Content-Type": "text/plain" });
			res.end("Method not allowed");
			return;
		}

		// Proxy the request
		await proxyRequest(req, res, parsed, session);
	});

	server.listen(finalConfig.port, finalConfig.host, () => {
		logger.info({ host: finalConfig.host, port: finalConfig.port }, "git proxy server listening");
	});

	return server;
}

export { parseGitUrl, getGitOperation };
