import fs from "node:fs";
import type http from "node:http";
import os from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";

import { getChildLogger } from "../logging.js";

const logger = getChildLogger({ module: "anthropic-proxy" });

const PROXY_PREFIX = "/v1/anthropic-proxy";
const ANTHROPIC_ORIGIN = "https://api.anthropic.com";
const RATE_LIMIT_PER_MINUTE = Number(process.env.TELCLAUDE_ANTHROPIC_PROXY_RPM ?? 120);

type AuthHeader = { name: string; value: string; source: string };

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
	}
	if (address.startsWith("fc") || address.startsWith("fd")) return true; // IPv6 ULA
	if (address.startsWith("fe80:")) return true; // IPv6 link-local
	return false;
}

function buildAuthHeader(): AuthHeader | null {
	const oauthToken = process.env.CLAUDE_CODE_OAUTH_TOKEN || process.env.ANTHROPIC_AUTH_TOKEN;
	if (oauthToken) {
		return { name: "Authorization", value: `Bearer ${oauthToken}`, source: "env" };
	}

	const apiKey = process.env.ANTHROPIC_API_KEY;
	if (apiKey) {
		return { name: "x-api-key", value: apiKey, source: "env" };
	}

	const credentialsPath =
		process.env.CLAUDE_CODE_CREDENTIALS_PATH ??
		path.join(process.env.HOME ?? os.homedir(), ".claude", ".credentials.json");
	try {
		const raw = fs.readFileSync(credentialsPath, "utf8");
		const parsed = JSON.parse(raw) as Record<string, unknown>;
		const token =
			extractToken(parsed, ["access_token", "accessToken"]) ??
			extractToken(parsed, ["oauth_token", "oauthToken", "token"]);
		if (token) {
			return { name: "Authorization", value: `Bearer ${token}`, source: "file" };
		}
	} catch {
		// Ignore missing/invalid credentials file
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
	return filtered;
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

	const authHeader = buildAuthHeader();
	if (!authHeader) {
		logger.warn("[anthropic-proxy] missing Anthropic credentials");
		res.writeHead(500, { "Content-Type": "application/json" });
		res.end(JSON.stringify({ error: "Anthropic credentials not configured." }));
		return;
	}

	const url = req.url ?? "";
	const suffix = url.slice(PROXY_PREFIX.length);
	const targetPath = suffix.length === 0 ? "/" : suffix;
	if (targetPath.startsWith("http://") || targetPath.startsWith("https://")) {
		res.writeHead(400, { "Content-Type": "application/json" });
		res.end(JSON.stringify({ error: "Invalid proxy path." }));
		return;
	}
	if (!targetPath.startsWith("/v1/")) {
		res.writeHead(400, { "Content-Type": "application/json" });
		res.end(JSON.stringify({ error: "Invalid Anthropic API path." }));
		return;
	}

	const targetUrl = `${ANTHROPIC_ORIGIN}${targetPath}`;
	const method = req.method ?? "POST";
	const headers = sanitizeRequestHeaders(req.headers, authHeader);

	const hasBody = !["GET", "HEAD"].includes(method.toUpperCase());

	logger.info({ method, path: targetPath, authSource: authHeader.source }, "proxying to Anthropic");
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
