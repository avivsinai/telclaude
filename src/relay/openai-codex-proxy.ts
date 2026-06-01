import crypto from "node:crypto";
import type http from "node:http";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";

import { getChildLogger } from "../logging.js";
import { getVaultClient, isVaultAvailable } from "../vault-daemon/client.js";
import {
	extractOpenAiCodexRelayProofToken,
	OPENAI_CODEX_RELAY_PROOF_SCHEMA_VERSION,
	OPENAI_CODEX_RELAY_PROOF_SOURCE,
	OPENAI_CODEX_RESPONSES_PATH,
	type OpenAiCodexRelayProof,
	openAiCodexRelayProofTokenSha256,
	signOpenAiCodexRelayProof,
} from "./openai-codex-relay-proof.js";
import { forwardResponseHeaders } from "./proxy-headers.js";
import { SlidingWindowRateLimiter } from "./shared-rate-limiter.js";

const logger = getChildLogger({ module: "openai-codex-proxy" });

const PROXY_PREFIX = "/v1/openai-codex-proxy";
const PROXY_PROOF_LATEST_PATH = `${PROXY_PREFIX}/_telclaude/relay-proof/latest`;
const CODEX_ORIGIN = "https://chatgpt.com";
const CODEX_BASE_PATH = "/backend-api/codex";
const CODEX_VAULT_TARGET = process.env.TELCLAUDE_OPENAI_CODEX_VAULT_TARGET ?? "openai-codex";
const CODEX_SECRET_TARGET =
	process.env.TELCLAUDE_OPENAI_CODEX_SECRET_TARGET ?? "openai-codex-oauth";
const PROXY_TOKEN_ENV = "TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN";
const RATE_LIMIT_PER_MINUTE = Number(process.env.TELCLAUDE_OPENAI_CODEX_PROXY_RPM ?? 120);
const MODEL_RELAY_OBSERVED_PEER_HEADER = "x-telclaude-model-relay-observed-peer-address";
const RAW_MODEL_PROVIDER_CREDENTIAL_PATTERN =
	/\b(?:sk-ant|sk-proj|sk-[A-Za-z0-9])[A-Za-z0-9_-]{8,}\b/;
const CODEX_ALLOWED_REQUESTS = [
	{ method: "GET", path: `${CODEX_BASE_PATH}/models` },
	{ method: "POST", path: `${CODEX_BASE_PATH}/responses` },
] as const;
const MAX_CODEX_REQUEST_BODY_BYTES = Number(
	process.env.TELCLAUDE_OPENAI_CODEX_PROXY_BODY_LIMIT ?? 1_000_000,
);

type CodexRelayProof = OpenAiCodexRelayProof;

type AuthHeader = {
	name: string;
	value: string;
	source: string;
	extraHeaders?: Record<string, string>;
};

const rateLimiter = new SlidingWindowRateLimiter();
const latestResponseProofByPeer = new Map<string, CodexRelayProof>();

export function isOpenAiCodexProxyRequest(url: string): boolean {
	return url === PROXY_PREFIX || url.startsWith(`${PROXY_PREFIX}/`);
}

export function resetOpenAiCodexProxyState(): void {
	rateLimiter.stopCleanup();
	latestResponseProofByPeer.clear();
}

export async function handleOpenAiCodexProxyRequest(
	req: http.IncomingMessage,
	res: http.ServerResponse,
): Promise<void> {
	const remoteAddress = normalizeRemoteAddress(req.socket.remoteAddress ?? null);
	const observedPeerAddress = normalizeObservedPeerAddress(remoteAddress);
	if (observedPeerAddress) {
		res.setHeader(MODEL_RELAY_OBSERVED_PEER_HEADER, observedPeerAddress);
	}

	if (!isOpenAiCodexProxyAllowedClientAddress(remoteAddress)) {
		logger.warn({ remoteAddress }, "[openai-codex-proxy] blocked non-private client");
		writeJson(res, 403, { error: "Forbidden." });
		return;
	}

	if (RATE_LIMIT_PER_MINUTE > 0 && remoteAddress) {
		if (!rateLimiter.check(remoteAddress, RATE_LIMIT_PER_MINUTE)) {
			writeJson(res, 429, { error: "Rate limited." });
			return;
		}
	}

	const proxyToken = process.env[PROXY_TOKEN_ENV];
	if (!proxyToken) {
		logger.warn("[openai-codex-proxy] missing relay proxy token");
		writeJson(res, 500, { error: "Proxy token not configured." });
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
			"[openai-codex-proxy] invalid proxy token",
		);
		writeJson(res, 401, { error: "Unauthorized." });
		return;
	}

	if (req.url === PROXY_PROOF_LATEST_PATH) {
		handleRelayProofRequest(req, res, observedPeerAddress);
		return;
	}

	const normalizedPath = normalizeCodexProxyPath(req.url ?? "");
	if (!normalizedPath) {
		writeJson(res, 400, { error: "Invalid OpenAI Codex API path." });
		return;
	}

	const method = (req.method ?? "POST").toUpperCase();
	if (!isAllowedCodexProxyRequest(method, normalizedPath)) {
		logger.warn(
			{ remoteAddress, method, path: normalizedPath },
			"[openai-codex-proxy] blocked unapproved Codex API request",
		);
		writeJson(res, 403, { error: "OpenAI Codex API path is not allowed." });
		return;
	}

	const authHeader = await buildAuthHeader();
	if (!authHeader) {
		logger.warn("[openai-codex-proxy] missing relay-owned Codex subscription credentials");
		writeJson(res, 500, { error: "OpenAI Codex subscription credentials not configured." });
		return;
	}

	const targetUrl = `${CODEX_ORIGIN}${normalizedPath}`;
	const headers = sanitizeRequestHeaders(req.headers, authHeader);
	const hasBody = !["GET", "HEAD"].includes(method);
	let requestBody: Buffer | undefined;
	if (hasBody) {
		try {
			requestBody = await readRequestBodyLimited(req, MAX_CODEX_REQUEST_BODY_BYTES);
		} catch (error) {
			logger.warn({ error: String(error) }, "[openai-codex-proxy] request body rejected");
			writeJson(res, 413, { error: "Request body too large." });
			return;
		}
	}

	logger.info(
		{ method, path: normalizedPath, authSource: authHeader.source },
		"proxying to OpenAI Codex subscription backend",
	);
	let upstream: Response;
	try {
		upstream = await fetch(targetUrl, {
			method,
			headers,
			body: requestBody,
			...(hasBody ? { duplex: "half" } : {}),
		});
	} catch (err) {
		logger.warn({ error: String(err) }, "[openai-codex-proxy] upstream fetch failed");
		writeJson(res, 502, { error: "Upstream request failed." });
		return;
	}

	res.statusCode = upstream.status;
	if (
		method === "POST" &&
		new URL(normalizedPath, CODEX_ORIGIN).pathname === `${CODEX_BASE_PATH}/responses` &&
		observedPeerAddress &&
		requestBody
	) {
		try {
			latestResponseProofByPeer.set(
				observedPeerAddress,
				buildCodexRelayProof({
					observedPeerAddress,
					upstreamStatus: upstream.status,
					requestBody,
				}),
			);
		} catch (error) {
			latestResponseProofByPeer.delete(observedPeerAddress);
			logger.warn(
				{ error: String(error), observedPeerAddress },
				"[openai-codex-proxy] failed to sign relay proof",
			);
		}
	}
	forwardResponseHeaders(upstream, res);
	if (observedPeerAddress) {
		res.setHeader(MODEL_RELAY_OBSERVED_PEER_HEADER, observedPeerAddress);
	}

	if (!upstream.body) {
		res.end();
		return;
	}

	const nodeStream = Readable.fromWeb(upstream.body as import("stream/web").ReadableStream);
	try {
		await pipeline(nodeStream, res);
	} catch (err) {
		logger.warn({ error: String(err) }, "[openai-codex-proxy] response stream failed");
		if (!res.headersSent) {
			writeJson(res, 502, { error: "Upstream response failed." });
		} else {
			res.end();
		}
	}
}

function handleRelayProofRequest(
	req: http.IncomingMessage,
	res: http.ServerResponse,
	observedPeerAddress: string | undefined,
): void {
	if (req.method !== "GET") {
		writeJson(res, 405, { error: "Method not allowed." });
		return;
	}
	if (!observedPeerAddress) {
		writeJson(res, 403, { error: "Forbidden." });
		return;
	}
	const proof = latestResponseProofByPeer.get(observedPeerAddress);
	if (!proof) {
		writeJson(res, 404, { error: "No relay proof recorded for peer." });
		return;
	}
	writeJson(res, 200, proof);
}

function buildCodexRelayProof(input: {
	observedPeerAddress: string;
	upstreamStatus: number;
	requestBody: Buffer;
}): CodexRelayProof {
	const proofToken = extractOpenAiCodexRelayProofToken(input.requestBody.toString("utf8"));
	return signOpenAiCodexRelayProof({
		schemaVersion: OPENAI_CODEX_RELAY_PROOF_SCHEMA_VERSION,
		source: OPENAI_CODEX_RELAY_PROOF_SOURCE,
		requestId: crypto.randomUUID(),
		method: "POST",
		path: OPENAI_CODEX_RESPONSES_PATH,
		observedPeerAddress: input.observedPeerAddress,
		upstreamStatus: input.upstreamStatus,
		model: extractCodexRequestModel(input.requestBody),
		requestBodySha256: `sha256:${crypto
			.createHash("sha256")
			.update(input.requestBody)
			.digest("hex")}`,
		...(proofToken ? { proofTokenSha256: openAiCodexRelayProofTokenSha256(proofToken) } : {}),
		observedAt: new Date().toISOString(),
	});
}

function extractCodexRequestModel(body: Buffer): string {
	try {
		const parsed = JSON.parse(body.toString("utf8")) as Record<string, unknown>;
		for (const key of ["model", "model_slug", "modelSlug"]) {
			const value = parsed[key];
			if (typeof value === "string" && value.trim()) return value.trim();
		}
	} catch {
		// Keep the proof non-secret and explicit if the body cannot be parsed.
	}
	return "unknown";
}

async function readRequestBodyLimited(
	req: http.IncomingMessage,
	maxBytes: number,
): Promise<Buffer> {
	const chunks: Buffer[] = [];
	let total = 0;
	for await (const chunk of req) {
		const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
		total += buffer.length;
		if (total > maxBytes) {
			throw new Error(`request body exceeded ${maxBytes} bytes`);
		}
		chunks.push(buffer);
	}
	return Buffer.concat(chunks);
}

async function buildAuthHeader(): Promise<AuthHeader | null> {
	const accessToken = await getRelayOwnedCodexAccessToken();
	if (!accessToken) return null;
	return {
		name: "Authorization",
		value: `Bearer ${accessToken}`,
		source: "relay-vault-codex-oauth",
		extraHeaders: codexCloudflareHeaders(accessToken),
	};
}

async function getRelayOwnedCodexAccessToken(): Promise<string | null> {
	if (await isVaultAvailable()) {
		const client = getVaultClient();
		try {
			const token = await client.getToken(CODEX_VAULT_TARGET);
			if (token.ok) {
				const sanitized = sanitizeRelayOwnedCodexAccessToken(
					token.token,
					`vault-token:${CODEX_VAULT_TARGET}`,
				);
				return sanitized;
			}
		} catch (error) {
			logger.warn({ error: String(error) }, "[openai-codex-proxy] vault token lookup failed");
		}

		try {
			const secret = await client.getSecret(CODEX_SECRET_TARGET, { timeout: 5000 });
			if (secret.ok && secret.type === "get-secret" && secret.value) {
				const parsed = parseOpaqueCodexAccessToken(secret.value);
				if (parsed) {
					const sanitized = sanitizeRelayOwnedCodexAccessToken(
						parsed,
						`vault-secret:${CODEX_SECRET_TARGET}`,
					);
					return sanitized;
				}
			}
		} catch (error) {
			logger.warn({ error: String(error) }, "[openai-codex-proxy] vault secret lookup failed");
		}
	}
	return sanitizeRelayOwnedCodexAccessToken(
		process.env.TELCLAUDE_OPENAI_CODEX_OAUTH_TOKEN,
		"env:TELCLAUDE_OPENAI_CODEX_OAUTH_TOKEN",
	);
}

function sanitizeRelayOwnedCodexAccessToken(
	value: string | undefined,
	source: string,
): string | null {
	const trimmed = value?.trim();
	if (!trimmed) return null;
	if (RAW_MODEL_PROVIDER_CREDENTIAL_PATTERN.test(trimmed)) {
		logger.warn({ source }, "[openai-codex-proxy] rejected raw provider-like Codex credential");
		return null;
	}
	return trimmed;
}

function parseOpaqueCodexAccessToken(raw: string): string | null {
	const trimmed = raw.trim();
	if (!trimmed) return null;
	if (!trimmed.startsWith("{")) return trimmed;
	try {
		const parsed = JSON.parse(trimmed) as Record<string, unknown>;
		for (const key of ["access_token", "accessToken", "token"]) {
			const value = parsed[key];
			if (typeof value === "string" && value.trim()) return value.trim();
		}
	} catch {
		return null;
	}
	return null;
}

function codexCloudflareHeaders(accessToken: string): Record<string, string> {
	const headers: Record<string, string> = {
		"User-Agent": "codex_cli_rs/0.0.0 (Telclaude Relay)",
		originator: "codex_cli_rs",
	};
	const accountId = chatGptAccountId(accessToken);
	if (accountId) headers["ChatGPT-Account-ID"] = accountId;
	return headers;
}

function chatGptAccountId(accessToken: string): string | null {
	try {
		const parts = accessToken.split(".");
		if (parts.length < 2) return null;
		const payload = `${parts[1]}${"=".repeat((4 - ((parts[1]?.length ?? 0) % 4)) % 4)}`;
		const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Record<
			string,
			unknown
		>;
		const authClaims = claims["https://api.openai.com/auth"];
		if (typeof authClaims !== "object" || authClaims === null) return null;
		const accountId = (authClaims as Record<string, unknown>).chatgpt_account_id;
		return typeof accountId === "string" && accountId ? accountId : null;
	} catch {
		return null;
	}
}

function normalizeCodexProxyPath(url: string): string | null {
	const suffix = url.slice(PROXY_PREFIX.length);
	const targetPath = suffix.length === 0 ? "/" : suffix;
	if (
		targetPath.startsWith("http://") ||
		targetPath.startsWith("https://") ||
		targetPath.startsWith("//")
	) {
		return null;
	}
	let decodedPath = targetPath;
	try {
		for (let iteration = 0; iteration < 3; iteration += 1) {
			const nextDecodedPath = decodeURIComponent(decodedPath);
			if (nextDecodedPath === decodedPath) break;
			decodedPath = nextDecodedPath;
		}
	} catch {
		return null;
	}
	if (decodedPath.includes("..") || decodedPath.includes("\\") || decodedPath.includes("://")) {
		return null;
	}
	const normalized = new URL(`${CODEX_BASE_PATH}${targetPath}`, CODEX_ORIGIN);
	if (
		normalized.origin !== CODEX_ORIGIN ||
		!normalized.pathname.startsWith(`${CODEX_BASE_PATH}/`)
	) {
		return null;
	}
	return `${normalized.pathname}${normalized.search}`;
}

function isAllowedCodexProxyRequest(method: string, normalizedPath: string): boolean {
	let pathname: string;
	try {
		pathname = new URL(normalizedPath, CODEX_ORIGIN).pathname;
	} catch {
		return false;
	}
	return CODEX_ALLOWED_REQUESTS.some(
		(allowed) => allowed.method === method && allowed.path === pathname,
	);
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
		"accept-encoding",
		"cookie",
		"set-cookie",
		"chatgpt-account-id",
		"openai-organization",
		"openai-project",
		"origin",
		"referer",
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
		for (const [key, value] of Object.entries(authHeader.extraHeaders)) {
			filtered[key] = value;
		}
	}
	return filtered;
}

function extractProxyToken(req: http.IncomingMessage): string | null {
	return (
		extractBearerToken(req.headers.authorization) ??
		singleHeaderValue(req.headers["x-api-key"])?.trim() ??
		null
	);
}

function extractBearerToken(headerValue: string | string[] | undefined): string | null {
	const raw = singleHeaderValue(headerValue);
	if (!raw) return null;
	const trimmed = raw.trim();
	if (!trimmed) return null;
	const match = trimmed.match(/^Bearer\s+(.+)$/i);
	if (!match) return null;
	return match[1]?.trim() ?? null;
}

function singleHeaderValue(headerValue: string | string[] | undefined): string | null {
	if (!headerValue) return null;
	if (Array.isArray(headerValue)) return null;
	return headerValue;
}

function constantTimeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	return crypto.timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

function writeJson(res: http.ServerResponse, status: number, payload: unknown): void {
	const body = JSON.stringify(payload);
	res.writeHead(status, {
		"Content-Type": "application/json; charset=utf-8",
		"Content-Length": Buffer.byteLength(body),
	});
	res.end(body);
}

function normalizeRemoteAddress(remoteAddress?: string | null): string | null {
	if (!remoteAddress) return null;
	if (remoteAddress.startsWith("::ffff:")) return remoteAddress.slice("::ffff:".length);
	return remoteAddress;
}

function normalizeObservedPeerAddress(remoteAddress?: string | null): string | undefined {
	const trimmed = remoteAddress?.trim();
	if (!trimmed) return undefined;
	if (trimmed.startsWith("::ffff:")) return trimmed.slice("::ffff:".length);
	if (trimmed === "::1") return "127.0.0.1";
	return trimmed;
}

export function isOpenAiCodexProxyAllowedClientAddress(address: string | null): boolean {
	const normalized = normalizeRemoteAddress(address)?.toLowerCase();
	if (!normalized) return false;
	if (normalized === "127.0.0.1" || normalized === "::1") return true;
	if (normalized.startsWith("10.")) return true;
	if (normalized.startsWith("192.168.")) return true;
	const octets = normalized.split(".");
	if (octets.length === 4) {
		const first = Number.parseInt(octets[0] ?? "", 10);
		const second = Number.parseInt(octets[1] ?? "", 10);
		if (first === 172 && second >= 16 && second <= 31) return true;
	}
	if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true;
	return false;
}
