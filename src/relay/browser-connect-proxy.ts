/**
 * Relay-owned HTTP CONNECT proxy for brokered browser egress.
 *
 * The proxy deliberately does not terminate TLS. It validates the CONNECT
 * authority, resolves and blocks private/metadata/provider-adjacent targets,
 * dials the validated IP directly, then tunnels bytes without inspecting HTTPS.
 */

import { once } from "node:events";
import http from "node:http";
import net from "node:net";

import { getChildLogger } from "../logging.js";
import { BLOCKED_METADATA_DOMAINS } from "../sandbox/config.js";
import { getSandboxMode } from "../sandbox/index.js";
import {
	cachedDNSLookup,
	isBlockedIP,
	isNonOverridableBlock,
	isPrivateIP,
} from "../sandbox/network-proxy.js";
import {
	type BrowserConnectContextVerification,
	type BrowserConnectContextVerifier,
	hostMatchesBrowserOriginScope,
} from "./browser-connect-contract.js";
import { SlidingWindowRateLimiter } from "./shared-rate-limiter.js";

const logger = getChildLogger({ module: "browser-connect-proxy" });

const DEFAULT_PORT = 8794;
const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_ALLOWED_PORTS = [443];
const DEFAULT_CLIENT_TO_UPSTREAM_BYTE_BUDGET = 2 * 1024 * 1024;
const DEFAULT_RATE_LIMIT_PER_MINUTE = 120;

export interface BrowserConnectProxyConfig {
	readonly port: number;
	readonly host: string;
	readonly allowedPorts: readonly number[];
	readonly requireContextIdentity: boolean;
	readonly clientToUpstreamByteBudget: number;
	readonly rateLimitPerMinute: number;
	readonly contextVerifier?: BrowserConnectContextVerifier;
	readonly resolveHost?: (host: string) => Promise<readonly string[] | null>;
	readonly dial?: (options: net.NetConnectOpts) => net.Socket;
}

export interface BrowserConnectProxyHandle {
	readonly server: http.Server;
	readonly stop: () => Promise<void>;
}

export interface ParsedConnectAuthority {
	readonly host: string;
	readonly port: number;
}

export interface ValidatedConnectTarget {
	readonly authority: ParsedConnectAuthority;
	readonly validatedIp: string;
	readonly resolvedIps: readonly string[];
}

export type BrowserConnectValidationFailureCode =
	| "invalid-authority"
	| "port-denied"
	| "blocked-host"
	| "resolution-failed"
	| "blocked-ip";

export interface BrowserConnectValidationFailure {
	readonly code: BrowserConnectValidationFailureCode;
	readonly reason: string;
}

export type BrowserConnectValidationResult =
	| { readonly allowed: true; readonly target: ValidatedConnectTarget }
	| { readonly allowed: false; readonly failure: BrowserConnectValidationFailure };

export function readBrowserConnectProxyConfigFromEnv(
	overrides: Partial<BrowserConnectProxyConfig> = {},
): BrowserConnectProxyConfig {
	return {
		port:
			overrides.port ?? Number(process.env.TELCLAUDE_BROWSER_CONNECT_PROXY_PORT ?? DEFAULT_PORT),
		host:
			overrides.host ??
			process.env.TELCLAUDE_BROWSER_CONNECT_PROXY_HOST ??
			(getSandboxMode() === "docker" ? "0.0.0.0" : DEFAULT_HOST),
		allowedPorts:
			overrides.allowedPorts ??
			parsePortList(process.env.TELCLAUDE_BROWSER_CONNECT_PROXY_ALLOWED_PORTS) ??
			DEFAULT_ALLOWED_PORTS,
		requireContextIdentity:
			overrides.requireContextIdentity ??
			process.env.TELCLAUDE_BROWSER_CONNECT_PROXY_REQUIRE_CONTEXT !== "0",
		clientToUpstreamByteBudget:
			overrides.clientToUpstreamByteBudget ??
			Number(
				process.env.TELCLAUDE_BROWSER_CONNECT_PROXY_CLIENT_TO_UPSTREAM_BYTES ??
					DEFAULT_CLIENT_TO_UPSTREAM_BYTE_BUDGET,
			),
		rateLimitPerMinute:
			overrides.rateLimitPerMinute ??
			Number(
				process.env.TELCLAUDE_BROWSER_CONNECT_PROXY_RATE_LIMIT_PER_MINUTE ??
					DEFAULT_RATE_LIMIT_PER_MINUTE,
			),
		contextVerifier: overrides.contextVerifier,
		resolveHost: overrides.resolveHost,
		dial: overrides.dial,
	};
}

export function startBrowserConnectProxy(
	config: Partial<BrowserConnectProxyConfig> = {},
): BrowserConnectProxyHandle {
	const finalConfig = readBrowserConnectProxyConfigFromEnv(config);
	const rateLimiter = new SlidingWindowRateLimiter();
	rateLimiter.startCleanup();

	const server = http.createServer((req, res) => {
		if (req.method === "GET" && req.url === "/health") {
			res.writeHead(200, { "Content-Type": "application/json" });
			res.end(JSON.stringify({ ok: true, service: "browser-connect-proxy" }));
			return;
		}
		res.writeHead(405, { "Content-Type": "text/plain" });
		res.end("Method not allowed");
	});

	server.on("connect", (req, clientSocket, head) => {
		void handleConnectRequest(req, clientSocket as net.Socket, head, finalConfig, rateLimiter);
	});

	server.on("clientError", (_err, socket) => {
		socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
	});

	server.listen(finalConfig.port, finalConfig.host, () => {
		logger.info(
			{
				host: finalConfig.host,
				port: finalConfig.port,
				requireContextIdentity: finalConfig.requireContextIdentity,
			},
			"browser CONNECT proxy listening",
		);
	});

	return {
		server,
		stop: async () => {
			rateLimiter.stopCleanup();
			return new Promise((resolve) => {
				server.close(() => resolve());
			});
		},
	};
}

export async function validateBrowserConnectTarget(
	authority: string,
	options: {
		readonly allowedPorts?: readonly number[];
		readonly resolveHost?: (host: string) => Promise<readonly string[] | null>;
	} = {},
): Promise<BrowserConnectValidationResult> {
	const parsed = parseConnectAuthority(authority);
	if (!parsed) {
		return {
			allowed: false,
			failure: { code: "invalid-authority", reason: "invalid CONNECT authority" },
		};
	}

	const allowedPorts = options.allowedPorts ?? DEFAULT_ALLOWED_PORTS;
	if (!allowedPorts.includes(parsed.port)) {
		return {
			allowed: false,
			failure: { code: "port-denied", reason: `CONNECT port ${parsed.port} is not allowed` },
		};
	}

	if (isBlockedHostName(parsed.host)) {
		return {
			allowed: false,
			failure: { code: "blocked-host", reason: `blocked host: ${parsed.host}` },
		};
	}

	const resolver = options.resolveHost ?? resolveConnectHost;
	const resolved = await resolver(parsed.host);
	if (!resolved || resolved.length === 0) {
		return {
			allowed: false,
			failure: { code: "resolution-failed", reason: `failed to resolve ${parsed.host}` },
		};
	}

	const normalizedIps: string[] = [];
	for (const rawIp of resolved) {
		const normalizedIp = normalizeIpForBlocking(rawIp);
		if (!normalizedIp) {
			return {
				allowed: false,
				failure: { code: "blocked-ip", reason: `invalid resolved IP: ${rawIp}` },
			};
		}
		if (isBlockedConnectIp(normalizedIp)) {
			return {
				allowed: false,
				failure: { code: "blocked-ip", reason: `blocked resolved IP: ${rawIp}` },
			};
		}
		normalizedIps.push(normalizedIp);
	}

	return {
		allowed: true,
		target: {
			authority: parsed,
			validatedIp: normalizedIps[0] as string,
			resolvedIps: normalizedIps,
		},
	};
}

export function parseConnectAuthority(authority: string): ParsedConnectAuthority | null {
	const raw = authority.trim();
	if (!raw || /[\s/@%]/.test(raw)) return null;

	let host: string;
	let portText: string;
	if (raw.startsWith("[")) {
		const match = raw.match(/^\[([^\]]+)\]:(\d{1,5})$/);
		if (!match) return null;
		host = match[1] ?? "";
		portText = match[2] ?? "";
	} else {
		const parts = raw.split(":");
		if (parts.length !== 2) return null;
		host = parts[0] ?? "";
		portText = parts[1] ?? "";
	}

	if (!host || !portText) return null;
	const port = Number(portText);
	if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
	const normalizedHost = normalizeConnectHost(host);
	if (!normalizedHost) return null;
	return { host: normalizedHost, port };
}

export function normalizeIpForBlocking(ip: string): string | null {
	const trimmed = ip.trim();
	if (!trimmed) return null;
	const withoutBrackets =
		trimmed.startsWith("[") && trimmed.endsWith("]") ? trimmed.slice(1, -1) : trimmed;
	if (net.isIP(withoutBrackets) === 4) return withoutBrackets;
	if (net.isIP(withoutBrackets) !== 6) return null;

	const ipv4Mapped = withoutBrackets.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
	if (ipv4Mapped?.[1] && net.isIP(ipv4Mapped[1]) === 4) return ipv4Mapped[1];

	const nat64 = extractWellKnownNat64Ipv4(withoutBrackets);
	if (nat64) return nat64;
	return withoutBrackets;
}

async function handleConnectRequest(
	req: http.IncomingMessage,
	clientSocket: net.Socket,
	head: Buffer,
	config: BrowserConnectProxyConfig,
	rateLimiter: SlidingWindowRateLimiter,
): Promise<void> {
	const remoteAddress = clientSocket.remoteAddress ?? "";
	const authority = req.url ?? "";
	const targetResult = await validateBrowserConnectTarget(authority, config);
	if (!targetResult.allowed) {
		logger.warn({ authority, failure: targetResult.failure.code }, "browser CONNECT target denied");
		denyConnect(clientSocket, 403, targetResult.failure.reason);
		return;
	}

	const contextResult = await validateBrowserConnectContext(
		req.headers,
		targetResult.target,
		remoteAddress,
		config,
	);
	if (!contextResult.allowed || !contextResult.context) {
		logger.warn(
			{ authority, reason: contextResult.reason },
			"browser CONNECT context identity denied",
		);
		denyConnect(clientSocket, 407, contextResult.reason ?? "proxy context identity required");
		return;
	}

	const rateLimitKey =
		contextResult.context.sessionRef ??
		contextResult.context.actor ??
		contextResult.context.contextId ??
		remoteAddress;
	if (!rateLimiter.check(rateLimitKey, config.rateLimitPerMinute)) {
		denyConnect(clientSocket, 429, "too many CONNECT requests");
		return;
	}

	const dialIp = targetResult.target.validatedIp;
	if (isBlockedConnectIp(dialIp)) {
		denyConnect(clientSocket, 403, "validated IP failed dial-time blocked-range recheck");
		return;
	}

	const upstreamSocket = config.dial
		? config.dial({ host: dialIp, port: targetResult.target.authority.port })
		: net.connect({ host: dialIp, port: targetResult.target.authority.port });

	const handleDialError = (err: Error) => {
		logger.warn(
			{
				host: targetResult.target.authority.host,
				validatedIp: dialIp,
				error: err instanceof Error ? err.message : String(err),
			},
			"browser CONNECT upstream dial failed",
		);
		denyConnect(clientSocket, 502, "upstream dial failed");
	};

	upstreamSocket.once("connect", () => {
		upstreamSocket.off("error", handleDialError);
		clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
		if (head.length > 0) upstreamSocket.write(head);
		void tunnelWithClientByteBudget(
			clientSocket,
			upstreamSocket,
			config.clientToUpstreamByteBudget,
		);
	});

	upstreamSocket.once("error", handleDialError);
}

export async function validateBrowserConnectContext(
	headers: http.IncomingHttpHeaders,
	target: ValidatedConnectTarget,
	remoteAddress: string,
	config: BrowserConnectProxyConfig,
): Promise<BrowserConnectContextVerification> {
	const token = extractProxyContextToken(headers);
	if (!token) {
		return config.requireContextIdentity
			? { allowed: false, reason: "relay-issued browser context token required" }
			: { allowed: true, context: { contextId: `anonymous:${remoteAddress || "unknown"}` } };
	}
	if (!config.contextVerifier) {
		return { allowed: false, reason: "browser context verifier is not configured" };
	}

	const verification = await config.contextVerifier({
		token,
		targetHost: target.authority.host,
		targetPort: target.authority.port,
		remoteAddress,
		headers,
	});
	if (!verification.allowed || !verification.context) return verification;

	const scope = verification.context.hydratedOriginScope ?? [];
	if (verification.context.cookieBearing && scope.length === 0) {
		return { allowed: false, reason: "cookie-bearing browser context has no origin scope" };
	}
	if (scope.length > 0 && !hostMatchesBrowserOriginScope(target.authority.host, scope)) {
		return {
			allowed: false,
			reason: "cookie-bearing browser context cannot egress outside hydrated origin scope",
		};
	}
	return verification;
}

async function tunnelWithClientByteBudget(
	clientSocket: net.Socket,
	upstreamSocket: net.Socket,
	clientToUpstreamByteBudget: number,
): Promise<void> {
	let clientBytes = 0;
	clientSocket.on("data", (chunk: Buffer) => {
		const budget = addBrowserConnectClientBytes(
			clientBytes,
			chunk.length,
			clientToUpstreamByteBudget,
		);
		clientBytes = budget.totalBytes;
		if (!budget.allowed) {
			clientSocket.destroy(new Error("browser CONNECT client byte budget exceeded"));
			upstreamSocket.destroy(new Error("browser CONNECT client byte budget exceeded"));
			return;
		}
		upstreamSocket.write(chunk);
	});
	upstreamSocket.on("data", (chunk: Buffer) => {
		clientSocket.write(chunk);
	});
	clientSocket.on("error", () => upstreamSocket.destroy());
	upstreamSocket.on("error", () => clientSocket.destroy());
	clientSocket.on("end", () => upstreamSocket.end());
	upstreamSocket.on("end", () => clientSocket.end());
	await Promise.race([once(clientSocket, "close"), once(upstreamSocket, "close")]);
}

export function addBrowserConnectClientBytes(
	currentBytes: number,
	chunkBytes: number,
	budgetBytes: number,
): { readonly allowed: boolean; readonly totalBytes: number } {
	const totalBytes = currentBytes + chunkBytes;
	return { allowed: totalBytes <= budgetBytes, totalBytes };
}

function denyConnect(clientSocket: net.Socket, status: number, reason: string): void {
	if (clientSocket.destroyed) return;
	const statusText =
		status === 407
			? "Proxy Authentication Required"
			: status === 429
				? "Too Many Requests"
				: status === 502
					? "Bad Gateway"
					: "Forbidden";
	clientSocket.end(
		`HTTP/1.1 ${status} ${statusText}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n${reason}`,
	);
}

async function resolveConnectHost(host: string): Promise<readonly string[] | null> {
	const literal = normalizeIpForBlocking(host);
	if (literal) return [literal];
	return cachedDNSLookup(host);
}

function isBlockedConnectIp(ip: string): boolean {
	return isNonOverridableBlock(ip) || isBlockedIP(ip) || isPrivateIP(ip);
}

function isBlockedHostName(host: string): boolean {
	const lower = host.toLowerCase();
	if (lower === "localhost" || lower.endsWith(".localhost")) return true;
	return BLOCKED_METADATA_DOMAINS.some((blocked) => lower === blocked.toLowerCase());
}

function normalizeConnectHost(host: string): string | null {
	const trimmed = host.trim().toLowerCase();
	if (!trimmed || trimmed.length > 253) return null;
	const literal = normalizeIpForBlocking(trimmed);
	if (literal) return literal;
	if (trimmed.includes("..") || trimmed.startsWith(".") || trimmed.endsWith(".")) return null;
	if (!/^[a-z0-9.-]+$/.test(trimmed)) return null;
	if (!trimmed.includes(".")) return null;
	return trimmed;
}

function extractProxyContextToken(headers: http.IncomingHttpHeaders): string | null {
	const explicit = firstHeaderValue(headers["x-telclaude-browser-context"]);
	if (explicit) return explicit;
	const proxyAuthorization = firstHeaderValue(headers["proxy-authorization"]);
	if (!proxyAuthorization) return null;
	const bearer = proxyAuthorization.match(/^Bearer\s+(.+)$/i);
	if (bearer?.[1]) return bearer[1].trim();
	return null;
}

function firstHeaderValue(value: string | string[] | undefined): string | null {
	const first = Array.isArray(value) ? value[0] : value;
	const trimmed = first?.trim();
	return trimmed ? trimmed : null;
}

function extractWellKnownNat64Ipv4(ipv6: string): string | null {
	const expanded = expandIpv6(ipv6);
	if (!expanded) return null;
	const prefix = expanded.slice(0, 6).join(":");
	if (prefix !== "0064:ff9b:0000:0000:0000:0000") return null;
	const high = Number.parseInt(expanded[6] ?? "", 16);
	const low = Number.parseInt(expanded[7] ?? "", 16);
	if (!Number.isFinite(high) || !Number.isFinite(low)) return null;
	return [high >> 8, high & 0xff, low >> 8, low & 0xff].join(".");
}

function expandIpv6(ipv6: string): string[] | null {
	if (ipv6.includes(".")) return null;
	const lower = ipv6.toLowerCase();
	const [left = "", right = ""] = lower.split("::");
	const hasCompression = lower.includes("::");
	if (lower.indexOf("::") !== lower.lastIndexOf("::")) return null;
	const leftParts = left ? left.split(":").filter(Boolean) : [];
	const rightParts = right ? right.split(":").filter(Boolean) : [];
	const missing = hasCompression ? 8 - leftParts.length - rightParts.length : 0;
	if (missing < 0) return null;
	const parts = hasCompression
		? [...leftParts, ...Array(missing).fill("0"), ...rightParts]
		: lower.split(":");
	if (parts.length !== 8) return null;
	if (parts.some((part) => !/^[a-f0-9]{1,4}$/.test(part))) return null;
	return parts.map((part) => part.padStart(4, "0"));
}

function parsePortList(raw: string | undefined): readonly number[] | null {
	if (!raw?.trim()) return null;
	const ports = raw
		.split(",")
		.map((part) => Number(part.trim()))
		.filter((port) => Number.isInteger(port) && port > 0 && port <= 65535);
	return ports.length > 0 ? ports : null;
}
