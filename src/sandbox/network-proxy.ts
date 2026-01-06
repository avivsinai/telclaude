/**
 * Network Proxy Configuration
 *
 * Provides domain allowlist configuration for sandboxed network access.
 *
 * IMPORTANT: Method (GET/POST) and port restrictions defined here are NOT enforced
 * at runtime. The @anthropic-ai/sandbox-runtime library only supports domain-based
 * filtering. These configurations are used for:
 * - Doctor diagnostics (to show intended policy)
 * - Future reference if sandbox-runtime adds method/port support
 * - Documentation of security intent
 *
 * What IS enforced:
 * - Domain allowlist (via sandbox-runtime)
 * - Private network blocking (127.x, 10.x, 192.168.x, etc.) via sandboxAskCallback
 * - Cloud metadata endpoint blocking (169.254.169.254, etc.)
 *
 * What is NOT enforced:
 * - HTTP method restrictions (GET/HEAD vs POST/PUT)
 * - Port restrictions (any port works on allowed domains)
 *
 * Design principles:
 * - Block by default, allow only specified domains
 * - Hard-block localhost, RFC1918, and cloud metadata endpoints
 * - Output filter is the primary defense for secrets
 */

import type { LookupAddress } from "node:dns";
import dns from "node:dns/promises";
import net from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { IPv4, IPv4CidrRange, IPv6, IPv6CidrRange, Validator } from "ip-num";
import type { PrivateEndpoint } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { BLOCKED_METADATA_DOMAINS, BLOCKED_PRIVATE_NETWORKS } from "./config.js";
import {
	DEFAULT_ALLOWED_DOMAINS,
	type DomainRule,
	domainMatchesPattern,
	type HttpMethod,
} from "./domains.js";

const logger = getChildLogger({ module: "network-proxy" });

// ═══════════════════════════════════════════════════════════════════════════════
// DNS Cache (prevents DNS rebinding attacks)
//
// SECURITY: DNS rebinding attacks work by returning different IP addresses
// for the same hostname on subsequent DNS queries. By caching the first
// result, we ensure the same IP is used for both security check and connection.
// ═══════════════════════════════════════════════════════════════════════════════

interface CachedDNSResult {
	addresses: string[];
	blocked: boolean;
	expireAt: number;
}

const DNS_CACHE = new Map<string, CachedDNSResult>();
const DNS_CACHE_TTL_MS = 60_000; // 60 seconds
const DNS_LOOKUP_TIMEOUT_MS = 3_000; // 3 seconds

/**
 * Perform DNS lookup with timeout.
 *
 * @param host - Hostname to resolve
 * @param timeoutMs - Timeout in milliseconds (default: 3000)
 * @returns Resolved addresses or null on timeout/error
 */
async function lookupWithTimeout(
	host: string,
	timeoutMs = DNS_LOOKUP_TIMEOUT_MS,
): Promise<LookupAddress[] | null> {
	try {
		const result = await Promise.race([
			dns.lookup(host, { all: true }),
			delay(timeoutMs).then(() => {
				throw new Error("DNS lookup timeout");
			}),
		]);
		return result as LookupAddress[];
	} catch (error) {
		if ((error as Error).message === "DNS lookup timeout") {
			logger.warn({ host, timeoutMs }, "DNS lookup timed out");
		}
		return null;
	}
}

/**
 * Cached DNS lookup to prevent DNS rebinding attacks.
 *
 * SECURITY: This function caches DNS results for 60 seconds, ensuring that:
 * 1. The same IP is used for security check and actual connection
 * 2. Attacker cannot change DNS response between check and use
 * 3. Reduced DNS query load
 *
 * @param host - Hostname to resolve
 * @returns Array of resolved IP addresses, or null on failure
 */
export async function cachedDNSLookup(host: string): Promise<string[] | null> {
	const now = Date.now();
	const cached = DNS_CACHE.get(host);

	if (cached && cached.expireAt > now) {
		return cached.addresses;
	}

	const results = await lookupWithTimeout(host);

	if (results) {
		const addresses = results.map((r) => r.address);
		DNS_CACHE.set(host, {
			addresses,
			blocked: addresses.some((addr) => isBlockedIP(addr)),
			expireAt: now + DNS_CACHE_TTL_MS,
		});
		return addresses;
	}

	// Cache negative results too (prevents repeated slow lookups)
	DNS_CACHE.set(host, {
		addresses: [],
		blocked: false,
		expireAt: now + DNS_CACHE_TTL_MS,
	});
	return null;
}

/**
 * Clear DNS cache entries.
 *
 * @param host - Specific host to clear, or undefined to clear all
 */
export function clearDNSCache(host?: string): void {
	if (host) {
		DNS_CACHE.delete(host);
	} else {
		DNS_CACHE.clear();
	}
}

/**
 * Get DNS cache statistics for diagnostics.
 */
export function getDNSCacheStats(): { size: number; ttlMs: number } {
	return {
		size: DNS_CACHE.size,
		ttlMs: DNS_CACHE_TTL_MS,
	};
}

export type { DomainRule, HttpMethod } from "./domains.js";
export { DEFAULT_ALLOWED_DOMAINS } from "./domains.js";

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

export interface NetworkProxyConfig {
	/** Unix socket path for proxy (default: ~/.telclaude/network-proxy.sock) */
	proxySocket?: string;

	/** Domain allowlist with method restrictions */
	allowedDomains: DomainRule[];

	/** Default action for unlisted domains */
	defaultAction: "block" | "prompt";

	/** Allowed ports (default: 80, 443) */
	allowedPorts: number[];
}

// ═══════════════════════════════════════════════════════════════════════════════
// Default Configuration
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Default network proxy configuration.
 * Domain list lives in sandbox/domains.ts to stay consistent with sandbox config defaults.
 */
export const DEFAULT_NETWORK_CONFIG: NetworkProxyConfig = {
	allowedDomains: DEFAULT_ALLOWED_DOMAINS,
	defaultAction: "block",
	allowedPorts: [80, 443],
};

// ═══════════════════════════════════════════════════════════════════════════════
// Domain Matching
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Check if an IP address is in a blocked network range.
 * We support the private ranges in BLOCKED_PRIVATE_NETWORKS for both IPv4 and IPv6.
 */
export function isBlockedIP(ip: string): boolean {
	// Check literal matches first
	for (const blocked of BLOCKED_PRIVATE_NETWORKS) {
		if (blocked === ip) return true;
		if (blocked === "localhost" && (ip === "127.0.0.1" || ip === "::1")) return true;
	}

	const ipType = net.isIP(ip);

	// Check IPv4 ranges (fast path)
	if (ipType === 4) {
		const ipv4Match = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
		if (!ipv4Match) return false;
		const [, a, b] = ipv4Match.map(Number);

		// 127.0.0.0/8
		if (a === 127) return true;

		// 10.0.0.0/8
		if (a === 10) return true;

		// 172.16.0.0/12
		if (a === 172 && b >= 16 && b <= 31) return true;

		// 192.168.0.0/16
		if (a === 192 && b === 168) return true;

		// 169.254.0.0/16 (link-local)
		if (a === 169 && b === 254) return true;
		return false;
	}

	// Check IPv6 private/link-local ranges declared in BLOCKED_PRIVATE_NETWORKS
	if (ipType === 6) {
		// Handle IPv4-mapped IPv6 addresses like ::ffff:192.168.1.1
		if (ip.includes(".")) {
			const maybeV4 = ip.slice(ip.lastIndexOf(":") + 1);
			if (net.isIP(maybeV4) === 4) {
				return isBlockedIP(maybeV4);
			}
		}

		const ipBig = ipv6ToBigInt(ip);
		if (ipBig !== null) {
			for (const blocked of BLOCKED_PRIVATE_NETWORKS) {
				if (blocked.includes(":") && blocked.includes("/")) {
					if (ipv6InCidr(ipBig, blocked)) return true;
				}
			}
		}
	}

	return false;
}

function ipv6ToBigInt(address: string): bigint | null {
	const lower = address.toLowerCase();
	if (lower.includes(".")) return null;

	const hasCompression = lower.includes("::");
	const [left, right] = lower.split("::");
	const leftParts = left ? left.split(":").filter(Boolean) : [];
	const rightParts = right ? right.split(":").filter(Boolean) : [];

	let parts: string[];
	if (hasCompression) {
		const missing = 8 - (leftParts.length + rightParts.length);
		if (missing < 0) return null;
		parts = [...leftParts, ...Array(missing).fill("0"), ...rightParts];
	} else {
		parts = lower.split(":");
	}

	if (parts.length !== 8) return null;

	let value = 0n;
	for (const part of parts) {
		const num = BigInt(Number.parseInt(part || "0", 16));
		if (num < 0n || num > 0xffffn) return null;
		value = (value << 16n) + num;
	}
	return value;
}

function ipv6InCidr(ipBig: bigint, cidr: string): boolean {
	const [prefix, bitsStr] = cidr.split("/");
	const bits = Number(bitsStr);
	if (!Number.isFinite(bits) || bits < 0 || bits > 128) return false;
	const prefixBig = ipv6ToBigInt(prefix);
	if (prefixBig === null) return false;
	const shift = BigInt(128 - bits);
	return ipBig >> shift === prefixBig >> shift;
}

/**
 * Check if a domain is a blocked metadata endpoint.
 */
function isBlockedMetadata(domain: string): boolean {
	const normalizedDomain = domain.toLowerCase();

	for (const blocked of BLOCKED_METADATA_DOMAINS) {
		if (blocked.includes("*")) {
			// Wildcard pattern
			const pattern = blocked.replace("*", ".*");
			if (new RegExp(`^${pattern}$`).test(normalizedDomain)) {
				return true;
			}
		} else if (normalizedDomain === blocked.toLowerCase()) {
			return true;
		}
	}

	return false;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Private Network Allowlist (for local services like Home Assistant, NAS, Plex)
//
// SECURITY: This allows controlled access to private network endpoints.
// - Only explicitly listed hosts/CIDRs are allowed
// - Port enforcement is REQUIRED (prevents service probing)
// - Metadata endpoints remain NON-OVERRIDABLE (always blocked)
// - ALL resolved IPs must match an allowlist entry (prevents bypass via dual-stack DNS)
// ═══════════════════════════════════════════════════════════════════════════════

/** Default ports allowed when no ports specified in config */
const DEFAULT_ALLOWED_PORTS = [80, 443];

/** Non-overridable blocked ranges (metadata, link-local) - cannot be allowlisted */
const NON_OVERRIDABLE_BLOCKS = [
	"169.254.0.0/16", // Link-local / APIPA
	"169.254.169.254", // AWS/GCP/Azure metadata
	"169.254.170.2", // AWS ECS metadata
	"100.100.100.200", // Alibaba Cloud metadata
	"fe80::/10", // IPv6 link-local
];

/**
 * Check if an IP is in a non-overridable blocked range (metadata, link-local).
 * These CANNOT be allowlisted under any circumstances.
 */
export function isNonOverridableBlock(ip: string): boolean {
	// Fast path: literal matches
	if (NON_OVERRIDABLE_BLOCKS.includes(ip)) return true;

	const ipType = net.isIP(ip);

	if (ipType === 4) {
		// Check IPv4 link-local (169.254.0.0/16)
		const match = ip.match(/^(\d+)\.(\d+)\./);
		if (match) {
			const [, a, b] = match.map(Number);
			if (a === 169 && b === 254) return true;
			// Alibaba Cloud metadata
			if (a === 100 && ip === "100.100.100.200") return true;
		}
	} else if (ipType === 6) {
		// Check IPv6 link-local (fe80::/10)
		const lower = ip.toLowerCase();
		if (
			lower.startsWith("fe8") ||
			lower.startsWith("fe9") ||
			lower.startsWith("fea") ||
			lower.startsWith("feb")
		) {
			return true;
		}
	}

	return false;
}

/**
 * Check if an IP is a private/RFC1918 address (but NOT non-overridable like metadata).
 * This is used to determine if we need to check the privateEndpoints allowlist.
 */
export function isPrivateIP(ip: string): boolean {
	// Non-overridable blocks are a subset of "private" - but handled separately
	if (isNonOverridableBlock(ip)) return false;

	const ipType = net.isIP(ip);

	if (ipType === 4) {
		const match = ip.match(/^(\d+)\.(\d+)\./);
		if (!match) return false;
		const [, a, b] = match.map(Number);

		// 127.0.0.0/8 (loopback)
		if (a === 127) return true;
		// 10.0.0.0/8
		if (a === 10) return true;
		// 172.16.0.0/12
		if (a === 172 && b >= 16 && b <= 31) return true;
		// 192.168.0.0/16
		if (a === 192 && b === 168) return true;
		// 100.64.0.0/10 (CGNAT / Tailscale) - RFC 6598 shared address space
		if (a === 100 && b >= 64 && b <= 127) return true;
	} else if (ipType === 6) {
		// Handle IPv4-mapped IPv6 (::ffff:192.168.1.1)
		if (ip.includes(".")) {
			const maybeV4 = ip.slice(ip.lastIndexOf(":") + 1);
			if (net.isIP(maybeV4) === 4) {
				return isPrivateIP(maybeV4);
			}
		}

		// fc00::/7 (Unique Local Addresses)
		const lower = ip.toLowerCase();
		if (lower.startsWith("fc") || lower.startsWith("fd")) return true;

		// ::1 (loopback)
		if (ip === "::1") return true;
	}

	return false;
}

/**
 * Canonicalize an IP address for comparison.
 * Handles obfuscation attempts like hex/octal notation.
 */
function canonicalizeIP(input: string): string | null {
	// Try IPv4 first
	const [isValidV4] = Validator.isValidIPv4String(input);
	if (isValidV4) {
		try {
			return IPv4.fromDecimalDottedString(input).toString();
		} catch {
			// Fall through to IPv6 check
		}
	}

	// Try IPv6
	const [isValidV6] = Validator.isValidIPv6String(input);
	if (isValidV6) {
		try {
			return IPv6.fromString(input).toString();
		} catch {
			return null;
		}
	}

	return null;
}

/**
 * Check if an IP matches a CIDR range using ip-num library.
 * Handles both IPv4 and IPv6 with proper canonicalization.
 */
function ipMatchesCidr(ip: string, cidr: string): boolean {
	try {
		// IPv4 CIDR
		if (cidr.includes(".") && cidr.includes("/")) {
			const [isValidRange] = Validator.isValidIPv4CidrRange(cidr);
			if (!isValidRange) return false;

			const range = IPv4CidrRange.fromCidr(cidr);
			const [isValidIP] = Validator.isValidIPv4String(ip);
			if (!isValidIP) return false;

			const ipAddr = IPv4.fromDecimalDottedString(ip);
			return range.contains(ipAddr);
		}

		// IPv6 CIDR
		if (cidr.includes(":") && cidr.includes("/")) {
			const [isValidRange] = Validator.isValidIPv6CidrRange(cidr);
			if (!isValidRange) return false;

			const range = IPv6CidrRange.fromCidr(cidr);
			const [isValidIP] = Validator.isValidIPv6String(ip);
			if (!isValidIP) return false;

			const ipAddr = IPv6.fromString(ip);
			return range.contains(ipAddr);
		}

		return false;
	} catch {
		return false;
	}
}

export interface PrivateEndpointMatch {
	matched: boolean;
	endpoint?: PrivateEndpoint;
	reason?: string;
}

/**
 * Find a matching private endpoint for an IP address.
 * Uses ip-num for robust CIDR matching and handles IP canonicalization.
 *
 * @param ip - The IP address to check (already resolved)
 * @param endpoints - Array of configured private endpoints
 * @returns Match result with the matched endpoint if found
 */
export function findMatchingPrivateEndpoint(
	ip: string,
	endpoints: PrivateEndpoint[],
): PrivateEndpointMatch {
	// Canonicalize input IP to prevent obfuscation bypasses
	const canonicalIP = canonicalizeIP(ip);
	if (!canonicalIP) {
		return { matched: false, reason: `Invalid IP address: ${ip}` };
	}

	for (const endpoint of endpoints) {
		// Check CIDR match
		if (endpoint.cidr) {
			if (ipMatchesCidr(canonicalIP, endpoint.cidr)) {
				return { matched: true, endpoint };
			}
			continue;
		}

		// Check host match (could be IP or hostname)
		if (endpoint.host) {
			// Direct IP comparison
			const hostCanonical = canonicalizeIP(endpoint.host);
			if (hostCanonical && hostCanonical === canonicalIP) {
				return { matched: true, endpoint };
			}
		}
	}

	return { matched: false };
}

/**
 * Check if a port is allowed by a private endpoint.
 * If no ports specified in config, defaults to 80/443.
 */
export function isPortAllowedByEndpoint(port: number, endpoint: PrivateEndpoint): boolean {
	const allowedPorts = endpoint.ports ?? DEFAULT_ALLOWED_PORTS;
	return allowedPorts.includes(port);
}

export interface PrivateNetworkCheckResult {
	allowed: boolean;
	reason?: string;
	matchedEndpoint?: PrivateEndpoint;
}

/**
 * Check if access to a private network host/port is allowed.
 *
 * SECURITY ALGORITHM (per Gemini review):
 * 1. Check for non-overridable blocks (metadata, link-local) - ALWAYS blocked
 * 2. Resolve hostname to IPs using cached DNS lookup
 * 3. Check if ANY resolved IP is in a non-overridable block - if so, BLOCK
 * 4. Check if ALL resolved IPs are in the privateEndpoints allowlist - if not, BLOCK
 * 5. Check if port is allowed by ALL matching endpoints
 *
 * @param hostname - Target hostname or IP
 * @param port - Target port (default: 443)
 * @param endpoints - Configured private endpoints from config
 */
export async function checkPrivateNetworkAccess(
	hostname: string,
	port: number,
	endpoints: PrivateEndpoint[],
): Promise<PrivateNetworkCheckResult> {
	// 1. Fast-path: Check if hostname is a blocked metadata domain
	if (isBlockedMetadata(hostname)) {
		return {
			allowed: false,
			reason: `Metadata endpoint access is forbidden: ${hostname}`,
		};
	}

	// 2. Fast-path: Check if hostname is a literal non-overridable IP
	const canonicalHostname = canonicalizeIP(hostname);
	if (canonicalHostname && isNonOverridableBlock(canonicalHostname)) {
		return {
			allowed: false,
			reason: `Non-overridable blocked IP: ${hostname}`,
		};
	}

	// 3. Resolve hostname to IPs using cached DNS lookup (prevents rebinding)
	let targetIPs: string[];
	if (canonicalHostname) {
		// It's already a valid IP - use directly
		targetIPs = [canonicalHostname];
	} else {
		// It's a hostname - resolve via cached DNS
		const resolved = await cachedDNSLookup(hostname);
		if (!resolved || resolved.length === 0) {
			return {
				allowed: false,
				reason: `Failed to resolve hostname: ${hostname}`,
			};
		}
		targetIPs = resolved;
	}

	// 4. Check EACH resolved IP
	const matchedEndpoints: PrivateEndpoint[] = [];

	for (const ip of targetIPs) {
		const canonicalIP = canonicalizeIP(ip);
		if (!canonicalIP) {
			return {
				allowed: false,
				reason: `Invalid resolved IP: ${ip}`,
			};
		}

		// 4a. Non-overridable block check (after resolution)
		if (isNonOverridableBlock(canonicalIP)) {
			return {
				allowed: false,
				reason: `Resolved to non-overridable blocked IP: ${ip}`,
			};
		}

		// 4b. Check if IP is private - if so, must be in allowlist
		if (isPrivateIP(canonicalIP)) {
			const match = findMatchingPrivateEndpoint(canonicalIP, endpoints);
			if (!match.matched) {
				return {
					allowed: false,
					reason: `Private IP ${ip} is not in the allowlist`,
				};
			}
			if (match.endpoint) {
				matchedEndpoints.push(match.endpoint);
			}
		}
		// If it's a public IP, it's handled by the regular domain allowlist
	}

	// 5. Port enforcement - check ALL matched endpoints
	if (matchedEndpoints.length > 0) {
		for (const endpoint of matchedEndpoints) {
			if (!isPortAllowedByEndpoint(port, endpoint)) {
				const allowedPorts = endpoint.ports ?? DEFAULT_ALLOWED_PORTS;
				return {
					allowed: false,
					reason: `Port ${port} is not allowed for ${endpoint.label || "endpoint"} (allowed: ${allowedPorts.join(", ")})`,
				};
			}
		}
	}

	// All checks passed
	return {
		allowed: true,
		matchedEndpoint: matchedEndpoints[0],
	};
}

/**
 * Check if a host should be blocked due to resolving to a private/metadata IP.
 *
 * SECURITY: Uses cached DNS lookup to prevent DNS rebinding attacks.
 * The cache ensures the same IP is used for security check and actual connection.
 *
 * @param host - Hostname or IP address to check
 * @returns true if the host resolves to a blocked IP, false otherwise
 */
export async function isBlockedHost(host: string): Promise<boolean> {
	// Fast path for literal IPs and localhost
	if (isBlockedIP(host)) return true;

	// Use cached DNS lookup (prevents rebinding attacks)
	const addresses = await cachedDNSLookup(host);
	return addresses?.some((addr) => isBlockedIP(addr)) ?? false;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Request Validation
// ═══════════════════════════════════════════════════════════════════════════════

export interface NetworkRequestCheck {
	allowed: boolean;
	reason?: string;
	matchedRule?: DomainRule;
}

/**
 * Check if a network request should be allowed.
 *
 * @param domain - Target domain (e.g., "api.github.com")
 * @param method - HTTP method (e.g., "GET", "POST")
 * @param port - Target port (default: 443)
 * @param config - Network proxy configuration
 */
export function checkNetworkRequest(
	domain: string,
	method: HttpMethod,
	port = 443,
	config: NetworkProxyConfig = DEFAULT_NETWORK_CONFIG,
): NetworkRequestCheck {
	// 1. Check for blocked metadata endpoints
	if (isBlockedMetadata(domain)) {
		logger.warn({ domain, method }, "blocked cloud metadata endpoint");
		return {
			allowed: false,
			reason: `Cloud metadata endpoint blocked: ${domain}`,
		};
	}

	// 2. Check for blocked private networks (IP check)
	if (isBlockedIP(domain)) {
		logger.warn({ domain, method }, "blocked private network access");
		return {
			allowed: false,
			reason: `Private network access blocked: ${domain}`,
		};
	}

	// 3. Check port
	if (!config.allowedPorts.includes(port)) {
		logger.warn({ domain, method, port }, "blocked non-standard port");
		return {
			allowed: false,
			reason: `Port ${port} not allowed (only ${config.allowedPorts.join(", ")})`,
		};
	}

	// 4. Find matching domain rule
	const matchedRule = config.allowedDomains.find((rule) =>
		domainMatchesPattern(domain, rule.domain),
	);

	if (!matchedRule) {
		logger.info({ domain, method }, "domain not in allowlist");
		return {
			allowed: false,
			reason: `Domain not in allowlist: ${domain}`,
		};
	}

	// 5. Check method restriction
	if (!matchedRule.methods.includes(method)) {
		logger.warn({ domain, method, allowedMethods: matchedRule.methods }, "method not allowed");
		return {
			allowed: false,
			reason: `Method ${method} not allowed for ${domain} (only ${matchedRule.methods.join(", ")})`,
		};
	}

	return {
		allowed: true,
		matchedRule,
	};
}

// ═══════════════════════════════════════════════════════════════════════════════
// Configuration Helpers
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Add POST permission for a domain.
 * Use sparingly - POST can exfiltrate secrets to allowed domains.
 */
export function allowPost(config: NetworkProxyConfig, domain: string): NetworkProxyConfig {
	const updatedDomains = config.allowedDomains.map((rule) => {
		if (domainMatchesPattern(domain, rule.domain)) {
			return {
				...rule,
				methods: [...new Set([...rule.methods, "POST" as const])],
			};
		}
		return rule;
	});

	// If domain wasn't in list, add it
	if (!updatedDomains.some((rule) => domainMatchesPattern(domain, rule.domain))) {
		updatedDomains.push({ domain, methods: ["GET", "HEAD", "POST"] });
	}

	return { ...config, allowedDomains: updatedDomains };
}

/**
 * Add a new domain to the allowlist.
 */
export function addAllowedDomain(
	config: NetworkProxyConfig,
	domain: string,
	methods: HttpMethod[] = ["GET", "HEAD"],
): NetworkProxyConfig {
	// Check if domain already exists
	if (config.allowedDomains.some((rule) => rule.domain === domain)) {
		return config;
	}

	return {
		...config,
		allowedDomains: [...config.allowedDomains, { domain, methods }],
	};
}

// ═══════════════════════════════════════════════════════════════════════════════
// Summary for Doctor
// ═══════════════════════════════════════════════════════════════════════════════

export interface NetworkIsolationSummary {
	allowedDomains: number;
	/**
	 * Domains configured for POST access.
	 * NOTE: Method restrictions are NOT enforced at runtime by sandbox-runtime.
	 * This is informational only (shows intended policy).
	 */
	domainsWithPost: string[];
	blockedMetadataEndpoints: number;
	blockedPrivateNetworks: number;
	/** True if network uses "*" wildcard (unrestricted egress) */
	isPermissive: boolean;
	/**
	 * Port restrictions configured in policy.
	 * NOTE: Port restrictions are NOT enforced at runtime by sandbox-runtime.
	 * This is informational only (shows intended policy).
	 */
	allowedPorts?: number[];
}

/**
 * Get network isolation summary for doctor output.
 *
 * @param config - Network proxy config (optional)
 * @param sandboxAllowedDomains - The actual domains allowed by the sandbox (e.g., ["*"] for permissive)
 */
export function getNetworkIsolationSummary(
	config: NetworkProxyConfig = DEFAULT_NETWORK_CONFIG,
	sandboxAllowedDomains?: string[],
): NetworkIsolationSummary {
	const domainsWithPost = config.allowedDomains
		.filter((rule) => rule.methods.includes("POST"))
		.map((rule) => rule.domain);

	// Check if sandbox is permissive.
	// Note: telclaude treats TELCLAUDE_NETWORK_MODE=open|permissive as "allow all non-private egress"
	// via the sandboxAskCallback layer (so private networks are still blocked, including DNS rebinding).
	const sandboxDomainPatterns =
		sandboxAllowedDomains ?? config.allowedDomains.map((rule) => rule.domain);
	const envMode = process.env.TELCLAUDE_NETWORK_MODE?.toLowerCase();
	const isPermissive =
		envMode === "open" || envMode === "permissive" || sandboxDomainPatterns.includes("*");

	return {
		allowedDomains: config.allowedDomains.length,
		domainsWithPost,
		blockedMetadataEndpoints: BLOCKED_METADATA_DOMAINS.length,
		blockedPrivateNetworks: BLOCKED_PRIVATE_NETWORKS.length,
		isPermissive,
		allowedPorts: config.allowedPorts,
	};
}

// ═══════════════════════════════════════════════════════════════════════════════
// Self-Test for Doctor
// ═══════════════════════════════════════════════════════════════════════════════

export interface NetworkSelfTestResult {
	passed: boolean;
	tests: Array<{
		name: string;
		passed: boolean;
		details?: string;
	}>;
}

/**
 * Run network isolation self-tests.
 *
 * IMPORTANT: These are POLICY checks only - they test the checkNetworkRequest() logic,
 * not actual runtime enforcement. The sandbox-runtime only enforces:
 * - Domain allowlist (via sandboxAskCallback for private networks)
 * - Cloud metadata blocking
 *
 * Tests for method/port restrictions pass the policy check but are NOT enforced
 * at runtime by sandbox-runtime.
 */
export function runNetworkSelfTest(
	config: NetworkProxyConfig = DEFAULT_NETWORK_CONFIG,
): NetworkSelfTestResult {
	const tests: NetworkSelfTestResult["tests"] = [];

	// Test 1: Allowed domain with GET should pass (ENFORCED by sandbox-runtime)
	{
		const result = checkNetworkRequest("registry.npmjs.org", "GET", 443, config);
		tests.push({
			name: "Allowed domain (GET)",
			passed: result.allowed,
			details: result.allowed ? "registry.npmjs.org allowed" : result.reason,
		});
	}

	// Test 2: Metadata endpoint should be blocked (ENFORCED via isBlockedIP)
	{
		const result = checkNetworkRequest("169.254.169.254", "GET", 80, config);
		tests.push({
			name: "Cloud metadata blocked",
			passed: !result.allowed,
			details: !result.allowed ? "169.254.169.254 blocked" : "FAIL: metadata not blocked",
		});
	}

	// Test 3: Localhost should be blocked (ENFORCED via isBlockedIP)
	{
		const result = checkNetworkRequest("127.0.0.1", "GET", 8080, config);
		tests.push({
			name: "Localhost blocked",
			passed: !result.allowed,
			details: !result.allowed ? "127.0.0.1 blocked" : "FAIL: localhost not blocked",
		});
	}

	// Test 4: Private network should be blocked (ENFORCED via isBlockedIP)
	{
		const result = checkNetworkRequest("192.168.1.1", "GET", 80, config);
		tests.push({
			name: "Private network blocked",
			passed: !result.allowed,
			details: !result.allowed ? "192.168.1.1 blocked" : "FAIL: RFC1918 not blocked",
		});
	}

	// Test 5: Unknown domain should be blocked (ENFORCED by sandbox-runtime)
	{
		const result = checkNetworkRequest("evil.com", "GET", 443, config);
		tests.push({
			name: "Unknown domain blocked",
			passed: !result.allowed,
			details: !result.allowed ? "evil.com blocked" : "FAIL: unknown domain allowed",
		});
	}

	// Test 6: POST to github.com - POLICY CHECK ONLY, NOT ENFORCED AT RUNTIME
	// sandbox-runtime does not support method restrictions
	{
		const result = checkNetworkRequest("github.com", "POST", 443, config);
		const shouldBlock = !config.allowedDomains.some(
			(r) => domainMatchesPattern("github.com", r.domain) && r.methods.includes("POST"),
		);
		tests.push({
			name: "POST to github.com (policy: blocked, NOT enforced)",
			passed: shouldBlock ? !result.allowed : result.allowed,
			details: result.allowed
				? "POST allowed (explicit config)"
				: "POST blocked in policy (not runtime-enforced)",
		});
	}

	return {
		passed: tests.every((t) => t.passed),
		tests,
	};
}
