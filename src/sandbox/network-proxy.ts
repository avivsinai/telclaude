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

import { getChildLogger } from "../logging.js";
import { BLOCKED_METADATA_DOMAINS, BLOCKED_PRIVATE_NETWORKS } from "./config.js";
import {
	DEFAULT_ALLOWED_DOMAINS,
	type DomainRule,
	type HttpMethod,
	domainMatchesPattern,
} from "./domains.js";

const logger = getChildLogger({ module: "network-proxy" });

export { DEFAULT_ALLOWED_DOMAINS } from "./domains.js";
export type { DomainRule, HttpMethod } from "./domains.js";

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
 * Simplified implementation - for full CIDR support, use a library.
 */
export function isBlockedIP(ip: string): boolean {
	// Check literal matches first
	for (const blocked of BLOCKED_PRIVATE_NETWORKS) {
		if (blocked === ip) return true;
		if (blocked === "localhost" && (ip === "127.0.0.1" || ip === "::1")) return true;
	}

	// Check IPv4 ranges (simplified)
	const ipv4Match = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
	if (ipv4Match) {
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
	}

	return false;
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

	// Check if sandbox is permissive (uses "*" wildcard)
	const sandboxDomainPatterns =
		sandboxAllowedDomains ?? config.allowedDomains.map((rule) => rule.domain);
	const isPermissive = sandboxDomainPatterns.includes("*");

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
