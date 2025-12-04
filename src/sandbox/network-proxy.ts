/**
 * Network Proxy Configuration - V2 Security
 *
 * Provides domain allowlist with method restrictions for sandboxed network access.
 *
 * Design principles:
 * - Proxy all traffic through controlled interface
 * - Block by default, allow only specified domains
 * - Restrict methods (GET/HEAD default, POST requires explicit config)
 * - Hard-block localhost, RFC1918, and cloud metadata endpoints
 *
 * HTTP exfiltration stance:
 * - Simple profile: Accept limited GET-based exfil (secrets can be in query params)
 * - Strict profile: Optional filtering of high-entropy query params
 * - Output filter is the primary defense for secrets
 */

import { getChildLogger } from "../logging.js";
import { BLOCKED_METADATA_DOMAINS, BLOCKED_PRIVATE_NETWORKS } from "./config.js";

const logger = getChildLogger({ module: "network-proxy" });

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

export type HttpMethod = "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";

export interface DomainRule {
	/** Domain pattern (e.g., "registry.npmjs.org", "*.pypi.org") */
	domain: string;
	/** Allowed HTTP methods (default: GET, HEAD) */
	methods: HttpMethod[];
}

export interface NetworkProxyConfig {
	/** Unix socket path for proxy (default: ~/.telclaude/network-proxy.sock) */
	proxySocket?: string;

	/** Domain allowlist with method restrictions */
	allowedDomains: DomainRule[];

	/** Default action for unlisted domains */
	defaultAction: "block" | "prompt";

	/** Allowed ports (default: 80, 443) */
	allowedPorts: number[];

	/** Enable feature (behind feature flag for safe rollout) */
	enabled: boolean;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Default Configuration
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Default domain allowlist with method restrictions.
 * GET/HEAD only by default - POST requires explicit config.
 */
export const DEFAULT_ALLOWED_DOMAINS: DomainRule[] = [
	// Package registries (read-only)
	{ domain: "registry.npmjs.org", methods: ["GET", "HEAD"] },
	{ domain: "pypi.org", methods: ["GET", "HEAD"] },
	{ domain: "files.pythonhosted.org", methods: ["GET", "HEAD"] },
	{ domain: "crates.io", methods: ["GET", "HEAD"] },
	{ domain: "static.crates.io", methods: ["GET", "HEAD"] },
	{ domain: "rubygems.org", methods: ["GET", "HEAD"] },

	// Documentation sites
	{ domain: "docs.python.org", methods: ["GET", "HEAD"] },
	{ domain: "docs.rs", methods: ["GET", "HEAD"] },
	{ domain: "developer.mozilla.org", methods: ["GET", "HEAD"] },
	{ domain: "stackoverflow.com", methods: ["GET", "HEAD"] },
	{ domain: "*.stackexchange.com", methods: ["GET", "HEAD"] },

	// Code hosting (READ ONLY by default)
	// POST requires explicit config - prevents pushing secrets to repos
	{ domain: "github.com", methods: ["GET", "HEAD"] },
	{ domain: "api.github.com", methods: ["GET", "HEAD"] },
	{ domain: "gitlab.com", methods: ["GET", "HEAD"] },
	{ domain: "bitbucket.org", methods: ["GET", "HEAD"] },
	{ domain: "raw.githubusercontent.com", methods: ["GET", "HEAD"] },
	{ domain: "gist.githubusercontent.com", methods: ["GET", "HEAD"] },

	// npm/yarn CDNs
	{ domain: "unpkg.com", methods: ["GET", "HEAD"] },
	{ domain: "cdn.jsdelivr.net", methods: ["GET", "HEAD"] },

	// Anthropic API (for SDK)
	{ domain: "api.anthropic.com", methods: ["GET", "HEAD", "POST"] },
];

/**
 * Default network proxy configuration.
 */
export const DEFAULT_NETWORK_CONFIG: NetworkProxyConfig = {
	allowedDomains: DEFAULT_ALLOWED_DOMAINS,
	defaultAction: "block",
	allowedPorts: [80, 443],
	enabled: false, // Behind feature flag
};

// ═══════════════════════════════════════════════════════════════════════════════
// Domain Matching
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Check if a domain matches a pattern.
 * Supports wildcard prefixes like "*.example.com".
 */
function domainMatches(domain: string, pattern: string): boolean {
	const normalizedDomain = domain.toLowerCase();
	const normalizedPattern = pattern.toLowerCase();

	if (normalizedPattern.startsWith("*.")) {
		// Wildcard pattern: *.example.com matches sub.example.com
		const suffix = normalizedPattern.slice(1); // .example.com
		return normalizedDomain.endsWith(suffix) || normalizedDomain === normalizedPattern.slice(2);
	}

	return normalizedDomain === normalizedPattern;
}

/**
 * Check if an IP address is in a blocked network range.
 * Simplified implementation - for full CIDR support, use a library.
 */
function isBlockedIP(ip: string): boolean {
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
	const matchedRule = config.allowedDomains.find((rule) => domainMatches(domain, rule.domain));

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
		if (domainMatches(domain, rule.domain)) {
			return {
				...rule,
				methods: [...new Set([...rule.methods, "POST" as const])],
			};
		}
		return rule;
	});

	// If domain wasn't in list, add it
	if (!updatedDomains.some((rule) => domainMatches(domain, rule.domain))) {
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
	enabled: boolean;
	allowedDomains: number;
	domainsWithPost: string[];
	blockedMetadataEndpoints: number;
	blockedPrivateNetworks: number;
}

/**
 * Get network isolation summary for doctor output.
 */
export function getNetworkIsolationSummary(
	config: NetworkProxyConfig = DEFAULT_NETWORK_CONFIG,
): NetworkIsolationSummary {
	const domainsWithPost = config.allowedDomains
		.filter((rule) => rule.methods.includes("POST"))
		.map((rule) => rule.domain);

	return {
		enabled: config.enabled,
		allowedDomains: config.allowedDomains.length,
		domainsWithPost,
		blockedMetadataEndpoints: BLOCKED_METADATA_DOMAINS.length,
		blockedPrivateNetworks: BLOCKED_PRIVATE_NETWORKS.length,
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
 * These are logic tests only - no actual network requests are made.
 */
export function runNetworkSelfTest(
	config: NetworkProxyConfig = DEFAULT_NETWORK_CONFIG,
): NetworkSelfTestResult {
	const tests: NetworkSelfTestResult["tests"] = [];

	// Test 1: Allowed domain with GET should pass
	{
		const result = checkNetworkRequest("registry.npmjs.org", "GET", 443, config);
		tests.push({
			name: "Allowed domain (GET)",
			passed: result.allowed,
			details: result.allowed ? "registry.npmjs.org allowed" : result.reason,
		});
	}

	// Test 2: Metadata endpoint should be blocked
	{
		const result = checkNetworkRequest("169.254.169.254", "GET", 80, config);
		tests.push({
			name: "Cloud metadata blocked",
			passed: !result.allowed,
			details: !result.allowed ? "169.254.169.254 blocked" : "FAIL: metadata not blocked",
		});
	}

	// Test 3: Localhost should be blocked
	{
		const result = checkNetworkRequest("127.0.0.1", "GET", 8080, config);
		tests.push({
			name: "Localhost blocked",
			passed: !result.allowed,
			details: !result.allowed ? "127.0.0.1 blocked" : "FAIL: localhost not blocked",
		});
	}

	// Test 4: Private network should be blocked
	{
		const result = checkNetworkRequest("192.168.1.1", "GET", 80, config);
		tests.push({
			name: "Private network blocked",
			passed: !result.allowed,
			details: !result.allowed ? "192.168.1.1 blocked" : "FAIL: RFC1918 not blocked",
		});
	}

	// Test 5: Unknown domain should be blocked
	{
		const result = checkNetworkRequest("evil.com", "GET", 443, config);
		tests.push({
			name: "Unknown domain blocked",
			passed: !result.allowed,
			details: !result.allowed ? "evil.com blocked" : "FAIL: unknown domain allowed",
		});
	}

	// Test 6: POST to github.com should be blocked (default config)
	{
		const result = checkNetworkRequest("github.com", "POST", 443, config);
		const shouldBlock = !config.allowedDomains.some(
			(r) => domainMatches("github.com", r.domain) && r.methods.includes("POST"),
		);
		tests.push({
			name: "POST to github.com (default: blocked)",
			passed: shouldBlock ? !result.allowed : result.allowed,
			details: result.allowed
				? "POST allowed (explicit config)"
				: "POST blocked (method restriction)",
		});
	}

	return {
		passed: tests.every((t) => t.passed),
		tests,
	};
}
