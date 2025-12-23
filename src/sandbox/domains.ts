/**
 * Network domain allowlist for sandboxed network access.
 *
 * Simplified: Single allowlist with all developer-friendly domains.
 * OpenAI is always included (harmless without key exposure via env var).
 */

export type HttpMethod = "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";

export interface DomainRule {
	domain: string;
	methods: HttpMethod[];
}

/**
 * Common package registry domains (read-only).
 */
export const PACKAGE_MANAGER_DOMAINS: DomainRule[] = [
	{ domain: "registry.npmjs.org", methods: ["GET", "HEAD"] },
	{ domain: "registry.yarnpkg.com", methods: ["GET", "HEAD"] },
	{ domain: "pypi.org", methods: ["GET", "HEAD"] },
	{ domain: "files.pythonhosted.org", methods: ["GET", "HEAD"] },
	{ domain: "crates.io", methods: ["GET", "HEAD"] },
	{ domain: "static.crates.io", methods: ["GET", "HEAD"] },
	{ domain: "index.crates.io", methods: ["GET", "HEAD"] },
	{ domain: "rubygems.org", methods: ["GET", "HEAD"] },
	{ domain: "repo.maven.apache.org", methods: ["GET", "HEAD"] },
	{ domain: "repo1.maven.org", methods: ["GET", "HEAD"] },
	{ domain: "api.nuget.org", methods: ["GET", "HEAD"] },
	{ domain: "proxy.golang.org", methods: ["GET", "HEAD"] },
	{ domain: "sum.golang.org", methods: ["GET", "HEAD"] },
	{ domain: "repo.packagist.org", methods: ["GET", "HEAD"] },
];

/**
 * Documentation domains (read-only).
 */
export const DOC_DOMAINS: DomainRule[] = [
	{ domain: "docs.python.org", methods: ["GET", "HEAD"] },
	{ domain: "docs.rs", methods: ["GET", "HEAD"] },
	{ domain: "developer.mozilla.org", methods: ["GET", "HEAD"] },
	{ domain: "stackoverflow.com", methods: ["GET", "HEAD"] },
	{ domain: "*.stackexchange.com", methods: ["GET", "HEAD"] },
];

/**
 * Code hosting domains (read-only by default).
 * POST requires explicit config - prevents pushing secrets to repos.
 */
export const CODE_HOST_DOMAINS: DomainRule[] = [
	{ domain: "github.com", methods: ["GET", "HEAD"] },
	{ domain: "api.github.com", methods: ["GET", "HEAD"] },
	{ domain: "codeload.github.com", methods: ["GET", "HEAD"] },
	{ domain: "objects.githubusercontent.com", methods: ["GET", "HEAD"] },
	{ domain: "gitlab.com", methods: ["GET", "HEAD"] },
	{ domain: "bitbucket.org", methods: ["GET", "HEAD"] },
	{ domain: "raw.githubusercontent.com", methods: ["GET", "HEAD"] },
	{ domain: "gist.githubusercontent.com", methods: ["GET", "HEAD"] },
];

/**
 * CDN domains used by package ecosystems (read-only).
 */
export const CDN_DOMAINS: DomainRule[] = [
	{ domain: "unpkg.com", methods: ["GET", "HEAD"] },
	{ domain: "cdn.jsdelivr.net", methods: ["GET", "HEAD"] },
];

/**
 * Anthropic API + Claude Code endpoints.
 */
export const ANTHROPIC_DOMAINS: DomainRule[] = [
	{ domain: "api.anthropic.com", methods: ["GET", "HEAD", "POST"] },
	{ domain: "claude.ai", methods: ["GET", "HEAD", "POST"] },
	{ domain: "*.claude.ai", methods: ["GET", "HEAD", "POST"] },
	{ domain: "code.anthropic.com", methods: ["GET", "HEAD", "POST"] },
	{ domain: "*.code.anthropic.com", methods: ["GET", "HEAD", "POST"] },
];

/**
 * OpenAI API domains.
 * Always included in allowlist. Keys are exposed for WRITE_LOCAL and FULL_ACCESS tiers.
 */
export const OPENAI_DOMAINS: DomainRule[] = [
	{ domain: "api.openai.com", methods: ["GET", "HEAD", "POST"] },
];

/**
 * Default domain allowlist with all developer-friendly domains.
 */
export const DEFAULT_ALLOWED_DOMAINS: DomainRule[] = [
	...PACKAGE_MANAGER_DOMAINS,
	...DOC_DOMAINS,
	...CODE_HOST_DOMAINS,
	...CDN_DOMAINS,
	...ANTHROPIC_DOMAINS,
	...OPENAI_DOMAINS,
];

/**
 * Build the allowed domains list with optional additional domains.
 *
 * @param additionalDomains - Extra domains to allow (GET/HEAD only)
 */
export function buildAllowedDomains(additionalDomains: string[] = []): DomainRule[] {
	const extraRules = additionalDomains.map((domain) => ({
		domain,
		methods: ["GET", "HEAD"] as HttpMethod[],
	}));

	const combined = [...DEFAULT_ALLOWED_DOMAINS, ...extraRules];

	// Merge duplicate domains
	const merged = new Map<string, Set<HttpMethod>>();
	for (const rule of combined) {
		const key = rule.domain.toLowerCase();
		const set = merged.get(key) ?? new Set<HttpMethod>();
		for (const method of rule.methods) {
			set.add(method);
		}
		merged.set(key, set);
	}

	return Array.from(merged.entries()).map(([domain, methods]) => ({
		domain,
		methods: Array.from(methods),
	}));
}

/**
 * Build the allowed domain names (strings only).
 */
export function buildAllowedDomainNames(additionalDomains: string[] = []): string[] {
	return buildAllowedDomains(additionalDomains).map((rule) => rule.domain);
}

/**
 * Default domain patterns for sandbox-runtime config.
 */
export const DEFAULT_ALLOWED_DOMAIN_NAMES = DEFAULT_ALLOWED_DOMAINS.map((rule) => rule.domain);

/**
 * Check if a domain matches a pattern.
 * Supports:
 * - Exact matches: "example.com"
 * - Wildcard subdomain prefixes: "*.example.com"
 */
export function domainMatchesPattern(domain: string, pattern: string): boolean {
	const normalizedDomain = domain.toLowerCase();
	const normalizedPattern = pattern.toLowerCase();

	if (normalizedPattern.startsWith("*.")) {
		// Match subdomains only (align with @anthropic-ai/sandbox-runtime behavior)
		const baseDomain = normalizedPattern.slice(2); // "example.com"
		return normalizedDomain.endsWith(`.${baseDomain}`);
	}

	return normalizedDomain === normalizedPattern;
}
