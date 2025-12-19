/**
 * Shared domain allowlist defaults for sandboxed network access.
 *
 * Kept in a dedicated module so both the sandbox runtime config and
 * the network policy helper can reference the same source of truth.
 */

export type HttpMethod = "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";

export interface DomainRule {
	domain: string;
	methods: HttpMethod[];
}

/**
 * Default domain allowlist with method intentions.
 * Runtime enforcement is domain-based; methods are informational.
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
	{ domain: "codeload.github.com", methods: ["GET", "HEAD"] },
	{ domain: "objects.githubusercontent.com", methods: ["GET", "HEAD"] },
	{ domain: "gitlab.com", methods: ["GET", "HEAD"] },
	{ domain: "bitbucket.org", methods: ["GET", "HEAD"] },
	{ domain: "raw.githubusercontent.com", methods: ["GET", "HEAD"] },
	{ domain: "gist.githubusercontent.com", methods: ["GET", "HEAD"] },

	// npm/yarn CDNs
	{ domain: "unpkg.com", methods: ["GET", "HEAD"] },
	{ domain: "cdn.jsdelivr.net", methods: ["GET", "HEAD"] },

	// Anthropic API + Claude Code endpoints
	{ domain: "api.anthropic.com", methods: ["GET", "HEAD", "POST"] },
	{ domain: "claude.ai", methods: ["GET", "HEAD", "POST"] },
	{ domain: "*.claude.ai", methods: ["GET", "HEAD", "POST"] },
	{ domain: "code.anthropic.com", methods: ["GET", "HEAD", "POST"] },
	{ domain: "*.code.anthropic.com", methods: ["GET", "HEAD", "POST"] },

	// OpenAI API (for image generation, TTS, transcription via telclaude CLI)
	{ domain: "api.openai.com", methods: ["GET", "HEAD", "POST"] },
];

/**
 * Default domain patterns (without method metadata) for sandbox-runtime config.
 */
export const DEFAULT_ALLOWED_DOMAIN_NAMES = DEFAULT_ALLOWED_DOMAINS.map((rule) => rule.domain);

/**
 * Check if a domain matches a pattern.
 * Supports wildcard prefixes like "*.example.com".
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
