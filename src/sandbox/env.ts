/**
 * Environment Isolation - V2 Security
 *
 * Principle: Construct a fresh env from allowlist. Never pass through secrets.
 *
 * - Allowlist-only model: Only vars in ENV_ALLOWLIST pass through
 * - Deny prefixes: Secondary belt catching credential patterns
 * - HOME alignment: HOME=/home/sandbox (synthetic, not real ~)
 */

import { getChildLogger } from "../logging.js";

const logger = getChildLogger({ module: "env-isolation" });

// ═══════════════════════════════════════════════════════════════════════════════
// Environment Allowlist
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Only these env vars pass through to sandbox.
 * Everything else is implicitly denied.
 */
export const ENV_ALLOWLIST = [
	// System
	"PATH",
	"LANG",
	"LC_ALL",
	"LC_CTYPE",
	"TZ",
	"TERM",
	"COLORTERM",

	// User info (HOME overridden to synthetic path)
	"HOME",
	"USER",
	"SHELL",

	// Editor preferences
	"EDITOR",
	"VISUAL",

	// XDG directories
	"XDG_RUNTIME_DIR",
	"XDG_CONFIG_HOME",
	"XDG_DATA_HOME",
	"XDG_CACHE_HOME",

	// Node.js
	"NODE_ENV",
	"NODE_OPTIONS",

	// Debugging (safe)
	"DEBUG",
	"FORCE_COLOR",
	"NO_COLOR",
];

// ═══════════════════════════════════════════════════════════════════════════════
// Deny Prefixes (Secondary Belt)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * These prefixes are NEVER passed through, even if somehow in allowlist.
 * Defense in depth against credential leakage.
 */
export const ENV_DENY_PREFIXES = [
	// Cloud providers
	"AWS_",
	"GCP_",
	"AZURE_",
	"GOOGLE_",
	"ALIBABA_",
	"DO_", // DigitalOcean

	// AI providers
	"ANTHROPIC_",
	"OPENAI_",
	"COHERE_",
	"HUGGINGFACE_",

	// Messaging
	"TELEGRAM_",
	"SLACK_",
	"DISCORD_",
	"TWILIO_",

	// Source control
	"GH_",
	"GITHUB_",
	"GITLAB_",
	"BITBUCKET_",

	// Package managers
	"NPM_",
	"YARN_",
	"PNPM_",
	"PIP_",
	"PYPI_",
	"CARGO_",
	"GEM_",

	// Container/orchestration
	"DOCKER_",
	"KUBERNETES_",
	"K8S_",
	"HELM_",

	// Databases
	"DATABASE_",
	"DB_",
	"REDIS_",
	"MONGO_",
	"POSTGRES_",
	"MYSQL_",

	// Generic secrets
	"SECRET_",
	"PASSWORD_",
	"TOKEN_",
	"KEY_",
	"CREDENTIAL_",
	"AUTH_",
	"API_KEY",
	"PRIVATE_",

	// Payment
	"STRIPE_",
	"PAYPAL_",
	"SQUARE_",

	// Analytics/monitoring
	"SENTRY_",
	"DATADOG_",
	"NEW_RELIC_",
	"SEGMENT_",

	// CI/CD
	"CI_",
	"JENKINS_",
	"TRAVIS_",
	"CIRCLE_",
	"BUILDKITE_",
];

// ═══════════════════════════════════════════════════════════════════════════════
// Environment Builder
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Check if a key matches any deny prefix.
 */
function matchesDenyPrefix(key: string): boolean {
	const upperKey = key.toUpperCase();
	return ENV_DENY_PREFIXES.some((prefix) => upperKey.startsWith(prefix));
}

/**
 * Build a sanitized environment for the sandbox.
 *
 * @param processEnv - The current process environment
 * @returns Sanitized environment with only safe variables
 */
export function buildSandboxEnv(processEnv: NodeJS.ProcessEnv): Record<string, string> {
	const sandboxEnv: Record<string, string> = {};
	let blockedCount = 0;
	let allowedCount = 0;

	for (const key of ENV_ALLOWLIST) {
		const value = processEnv[key];
		if (value !== undefined) {
			// Double-check against deny prefixes (defense in depth)
			if (matchesDenyPrefix(key)) {
				logger.warn({ key }, "env var in allowlist but matches deny prefix - blocked");
				blockedCount++;
				continue;
			}
			sandboxEnv[key] = value;
			allowedCount++;
		}
	}

	// Override HOME to synthetic path
	sandboxEnv.HOME = "/home/sandbox";

	// Count blocked vars for metrics
	for (const key of Object.keys(processEnv)) {
		if (!ENV_ALLOWLIST.includes(key)) {
			blockedCount++;
		}
	}

	logger.debug({ allowed: allowedCount, blocked: blockedCount }, "sandbox env built");

	return sandboxEnv;
}

/**
 * Get a summary of environment isolation for doctor output.
 */
export function getEnvIsolationSummary(processEnv: NodeJS.ProcessEnv): {
	allowed: number;
	blocked: number;
	deniedPrefixes: string[];
} {
	let allowed = 0;
	let blocked = 0;
	const deniedPrefixes: string[] = [];

	for (const key of Object.keys(processEnv)) {
		if (ENV_ALLOWLIST.includes(key) && !matchesDenyPrefix(key)) {
			allowed++;
		} else {
			blocked++;
			// Track which prefixes matched
			for (const prefix of ENV_DENY_PREFIXES) {
				if (key.toUpperCase().startsWith(prefix) && !deniedPrefixes.includes(prefix)) {
					deniedPrefixes.push(prefix);
				}
			}
		}
	}

	return { allowed, blocked, deniedPrefixes };
}

/**
 * Check if a specific environment variable is safe.
 */
export function isEnvVarSafe(key: string): boolean {
	return ENV_ALLOWLIST.includes(key) && !matchesDenyPrefix(key);
}

/**
 * Get list of blocked env vars (for debugging).
 */
export function getBlockedEnvVars(processEnv: NodeJS.ProcessEnv): string[] {
	return Object.keys(processEnv).filter((key) => !isEnvVarSafe(key));
}
