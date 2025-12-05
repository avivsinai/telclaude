/**
 * Environment Isolation
 *
 * Principle: Construct a fresh env from allowlist. Never pass through secrets.
 *
 * - Allowlist-only model: Only vars in ENV_ALLOWLIST pass through
 * - Deny prefixes: Secondary belt catching credential patterns
 * - HOME alignment: HOME points to private temp dir (writable, isolated from real ~)
 * - TMPDIR: Points to private temp dir (host /tmp is blocked)
 */

import os from "node:os";
import path from "node:path";
import { getChildLogger } from "../logging.js";
import { PRIVATE_TMP_PATH } from "./config.js";

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

	// User info (HOME overridden to private temp - writable and isolated)
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
	// SECURITY: NODE_OPTIONS removed - allows --require injection to preload arbitrary code

	// Debugging (safe)
	"FORCE_COLOR",
	"NO_COLOR",

	// Temp directories (we override TMPDIR to private temp)
	"TMPDIR",
	"TMP",
	"TEMP",
];

// ═══════════════════════════════════════════════════════════════════════════════
// Deny Prefixes (Secondary Belt)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * These prefixes are NEVER passed through, even if somehow in allowlist.
 * Defense in depth against credential leakage and code injection.
 */
export const ENV_DENY_PREFIXES = [
	// === CODE INJECTION VECTORS (CRITICAL) ===
	// Dynamic linker injection (Linux)
	"LD_", // LD_PRELOAD, LD_LIBRARY_PATH - inject shared libraries
	// Dynamic linker injection (macOS)
	"DYLD_", // DYLD_INSERT_LIBRARIES, DYLD_LIBRARY_PATH - same as LD_PRELOAD
	// Node.js injection (NODE_ENV is safe and in allowlist, these are dangerous)
	"NODE_OPTIONS", // --require injection to preload arbitrary code
	"NODE_PATH", // Module path injection
	// Python injection
	"PYTHON", // PYTHONSTARTUP, PYTHONPATH, PYTHONUSERSITE
	// Ruby injection
	"RUBY", // RUBYOPT, RUBYLIB
	// Perl injection
	"PERL", // PERL5OPT, PERL5LIB
	// Bash startup injection
	"BASH_ENV", // Runs commands before bash scripts
	// Note: "ENV" omitted as it conflicts with legitimate env vars

	// === CLOUD PROVIDERS ===
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

	// SECURITY: Override TMPDIR to private temp directory
	// This ensures commands use our private temp instead of host /tmp
	// (which is blocked via denyRead in sandbox config)
	const resolvedTmpPath = PRIVATE_TMP_PATH.startsWith("~")
		? path.join(os.homedir(), PRIVATE_TMP_PATH.slice(2))
		: PRIVATE_TMP_PATH;
	sandboxEnv.TMPDIR = resolvedTmpPath;
	sandboxEnv.TMP = resolvedTmpPath;
	sandboxEnv.TEMP = resolvedTmpPath;

	// Override HOME to private temp directory (writable and isolated from real ~)
	// Using the same path as TMPDIR ensures HOME is in allowWrite and exists.
	// Previously set to "/home/sandbox" which didn't exist and wasn't writable.
	sandboxEnv.HOME = resolvedTmpPath;

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
