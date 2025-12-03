/**
 * Sandbox configuration for telclaude.
 *
 * Uses @anthropic-ai/sandbox-runtime to isolate Claude's execution environment.
 * This provides OS-level sandboxing (Seatbelt on macOS, bubblewrap on Linux).
 *
 * Security model:
 * - Filesystem: Deny access to sensitive paths (~/.telclaude, ~/.ssh, etc.)
 * - Network: Permissive by default (configurable via config)
 * - All permission tiers are sandboxed for defense-in-depth
 * - Tier-aligned configs: READ_ONLY has stricter write restrictions
 */

import type { SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime";
import type { PermissionTier } from "../config/config.js";

/**
 * Sensitive paths that should never be readable by sandboxed processes.
 * These include telclaude's own data and common credential stores.
 */
export const SENSITIVE_READ_PATHS = [
	// === Telclaude data ===
	"~/.telclaude", // Our database, config, sockets

	// === Environment files (secrets!) ===
	// These patterns block .env files anywhere in readable paths
	"**/.env",
	"**/.env.*", // .env.local, .env.production, etc.
	"**/.envrc", // direnv files
	"**/secrets.json",
	"**/secrets.yaml",
	"**/secrets.yml",

	// === Claude Code data ===
	"~/.claude", // Conversation history, settings
	"~/Library/Application Support/Claude", // macOS app data

	// === Shell history (may contain typed secrets) ===
	"~/.bash_history",
	"~/.zsh_history",
	"~/.zsh_sessions",
	"~/.sh_history",
	"~/.history",
	"~/.lesshst",
	"~/.node_repl_history",
	"~/.python_history",
	"~/.psql_history",
	"~/.mysql_history",
	"~/.sqlite_history",
	"~/.rediscli_history",

	// === SSH/GPG keys ===
	"~/.ssh", // SSH keys
	"~/.gnupg", // GPG keys

	// === Cloud credentials ===
	"~/.aws", // AWS credentials
	"~/.azure", // Azure credentials
	"~/.config/gcloud", // GCP credentials
	"~/.kube", // Kubernetes configs
	"~/.docker/config.json", // Docker registry auth

	// === Package manager auth ===
	"~/.npmrc", // npm auth tokens
	"~/.pypirc", // PyPI credentials
	"~/.gem/credentials", // RubyGems
	"~/.cargo/credentials", // Cargo/crates.io

	// === Git credentials ===
	"~/.netrc", // Various service credentials
	"~/.gitconfig", // Git config (may contain credentials)
	"~/.git-credentials", // Git credentials

	// === Browser profiles (localStorage may have tokens) ===
	"~/Library/Application Support/Google/Chrome",
	"~/Library/Application Support/Firefox",
	"~/Library/Application Support/Arc",
	"~/.config/chromium",
	"~/.config/google-chrome",
	"~/.mozilla",

	// === macOS Keychain (defense in depth) ===
	"~/Library/Keychains",

	// === Linux proc filesystem ===
	"/proc/self/environ", // Environment variables
	"/proc/self/cmdline", // Command line args
];

/**
 * Default write-allowed paths.
 * Sandboxed processes can only write to these locations.
 */
export const DEFAULT_WRITE_PATHS = [
	".", // Current working directory
	"/tmp", // Temporary files
	"/var/tmp", // Persistent temp files
];

/**
 * Paths that should never be writable, even if in an allowed write path.
 * This is a safety net for sensitive files that might be in cwd.
 */
export const DENY_WRITE_PATHS = [
	".env", // Environment secrets
	".env.local",
	".env.production",
	".env.development",
	"*.pem", // Private keys
	"*.key",
	"id_rsa",
	"id_ed25519",
	"credentials.json", // Service account keys
	"service-account.json",
];

/**
 * Build sandbox configuration.
 *
 * @param options - Configuration overrides
 * @returns SandboxRuntimeConfig for the sandbox manager
 */
export function buildSandboxConfig(options: {
	/** Additional paths to deny reading */
	additionalDenyRead?: string[];
	/** Additional paths to allow writing */
	additionalAllowWrite?: string[];
	/** Allowed network domains (default: all via '*') */
	allowedDomains?: string[];
	/** Denied network domains (takes precedence over allowed) */
	deniedDomains?: string[];
	/** Allow Unix socket access (e.g., for Docker) */
	allowUnixSockets?: string[];
}): SandboxRuntimeConfig {
	return {
		filesystem: {
			denyRead: [...SENSITIVE_READ_PATHS, ...(options.additionalDenyRead ?? [])],
			allowWrite: [...DEFAULT_WRITE_PATHS, ...(options.additionalAllowWrite ?? [])],
			denyWrite: DENY_WRITE_PATHS,
		},
		network: {
			// Default to permissive network access (user's choice)
			// Can be restricted via config
			allowedDomains: options.allowedDomains ?? ["*"],
			deniedDomains: options.deniedDomains ?? [],
			allowUnixSockets: options.allowUnixSockets ?? [],
			allowLocalBinding: false, // No need to bind local ports
		},
	};
}

/**
 * Default sandbox configuration.
 * Uses permissive network but restricts filesystem access to sensitive paths.
 */
export const DEFAULT_SANDBOX_CONFIG = buildSandboxConfig({});

// ═══════════════════════════════════════════════════════════════════════════════
// Tier-Aligned Sandbox Configs
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Sandbox configuration aligned with permission tiers.
 *
 * The sandbox enforces what Claude CAN do (enforcement),
 * while the tier controls what Claude SHOULD do (policy).
 * The sandbox matches the tier, not more restrictive.
 *
 * - READ_ONLY: No writes allowed (empty allowWrite)
 * - WRITE_SAFE: Writes to cwd + /tmp
 * - FULL_ACCESS: Same as WRITE_SAFE (sandbox is safety net, not policy)
 */
export const TIER_SANDBOX_CONFIGS: Record<PermissionTier, SandboxRuntimeConfig> = {
	READ_ONLY: buildSandboxConfig({
		// No writes allowed for read-only tier
		additionalAllowWrite: [],
	}),
	WRITE_SAFE: buildSandboxConfig({
		// Standard write paths for write-safe tier
		additionalAllowWrite: [],
	}),
	FULL_ACCESS: buildSandboxConfig({
		// Same as WRITE_SAFE - sandbox is safety net, tier is policy
		additionalAllowWrite: [],
	}),
};

// Override the allowWrite for READ_ONLY to be empty
// (buildSandboxConfig adds DEFAULT_WRITE_PATHS, we need to remove them)
TIER_SANDBOX_CONFIGS.READ_ONLY = {
	...TIER_SANDBOX_CONFIGS.READ_ONLY,
	filesystem: {
		...TIER_SANDBOX_CONFIGS.READ_ONLY.filesystem,
		allowWrite: [], // No writes for READ_ONLY
	},
};

/**
 * Get sandbox configuration for a specific permission tier.
 */
export function getSandboxConfigForTier(tier: PermissionTier): SandboxRuntimeConfig {
	return TIER_SANDBOX_CONFIGS[tier];
}
