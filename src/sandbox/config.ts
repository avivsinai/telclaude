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
 */

import type { SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime";

/**
 * Sensitive paths that should never be readable by sandboxed processes.
 * These include telclaude's own data and common credential stores.
 */
export const SENSITIVE_READ_PATHS = [
	"~/.telclaude", // Our database, config, sockets
	"~/.ssh", // SSH keys
	"~/.gnupg", // GPG keys
	"~/.aws", // AWS credentials
	"~/.azure", // Azure credentials
	"~/.config/gcloud", // GCP credentials
	"~/.kube", // Kubernetes configs
	"~/.docker/config.json", // Docker registry auth
	"~/.npmrc", // npm auth tokens
	"~/.pypirc", // PyPI credentials
	"~/.netrc", // Various service credentials
	"~/.gitconfig", // Git config (may contain credentials)
	"~/.git-credentials", // Git credentials
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
