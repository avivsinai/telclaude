/**
 * Sandbox configuration for telclaude.
 *
 * SECURITY ARCHITECTURE:
 * Uses @anthropic-ai/sandbox-runtime to isolate Claude's execution environment.
 * This provides OS-level sandboxing (Seatbelt on macOS, bubblewrap on Linux).
 *
 * Security model:
 * - Filesystem: Deny ~ broadly, allow only workspace
 * - Environment: Allowlist-only model (see src/sandbox/env.ts)
 * - Network: Domain + method restrictions via proxy
 * - Private temp: Writes go to ~/.telclaude/sandbox-tmp (but host /tmp NOT blocked,
 *   as Linux sandbox-runtime creates tmpfs mounts that would hide network sockets)
 *
 * Tier-aligned configs:
 * - READ_ONLY: No writes allowed
 * - WRITE_SAFE/FULL_ACCESS: Writes to workspace + private temp
 *
 * LINUX GLOB WORKAROUND:
 * The @anthropic-ai/sandbox-runtime library silently drops glob patterns on Linux
 * (bubblewrap doesn't support them). We work around this by expanding globs to
 * literal paths before passing to the sandbox. See glob-expansion.ts for details.
 */

import type { SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime";
import type { PermissionTier } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { DEFAULT_ALLOWED_DOMAIN_NAMES } from "./domains.js";
import { expandGlobsForLinux, getGlobPatterns, isLinux } from "./glob-expansion.js";

const IS_PROD = process.env.TELCLAUDE_ENV === "prod" || process.env.NODE_ENV === "production";

/**
 * Sensitive paths that should never be readable by sandboxed processes.
 * These include telclaude's own data and common credential stores.
 *
 * LINUX LIMITATION: On Linux, glob patterns like ".env" and "secrets.*" are
 * expanded to literal paths at sandbox initialization time. Two caveats:
 * 1. Files matching these patterns CREATED AFTER init will NOT be protected
 * 2. Expansion runs from cwd AND home directory to cover sensitive files outside cwd
 *
 * This is a fundamental limitation of bubblewrap (Linux sandbox).
 * See glob-expansion.ts for details.
 *
 * On macOS (Seatbelt), glob patterns work natively and these limitations do not apply.
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

	// NOTE: ~/.claude is NOT blocked because Claude CLI needs it for authentication.
	// The srt sandbox wraps the entire Claude process, so blocking ~/.claude would
	// prevent Claude from reading its own OAuth tokens and settings.

	// === Claude desktop app data ===
	"~/Library/Application Support/Claude", // macOS app data

	// === Shell configuration files (can inject startup malware) ===
	"~/.bashrc",
	"~/.bash_profile",
	"~/.bash_login",
	"~/.zshrc",
	"~/.zprofile",
	"~/.zlogin",
	"~/.zshenv",
	"~/.profile",
	"~/.login",
	"~/.cshrc",
	"~/.tcshrc",
	"~/.config/fish/config.fish",

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
	"~/.git-credentials", // Git credentials

	// === Browser profiles (localStorage may have tokens) ===
	"~/Library/Application Support/Google/Chrome",
	"~/Library/Application Support/Firefox",
	"~/Library/Application Support/Arc",
	"~/.config/chromium",
	"~/.config/google-chrome",
	"~/.mozilla",

	// NOTE: ~/Library/Keychains is NOT blocked to allow Claude CLI subscription auth.
	// Claude uses macOS Keychain to store OAuth tokens from `claude login`.
	// Blocking Keychain would require ANTHROPIC_API_KEY which triggers API billing.
	// Trade-off: Keychain access grants potential access to OTHER stored secrets.
	// Mitigations:
	// - Claude's Seatbelt profile restricts Keychain access to its own items
	// - Network isolation prevents exfiltration
	// - Output filter catches leaked secrets

	// === Linux proc filesystem ===
	"/proc/self/environ", // Environment variables
	"/proc/self/cmdline", // Command line args

	// === Temp directories ===
	// Host temp directories contain secrets: SSH agent sockets, keyring sockets,
	// D-Bus sockets, credential files, etc.
	//
	// IMPORTANT: We set TMPDIR to our private temp (~/.telclaude/sandbox-tmp) BEFORE
	// calling SandboxManager.initialize() in manager.ts. This makes sandbox-runtime
	// create its network bridge sockets there instead of /tmp, allowing us to safely
	// block host /tmp and /var/tmp without breaking network functionality.
	"/tmp",
	"/var/tmp",

	// systemd user runtime directories (contains keyring, gpg-agent, ssh-agent, etc.)
	"/run/user",
];

/**
 * Private temporary directory for sandboxed processes.
 * This is used instead of host /tmp to prevent reading secrets.
 */
export const PRIVATE_TMP_PATH = "~/.telclaude/sandbox-tmp";

/**
 * Default write-allowed paths (excluding cwd which must be passed dynamically).
 * Sandboxed processes can only write to these locations plus their cwd.
 *
 * Note: We use PRIVATE_TMP_PATH instead of /tmp to prevent
 * reading secrets from host /tmp (keyring sockets, dbus secrets, etc.)
 */
export const DEFAULT_WRITE_PATHS = [
	PRIVATE_TMP_PATH, // Private temp dir (host /tmp is blocked)
	// Claude CLI config + atomic temp files
	"~/.claude.json",
	"~/.claude.json.*",
	// Claude CLI workspace data (sessions, history, logs)
	"~/.claude",
	"~/.claude/**",
];

/**
 * @deprecated Use PRIVATE_TMP_PATH instead. This is kept for backward compatibility.
 * The SDK doesn't support bind mounts, so we block host /tmp via denyRead
 * and allow writes to PRIVATE_TMP_PATH instead.
 */
export const PRIVATE_TMP_CONFIG = {
	hostPath: PRIVATE_TMP_PATH,
	sandboxPath: PRIVATE_TMP_PATH, // No actual mounting, just the write-allowed path
};

// NOTE: Symlink protection is NOT implemented. The @anthropic-ai/sandbox-runtime
// SDK does not support symlink policies. The underlying sandbox (Seatbelt/bubblewrap)
// may provide some protection, but it's not configurable via the SDK.
// DO NOT claim symlink protection in documentation.

/**
 * Cloud metadata endpoints that should be blocked to prevent SSRF attacks.
 * These are used by cloud providers for instance metadata and credentials.
 */
export const BLOCKED_METADATA_DOMAINS = [
	// AWS IMDSv1/v2 metadata service
	"169.254.169.254",
	// AWS ECS container metadata
	"169.254.170.2",
	// GCP metadata service
	"metadata.google.internal",
	"metadata.goog",
	// Azure Instance Metadata Service (IMDS)
	"169.254.169.254", // Same IP as AWS
	// Link-local addresses (entire range)
	"169.254.*",
	// Kubernetes service account tokens
	"kubernetes.default.svc",
	// DigitalOcean metadata
	"169.254.169.254",
	// Oracle Cloud Infrastructure
	"169.254.169.254",
	// Alibaba Cloud
	"100.100.100.200",
];

/**
 * RFC1918 private networks - always blocked.
 * Prevents accessing internal services, routers, etc.
 */
export const BLOCKED_PRIVATE_NETWORKS = [
	// Localhost
	"127.0.0.0/8",
	"::1",
	"localhost",
	// RFC1918 private ranges
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	// Link-local
	"169.254.0.0/16",
	"fe80::/10",
];

/**
 * Paths that should never be writable, even if in an allowed write path.
 * This is a safety net for sensitive files that might be in cwd.
 *
 * IMPORTANT: sandbox-runtime adds default write paths internally (e.g., /tmp/claude,
 * ~/.claude/debug) that we cannot disable. These denyWrite patterns are applied
 * to ALL writable paths, providing defense-in-depth against writing sensitive
 * file patterns to sandbox-runtime's internal paths.
 *
 * LINUX LIMITATION: On Linux, glob patterns (*.pem, *.key, .env.*, etc.) are
 * expanded to literal paths at sandbox initialization time. Files matching these
 * patterns that are CREATED AFTER init will NOT be protected by denyWrite.
 * This is a fundamental limitation of bubblewrap (Linux sandbox).
 *
 * Mitigations:
 * - Output filter (CORE patterns) catches secrets in output regardless of filesystem
 * - Most sensitive files (SSH keys, credentials) pre-exist before the sandbox runs
 * - The sandbox is defense-in-depth, not the primary security mechanism
 *
 * On macOS (Seatbelt), glob patterns work natively and this limitation does not apply.
 */
export const DENY_WRITE_PATHS = [
	// === Environment secrets ===
	".env",
	".env.local",
	".env.production",
	".env.development",
	".env.*", // Catch all .env variants
	".envrc", // direnv
	"secrets.json",
	"secrets.yaml",
	"secrets.yml",

	// === SSH keys ===
	"id_rsa",
	"id_rsa.pub",
	"id_ed25519",
	"id_ed25519.pub",
	"id_ecdsa",
	"id_ecdsa.pub",
	"id_dsa",
	"id_dsa.pub",
	"authorized_keys",
	"known_hosts",
	"*.pem",
	"*.key",
	"*.ppk", // PuTTY private keys

	// === SSL/TLS certificates and keys ===
	"*.crt",
	"*.cer",
	"*.p12",
	"*.pfx",
	"*.jks", // Java keystore

	// === Cloud provider credentials ===
	"credentials.json", // GCP service account
	"service-account.json",
	"credentials", // AWS credentials file
	"config", // AWS config (when writing to ~/.aws/)

	// === Package manager auth ===
	".npmrc",
	".pypirc",
	".netrc",
	".git-credentials",
	".gitconfig",

	// === Shell configuration (prevent injection) ===
	".bashrc",
	".bash_profile",
	".zshrc",
	".zprofile",
	".profile",
	"config.fish",

	// === GPG keys ===
	"*.gpg",
	"*.asc",
	"pubring.kbx",
	"trustdb.gpg",

	// === Kubernetes/Docker ===
	"kubeconfig",
	"config.json", // Docker config

	// === Generic secret patterns ===
	"*_secret*",
	"*_private*",
	"*_token*",
	"*_credential*",
];

const logger = getChildLogger({ module: "sandbox-config" });

/**
 * Build sandbox configuration.
 *
 * On Linux, glob patterns are expanded to literal paths since bubblewrap
 * doesn't support globs. This is a point-in-time expansion.
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
	/** Working directory for glob expansion (default: process.cwd()) */
	cwd?: string;
}): SandboxRuntimeConfig {
	const cwd = options.cwd ?? process.cwd();
	const envNetworkMode = process.env.TELCLAUDE_NETWORK_MODE?.toLowerCase();

	let resolvedDefaultAllowed = DEFAULT_ALLOWED_DOMAIN_NAMES;
	if (envNetworkMode === "open" || envNetworkMode === "permissive") {
		logger.warn(
			'TELCLAUDE_NETWORK_MODE=open|permissive requested but sandbox-runtime forbids "*"; using default allowlist instead',
		);
		resolvedDefaultAllowed = DEFAULT_ALLOWED_DOMAIN_NAMES;
	}

	// Collect all deny/allow paths
	let denyRead = [...SENSITIVE_READ_PATHS, ...(options.additionalDenyRead ?? [])];
	let denyWrite = [...DENY_WRITE_PATHS];
	let allowWrite = [...DEFAULT_WRITE_PATHS, ...(options.additionalAllowWrite ?? [])];

	// LINUX GLOB WORKAROUND: Expand globs to literal paths
	// The sandbox-runtime silently drops glob patterns on Linux
	if (isLinux()) {
		const denyReadGlobs = getGlobPatterns(denyRead);
		const denyWriteGlobs = getGlobPatterns(denyWrite);

		const allowWriteGlobs = getGlobPatterns(allowWrite);

		if (denyReadGlobs.length > 0 || denyWriteGlobs.length > 0 || allowWriteGlobs.length > 0) {
			logger.warn(
				{
					denyReadGlobs: denyReadGlobs.length,
					denyWriteGlobs: denyWriteGlobs.length,
					allowWriteGlobs: allowWriteGlobs.length,
					patterns: [...denyReadGlobs, ...denyWriteGlobs, ...allowWriteGlobs].slice(0, 10),
				},
				"Linux sandbox: expanding glob patterns to literal paths (bubblewrap limitation)",
			);
		}

		denyRead = expandGlobsForLinux(denyRead, cwd);
		denyWrite = expandGlobsForLinux(denyWrite, cwd);
		allowWrite = expandGlobsForLinux(allowWrite, cwd);
	}

	return {
		filesystem: {
			denyRead,
			allowWrite,
			denyWrite,
		},
		network: {
			// Default to strict allowlist using well-known developer domains.
			// Users can opt into broader access via options.allowedDomains or TELCLAUDE_NETWORK_MODE=open.
			allowedDomains: options.allowedDomains ?? resolvedDefaultAllowed,
			// SECURITY: Always block cloud metadata endpoints to prevent SSRF
			deniedDomains: [...BLOCKED_METADATA_DOMAINS, ...(options.deniedDomains ?? [])],
			allowUnixSockets: options.allowUnixSockets ?? [],
			// In dev we allow local binding/Unix sockets to avoid host-seatbelt friction.
			allowLocalBinding: !IS_PROD,
			// SECURITY: Disable arbitrary Unix socket creation in prod; relax in dev to reduce failures.
			allowAllUnixSockets: !IS_PROD,
		},
	};
}

/**
 * Default sandbox configuration.
 * Uses a strict network allowlist and restricts filesystem access to sensitive paths.
 */
export const DEFAULT_SANDBOX_CONFIG = buildSandboxConfig({});

// ═══════════════════════════════════════════════════════════════════════════════
// Tier-Aligned Sandbox Configs
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Get sandbox configuration for a specific permission tier.
 *
 * The sandbox enforces what Claude CAN do (enforcement),
 * while the tier controls what Claude SHOULD do (policy).
 * The sandbox matches the tier, not more restrictive.
 *
 * @param tier - Permission tier
 * @param cwd - Working directory to allow writes to (for WRITE_SAFE/FULL_ACCESS) and for glob expansion
 * @returns SandboxRuntimeConfig with tier-appropriate permissions
 *
 * - READ_ONLY: No writes allowed
 * - WRITE_SAFE: Writes to cwd + private temp
 * - FULL_ACCESS: Same as WRITE_SAFE (sandbox is safety net, not policy)
 */
export function getSandboxConfigForTier(tier: PermissionTier, cwd?: string): SandboxRuntimeConfig {
	const workingDir = cwd ?? process.cwd();

	if (tier === "READ_ONLY") {
		// No writes allowed for read-only tier
		// Still pass cwd for glob expansion on Linux
		const baseConfig = buildSandboxConfig({ cwd: workingDir });
		return {
			...baseConfig,
			filesystem: {
				...baseConfig.filesystem,
				allowWrite: [], // No writes for READ_ONLY
			},
		};
	}

	// WRITE_SAFE and FULL_ACCESS: allow writes to cwd and private temp
	return buildSandboxConfig({
		additionalAllowWrite: cwd ? [cwd] : [],
		cwd: workingDir,
	});
}
