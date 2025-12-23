/**
 * Sandbox configuration constants for telclaude.
 *
 * These constants are used for application-level security checks:
 * - SENSITIVE_READ_PATHS: Used by canUseTool to block reads
 * - BLOCKED_METADATA_DOMAINS: Used by isBlockedHost for SSRF protection
 * - BLOCKED_PRIVATE_NETWORKS: Used by isBlockedHost for RFC1918 blocking
 *
 * NOTE: The actual sandbox (bubblewrap/Seatbelt) is managed by SDK in native mode,
 * or by Docker in container mode. These constants provide application-level
 * defense-in-depth via canUseTool and PreToolUse hooks.
 */

/**
 * Sensitive paths that should never be readable.
 * Used by isSensitivePath() in security/permissions.ts for canUseTool checks.
 */
export const SENSITIVE_READ_PATHS = [
	// === Telclaude data ===
	"~/.telclaude",

	// === Environment files (secrets!) ===
	"**/.env",
	"**/.env.*",
	"**/.envrc",
	"**/secrets.json",
	"**/secrets.yaml",
	"**/secrets.yml",

	// === Claude desktop app data ===
	"~/Library/Application Support/Claude",

	// === Shell configuration files ===
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

	// === Shell history ===
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
	"~/.ssh",
	"~/.gnupg",

	// === Cloud credentials ===
	"~/.aws",
	"~/.azure",
	"~/.config/gcloud",
	"~/.kube",
	"~/.docker/config.json",

	// === Package manager auth ===
	"~/.npmrc",
	"~/.pypirc",
	"~/.gem/credentials",
	"~/.cargo/credentials",

	// === Git credentials ===
	"~/.netrc",
	"~/.git-credentials",

	// === Browser profiles ===
	"~/Library/Application Support/Google/Chrome",
	"~/Library/Application Support/Firefox",
	"~/Library/Application Support/Arc",
	"~/.config/chromium",
	"~/.config/google-chrome",
	"~/.mozilla",

	// === Linux proc filesystem ===
	"/proc/self/environ",
	"/proc/self/cmdline",

	// === Temp directories ===
	"/tmp",
	"/var/tmp",
	"/run/user",

	// === Claude settings (prevent disableAllHooks bypass) ===
	".claude/settings.json",
	".claude/settings.local.json",
];

/**
 * Cloud metadata endpoints that should be blocked to prevent SSRF attacks.
 */
export const BLOCKED_METADATA_DOMAINS = [
	"169.254.169.254", // AWS/GCP/Azure/OCI/DO instance metadata
	"169.254.170.2", // AWS ECS container metadata
	"metadata.google.internal",
	"metadata.goog",
	"kubernetes.default.svc",
	"100.100.100.200", // Alibaba Cloud metadata
];

/**
 * RFC1918 private networks - always blocked.
 */
export const BLOCKED_PRIVATE_NETWORKS = [
	"127.0.0.0/8",
	"::1",
	"localhost",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"fc00::/7",
	"fe80::/10",
];

/**
 * Paths that should never be writable.
 * Used by isSensitivePath() for write checks.
 */
export const DENY_WRITE_PATHS = [
	// Environment secrets
	".env",
	".env.local",
	".env.production",
	".env.development",
	".env.*",
	".envrc",
	"secrets.json",
	"secrets.yaml",
	"secrets.yml",

	// SSH keys
	"id_rsa",
	"id_rsa.pub",
	"id_ed25519",
	"id_ed25519.pub",
	"id_ecdsa",
	"id_ecdsa.pub",
	"authorized_keys",
	"known_hosts",

	// Shell configuration
	".bashrc",
	".bash_profile",
	".zshrc",
	".zprofile",
	".profile",

	// Git credentials
	".npmrc",
	".pypirc",
	".netrc",
	".git-credentials",
	".gitconfig",

	// Private keys and certificates
	"*.pem",
	"*.key",
	"*.p12",
	"*.pfx",
	"*.jks",
	"*.keystore",

	// Cloud credentials
	"credentials.json",
	"service-account.json",
	"gcloud-credentials.json",
	"application_default_credentials.json",

	// Claude settings (prevent disableAllHooks bypass)
	".claude/settings.json",
	".claude/settings.local.json",
];
