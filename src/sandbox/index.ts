/**
 * Sandbox module exports.
 *
 * Provides OS-level isolation using @anthropic-ai/sandbox-runtime.
 * - Filesystem: Deny ~ broadly, allow only workspace
 * - Environment: Allowlist-only model
 * - Network: Domain + method restrictions
 * - Private /tmp: Host /tmp blocked; writes go to ~/.telclaude/sandbox-tmp
 */

export {
	initializeSandbox,
	resetSandbox,
	isSandboxInitialized,
	getSandboxConfig,
	wrapCommand,
	isSandboxAvailable,
	buildSandboxConfig,
	updateSandboxConfig,
	type SandboxInitResult,
} from "./manager.js";

// Claude SDK settings builder (fed to @anthropic-ai/claude-agent-sdk via --settings)
export { buildSdkPermissionsForTier } from "./sdk-settings.js";

export {
	SENSITIVE_READ_PATHS,
	DEFAULT_WRITE_PATHS,
	DENY_WRITE_PATHS,
	DEFAULT_SANDBOX_CONFIG,
	getSandboxConfigForTier,
	prewarmSandboxConfigCache,
	PRIVATE_TMP_PATH,
	PRIVATE_TMP_CONFIG, // Deprecated, use PRIVATE_TMP_PATH
	BLOCKED_METADATA_DOMAINS,
	BLOCKED_PRIVATE_NETWORKS,
} from "./config.js";

// Environment isolation
export {
	buildSandboxEnv,
	getEnvIsolationSummary,
	isEnvVarSafe,
	getBlockedEnvVars,
	ENV_ALLOWLIST,
	ENV_DENY_PREFIXES,
} from "./env.js";

// Network proxy with domain allowlist and method restrictions
export {
	checkNetworkRequest,
	getNetworkIsolationSummary,
	runNetworkSelfTest,
	isBlockedIP,
	DEFAULT_NETWORK_CONFIG,
	DEFAULT_ALLOWED_DOMAINS,
	type NetworkProxyConfig,
	type DomainRule,
	type HttpMethod,
	type NetworkRequestCheck,
	type NetworkIsolationSummary,
	type NetworkSelfTestResult,
} from "./network-proxy.js";

// Domain builders
export {
	buildAllowedDomains,
	buildAllowedDomainNames,
	OPENAI_DOMAINS,
} from "./domains.js";

// Sandbox-runtime version helper (for CVE checks)
export {
	getSandboxRuntimeVersion,
	isSandboxRuntimeAtLeast,
	MIN_SANDBOX_RUNTIME_VERSION,
} from "./version.js";

// Glob expansion for Linux (bubblewrap doesn't support globs)
export {
	expandGlobsForLinux,
	analyzeGlobPatterns,
	isLinux,
	containsGlobChars,
	getGlobPatterns,
} from "./glob-expansion.js";
