/**
 * Sandbox module exports.
 *
 * V2 SECURITY ARCHITECTURE:
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
} from "./manager.js";

export {
	SENSITIVE_READ_PATHS,
	DEFAULT_WRITE_PATHS,
	DENY_WRITE_PATHS,
	DEFAULT_SANDBOX_CONFIG,
	TIER_SANDBOX_CONFIGS,
	getSandboxConfigForTier,
	PRIVATE_TMP_PATH,
	PRIVATE_TMP_CONFIG, // Deprecated, use PRIVATE_TMP_PATH
	BLOCKED_METADATA_DOMAINS,
	BLOCKED_PRIVATE_NETWORKS,
} from "./config.js";

// V2: Environment isolation
export {
	buildSandboxEnv,
	getEnvIsolationSummary,
	isEnvVarSafe,
	getBlockedEnvVars,
	ENV_ALLOWLIST,
	ENV_DENY_PREFIXES,
} from "./env.js";

// V2: Network proxy with domain allowlist and method restrictions
export {
	checkNetworkRequest,
	getNetworkIsolationSummary,
	runNetworkSelfTest,
	DEFAULT_NETWORK_CONFIG,
	DEFAULT_ALLOWED_DOMAINS,
	type NetworkProxyConfig,
	type DomainRule,
	type HttpMethod,
	type NetworkRequestCheck,
	type NetworkIsolationSummary,
	type NetworkSelfTestResult,
} from "./network-proxy.js";
