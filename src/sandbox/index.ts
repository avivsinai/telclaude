/**
 * Sandbox module exports.
 *
 * Simplified architecture:
 * - Docker mode: SDK sandbox disabled, Docker container provides isolation
 * - Native mode: SDK sandbox enabled (bubblewrap/Seatbelt)
 *
 * Application-level security (canUseTool, PreToolUse hooks) provides defense-in-depth.
 */

// Constants for application-level security checks
export {
	BLOCKED_METADATA_DOMAINS,
	BLOCKED_PRIVATE_NETWORKS,
	DENY_WRITE_PATHS,
	SENSITIVE_READ_PATHS,
} from "./config.js";
// Domain builders (for SDK sandbox network config)
export {
	buildAllowedDomainNames,
	buildAllowedDomains,
	domainMatchesPattern,
	OPENAI_DOMAINS,
} from "./domains.js";
// Fetch guard (DNS-pinned fetch with redirect validation)
export {
	createPinnedLookup,
	FetchGuardError,
	type FetchWithGuardOptions,
	type FetchWithGuardResult,
	fetchWithGuard,
} from "./fetch-guard.js";
// Mode detection
export {
	getSandboxMode,
	isDockerEnvironment,
	type SandboxMode,
	shouldEnableSdkSandbox,
} from "./mode.js";
// Network proxy (for isBlockedHost in canUseTool)
export {
	checkNetworkRequest,
	DEFAULT_ALLOWED_DOMAINS,
	DEFAULT_NETWORK_CONFIG,
	type DomainRule,
	getNetworkIsolationSummary,
	type HttpMethod,
	isBlockedHost,
	isBlockedIP,
	type NetworkIsolationSummary,
	type NetworkProxyConfig,
	type NetworkRequestCheck,
	type NetworkSelfTestResult,
	runNetworkSelfTest,
} from "./network-proxy.js";
// SDK settings builder (for allowedTools per tier)
export { buildSdkPermissionsForTier } from "./sdk-settings.js";

// Version helper
export {
	getSandboxRuntimeVersion,
	isSandboxRuntimeAtLeast,
	MIN_SANDBOX_RUNTIME_VERSION,
} from "./version.js";
