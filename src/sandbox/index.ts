/**
 * Sandbox module exports.
 *
 * Simplified architecture:
 * - Docker mode: SDK sandbox disabled, Docker container provides isolation
 * - Native mode: SDK sandbox enabled (bubblewrap/Seatbelt)
 *
 * Application-level security (canUseTool, PreToolUse hooks) provides defense-in-depth.
 */

// Mode detection
export {
	getSandboxMode,
	isDockerEnvironment,
	shouldEnableSdkSandbox,
	type SandboxMode,
} from "./mode.js";

// Constants for application-level security checks
export {
	SENSITIVE_READ_PATHS,
	BLOCKED_METADATA_DOMAINS,
	BLOCKED_PRIVATE_NETWORKS,
	DENY_WRITE_PATHS,
} from "./config.js";

// SDK settings builder (for allowedTools per tier)
export { buildSdkPermissionsForTier } from "./sdk-settings.js";

// Network proxy (for isBlockedHost in canUseTool)
export {
	checkNetworkRequest,
	getNetworkIsolationSummary,
	runNetworkSelfTest,
	isBlockedIP,
	isBlockedHost,
	DEFAULT_NETWORK_CONFIG,
	DEFAULT_ALLOWED_DOMAINS,
	type NetworkProxyConfig,
	type DomainRule,
	type HttpMethod,
	type NetworkRequestCheck,
	type NetworkIsolationSummary,
	type NetworkSelfTestResult,
} from "./network-proxy.js";

// Domain builders (for SDK sandbox network config)
export {
	buildAllowedDomains,
	buildAllowedDomainNames,
	domainMatchesPattern,
	OPENAI_DOMAINS,
} from "./domains.js";

// Version helper
export {
	getSandboxRuntimeVersion,
	isSandboxRuntimeAtLeast,
	MIN_SANDBOX_RUNTIME_VERSION,
} from "./version.js";
