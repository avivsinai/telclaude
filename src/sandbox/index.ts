/**
 * Sandbox module exports.
 *
 * Simplified architecture:
 * - Docker mode: relay container provides process-level isolation.
 * - Native mode: relay is host-local; LLM/persona execution still routes
 *   through contained Hermes.
 *
 * Application-level security and relay/Hermes containment provide defense-in-depth.
 */

// Constants for application-level security checks
export {
	BLOCKED_METADATA_DOMAINS,
	BLOCKED_PRIVATE_NETWORKS,
	DENY_WRITE_PATHS,
	SENSITIVE_READ_PATHS,
} from "./config.js";
// Domain builders (for firewall/network policy config)
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
