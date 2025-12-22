/**
 * Sandbox manager for telclaude.
 *
 * Provides a high-level interface for sandboxing commands with
 * telclaude-specific configuration and lifecycle management.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { SandboxManager, type SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime";
import { getChildLogger } from "../logging.js";
import { getGitCredentials } from "../services/git-credentials.js";
import { getOpenAIKey } from "../services/openai-client.js";
import { DEFAULT_SANDBOX_CONFIG, PRIVATE_TMP_PATH, buildSandboxConfig } from "./config.js";
import { domainMatchesPattern } from "./domains.js";
import { buildSandboxEnv } from "./env.js";
import { isBlockedHost } from "./network-proxy.js";
import {
	MIN_SANDBOX_RUNTIME_VERSION,
	getSandboxRuntimeVersion,
	isSandboxRuntimeAtLeast,
} from "./version.js";
const logger = getChildLogger({ module: "sandbox" });

// ═══════════════════════════════════════════════════════════════════════════════
// Sandbox State
// ═══════════════════════════════════════════════════════════════════════════════

let initialized = false;
let currentConfig: SandboxRuntimeConfig | null = null;
let sanitizedEnv: Record<string, string> | null = null;
let originalTmpdir: string | undefined;

// ═══════════════════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════════════════

/** Result of sandbox initialization */
export type SandboxInitResult = {
	/** Whether core sandbox (Bash isolation) initialized successfully */
	initialized: boolean;
};

/**
 * Initialize the sandbox manager with the given configuration.
 * Must be called before any sandboxed commands can be executed.
 *
 * Initializes two sandbox layers:
 * 1. Wrapper: Sandboxes entire Claude CLI subprocess (via pathToClaudeCodeExecutable)
 * 2. SandboxManager: Additional sandboxing for Bash commands (defense-in-depth)
 *
 * @param config - Optional configuration override (defaults to DEFAULT_SANDBOX_CONFIG)
 * @returns Status of sandbox initialization
 */
export async function initializeSandbox(config?: SandboxRuntimeConfig): Promise<SandboxInitResult> {
	if (initialized) {
		logger.debug("sandbox already initialized, skipping");
		return { initialized: true };
	}

	const runtimeVersion = getSandboxRuntimeVersion();
	if (runtimeVersion && !isSandboxRuntimeAtLeast()) {
		logger.warn(
			{ runtimeVersion, minimum: MIN_SANDBOX_RUNTIME_VERSION },
			"sandbox-runtime below patched version; upgrade recommended to fix network allowlist bug (CVE-2025-66479)",
		);
	} else if (!runtimeVersion) {
		logger.warn(
			"sandbox-runtime package not found; ensure dependencies are installed for network isolation",
		);
	}

	const sandboxConfig = config ?? DEFAULT_SANDBOX_CONFIG;
	try {
		// SECURITY: Create private temp directory before initializing sandbox
		// This ensures commands have a writable temp dir (host /tmp is blocked)
		const resolvedTmpPath = PRIVATE_TMP_PATH.startsWith("~")
			? path.join(os.homedir(), PRIVATE_TMP_PATH.slice(2))
			: PRIVATE_TMP_PATH;
		if (!fs.existsSync(resolvedTmpPath)) {
			fs.mkdirSync(resolvedTmpPath, { recursive: true, mode: 0o700 });
			logger.info({ path: resolvedTmpPath }, "created private temp directory");
		}

		// CRITICAL: Set TMPDIR BEFORE SandboxManager.initialize() on Linux
		// The sandbox-runtime creates network bridge sockets at tmpdir()/claude-*.sock
		// By pointing TMPDIR to our private temp, sockets land there instead of host /tmp.
		// This allows us to safely block host /tmp in denyRead without breaking network.
		originalTmpdir = process.env.TMPDIR;
		process.env.TMPDIR = resolvedTmpPath;
		logger.debug(
			{ tmpdir: resolvedTmpPath, originalTmpdir },
			"set TMPDIR for sandbox bridge sockets",
		);

		// Initialize SandboxManager for Bash commands (defense-in-depth)
		// NETWORK NOTES:
		// - We avoid a catch-all allowedDomains entry because it would bypass sandboxAskCallback,
		//   which we use to block private networks (including DNS rebinding) even in permissive mode.
		// - sandboxAskCallback is only invoked for domains NOT matched by allowedDomains/deniedDomains rules.
		// We use sandboxAskCallback to:
		// 1. Block private networks (RFC1918, localhost) - always enforced
		// 2. Allow broad egress when TELCLAUDE_NETWORK_MODE=open|permissive is set
		// NOTE: Callback reads currentConfig dynamically so updateSandboxConfig takes effect
		const sandboxAskCallback = async ({ host }: { host: string; port?: number }) => {
			// Always block private/internal networks (security critical)
			if (await isBlockedHost(host)) {
				logger.debug({ host }, "blocked private network access via sandboxAskCallback");
				return false;
			}
			const envMode = process.env.TELCLAUDE_NETWORK_MODE?.toLowerCase();
			if (envMode === "open" || envMode === "permissive") {
				return true;
			}
			// SECURITY: Check currentConfig dynamically (not captured at init time)
			// This ensures updateSandboxConfig() changes take effect immediately
			const allowedDomains = currentConfig?.network?.allowedDomains ?? [];
			if (allowedDomains.includes("*")) {
				return true;
			}
			if (allowedDomains.length === 0) {
				return false;
			}
			return allowedDomains.some((pattern) => domainMatchesPattern(host, pattern));
		};
		await SandboxManager.initialize(sandboxConfig, sandboxAskCallback);
		initialized = true;
		currentConfig = sandboxConfig;

		// SECURITY: Build sanitized environment for commands
		sanitizedEnv = buildSandboxEnv(process.env);

		logger.info(
			{
				denyRead: sandboxConfig.filesystem?.denyRead?.length ?? 0,
				allowWrite: sandboxConfig.filesystem?.allowWrite?.length ?? 0,
				allowedDomains: sandboxConfig.network?.allowedDomains?.length ?? 0,
				envVarsAllowed: Object.keys(sanitizedEnv).length,
			},
			"sandbox initialized",
		);

		return {
			initialized: true,
		};
	} catch (err) {
		logger.error({ error: String(err) }, "failed to initialize sandbox");
		throw new Error(`Sandbox initialization failed: ${String(err)}`);
	}
}

/**
 * Reset the sandbox manager.
 * Should be called during shutdown or when reconfiguring.
 */
export async function resetSandbox(): Promise<void> {
	if (!initialized) {
		return;
	}

	try {
		await SandboxManager.reset();
		initialized = false;
		currentConfig = null;
		sanitizedEnv = null;
		logger.info("sandbox reset");
	} catch (err) {
		logger.warn({ error: String(err) }, "error resetting sandbox");
	} finally {
		// Restore TMPDIR to its original value to avoid leaking global state.
		if (originalTmpdir === undefined) {
			Reflect.deleteProperty(process.env, "TMPDIR");
		} else {
			process.env.TMPDIR = originalTmpdir;
		}
		originalTmpdir = undefined;
	}
}

/**
 * Check if the sandbox is initialized.
 */
export function isSandboxInitialized(): boolean {
	return initialized;
}

/**
 * Get the current sandbox configuration.
 */
export function getSandboxConfig(): SandboxRuntimeConfig | null {
	return currentConfig;
}

/**
 * Update the sandbox configuration without restarting.
 *
 * Updates SandboxManager config (for Bash commands).
 */
export function updateSandboxConfig(config: SandboxRuntimeConfig): void {
	if (!initialized) {
		logger.warn("cannot update config: sandbox not initialized");
		return;
	}

	try {
		// Update SandboxManager config (for Bash commands)
		SandboxManager.updateConfig(config);
		currentConfig = config;
		logger.debug(
			{
				denyRead: config.filesystem?.denyRead?.length ?? 0,
				allowWrite: config.filesystem?.allowWrite?.length ?? 0,
			},
			"sandbox config updated",
		);
	} catch (err) {
		logger.error({ error: String(err) }, "failed to update sandbox config");
	}
}

/**
 * Escape a string for use in shell command (single-quote escaping).
 */
function shellEscape(value: string): string {
	// Replace single quotes with '\'' (end quote, escaped quote, start quote)
	return `'${value.replace(/'/g, "'\\''")}'`;
}

/**
 * Build environment prefix for commands.
 * Uses `env -i KEY=VALUE...` to ensure only allowed vars reach the command.
 *
 * Reads API keys fresh from secure storage on each call for hot-loading support.
 * If keys are updated via `telclaude setup-openai` or `telclaude setup-git`,
 * subsequent commands will pick up the new values without restart.
 */
async function buildEnvPrefixAsync(): Promise<string> {
	if (!sanitizedEnv) {
		return "";
	}

	// Start with the sanitized base env
	const envToApply: Record<string, string> = { ...sanitizedEnv };

	// Fetch API keys fresh from secure storage (supports hot-loading)
	const openaiKey = await getOpenAIKey();
	if (openaiKey) {
		envToApply.OPENAI_API_KEY = openaiKey;
	}

	const gitCreds = await getGitCredentials();
	const githubToken = gitCreds?.token || process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
	if (githubToken) {
		envToApply.GITHUB_TOKEN = githubToken;
		envToApply.GH_TOKEN = githubToken;
	}

	const envAssignments = Object.entries(envToApply)
		.map(([key, value]) => `${key}=${shellEscape(value)}`)
		.join(" ");

	return `env -i ${envAssignments} `;
}

/**
 * Wrap a command with sandbox isolation.
 *
 * Returns the command string prefixed with:
 * 1. Environment isolation (env -i KEY=VALUE...)
 * 2. Sandbox (filesystem + network restrictions)
 *
 * The sandbox enforces filesystem and network restrictions at the OS level.
 * Environment isolation ensures only allowlisted env vars reach the command.
 *
 * @param command - The command to sandbox
 * @returns The sandboxed command string
 * @throws If sandbox is not initialized
 */
export async function wrapCommand(command: string): Promise<string> {
	if (!initialized) {
		throw new Error("Sandbox not initialized. Call initializeSandbox() first.");
	}

	try {
		// SECURITY: Override NO_PROXY to force RFC1918 traffic through the proxy.
		// The sandbox-runtime hardcodes NO_PROXY to bypass private networks (10.0.0.0/8, etc.)
		// for developer convenience. We reset it so all traffic goes through the proxy
		// where sandboxAskCallback can block RFC1918 addresses.
		const noProxyOverride = "export NO_PROXY= no_proxy= && ";
		const commandWithOverride = noProxyOverride + command;

		// First wrap with sandbox (filesystem + network isolation)
		const sandboxWrapped = await SandboxManager.wrapWithSandbox(commandWithOverride);

		// Then wrap with environment isolation
		// SECURITY: Apply allowlist-only environment
		// Uses async to fetch fresh API keys (supports hot-loading)
		const envPrefix = await buildEnvPrefixAsync();
		const fullyWrapped = envPrefix + sandboxWrapped;

		logger.debug(
			{
				original: command,
				wrapped: fullyWrapped.substring(0, 150),
				envVarsApplied: sanitizedEnv ? Object.keys(sanitizedEnv).length : 0,
			},
			"command wrapped with env isolation",
		);

		return fullyWrapped;
	} catch (err) {
		logger.error({ error: String(err), command }, "failed to wrap command");
		throw new Error(`Failed to sandbox command: ${String(err)}`);
	}
}

// Cache for sandbox availability (computed once at startup)
let sandboxAvailabilityChecked = false;
let sandboxAvailable = false;

/**
 * Check if sandboxing is available on this platform.
 *
 * Returns false on unsupported platforms (e.g., Windows) or if
 * required dependencies are missing (e.g., bubblewrap on Linux).
 *
 * This function is safe to call multiple times - it caches the result
 * and short-circuits if sandbox is already initialized.
 */
export async function isSandboxAvailable(): Promise<boolean> {
	// If already initialized in production, it's definitely available
	if (initialized) {
		return true;
	}

	// Return cached result if we've already checked
	if (sandboxAvailabilityChecked) {
		return sandboxAvailable;
	}

	// Perform the availability check once
	const resolvedTmpPath = PRIVATE_TMP_PATH.startsWith("~")
		? path.join(os.homedir(), PRIVATE_TMP_PATH.slice(2))
		: PRIVATE_TMP_PATH;
	const originalEnvTmpdir = process.env.TMPDIR;

	try {
		// Mirror initializeSandbox(): ensure private temp exists + use it for sandbox-runtime sockets.
		if (!fs.existsSync(resolvedTmpPath)) {
			fs.mkdirSync(resolvedTmpPath, { recursive: true, mode: 0o700 });
		}
		process.env.TMPDIR = resolvedTmpPath;

		const testConfig = buildSandboxConfig({});
		// Use same callback pattern for consistency with initializeSandbox
		const allowedDomains = testConfig.network?.allowedDomains ?? [];
		const sandboxAskCallback = async ({ host }: { host: string; port?: number }) => {
			if (await isBlockedHost(host)) return false;
			const envMode = process.env.TELCLAUDE_NETWORK_MODE?.toLowerCase();
			if (envMode === "open" || envMode === "permissive") return true;
			if (allowedDomains.includes("*")) return true;
			if (allowedDomains.length === 0) return false;
			return allowedDomains.some((pattern) => domainMatchesPattern(host, pattern));
		};
		await SandboxManager.initialize(testConfig, sandboxAskCallback);
		await SandboxManager.reset();
		sandboxAvailable = true;
	} catch {
		sandboxAvailable = false;
	} finally {
		// Restore TMPDIR to avoid leaking global state during a best-effort check.
		if (originalEnvTmpdir === undefined) {
			Reflect.deleteProperty(process.env, "TMPDIR");
		} else {
			process.env.TMPDIR = originalEnvTmpdir;
		}
	}

	sandboxAvailabilityChecked = true;
	return sandboxAvailable;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Config Helpers
// ═══════════════════════════════════════════════════════════════════════════════

export { buildSandboxConfig } from "./config.js";
