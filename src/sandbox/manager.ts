/**
 * Sandbox manager wrapper for telclaude.
 *
 * Provides a high-level interface for sandboxing commands with
 * telclaude-specific configuration and lifecycle management.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { SandboxManager, type SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime";
import { getChildLogger } from "../logging.js";
import { DEFAULT_SANDBOX_CONFIG, PRIVATE_TMP_PATH, buildSandboxConfig } from "./config.js";
import { buildSandboxEnv } from "./env.js";

const logger = getChildLogger({ module: "sandbox" });

// ═══════════════════════════════════════════════════════════════════════════════
// Sandbox State
// ═══════════════════════════════════════════════════════════════════════════════

let initialized = false;
let currentConfig: SandboxRuntimeConfig | null = null;
let sanitizedEnv: Record<string, string> | null = null;

// ═══════════════════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Initialize the sandbox manager with the given configuration.
 * Must be called before any sandboxed commands can be executed.
 *
 * @param config - Optional configuration override (defaults to DEFAULT_SANDBOX_CONFIG)
 */
export async function initializeSandbox(config?: SandboxRuntimeConfig): Promise<void> {
	if (initialized) {
		logger.debug("sandbox already initialized, skipping");
		return;
	}

	const sandboxConfig = config ?? DEFAULT_SANDBOX_CONFIG;

	try {
		// V2 SECURITY: Create private temp directory before initializing sandbox
		// This ensures commands have a writable temp dir (host /tmp is blocked)
		const resolvedTmpPath = PRIVATE_TMP_PATH.startsWith("~")
			? path.join(os.homedir(), PRIVATE_TMP_PATH.slice(2))
			: PRIVATE_TMP_PATH;
		if (!fs.existsSync(resolvedTmpPath)) {
			fs.mkdirSync(resolvedTmpPath, { recursive: true, mode: 0o700 });
			logger.info({ path: resolvedTmpPath }, "created private temp directory");
		}

		await SandboxManager.initialize(sandboxConfig);
		initialized = true;
		currentConfig = sandboxConfig;

		// V2 SECURITY: Build sanitized environment for commands
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
 * Uses SandboxManager.updateConfig() to hot-swap the configuration.
 * This is useful for tier-aligned configs where different tiers
 * have different sandbox restrictions.
 *
 * @param config - New configuration to apply
 */
export function updateSandboxConfig(config: SandboxRuntimeConfig): void {
	if (!initialized) {
		logger.warn("cannot update config: sandbox not initialized");
		return;
	}

	try {
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
 */
function buildEnvPrefix(): string {
	if (!sanitizedEnv) {
		return "";
	}

	const envAssignments = Object.entries(sanitizedEnv)
		.map(([key, value]) => `${key}=${shellEscape(value)}`)
		.join(" ");

	return `env -i ${envAssignments} `;
}

/**
 * Wrap a command with sandbox isolation.
 *
 * Returns the command string prefixed with:
 * 1. Environment isolation (env -i KEY=VALUE...)
 * 2. Sandbox wrapper (filesystem + network restrictions)
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
		// First wrap with sandbox (filesystem + network isolation)
		const sandboxWrapped = await SandboxManager.wrapWithSandbox(command);

		// Then wrap with environment isolation
		// V2 SECURITY: Apply allowlist-only environment
		const envPrefix = buildEnvPrefix();
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
	try {
		const testConfig = buildSandboxConfig({});
		await SandboxManager.initialize(testConfig);
		await SandboxManager.reset();
		sandboxAvailable = true;
	} catch {
		sandboxAvailable = false;
	}

	sandboxAvailabilityChecked = true;
	return sandboxAvailable;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Config Helpers
// ═══════════════════════════════════════════════════════════════════════════════

export { buildSandboxConfig } from "./config.js";
