/**
 * Sandbox manager wrapper for telclaude.
 *
 * Provides a high-level interface for sandboxing commands with
 * telclaude-specific configuration and lifecycle management.
 */

import { SandboxManager, type SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime";
import { getChildLogger } from "../logging.js";
import { DEFAULT_SANDBOX_CONFIG, buildSandboxConfig } from "./config.js";

const logger = getChildLogger({ module: "sandbox" });

// ═══════════════════════════════════════════════════════════════════════════════
// Sandbox State
// ═══════════════════════════════════════════════════════════════════════════════

let initialized = false;
let currentConfig: SandboxRuntimeConfig | null = null;

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
		await SandboxManager.initialize(sandboxConfig);
		initialized = true;
		currentConfig = sandboxConfig;

		logger.info(
			{
				denyRead: sandboxConfig.filesystem?.denyRead?.length ?? 0,
				allowWrite: sandboxConfig.filesystem?.allowWrite?.length ?? 0,
				allowedDomains: sandboxConfig.network?.allowedDomains?.length ?? 0,
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
 * Wrap a command with sandbox isolation.
 *
 * Returns the command string prefixed with the sandbox wrapper.
 * The sandbox enforces filesystem and network restrictions at the OS level.
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
		const wrapped = await SandboxManager.wrapWithSandbox(command);
		logger.debug({ original: command, wrapped: wrapped.substring(0, 100) }, "command wrapped");
		return wrapped;
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
