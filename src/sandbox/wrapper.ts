/**
 * Sandbox wrapper for Claude CLI subprocess.
 *
 * Generates a wrapper script that runs the Claude CLI through sandbox-runtime (srt),
 * applying filesystem and network restrictions at the OS level.
 *
 * Architecture:
 * ```
 * telclaude process
 *     │
 *     └─→ SDK spawns Claude via wrapper (pathToClaudeCodeExecutable)
 *             │
 *             └─→ srt sandboxes entire Claude process
 *                     │
 *                     └─→ All tools (Read/Write/Bash/etc) run sandboxed
 * ```
 *
 * This ensures ALL Claude operations (not just Bash) are sandboxed at the OS level,
 * matching our documented architecture: `seatbelt → sdk-sandbox → claude-code`
 */

import { execSync } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import type { SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime";
import { getChildLogger } from "../logging.js";
import { BLOCKED_METADATA_DOMAINS, BLOCKED_PRIVATE_NETWORKS } from "./config.js";
import { DEFAULT_ALLOWED_DOMAIN_NAMES } from "./domains.js";

// For resolving packages relative to telclaude installation
const require = createRequire(import.meta.url);

const logger = getChildLogger({ module: "sandbox-wrapper" });

// ═══════════════════════════════════════════════════════════════════════════════
// Paths
// ═══════════════════════════════════════════════════════════════════════════════

const TELCLAUDE_BIN_DIR = path.join(os.homedir(), ".telclaude", "bin");
const WRAPPER_PATH = path.join(TELCLAUDE_BIN_DIR, "claude");
const SRT_SETTINGS_PATH = path.join(os.homedir(), ".telclaude", "srt-settings.json");

// ═══════════════════════════════════════════════════════════════════════════════
// Binary Discovery
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Find the real Claude CLI binary path.
 * Searches PATH and common installation locations.
 */
function findClaudeBinary(): string | null {
	try {
		// Use 'which' to find the Claude binary, excluding our wrapper
		const result = execSync("which -a claude 2>/dev/null || true", { encoding: "utf-8" }).trim();
		const paths = result.split("\n").filter((p) => p && p !== WRAPPER_PATH);

		for (const p of paths) {
			if (fs.existsSync(p)) {
				// Verify it's the real claude, not a symlink to our wrapper
				const realPath = fs.realpathSync(p);
				if (realPath !== WRAPPER_PATH) {
					return p;
				}
			}
		}
	} catch {
		// which failed or not available
	}

	// Check common installation locations
	const commonPaths = [
		"/opt/homebrew/bin/claude", // Homebrew on Apple Silicon
		"/usr/local/bin/claude", // Homebrew on Intel Mac / manual install
		path.join(os.homedir(), ".npm-global", "bin", "claude"), // npm global
		"/usr/bin/claude", // System package
		path.join(os.homedir(), ".local", "bin", "claude"), // pip/pipx style
		// pnpm global bin locations
		path.join(os.homedir(), ".local", "share", "pnpm", "claude"), // pnpm on Linux
		path.join(os.homedir(), "Library", "pnpm", "claude"), // pnpm on macOS
		// Also check pnpm's PNPM_HOME if set
		...(process.env.PNPM_HOME ? [path.join(process.env.PNPM_HOME, "claude")] : []),
	];

	for (const p of commonPaths) {
		if (fs.existsSync(p) && p !== WRAPPER_PATH) {
			return p;
		}
	}

	return null;
}

/**
 * Find the srt (sandbox-runtime) binary path.
 *
 * Resolution order:
 * 1. Project root node_modules/.bin/srt (pnpm hoisted layout)
 * 2. Walk up from @anthropic-ai/sandbox-runtime to find .bin/srt
 * 3. which srt (PATH lookup)
 * 4. Common global installation paths
 */
function findSrtBinary(): string | null {
	// PRIMARY: Check project root node_modules/.bin (pnpm hoisted layout)
	// pnpm places shims at node_modules/.bin even when packages are in .pnpm store
	const cwdBin = path.join(process.cwd(), "node_modules", ".bin", "srt");
	if (fs.existsSync(cwdBin)) {
		return cwdBin;
	}

	// SECONDARY: Walk up from @anthropic-ai/sandbox-runtime package to find .bin/srt
	// This handles various npm/yarn/pnpm layouts
	try {
		const sandboxRuntimePkg = require.resolve("@anthropic-ai/sandbox-runtime/package.json");
		let searchDir = path.dirname(sandboxRuntimePkg);

		// Walk up directory tree looking for node_modules/.bin/srt
		// Stop at filesystem root
		while (searchDir !== path.dirname(searchDir)) {
			// Check if current dir has .bin/srt sibling (we're inside node_modules/@anthropic-ai/sandbox-runtime)
			const parentNodeModules = path.dirname(path.dirname(searchDir));
			const srtInBin = path.join(parentNodeModules, ".bin", "srt");
			if (fs.existsSync(srtInBin)) {
				return srtInBin;
			}

			// Also check if this directory itself is a node_modules with .bin
			const directBin = path.join(searchDir, ".bin", "srt");
			if (fs.existsSync(directBin)) {
				return directBin;
			}

			// Check node_modules/.bin at each level
			const nodeModulesBin = path.join(searchDir, "node_modules", ".bin", "srt");
			if (fs.existsSync(nodeModulesBin)) {
				return nodeModulesBin;
			}

			searchDir = path.dirname(searchDir);
		}

		// Also check if srt is directly in the package (some packages bundle their binaries)
		const sandboxRuntimeDir = path.dirname(sandboxRuntimePkg);
		const srtInPackage = path.join(sandboxRuntimeDir, "bin", "srt");
		if (fs.existsSync(srtInPackage)) {
			return srtInPackage;
		}
	} catch {
		// Package resolution failed - try other methods
	}

	// FALLBACK: Check PATH
	try {
		const result = execSync("which srt 2>/dev/null || true", { encoding: "utf-8" }).trim();
		if (result && fs.existsSync(result)) {
			return result;
		}
	} catch {
		// which failed
	}

	// FALLBACK: Check common global installation paths
	const globalPaths = [
		"/opt/homebrew/bin/srt",
		"/usr/local/bin/srt",
		path.join(os.homedir(), ".npm-global", "bin", "srt"),
	];

	for (const p of globalPaths) {
		if (fs.existsSync(p)) {
			return p;
		}
	}

	return null;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Wrapper Generation
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Generate the wrapper script content.
 *
 * The wrapper:
 * 1. Verifies SRT settings exist
 * 2. Executes the real Claude binary through srt with our settings
 * 3. Passes all arguments through
 */
function generateWrapperScript(claudePath: string, srtPath: string): string {
	return `#!/bin/bash
# Telclaude sandbox wrapper for Claude CLI
# Generated by telclaude - DO NOT EDIT MANUALLY
#
# This script runs Claude through sandbox-runtime (srt) for OS-level
# filesystem and network isolation. All Claude tools (Read, Write, Bash, etc.)
# execute inside the sandbox.

set -euo pipefail

# Settings file path
SETTINGS="${SRT_SETTINGS_PATH}"

# Verify settings exist
if [ ! -f "$SETTINGS" ]; then
    echo "Error: Telclaude sandbox settings not found at $SETTINGS" >&2
    echo "Please run 'telclaude relay' to initialize the sandbox." >&2
    exit 1
fi

# Pass through ANTHROPIC_API_KEY if set (optional - for API billing fallback)
# Claude uses Keychain OAuth tokens by default for subscription billing.
# If ANTHROPIC_API_KEY is set, Claude will use API billing instead of subscription.
if [ -n "\${ANTHROPIC_API_KEY:-}" ]; then
    export ANTHROPIC_API_KEY
fi

# Execute Claude through srt with our settings
# The --settings flag tells srt to use our custom configuration
exec "${srtPath}" --settings "$SETTINGS" "${claudePath}" "$@"
`;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SRT Settings Management
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Check if a string looks like a valid domain pattern for srt allowlists.
 *
 * This is intentionally strict: allowlists should only contain real domains
 * (with optional leading wildcard). IPs/CIDRs belong in denied lists.
 */
function isValidSrtAllowPattern(pattern: string): boolean {
	// Reject bare "*" and overly broad "*.*" (schema forbids)
	if (pattern === "*" || pattern === "*.*") return false;

	// Reject localhost variants
	if (pattern === "localhost" || pattern === "::1") {
		return false;
	}

	// Accept valid domain patterns (with optional wildcard prefix)
	return /^(\*\.)?[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+$/.test(pattern);
}

/**
 * Expand tilde (~) in paths to the actual home directory.
 * srt requires absolute paths, not tilde notation.
 */
function expandTilde(p: string): string {
	if (p.startsWith("~/")) {
		return path.join(os.homedir(), p.slice(2));
	}
	if (p === "~") {
		return os.homedir();
	}
	return p;
}

/**
 * Convert our SandboxRuntimeConfig to SRT settings file format.
 *
 * IMPORTANT: The srt CLI expects:
 * 1. Domain patterns in allowedDomains (supports wildcard prefixes like "*.example.com", NOT bare "*")
 * 2. deniedDomains follows the same domain pattern rules (no IPs/CIDRs)
 * 3. Filesystem paths must be absolute (no tildes)
 */
function configToSrtSettings(config: SandboxRuntimeConfig): object {
	const rawAllowedDomains = config.network?.allowedDomains ?? [];
	const allowAllRequested = rawAllowedDomains.includes("*");

	const diagnostic = process.env.TELCLAUDE_SANDBOX_DIAGNOSTIC === "1";

	// Diagnostic mode: don't filter domain patterns (user requested maximal allow)
	const filteredAllowed = diagnostic
		? rawAllowedDomains
		: (allowAllRequested ? DEFAULT_ALLOWED_DOMAIN_NAMES : rawAllowedDomains).filter(
				isValidSrtAllowPattern,
			);

	// Deny list: keep only domain patterns srt accepts (IPs/CIDRs are rejected by schema)
	const configDeniedDomains = config.network?.deniedDomains ?? [];
	const deniedDomains = diagnostic
		? configDeniedDomains
		: [...BLOCKED_METADATA_DOMAINS, ...BLOCKED_PRIVATE_NETWORKS, ...configDeniedDomains].filter(
				isValidSrtAllowPattern,
			);

	const allowedDomains = [...new Set(filteredAllowed)];
	const uniqueDeniedDomains = [...new Set(deniedDomains)];

	// Expand tildes in filesystem paths - srt requires absolute paths
	const denyRead = (config.filesystem?.denyRead ?? []).map(expandTilde);
	const allowWrite = (config.filesystem?.allowWrite ?? []).map(expandTilde);
	const denyWrite = (config.filesystem?.denyWrite ?? []).map(expandTilde);

	return {
		network: {
			allowedDomains,
			deniedDomains: uniqueDeniedDomains,
			allowUnixSockets: config.network?.allowUnixSockets ?? [],
			allowLocalBinding: config.network?.allowLocalBinding ?? false,
			// SECURITY: Disable arbitrary Unix socket creation via seccomp (Linux only).
			// When false, only paths in allowUnixSockets are permitted.
			allowAllUnixSockets: config.network?.allowAllUnixSockets ?? false,
		},
		filesystem: {
			denyRead,
			allowWrite,
			denyWrite,
		},
		// Allow nested sandboxing (for defense-in-depth with Bash commands)
		// but accept weaker guarantees for the inner sandbox
		enableWeakerNestedSandbox: true,
	};
}

/**
 * Write the SRT settings file based on sandbox config.
 *
 * This file is read by srt when the wrapper executes.
 * Must be called before any SDK queries and when tier changes.
 */
export function writeSrtSettings(config: SandboxRuntimeConfig): void {
	// Ensure directory exists
	const settingsDir = path.dirname(SRT_SETTINGS_PATH);
	if (!fs.existsSync(settingsDir)) {
		fs.mkdirSync(settingsDir, { recursive: true, mode: 0o700 });
	}

	const srtConfig = configToSrtSettings(config);

	fs.writeFileSync(SRT_SETTINGS_PATH, JSON.stringify(srtConfig, null, 2), {
		mode: 0o600, // Owner read/write only
	});

	logger.debug(
		{
			path: SRT_SETTINGS_PATH,
			denyRead: config.filesystem?.denyRead?.length ?? 0,
			allowWrite: config.filesystem?.allowWrite?.length ?? 0,
			allowedDomains: config.network?.allowedDomains?.length ?? 0,
		},
		"wrote SRT settings",
	);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════════════════

/** Result of wrapper initialization */
export type WrapperInitResult =
	| {
			success: true;
			wrapperPath: string;
			claudePath: string;
			srtPath: string;
	  }
	| {
			success: false;
			error: string;
	  };

/**
 * Initialize the wrapper script and settings.
 *
 * Creates:
 * 1. ~/.telclaude/bin/claude - wrapper script
 * 2. ~/.telclaude/srt-settings.json - sandbox configuration
 *
 * The wrapper is regenerated if:
 * - It doesn't exist
 * - The embedded binary paths no longer exist
 * - The binary paths have changed (e.g., after `brew upgrade claude`)
 *
 * @param config - Sandbox configuration to apply
 * @returns Result with wrapper path or error
 */
export async function initializeWrapper(config: SandboxRuntimeConfig): Promise<WrapperInitResult> {
	// Check if wrapper needs regeneration due to binary path changes
	const validation = validateWrapperPaths();
	if (validation.valid && !validation.needsRegeneration && fs.existsSync(SRT_SETTINGS_PATH)) {
		// Wrapper is valid and up-to-date, just update settings
		writeSrtSettings(config);
		const embedded = extractEmbeddedPaths();
		logger.debug("wrapper is up-to-date, skipping regeneration");
		return {
			success: true,
			wrapperPath: WRAPPER_PATH,
			claudePath: embedded?.claudePath ?? "unknown",
			srtPath: embedded?.srtPath ?? "unknown",
		};
	}

	if (validation.needsRegeneration) {
		logger.info(
			{ reason: validation.reason, currentPaths: validation.currentPaths },
			"regenerating wrapper due to binary path changes",
		);
	}

	// Find real Claude binary
	const claudePath = findClaudeBinary();
	if (!claudePath) {
		const error =
			"Could not find Claude CLI binary. Install with: brew install anthropic-ai/cli/claude";
		logger.error(error);
		return { success: false, error };
	}

	// Verify it's not pointing to ourselves (circular reference)
	const realClaudePath = fs.realpathSync(claudePath);
	// Only check for circular reference if wrapper already exists
	if (fs.existsSync(WRAPPER_PATH)) {
		const realWrapperPath = fs.realpathSync(WRAPPER_PATH);
		if (realClaudePath === WRAPPER_PATH || realClaudePath === realWrapperPath) {
			const error = "Claude binary path resolves to our wrapper - circular reference detected";
			logger.error({ claudePath, realClaudePath, wrapperPath: WRAPPER_PATH }, error);
			return { success: false, error };
		}
	} else if (realClaudePath === WRAPPER_PATH) {
		// Wrapper doesn't exist yet, but claude path equals our target wrapper path
		const error = "Claude binary path equals our wrapper path - circular reference detected";
		logger.error({ claudePath, realClaudePath, wrapperPath: WRAPPER_PATH }, error);
		return { success: false, error };
	}

	// Find srt binary
	const srtPath = findSrtBinary();
	if (!srtPath) {
		const error =
			"Could not find srt binary. It should be installed as a dependency of @anthropic-ai/sandbox-runtime";
		logger.error(error);
		return { success: false, error };
	}

	logger.info({ claudePath, srtPath }, "found binaries for sandbox wrapper");

	// Ensure bin directory exists with secure permissions
	if (!fs.existsSync(TELCLAUDE_BIN_DIR)) {
		fs.mkdirSync(TELCLAUDE_BIN_DIR, { recursive: true, mode: 0o700 });
	}

	// Write SRT settings file
	writeSrtSettings(config);

	// Generate and write wrapper script
	const wrapperScript = generateWrapperScript(claudePath, srtPath);
	fs.writeFileSync(WRAPPER_PATH, wrapperScript, { mode: 0o755 });

	logger.info({ path: WRAPPER_PATH }, "created sandbox wrapper for Claude CLI");

	return {
		success: true,
		wrapperPath: WRAPPER_PATH,
		claudePath,
		srtPath,
	};
}

/**
 * Check if the wrapper is already set up and valid.
 */
export function isWrapperInitialized(): boolean {
	return fs.existsSync(WRAPPER_PATH) && fs.existsSync(SRT_SETTINGS_PATH);
}

/**
 * Get the wrapper path if it exists.
 * Returns null if wrapper is not initialized.
 */
export function getWrapperPath(): string | null {
	if (isWrapperInitialized()) {
		return WRAPPER_PATH;
	}
	return null;
}

/**
 * Update the SRT settings (e.g., when permission tier changes).
 *
 * This is called when a user's tier changes to update the sandbox restrictions.
 */
export function updateWrapperConfig(config: SandboxRuntimeConfig): void {
	if (!isWrapperInitialized()) {
		logger.warn("cannot update wrapper config: wrapper not initialized");
		return;
	}
	writeSrtSettings(config);
}

/**
 * Remove the wrapper and settings (cleanup).
 */
export function cleanupWrapper(): void {
	try {
		if (fs.existsSync(WRAPPER_PATH)) {
			fs.unlinkSync(WRAPPER_PATH);
			logger.debug("removed wrapper script");
		}
		if (fs.existsSync(SRT_SETTINGS_PATH)) {
			fs.unlinkSync(SRT_SETTINGS_PATH);
			logger.debug("removed SRT settings");
		}
		// Remove bin directory if empty
		if (fs.existsSync(TELCLAUDE_BIN_DIR)) {
			const files = fs.readdirSync(TELCLAUDE_BIN_DIR);
			if (files.length === 0) {
				fs.rmdirSync(TELCLAUDE_BIN_DIR);
			}
		}
	} catch (err) {
		logger.warn({ error: String(err) }, "error during wrapper cleanup");
	}
}

/**
 * Verify the wrapper is functional by running a simple test.
 */
export async function verifyWrapper(): Promise<{ valid: boolean; error?: string }> {
	if (!isWrapperInitialized()) {
		return { valid: false, error: "Wrapper not initialized" };
	}

	try {
		// Try running the wrapper with --version
		// The output will be from srt wrapping claude, so we check for either
		const result = execSync(`"${WRAPPER_PATH}" --version 2>&1`, {
			encoding: "utf-8",
			timeout: 10000,
		});

		// Accept any version-like output (srt version or claude version)
		// Both indicate the wrapper is executable and producing output
		if (
			result.includes("claude") ||
			result.includes("Claude") ||
			/^\d+\.\d+\.\d+/.test(result.trim())
		) {
			return { valid: true };
		}

		return { valid: false, error: `Unexpected output: ${result.substring(0, 100)}` };
	} catch (err) {
		const error = err instanceof Error ? err.message : String(err);
		return { valid: false, error };
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Binary Path Validation
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Extract embedded binary paths from the wrapper script.
 * Returns null if wrapper doesn't exist or can't be parsed.
 */
function extractEmbeddedPaths(): { claudePath: string; srtPath: string } | null {
	if (!fs.existsSync(WRAPPER_PATH)) {
		return null;
	}

	try {
		const content = fs.readFileSync(WRAPPER_PATH, "utf-8");

		// Extract paths from the exec line: exec "srtPath" --settings "$SETTINGS" "claudePath" "$@"
		const execMatch = content.match(/exec "([^"]+)" --settings "\$SETTINGS" "([^"]+)" "\$@"/);
		if (execMatch) {
			return {
				srtPath: execMatch[1],
				claudePath: execMatch[2],
			};
		}
	} catch {
		// Parse failed
	}

	return null;
}

/**
 * Validate the wrapper script and check if regeneration is needed.
 *
 * Returns:
 * - valid: true if wrapper is functional with current binary paths
 * - needsRegeneration: true if binaries have moved and wrapper should be regenerated
 * - reason: human-readable explanation of the issue
 */
export function validateWrapperPaths(): {
	valid: boolean;
	needsRegeneration: boolean;
	reason?: string;
	currentPaths?: { claudePath: string; srtPath: string };
	embeddedPaths?: { claudePath: string; srtPath: string };
} {
	// Check if wrapper exists
	if (!fs.existsSync(WRAPPER_PATH)) {
		return { valid: false, needsRegeneration: false, reason: "Wrapper not installed" };
	}

	// Extract paths from wrapper
	const embeddedPaths = extractEmbeddedPaths();
	if (!embeddedPaths) {
		return { valid: false, needsRegeneration: true, reason: "Cannot parse wrapper script" };
	}

	// Check if embedded paths still exist
	const embeddedClaudeExists = fs.existsSync(embeddedPaths.claudePath);
	const embeddedSrtExists = fs.existsSync(embeddedPaths.srtPath);

	if (!embeddedClaudeExists || !embeddedSrtExists) {
		const missing = [];
		if (!embeddedClaudeExists) missing.push(`claude (${embeddedPaths.claudePath})`);
		if (!embeddedSrtExists) missing.push(`srt (${embeddedPaths.srtPath})`);

		// Find current paths to check if regeneration would help
		const currentClaudePath = findClaudeBinary();
		const currentSrtPath = findSrtBinary();

		if (currentClaudePath && currentSrtPath) {
			return {
				valid: false,
				needsRegeneration: true,
				reason: `Embedded paths no longer exist: ${missing.join(", ")}. New paths available.`,
				currentPaths: { claudePath: currentClaudePath, srtPath: currentSrtPath },
				embeddedPaths,
			};
		}

		return {
			valid: false,
			needsRegeneration: false,
			reason: `Embedded paths no longer exist and no replacements found: ${missing.join(", ")}`,
			embeddedPaths,
		};
	}

	// Embedded paths exist - check if current discovery would find different paths
	const currentClaudePath = findClaudeBinary();
	const currentSrtPath = findSrtBinary();

	if (currentClaudePath && currentSrtPath) {
		// Compare paths (resolve symlinks for accurate comparison)
		const embeddedClaudeReal = fs.realpathSync(embeddedPaths.claudePath);
		const embeddedSrtReal = fs.realpathSync(embeddedPaths.srtPath);
		const currentClaudeReal = fs.realpathSync(currentClaudePath);
		const currentSrtReal = fs.realpathSync(currentSrtPath);

		if (embeddedClaudeReal !== currentClaudeReal || embeddedSrtReal !== currentSrtReal) {
			// Paths differ - might want to regenerate but current wrapper is still functional
			logger.debug(
				{
					embeddedClaude: embeddedPaths.claudePath,
					currentClaude: currentClaudePath,
					embeddedSrt: embeddedPaths.srtPath,
					currentSrt: currentSrtPath,
				},
				"wrapper binary paths differ from current discovery",
			);

			return {
				valid: true, // Still functional
				needsRegeneration: true, // But should update
				reason: "Binary paths have changed since wrapper was created",
				currentPaths: { claudePath: currentClaudePath, srtPath: currentSrtPath },
				embeddedPaths,
			};
		}
	}

	// All good
	return { valid: true, needsRegeneration: false };
}

// Export paths for testing/debugging
export { WRAPPER_PATH, SRT_SETTINGS_PATH, TELCLAUDE_BIN_DIR };
