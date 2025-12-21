/**
 * SDK permission settings builder.
 *
 * Builds permission rules for @anthropic-ai/claude-agent-sdk.
 * These are passed via `--settings` per SDK invocation (no writes to ~/.claude).
 */

import os from "node:os";
import path from "node:path";

import type { PermissionTier } from "../config/config.js";
import {
	DEFAULT_WRITE_PATHS,
	DENY_WRITE_PATHS,
	PRIVATE_TMP_PATH,
	SENSITIVE_READ_PATHS,
} from "./config.js";

function uniq(values: string[]): string[] {
	return Array.from(new Set(values));
}

function expandHome(p: string): string {
	if (p.startsWith("~")) {
		return path.join(os.homedir(), p.slice(2));
	}
	return p;
}

function withGlobVariants(p: string): string[] {
	const base = expandHome(p);
	const parts = [base];
	if (!base.endsWith("/**")) {
		parts.push(path.join(base, "**"));
	}
	return parts;
}

/**
 * Build Claude Code permission rules for @anthropic-ai/claude-agent-sdk.
 *
 * Network enforcement model:
 * - Bash: SDK sandbox `allowedDomains` provides OS-level enforcement (strict allowlist always)
 * - WebFetch/WebSearch: canUseTool callback provides enforcement (respects permissive mode)
 *
 * Note: SDK permission rules like `Network(domain:...)` or `WebFetch(domain:...)` are NOT used
 * because the SDK's domain matcher doesn't support wildcards we need for permissive mode.
 * All WebFetch/WebSearch domain filtering is done in canUseTool for consistency.
 *
 * @param tier - Permission tier for the user
 * @param _additionalDomains - Extra domains (used by sandbox config, not permissions)
 */
export function buildSdkPermissionsForTier(
	tier: PermissionTier,
	_additionalDomains: string[] = [],
): {
	allow: string[];
	deny: string[];
} {
	const allowWrite: string[] = [];
	if (tier !== "READ_ONLY") {
		// Allow writing to the SDK CWD (workspace) for WRITE_LOCAL/FULL_ACCESS.
		// `Write(.)` is interpreted relative to the Claude Code process cwd.
		allowWrite.push("Write(.)");
	}

	allowWrite.push(
		...DEFAULT_WRITE_PATHS.flatMap((p) => withGlobVariants(p).map((v) => `Write(${v})`)),
		...withGlobVariants(PRIVATE_TMP_PATH).map((p) => `Write(${p})`),
	);

	const denyRead = SENSITIVE_READ_PATHS.flatMap((p) =>
		withGlobVariants(p).map((v) => `Read(${v})`),
	);
	const denyWrite = DENY_WRITE_PATHS.flatMap((p) => withGlobVariants(p).map((v) => `Write(${v})`));

	// Network rules are NOT included here - see docstring above
	// WebFetch/WebSearch domain filtering is done in canUseTool (src/sdk/client.ts)
	// Bash network filtering is done by SDK sandbox allowedDomains

	return {
		allow: uniq([...allowWrite]),
		deny: uniq([...denyRead, ...denyWrite]),
	};
}
