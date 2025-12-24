/**
 * SDK permission settings builder.
 *
 * Builds permission rules for @anthropic-ai/claude-agent-sdk.
 * These are passed via `--settings` per SDK invocation.
 */

import os from "node:os";
import path from "node:path";

import type { PermissionTier } from "../config/config.js";
import { DENY_WRITE_PATHS, SENSITIVE_READ_PATHS } from "./config.js";

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
 * Filesystem isolation is handled by:
 * - Docker mode: Container filesystem isolation
 * - Native mode: SDK sandbox (bubblewrap/Seatbelt)
 *
 * These permission rules provide defense-in-depth via canUseTool callback.
 *
 * @param tier - Permission tier for the user
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
		// Allow writing to the SDK CWD (workspace) for WRITE_LOCAL/FULL_ACCESS
		allowWrite.push("Write(.)");
	}

	const denyRead = SENSITIVE_READ_PATHS.flatMap((p: string) =>
		withGlobVariants(p).map((v) => `Read(${v})`),
	);
	const denyWrite = DENY_WRITE_PATHS.flatMap((p: string) =>
		withGlobVariants(p).map((v) => `Write(${v})`),
	);

	return {
		allow: uniq([...allowWrite]),
		deny: uniq([...denyRead, ...denyWrite]),
	};
}
