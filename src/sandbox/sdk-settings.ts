import os from "node:os";
import path from "node:path";

import type { PermissionTier } from "../config/config.js";
import {
	BLOCKED_METADATA_DOMAINS,
	BLOCKED_PRIVATE_NETWORKS,
	DEFAULT_WRITE_PATHS,
	DENY_WRITE_PATHS,
	PRIVATE_TMP_PATH,
	SENSITIVE_READ_PATHS,
} from "./config.js";
import { DEFAULT_ALLOWED_DOMAIN_NAMES } from "./domains.js";

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
 * Telclaude passes these rules via `--settings` per SDK invocation (no writes to ~/.claude).
 * Rules are used by Claude Code to configure its built-in sandbox policy.
 */
export function buildSdkPermissionsForTier(tier: PermissionTier): {
	allow: string[];
	deny: string[];
} {
	const allowWrite: string[] = [];
	if (tier !== "READ_ONLY") {
		// Allow writing to the SDK CWD (workspace) for WRITE_SAFE/FULL_ACCESS.
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

	const allowNetwork = DEFAULT_ALLOWED_DOMAIN_NAMES.map((d) => `Network(domain:${d})`);
	const denyNetwork = [...BLOCKED_METADATA_DOMAINS, ...BLOCKED_PRIVATE_NETWORKS].map(
		(d) => `Network(domain:${d})`,
	);

	return {
		allow: uniq([...allowWrite, ...allowNetwork]),
		deny: uniq([...denyRead, ...denyWrite, ...denyNetwork]),
	};
}
