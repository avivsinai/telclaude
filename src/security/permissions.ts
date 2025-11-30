/**
 * Permission tier system for controlling Claude's capabilities.
 *
 * Uses SDK allowedTools arrays instead of CLI flags.
 */

import type { PermissionTier, SecurityConfig } from "../config/config.js";
import { chatIdToString } from "../utils.js";
import { getIdentityLink } from "./linking.js";

/**
 * Allowed tools for each permission tier.
 */
export const TIER_TOOLS: Record<PermissionTier, string[]> = {
	READ_ONLY: ["Read", "Glob", "Grep", "WebFetch", "WebSearch"],
	WRITE_SAFE: ["Read", "Glob", "Grep", "WebFetch", "WebSearch", "Write", "Edit", "Bash"],
	FULL_ACCESS: [], // Empty = all tools allowed (with bypassPermissions)
};

/**
 * Commands blocked for WRITE_SAFE tier (Bash restrictions).
 */
export const WRITE_SAFE_BLOCKED_COMMANDS = [
	"rm",
	"rmdir",
	"mv",
	"chmod",
	"chown",
	"kill",
	"pkill",
	"killall",
	"sudo",
	"su",
	"shutdown",
	"reboot",
	"mkfs",
	"dd",
];

/**
 * Tier descriptions for display.
 */
export const TIER_DESCRIPTIONS: Record<PermissionTier, string> = {
	READ_ONLY: "Can only read files and search. No write operations allowed.",
	WRITE_SAFE: "Can read and write files, but cannot delete or modify permissions.",
	FULL_ACCESS: "Full system access with no restrictions.",
};

/**
 * Get the permission tier for a user.
 *
 * Resolution order:
 * 1. Check if the chatId has an identity link -> use linked localUserId
 * 2. Look up by raw chatId or tg:chatId prefix
 * 3. Fall back to default tier
 */
export function getUserPermissionTier(
	userId: string | number,
	securityConfig?: SecurityConfig,
): PermissionTier {
	const normalizedId = typeof userId === "number" ? String(userId) : userId;
	const numericId = typeof userId === "number" ? userId : Number.parseInt(userId, 10);
	const withPrefix = chatIdToString(userId);

	const userPerms = securityConfig?.permissions?.users;

	// 1. Check for identity link first
	if (!Number.isNaN(numericId)) {
		const link = getIdentityLink(numericId);
		if (link && userPerms) {
			// Look up by the linked localUserId
			const linkedPerms = userPerms[link.localUserId];
			if (linkedPerms) {
				return linkedPerms.tier;
			}
		}
	}

	// 2. Check user-specific permissions by chatId
	if (userPerms) {
		if (userPerms[normalizedId]) {
			return userPerms[normalizedId].tier;
		}
		if (userPerms[withPrefix]) {
			return userPerms[withPrefix].tier;
		}
	}

	// 3. Fall back to default tier
	return securityConfig?.permissions?.defaultTier ?? "READ_ONLY";
}

/**
 * Dangerous patterns beyond simple command names.
 * These patterns detect shell features that could be abused.
 */
const DANGEROUS_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
	// Global/system-wide package installs
	{ pattern: /npm\s+(?:i|install)\s+.*-g\b/i, reason: "global npm install" },
	{ pattern: /npm\s+(?:i|install)\s+.*--global\b/i, reason: "global npm install" },
	{ pattern: /pip\s+install\s+.*--system\b/i, reason: "system pip install" },
	// Shell redirects to sensitive files
	{
		pattern: />+\s*[~\/]*(\.bashrc|\.profile|\.zshrc|\.bash_profile)/i,
		reason: "redirect to shell config",
	},
	{ pattern: />+\s*\/etc\//i, reason: "redirect to /etc" },
	{ pattern: />+\s*\/usr\//i, reason: "redirect to /usr" },
	// Curl/wget piped to shell
	{ pattern: /curl\s+.*\|\s*(ba)?sh/i, reason: "curl piped to shell" },
	{ pattern: /wget\s+.*\|\s*(ba)?sh/i, reason: "wget piped to shell" },
	// Git hooks (can execute arbitrary code)
	{ pattern: /git\s+config\s+.*core\.hooksPath/i, reason: "git hooks modification" },
	{ pattern: /\.git\/hooks\//i, reason: "direct git hooks access" },
	// Environment manipulation
	{ pattern: /export\s+.*PATH=/i, reason: "PATH modification" },
	{ pattern: /export\s+.*LD_PRELOAD/i, reason: "LD_PRELOAD manipulation" },
	// Variable interpolation that could hide commands
	{ pattern: /\$\([^)]+\)/, reason: "command substitution $()" },
	{ pattern: /`[^`]+`/, reason: "backtick command substitution" },
	{ pattern: /\$\{[^}]*[;|&`][^}]*\}/, reason: "variable with embedded command" },
	// Eval and source (arbitrary code execution)
	{ pattern: /\beval\s+/i, reason: "eval command" },
	{ pattern: /\bsource\s+/i, reason: "source command" },
	{ pattern: /\.\s+[^\s]/, reason: "dot source command" },
	// Process substitution
	{ pattern: /<\([^)]+\)/, reason: "process substitution <()" },
	{ pattern: />\([^)]+\)/, reason: "process substitution >()" },
	// Cron/at for delayed execution
	{ pattern: /\bcrontab\b/i, reason: "crontab access" },
	{ pattern: /\bat\s+/i, reason: "at command scheduling" },
	// Network tools that could exfiltrate data
	{ pattern: /\bnc\s+/i, reason: "netcat" },
	{ pattern: /\bnetcat\s+/i, reason: "netcat" },
	{ pattern: /\bnmap\s+/i, reason: "nmap scan" },
];

/**
 * Check if a command contains blocked operations for WRITE_SAFE tier.
 * Returns the reason if blocked, null if allowed.
 */
export function containsBlockedCommand(command: string): string | null {
	const lowerCommand = command.toLowerCase();

	// Check simple blocked commands
	for (const blocked of WRITE_SAFE_BLOCKED_COMMANDS) {
		// Check for command at start, after &&, after ;, after |, or after whitespace
		const patterns = [
			new RegExp(`^${blocked}\\b`),
			new RegExp(`&&\\s*${blocked}\\b`),
			new RegExp(`;\\s*${blocked}\\b`),
			new RegExp(`\\|\\s*${blocked}\\b`),
			new RegExp(`\\s${blocked}\\b`),
		];
		if (patterns.some((p) => p.test(lowerCommand))) {
			return blocked;
		}
	}

	// Check dangerous patterns
	for (const { pattern, reason } of DANGEROUS_PATTERNS) {
		if (pattern.test(command)) {
			return reason;
		}
	}

	return null;
}

/**
 * Check if a user has at least the specified permission tier.
 */
export function hasMinimumTier(userTier: PermissionTier, requiredTier: PermissionTier): boolean {
	const tierOrder: PermissionTier[] = ["READ_ONLY", "WRITE_SAFE", "FULL_ACCESS"];
	return tierOrder.indexOf(userTier) >= tierOrder.indexOf(requiredTier);
}

/**
 * Format tier for display.
 */
export function formatTier(tier: PermissionTier): string {
	switch (tier) {
		case "READ_ONLY":
			return "Read Only";
		case "WRITE_SAFE":
			return "Write Safe";
		case "FULL_ACCESS":
			return "Full Access";
	}
}
