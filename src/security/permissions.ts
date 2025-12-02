/**
 * Permission tier system for controlling Claude's capabilities.
 *
 * Uses SDK allowedTools arrays instead of CLI flags.
 *
 * SECURITY NOTE ON WRITE_SAFE:
 * The WRITE_SAFE tier provides protection against *accidental* damage, NOT
 * *malicious* attacks. A user with write access can escape the sandbox by:
 * - Writing a Python/Node script that deletes files, then running it
 * - Modifying shell configs that execute on next session
 * - Using language interpreters to bypass bash restrictions
 *
 * For true isolation against malicious users, run the agent in a container
 * (Docker) or VM. WRITE_SAFE is appropriate for trusted users who might
 * accidentally run dangerous commands.
 */

import path from "node:path";
import type { PermissionTier, SecurityConfig } from "../config/config.js";
import { SENSITIVE_READ_PATHS } from "../sandbox/config.js";
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
 *
 * NOTE: WRITE_SAFE prevents accidental damage, not malicious attacks.
 * See module-level security note for details.
 */
export const TIER_DESCRIPTIONS: Record<PermissionTier, string> = {
	READ_ONLY: "Can only read files and search. No write operations allowed.",
	WRITE_SAFE:
		"Can read and write files, but cannot delete or modify permissions. Note: prevents accidental damage, not malicious attacks.",
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

	// Additional patterns for better coverage (Grok-4 review)
	// Sudo with blocked commands
	{ pattern: /\bsudo\s+rm\b/i, reason: "sudo rm" },
	{ pattern: /\bsudo\s+chmod\b/i, reason: "sudo chmod" },
	{ pattern: /\bsudo\s+chown\b/i, reason: "sudo chown" },
	{ pattern: /\bsudo\s+kill\b/i, reason: "sudo kill" },
	{ pattern: /\bsudo\s+pkill\b/i, reason: "sudo pkill" },
	{ pattern: /\bsudo\s+shutdown\b/i, reason: "sudo shutdown" },
	{ pattern: /\bsudo\s+reboot\b/i, reason: "sudo reboot" },
	{ pattern: /\bsudo\s+dd\b/i, reason: "sudo dd" },

	// Bash -c with dangerous commands
	{ pattern: /\bbash\s+-c\s+['"].*\brm\b/i, reason: "bash -c rm" },
	{ pattern: /\bsh\s+-c\s+['"].*\brm\b/i, reason: "sh -c rm" },
	{ pattern: /\bzsh\s+-c\s+['"].*\brm\b/i, reason: "zsh -c rm" },

	// Python/Ruby/Node command execution
	{
		pattern: /\bpython[23]?\s+-c\s+['"].*(?:os\.remove|os\.system|subprocess)/i,
		reason: "python code execution",
	},
	{ pattern: /\bruby\s+-e\s+['"].*(?:File\.delete|system|exec)/i, reason: "ruby code execution" },
	{
		pattern: /\bnode\s+-e\s+['"].*(?:child_process|unlink|rmSync)/i,
		reason: "node code execution",
	},

	// Perl one-liners
	{ pattern: /\bperl\s+-e\s+['"].*(?:unlink|system)/i, reason: "perl code execution" },

	// Xargs with dangerous commands
	{ pattern: /xargs\s+.*\brm\b/i, reason: "xargs rm" },
	{ pattern: /find\s+.*-exec\s+.*\brm\b/i, reason: "find -exec rm" },
	{ pattern: /find\s+.*-delete\b/i, reason: "find -delete" },
];

/**
 * Check if a command contains blocked operations for WRITE_SAFE tier.
 * Returns the reason if blocked, null if allowed.
 *
 * Uses tokenization for more reliable detection than pure regex.
 * Splits on shell operators and whitespace to find command tokens.
 */
export function containsBlockedCommand(command: string): string | null {
	// Tokenize: split by shell operators and whitespace to get individual tokens
	// This catches commands regardless of flag ordering (e.g., "rm -rf" or "rm --force -r")
	const tokens = command
		.toLowerCase()
		.split(/[\s;|&]+/)
		.filter((t) => t.length > 0);

	// Check if any token is a blocked command
	for (const token of tokens) {
		// Strip leading dashes for flag detection, but check full token for commands
		const cleanToken = token.replace(/^-+/, "");
		if (WRITE_SAFE_BLOCKED_COMMANDS.includes(token)) {
			return token;
		}
		// Also check long-form flags like --recursive that map to rm behavior
		if (cleanToken === "recursive" && tokens.includes("rm")) {
			return "rm --recursive";
		}
		if (cleanToken === "force" && tokens.includes("rm")) {
			return "rm --force";
		}
	}

	// Check dangerous patterns (these need regex for complex matching)
	for (const { pattern, reason } of DANGEROUS_PATTERNS) {
		if (pattern.test(command)) {
			return reason;
		}
	}

	return null;
}

/**
 * Sensitive paths that the agent should never access.
 * These contain secrets (TOTP, etc.) that must not be exposed.
 */
const SENSITIVE_PATH_PATTERNS = [
	/\.telclaude(\/|$)/i, // Config directory with database (with or without trailing slash)
	/telclaude\.db/i, // Database file directly
	/telclaude\.json/i, // Config file
	/totp_secrets/i, // TOTP table name in queries
	/totp\.sock/i, // TOTP socket
];

/**
 * Expand ~ to home directory for path comparison.
 */
function expandHome(p: string): string {
	if (p.startsWith("~/")) {
		return path.join(process.env.HOME ?? "", p.slice(2));
	}
	if (p === "~") {
		return process.env.HOME ?? "";
	}
	return p;
}

/**
 * Normalize a path for comparison (resolve ~, make absolute).
 */
function normalizePath(inputPath: string): string {
	const expanded = expandHome(inputPath);
	// Handle relative paths
	if (!path.isAbsolute(expanded)) {
		return path.resolve(process.cwd(), expanded);
	}
	return path.normalize(expanded);
}

/**
 * Check if a path matches any of the sensitive credential paths.
 * This includes SSH keys, cloud credentials, etc.
 * Only use for single path strings, not commands.
 */
function matchesSensitiveCredentialPath(inputPath: string): boolean {
	const normalizedInput = normalizePath(inputPath);

	for (const sensitivePath of SENSITIVE_READ_PATHS) {
		const normalizedSensitive = normalizePath(sensitivePath);
		// Check if the input path is under or equals the sensitive path
		if (
			normalizedInput === normalizedSensitive ||
			normalizedInput.startsWith(normalizedSensitive + path.sep)
		) {
			return true;
		}
	}
	return false;
}

/**
 * Build regex patterns for sensitive paths to detect them in commands.
 * Handles both ~/path and /home/user/path forms.
 */
function buildSensitivePathPatterns(): RegExp[] {
	const patterns: RegExp[] = [];
	const home = process.env.HOME ?? "/home/user";

	for (const sensitivePath of SENSITIVE_READ_PATHS) {
		// Escape special regex characters in the path
		const escaped = sensitivePath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
		// Match the path with ~ prefix
		patterns.push(new RegExp(escaped, "i"));
		// Also match with expanded home directory
		if (sensitivePath.startsWith("~/")) {
			const expandedPath = sensitivePath.replace("~", home);
			const expandedEscaped = expandedPath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
			patterns.push(new RegExp(expandedEscaped, "i"));
		}
	}

	return patterns;
}

// Pre-computed patterns for command checking (computed once at module load)
const SENSITIVE_COMMAND_PATTERNS = buildSensitivePathPatterns();

/**
 * Check if a command string references any sensitive paths.
 * Uses substring/regex matching rather than path normalization.
 */
function commandContainsSensitivePath(command: string): boolean {
	// Check against pre-computed patterns
	for (const pattern of SENSITIVE_COMMAND_PATTERNS) {
		if (pattern.test(command)) {
			return true;
		}
	}
	return false;
}

/**
 * Check if a path or command accesses sensitive data.
 * This includes telclaude internals AND system credential paths.
 */
export function isSensitivePath(pathOrCommand: string): boolean {
	// Check telclaude-specific patterns (regex-based for flexibility)
	if (SENSITIVE_PATH_PATTERNS.some((pattern) => pattern.test(pathOrCommand))) {
		return true;
	}

	// Check if the input looks like a command (contains spaces or shell operators)
	const looksLikeCommand = /[\s;|&<>]/.test(pathOrCommand);

	if (looksLikeCommand) {
		// For commands, use substring matching to find sensitive paths anywhere
		if (commandContainsSensitivePath(pathOrCommand)) {
			return true;
		}
	} else {
		// For single paths, use path normalization for accurate matching
		if (matchesSensitiveCredentialPath(pathOrCommand)) {
			return true;
		}
	}

	return false;
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
