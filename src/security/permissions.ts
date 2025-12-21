/**
 * Permission tier system for controlling Claude's capabilities.
 *
 * Uses SDK allowedTools arrays instead of CLI flags.
 *
 * SECURITY NOTE ON WRITE_LOCAL:
 * The WRITE_LOCAL tier provides protection against *accidental* damage, NOT
 * *malicious* attacks. A user with write access can escape the sandbox by:
 * - Writing a Python/Node script that deletes files, then running it
 * - Modifying shell configs that execute on next session
 * - Using language interpreters to bypass bash restrictions
 *
 * For true isolation against malicious users, run the agent in a container
 * (Docker) or VM. WRITE_LOCAL is appropriate for trusted users who might
 * accidentally run dangerous commands.
 */

import path from "node:path";
import { parse as shellParse } from "shell-quote";
import type { PermissionTier, SecurityConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { SENSITIVE_READ_PATHS } from "../sandbox/config.js";
import { isSandboxInitialized } from "../sandbox/index.js";
import { chatIdToString } from "../utils.js";
import { getIdentityLink } from "./linking.js";

const logger = getChildLogger({ module: "permissions" });

/**
 * Allowed tools for each permission tier.
 */
export const TIER_TOOLS: Record<PermissionTier, string[]> = {
	READ_ONLY: ["Read", "Glob", "Grep", "WebFetch", "WebSearch"],
	WRITE_LOCAL: ["Read", "Glob", "Grep", "WebFetch", "WebSearch", "Write", "Edit", "Bash"],
	FULL_ACCESS: [], // Empty = all tools allowed (still sandboxed + canUseTool guards)
};

/**
 * Commands blocked for WRITE_LOCAL tier (Bash restrictions).
 */
export const WRITE_LOCAL_BLOCKED_COMMANDS = [
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
 * NOTE: WRITE_LOCAL prevents accidental damage, not malicious attacks.
 * See module-level security note for details.
 */
export const TIER_DESCRIPTIONS: Record<PermissionTier, string> = {
	READ_ONLY: "Can only read files and search. No write operations allowed.",
	WRITE_LOCAL:
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
 *
 * Security: FULL_ACCESS requires the OS sandbox. Relay startup already fails
 * if sandboxing is unavailable; this runtime check is a last-resort safety net
 * and will log+degrade if somehow reached.
 */
export function getUserPermissionTier(
	userId: string | number,
	securityConfig?: SecurityConfig,
): PermissionTier {
	const normalizedId = typeof userId === "number" ? String(userId) : userId;
	const numericId = typeof userId === "number" ? userId : Number.parseInt(userId, 10);
	const withPrefix = chatIdToString(userId);

	const userPerms = securityConfig?.permissions?.users;

	let tier: PermissionTier | undefined;

	// 1. Check for identity link first
	if (!Number.isNaN(numericId)) {
		const link = getIdentityLink(numericId);
		if (link) {
			// ADMIN: The admin claim flow uses "admin" as the localUserId.
			// Grant FULL_ACCESS automatically for claimed admins.
			if (link.localUserId === "admin") {
				tier = "FULL_ACCESS";
			} else if (userPerms) {
				// Look up by the linked localUserId
				const linkedPerms = userPerms[link.localUserId];
				if (linkedPerms) {
					tier = linkedPerms.tier;
				}
			}
		}
	}

	// 2. Check user-specific permissions by chatId
	if (tier === undefined && userPerms) {
		if (userPerms[normalizedId]) {
			tier = userPerms[normalizedId].tier;
		} else if (userPerms[withPrefix]) {
			tier = userPerms[withPrefix].tier;
		}
	}

	// 3. Fall back to default tier
	if (tier === undefined) {
		tier = securityConfig?.permissions?.defaultTier ?? "READ_ONLY";
	}

	// Note: Sandbox is now mandatory at relay startup (fail-fast).
	// This check remains as a safety net in case of edge cases.
	if (tier === "FULL_ACCESS" && !isSandboxInitialized()) {
		logger.error(
			{ userId: normalizedId, originalTier: tier },
			"FULL_ACCESS denied: sandbox not initialized (this should not happen)",
		);
		return "WRITE_LOCAL";
	}

	return tier;
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
 * Check if a command contains blocked operations for WRITE_LOCAL tier.
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
		if (WRITE_LOCAL_BLOCKED_COMMANDS.includes(token)) {
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
 *
 * NOTE: These are regex patterns checked against the FULL path string.
 * They complement matchesSensitiveCredentialPath() which does prefix-based
 * directory matching (e.g., ~/.ssh/*, ~/.aws/*). These patterns catch
 * individual secret FILES that can appear anywhere in the filesystem.
 *
 * SECURITY: This is a critical policy layer. Even when the sandbox is
 * unavailable or the layer fails, these patterns block tool access
 * to sensitive files.
 */
const SENSITIVE_PATH_PATTERNS: RegExp[] = [
	// === Telclaude internals ===
	/\.telclaude(\/|$)/i, // Config directory with database (with or without trailing slash)
	/telclaude\.db/i, // Database file directly
	/telclaude\.json/i, // Config file
	/totp_secrets/i, // TOTP table name in queries
	/totp\.sock/i, // TOTP socket

	// === Claude Code settings (prevent hook bypass via disableAllHooks) ===
	// SECURITY: Blocking writes to these prevents prompt injection from setting
	// disableAllHooks: true, which would disable our PreToolUse security hook.
	/(?:^|[/\\])\.claude[/\\]settings(?:\.local)?\.json$/i, // .claude/settings.json, .claude/settings.local.json

	// === Environment files (secrets!) ===
	// Match .env anywhere in path (but not .environment or similar)
	/[/\\]\.env$/i, // Exact .env file
	/[/\\]\.env\.[^/\\]+$/i, // .env.local, .env.production, .env.development, etc.
	/[/\\]\.envrc$/i, // direnv config

	// === Secret files ===
	/[/\\]secrets\.(json|ya?ml)$/i, // secrets.json, secrets.yaml, secrets.yml
	/[/\\]credentials\.json$/i, // GCP service account key
	/[/\\]service[-_]?account\.json$/i, // Service account keys

	// === SSH/Private keys ===
	/[/\\]id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/i, // SSH key files
	/[/\\]authorized_keys$/i,
	/[/\\]known_hosts$/i,
	/\.pem$/i, // PEM certificates/keys
	/\.key$/i, // Generic private keys
	/\.ppk$/i, // PuTTY private keys

	// === Package manager auth ===
	/[/\\]\.npmrc$/i, // npm auth tokens
	/[/\\]\.pypirc$/i, // PyPI credentials
	/[/\\]\.netrc$/i, // Various service credentials
	/[/\\]\.git-credentials$/i, // Git credential storage

	// === Cloud provider configs ===
	/[/\\]kubeconfig$/i, // Kubernetes config
];

/**
 * Basename-only checks (catch relative paths like ".env" that lack separators).
 * These complement SENSITIVE_PATH_PATTERNS which expect a slash.
 */
const SENSITIVE_BASENAME_PATTERNS: RegExp[] = [
	/^\.env(\..+)?$/i, // .env, .env.local, etc.
	/^\.envrc$/i,
	/^secrets\.(json|ya?ml)$/i,
	/^(credentials|service[-_]?account)\.json$/i,
	/^id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/i,
	/^authorized_keys$/i,
	/^known_hosts$/i,
	/\.pem$/i,
	/\.key$/i,
	/\.ppk$/i,
	// NOTE: settings.json and settings.local.json are NOT blocked globally.
	// They're protected via detectClaudeSettingsBypass() which catches
	// "cd .claude && cat settings.json" patterns without blocking legitimate
	// settings.json files in other directories.
];

function isSensitiveBasename(name: string): boolean {
	return SENSITIVE_BASENAME_PATTERNS.some((pattern) => pattern.test(name));
}

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

	// Basename-only fallback for patterns that don't include separators (e.g., ".env")
	if (isSensitiveBasename(path.basename(normalizedInput))) {
		return true;
	}

	return false;
}

/**
 * Heuristic: determine if a token could represent a filesystem path.
 */
function looksLikePath(token: string): boolean {
	return (
		token.startsWith("~") ||
		token.startsWith("/") ||
		token.startsWith(".") ||
		token.includes("/") ||
		token.includes("\\") ||
		token.includes(path.sep)
	);
}

function looksLikeUrl(token: string): boolean {
	return /^[a-zA-Z][a-zA-Z+.-]*:\/\//.test(token);
}

function stripPathSuffix(token: string): string {
	if (looksLikeUrl(token)) {
		return token;
	}
	let cleaned = token.replace(/(?::\d+){1,2}$/i, "");
	cleaned = cleaned.replace(/#l?\d+(?::\d+)?$/i, "");
	return cleaned;
}

/**
 * Expand home-like prefixes in a token for accurate path comparison.
 */
function expandHomeLike(token: string): string {
	if (token.startsWith("~/")) {
		return path.join(process.env.HOME ?? "", token.slice(2));
	}
	if (token === "~") {
		return process.env.HOME ?? token;
	}
	if (token.startsWith("$HOME/")) {
		return path.join(process.env.HOME ?? "", token.slice("$HOME/".length));
	}
	if (token.startsWith("${HOME}/")) {
		return path.join(process.env.HOME ?? "", token.slice("${HOME}/".length));
	}
	return token;
}

function normalizePathToken(token: string): string {
	const expanded = expandHomeLike(token);
	if (looksLikeUrl(expanded)) {
		return expanded;
	}
	const withoutSuffix = stripPathSuffix(expanded);
	return path.normalize(withoutSuffix);
}

function normalizeGlobPattern(pattern: string): string {
	// Replace simple character classes with single-char wildcards
	return pattern.replace(/\[[^\]]*]/g, "?");
}

function parseEnvAssignment(token: string): { name: string; value: string } | null {
	if (!/^[A-Za-z_][A-Za-z0-9_]*=/.test(token)) {
		return null;
	}
	const eqIndex = token.indexOf("=");
	if (eqIndex <= 0) return null;
	const name = token.slice(0, eqIndex);
	const value = token.slice(eqIndex + 1);
	return { name, value };
}

function resolveEnvVars(token: string, env: Map<string, string>): string {
	return token.replace(/\$(\w+)|\$\{([^}]+)\}/g, (match, var1, var2) => {
		const name = (var1 ?? var2) as string | undefined;
		if (!name) return match;
		const value = env.get(name);
		return value !== undefined ? value : match;
	});
}

function expandBracePatterns(pattern: string): string[] {
	const braceMatch = pattern.match(/\{([^}]+)\}/);
	if (!braceMatch) {
		return [pattern];
	}
	const [full, inner] = braceMatch;
	const parts = inner.split(",").map((part) => part.trim());
	const expanded: string[] = [];
	for (const part of parts) {
		const replaced = pattern.replace(full, part);
		for (const next of expandBracePatterns(replaced)) {
			expanded.push(next);
		}
	}
	return expanded;
}

function wildcardMatch(pattern: string, text: string): boolean {
	const normalizedPattern = pattern.toLowerCase();
	const normalizedText = text.toLowerCase();
	let p = 0;
	let t = 0;
	let starIdx = -1;
	let matchIdx = 0;

	while (t < normalizedText.length) {
		if (p < normalizedPattern.length) {
			const ch = normalizedPattern[p];
			if (ch === "?" || ch === normalizedText[t]) {
				p++;
				t++;
				continue;
			}
			if (ch === "*") {
				starIdx = p;
				matchIdx = t;
				p++;
				continue;
			}
		}

		if (starIdx !== -1) {
			p = starIdx + 1;
			matchIdx += 1;
			t = matchIdx;
			continue;
		}
		return false;
	}

	while (p < normalizedPattern.length && normalizedPattern[p] === "*") {
		p++;
	}

	return p === normalizedPattern.length;
}

function globCouldMatchClaudeSettings(pattern: string): boolean {
	const normalizedPattern = normalizeGlobPattern(pattern);
	const expandedPatterns = expandBracePatterns(normalizedPattern);
	const candidates = [
		"settings.json",
		"settings.local.json",
		"./settings.json",
		"./settings.local.json",
		"../settings.json",
		"../settings.local.json",
		".claude/settings.json",
		".claude/settings.local.json",
	];
	return expandedPatterns.some((expanded) =>
		candidates.some((candidate) => wildcardMatch(expanded, candidate)),
	);
}
/**
 * Detect "cd .claude && cat settings.json" bypass attempts.
 * Returns true if the command changes to a .claude directory AND accesses
 * settings.json or settings.local.json (bare, relative, or editor-suffixed).
 *
 * This is more targeted than blocking all settings.json files, which would
 * break many legitimate projects.
 *
 * Handles variants like:
 * - cd .claude && cat settings.json
 * - cd -P .claude && cat ./settings.json
 * - cd -- .claude && echo foo > settings.local.json
 * - cd .claude && cat $PWD/settings.json
 * - cd .claude && code settings.json:10:3
 */
function detectClaudeSettingsBypass(tokens: Array<string | { op: string }>): boolean {
	const settingsPattern = /^(?:\.\.?[/\\])?settings(?:\.local)?\.json$/i;
	const settingsPwdPattern =
		/^(?:\$\{?PWD\}?|\$\(pwd\)|`pwd`)[/\\](?:\.\.?[/\\])?settings(?:\.local)?\.json$/i;
	const claudePathPattern = /(?:^|[/\\])\.claude(?:[/\\]|$)/i;
	const commandSeparators = new Set([";", "&&", "||", "|", "|&", "\n"]);
	const controlKeywords = new Set([
		"if",
		"then",
		"elif",
		"else",
		"fi",
		"do",
		"done",
		"while",
		"until",
		"for",
		"case",
		"esac",
		"select",
		"function",
		"{",
		"}",
	]);
	const envValues = new Map<string, string>();

	const isSeparator = (token: string | { op: string }): boolean => {
		if (typeof token !== "string") {
			return commandSeparators.has(token.op);
		}
		return commandSeparators.has(token);
	};

	const isEnvAssignment = (token: string): boolean => /^[A-Za-z_][A-Za-z0-9_]*=/.test(token);

	const findCdTarget = (startIndex: number): { target?: string; nextIndex: number } => {
		for (let i = startIndex; i < tokens.length; i++) {
			const candidate = tokens[i];
			if (typeof candidate !== "string") {
				return { nextIndex: i - 1 };
			}
			if (candidate === "--") {
				const next = tokens[i + 1];
				if (typeof next === "string") {
					return { target: next, nextIndex: i + 1 };
				}
				return { nextIndex: i };
			}
			if (candidate.startsWith("-")) {
				continue;
			}
			return { target: candidate, nextIndex: i };
		}
		return { nextIndex: tokens.length - 1 };
	};

	let inClaudeDir = false;
	let atCommandStart = true;

	for (let i = 0; i < tokens.length; i++) {
		const token = tokens[i];
		if (isSeparator(token)) {
			atCommandStart = true;
			continue;
		}
		const tokenValue =
			typeof token === "string"
				? token
				: token.op === "glob"
					? ((token as { op: string; pattern?: string }).pattern ?? "")
					: "";
		if (!tokenValue) {
			continue;
		}

		const tokenLower = tokenValue.toLowerCase();
		if (atCommandStart && controlKeywords.has(tokenLower)) {
			continue;
		}
		if (atCommandStart && isEnvAssignment(tokenValue)) {
			const assignment = parseEnvAssignment(tokenValue);
			if (assignment) {
				envValues.set(assignment.name, assignment.value);
			}
			continue;
		}

		if (atCommandStart && tokenLower === "export") {
			for (let j = i + 1; j < tokens.length; j++) {
				if (isSeparator(tokens[j])) {
					i = j - 1;
					break;
				}
				const tok = tokens[j];
				let exportToken: string;
				if (typeof tok === "string") {
					exportToken = tok;
				} else if (tok.op === "glob") {
					exportToken = (tok as { op: string; pattern?: string }).pattern ?? "";
				} else {
					continue;
				}
				if (!exportToken) {
					continue;
				}
				const assignment = parseEnvAssignment(exportToken);
				if (assignment) {
					envValues.set(assignment.name, assignment.value);
				}
			}
			atCommandStart = false;
			continue;
		}

		if (atCommandStart && (tokenLower === "cd" || tokenLower === "pushd")) {
			const { target, nextIndex } = findCdTarget(i + 1);
			if (target) {
				const resolvedTarget = resolveEnvVars(target, envValues);
				const normalizedTarget = normalizePathToken(resolvedTarget);
				if (claudePathPattern.test(normalizedTarget) || normalizedTarget === ".claude") {
					inClaudeDir = true;
				} else {
					inClaudeDir = false;
				}
			}
			atCommandStart = false;
			i = Math.max(i, nextIndex);
			continue;
		}

		atCommandStart = false;

		if (inClaudeDir) {
			const resolvedToken = resolveEnvVars(tokenValue, envValues);
			const normalizedToken = normalizePathToken(resolvedToken);
			if (settingsPattern.test(normalizedToken) || settingsPwdPattern.test(resolvedToken)) {
				return true;
			}
			if (/[?*[\]{]/.test(normalizedToken) && globCouldMatchClaudeSettings(normalizedToken)) {
				return true;
			}
		}
	}

	return false;
}

/**
 * Check if a command string references any sensitive paths.
 * Uses shell-style tokenization to avoid brittle whitespace parsing.
 */
function commandContainsSensitivePath(command: string): boolean {
	let tokens: Array<string | { op: string }>;
	const normalizedCommand = command
		.replace(/\r?\n/g, ";")
		.replace(/\$\(\s*pwd\s*\)/gi, "$PWD")
		.replace(/`\s*pwd\s*`/gi, "$PWD");
	try {
		// Keep variables unexpanded by returning them as-is
		const keepVars = (key: string): string => `$${key}`;
		tokens = (
			shellParse as (cmd: string, env: (k: string) => string) => Array<string | { op: string }>
		)(normalizedCommand, keepVars);
	} catch {
		// Fallback to simple split if parsing fails
		tokens = normalizedCommand.split(/\s+/).filter((t) => t.length > 0);
	}

	// SECURITY: Detect "cd .claude && cat settings.json" bypass attempts.
	// This catches commands that cd to .claude and access settings.json,
	// without blocking legitimate settings.json files in other directories.
	if (detectClaudeSettingsBypass(tokens)) {
		return true;
	}

	for (const token of tokens) {
		const tokenValue =
			typeof token === "string"
				? token
				: token.op === "glob"
					? ((token as { op: string; pattern?: string }).pattern ?? "")
					: "";
		if (!tokenValue) continue;

		// Check basename patterns for bare filenames (e.g., ".env", "secrets.json").
		if (isSensitiveBasename(tokenValue)) {
			return true;
		}

		// For path-like tokens, do additional checks
		if (!looksLikePath(tokenValue)) continue;

		const expanded = expandHomeLike(tokenValue);
		const normalized = normalizePathToken(tokenValue);

		// Check telclaude-specific sensitive patterns on both raw and expanded
		if (
			SENSITIVE_PATH_PATTERNS.some(
				(pattern) => pattern.test(tokenValue) || pattern.test(expanded) || pattern.test(normalized),
			)
		) {
			return true;
		}

		// Check credential roots
		if (!looksLikeUrl(expanded) && matchesSensitiveCredentialPath(expanded)) {
			return true;
		}

		// Basename-only detection for path-like tokens (e.g., "./settings.json")
		if (isSensitiveBasename(path.basename(normalized))) {
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
	const normalized = normalizePathToken(pathOrCommand);
	// Check telclaude-specific patterns (regex-based for flexibility)
	if (
		SENSITIVE_PATH_PATTERNS.some(
			(pattern) => pattern.test(pathOrCommand) || pattern.test(normalized),
		)
	) {
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
	const tierOrder: PermissionTier[] = ["READ_ONLY", "WRITE_LOCAL", "FULL_ACCESS"];
	return tierOrder.indexOf(userTier) >= tierOrder.indexOf(requiredTier);
}

/**
 * Format tier for display.
 */
export function formatTier(tier: PermissionTier): string {
	switch (tier) {
		case "READ_ONLY":
			return "Read Only";
		case "WRITE_LOCAL":
			return "Write Local";
		case "FULL_ACCESS":
			return "Full Access";
	}
}
