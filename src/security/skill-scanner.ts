/**
 * Static code scanner for skill files (SKILL.md and bundled resources).
 *
 * Detects malicious patterns in skill definitions before activation:
 * - Dangerous shell execution directives
 * - eval() and dynamic code execution
 * - Crypto-mining indicators
 * - Data exfiltration patterns
 * - Obfuscation techniques
 * - Environment variable harvesting
 * - Path traversal (../../)
 * - Auto-install directives (OpenClaw-specific)
 *
 * Designed to run both at import time (A1) and promotion time (A2),
 * and as part of `telclaude doctor --skills`.
 */

import fs from "node:fs";
import path from "node:path";
import { getChildLogger } from "../logging.js";
import { PROMPT_INJECTION_PATTERNS } from "./shared-patterns.js";

const logger = getChildLogger({ module: "skill-scanner" });

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

export type ScanSeverity = "critical" | "high" | "medium" | "info";

export type ScanFinding = {
	/** Rule that triggered. */
	rule: string;
	/** Human-readable description. */
	message: string;
	/** Severity level. */
	severity: ScanSeverity;
	/** File where the finding occurred (relative to skill root). */
	file: string;
	/** Line number (1-based), if applicable. */
	line?: number;
	/** The matched content (truncated for display). */
	match?: string;
};

export type ScanResult = {
	/** Skill name (directory name). */
	skillName: string;
	/** Absolute path to skill directory. */
	skillPath: string;
	/** All findings. */
	findings: ScanFinding[];
	/** Whether the skill should be blocked (has critical/high findings). */
	blocked: boolean;
	/** Summary counts by severity. */
	counts: Record<ScanSeverity, number>;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Pattern Definitions
// ═══════════════════════════════════════════════════════════════════════════════

type ScanPattern = {
	rule: string;
	pattern: RegExp;
	message: string;
	severity: ScanSeverity;
	/** Only apply to specific file types (by extension). */
	fileTypes?: string[];
};

const CONTENT_PATTERNS: ScanPattern[] = [
	// === Dangerous execution ===
	{
		rule: "dangerous-exec",
		pattern: /\b(?:exec|execSync|spawn|spawnSync|fork)\s*\(/gi,
		message: "Direct process execution function call",
		severity: "critical",
		fileTypes: [".js", ".ts", ".mjs", ".cjs"],
	},
	{
		rule: "shell-exec-directive",
		pattern:
			/```(?:bash|sh|shell|zsh)\s*\n[^`]*(?:curl|wget|pip install|npm install|brew install|go install|cargo install)[^`]*```/gis,
		message: "Shell execution with network install commands in code block",
		severity: "high",
	},
	{
		rule: "auto-install",
		pattern: /\b(?:auto[_-]?install|install[_-]?deps|setup[_-]?script)\s*:/gi,
		message: "Auto-install directive (must be manually approved)",
		severity: "high",
	},

	// === eval and dynamic code ===
	{
		rule: "eval-usage",
		pattern: /\beval\s*\(/gi,
		message: "eval() usage — dynamic code execution",
		severity: "critical",
		fileTypes: [".js", ".ts", ".mjs", ".cjs"],
	},
	{
		rule: "function-constructor",
		pattern: /new\s+Function\s*\(/gi,
		message: "Function constructor — dynamic code execution",
		severity: "critical",
		fileTypes: [".js", ".ts", ".mjs", ".cjs"],
	},
	{
		rule: "dynamic-import",
		pattern: /import\s*\(\s*[^"'`\s]/gi,
		message: "Dynamic import with variable — potential code injection",
		severity: "high",
		fileTypes: [".js", ".ts", ".mjs", ".cjs"],
	},

	// === Crypto mining ===
	{
		rule: "crypto-mining",
		pattern: /\b(?:coinhive|cryptonight|monero|xmr[_-]?mine|stratum\+tcp|mining[_-]?pool)\b/gi,
		message: "Crypto-mining indicator",
		severity: "critical",
	},
	{
		rule: "crypto-mining-wasm",
		pattern: /\b(?:wasm[_-]?miner|webassembly.*(?:mine|hash)|cryptonight\.wasm)\b/gi,
		message: "WebAssembly crypto-mining indicator",
		severity: "critical",
	},

	// === Data exfiltration ===
	{
		rule: "exfil-fetch",
		pattern: /fetch\s*\(\s*['"`]https?:\/\/[^'"` ]*\b(?:webhook|hook|exfil|leak|collect|log)\b/gi,
		message: "Suspicious fetch to potential exfiltration endpoint",
		severity: "high",
		fileTypes: [".js", ".ts", ".mjs", ".cjs"],
	},
	{
		rule: "exfil-curl",
		pattern: /curl\s+.*--data.*\$\{?(?:HOME|USER|PATH|TOKEN|KEY|SECRET|PASSWORD)/gi,
		message: "curl sending environment/credential data",
		severity: "critical",
	},
	{
		rule: "exfil-base64-env",
		pattern: /(?:btoa|Buffer\.from|base64)\s*\(.*(?:process\.env|env\[|ENV\[)/gi,
		message: "Base64-encoding environment variables (exfiltration prep)",
		severity: "critical",
		fileTypes: [".js", ".ts", ".mjs", ".cjs"],
	},

	// === Environment harvesting ===
	{
		rule: "env-harvesting",
		pattern:
			/(?:Object\.(?:keys|entries|values)\s*\(\s*process\.env|JSON\.stringify\s*\(\s*process\.env|for\s*\(\s*(?:let|const|var)\s+\w+\s+(?:in|of)\s+process\.env)/gi,
		message: "Bulk environment variable access (harvesting)",
		severity: "critical",
		fileTypes: [".js", ".ts", ".mjs", ".cjs"],
	},
	{
		rule: "env-specific-secrets",
		pattern:
			/process\.env\s*\[\s*['"`](?:TELEGRAM_BOT_TOKEN|ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET|GITHUB_TOKEN|GH_TOKEN)['"`]\s*\]/gi,
		message: "Direct access to known secret environment variables",
		severity: "high",
		fileTypes: [".js", ".ts", ".mjs", ".cjs"],
	},

	// === Obfuscation ===
	{
		rule: "obfuscation-char-codes",
		pattern: /String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){4,}/gi,
		message: "String.fromCharCode with many arguments (obfuscation)",
		severity: "high",
		fileTypes: [".js", ".ts", ".mjs", ".cjs"],
	},
	{
		rule: "obfuscation-hex-string",
		pattern: /\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){10,}/gi,
		message: "Long hex-escaped string (obfuscation)",
		severity: "high",
	},
	{
		rule: "obfuscation-unicode-escape",
		pattern: /\\u[0-9a-f]{4}(?:\\u[0-9a-f]{4}){10,}/gi,
		message: "Long unicode-escaped string (obfuscation)",
		severity: "high",
	},
	{
		rule: "obfuscation-atob",
		pattern: /atob\s*\(\s*['"`][A-Za-z0-9+/=]{20,}['"`]\s*\)/gi,
		message: "Base64 decode of encoded payload (obfuscation)",
		severity: "high",
		fileTypes: [".js", ".ts", ".mjs", ".cjs"],
	},

	// === Network backdoors ===
	{
		rule: "reverse-shell",
		pattern: /\b(?:reverse[_-]?shell|bind[_-]?shell|nc\s+-[el]|netcat\s+-[el])\b/gi,
		message: "Reverse/bind shell indicator",
		severity: "critical",
	},
	{
		rule: "websocket-backdoor",
		pattern: /new\s+WebSocket\s*\(\s*['"`]wss?:\/\//gi,
		message: "WebSocket connection — potential C2 channel",
		severity: "medium",
		fileTypes: [".js", ".ts", ".mjs", ".cjs"],
	},

	// === File system abuse ===
	{
		rule: "fs-write-sensitive",
		pattern:
			/(?:writeFile|appendFile|createWriteStream)\s*\(\s*['"`].*(?:\.ssh|\.aws|\.env|\.bashrc|\.profile|crontab)/gi,
		message: "Writing to sensitive system paths",
		severity: "critical",
		fileTypes: [".js", ".ts", ".mjs", ".cjs"],
	},
	{
		rule: "chmod-suid",
		pattern: /chmod\s+[24]?[0-7]{3}\s|chmod\s+[ug]\+s\b/gi,
		message: "chmod with setuid/setgid or broad permissions",
		severity: "high",
	},

	// === Prompt injection in skill definitions (from shared patterns) ===
	...PROMPT_INJECTION_PATTERNS.filter(
		(p) => p.severity === "critical" || p.severity === "high",
	).map((p) => ({
		rule: `prompt-injection-${p.name}`,
		pattern: p.regex,
		message: `Prompt injection pattern: ${p.name}`,
		severity: "high" as const,
	})),
];

/**
 * Path-level patterns checked against file references and paths within skills.
 */
const PATH_PATTERNS: ScanPattern[] = [
	{
		rule: "path-traversal",
		pattern: /(?:^|[/\\])\.\.(?:[/\\]|$)/g,
		message: "Path traversal detected (../)",
		severity: "critical",
	},
	{
		rule: "absolute-path-escape",
		pattern: /(?:^|['"`\s])\/(?:etc|usr|var|tmp|root|home)(?:\/|['"`\s]|$)/g,
		message: "Absolute path to system directory",
		severity: "high",
	},
	{
		rule: "home-tilde-escape",
		pattern: /~\/\./g,
		message: "Home directory dotfile access",
		severity: "medium",
	},
];

// ═══════════════════════════════════════════════════════════════════════════════
// Frontmatter Validation
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Parse YAML-like frontmatter from SKILL.md.
 * Simple parser — handles key: value pairs and basic indentation.
 */
function parseFrontmatter(content: string): Record<string, unknown> | null {
	const frontmatterMatch = content.match(/^---\s*\n([\s\S]*?)\n---/);
	if (!frontmatterMatch) return null;

	const lines = frontmatterMatch[1].split("\n");
	const result: Record<string, string> = {};

	for (const line of lines) {
		const match = line.match(/^(\w[\w.-]*)\s*:\s*(.*)$/);
		if (match) {
			result[match[1]] = match[2].trim();
		}
	}

	return result;
}

/**
 * Validate skill frontmatter for required fields and suspicious values.
 */
function validateFrontmatter(content: string, filename: string): ScanFinding[] {
	const findings: ScanFinding[] = [];
	const frontmatter = parseFrontmatter(content);

	if (!frontmatter) {
		findings.push({
			rule: "missing-frontmatter",
			message: "Skill file missing YAML frontmatter (---...---)",
			severity: "info",
			file: filename,
		});
		return findings;
	}

	// Check for dangerous allowed-tools
	const allowedTools = String(frontmatter["allowed-tools"] ?? "");
	if (allowedTools) {
		const dangerousTools = ["Bash", "Write", "Edit", "NotebookEdit"];
		for (const tool of dangerousTools) {
			if (allowedTools.includes(tool)) {
				findings.push({
					rule: "dangerous-allowed-tool",
					message: `Skill requests dangerous tool: ${tool}`,
					severity: "medium",
					file: filename,
					match: `allowed-tools: ${allowedTools.slice(0, 80)}`,
				});
			}
		}
	}

	return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Core Scanner
// ═══════════════════════════════════════════════════════════════════════════════

/** Max file size to scan (1 MB). Larger files are suspicious in a skill. */
const MAX_SCAN_FILE_SIZE = 1024 * 1024;

/** File extensions to scan for content patterns. */
const SCANNABLE_EXTENSIONS = new Set([
	".md",
	".txt",
	".js",
	".ts",
	".mjs",
	".cjs",
	".json",
	".yaml",
	".yml",
	".sh",
	".bash",
	".py",
	".rb",
]);

/**
 * Scan a single file for malicious patterns.
 */
function scanFile(filePath: string, relativeToSkill: string): ScanFinding[] {
	const findings: ScanFinding[] = [];
	const ext = path.extname(filePath).toLowerCase();

	// Check file size
	let stat: fs.Stats;
	try {
		stat = fs.statSync(filePath);
	} catch {
		return findings;
	}

	if (stat.size > MAX_SCAN_FILE_SIZE) {
		findings.push({
			rule: "oversized-file",
			message: `File is ${(stat.size / 1024).toFixed(0)}KB — unusually large for a skill`,
			severity: "medium",
			file: relativeToSkill,
		});
		return findings; // Don't scan oversized files
	}

	if (!SCANNABLE_EXTENSIONS.has(ext)) {
		// Check if it's a binary file
		if (stat.size > 0) {
			try {
				const head = Buffer.alloc(512);
				const fd = fs.openSync(filePath, "r");
				fs.readSync(fd, head, 0, 512, 0);
				fs.closeSync(fd);
				if (head.includes(0)) {
					findings.push({
						rule: "binary-file",
						message: "Binary file in skill directory — review manually",
						severity: "medium",
						file: relativeToSkill,
					});
				}
			} catch {
				// Ignore read errors
			}
		}
		return findings;
	}

	let content: string;
	try {
		content = fs.readFileSync(filePath, "utf-8");
	} catch {
		return findings;
	}

	// Path-level checks on the relative path itself
	for (const { rule, pattern, message, severity } of PATH_PATTERNS) {
		pattern.lastIndex = 0;
		if (pattern.test(relativeToSkill)) {
			findings.push({
				rule,
				message: `${message} in file path`,
				severity,
				file: relativeToSkill,
				match: relativeToSkill,
			});
		}
	}

	// Content pattern checks
	for (const scanPattern of CONTENT_PATTERNS) {
		// Check file type filter
		if (scanPattern.fileTypes && !scanPattern.fileTypes.includes(ext)) {
			continue;
		}

		scanPattern.pattern.lastIndex = 0;
		let match = scanPattern.pattern.exec(content);
		while (match !== null) {
			// Find line number
			const beforeMatch = content.slice(0, match.index);
			const lineNum = beforeMatch.split("\n").length;

			findings.push({
				rule: scanPattern.rule,
				message: scanPattern.message,
				severity: scanPattern.severity,
				file: relativeToSkill,
				line: lineNum,
				match: match[0].slice(0, 100),
			});

			// Avoid infinite loops on zero-width matches
			if (match[0].length === 0) {
				scanPattern.pattern.lastIndex++;
			}
			match = scanPattern.pattern.exec(content);
		}
	}

	// Path pattern checks within content
	for (const { rule, pattern, message, severity } of PATH_PATTERNS) {
		pattern.lastIndex = 0;
		let match = pattern.exec(content);
		while (match !== null) {
			const beforeMatch = content.slice(0, match.index);
			const lineNum = beforeMatch.split("\n").length;

			findings.push({
				rule,
				message,
				severity,
				file: relativeToSkill,
				line: lineNum,
				match: match[0].slice(0, 100),
			});

			if (match[0].length === 0) {
				pattern.lastIndex++;
			}
			match = pattern.exec(content);
		}
	}

	// Frontmatter validation for SKILL.md
	if (path.basename(filePath).toLowerCase() === "skill.md") {
		findings.push(...validateFrontmatter(content, relativeToSkill));
	}

	return findings;
}

/**
 * Recursively collect all files in a directory.
 */
function collectFiles(dir: string, base: string = dir): string[] {
	const files: string[] = [];
	let entries: fs.Dirent[];
	try {
		entries = fs.readdirSync(dir, { withFileTypes: true });
	} catch {
		return files;
	}

	for (const entry of entries) {
		const fullPath = path.join(dir, entry.name);
		if (entry.isDirectory()) {
			// Don't follow symlinks to prevent traversal
			if (entry.isSymbolicLink()) {
				continue;
			}
			files.push(...collectFiles(fullPath, base));
		} else if (entry.isFile()) {
			files.push(fullPath);
		}
	}

	return files;
}

/**
 * Options controlling skill scan behaviour.
 *
 * `repoRoot` is used by the symlink-root rule to distinguish between
 * in-repo symlinks (benign — e.g., `.claude/skills/X` → `.agents/skills/X`,
 * our canonical layout) and out-of-repo symlinks (critical — potential
 * traversal or exfiltration vector). When omitted, we default to three
 * levels above the skill directory, which matches the typical
 * `<repo>/.claude/skills/<name>` layout.
 */
export type ScanSkillOptions = {
	repoRoot?: string;
};

/**
 * Return the canonical (realpath) form of `p`, or the original string if
 * resolution fails (e.g., the path doesn't exist). Symlink chains are
 * followed so we can compare against the real repo root.
 */
function safeRealpath(p: string): string {
	try {
		return fs.realpathSync(p);
	} catch {
		return path.resolve(p);
	}
}

/**
 * Infer a reasonable repo root from a skill directory. Skills are typically
 * stored at `<repo>/.claude/skills/<name>`, so three parents above the skill
 * dir is the repo root in the common case. Callers should pass an explicit
 * `repoRoot` when that heuristic does not apply.
 */
function defaultRepoRootFor(skillDir: string): string {
	return path.resolve(skillDir, "..", "..", "..");
}

/**
 * Resolve a symlink at `linkPath` to its absolute target, even if the
 * target does not currently exist (so `fs.realpathSync` would throw).
 *
 * We first try `realpathSync` to follow symlink chains to their canonical
 * form. If that fails (broken symlink), we fall back to reading the raw
 * link target and resolving it relative to the link's parent directory.
 * This lets us classify broken-but-attempting-to-escape symlinks as
 * out-of-repo rather than treating them as in-repo by default.
 */
function resolveSymlinkTarget(linkPath: string): string {
	try {
		return fs.realpathSync(linkPath);
	} catch {
		// realpath failed — the symlink target probably does not exist.
		// Fall back to the link's raw target resolved against its parent.
		try {
			const rawTarget = fs.readlinkSync(linkPath);
			if (path.isAbsolute(rawTarget)) return path.resolve(rawTarget);
			return path.resolve(path.dirname(linkPath), rawTarget);
		} catch {
			return path.resolve(linkPath);
		}
	}
}

/**
 * Return true if `resolvedCandidate` sits inside `root` (or equals it),
 * comparing their real paths. `resolvedCandidate` is assumed to already
 * be fully resolved (e.g., via `resolveSymlinkTarget`); `root` is
 * canonicalised here so broken or missing roots still compare correctly.
 */
function isResolvedPathInside(resolvedCandidate: string, root: string): boolean {
	const realRoot = safeRealpath(root);
	if (resolvedCandidate === realRoot) return true;
	const prefix = realRoot.endsWith(path.sep) ? realRoot : `${realRoot}${path.sep}`;
	return resolvedCandidate.startsWith(prefix);
}

/** Tally findings by severity. */
function countFindings(findings: readonly ScanFinding[]): Record<ScanSeverity, number> {
	const counts: Record<ScanSeverity, number> = { critical: 0, high: 0, medium: 0, info: 0 };
	for (const f of findings) counts[f.severity]++;
	return counts;
}

/**
 * Scan a single skill directory.
 */
export function scanSkill(skillDir: string, options?: ScanSkillOptions): ScanResult {
	const skillName = path.basename(skillDir);
	const findings: ScanFinding[] = [];

	// Check for symlink at the skill root level BEFORE existence checks so
	// broken traversal symlinks (whose target does not resolve) are still
	// flagged. `fs.existsSync` follows symlinks and returns false for a
	// dangling link, which would otherwise short-circuit the whole scan.
	//
	// A symlink alone is not inherently malicious — this repo uses
	// `.claude/skills/<name>` → `.agents/skills/<name>` as the canonical
	// layout so skills can be authored once and surfaced to the SDK via a
	// mount point. The concern is a symlink whose realpath escapes the
	// repo root (e.g., `../../../../etc/passwd`): that indicates either a
	// malicious skill bundle or an accidental misconfiguration, and still
	// warrants a critical finding. We resolve the target even when the
	// symlink is broken, so a traversal attempt pointing at a non-existent
	// file is still caught rather than treated as in-repo by default.
	let lstat: fs.Stats | null = null;
	try {
		lstat = fs.lstatSync(skillDir);
	} catch {
		lstat = null;
	}
	if (lstat?.isSymbolicLink()) {
		const repoRoot = options?.repoRoot ?? defaultRepoRootFor(skillDir);
		try {
			const target = fs.readlinkSync(skillDir);
			const resolvedTarget = resolveSymlinkTarget(skillDir);
			if (!isResolvedPathInside(resolvedTarget, repoRoot)) {
				findings.push({
					rule: "symlink-root",
					message:
						"Skill root is a symlink whose realpath is outside the repo — potential path traversal",
					severity: "critical",
					file: ".",
					match: target,
				});
			}
		} catch {
			// readlink/resolve failed — ignore; outer scan continues.
		}
	}

	// Check directory exists (following symlinks). A broken symlink returns
	// false here, which is fine: if we flagged it above we still surface
	// the finding; otherwise there is nothing further to scan.
	if (!fs.existsSync(skillDir)) {
		if (findings.length === 0) {
			findings.push({
				rule: "not-found",
				message: "Skill directory does not exist",
				severity: "info",
				file: ".",
			});
		}
		const counts = countFindings(findings);
		return {
			skillName,
			skillPath: skillDir,
			findings,
			blocked: counts.critical > 0 || counts.high > 0,
			counts,
		};
	}

	// Collect and scan all files
	const files = collectFiles(skillDir);
	for (const filePath of files) {
		const relative = path.relative(skillDir, filePath);
		findings.push(...scanFile(filePath, relative));
	}

	const counts = countFindings(findings);
	const blocked = counts.critical > 0 || counts.high > 0;

	if (blocked) {
		logger.warn(
			{ skillName, critical: counts.critical, high: counts.high },
			"skill blocked by scanner",
		);
	}

	return {
		skillName,
		skillPath: skillDir,
		findings,
		blocked,
		counts,
	};
}

/**
 * Scan all skills in a directory (each subdirectory is a skill).
 *
 * When `options.repoRoot` is omitted, we default to the parent of
 * `skillsRoot` (e.g., for `<repo>/.claude/skills`, the repo root is
 * `<repo>/.claude`'s parent — i.e., two levels up). This lets in-repo
 * symlinks (such as the canonical `.claude/skills/<name>` →
 * `.agents/skills/<name>` layout) pass the symlink-root rule.
 */
export function scanAllSkills(skillsRoot: string, options?: ScanSkillOptions): ScanResult[] {
	const results: ScanResult[] = [];

	if (!fs.existsSync(skillsRoot)) {
		return results;
	}

	const repoRoot = options?.repoRoot ?? path.resolve(skillsRoot, "..", "..");

	let entries: fs.Dirent[];
	try {
		entries = fs.readdirSync(skillsRoot, { withFileTypes: true });
	} catch {
		return results;
	}

	for (const entry of entries) {
		// Accept either a real directory or a symlink pointing to a
		// directory. Dirent.isDirectory() returns false for symlinks even
		// when they resolve to directories, so we fall back to statSync()
		// which follows the link.
		let isDirLike = entry.isDirectory();
		if (!isDirLike && entry.isSymbolicLink()) {
			try {
				isDirLike = fs.statSync(path.join(skillsRoot, entry.name)).isDirectory();
			} catch {
				isDirLike = false;
			}
		}
		if (!isDirLike) continue;
		const skillDir = path.join(skillsRoot, entry.name);
		results.push(scanSkill(skillDir, { repoRoot }));
	}

	return results;
}

/**
 * Format scan results for CLI display.
 */
export function formatScanResults(results: ScanResult[]): string {
	const lines: string[] = [];
	let totalBlocked = 0;
	let totalFindings = 0;

	for (const result of results) {
		const status = result.blocked ? "BLOCKED" : "OK";
		const icon = result.blocked ? "\u2717" : "\u2713";

		if (result.findings.length === 0) {
			lines.push(`  ${icon} ${result.skillName} — ${status}`);
			continue;
		}

		lines.push(`  ${icon} ${result.skillName} — ${status}`);
		totalFindings += result.findings.length;
		if (result.blocked) totalBlocked++;

		for (const finding of result.findings) {
			const loc = finding.line ? `:${finding.line}` : "";
			const match = finding.match ? ` [${finding.match}]` : "";
			lines.push(
				`    ${finding.severity.toUpperCase()}: ${finding.message} (${finding.file}${loc})${match}`,
			);
		}
	}

	lines.push("");
	lines.push(
		`Scanned ${results.length} skills: ${totalBlocked} blocked, ${totalFindings} findings`,
	);

	return lines.join("\n");
}
