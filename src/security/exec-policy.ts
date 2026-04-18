/**
 * Workstream W8 — Exec policy allowlists & safe-bin shortcuts.
 *
 * Two layers working together:
 *
 * 1. Safe-bin catalog (`isSafeBinCommand`):
 *    Read-only text utilities that are safe to run WITHOUT approval so long
 *    as their arguments stay stdin-only — no positional file paths, no
 *    output redirects, no process substitution. Matches Openclaw's "host
 *    guardrail" pattern: `grep foo` reads stdin so it's harmless, but
 *    `grep foo /etc/passwd` reads a real file so it falls back to the
 *    normal approval path.
 *
 * 2. Per-chat glob allowlist (`checkExecPolicy`):
 *    Operator-curated globs persisted to `~/.telclaude/exec-policy.json`.
 *    Populated via `telclaude exec-policy add` and (once W1 dynamic lands)
 *    via the "approve always" button on the ApprovalScopeCard. Match
 *    semantics are intentionally coarse: the whole normalised command
 *    string is matched against the glob.
 *
 * Both layers FAIL OPEN to "prompt" — they can only grant bypass, never
 * add a new denial. Destructive patterns (caught by `risk-tiers.ts`) stay
 * above this layer: a safe-bin or glob match never overrides a destructive
 * classification.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { getChildLogger } from "../logging.js";
import { isDestructiveBash } from "./risk-tiers.js";

const logger = getChildLogger({ module: "exec-policy" });

// ═══════════════════════════════════════════════════════════════════════════════
// Persistence
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Resolve the exec-policy file path at call time so tests (and operators
 * who export `TELCLAUDE_DATA_DIR` at runtime) get the current location
 * instead of whatever was set at module load. Mirrors the `CONFIG_DIR`
 * resolution in `src/utils.ts` but re-evaluated per call.
 */
export function resolveExecPolicyPath(): string {
	const dataDir = process.env.TELCLAUDE_DATA_DIR;
	if (dataDir && path.isAbsolute(dataDir)) {
		return path.join(dataDir.replace(/\/+$/, ""), "exec-policy.json");
	}
	return path.join(os.homedir(), ".telclaude", "exec-policy.json");
}

const MAX_GLOBS_PER_CHAT = 256;
const MAX_GLOB_LENGTH = 256;

/** Per-chat entry as persisted on disk. */
export type ChatExecPolicy = {
	globs: string[];
};

/** Top-level persisted schema. */
export type ExecPolicyFile = {
	chats: Record<string, ChatExecPolicy>;
};

function emptyFile(): ExecPolicyFile {
	return { chats: {} };
}

/**
 * Read the policy file. Missing file, malformed JSON, or unexpected schema
 * all collapse to an empty policy — we never crash the caller over a
 * bad on-disk file; worst case the operator re-adds their globs.
 */
export function loadExecPolicy(filePath?: string): ExecPolicyFile {
	const resolved = filePath ?? resolveExecPolicyPath();
	if (!fs.existsSync(resolved)) {
		return emptyFile();
	}
	try {
		const raw = fs.readFileSync(resolved, "utf-8");
		const parsed = JSON.parse(raw);
		if (!parsed || typeof parsed !== "object") {
			logger.warn({ filePath: resolved }, "exec-policy: malformed root (not an object)");
			return emptyFile();
		}
		const rawChats = (parsed as { chats?: unknown }).chats;
		if (!rawChats || typeof rawChats !== "object") {
			return emptyFile();
		}
		const chats: Record<string, ChatExecPolicy> = {};
		for (const [chatId, entry] of Object.entries(rawChats as Record<string, unknown>)) {
			if (!entry || typeof entry !== "object") continue;
			const globsValue = (entry as { globs?: unknown }).globs;
			if (!Array.isArray(globsValue)) continue;
			const globs = globsValue
				.filter((g): g is string => typeof g === "string" && g.length > 0)
				.map((g) => g.slice(0, MAX_GLOB_LENGTH))
				.slice(0, MAX_GLOBS_PER_CHAT);
			if (globs.length === 0) continue;
			chats[String(chatId)] = { globs };
		}
		return { chats };
	} catch (err) {
		logger.warn(
			{ filePath: resolved, err: String(err) },
			"exec-policy: failed to parse file; using empty",
		);
		return emptyFile();
	}
}

/**
 * Atomically persist the policy file (write temp + rename).
 * Directory created with 0o700 and file written with 0o600 because this
 * file ties chat ids to operator-approved command patterns.
 */
export function saveExecPolicy(file: ExecPolicyFile, filePath?: string): void {
	const resolved = filePath ?? resolveExecPolicyPath();
	fs.mkdirSync(path.dirname(resolved), { recursive: true, mode: 0o700 });
	const tmp = `${resolved}.tmp-${process.pid}-${Date.now()}`;
	const payload = `${JSON.stringify(file, null, 2)}\n`;
	fs.writeFileSync(tmp, payload, { mode: 0o600 });
	fs.renameSync(tmp, resolved);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Mutations — CLI + future W1 integration hook call these.
// ═══════════════════════════════════════════════════════════════════════════════

function normalizeChatId(chatId: number | string): string {
	return String(chatId).trim();
}

function normalizeGlob(glob: string): string {
	return glob.trim();
}

/** List entries for a single chat, or all chats. */
export function listExecPolicy(options: { chatId?: number | string } = {}): Array<{
	chatId: string;
	globs: string[];
}> {
	const file = loadExecPolicy();
	const entries = Object.entries(file.chats).map(([chatId, entry]) => ({
		chatId,
		globs: [...entry.globs],
	}));
	if (options.chatId !== undefined) {
		const needle = normalizeChatId(options.chatId);
		return entries.filter((e) => e.chatId === needle);
	}
	return entries;
}

/**
 * Add a glob to a chat's allowlist (idempotent). Returns true when a new
 * entry was added, false when the glob was already present.
 */
export function addExecPolicyGlob(chatId: number | string, glob: string): boolean {
	const id = normalizeChatId(chatId);
	const cleaned = normalizeGlob(glob);
	if (!id) throw new Error("addExecPolicyGlob: chatId is required");
	if (!cleaned) throw new Error("addExecPolicyGlob: glob is required");
	if (cleaned.length > MAX_GLOB_LENGTH) {
		throw new Error(`addExecPolicyGlob: glob exceeds ${MAX_GLOB_LENGTH} chars`);
	}
	const file = loadExecPolicy();
	const entry = file.chats[id] ?? { globs: [] };
	if (entry.globs.includes(cleaned)) {
		return false;
	}
	if (entry.globs.length >= MAX_GLOBS_PER_CHAT) {
		throw new Error(`addExecPolicyGlob: chat ${id} already has ${MAX_GLOBS_PER_CHAT} globs (max)`);
	}
	entry.globs.push(cleaned);
	file.chats[id] = entry;
	saveExecPolicy(file);
	logger.info({ chatId: id, glob: cleaned }, "exec-policy: glob added");
	return true;
}

/**
 * Remove a glob (or the entire chat when `glob` is omitted).
 * Returns the number of globs actually removed.
 */
export function revokeExecPolicyGlob(chatId: number | string, glob?: string): number {
	const id = normalizeChatId(chatId);
	if (!id) throw new Error("revokeExecPolicyGlob: chatId is required");
	const file = loadExecPolicy();
	const entry = file.chats[id];
	if (!entry) return 0;

	if (glob === undefined) {
		const removed = entry.globs.length;
		delete file.chats[id];
		saveExecPolicy(file);
		logger.info({ chatId: id, removed }, "exec-policy: chat cleared");
		return removed;
	}

	const cleaned = normalizeGlob(glob);
	const before = entry.globs.length;
	entry.globs = entry.globs.filter((g) => g !== cleaned);
	const removed = before - entry.globs.length;
	if (entry.globs.length === 0) {
		delete file.chats[id];
	} else {
		file.chats[id] = entry;
	}
	if (removed > 0) {
		saveExecPolicy(file);
		logger.info({ chatId: id, glob: cleaned }, "exec-policy: glob removed");
	}
	return removed;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Safe-bin catalog
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Read-only text utilities safe when used with stdin-only arguments.
 *
 * These were chosen to mirror Openclaw's host guardrail set — they inspect
 * data already on stdin (from a pipe, heredoc, or subshell) and cannot
 * themselves open new paths or write files when no positional argument
 * points to one.
 *
 * NOTE: We do not include `sed` / `awk` because their stock invocations
 * legitimately take positional file arguments and their edit commands
 * (`sed -i`, `awk ... > out`) are non-trivial to disambiguate from safe
 * use. Operators who need them can add a targeted glob via the CLI.
 */
export const SAFE_BINS: readonly string[] = Object.freeze([
	"cat",
	"cut",
	"head",
	"tail",
	"wc",
	"grep",
	"egrep",
	"fgrep",
	"rg",
	"sort",
	"uniq",
	"tr",
	"jq",
]);

const SAFE_BIN_SET: ReadonlySet<string> = new Set(SAFE_BINS);

/** Commands/options that make a `jq` invocation no longer read-only. */
const JQ_WRITE_FLAGS = new Set(["-i", "--in-place", "--rcfile"]);

/**
 * Short-option letters that consume the next token as their value. E.g.
 * `head -n 10` → `-n` + `10`, not `head -n` + positional `10`. Using a
 * catalog keeps tokenisation conservative: anything not in this set is
 * treated as a bare flag (no value), mirroring GNU style.
 */
const FLAGS_WITH_ARG: Record<string, ReadonlySet<string>> = {
	grep: new Set([
		"-e",
		"--regexp",
		"-f",
		"--file",
		"-A",
		"-B",
		"-C",
		"--after-context",
		"--before-context",
		"--context",
		"-m",
		"--max-count",
	]),
	egrep: new Set(["-e", "-f", "-A", "-B", "-C", "-m"]),
	fgrep: new Set(["-e", "-f", "-A", "-B", "-C", "-m"]),
	rg: new Set([
		"-e",
		"--regexp",
		"-g",
		"--glob",
		"-A",
		"--after-context",
		"-B",
		"--before-context",
		"-C",
		"--context",
		"-m",
		"--max-count",
		"-t",
		"--type",
		"-T",
		"--type-not",
	]),
	head: new Set(["-n", "--lines", "-c", "--bytes"]),
	tail: new Set(["-n", "--lines", "-c", "--bytes"]),
	wc: new Set([]),
	cut: new Set(["-d", "--delimiter", "-f", "--fields", "-c", "--characters", "-b", "--bytes"]),
	sort: new Set(["-k", "--key", "-t", "--field-separator", "-o", "--output"]),
	uniq: new Set(["-f", "--skip-fields", "-s", "--skip-chars", "-w", "--check-chars"]),
	tr: new Set([]),
	jq: new Set(["-f", "--from-file", "--arg", "--argjson", "--slurpfile", "--rawfile", "--indent"]),
	cat: new Set([]),
};

/**
 * Binaries whose FIRST positional argument is a pattern (not a file).
 * They may safely take exactly one positional arg; additional positionals
 * would point to file paths and fall through to the normal approval flow.
 */
const FIRST_POSITIONAL_IS_PATTERN = new Set(["grep", "egrep", "fgrep", "rg", "jq"]);

/**
 * Tokenise a shell command well enough to recognise safe-bin patterns.
 *
 * We intentionally do NOT implement a real shell parser. Anything even
 * vaguely unusual — pipes, subshells, backticks, `$()`, redirects, `&&`,
 * `||`, `;`, `&`, here-docs, env-assignments before the binary — causes
 * us to bail out. A bailout is not a deny; the caller's normal approval
 * path still applies.
 */
const SHELL_METACHARS = /[|&;<>`$(){}\\\n]/;
const ENV_ASSIGN = /^[A-Za-z_][A-Za-z0-9_]*=/;

export type SafeBinMatch = { safe: true; binary: string } | { safe: false; reason: string };

/**
 * Decide whether a raw Bash command is safe to auto-allow because it
 * matches a read-only binary invoked with stdin-only arguments.
 */
export function isSafeBinCommand(command: string | undefined): SafeBinMatch {
	if (!command) return { safe: false, reason: "empty command" };
	const trimmed = command.trim();
	if (!trimmed) return { safe: false, reason: "empty command" };
	if (trimmed.length > 2048) return { safe: false, reason: "command too long" };

	// Refuse anything that includes shell metacharacters. Subshells, pipes,
	// redirects, heredocs, command substitution, job control — all out.
	if (SHELL_METACHARS.test(trimmed)) {
		return { safe: false, reason: "shell metacharacters present" };
	}

	// Hard-block destructive patterns as a belt-and-braces check. Even if
	// a safe bin *name* prefixes such a command, we refuse.
	if (isDestructiveBash(trimmed)) {
		return { safe: false, reason: "destructive pattern" };
	}

	const tokens = trimmed.split(/\s+/).filter(Boolean);
	if (tokens.length === 0) return { safe: false, reason: "empty after split" };

	// Strip leading env-var assignments: `FOO=bar grep x` is fine so long
	// as the binary itself is safe. But any `FOO=...` with metacharacters
	// was already rejected above.
	let i = 0;
	while (i < tokens.length && ENV_ASSIGN.test(tokens[i])) {
		i++;
	}
	if (i >= tokens.length) return { safe: false, reason: "only env assignments" };

	const bin = path.basename(tokens[i]);
	if (!SAFE_BIN_SET.has(bin)) {
		return { safe: false, reason: `binary ${bin} not in safe-bin catalog` };
	}

	const rest = tokens.slice(i + 1);

	// For `jq`, reject the in-place family regardless of positional args.
	if (bin === "jq") {
		for (const tok of rest) {
			if (JQ_WRITE_FLAGS.has(tok)) {
				return { safe: false, reason: `jq ${tok} writes to disk` };
			}
		}
	}

	// Walk tokens, skipping flag values for flags that take arguments.
	// Count positional (file-path-like) arguments: any non-flag token that
	// isn't consumed by a preceding flag.
	const argFlags = FLAGS_WITH_ARG[bin] ?? new Set<string>();
	const allowOnePattern = FIRST_POSITIONAL_IS_PATTERN.has(bin);

	let positionals = 0;
	for (let k = 0; k < rest.length; k++) {
		const tok = rest[k];
		if (tok.startsWith("--")) {
			// --long-flag=value is self-contained; --long-flag with a
			// separate value consumes the next token when in argFlags.
			if (tok.includes("=")) continue;
			const base = tok;
			if (argFlags.has(base) && k + 1 < rest.length) {
				k++; // skip the value token
			}
			continue;
		}
		if (tok.startsWith("-") && tok.length > 1) {
			// Short flag cluster like "-n" or "-rf" or "-n10".
			// Only treat as arg-consuming when it's a bare short flag
			// that appears in argFlags, e.g. "-n". Clustered forms
			// ("-n10") embed the value and consume no next token.
			if (argFlags.has(tok) && k + 1 < rest.length) {
				k++;
			}
			continue;
		}
		// Positional argument.
		positionals++;
		if (allowOnePattern && positionals === 1) {
			// The first positional is the pattern/expression, not a path.
			continue;
		}
		return { safe: false, reason: "positional argument present" };
	}

	return { safe: true, binary: bin };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Glob matcher — minimal, dependency-free
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Compile a glob pattern to a RegExp. Supports `*`, `?`, and character
 * classes `[abc]`. Matches the whole string. Intentionally does not
 * support `**` or brace expansion — the patterns are operator-authored
 * and we prefer an easy-to-reason-about subset.
 */
export function globToRegExp(glob: string): RegExp {
	let out = "";
	let i = 0;
	while (i < glob.length) {
		const ch = glob[i];
		if (ch === "*") {
			out += ".*";
			i++;
			continue;
		}
		if (ch === "?") {
			out += ".";
			i++;
			continue;
		}
		if (ch === "[") {
			// Character class — copy verbatim until the matching ']',
			// translating the leading `!` to `^` for regex.
			let j = i + 1;
			if (glob[j] === "!") {
				j++;
			}
			while (j < glob.length && glob[j] !== "]") {
				j++;
			}
			if (j >= glob.length) {
				// No closing bracket — treat the literal '[' as literal.
				out += "\\[";
				i++;
				continue;
			}
			const body = glob.slice(i + 1, j);
			const regexBody = body.startsWith("!") ? `^${body.slice(1)}` : body;
			out += `[${regexBody}]`;
			i = j + 1;
			continue;
		}
		// Escape all regex metacharacters except our known set above.
		if (/[.+^${}()|\\]/.test(ch)) {
			out += `\\${ch}`;
		} else {
			out += ch;
		}
		i++;
	}
	return new RegExp(`^${out}$`);
}

/** Match a command string against a single glob pattern. */
export function matchGlob(glob: string, command: string): boolean {
	try {
		return globToRegExp(glob).test(command);
	} catch (err) {
		logger.warn({ glob, err: String(err) }, "exec-policy: invalid glob");
		return false;
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Policy check — the entry point pipeline.ts consults
// ═══════════════════════════════════════════════════════════════════════════════

export type ExecPolicyDecision =
	| { decision: "allow"; reason: string; matchedGlob?: string; safeBin?: string }
	| { decision: "prompt"; reason: string }
	| { decision: "deny"; reason: string };

/**
 * Decide whether a Bash command is covered by the exec policy.
 *
 * Evaluation order:
 *   1. Destructive patterns → always `prompt` (leaves the normal risk
 *      classifier to handle them; we refuse to whitelist destruction).
 *   2. Safe-bin shortcut → `allow` when the command is stdin-only.
 *   3. Per-chat glob allowlist → `allow` on match.
 *   4. Otherwise → `prompt` (no-op; the existing flow continues).
 *
 * We never return `deny` today; the `deny` arm is reserved for future
 * per-chat blocklists. Returning `prompt` here is strictly additive —
 * the pipeline's existing risk classifier is still authoritative on
 * whether an approval prompt is actually shown.
 */
export function checkExecPolicy(input: {
	chatId?: number | string | null;
	command: string | undefined;
}): ExecPolicyDecision {
	const { command } = input;
	if (!command?.trim()) {
		return { decision: "prompt", reason: "empty command" };
	}

	// 1. Destructive — never shortcut, even if the operator added a glob.
	if (isDestructiveBash(command)) {
		return { decision: "prompt", reason: "destructive pattern — no allowlist shortcut" };
	}

	// 2. Safe-bin catalog.
	const safe = isSafeBinCommand(command);
	if (safe.safe) {
		return {
			decision: "allow",
			reason: `safe-bin ${safe.binary} (stdin-only)`,
			safeBin: safe.binary,
		};
	}

	// 3. Per-chat allowlist lookup.
	if (input.chatId !== undefined && input.chatId !== null) {
		const id = normalizeChatId(input.chatId);
		const file = loadExecPolicy();
		const entry = file.chats[id];
		if (entry) {
			for (const glob of entry.globs) {
				if (matchGlob(glob, command.trim())) {
					return {
						decision: "allow",
						reason: `allowlist match: ${glob}`,
						matchedGlob: glob,
					};
				}
			}
		}
	}

	return { decision: "prompt", reason: safe.reason };
}

// ═══════════════════════════════════════════════════════════════════════════════
// W1 integration hook (pending merge)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * TODO(W1 merge): wire the "approve always" grant path into this helper so
 * a Bash `always` grant persists an exec-policy glob for the chat.
 *
 * The W1 dynamic branch owns `src/security/approvals.ts` and the
 * ApprovalScopeCard flow in `src/telegram/cards/`, so this worktree leaves
 * a stable import target instead of editing those files directly. When
 * both waves land, `grantAllowlist` in approvals.ts should call this with
 * the approved Bash command string; exec-policy will store a
 * conservative glob derived from the binary + first argument.
 *
 * Signature kept intentionally narrow so approvals.ts needs no new deps.
 */
export function recordAlwaysFromAllowlist(input: {
	chatId: number | string;
	bashCommand: string;
}): void {
	const { chatId, bashCommand } = input;
	if (!chatId || !bashCommand) return;

	// Reject destructive: we never promote a destructive command even
	// when the user clicks "always" — the approvals layer should have
	// already clamped this to "once", but defence in depth.
	if (isDestructiveBash(bashCommand)) {
		logger.warn(
			{ chatId: String(chatId), cmd: bashCommand.slice(0, 120) },
			"exec-policy: refused to promote destructive command to always",
		);
		return;
	}

	const glob = deriveGlobFromCommand(bashCommand);
	if (!glob) return;
	try {
		addExecPolicyGlob(chatId, glob);
	} catch (err) {
		logger.warn(
			{ chatId: String(chatId), glob, err: String(err) },
			"exec-policy: failed to record always grant",
		);
	}
}

/**
 * Build a conservative glob from a Bash command. Strategy:
 * - Strip trailing arguments; keep the binary name and the first
 *   positional arg (if any), with a trailing `*` wildcard.
 * - Example: `npm test --watch` → `npm test*`
 * - Example: `grep foo /etc/passwd` → `grep foo*`
 *
 * Returns null when the command cannot be safely generalised (shell
 * metacharacters present, zero tokens, etc.).
 */
export function deriveGlobFromCommand(command: string): string | null {
	if (!command) return null;
	const trimmed = command.trim();
	if (!trimmed) return null;
	if (SHELL_METACHARS.test(trimmed)) return null;
	const tokens = trimmed.split(/\s+/).filter(Boolean);
	if (tokens.length === 0) return null;
	// Skip env assignments so `FOO=1 npm test` becomes `npm test*`.
	let i = 0;
	while (i < tokens.length && ENV_ASSIGN.test(tokens[i])) i++;
	if (i >= tokens.length) return null;
	const bin = path.basename(tokens[i]);
	const firstArg = tokens[i + 1];
	if (firstArg && !firstArg.startsWith("-")) {
		return `${bin} ${firstArg}*`;
	}
	return `${bin}*`;
}
