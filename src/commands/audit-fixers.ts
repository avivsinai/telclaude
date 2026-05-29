/**
 * Security auto-remediation for `doctor --security --fix`.
 *
 * Applies safe fixes for audit findings:
 *   - Tighten file permissions on config/auth files
 *   - Set conservative config defaults for flagged settings
 *   - Report what was changed with before/after state
 *
 * Inspired by OpenClaw's fix.ts pattern: safeChmod, atomic config write + backup.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import JSON5 from "json5";
import type { TelclaudeConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";

const logger = getChildLogger({ module: "cmd-audit-fixers" });

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

export type FixActionKind = "chmod" | "config" | "create";

export type FixAction = {
	/** What kind of fix was applied. */
	kind: FixActionKind;
	/** Target file or config key. */
	target: string;
	/** Description of the fix. */
	description: string;
	/** Value before the fix (null if not applicable). */
	before: string | null;
	/** Value after the fix. */
	after: string;
	/** Whether the fix was actually applied. */
	applied: boolean;
	/** Reason if skipped (e.g., "already correct", "file not found", "symlink"). */
	skipped?: string;
	/** Error message if the fix failed. */
	error?: string;
};

export type FixReport = {
	actions: FixAction[];
	configBackupPath: string | null;
	/** Operator-facing warnings emitted during the run (e.g., comment-loss on rewrite). */
	warnings?: string[];
	summary: {
		applied: number;
		skipped: number;
		errors: number;
	};
};

// ═══════════════════════════════════════════════════════════════════════════════
// Safe chmod helper (adapted from OpenClaw's safeChmod)
// ═══════════════════════════════════════════════════════════════════════════════

function safeChmod(filePath: string, targetMode: number, label: string): FixAction {
	try {
		if (!fs.existsSync(filePath)) {
			return {
				kind: "chmod",
				target: filePath,
				description: `Tighten permissions on ${label}`,
				before: null,
				after: targetMode.toString(8),
				applied: false,
				skipped: "file not found",
			};
		}

		const stat = fs.lstatSync(filePath);

		// Never follow symlinks
		if (stat.isSymbolicLink()) {
			return {
				kind: "chmod",
				target: filePath,
				description: `Tighten permissions on ${label}`,
				before: null,
				after: targetMode.toString(8),
				applied: false,
				skipped: "symlink — refusing to follow",
			};
		}

		const currentMode = stat.mode & 0o777;

		// Already correct
		if (currentMode === targetMode) {
			return {
				kind: "chmod",
				target: filePath,
				description: `Tighten permissions on ${label}`,
				before: currentMode.toString(8),
				after: targetMode.toString(8),
				applied: false,
				skipped: "already correct",
			};
		}

		// Only tighten — never loosen permissions.
		// Bitwise check: if current mode has no bits set beyond what target allows,
		// it's already at least as restrictive (e.g., 0o400 is stricter than 0o600).
		if ((currentMode & ~targetMode) === 0 && currentMode !== targetMode) {
			return {
				kind: "chmod",
				target: filePath,
				description: `Tighten permissions on ${label}`,
				before: currentMode.toString(8),
				after: targetMode.toString(8),
				applied: false,
				skipped: "current permissions are already stricter",
			};
		}

		fs.chmodSync(filePath, targetMode);

		return {
			kind: "chmod",
			target: filePath,
			description: `Tighten permissions on ${label}`,
			before: currentMode.toString(8),
			after: targetMode.toString(8),
			applied: true,
		};
	} catch (err) {
		return {
			kind: "chmod",
			target: filePath,
			description: `Tighten permissions on ${label}`,
			before: null,
			after: targetMode.toString(8),
			applied: false,
			error: String(err),
		};
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Atomic config write with backup
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Write config atomically: write to .tmp, create .bak of original, rename .tmp to target.
 * Returns the backup path on success, null if no write was needed.
 */
function atomicConfigWrite(configPath: string, content: string): { backupPath: string } {
	const tmpPath = `${configPath}.tmp`;
	const bakPath = `${configPath}.bak`;

	// Write new content to temp file
	fs.writeFileSync(tmpPath, content, "utf-8");

	// Backup original
	if (fs.existsSync(configPath)) {
		fs.copyFileSync(configPath, bakPath);
	}

	// Atomic rename
	fs.renameSync(tmpPath, configPath);

	// Preserve restrictive permissions on the new file
	try {
		fs.chmodSync(configPath, 0o600);
	} catch {
		// Non-fatal — the file was written successfully
	}

	return { backupPath: bakPath };
}

/**
 * Write a JSON file atomically (tmp → rename) with 0o600 permissions.
 * Unlike atomicConfigWrite, this does not create a .bak — used for
 * small settings files where backup is unnecessary.
 */
function atomicJsonWrite(filePath: string, content: string): void {
	const tmpPath = `${filePath}.tmp`;
	fs.writeFileSync(tmpPath, content, "utf-8");
	fs.renameSync(tmpPath, filePath);
	try {
		fs.chmodSync(filePath, 0o600);
	} catch {
		// Non-fatal
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Config fixers
// ═══════════════════════════════════════════════════════════════════════════════

type RawConfig = Record<string, unknown>;

/** Return the nested object at `key`, creating it if absent. Throws if a non-object sits there. */
function ensureObject(parent: RawConfig, key: string): RawConfig {
	const existing = parent[key];
	if (
		existing !== undefined &&
		(typeof existing !== "object" || existing === null || Array.isArray(existing))
	) {
		throw new Error(
			`expected object at "${key}", found ${Array.isArray(existing) ? "array" : typeof existing}`,
		);
	}
	const obj = (existing as RawConfig | undefined) ?? {};
	parent[key] = obj;
	return obj;
}

/** Read the nested object at `key` for inspection only. Throws if a non-object sits there. */
function readObject(parent: RawConfig | undefined, key: string): RawConfig | undefined {
	if (parent === undefined) return undefined;
	const existing = parent[key];
	if (existing === undefined) return undefined;
	if (typeof existing !== "object" || existing === null || Array.isArray(existing)) {
		throw new Error(
			`expected object at "${key}", found ${Array.isArray(existing) ? "array" : typeof existing}`,
		);
	}
	return existing as RawConfig;
}

/**
 * Apply safe config fixes derived SOLELY from the RAW policy config object (the sparse,
 * comment-free shape parsed from the policy file only — no `loadConfig()`, no
 * runtime/private overlays, no Zod defaults).
 *
 * Both the decisions ("is this value dangerous?") and the mutations read and write `raw`.
 * This guarantees we only ever fix values the operator explicitly wrote into the policy
 * file, and never bake an overlay value or a Zod default into the agent-facing policy
 * config. A flagged value that lives only in the runtime/private overlay is invisible
 * here by design — the policy file stays untouched rather than absorbing merged state.
 *
 * If a fix ever needed a value that only exists after the merge, it must refuse rather
 * than read merged state. None of the current fixes need merged state.
 *
 * Returns the mutated raw object and a list of actions taken. May throw via
 * `ensureObject`/`readObject` if the policy file has a malformed `security` subtree; the
 * caller runs this inside the parse try/catch so the operator sees a clear message.
 */
function applyConfigFixes(
	raw: RawConfig,
	env: NodeJS.ProcessEnv,
): { config: RawConfig; actions: FixAction[] } {
	const actions: FixAction[] = [];
	// Inspect the existing security subtree without materializing it; mutations below
	// create it lazily only when a fix actually fires.
	const rawSecurity = readObject(raw, "security");
	const rawProfile = rawSecurity?.profile;
	const rawPermissions = readObject(rawSecurity, "permissions");
	const rawAudit = readObject(rawSecurity, "audit");
	const rawObserver = readObject(rawSecurity, "observer");

	// 1. Test profile → simple
	if (rawProfile === "test") {
		const isTestEnvEnabled = env.TELCLAUDE_ENABLE_TEST_PROFILE === "1";
		if (!isTestEnvEnabled) {
			const security = ensureObject(raw, "security");
			security.profile = "simple";
			actions.push({
				kind: "config",
				target: "security.profile",
				description: "Change test profile to simple (production-safe default)",
				before: "test",
				after: "simple",
				applied: true,
			});
		} else {
			actions.push({
				kind: "config",
				target: "security.profile",
				description: "Test profile is active but TELCLAUDE_ENABLE_TEST_PROFILE=1 is set",
				before: "test",
				after: "test",
				applied: false,
				skipped: "TELCLAUDE_ENABLE_TEST_PROFILE=1 is set — intentional test mode",
			});
		}
	}

	// 2. FULL_ACCESS default tier → READ_ONLY
	if (rawPermissions?.defaultTier === "FULL_ACCESS") {
		const security = ensureObject(raw, "security");
		const permissions = ensureObject(security, "permissions");
		permissions.defaultTier = "READ_ONLY";
		actions.push({
			kind: "config",
			target: "security.permissions.defaultTier",
			description: "Lower default tier from FULL_ACCESS to READ_ONLY",
			before: "FULL_ACCESS",
			after: "READ_ONLY",
			applied: true,
		});
	}

	// 3. Audit logging disabled → enable
	if (rawAudit?.enabled === false) {
		const security = ensureObject(raw, "security");
		const audit = ensureObject(security, "audit");
		audit.enabled = true;
		actions.push({
			kind: "config",
			target: "security.audit.enabled",
			description: "Enable audit logging for forensic trail",
			before: "false",
			after: "true",
			applied: true,
		});
	}

	// 4. Observer disabled in strict profile → enable
	if (rawProfile === "strict" && rawObserver?.enabled === false) {
		const security = ensureObject(raw, "security");
		const observer = ensureObject(security, "observer");
		observer.enabled = true;
		actions.push({
			kind: "config",
			target: "security.observer.enabled",
			description: "Enable observer in strict profile for LLM classification",
			before: "false",
			after: "true",
			applied: true,
		});
	}

	return { config: raw, actions };
}

// ═══════════════════════════════════════════════════════════════════════════════
// File permission fixers
// ═══════════════════════════════════════════════════════════════════════════════

function applyFilesystemFixes(cwd: string): FixAction[] {
	const actions: FixAction[] = [];
	const homeDir = os.homedir();

	// Config files — should be 600 (files) or 700 (dirs)
	const configFiles = [
		{
			label: "telclaude.json (policy config)",
			path: path.join(cwd, "docker", "telclaude.json"),
			mode: 0o600,
		},
		{
			label: "telclaude-private.json (private config)",
			path: path.join(cwd, "docker", "telclaude-private.json"),
			mode: 0o600,
		},
		{ label: "docker/.env (secrets)", path: path.join(cwd, "docker", ".env"), mode: 0o600 },
	];

	for (const { label, path: filePath, mode } of configFiles) {
		actions.push(safeChmod(filePath, mode, label));
	}

	// Sensitive system paths
	const sensitivePaths = [
		{ label: "SSH directory", path: path.join(homeDir, ".ssh"), mode: 0o700 },
		{ label: "AWS credentials", path: path.join(homeDir, ".aws", "credentials"), mode: 0o600 },
		{ label: "telclaude data dir", path: path.join(homeDir, ".telclaude"), mode: 0o700 },
		{
			label: "telclaude database",
			path: path.join(homeDir, ".telclaude", "telclaude.db"),
			mode: 0o600,
		},
		{ label: "Audit log directory", path: path.join(homeDir, ".telclaude", "logs"), mode: 0o700 },
	];

	for (const { label, path: filePath, mode } of sensitivePaths) {
		actions.push(safeChmod(filePath, mode, label));
	}

	return actions;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Hook hardening fixers
// ═══════════════════════════════════════════════════════════════════════════════

function applyHookHardeningFixes(cwd: string): FixAction[] {
	const actions: FixAction[] = [];
	const claudeDir = path.join(cwd, ".claude");
	const settingsFile = path.join(claudeDir, "settings.json");

	if (fs.existsSync(settingsFile)) {
		try {
			const raw = fs.readFileSync(settingsFile, "utf-8");
			const settings = JSON.parse(raw) as Record<string, unknown>;
			let modified = false;

			// Fix: add settingSources if missing
			if (!settings.settingSources) {
				settings.settingSources = ["project"];
				actions.push({
					kind: "config",
					target: ".claude/settings.json → settingSources",
					description: "Add settingSources restriction to prevent user-level overrides",
					before: "undefined",
					after: '["project"]',
					applied: true,
				});
				modified = true;
			}

			// Fix: remove disableAllHooks if true
			if (settings.disableAllHooks === true) {
				delete settings.disableAllHooks;
				actions.push({
					kind: "config",
					target: ".claude/settings.json → disableAllHooks",
					description: "Remove disableAllHooks to restore PreToolUse security hooks",
					before: "true",
					after: "(removed)",
					applied: true,
				});
				modified = true;
			}

			if (modified) {
				atomicJsonWrite(settingsFile, `${JSON.stringify(settings, null, "\t")}\n`);
			}
		} catch {
			// Parse error — don't touch a broken file
		}

		// Tighten permissions on settings.json
		actions.push(safeChmod(settingsFile, 0o600, ".claude/settings.json"));
	} else {
		// Create settings.json with proper isolation
		if (!fs.existsSync(claudeDir)) {
			fs.mkdirSync(claudeDir, { recursive: true });
		}
		const content = JSON.stringify({ settingSources: ["project"] }, null, "\t");
		atomicJsonWrite(settingsFile, `${content}\n`);
		actions.push({
			kind: "create",
			target: settingsFile,
			description: "Create .claude/settings.json with settingSources isolation",
			before: null,
			after: '{"settingSources": ["project"]}',
			applied: true,
		});
	}

	// Fix settings.local.json disableAllHooks
	const localSettingsFile = path.join(claudeDir, "settings.local.json");
	if (fs.existsSync(localSettingsFile)) {
		try {
			const raw = fs.readFileSync(localSettingsFile, "utf-8");
			const localSettings = JSON.parse(raw) as Record<string, unknown>;

			if (localSettings.disableAllHooks === true) {
				delete localSettings.disableAllHooks;
				atomicJsonWrite(localSettingsFile, `${JSON.stringify(localSettings, null, "\t")}\n`);
				actions.push({
					kind: "config",
					target: ".claude/settings.local.json → disableAllHooks",
					description: "Remove disableAllHooks from local settings to restore security hooks",
					before: "true",
					after: "(removed)",
					applied: true,
				});
			}
		} catch {
			// Parse error — skip
		}

		actions.push(safeChmod(localSettingsFile, 0o600, ".claude/settings.local.json"));
	}

	return actions;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main runner
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Run all auto-remediation fixers.
 *
 * Only applies "safe" fixes:
 *   - Permission tightening (never loosens)
 *   - Conservative config defaults (test → simple, FULL_ACCESS → READ_ONLY)
 *   - settingSources isolation
 *
 * Config decisions AND writes are derived solely from the RAW policy file (JSON5.parse
 * of `configPath` only — no `loadConfig()`, no runtime/private overlays, no Zod
 * defaults). `loadConfig()` always deep-merges the `*.runtime.json` overlay (and, when
 * `TELCLAUDE_PRIVATE_CONFIG` is set, the private overlay), so consulting the merged
 * config could fold an overlay value or a defaulted value into the agent-facing policy
 * file. Reading only the raw policy file means we fix exactly what the operator wrote
 * there and nothing else; a dangerous value that lives only in an overlay is invisible
 * here by design and the policy file is left untouched.
 *
 * Writes use atomic write + backup (write to .tmp, rename, keep .bak). JSON5 comments in
 * the policy file are lost on rewrite (JSON.stringify output is plain JSON); a warning is
 * emitted to make that disclosure visible to the operator.
 *
 * `_cfg` (the merged, loadConfig()-produced config) is intentionally NOT consulted for
 * config decisions — doing so would reintroduce the overlay/default leak. It is kept in
 * the signature for caller compatibility and so callers don't have to recompute it.
 */
export function runAutoFix(
	_cfg: TelclaudeConfig,
	configPath: string,
	cwd: string,
	env: NodeJS.ProcessEnv = process.env,
): FixReport {
	const allActions: FixAction[] = [];
	const warnings: string[] = [];
	let configBackupPath: string | null = null;

	// 1. Config fixes — never write merged config back; decide and patch off the raw
	// policy file only. The parse, the fix decisions (ensureObject/readObject can throw
	// on a malformed security subtree), and the write all run inside one try/catch so a
	// broken policy file fails with a clear operator-facing message, not an uncaught
	// exception.
	const configActions: FixAction[] = [];
	try {
		let raw: RawConfig = {};
		if (fs.existsSync(configPath)) {
			raw = JSON5.parse(fs.readFileSync(configPath, "utf-8")) as RawConfig;
		}

		const configResult = applyConfigFixes(raw, env);
		configActions.push(...configResult.actions);
		const hasAppliedFix = configResult.actions.some((a) => a.applied);

		if (hasAppliedFix) {
			const content = `${JSON.stringify(configResult.config, null, "\t")}\n`;
			const { backupPath } = atomicConfigWrite(configPath, content);
			configBackupPath = backupPath;
			const warning =
				"Rewriting the policy config drops JSON5 comments; review the regenerated file (a .bak of the original was kept).";
			warnings.push(warning);
			logger.warn({ configPath, backupPath }, warning);
		}
	} catch (err) {
		// Parse error, malformed security subtree, or atomic write failure: do not leave a
		// half-applied state. Surface a single clear error action so the operator knows the
		// policy file needs manual attention.
		configActions.length = 0;
		configActions.push({
			kind: "config",
			target: configPath,
			description: "Apply safe policy-config remediations",
			before: null,
			after: "(no change)",
			applied: false,
			error: `Could not auto-fix policy config (it may be malformed): ${String(err)}`,
		});
	}
	allActions.push(...configActions);

	// 2. Filesystem permission fixes
	allActions.push(...applyFilesystemFixes(cwd));

	// 3. Hook hardening fixes
	allActions.push(...applyHookHardeningFixes(cwd));

	// Build summary
	let applied = 0;
	let skipped = 0;
	let errors = 0;
	for (const action of allActions) {
		if (action.applied) applied++;
		else if (action.error) errors++;
		else skipped++;
	}

	return {
		actions: allActions,
		configBackupPath,
		warnings: warnings.length > 0 ? warnings : undefined,
		summary: { applied, skipped, errors },
	};
}

/**
 * Format a fix report for console output.
 */
export function formatFixReport(report: FixReport): string {
	const lines: string[] = [];
	const { actions, configBackupPath, summary } = report;

	// Show applied fixes
	const applied = actions.filter((a) => a.applied);
	if (applied.length > 0) {
		lines.push("\n   APPLIED:");
		for (const action of applied) {
			const arrow = action.before ? `${action.before} -> ${action.after}` : action.after;
			lines.push(`     [${action.kind}] ${action.description}`);
			lines.push(`       ${action.target}: ${arrow}`);
		}
	}

	// Show skipped (only interesting ones — not "file not found")
	const skippedInteresting = actions.filter(
		(a) => !a.applied && !a.error && a.skipped && a.skipped !== "file not found",
	);
	if (skippedInteresting.length > 0) {
		lines.push("\n   SKIPPED:");
		for (const action of skippedInteresting) {
			lines.push(`     [${action.kind}] ${action.description}: ${action.skipped}`);
		}
	}

	// Show errors
	const errored = actions.filter((a) => a.error);
	if (errored.length > 0) {
		lines.push("\n   ERRORS:");
		for (const action of errored) {
			lines.push(`     [${action.kind}] ${action.description}: ${action.error}`);
		}
	}

	// Backup info
	if (configBackupPath) {
		lines.push(`\n   Config backup: ${configBackupPath}`);
	}

	// Warnings (e.g., JSON5 comment loss on rewrite)
	if (report.warnings && report.warnings.length > 0) {
		lines.push("\n   WARNINGS:");
		for (const warning of report.warnings) {
			lines.push(`     ${warning}`);
		}
	}

	// Summary
	lines.push(
		`\n   Summary: ${summary.applied} applied, ${summary.skipped} skipped, ${summary.errors} errors`,
	);

	if (summary.errors > 0) {
		lines.push("   Status: PARTIAL — some fixes could not be applied");
	} else if (summary.applied > 0) {
		lines.push("   Status: FIXED — all applicable remediations applied");
	} else {
		lines.push("   Status: CLEAN — nothing to fix");
	}

	return lines.join("\n");
}
