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
import type { TelclaudeConfig } from "../config/config.js";

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

		// Only tighten — never loosen permissions
		if (currentMode < targetMode) {
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

// ═══════════════════════════════════════════════════════════════════════════════
// Config fixers
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Apply safe config fixes. Returns the modified config and a list of actions taken.
 * Only modifies values that the audit collectors flagged as dangerous.
 */
function applyConfigFixes(
	cfg: TelclaudeConfig,
	env: NodeJS.ProcessEnv,
): { config: TelclaudeConfig; actions: FixAction[] } {
	const actions: FixAction[] = [];

	// Deep clone to avoid mutating the original
	const next = JSON.parse(JSON.stringify(cfg)) as TelclaudeConfig;

	// 1. Test profile → simple
	if (next.security.profile === "test") {
		const isTestEnvEnabled = env.TELCLAUDE_ENABLE_TEST_PROFILE === "1";
		if (!isTestEnvEnabled) {
			actions.push({
				kind: "config",
				target: "security.profile",
				description: "Change test profile to simple (production-safe default)",
				before: "test",
				after: "simple",
				applied: true,
			});
			next.security.profile = "simple";
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
	const defaultTier = next.security.permissions?.defaultTier;
	if (defaultTier === "FULL_ACCESS") {
		if (!next.security.permissions) {
			next.security.permissions = { defaultTier: "READ_ONLY", users: {} };
		} else {
			next.security.permissions.defaultTier = "READ_ONLY";
		}
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
	if (next.security.audit?.enabled === false) {
		next.security.audit.enabled = true;
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
	if (next.security.profile === "strict" && next.security.observer?.enabled === false) {
		next.security.observer.enabled = true;
		actions.push({
			kind: "config",
			target: "security.observer.enabled",
			description: "Enable observer in strict profile for LLM classification",
			before: "false",
			after: "true",
			applied: true,
		});
	}

	return { config: next, actions };
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
				fs.writeFileSync(settingsFile, `${JSON.stringify(settings, null, "\t")}\n`, "utf-8");
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
		fs.writeFileSync(settingsFile, `${content}\n`, "utf-8");
		fs.chmodSync(settingsFile, 0o600);
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
				fs.writeFileSync(
					localSettingsFile,
					`${JSON.stringify(localSettings, null, "\t")}\n`,
					"utf-8",
				);
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
 * Config writes use atomic write + backup (write to .tmp, rename, keep .bak).
 */
export function runAutoFix(
	cfg: TelclaudeConfig,
	configPath: string,
	cwd: string,
	env: NodeJS.ProcessEnv = process.env,
): FixReport {
	const allActions: FixAction[] = [];
	let configBackupPath: string | null = null;

	// 1. Config fixes (requires atomic write)
	const configResult = applyConfigFixes(cfg, env);
	const configActionsApplied = configResult.actions.filter((a) => a.applied);

	if (configActionsApplied.length > 0) {
		try {
			const content = `${JSON.stringify(configResult.config, null, "\t")}\n`;
			const { backupPath } = atomicConfigWrite(configPath, content);
			configBackupPath = backupPath;
		} catch (err) {
			// Mark all config actions as failed
			for (const action of configResult.actions) {
				if (action.applied) {
					action.applied = false;
					action.error = `Atomic write failed: ${String(err)}`;
				}
			}
		}
	}
	allActions.push(...configResult.actions);

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
