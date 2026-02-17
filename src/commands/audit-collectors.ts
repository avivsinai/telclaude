/**
 * Deep security audit collectors for `doctor --security`.
 *
 * Each collector returns structured findings with severity levels,
 * category, and optional remediation. Inspired by OpenClaw's
 * audit-extra pattern, adapted to telclaude's architecture.
 *
 * Categories:
 *   config   — dangerous settings, permissive modes, missing security
 *   fs       — file permission issues on config/auth/data files
 *   skills   — untrusted or malicious skill patterns
 *   hooks    — disableAllHooks bypass vectors, settings isolation
 *   exposure — tier-to-capability mapping, over-permissive configs
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { TelclaudeConfig } from "../config/config.js";
import { getSandboxMode } from "../sandbox/index.js";
import { auditSandboxPosture } from "../sandbox/validate-config.js";
import { TIER_TOOLS } from "../security/permissions.js";
import { scanAllSkills } from "../security/skill-scanner.js";

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

export type AuditSeverity = "critical" | "warning" | "info";

export type AuditFinding = {
	/** Severity level: critical requires immediate action, warning is best-effort, info is informational. */
	severity: AuditSeverity;
	/** Category grouping (config, fs, skills, hooks, exposure). */
	category: string;
	/** Human-readable description of the finding. */
	message: string;
	/** Optional remediation instruction. */
	fix?: string;
};

export type AuditReport = {
	findings: AuditFinding[];
	summary: Record<AuditSeverity, number>;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════════

function countBySeverity(findings: AuditFinding[]): Record<AuditSeverity, number> {
	let critical = 0;
	let warning = 0;
	let info = 0;
	for (const f of findings) {
		if (f.severity === "critical") critical++;
		else if (f.severity === "warning") warning++;
		else info++;
	}
	return { critical, warning, info };
}

function checkFilePermissions(filePath: string, label: string, category: string): AuditFinding[] {
	const findings: AuditFinding[] = [];
	if (!fs.existsSync(filePath)) return findings;

	try {
		const stat = fs.lstatSync(filePath);

		// Symlink check
		if (stat.isSymbolicLink()) {
			findings.push({
				severity: "warning",
				category,
				message: `${label} is a symlink — ensure you trust the target`,
				fix: `Verify symlink target: readlink ${filePath}`,
			});
			return findings;
		}

		const mode = stat.mode & 0o777;
		const worldWritable = (mode & 0o002) !== 0;
		const worldReadable = (mode & 0o004) !== 0;
		const groupWritable = (mode & 0o020) !== 0;
		const groupReadable = (mode & 0o040) !== 0;

		if (worldWritable || groupWritable) {
			findings.push({
				severity: "critical",
				category,
				message: `${label} is writable by others (mode ${mode.toString(8)})`,
				fix: `chmod ${stat.isDirectory() ? "700" : "600"} ${filePath}`,
			});
		} else if (worldReadable) {
			findings.push({
				severity: "critical",
				category,
				message: `${label} is world-readable (mode ${mode.toString(8)})`,
				fix: `chmod ${stat.isDirectory() ? "700" : "600"} ${filePath}`,
			});
		} else if (groupReadable) {
			findings.push({
				severity: "warning",
				category,
				message: `${label} is group-readable (mode ${mode.toString(8)})`,
				fix: `chmod ${stat.isDirectory() ? "700" : "600"} ${filePath}`,
			});
		}
	} catch {
		// Cannot stat — skip
	}

	return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Config collectors
// ═══════════════════════════════════════════════════════════════════════════════

export function collectConfigFindings(
	cfg: TelclaudeConfig,
	env: NodeJS.ProcessEnv = process.env,
): AuditFinding[] {
	const findings: AuditFinding[] = [];

	// 1. Test profile in production
	if (cfg.security.profile === "test") {
		const isTestEnvEnabled = env.TELCLAUDE_ENABLE_TEST_PROFILE === "1";
		findings.push({
			severity: isTestEnvEnabled ? "warning" : "critical",
			category: "config",
			message: "Security profile is 'test' — ALL security layers disabled",
			fix: "Set security.profile to 'simple' or 'strict' for production use",
		});
	}

	// 2. Permissive network mode
	const networkMode = env.TELCLAUDE_NETWORK_MODE;
	if (networkMode === "open") {
		findings.push({
			severity: "critical",
			category: "config",
			message: "TELCLAUDE_NETWORK_MODE=open — wildcard egress enabled, only metadata blocked",
			fix: "Remove TELCLAUDE_NETWORK_MODE or set to 'permissive' for tighter control",
		});
	} else if (networkMode === "permissive") {
		findings.push({
			severity: "warning",
			category: "config",
			message: "TELCLAUDE_NETWORK_MODE=permissive — broader WebFetch egress allowed",
			fix: "Remove TELCLAUDE_NETWORK_MODE for strict allowlist enforcement",
		});
	}

	// 3. Observer disabled in strict profile
	if (cfg.security.profile === "strict" && cfg.security.observer?.enabled === false) {
		findings.push({
			severity: "warning",
			category: "config",
			message: "Observer is disabled in strict profile — LLM classification will not run",
			fix: "Remove security.observer.enabled or set to true",
		});
	}

	// 4. Default tier too permissive
	const defaultTier = cfg.security.permissions?.defaultTier ?? "READ_ONLY";
	if (defaultTier === "FULL_ACCESS") {
		findings.push({
			severity: "critical",
			category: "config",
			message: "Default permission tier is FULL_ACCESS — all users get unrestricted access",
			fix: "Set security.permissions.defaultTier to READ_ONLY or WRITE_LOCAL",
		});
	} else if (defaultTier === "WRITE_LOCAL") {
		findings.push({
			severity: "warning",
			category: "config",
			message: "Default permission tier is WRITE_LOCAL — new users can write files by default",
			fix: "Consider setting security.permissions.defaultTier to READ_ONLY",
		});
	}

	// 5. Rate limits disabled or very high
	if (!cfg.security.rateLimits?.perUser) {
		findings.push({
			severity: "info",
			category: "config",
			message: "Per-user rate limits not configured — using defaults",
		});
	} else {
		const perMin = cfg.security.rateLimits.perUser.perMinute;
		if (perMin !== undefined && perMin > 30) {
			findings.push({
				severity: "warning",
				category: "config",
				message: `Per-user rate limit is high (${perMin}/min) — consider lowering for cost control`,
			});
		}
	}

	// 6. Audit logging disabled
	if (cfg.security.audit?.enabled === false) {
		findings.push({
			severity: "warning",
			category: "config",
			message: "Audit logging is disabled — no forensic trail for security events",
			fix: "Set security.audit.enabled to true",
		});
	}

	// 7. Exposed sensitive env vars (when running as relay — not in agent containers)
	const sensitiveEnvVars = [
		"TELEGRAM_BOT_TOKEN",
		"ANTHROPIC_API_KEY",
		"OPENAI_API_KEY",
		"GITHUB_TOKEN",
		"GH_TOKEN",
	];
	const exposedVars = sensitiveEnvVars.filter((v) => env[v]);
	if (exposedVars.length > 0) {
		findings.push({
			severity: "info",
			category: "config",
			message: `Sensitive env vars present: ${exposedVars.join(", ")}`,
		});
	}

	// 8. Video processing enabled (FFmpeg security risk)
	if (cfg.videoProcessing?.enabled === true) {
		findings.push({
			severity: "warning",
			category: "config",
			message: "Video processing is enabled — FFmpeg runs unsandboxed with parsing vulnerabilities",
			fix: "Disable videoProcessing unless you trust all users in allowedChats",
		});
	}

	// 9. TOTP session TTL very long
	const totpTtl = cfg.security.totp?.sessionTtlMinutes;
	if (totpTtl !== undefined && totpTtl > 480) {
		findings.push({
			severity: "warning",
			category: "config",
			message: `TOTP session TTL is ${totpTtl} minutes (${(totpTtl / 60).toFixed(1)}h) — consider shortening`,
			fix: "Set security.totp.sessionTtlMinutes to 240 or less",
		});
	}

	return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Filesystem collectors
// ═══════════════════════════════════════════════════════════════════════════════

export function collectFilesystemFindings(cwd: string): AuditFinding[] {
	const findings: AuditFinding[] = [];
	const homeDir = os.homedir();

	// Config files
	const configPaths = [
		{ label: "telclaude.json (policy config)", path: path.join(cwd, "docker", "telclaude.json") },
		{
			label: "telclaude-private.json (private config)",
			path: path.join(cwd, "docker", "telclaude-private.json"),
		},
		{ label: "docker/.env (secrets)", path: path.join(cwd, "docker", ".env") },
	];

	for (const { label, path: filePath } of configPaths) {
		findings.push(...checkFilePermissions(filePath, label, "fs"));
	}

	// Sensitive system paths
	const sensitivePaths = [
		{ label: "SSH directory", path: path.join(homeDir, ".ssh") },
		{ label: "AWS credentials", path: path.join(homeDir, ".aws", "credentials") },
		{ label: "telclaude database", path: path.join(homeDir, ".telclaude", "telclaude.db") },
		{ label: "telclaude data dir", path: path.join(homeDir, ".telclaude") },
	];

	for (const { label, path: filePath } of sensitivePaths) {
		findings.push(...checkFilePermissions(filePath, label, "fs"));
	}

	// Audit log directory permissions
	const auditLogDir = path.join(homeDir, ".telclaude", "logs");
	findings.push(...checkFilePermissions(auditLogDir, "Audit log directory", "fs"));

	// Check for .env in project root (common mistake)
	const rootEnv = path.join(cwd, ".env");
	if (fs.existsSync(rootEnv)) {
		findings.push({
			severity: "warning",
			category: "fs",
			message: ".env file exists in project root — secrets may be committed to git",
			fix: "Ensure .env is in .gitignore and move secrets to docker/.env",
		});
	}

	return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Skill trust collectors
// ═══════════════════════════════════════════════════════════════════════════════

export function collectSkillTrustFindings(cwd: string): AuditFinding[] {
	const findings: AuditFinding[] = [];

	const skillRoots = [
		path.join(cwd, ".claude", "skills"),
		path.join(cwd, ".claude", "skills-draft"),
	];

	// Also check CLAUDE_CONFIG_DIR skills (Docker profiles)
	const configDir = process.env.CLAUDE_CONFIG_DIR;
	if (configDir) {
		skillRoots.push(path.join(configDir, "skills"));
	}

	let totalSkills = 0;
	let blockedSkills = 0;
	let warningSkills = 0;

	for (const root of skillRoots) {
		if (!fs.existsSync(root)) continue;

		const results = scanAllSkills(root);
		for (const result of results) {
			totalSkills++;
			if (result.blocked) {
				blockedSkills++;
				findings.push({
					severity: "critical",
					category: "skills",
					message: `Skill "${result.skillName}" contains dangerous patterns (${result.counts.critical} critical, ${result.counts.high} high)`,
					fix: `Review and remove: ${result.skillPath}`,
				});
			} else if (result.counts.medium > 0 || result.counts.info > 0) {
				warningSkills++;
				findings.push({
					severity: "warning",
					category: "skills",
					message: `Skill "${result.skillName}" has ${result.counts.medium} medium, ${result.counts.info} info findings`,
					fix: `Review: ${result.skillPath}`,
				});
			}
		}
	}

	// Skills-draft directory exists — draft skills are unvetted
	const draftDir = path.join(cwd, ".claude", "skills-draft");
	if (fs.existsSync(draftDir)) {
		try {
			const entries = fs.readdirSync(draftDir, { withFileTypes: true });
			const draftCount = entries.filter((e) => e.isDirectory()).length;
			if (draftCount > 0) {
				findings.push({
					severity: "warning",
					category: "skills",
					message: `${draftCount} skill(s) in skills-draft/ — unvetted skills should not be promoted without review`,
					fix: "Run telclaude doctor --skills to scan draft skills",
				});
			}
		} catch {
			// ignore
		}
	}

	if (totalSkills > 0 && blockedSkills === 0 && warningSkills === 0) {
		findings.push({
			severity: "info",
			category: "skills",
			message: `${totalSkills} skill(s) scanned — all clean`,
		});
	}

	return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Hook hardening collectors
// ═══════════════════════════════════════════════════════════════════════════════

export function collectHookHardeningFindings(cwd: string): AuditFinding[] {
	const findings: AuditFinding[] = [];

	// 1. Check .claude/settings.json for settingSources restriction
	const claudeDir = path.join(cwd, ".claude");
	const settingsFile = path.join(claudeDir, "settings.json");

	if (fs.existsSync(settingsFile)) {
		try {
			const settings = JSON.parse(fs.readFileSync(settingsFile, "utf-8"));

			// settingSources should restrict to "project" to prevent user-level overrides
			const sources = settings.settingSources;
			if (!sources) {
				findings.push({
					severity: "critical",
					category: "hooks",
					message: "settingSources not configured — user-level settings can override project hooks",
					fix: 'Add "settingSources": ["project"] to .claude/settings.json',
				});
			} else if (Array.isArray(sources) && !sources.includes("project")) {
				findings.push({
					severity: "critical",
					category: "hooks",
					message: `settingSources does not include "project" — project hooks may not load`,
					fix: 'Add "project" to settingSources array in .claude/settings.json',
				});
			} else if (Array.isArray(sources) && sources.includes("project")) {
				// Check for "user" in sources which could allow disableAllHooks bypass
				if (sources.includes("user")) {
					findings.push({
						severity: "warning",
						category: "hooks",
						message: 'settingSources includes "user" — user-level settings can override hooks',
						fix: 'Remove "user" from settingSources to prevent disableAllHooks bypass',
					});
				}
			}

			// 2. Check if disableAllHooks is explicitly set (should never be true)
			if (settings.disableAllHooks === true) {
				findings.push({
					severity: "critical",
					category: "hooks",
					message: "disableAllHooks is TRUE — all PreToolUse security hooks are disabled",
					fix: "Remove disableAllHooks from .claude/settings.json immediately",
				});
			}
		} catch {
			findings.push({
				severity: "warning",
				category: "hooks",
				message: "Failed to parse .claude/settings.json",
				fix: "Verify the file contains valid JSON",
			});
		}
	} else {
		findings.push({
			severity: "warning",
			category: "hooks",
			message: ".claude/settings.json not found — SDK settings isolation not configured",
			fix: 'Create .claude/settings.json with {"settingSources": ["project"]}',
		});
	}

	// 3. Check settings.local.json (user override file)
	const localSettingsFile = path.join(claudeDir, "settings.local.json");
	if (fs.existsSync(localSettingsFile)) {
		try {
			const localSettings = JSON.parse(fs.readFileSync(localSettingsFile, "utf-8"));
			if (localSettings.disableAllHooks === true) {
				findings.push({
					severity: "critical",
					category: "hooks",
					message: "disableAllHooks is TRUE in settings.local.json — security hooks bypassed",
					fix: "Remove disableAllHooks from .claude/settings.local.json immediately",
				});
			}
		} catch {
			// Parse error is non-critical for local settings
		}
	}

	// 4. Verify settings files have restricted permissions
	findings.push(...checkFilePermissions(settingsFile, ".claude/settings.json", "hooks"));
	findings.push(...checkFilePermissions(localSettingsFile, ".claude/settings.local.json", "hooks"));

	return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Exposure matrix collectors
// ═══════════════════════════════════════════════════════════════════════════════

export function collectExposureMatrixFindings(cfg: TelclaudeConfig): AuditFinding[] {
	const findings: AuditFinding[] = [];
	const sandboxMode = getSandboxMode();

	// Build exposure summary
	const tierNames = Object.keys(TIER_TOOLS) as Array<keyof typeof TIER_TOOLS>;
	const matrixLines: string[] = [];

	for (const tier of tierNames) {
		const tools = TIER_TOOLS[tier];
		const toolList = tools.length === 0 ? "ALL TOOLS" : tools.join(", ");
		matrixLines.push(`  ${tier}: ${toolList}`);
	}

	findings.push({
		severity: "info",
		category: "exposure",
		message: `Tier-to-tool exposure matrix (${sandboxMode} mode):\n${matrixLines.join("\n")}`,
	});

	// Check for users with FULL_ACCESS
	const users = cfg.security.permissions?.users ?? {};
	const fullAccessUsers = Object.entries(users).filter(([, perm]) => perm.tier === "FULL_ACCESS");

	if (fullAccessUsers.length > 0) {
		findings.push({
			severity: "info",
			category: "exposure",
			message: `${fullAccessUsers.length} user(s) with FULL_ACCESS: ${fullAccessUsers.map(([id]) => id).join(", ")}`,
		});
	}

	// Social tier with Bash access
	const socialUsers = Object.entries(users).filter(([, perm]) => perm.tier === "SOCIAL");
	if (socialUsers.length > 0) {
		findings.push({
			severity: "info",
			category: "exposure",
			message: `${socialUsers.length} user(s) with SOCIAL tier (Bash trust-gated)`,
		});
	}

	// No user permissions configured at all
	if (!cfg.security.permissions) {
		findings.push({
			severity: "warning",
			category: "exposure",
			message: "No user permissions configured — all users get the default tier",
			fix: "Configure security.permissions.users for named users",
		});
	}

	// Check for social services with elevated access
	const enabledSocialServices = cfg.socialServices.filter((s) => s.enabled);
	if (enabledSocialServices.length > 0) {
		const withSkills = enabledSocialServices.filter((s) => s.enableSkills);
		if (withSkills.length > 0) {
			findings.push({
				severity: "warning",
				category: "exposure",
				message: `${withSkills.length} social service(s) have enableSkills=true: ${withSkills.map((s) => s.id).join(", ")}`,
				fix: "Ensure skills are appropriate for autonomous social posting",
			});
		}
	}

	return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Docker compose collectors
// ═══════════════════════════════════════════════════════════════════════════════

export function collectDockerComposeFindings(cwd: string): AuditFinding[] {
	const composePath = path.join(cwd, "docker", "docker-compose.yml");
	if (!fs.existsSync(composePath)) {
		// Keep historical collector behavior for callers/tests:
		// missing compose is treated as "no docker findings".
		return [];
	}

	const mappedFindings = auditSandboxPosture({ cwd }).map((finding) => {
		let message = `[${finding.category}] ${finding.message}`;

		if (finding.category === "compose.bind_mount" && /docker socket/i.test(finding.message)) {
			message = "Docker socket mount in docker-compose — container can control host Docker daemon";
		} else if (finding.category === "compose.network") {
			message = "Host network mode in docker-compose — bypasses network isolation";
		} else if (finding.category === "compose.privileged") {
			message = "Privileged mode in docker-compose — disables container security boundaries";
		}

		const fix =
			finding.severity === "critical"
				? "Update docker/docker-compose.yml to remove dangerous sandbox settings."
				: finding.severity === "warning"
					? "Review docker/.env and compose settings for least-privilege posture."
					: undefined;
		return {
			severity: finding.severity,
			category: "sandbox",
			message,
			fix,
		};
	});

	// Compatibility fallback: support coarse docker.sock pattern matches even when
	// the compose snippet is not under a parsed service block.
	const composeContent = fs.readFileSync(composePath, "utf8");
	const hasDockerSocket = /(?:^|[\s"'])\/(?:var\/run|run)\/docker\.sock(?:[\s"':]|$)/im.test(
		composeContent,
	);
	if (
		hasDockerSocket &&
		!mappedFindings.some((finding) => finding.message.includes("Docker socket mount"))
	) {
		mappedFindings.push({
			severity: "critical",
			category: "sandbox",
			message: "Docker socket mount in docker-compose — container can control host Docker daemon",
			fix: "Remove docker.sock bind mounts from docker/docker-compose.yml.",
		});
	}

	return mappedFindings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main runner
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Run all audit collectors and return a structured report.
 */
export function runAuditCollectors(
	cfg: TelclaudeConfig,
	cwd: string,
	env: NodeJS.ProcessEnv = process.env,
): AuditReport {
	const findings: AuditFinding[] = [];

	findings.push(...collectConfigFindings(cfg, env));
	findings.push(...collectFilesystemFindings(cwd));
	findings.push(...collectSkillTrustFindings(cwd));
	findings.push(...collectHookHardeningFindings(cwd));
	findings.push(...collectExposureMatrixFindings(cfg));
	findings.push(...collectDockerComposeFindings(cwd));

	return {
		findings,
		summary: countBySeverity(findings),
	};
}

/**
 * Format an audit report for console output, grouped by severity.
 */
export function formatAuditReport(report: AuditReport): string {
	const lines: string[] = [];
	const { findings, summary } = report;

	const severityOrder: AuditSeverity[] = ["critical", "warning", "info"];
	const severityLabels: Record<AuditSeverity, string> = {
		critical: "CRITICAL",
		warning: "WARNING",
		info: "INFO",
	};
	const severityIcons: Record<AuditSeverity, string> = {
		critical: "\u2717", // ✗
		warning: "\u26A0", // ⚠
		info: "\u2139", // ℹ
	};

	for (const severity of severityOrder) {
		const group = findings.filter((f) => f.severity === severity);
		if (group.length === 0) continue;

		lines.push(`\n   ${severityLabels[severity]} (${group.length}):`);
		for (const finding of group) {
			lines.push(`     ${severityIcons[severity]} [${finding.category}] ${finding.message}`);
			if (finding.fix) {
				lines.push(`       Fix: ${finding.fix}`);
			}
		}
	}

	// Summary line
	lines.push(
		`\n   Summary: ${summary.critical} critical, ${summary.warning} warning, ${summary.info} info`,
	);

	if (summary.critical > 0) {
		lines.push("   Status: FAIL — critical issues require immediate attention");
	} else if (summary.warning > 0) {
		lines.push("   Status: WARN — review warnings for potential improvements");
	} else {
		lines.push("   Status: PASS — no issues found");
	}

	return lines.join("\n");
}
