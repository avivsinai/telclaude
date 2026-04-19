/**
 * Skills doctor command.
 *
 * Walks every discovered skill (active and draft), runs the security
 * scanner, and parses frontmatter for structural validity. Emits a
 * pass/warn/fail verdict per skill and exits non-zero on any fail.
 *
 * Designed to run from both the CLI (`telclaude skills doctor`) and the
 * Telegram surface (`/skills doctor`) so operators can spot-check the
 * skill set from their phone.
 */

import fs from "node:fs";
import path from "node:path";
import type { Command } from "commander";
import { getChildLogger } from "../logging.js";
import { type ScanResult, scanSkill } from "../security/skill-scanner.js";
import { getAllSkillRoots, getWritableDraftSkillRootCandidates } from "./skill-path.js";

const logger = getChildLogger({ module: "cmd-skills-doctor" });

export type SkillKind = "active" | "draft";
export type SkillStatus = "pass" | "warn" | "fail";

export type SkillDoctorEntry = {
	name: string;
	kind: SkillKind;
	path: string;
	status: SkillStatus;
	findings: ScanResult["findings"];
	issues: string[];
	/** Count of severities for quick rendering. */
	counts: { critical: number; high: number; medium: number; info: number };
};

export type SkillDoctorReport = {
	entries: SkillDoctorEntry[];
	duplicates: string[];
	failCount: number;
	warnCount: number;
	passCount: number;
};

const REQUIRED_FRONTMATTER_FIELDS = ["name", "description"];
const ALLOWED_TOOL_NAMES = new Set([
	"Read",
	"Write",
	"Edit",
	"Glob",
	"Grep",
	"Bash",
	"WebFetch",
	"WebSearch",
	"NotebookEdit",
	"Skill",
	"Task",
]);

type ParsedFrontmatter = {
	fields: Record<string, string>;
	rawAllowedTools: string[];
	errors: string[];
};

function parseFrontmatter(content: string): ParsedFrontmatter | null {
	const match = content.match(/^---\s*\n([\s\S]*?)\n---/);
	if (!match) return null;

	const fields: Record<string, string> = {};
	const rawAllowedTools: string[] = [];
	const errors: string[] = [];

	const lines = match[1].split("\n");
	let currentKey: string | null = null;
	let collectingList = false;

	for (const rawLine of lines) {
		const line = rawLine.replace(/\r$/, "");
		if (!line.trim()) continue;

		const keyMatch = line.match(/^(\w[\w.-]*)\s*:\s*(.*)$/);
		if (keyMatch) {
			currentKey = keyMatch[1];
			const value = keyMatch[2].trim();
			if (value.length === 0) {
				collectingList = currentKey === "allowed-tools";
				fields[currentKey] = "";
				continue;
			}
			collectingList = false;
			if (currentKey === "allowed-tools") {
				const inlineList = value.replace(/^\[|\]$/g, "").trim();
				if (inlineList.length > 0) {
					for (const item of inlineList.split(",")) {
						const tool = item.trim().replace(/^['"]|['"]$/g, "");
						if (tool) rawAllowedTools.push(tool);
					}
				}
			}
			fields[currentKey] = value;
			continue;
		}

		if (collectingList && /^\s*-\s+/.test(line)) {
			const tool = line
				.replace(/^\s*-\s+/, "")
				.trim()
				.replace(/^['"]|['"]$/g, "");
			if (tool) rawAllowedTools.push(tool);
			continue;
		}

		if (currentKey && /^\s+/.test(line)) {
			// folded continuation line; append to current key value
			fields[currentKey] = `${fields[currentKey] ?? ""} ${line.trim()}`.trim();
			continue;
		}

		// Unknown structure — flag but don't fail.
		errors.push(`Unrecognized frontmatter line: "${line.trim()}"`);
	}

	return { fields, rawAllowedTools, errors };
}

function evaluateSkill(skillDir: string, kind: SkillKind): SkillDoctorEntry {
	const name = path.basename(skillDir);
	const issues: string[] = [];
	let status: SkillStatus = "pass";

	const skillMdPath = path.join(skillDir, "SKILL.md");
	if (!fs.existsSync(skillMdPath)) {
		return {
			name,
			kind,
			path: skillDir,
			status: "fail",
			findings: [],
			issues: ["Missing SKILL.md"],
			counts: { critical: 0, high: 0, medium: 0, info: 0 },
		};
	}

	// Frontmatter parse + required fields + allowed-tools sanity.
	let content: string;
	try {
		content = fs.readFileSync(skillMdPath, "utf8");
	} catch (err) {
		return {
			name,
			kind,
			path: skillDir,
			status: "fail",
			findings: [],
			issues: [`Cannot read SKILL.md: ${String(err)}`],
			counts: { critical: 0, high: 0, medium: 0, info: 0 },
		};
	}

	const parsed = parseFrontmatter(content);
	if (!parsed) {
		issues.push("SKILL.md is missing YAML frontmatter (`---` block).");
		status = "fail";
	} else {
		for (const required of REQUIRED_FRONTMATTER_FIELDS) {
			if (!parsed.fields[required] || parsed.fields[required].trim() === "") {
				issues.push(`Frontmatter missing required field: ${required}`);
				status = "fail";
			}
		}

		const declaredName = parsed.fields.name?.trim();
		if (declaredName && declaredName !== name) {
			issues.push(`Frontmatter name "${declaredName}" does not match directory name "${name}"`);
			status = "fail";
		}

		for (const tool of parsed.rawAllowedTools) {
			if (!ALLOWED_TOOL_NAMES.has(tool)) {
				issues.push(`Unknown tool in allowed-tools: "${tool}"`);
				if (status === "pass") status = "warn";
			}
		}

		for (const err of parsed.errors) {
			issues.push(err);
			if (status === "pass") status = "warn";
		}
	}

	const scan = scanSkill(skillDir);
	if (scan.blocked) {
		issues.push(`Scanner blocked (critical=${scan.counts.critical}, high=${scan.counts.high})`);
		status = "fail";
	} else if (scan.counts.medium > 0 && status === "pass") {
		status = "warn";
	}

	return {
		name,
		kind,
		path: skillDir,
		status,
		findings: scan.findings,
		issues,
		counts: scan.counts,
	};
}

function collectSkillsFromRoots(roots: string[], kind: SkillKind): SkillDoctorEntry[] {
	const seen = new Map<string, SkillDoctorEntry>();
	for (const root of roots) {
		if (!fs.existsSync(root)) continue;
		let entries: fs.Dirent[];
		try {
			entries = fs.readdirSync(root, { withFileTypes: true });
		} catch {
			continue;
		}
		for (const entry of entries) {
			if (entry.name.startsWith(".")) continue;
			const skillDir = path.join(root, entry.name);
			// Accept either a real directory or a symlink to a directory.
			let isDirLike = entry.isDirectory();
			if (!isDirLike && entry.isSymbolicLink()) {
				try {
					isDirLike = fs.statSync(skillDir).isDirectory();
				} catch {
					isDirLike = false;
				}
			}
			if (!isDirLike) continue;
			// For multiple active roots, prefer the earliest (highest-priority) occurrence.
			if (seen.has(entry.name)) continue;
			const evaluated = evaluateSkill(skillDir, kind);
			seen.set(entry.name, evaluated);
		}
	}
	return [...seen.values()];
}

/**
 * Build the doctor report across active and draft skill dirs. Flags duplicates
 * (same name appearing in both active and draft).
 */
export function runSkillsDoctor(options?: {
	cwd?: string;
	activeRoots?: string[];
	draftRoots?: string[];
}): SkillDoctorReport {
	const activeRoots = options?.activeRoots ?? getAllSkillRoots(options?.cwd);
	const draftRoots = options?.draftRoots ?? getWritableDraftSkillRootCandidates(options?.cwd);

	const active = collectSkillsFromRoots(activeRoots, "active");
	const draft = collectSkillsFromRoots(draftRoots, "draft");

	const duplicates: string[] = [];
	const activeNames = new Set(active.map((e) => e.name));
	for (const entry of draft) {
		if (activeNames.has(entry.name)) {
			duplicates.push(entry.name);
			entry.issues.push(`Duplicate: a skill named "${entry.name}" is already active.`);
			if (entry.status === "pass") entry.status = "warn";
		}
	}

	const entries = [...active, ...draft].sort((a, b) => {
		if (a.kind !== b.kind) return a.kind === "active" ? -1 : 1;
		return a.name.localeCompare(b.name);
	});

	const passCount = entries.filter((e) => e.status === "pass").length;
	const warnCount = entries.filter((e) => e.status === "warn").length;
	const failCount = entries.filter((e) => e.status === "fail").length;

	logger.debug({ passCount, warnCount, failCount, duplicates }, "skills-doctor evaluation");

	return { entries, duplicates, passCount, warnCount, failCount };
}

function statusIcon(status: SkillStatus): string {
	switch (status) {
		case "pass":
			return "[PASS]";
		case "warn":
			return "[WARN]";
		case "fail":
			return "[FAIL]";
	}
}

export function formatReportForCli(report: SkillDoctorReport): string {
	const lines: string[] = [];
	lines.push("=== telclaude skills doctor ===");
	lines.push("");

	if (report.entries.length === 0) {
		lines.push("No skills found.");
		return lines.join("\n");
	}

	for (const entry of report.entries) {
		lines.push(`${statusIcon(entry.status)} ${entry.kind.padEnd(6)} ${entry.name}`);
		lines.push(`       path: ${entry.path}`);
		if (entry.issues.length > 0) {
			for (const issue of entry.issues) {
				lines.push(`       - ${issue}`);
			}
		}
		if (entry.counts.critical > 0 || entry.counts.high > 0 || entry.counts.medium > 0) {
			lines.push(
				`       scanner: critical=${entry.counts.critical} high=${entry.counts.high} medium=${entry.counts.medium} info=${entry.counts.info}`,
			);
		}
	}

	lines.push("");
	lines.push(
		`Summary: ${report.passCount} pass, ${report.warnCount} warn, ${report.failCount} fail${
			report.duplicates.length > 0 ? `, duplicates: ${report.duplicates.join(", ")}` : ""
		}`,
	);

	return lines.join("\n");
}

/**
 * Compact output for Telegram — one line per skill, capped length.
 */
export function formatReportForTelegram(report: SkillDoctorReport, limit = 30): string {
	const lines: string[] = [];
	lines.push(
		`skills doctor: ${report.passCount} pass, ${report.warnCount} warn, ${report.failCount} fail`,
	);
	if (report.duplicates.length > 0) {
		lines.push(`duplicates: ${report.duplicates.join(", ")}`);
	}
	lines.push("");

	for (const entry of report.entries.slice(0, limit)) {
		const suffix = entry.issues.length > 0 ? ` — ${entry.issues[0]}` : "";
		lines.push(`${statusIcon(entry.status)} ${entry.kind} ${entry.name}${suffix}`);
	}
	if (report.entries.length > limit) {
		lines.push(`…and ${report.entries.length - limit} more.`);
	}
	return lines.join("\n");
}

/**
 * Register the doctor subcommand under `telclaude skills doctor`.
 */
export function registerSkillsDoctorSubcommand(parent: Command): void {
	parent
		.command("doctor")
		.description("Validate every active and draft skill (frontmatter + scanner)")
		.option("--json", "Emit machine-readable JSON")
		.action((options: { json?: boolean }) => {
			const report = runSkillsDoctor();
			if (options.json) {
				console.log(JSON.stringify(report, null, 2));
			} else {
				console.log(formatReportForCli(report));
			}
			if (report.failCount > 0) {
				process.exitCode = 1;
			}
		});
}
