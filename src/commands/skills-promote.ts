/**
 * Skill promotion command.
 *
 * Promotes agent-drafted skills from quarantine (.claude/skills-draft/)
 * to the active skill directory (.claude/skills/) after validation.
 *
 * Flow:
 * 1. Agent writes to .claude/skills-draft/<name>/SKILL.md (quarantine)
 * 2. Operator reviews via /promote-skill <name> or CLI
 * 3. Scanner + validation runs on the draft
 * 4. On pass, skill is moved to active directory
 * 5. Core security skills are ALWAYS blocked from modification
 */

import fs from "node:fs";
import path from "node:path";
import type { Command } from "commander";
import { getChildLogger } from "../logging.js";
import { scanSkill } from "../security/skill-scanner.js";

const logger = getChildLogger({ module: "cmd-skills-promote" });

/**
 * Skills that can NEVER be modified or replaced.
 * These are core security skills that must remain immutable.
 */
export const IMMUTABLE_SKILL_NAMES = new Set(["security-gate", "telegram-reply"]);

export type PromoteResult = {
	success: boolean;
	skillName: string;
	error?: string;
	scanBlocked?: boolean;
};

/**
 * Promote a skill from draft to active directory.
 */
/** Strict slug pattern for skill names — no path traversal, no special chars. */
const SKILL_NAME_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/;

export function promoteSkill(
	skillName: string,
	draftRoot?: string,
	activeRoot?: string,
): PromoteResult {
	// Validate skill name to prevent path traversal
	if (!SKILL_NAME_PATTERN.test(skillName)) {
		return {
			success: false,
			skillName,
			error: `Invalid skill name "${skillName}". Must match ${SKILL_NAME_PATTERN} (no path separators or traversal).`,
		};
	}

	const cwd = process.cwd();
	const effectiveDraftRoot = draftRoot ?? path.join(cwd, ".claude", "skills-draft");
	const effectiveActiveRoot = activeRoot ?? path.join(cwd, ".claude", "skills");
	const draftDir = path.join(effectiveDraftRoot, skillName);
	const activeDir = path.join(effectiveActiveRoot, skillName);

	// Verify resolved paths stay within their roots (defense in depth)
	const resolvedDraft = path.resolve(draftDir);
	const resolvedActive = path.resolve(activeDir);
	if (!resolvedDraft.startsWith(`${path.resolve(effectiveDraftRoot)}${path.sep}`)) {
		return { success: false, skillName, error: "Path traversal detected in draft path." };
	}
	if (!resolvedActive.startsWith(`${path.resolve(effectiveActiveRoot)}${path.sep}`)) {
		return { success: false, skillName, error: "Path traversal detected in active path." };
	}

	// Check immutable skills
	if (IMMUTABLE_SKILL_NAMES.has(skillName)) {
		logger.warn({ skillName }, "attempted to promote immutable skill");
		return {
			success: false,
			skillName,
			error: `"${skillName}" is an immutable core skill and cannot be replaced.`,
		};
	}

	// Check draft exists
	if (!fs.existsSync(draftDir)) {
		return {
			success: false,
			skillName,
			error: `Draft skill "${skillName}" not found in ${effectiveDraftRoot}`,
		};
	}

	// Check SKILL.md exists
	const skillMd = path.join(draftDir, "SKILL.md");
	if (!fs.existsSync(skillMd)) {
		return {
			success: false,
			skillName,
			error: `Draft "${skillName}" is missing SKILL.md`,
		};
	}

	// Run scanner
	const scanResult = scanSkill(draftDir);
	if (scanResult.blocked) {
		const criticalFindings = scanResult.findings
			.filter((f) => f.severity === "critical" || f.severity === "high")
			.map((f) => `  ${f.severity.toUpperCase()}: ${f.message}`)
			.join("\n");

		logger.warn(
			{ skillName, findings: scanResult.findings.length },
			"draft skill blocked by scanner",
		);
		return {
			success: false,
			skillName,
			error: `Skill "${skillName}" blocked by scanner:\n${criticalFindings}`,
			scanBlocked: true,
		};
	}

	// Move draft to active (overwrite if exists, but not immutable)
	try {
		if (fs.existsSync(activeDir)) {
			fs.rmSync(activeDir, { recursive: true });
		}
		// Copy instead of rename (may be across filesystems)
		copyDirRecursive(draftDir, activeDir);
		// Remove draft after successful copy
		fs.rmSync(draftDir, { recursive: true });
	} catch (err) {
		return {
			success: false,
			skillName,
			error: `Failed to promote: ${err}`,
		};
	}

	logger.info({ skillName }, "skill promoted from draft to active");
	return { success: true, skillName };
}

function copyDirRecursive(source: string, target: string): void {
	fs.mkdirSync(target, { recursive: true });
	const entries = fs.readdirSync(source, { withFileTypes: true });
	for (const entry of entries) {
		const srcPath = path.join(source, entry.name);
		const tgtPath = path.join(target, entry.name);
		if (entry.isDirectory()) {
			copyDirRecursive(srcPath, tgtPath);
		} else if (entry.isFile()) {
			fs.copyFileSync(srcPath, tgtPath);
		}
	}
}

/**
 * List all draft skills awaiting promotion.
 */
export function listDraftSkills(draftRoot?: string): string[] {
	const effectiveDraftRoot = draftRoot ?? path.join(process.cwd(), ".claude", "skills-draft");
	if (!fs.existsSync(effectiveDraftRoot)) return [];

	return fs
		.readdirSync(effectiveDraftRoot, { withFileTypes: true })
		.filter((e) => e.isDirectory())
		.filter((e) => fs.existsSync(path.join(effectiveDraftRoot, e.name, "SKILL.md")))
		.map((e) => e.name);
}

/**
 * Register CLI promote command.
 */
export function registerSkillsPromoteCommand(program: Command): void {
	// This is registered as a subcommand of the existing "skills" command group.
	// Since commander doesn't easily allow adding subcommands after creation,
	// we add it directly here. The caller should integrate this into the skills group.
	program
		.command("promote-skill")
		.description("Promote a draft skill to active")
		.argument("<name>", "Name of the draft skill to promote")
		.action((name: string) => {
			const result = promoteSkill(name);

			if (result.success) {
				console.log(`✓ Skill "${name}" promoted to active. Available next session.`);
			} else {
				console.error(`✗ ${result.error}`);
				process.exitCode = 1;
			}
		});

	program
		.command("list-drafts")
		.description("List draft skills awaiting promotion")
		.action(() => {
			const drafts = listDraftSkills();
			if (drafts.length === 0) {
				console.log("No draft skills found.");
				return;
			}
			console.log(`${drafts.length} draft skill(s) awaiting promotion:`);
			for (const name of drafts) {
				console.log(`  - ${name}`);
			}
		});
}
