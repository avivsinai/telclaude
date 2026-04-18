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
import { copyDirRecursive } from "./cli-utils.js";
import {
	getAllSkillRoots,
	getDraftSkillRoot,
	getSkillRoot,
	getWritableDraftSkillRootCandidates,
} from "./skill-path.js";

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

	// Use canonical root helpers so scaffold → promote → list share the same directories.
	// Explicit overrides (used in tests) still win.
	const effectiveDraftRoot = draftRoot ?? findExistingDraftRootFor(skillName) ?? getDraftSkillRoot();
	const effectiveActiveRoot = activeRoot ?? getSkillRoot();
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

/**
 * Resolve whether a directory entry is a directory, following symlinks.
 * Dirent.isDirectory() returns false for symlinks-to-directories; we resolve
 * the target so symlinked skill layouts (common in this repo where
 * .claude/skills/* → .agents/skills/*) are treated as real skills.
 */
function isSkillDirEntry(root: string, entry: fs.Dirent): boolean {
	if (entry.name.startsWith(".")) return false;
	if (entry.isDirectory()) return true;
	if (!entry.isSymbolicLink()) return false;
	try {
		return fs.statSync(path.join(root, entry.name)).isDirectory();
	} catch {
		return false;
	}
}

/**
 * List all active (loaded) skills from all configured skill roots.
 * Only includes directories (or symlinks to directories) that contain a SKILL.md file.
 */
export function listActiveSkills(): string[] {
	const roots = getAllSkillRoots();
	const seen = new Set<string>();
	for (const root of roots) {
		try {
			const entries = fs.readdirSync(root, { withFileTypes: true });
			for (const entry of entries) {
				if (
					isSkillDirEntry(root, entry) &&
					fs.existsSync(path.join(root, entry.name, "SKILL.md"))
				) {
					seen.add(entry.name);
				}
			}
		} catch {
			// Directory doesn't exist or not readable
		}
	}
	return Array.from(seen).sort();
}

/**
 * Find the first writable draft root that contains <skillName>. Used by
 * promoteSkill() so a draft created via the canonical root helper is
 * located even if the active cwd isn't writable.
 */
function findExistingDraftRootFor(skillName: string): string | null {
	for (const candidate of getWritableDraftSkillRootCandidates()) {
		if (fs.existsSync(path.join(candidate, skillName, "SKILL.md"))) {
			return candidate;
		}
	}
	return null;
}

/**
 * List all draft skills awaiting promotion. Walks every writable draft-root
 * candidate so scaffolds created outside process.cwd() (e.g., CLAUDE_CONFIG_DIR
 * when cwd isn't writable) are still surfaced.
 */
export function listDraftSkills(draftRoot?: string): string[] {
	const roots = draftRoot ? [draftRoot] : getWritableDraftSkillRootCandidates();
	const seen = new Set<string>();
	for (const root of roots) {
		if (!fs.existsSync(root)) continue;
		try {
			const entries = fs.readdirSync(root, { withFileTypes: true });
			for (const entry of entries) {
				if (
					isSkillDirEntry(root, entry) &&
					fs.existsSync(path.join(root, entry.name, "SKILL.md"))
				) {
					seen.add(entry.name);
				}
			}
		} catch {
			// Directory doesn't exist or not readable
		}
	}
	return Array.from(seen).sort();
}

/**
 * Register skills promote/drafts subcommands on a parent command group.
 * Parent is expected to be the "skills" group.
 */
export function registerSkillsPromoteSubcommands(parent: Command): void {
	parent
		.command("promote")
		.description("Promote a draft skill to active")
		.argument("<name>", "Name of the draft skill to promote")
		.action((name: string) => {
			const result = promoteSkill(name);

			if (result.success) {
				console.log(`Skill "${name}" promoted to active. Available next session.`);
			} else {
				console.error(`Error: ${result.error}`);
				process.exitCode = 1;
			}
		});

	parent
		.command("drafts")
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
