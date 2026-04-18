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
import { type ScanResult, type SkillSignatureInfo, scanSkill } from "../security/skill-scanner.js";
import type {
	SkillReviewCardState,
	SkillReviewFindingSummary,
	SkillReviewTrust,
} from "../telegram/cards/types.js";
import { CardKind } from "../telegram/cards/types.js";
import type { VaultClient } from "../vault-daemon/client.js";
import { copyDirRecursive } from "./cli-utils.js";
import {
	getAllSkillRoots,
	getDraftSkillRoot,
	getSkillRoot,
	getWritableDraftSkillRootCandidates,
} from "./skill-path.js";

const logger = getChildLogger({ module: "cmd-skills-promote" });

/**
 * Auto-install pattern set mirrored from `skills-import.ts` so the review
 * card can flag skills (including locally scaffolded drafts) that reach
 * for package-manager installs. Keep in sync with the importer.
 */
const AUTO_INSTALL_PATTERNS: RegExp[] = [
	/\b(?:brew|apt|yum|pacman|dnf)\s+install\b/i,
	/\bnpm\s+(?:i|install)\s+-g\b/i,
	/\bpip\s+install\b/i,
	/\bgo\s+install\b/i,
	/\bcargo\s+install\b/i,
	/\buv\s+(?:tool\s+)?install\b/i,
	/\bnpx\s+/i,
];

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
	const effectiveDraftRoot =
		draftRoot ?? findExistingDraftRootFor(skillName) ?? getDraftSkillRoot();
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
 * Extract the frontmatter `description` field from SKILL.md content for
 * use in the review card header. Returns undefined if absent.
 */
function readSkillDescription(skillDir: string): string | undefined {
	try {
		const raw = fs.readFileSync(path.join(skillDir, "SKILL.md"), "utf8");
		const match = raw.match(/^---\s*\n([\s\S]*?)\n---/);
		if (!match) return undefined;
		const desc = match[1].match(/^description\s*:\s*(.+)$/m);
		return desc ? desc[1].trim().replace(/^['"]|['"]$/g, "") : undefined;
	} catch {
		return undefined;
	}
}

/**
 * Scan a draft directory for auto-install patterns (lockfile-less
 * installs, `npx`, etc). Lifted from the importer so locally scaffolded
 * drafts get the same surfacing in the review card.
 */
function findAutoInstallPatterns(skillDir: string): string[] {
	const hits: string[] = [];
	let content: string;
	try {
		content = fs.readFileSync(path.join(skillDir, "SKILL.md"), "utf8");
	} catch {
		return hits;
	}
	for (const pattern of AUTO_INSTALL_PATTERNS) {
		const match = content.match(pattern);
		if (match) hits.push(match[0]);
	}
	return hits;
}

/**
 * Summarize the diff between the draft and the currently active skill
 * of the same name. Output is a one-line human string ("+12/-3 lines",
 * "new skill", or "identical"). No external diff tooling — byte-level
 * equality and line-count delta is enough for the review card.
 */
function summarizeDiff(
	draftDir: string,
	activeRoot: string,
	skillName: string,
): string | undefined {
	const draftSkillMd = path.join(draftDir, "SKILL.md");
	const activeSkillMd = path.join(activeRoot, skillName, "SKILL.md");
	if (!fs.existsSync(activeSkillMd)) {
		return "new skill";
	}
	let draftText: string;
	let activeText: string;
	try {
		draftText = fs.readFileSync(draftSkillMd, "utf8");
		activeText = fs.readFileSync(activeSkillMd, "utf8");
	} catch {
		return undefined;
	}
	if (draftText === activeText) return "identical";
	const draftLines = draftText.split("\n").length;
	const activeLines = activeText.split("\n").length;
	const delta = draftLines - activeLines;
	const sign = delta >= 0 ? "+" : "";
	return `${sign}${delta} lines (draft ${draftLines}, active ${activeLines})`;
}

/**
 * Resolve signature trust using the vault. If no vault client is
 * provided (or verification fails), trust falls back to:
 *   - "community" when no signature file is present, and
 *   - "unknown" when a signature exists but cannot be verified.
 *
 * The review card treats "trusted" as a positive badge, never as a
 * blocker — unsigned skills remain promotable when the scanner passes.
 */
async function resolveTrust(
	signature: SkillSignatureInfo,
	vault?: VaultClient,
): Promise<{ trust: SkillReviewTrust; detail?: string }> {
	if (signature.state === "unsigned") {
		return { trust: "community", detail: undefined };
	}
	if (signature.state !== "signed" || !signature.signature || !signature.digest) {
		return { trust: "unknown", detail: "signature file unreadable" };
	}
	if (!vault) {
		return {
			trust: "unknown",
			detail: `sha256:${signature.digest.slice(0, 12)}…`,
		};
	}
	try {
		const response = await vault.verifySkill(signature.digest, signature.signature);
		const short = `sha256:${signature.digest.slice(0, 12)}…`;
		if (response.type === "verify-skill" && response.valid) {
			return { trust: "trusted", detail: short };
		}
		return { trust: "unknown", detail: `${short} (verify failed)` };
	} catch {
		return {
			trust: "unknown",
			detail: `sha256:${signature.digest.slice(0, 12)}… (vault unavailable)`,
		};
	}
}

/**
 * Build a SkillReviewCardState from a draft directory. Pure data-assembly
 * so the renderer can stay sync; vault verification is awaited up front
 * so the card renders with a decided trust badge.
 */
export async function buildSkillReviewState(options: {
	skillName: string;
	adminControlsEnabled: boolean;
	draftRoot?: string;
	activeRoot?: string;
	vault?: VaultClient;
}): Promise<SkillReviewCardState | { error: string }> {
	if (!SKILL_NAME_PATTERN.test(options.skillName)) {
		return { error: `Invalid skill name "${options.skillName}".` };
	}
	const effectiveDraftRoot =
		options.draftRoot ?? findExistingDraftRootFor(options.skillName) ?? getDraftSkillRoot();
	const draftDir = path.join(effectiveDraftRoot, options.skillName);
	if (!fs.existsSync(path.join(draftDir, "SKILL.md"))) {
		return { error: `Draft "${options.skillName}" not found.` };
	}

	const scan: ScanResult = scanSkill(draftDir);
	const findingSummary: SkillReviewFindingSummary[] = (
		["critical", "high", "medium", "info"] as const
	)
		.map((severity) => ({ severity, count: scan.counts[severity] }))
		.filter((entry) => entry.count > 0);
	const topFindings = scan.findings
		.filter((f) => f.severity === "critical" || f.severity === "high")
		.slice(0, 4)
		.map((f) => ({ severity: f.severity, message: f.message, file: f.file }));

	const trust = await resolveTrust(scan.signature, options.vault);
	const effectiveActiveRoot = options.activeRoot ?? getSkillRoot();

	const state: SkillReviewCardState = {
		kind: CardKind.SkillReview,
		title: "Review Skill",
		skillName: options.skillName,
		description: readSkillDescription(draftDir),
		findingSummary,
		totalFindings: scan.findings.length,
		scannerBlocked: scan.blocked,
		topFindings,
		trust: trust.trust,
		trustDetail: trust.detail,
		autoInstallPatterns: findAutoInstallPatterns(draftDir),
		adminControlsEnabled: options.adminControlsEnabled,
		diffSummary: summarizeDiff(draftDir, effectiveActiveRoot, options.skillName),
	};
	return state;
}

/**
 * Register skills promote/drafts subcommands on a parent command group.
 * Parent is expected to be the "skills" group.
 */
export function registerSkillsPromoteSubcommands(parent: Command): void {
	parent
		.command("promote")
		.description("Promote a draft skill to active (shows review summary first)")
		.argument("<name>", "Name of the draft skill to promote")
		.option(
			"--no-review",
			"Skip the review summary and promote immediately (CI / non-interactive).",
		)
		.action(async (name: string, options: { review: boolean }) => {
			// Review summary is printed before promote so the operator sees the
			// same signals as the Telegram SkillReviewCard. `--no-review` jumps
			// straight to promote — necessary for CI and automated flows.
			if (options.review !== false) {
				const review = await buildSkillReviewState({
					skillName: name,
					adminControlsEnabled: true,
				});
				if ("error" in review) {
					console.error(`Error: ${review.error}`);
					process.exitCode = 1;
					return;
				}
				console.log(`=== Skill Review: ${review.skillName} ===`);
				if (review.description) console.log(`  ${review.description}`);
				console.log(
					`  trust:    ${review.trust}${review.trustDetail ? ` (${review.trustDetail})` : ""}`,
				);
				console.log(
					`  scanner:  ${review.findingSummary.map((s) => `${s.severity}=${s.count}`).join(" ") || "none"}`,
				);
				if (review.scannerBlocked) {
					console.log("  status:   BLOCKED (scanner flagged critical/high findings)");
				}
				if (review.autoInstallPatterns.length > 0) {
					console.log(`  auto-install: ${review.autoInstallPatterns.join(", ")}`);
				}
				if (review.diffSummary) console.log(`  diff:     ${review.diffSummary}`);
				if (review.scannerBlocked) {
					console.error("Refusing to promote a scanner-blocked skill.");
					process.exitCode = 1;
					return;
				}
				console.log("");
			}

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
