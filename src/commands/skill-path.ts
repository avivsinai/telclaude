import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Command } from "commander";

const SKILL_NAME_PATTERN = /^[a-z0-9][a-z0-9-]*$/;

export class SkillRootUnavailableError extends Error {
	readonly searched: string[];
	constructor(searched: string[]) {
		super(
			`No writable skill root found. Searched:\n${searched.map((p) => `  - ${p}`).join("\n")}\n\n` +
				`Fix by creating one of these directories with write access, or set CLAUDE_CONFIG_DIR / TELCLAUDE_CLAUDE_HOME to a writable absolute path.`,
		);
		this.name = "SkillRootUnavailableError";
		this.searched = searched;
	}
}

function getConfiguredClaudeHome(): string | null {
	const raw = process.env.CLAUDE_CONFIG_DIR ?? process.env.TELCLAUDE_CLAUDE_HOME;
	if (!raw || raw.startsWith("~") || !path.isAbsolute(raw)) {
		return null;
	}
	return raw.replace(/[/\\]+$/, "");
}

function getBundledSkillsRoot(): string {
	return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../.claude/skills");
}

function normalizeRelativeSkillPath(relativePath: string): string[] {
	if (!relativePath.trim()) {
		throw new Error("Skill path must not be empty.");
	}

	if (path.isAbsolute(relativePath)) {
		throw new Error("Skill path must be relative to the skill root.");
	}

	const normalized = path.posix.normalize(relativePath.replace(/\\/g, "/"));
	if (normalized === "." || normalized === ".." || normalized.startsWith("../")) {
		throw new Error("Skill path must stay within the skill directory.");
	}

	return normalized.split("/").filter(Boolean);
}

function dedupePaths(paths: readonly (string | null | undefined)[]): string[] {
	return paths
		.filter((p): p is string => Boolean(p))
		.filter((p, index, all) => {
			const resolved = path.resolve(p);
			return (
				all.findIndex((candidate) => candidate && path.resolve(candidate) === resolved) === index
			);
		});
}

/**
 * Build the ordered list of candidate skill roots (writable or not),
 * used for READING bundled assets. Order: project-local, configured Claude home,
 * bundled distribution root.
 */
export function getAllSkillRoots(cwd: string = process.cwd()): string[] {
	const configuredClaudeHome = getConfiguredClaudeHome();
	return dedupePaths([
		path.join(cwd, ".claude", "skills"),
		configuredClaudeHome ? path.join(configuredClaudeHome, "skills") : null,
		getBundledSkillsRoot(),
	]);
}

/**
 * Build the ordered list of candidate WRITABLE skill roots. Prefer the
 * configured Claude home when present so runtime-generated skill state
 * lands in the active profile, then fall back to the project-local root.
 */
export function getWritableSkillRootCandidates(cwd: string = process.cwd()): string[] {
	const configuredClaudeHome = getConfiguredClaudeHome();
	return dedupePaths([
		configuredClaudeHome ? path.join(configuredClaudeHome, "skills") : null,
		path.join(cwd, ".claude", "skills"),
	]);
}

/**
 * Build the ordered list of candidate WRITABLE draft-skill roots with the
 * same preference order as getWritableSkillRootCandidates().
 */
export function getWritableDraftSkillRootCandidates(cwd: string = process.cwd()): string[] {
	const configuredClaudeHome = getConfiguredClaudeHome();
	return dedupePaths([
		configuredClaudeHome ? path.join(configuredClaudeHome, "skills-draft") : null,
		path.join(cwd, ".claude", "skills-draft"),
	]);
}

function isWritableDir(dir: string): boolean {
	try {
		fs.mkdirSync(dir, { recursive: true });
		fs.accessSync(dir, fs.constants.W_OK);
		return true;
	} catch {
		return false;
	}
}

/**
 * Return the single canonical writable skill root for telclaude, creating
 * the directory if needed. Throws SkillRootUnavailableError if no candidate
 * is writable.
 */
export function getSkillRoot(cwd: string = process.cwd()): string {
	const candidates = getWritableSkillRootCandidates(cwd);
	for (const candidate of candidates) {
		if (isWritableDir(candidate)) {
			return candidate;
		}
	}
	throw new SkillRootUnavailableError(candidates);
}

/**
 * Return the single canonical writable draft-skill root, creating the
 * directory if needed. Throws SkillRootUnavailableError if no candidate
 * is writable.
 */
export function getDraftSkillRoot(cwd: string = process.cwd()): string {
	const candidates = getWritableDraftSkillRootCandidates(cwd);
	for (const candidate of candidates) {
		if (isWritableDir(candidate)) {
			return candidate;
		}
	}
	throw new SkillRootUnavailableError(candidates);
}

/**
 * @deprecated Use getAllSkillRoots() for read search paths or getSkillRoot()
 * for the canonical writable root. Kept as an alias for existing callers that
 * only read and enumerate skills.
 */
export function getSkillRoots(cwd: string = process.cwd()): string[] {
	return getAllSkillRoots(cwd);
}

export function resolveSkillAssetPath(
	skillName: string,
	relativePath: string,
	options?: { cwd?: string },
): string {
	if (!SKILL_NAME_PATTERN.test(skillName)) {
		throw new Error(
			`Invalid skill name "${skillName}". Must match ${SKILL_NAME_PATTERN} (no path separators or traversal).`,
		);
	}

	const pathParts = normalizeRelativeSkillPath(relativePath);
	const roots = getAllSkillRoots(options?.cwd);

	for (const root of roots) {
		const skillRoot = path.resolve(root, skillName);
		const candidate = path.resolve(skillRoot, ...pathParts);

		if (candidate !== skillRoot && !candidate.startsWith(`${skillRoot}${path.sep}`)) {
			continue;
		}

		if (!fs.existsSync(candidate)) {
			continue;
		}

		const stat = fs.statSync(candidate);
		if (!stat.isFile()) {
			continue;
		}

		return candidate;
	}

	const searchedRoots = roots.map((root) => path.join(root, skillName, relativePath)).join(", ");
	throw new Error(
		`Skill asset not found: ${skillName}/${relativePath}. Searched: ${searchedRoots}`,
	);
}

export function registerSkillPathCommand(program: Command): void {
	program
		.command("skill-path")
		.description("Resolve a bundled file within an installed skill")
		.argument("<skill>", "Skill name")
		.argument("<relative-path>", "Path inside the skill directory")
		.action((skill: string, relativePath: string) => {
			try {
				console.log(resolveSkillAssetPath(skill, relativePath));
			} catch (err) {
				console.error(String(err));
				process.exit(1);
			}
		});
}
