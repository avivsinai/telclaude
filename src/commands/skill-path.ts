import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Command } from "commander";

const SKILL_NAME_PATTERN = /^[a-z0-9][a-z0-9-]*$/;

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

export function getSkillRoots(cwd: string = process.cwd()): string[] {
	const configuredClaudeHome = getConfiguredClaudeHome();
	const roots = [
		path.join(cwd, ".claude", "skills"),
		configuredClaudeHome ? path.join(configuredClaudeHome, "skills") : null,
		getBundledSkillsRoot(),
	];

	return roots.filter((root): root is string => Boolean(root)).filter((root, index, all) => {
		const resolved = path.resolve(root);
		return all.findIndex((candidate) => candidate && path.resolve(candidate) === resolved) === index;
	});
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
	const roots = getSkillRoots(options?.cwd);

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
	throw new Error(`Skill asset not found: ${skillName}/${relativePath}. Searched: ${searchedRoots}`);
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
