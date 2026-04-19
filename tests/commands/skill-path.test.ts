import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	getAllDraftSkillRoots,
	getAllSkillRoots,
	getDraftSkillRoot,
	getSkillRoot,
	resolveSkillAssetPath,
	SkillRootUnavailableError,
} from "../../src/commands/skill-path.js";

function writeSkillFile(root: string, skillName: string, relativePath: string, content: string): string {
	const filePath = path.join(root, "skills", skillName, relativePath);
	fs.mkdirSync(path.dirname(filePath), { recursive: true });
	fs.writeFileSync(filePath, content, "utf8");
	return filePath;
}

describe("resolveSkillAssetPath", () => {
	let tempRoot = "";
	let projectRoot = "";
	let claudeHome = "";
	let skillCatalog = "";
	let originalClaudeConfigDir: string | undefined;
	let originalTelclaudeClaudeHome: string | undefined;
	let originalSkillCatalogDir: string | undefined;

	beforeEach(() => {
		tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "skill-path-test-"));
		projectRoot = path.join(tempRoot, "project");
		claudeHome = path.join(tempRoot, "claude-home");
		skillCatalog = path.join(tempRoot, "skill-catalog");
		fs.mkdirSync(projectRoot, { recursive: true });
		fs.mkdirSync(claudeHome, { recursive: true });
		fs.mkdirSync(skillCatalog, { recursive: true });
		originalClaudeConfigDir = process.env.CLAUDE_CONFIG_DIR;
		originalTelclaudeClaudeHome = process.env.TELCLAUDE_CLAUDE_HOME;
		originalSkillCatalogDir = process.env.TELCLAUDE_SKILL_CATALOG_DIR;
	});

	afterEach(() => {
		if (originalClaudeConfigDir === undefined) {
			delete process.env.CLAUDE_CONFIG_DIR;
		} else {
			process.env.CLAUDE_CONFIG_DIR = originalClaudeConfigDir;
		}

		if (originalTelclaudeClaudeHome === undefined) {
			delete process.env.TELCLAUDE_CLAUDE_HOME;
		} else {
			process.env.TELCLAUDE_CLAUDE_HOME = originalTelclaudeClaudeHome;
		}

		if (originalSkillCatalogDir === undefined) {
			delete process.env.TELCLAUDE_SKILL_CATALOG_DIR;
		} else {
			process.env.TELCLAUDE_SKILL_CATALOG_DIR = originalSkillCatalogDir;
		}

		if (tempRoot && fs.existsSync(tempRoot)) {
			fs.rmSync(tempRoot, { recursive: true, force: true });
		}
	});

	it("prefers project-local skill files over configured Claude home", () => {
		process.env.CLAUDE_CONFIG_DIR = claudeHome;

		const projectFile = path.join(
			projectRoot,
			".claude",
			"skills",
			"weather",
			"scripts",
			"weather.sh",
		);
		fs.mkdirSync(path.dirname(projectFile), { recursive: true });
		fs.writeFileSync(projectFile, "project", "utf8");
		writeSkillFile(claudeHome, "weather", "scripts/weather.sh", "configured");

		expect(resolveSkillAssetPath("weather", "scripts/weather.sh", { cwd: projectRoot })).toBe(
			projectFile,
		);
	});

	it("falls back to configured Claude home when the workspace has no matching skill", () => {
		process.env.CLAUDE_CONFIG_DIR = claudeHome;
		const configuredFile = writeSkillFile(
			claudeHome,
			"weather",
			"scripts/weather.sh",
			"configured",
		);

		expect(resolveSkillAssetPath("weather", "scripts/weather.sh", { cwd: projectRoot })).toBe(
			configuredFile,
		);
	});

	it("uses TELCLAUDE_CLAUDE_HOME when CLAUDE_CONFIG_DIR is unset", () => {
		delete process.env.CLAUDE_CONFIG_DIR;
		process.env.TELCLAUDE_CLAUDE_HOME = claudeHome;
		const configuredFile = writeSkillFile(
			claudeHome,
			"weather",
			"scripts/weather.sh",
			"configured",
		);

		expect(resolveSkillAssetPath("weather", "scripts/weather.sh", { cwd: projectRoot })).toBe(
			configuredFile,
		);
	});

	it("prefers TELCLAUDE_SKILL_CATALOG_DIR over CLAUDE_CONFIG_DIR for skill resolution", () => {
		process.env.CLAUDE_CONFIG_DIR = claudeHome;
		process.env.TELCLAUDE_SKILL_CATALOG_DIR = skillCatalog;
		const managedFile = writeSkillFile(skillCatalog, "weather", "scripts/weather.sh", "managed");
		writeSkillFile(claudeHome, "weather", "scripts/weather.sh", "configured");

		expect(resolveSkillAssetPath("weather", "scripts/weather.sh", { cwd: projectRoot })).toBe(
			managedFile,
		);
	});

	it("prefers TELCLAUDE_SKILL_CATALOG_DIR over project-local skills", () => {
		process.env.TELCLAUDE_SKILL_CATALOG_DIR = skillCatalog;
		const projectFile = path.join(
			projectRoot,
			".claude",
			"skills",
			"weather",
			"scripts",
			"weather.sh",
		);
		fs.mkdirSync(path.dirname(projectFile), { recursive: true });
		fs.writeFileSync(projectFile, "project", "utf8");
		const managedFile = writeSkillFile(skillCatalog, "weather", "scripts/weather.sh", "managed");

		expect(resolveSkillAssetPath("weather", "scripts/weather.sh", { cwd: projectRoot })).toBe(
			managedFile,
		);
	});

	it("rejects traversal attempts in relative paths", () => {
		expect(() =>
			resolveSkillAssetPath("weather", "../secrets.txt", { cwd: projectRoot }),
		).toThrow("Skill path must stay within the skill directory.");
	});

	it("rejects traversal-style skill names", () => {
		expect(() =>
			resolveSkillAssetPath("../weather", "scripts/weather.sh", { cwd: projectRoot }),
		).toThrow("Invalid skill name");
	});
});

describe("getSkillRoot / getDraftSkillRoot", () => {
	let tempRoot = "";
	let projectRoot = "";
	let skillCatalog = "";
	let originalClaudeConfigDir: string | undefined;
	let originalTelclaudeClaudeHome: string | undefined;
	let originalSkillCatalogDir: string | undefined;

	beforeEach(() => {
		tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "skill-root-test-"));
		projectRoot = path.join(tempRoot, "project");
		skillCatalog = path.join(tempRoot, "skill-catalog");
		fs.mkdirSync(projectRoot, { recursive: true });
		fs.mkdirSync(skillCatalog, { recursive: true });
		originalClaudeConfigDir = process.env.CLAUDE_CONFIG_DIR;
		originalTelclaudeClaudeHome = process.env.TELCLAUDE_CLAUDE_HOME;
		originalSkillCatalogDir = process.env.TELCLAUDE_SKILL_CATALOG_DIR;
	});

	afterEach(() => {
		if (originalClaudeConfigDir === undefined) {
			delete process.env.CLAUDE_CONFIG_DIR;
		} else {
			process.env.CLAUDE_CONFIG_DIR = originalClaudeConfigDir;
		}

		if (originalTelclaudeClaudeHome === undefined) {
			delete process.env.TELCLAUDE_CLAUDE_HOME;
		} else {
			process.env.TELCLAUDE_CLAUDE_HOME = originalTelclaudeClaudeHome;
		}

		if (originalSkillCatalogDir === undefined) {
			delete process.env.TELCLAUDE_SKILL_CATALOG_DIR;
		} else {
			process.env.TELCLAUDE_SKILL_CATALOG_DIR = originalSkillCatalogDir;
		}

		if (tempRoot && fs.existsSync(tempRoot)) {
			fs.rmSync(tempRoot, { recursive: true, force: true });
		}
	});

	it("creates and returns the project-local skills root", () => {
		delete process.env.CLAUDE_CONFIG_DIR;
		delete process.env.TELCLAUDE_CLAUDE_HOME;
		delete process.env.TELCLAUDE_SKILL_CATALOG_DIR;

		const root = getSkillRoot(projectRoot);
		expect(root).toBe(path.join(projectRoot, ".claude", "skills"));
		expect(fs.existsSync(root)).toBe(true);
	});

	it("prefers CLAUDE_CONFIG_DIR when the project-local root is not writable", () => {
		const configHome = path.join(tempRoot, "claude-home");
		fs.mkdirSync(configHome, { recursive: true });
		process.env.CLAUDE_CONFIG_DIR = configHome;
		// Block project-local by pointing cwd to a non-existent path that cannot be created.
		const blockedCwd = path.join(tempRoot, "blocked", "does-not-exist");
		// Make the parent read-only so mkdir fails.
		fs.mkdirSync(path.dirname(blockedCwd), { recursive: true, mode: 0o500 });
		try {
			const root = getSkillRoot(blockedCwd);
			expect(root).toBe(path.join(configHome, "skills"));
		} finally {
			fs.chmodSync(path.dirname(blockedCwd), 0o700);
		}
	});

	it("prefers TELCLAUDE_SKILL_CATALOG_DIR over CLAUDE_CONFIG_DIR for writable roots", () => {
		process.env.CLAUDE_CONFIG_DIR = path.join(tempRoot, "claude-home");
		process.env.TELCLAUDE_SKILL_CATALOG_DIR = skillCatalog;
		fs.mkdirSync(process.env.CLAUDE_CONFIG_DIR, { recursive: true });

		expect(getSkillRoot(projectRoot)).toBe(path.join(skillCatalog, "skills"));
		expect(getDraftSkillRoot(projectRoot)).toBe(path.join(skillCatalog, "skills-draft"));
	});

	it("throws SkillRootUnavailableError when no candidate is writable", () => {
		delete process.env.CLAUDE_CONFIG_DIR;
		delete process.env.TELCLAUDE_CLAUDE_HOME;
		delete process.env.TELCLAUDE_SKILL_CATALOG_DIR;
		// Make the cwd's .claude parent unwritable.
		fs.chmodSync(projectRoot, 0o500);
		try {
			expect(() => getSkillRoot(projectRoot)).toThrow(SkillRootUnavailableError);
		} finally {
			fs.chmodSync(projectRoot, 0o700);
		}
	});

	it("exposes the matching draft root", () => {
		delete process.env.CLAUDE_CONFIG_DIR;
		delete process.env.TELCLAUDE_CLAUDE_HOME;
		delete process.env.TELCLAUDE_SKILL_CATALOG_DIR;

		const root = getDraftSkillRoot(projectRoot);
		expect(root).toBe(path.join(projectRoot, ".claude", "skills-draft"));
		expect(fs.existsSync(root)).toBe(true);
	});

	it("returns all skill roots including the bundled fallback", () => {
		delete process.env.CLAUDE_CONFIG_DIR;
		delete process.env.TELCLAUDE_CLAUDE_HOME;
		delete process.env.TELCLAUDE_SKILL_CATALOG_DIR;

		const roots = getAllSkillRoots(projectRoot);
		// First root should be project-local.
		expect(roots[0]).toBe(path.join(projectRoot, ".claude", "skills"));
		// At least one bundled root at the end (resolved inside the telclaude package).
		expect(roots.length).toBeGreaterThanOrEqual(1);
	});

	it("returns all draft roots including the managed catalog when configured", () => {
		process.env.TELCLAUDE_SKILL_CATALOG_DIR = skillCatalog;

		const roots = getAllDraftSkillRoots(projectRoot);
		expect(roots).toContain(path.join(projectRoot, ".claude", "skills-draft"));
		expect(roots).toContain(path.join(skillCatalog, "skills-draft"));
		expect(roots).not.toContain(path.join(projectRoot, ".claude", "skills"));
	});
});
