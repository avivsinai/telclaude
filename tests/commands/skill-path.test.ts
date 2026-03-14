import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { resolveSkillAssetPath } from "../../src/commands/skill-path.js";

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
	let originalClaudeConfigDir: string | undefined;
	let originalTelclaudeClaudeHome: string | undefined;

	beforeEach(() => {
		tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "skill-path-test-"));
		projectRoot = path.join(tempRoot, "project");
		claudeHome = path.join(tempRoot, "claude-home");
		fs.mkdirSync(projectRoot, { recursive: true });
		fs.mkdirSync(claudeHome, { recursive: true });
		originalClaudeConfigDir = process.env.CLAUDE_CONFIG_DIR;
		originalTelclaudeClaudeHome = process.env.TELCLAUDE_CLAUDE_HOME;
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
