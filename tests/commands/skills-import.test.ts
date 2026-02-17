import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { registerSkillsCommands } from "../../src/commands/skills-import.js";

function writeOpenClawSkill(sourceRoot: string, skillName: string, skillContent: string): void {
	const skillDir = path.join(sourceRoot, "skills", skillName);
	fs.mkdirSync(skillDir, { recursive: true });
	fs.writeFileSync(path.join(skillDir, "SKILL.md"), skillContent, "utf8");
}

async function runSkillsCli(args: string[]): Promise<void> {
	const program = new Command();
	registerSkillsCommands(program);
	await program.parseAsync(args, { from: "user" });
}

describe("skills import-openclaw", () => {
	let tempRoot = "";
	let sourceRoot = "";
	let targetRoot = "";

	beforeEach(() => {
		tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "skills-import-test-"));
		sourceRoot = path.join(tempRoot, "openclaw-source");
		targetRoot = path.join(tempRoot, "import-target");
		fs.mkdirSync(sourceRoot, { recursive: true });
		fs.mkdirSync(targetRoot, { recursive: true });
		process.exitCode = undefined;
		vi.spyOn(console, "log").mockImplementation(() => {});
		vi.spyOn(console, "error").mockImplementation(() => {});
	});

	afterEach(() => {
		vi.restoreAllMocks();
		process.exitCode = undefined;
		if (tempRoot && fs.existsSync(tempRoot)) {
			fs.rmSync(tempRoot, { recursive: true, force: true });
		}
	});

	it("skips skills with auto-install directives by default", async () => {
		writeOpenClawSkill(
			sourceRoot,
			"auto-skill",
			[
				"---",
				"name: auto-skill",
				"description: requires install",
				'auto-install: "brew install jq"',
				"---",
				"",
				"Skill body.",
			].join("\n"),
		);

		await runSkillsCli(["skills", "import-openclaw", sourceRoot, "--target", targetRoot]);

		expect(fs.existsSync(path.join(targetRoot, "auto-skill"))).toBe(false);
	});

	it("imports auto-install skills when --allow-auto-install is set", async () => {
		writeOpenClawSkill(
			sourceRoot,
			"auto-skill",
			[
				"---",
				"name: auto-skill",
				"description: requires install",
				'auto-install: "brew install jq"',
				"---",
				"",
				"Skill body.",
			].join("\n"),
		);

		await runSkillsCli([
			"skills",
			"import-openclaw",
			sourceRoot,
			"--target",
			targetRoot,
			"--allow-auto-install",
		]);

		const importedPath = path.join(targetRoot, "auto-skill", "SKILL.md");
		expect(fs.existsSync(importedPath)).toBe(true);
		const importedContent = fs.readFileSync(importedPath, "utf8");
		expect(importedContent).not.toContain("auto-install:");
	});
});
