import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";

describe("docker/install-claude-assets.sh", () => {
	let tempRoot = "";

	afterEach(() => {
		if (tempRoot && fs.existsSync(tempRoot)) {
			fs.rmSync(tempRoot, { recursive: true, force: true });
		}
	});

	it("dereferences bundled skill symlinks into the writable Claude home", () => {
		tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "install-claude-assets-"));
		const appDir = path.join(tempRoot, "app");
		const bundledClaudeDir = path.join(appDir, ".claude");
		const bundledSkillsDir = path.join(bundledClaudeDir, "skills");
		const bundledAgentsSkillDir = path.join(appDir, ".agents", "skills", "external-provider");
		const claudeHome = path.join(tempRoot, "claude-home");

		fs.mkdirSync(bundledSkillsDir, { recursive: true });
		fs.mkdirSync(bundledAgentsSkillDir, { recursive: true });
		fs.mkdirSync(claudeHome, { recursive: true });

		fs.writeFileSync(
			path.join(bundledAgentsSkillDir, "SKILL.md"),
			"# External Provider\n",
			"utf8",
		);
		fs.writeFileSync(path.join(bundledClaudeDir, "CLAUDE.md"), "# Bundled Claude\n", "utf8");
		fs.symlinkSync(
			path.relative(bundledSkillsDir, bundledAgentsSkillDir),
			path.join(bundledSkillsDir, "external-provider"),
		);

		execFileSync("bash", ["docker/install-claude-assets.sh"], {
			cwd: path.resolve("."),
			env: {
				...process.env,
				TELCLAUDE_BUNDLED_CLAUDE_DIR: bundledClaudeDir,
				TELCLAUDE_CLAUDE_HOME: claudeHome,
				TELCLAUDE_UID: String(process.getuid?.() ?? 0),
				TELCLAUDE_GID: String(process.getgid?.() ?? 0),
			},
			stdio: "pipe",
		});

		const installedSkillDir = path.join(claudeHome, "skills", "external-provider");
		const installedSkillFile = path.join(installedSkillDir, "SKILL.md");
		expect(fs.lstatSync(installedSkillDir).isDirectory()).toBe(true);
		expect(fs.lstatSync(installedSkillDir).isSymbolicLink()).toBe(false);
		expect(fs.readFileSync(installedSkillFile, "utf8")).toContain("External Provider");
		expect(fs.readFileSync(path.join(claudeHome, "CLAUDE.md"), "utf8")).toContain("Bundled Claude");
	});

	it("keeps agent skill markdown in the Docker build context", () => {
		const dockerignore = fs.readFileSync(path.join(process.cwd(), ".dockerignore"), "utf8");
		expect(dockerignore).toContain("!.agents/skills/**/*.md");
	});
});
