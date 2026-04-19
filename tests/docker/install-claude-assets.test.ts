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

	it("migrates legacy profile skills into the shared catalog and rewires profile dirs", () => {
		tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "install-claude-assets-"));
		const appDir = path.join(tempRoot, "app");
		const bundledClaudeDir = path.join(appDir, ".claude");
		const bundledSkillsDir = path.join(bundledClaudeDir, "skills");
		const bundledAgentsSkillDir = path.join(appDir, ".agents", "skills", "memory");
		const claudeHome = path.join(tempRoot, "claude-home");
		const skillCatalog = path.join(tempRoot, "skill-catalog");
		const legacyActiveDir = path.join(claudeHome, "skills", "legacy-skill");
		const legacyDraftDir = path.join(claudeHome, "skills-draft", "draft-skill");
		const catalogActiveDir = path.join(skillCatalog, "skills", "legacy-skill");

		fs.mkdirSync(bundledSkillsDir, { recursive: true });
		fs.mkdirSync(bundledAgentsSkillDir, { recursive: true });
		fs.mkdirSync(legacyActiveDir, { recursive: true });
		fs.mkdirSync(legacyDraftDir, { recursive: true });
		fs.mkdirSync(catalogActiveDir, { recursive: true });

		fs.writeFileSync(path.join(bundledAgentsSkillDir, "SKILL.md"), "# Memory\n", "utf8");
		fs.writeFileSync(path.join(legacyActiveDir, "SKILL.md"), "# Legacy Skill\n", "utf8");
		fs.writeFileSync(path.join(legacyDraftDir, "SKILL.md"), "# Draft Skill\n", "utf8");
		fs.writeFileSync(path.join(catalogActiveDir, "SKILL.md"), "# Existing Catalog Skill\n", "utf8");
		fs.symlinkSync(
			path.relative(bundledSkillsDir, bundledAgentsSkillDir),
			path.join(bundledSkillsDir, "memory"),
		);

		execFileSync("bash", ["docker/install-claude-assets.sh"], {
			cwd: path.resolve("."),
			env: {
				...process.env,
				TELCLAUDE_BUNDLED_CLAUDE_DIR: bundledClaudeDir,
				TELCLAUDE_CLAUDE_HOME: claudeHome,
				TELCLAUDE_SKILL_CATALOG_DIR: skillCatalog,
				TELCLAUDE_UID: String(process.getuid?.() ?? 0),
				TELCLAUDE_GID: String(process.getgid?.() ?? 0),
			},
			stdio: "pipe",
		});

		expect(fs.lstatSync(path.join(claudeHome, "skills")).isSymbolicLink()).toBe(true);
		expect(fs.readlinkSync(path.join(claudeHome, "skills"))).toBe(path.join(skillCatalog, "skills"));
		expect(fs.lstatSync(path.join(claudeHome, "skills-draft")).isSymbolicLink()).toBe(true);
		expect(fs.readlinkSync(path.join(claudeHome, "skills-draft"))).toBe(
			path.join(skillCatalog, "skills-draft"),
		);
		expect(fs.readFileSync(path.join(skillCatalog, "skills", "memory", "SKILL.md"), "utf8")).toContain(
			"Memory",
		);
		expect(
			fs.readFileSync(path.join(skillCatalog, "skills-draft", "draft-skill", "SKILL.md"), "utf8"),
		).toContain("Draft Skill");
		expect(fs.readFileSync(path.join(skillCatalog, "skills", "legacy-skill", "SKILL.md"), "utf8")).toContain(
			"Existing Catalog Skill",
		);
	});

	it("preserves runtime-generated files while refreshing bundled skill contents in the shared catalog", () => {
		tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "install-claude-assets-"));
		const appDir = path.join(tempRoot, "app");
		const bundledClaudeDir = path.join(appDir, ".claude");
		const bundledSkillsDir = path.join(bundledClaudeDir, "skills");
		const bundledAgentsSkillDir = path.join(appDir, ".agents", "skills", "external-provider");
		const claudeHome = path.join(tempRoot, "claude-home");
		const skillCatalog = path.join(tempRoot, "skill-catalog");
		const runtimeSkillDir = path.join(skillCatalog, "skills", "external-provider");
		const runtimeRefsDir = path.join(runtimeSkillDir, "references");

		fs.mkdirSync(bundledSkillsDir, { recursive: true });
		fs.mkdirSync(path.join(bundledAgentsSkillDir, "references"), { recursive: true });
		fs.mkdirSync(runtimeRefsDir, { recursive: true });
		fs.mkdirSync(claudeHome, { recursive: true });

		fs.writeFileSync(path.join(bundledAgentsSkillDir, "SKILL.md"), "# External Provider v2\n", "utf8");
		fs.writeFileSync(
			path.join(bundledAgentsSkillDir, "references", "catalog.md"),
			"bundled reference\n",
			"utf8",
		);
		fs.writeFileSync(path.join(runtimeRefsDir, "provider-schema.md"), "runtime schema\n", "utf8");
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
				TELCLAUDE_SKILL_CATALOG_DIR: skillCatalog,
				TELCLAUDE_UID: String(process.getuid?.() ?? 0),
				TELCLAUDE_GID: String(process.getgid?.() ?? 0),
			},
			stdio: "pipe",
		});

		expect(fs.readFileSync(path.join(runtimeSkillDir, "SKILL.md"), "utf8")).toContain(
			"External Provider v2",
		);
		expect(fs.readFileSync(path.join(runtimeRefsDir, "catalog.md"), "utf8")).toContain(
			"bundled reference",
		);
		expect(fs.readFileSync(path.join(runtimeRefsDir, "provider-schema.md"), "utf8")).toContain(
			"runtime schema",
		);
	});

	it("rewires profile skill dirs even when the shared catalog is mounted read-only", () => {
		tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "install-claude-assets-"));
		const appDir = path.join(tempRoot, "app");
		const bundledClaudeDir = path.join(appDir, ".claude");
		const bundledSkillsDir = path.join(bundledClaudeDir, "skills");
		const bundledAgentsSkillDir = path.join(appDir, ".agents", "skills", "memory");
		const claudeHome = path.join(tempRoot, "claude-home");
		const skillCatalog = path.join(tempRoot, "skill-catalog");

		fs.mkdirSync(bundledSkillsDir, { recursive: true });
		fs.mkdirSync(bundledAgentsSkillDir, { recursive: true });
		fs.mkdirSync(path.join(skillCatalog, "skills"), { recursive: true });
		fs.mkdirSync(path.join(skillCatalog, "skills-draft"), { recursive: true });
		fs.mkdirSync(claudeHome, { recursive: true });

		fs.writeFileSync(path.join(bundledAgentsSkillDir, "SKILL.md"), "# Memory\n", "utf8");
		fs.symlinkSync(
			path.relative(bundledSkillsDir, bundledAgentsSkillDir),
			path.join(bundledSkillsDir, "memory"),
		);
		fs.chmodSync(skillCatalog, 0o555);
		fs.chmodSync(path.join(skillCatalog, "skills"), 0o555);
		fs.chmodSync(path.join(skillCatalog, "skills-draft"), 0o555);

		try {
			execFileSync("bash", ["docker/install-claude-assets.sh"], {
				cwd: path.resolve("."),
				env: {
					...process.env,
					TELCLAUDE_BUNDLED_CLAUDE_DIR: bundledClaudeDir,
					TELCLAUDE_CLAUDE_HOME: claudeHome,
					TELCLAUDE_SKILL_CATALOG_DIR: skillCatalog,
					TELCLAUDE_UID: String(process.getuid?.() ?? 0),
					TELCLAUDE_GID: String(process.getgid?.() ?? 0),
				},
				stdio: "pipe",
			});
		} finally {
			fs.chmodSync(path.join(skillCatalog, "skills-draft"), 0o755);
			fs.chmodSync(path.join(skillCatalog, "skills"), 0o755);
			fs.chmodSync(skillCatalog, 0o755);
		}

		expect(fs.lstatSync(path.join(claudeHome, "skills")).isSymbolicLink()).toBe(true);
		expect(fs.readlinkSync(path.join(claudeHome, "skills"))).toBe(path.join(skillCatalog, "skills"));
		expect(fs.lstatSync(path.join(claudeHome, "skills-draft")).isSymbolicLink()).toBe(true);
		expect(fs.readlinkSync(path.join(claudeHome, "skills-draft"))).toBe(
			path.join(skillCatalog, "skills-draft"),
		);
		expect(fs.existsSync(path.join(skillCatalog, "skills", "memory"))).toBe(false);
	});

	it("keeps agent skill markdown in the Docker build context", () => {
		const dockerignore = fs.readFileSync(path.join(process.cwd(), ".dockerignore"), "utf8");
		expect(dockerignore).toContain("!.agents/skills/**/*.md");
	});
});
