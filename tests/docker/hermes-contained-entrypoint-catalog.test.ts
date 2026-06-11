import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

const repoRoot = path.resolve(import.meta.dirname, "../..");
const entrypointPath = path.join(repoRoot, "docker/hermes-contained-entrypoint.sh");

let tempRoot = "";

afterEach(() => {
	if (tempRoot && fs.existsSync(tempRoot)) {
		fs.rmSync(tempRoot, { recursive: true, force: true });
	}
});

function makeMount(): string {
	tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-entrypoint-catalog-"));
	const mount = path.join(tempRoot, "catalog");
	fs.mkdirSync(path.join(mount, "skills"), { recursive: true });
	return mount;
}

function writeSkill(mount: string, name: string): string {
	const dir = path.join(mount, "skills", name);
	fs.mkdirSync(dir, { recursive: true });
	fs.writeFileSync(
		path.join(dir, "SKILL.md"),
		`---\nname: ${name}\ndescription: Helps with ${name}\n---\n`,
	);
	return dir;
}

function runValidateCatalogOnly(mount: string): string {
	return execFileSync("sh", [entrypointPath, "validate-catalog-only"], {
		cwd: repoRoot,
		env: { ...process.env, TELCLAUDE_HERMES_SKILL_CATALOG_MOUNT: mount },
		stdio: "pipe",
		encoding: "utf8",
	});
}

function expectValidationDeath(mount: string, message: string): void {
	let stderr = "";
	try {
		runValidateCatalogOnly(mount);
	} catch (err) {
		stderr = String((err as { stderr?: unknown }).stderr ?? "");
	}
	expect(stderr).toContain(message);
}

describe("hermes-contained-entrypoint.sh validate-catalog-only", () => {
	it("reports disabled when the mount is absent", () => {
		tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-entrypoint-catalog-"));
		const output = runValidateCatalogOnly(path.join(tempRoot, "does-not-exist"));
		expect(output).toContain("catalog disabled");
	});

	it("reports enabled for a valid catalog mount", () => {
		const mount = makeMount();
		writeSkill(mount, "daily-brief");
		const output = runValidateCatalogOnly(mount);
		expect(output).toContain(`catalog enabled at ${path.join(mount, "skills")}`);
	});

	it("dies on a scripts/ directory inside a skill", () => {
		const mount = makeMount();
		const dir = writeSkill(mount, "scripted");
		fs.mkdirSync(path.join(dir, "scripts"));
		fs.writeFileSync(path.join(dir, "scripts", "x.py"), "print()\n");
		expectValidationDeath(mount, "contains a scripts/ directory: scripted");
	});

	it("dies on a symlink inside a skill", () => {
		const mount = makeMount();
		const dir = writeSkill(mount, "linked");
		fs.symlinkSync("/etc/hosts", path.join(dir, "hosts"));
		expectValidationDeath(mount, "contains a symlink: linked");
	});

	it("dies on an executable file inside a skill", () => {
		const mount = makeMount();
		const dir = writeSkill(mount, "execy");
		const tool = path.join(dir, "tool.md");
		fs.writeFileSync(tool, "text\n");
		fs.chmodSync(tool, 0o755);
		expectValidationDeath(mount, "contains an executable file: execy");
	});

	it("dies on dot-named and whitespace-named entries", () => {
		const mount = makeMount();
		writeSkill(mount, "good-skill");
		fs.mkdirSync(path.join(mount, "skills", ".sneaky"));
		expectValidationDeath(mount, "invalid catalog skill name: .sneaky");

		fs.rmSync(path.join(mount, "skills", ".sneaky"), { recursive: true, force: true });
		fs.mkdirSync(path.join(mount, "skills", "bad name"));
		expectValidationDeath(mount, "invalid catalog skill name: bad name");
	});

	it("dies on a skill without SKILL.md", () => {
		const mount = makeMount();
		fs.mkdirSync(path.join(mount, "skills", "hollow"));
		expectValidationDeath(mount, "catalog skill missing SKILL.md: hollow");
	});
});

describe("hermes-contained-entrypoint.sh catalog config merge", () => {
	it("keeps one skills: block and appends external_dirs conditionally", () => {
		const script = fs.readFileSync(entrypointPath, "utf8");

		// Exactly one skills: block in the generated config heredoc.
		expect(script.match(/^skills:$/gm)).toHaveLength(1);
		// creation_nudge_interval stays in the block; external_dirs joins it via the
		// conditional expansion rather than a second skills: key.
		expect(script).toContain(`  creation_nudge_interval: 0\${SKILLS_EXTERNAL_DIRS_BLOCK}`);
		expect(script).toContain('SKILLS_EXTERNAL_DIRS_BLOCK=""');
		expect(script).toContain("  external_dirs:");
		expect(script).toContain(`    - \\"\${CATALOG_SKILLS_DIR}\\"`);
		// Default mount path and validation wiring.
		expect(script).toContain(
			`SKILL_CATALOG_MOUNT=\${TELCLAUDE_HERMES_SKILL_CATALOG_MOUNT:-/opt/data/telclaude-hermes-skill-catalog}`,
		);
		expect(script).toContain("validate_catalog_skill_entry");
		// The catalog block is computed before the config heredoc is written.
		expect(script.indexOf('SKILLS_EXTERNAL_DIRS_BLOCK=""')).toBeLessThan(
			script.indexOf(`cat > "\${HERMES_HOME}/config.yaml"`),
		);
	});
});
