import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SKILL_TEMPLATES, scaffoldSkill } from "../../src/commands/skill-scaffold.js";
import { scanSkill } from "../../src/security/skill-scanner.js";

const TEMPLATES_ROOT = path.resolve(__dirname, "..", "..", "assets", "skill-templates");

describe("skill-scaffold", () => {
	let tempRoot = "";
	let draftRoot = "";

	beforeEach(() => {
		tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "skill-scaffold-test-"));
		draftRoot = path.join(tempRoot, "skills-draft");
		fs.mkdirSync(draftRoot, { recursive: true });
	});

	afterEach(() => {
		if (tempRoot && fs.existsSync(tempRoot)) {
			fs.rmSync(tempRoot, { recursive: true, force: true });
		}
	});

	it("creates .claude/skills-draft/<name>/SKILL.md with valid frontmatter", () => {
		const result = scaffoldSkill({
			name: "my-skill",
			template: "basic",
			description: "Does the thing. Use when users ask for thing.",
			draftRoot,
			templatesRoot: TEMPLATES_ROOT,
		});

		expect(result.success).toBe(true);
		expect(result.skillMdPath).toBe(path.join(draftRoot, "my-skill", "SKILL.md"));
		expect(fs.existsSync(result.skillMdPath!)).toBe(true);

		const content = fs.readFileSync(result.skillMdPath!, "utf8");
		expect(content).toMatch(/^---/);
		expect(content).toContain("name: my-skill");
		expect(content).toContain("description: Does the thing. Use when users ask for thing.");
		expect(content).toMatch(/allowed-tools:\s*\n(\s*-\s*\w+\s*\n)+/);
	});

	it("creates standard subdirectories with .gitkeep markers", () => {
		const result = scaffoldSkill({
			name: "subdir-skill",
			description: "A description that is sufficiently long.",
			draftRoot,
			templatesRoot: TEMPLATES_ROOT,
		});
		expect(result.success).toBe(true);
		for (const sub of ["scripts", "references", "assets"]) {
			expect(fs.existsSync(path.join(draftRoot, "subdir-skill", sub))).toBe(true);
			expect(fs.existsSync(path.join(draftRoot, "subdir-skill", sub, ".gitkeep"))).toBe(true);
		}
	});

	it("writes PREVIEW.md with a promotion checklist", () => {
		const result = scaffoldSkill({
			name: "preview-skill",
			description: "Skill with preview checklist.",
			draftRoot,
			templatesRoot: TEMPLATES_ROOT,
		});
		expect(result.success).toBe(true);
		const preview = fs.readFileSync(result.previewPath!, "utf8");
		expect(preview).toContain("Promotion checklist");
		expect(preview).toContain("telclaude skills scan");
		expect(preview).toContain("telclaude skills doctor");
		expect(preview).toContain("telclaude skills promote preview-skill");
	});

	it.each(SKILL_TEMPLATES)("supports template %s", (template) => {
		const result = scaffoldSkill({
			name: `tpl-${template}`.replace(/[^a-z0-9-]/g, "-"),
			template,
			description: `Built from ${template} template for tests.`,
			draftRoot,
			templatesRoot: TEMPLATES_ROOT,
		});
		expect(result.success).toBe(true);
		const content = fs.readFileSync(result.skillMdPath!, "utf8");
		expect(content).toContain("---");
		expect(content).not.toContain("{{");
	});

	it("refuses to overwrite an existing draft", () => {
		const first = scaffoldSkill({
			name: "collide",
			description: "First write — intentionally collides below.",
			draftRoot,
			templatesRoot: TEMPLATES_ROOT,
		});
		expect(first.success).toBe(true);

		const second = scaffoldSkill({
			name: "collide",
			description: "Second write should fail.",
			draftRoot,
			templatesRoot: TEMPLATES_ROOT,
		});
		expect(second.success).toBe(false);
		expect(second.error).toMatch(/already exists/);
	});

	it("rejects invalid skill names", () => {
		const result = scaffoldSkill({
			name: "Bad_Name",
			description: "Should fail because of uppercase and underscore.",
			draftRoot,
			templatesRoot: TEMPLATES_ROOT,
		});
		expect(result.success).toBe(false);
		expect(result.error).toMatch(/Invalid skill name/);
	});

	it("rejects unknown templates", () => {
		const result = scaffoldSkill({
			name: "bogus",
			// biome-ignore lint/suspicious/noExplicitAny: intentionally testing invalid input
			template: "does-not-exist" as any,
			description: "Valid description but unknown template.",
			draftRoot,
			templatesRoot: TEMPLATES_ROOT,
		});
		expect(result.success).toBe(false);
		expect(result.error).toMatch(/Unknown template/);
	});

	it("passes the scanner over a freshly scaffolded skill", () => {
		const result = scaffoldSkill({
			name: "scanner-ok",
			template: "basic",
			description: "Scanner baseline skill for tests.",
			draftRoot,
			templatesRoot: TEMPLATES_ROOT,
		});
		expect(result.success).toBe(true);
		const scan = scanSkill(result.draftDir!);
		expect(scan.blocked).toBe(false);
		expect(scan.counts.critical).toBe(0);
		expect(scan.counts.high).toBe(0);
	});
});
