import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { listDraftSkills, promoteSkill } from "../../src/commands/skills-promote.js";

function writeDraftSkill(draftRoot: string, name: string, content?: string): void {
	const skillDir = path.join(draftRoot, name);
	fs.mkdirSync(skillDir, { recursive: true });
	fs.writeFileSync(
		path.join(skillDir, "SKILL.md"),
		content ??
			[
				"---",
				"name: test-skill",
				"description: test",
				"allowed-tools: []",
				"---",
				"",
				"Test skill body.",
			].join("\n"),
		"utf8",
	);
}

describe("skills-promote", () => {
	let tempRoot = "";
	let draftRoot = "";
	let activeRoot = "";

	beforeEach(() => {
		tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "skills-promote-test-"));
		draftRoot = path.join(tempRoot, "skills-draft");
		activeRoot = path.join(tempRoot, "skills");
		fs.mkdirSync(draftRoot, { recursive: true });
		fs.mkdirSync(activeRoot, { recursive: true });
	});

	afterEach(() => {
		if (tempRoot && fs.existsSync(tempRoot)) {
			fs.rmSync(tempRoot, { recursive: true, force: true });
		}
	});

	it("rejects traversal-style skill names", () => {
		const result = promoteSkill("../outside", draftRoot, activeRoot);
		expect(result.success).toBe(false);
		expect(result.error).toContain("Invalid skill name");
	});

	it("rejects skill names with path separators", () => {
		const result = promoteSkill("nested/skill", draftRoot, activeRoot);
		expect(result.success).toBe(false);
		expect(result.error).toContain("Invalid skill name");
	});

	it("promotes valid draft skill to active and removes draft", () => {
		writeDraftSkill(draftRoot, "safe-skill");

		const result = promoteSkill("safe-skill", draftRoot, activeRoot);
		expect(result.success).toBe(true);

		expect(fs.existsSync(path.join(activeRoot, "safe-skill", "SKILL.md"))).toBe(true);
		expect(fs.existsSync(path.join(draftRoot, "safe-skill"))).toBe(false);
	});

	it("listDraftSkills only returns directories with SKILL.md", () => {
		writeDraftSkill(draftRoot, "valid-draft");
		fs.mkdirSync(path.join(draftRoot, "invalid-draft"), { recursive: true });

		const drafts = listDraftSkills(draftRoot);
		expect(drafts).toEqual(["valid-draft"]);
	});
});
