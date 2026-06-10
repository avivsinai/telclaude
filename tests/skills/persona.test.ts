import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildSkillLoadPlan, listSkillInventory } from "../../src/skills/persona.js";

const ORIGINAL_SKILL_CATALOG_DIR = process.env.TELCLAUDE_SKILL_CATALOG_DIR;

function writeSkill(root: string, relativeDir: string): void {
	const skillDir = path.join(root, "skills", relativeDir);
	fs.mkdirSync(skillDir, { recursive: true });
	fs.writeFileSync(
		path.join(skillDir, "SKILL.md"),
		["---", `name: ${path.basename(skillDir)}`, "description: test", "---", "", "Body."].join("\n"),
		"utf8",
	);
}

describe("persona skill load plans", () => {
	let tempRoot = "";
	let projectRoot = "";
	let skillCatalog = "";

	beforeEach(() => {
		tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-skill-persona-"));
		projectRoot = path.join(tempRoot, "project");
		skillCatalog = path.join(tempRoot, "catalog");
		fs.mkdirSync(projectRoot, { recursive: true });
		fs.mkdirSync(skillCatalog, { recursive: true });
		process.env.TELCLAUDE_SKILL_CATALOG_DIR = skillCatalog;
	});

	afterEach(() => {
		if (ORIGINAL_SKILL_CATALOG_DIR === undefined) {
			delete process.env.TELCLAUDE_SKILL_CATALOG_DIR;
		} else {
			process.env.TELCLAUDE_SKILL_CATALOG_DIR = ORIGINAL_SKILL_CATALOG_DIR;
		}
		fs.rmSync(tempRoot, { recursive: true, force: true });
	});

	it("derives provenance from the skill path", () => {
		writeSkill(skillCatalog, "memory");
		writeSkill(skillCatalog, "agent/telegram/private-helper");
		writeSkill(skillCatalog, "agent/social/xtwitter/x-helper");
		writeSkill(skillCatalog, "agent/social/moltbook/m-helper");

		const inventory = listSkillInventory(projectRoot);
		expect(inventory.find((entry) => entry.name === "memory")?.provenance).toEqual({
			kind: "user",
		});
		expect(inventory.find((entry) => entry.name === "private-helper")?.provenance).toEqual({
			kind: "agent",
			persona: "telegram",
		});
		expect(inventory.find((entry) => entry.name === "x-helper")?.provenance).toEqual({
			kind: "agent",
			persona: "social",
			serviceId: "xtwitter",
		});
	});

	it("loads user and telegram-agent skills for the telegram persona only", () => {
		writeSkill(skillCatalog, "memory");
		writeSkill(skillCatalog, "agent/telegram/private-helper");
		writeSkill(skillCatalog, "agent/social/xtwitter/x-helper");

		const plan = buildSkillLoadPlan({ kind: "telegram" }, { cwd: projectRoot });
		expect(plan.names).toContain("memory");
		expect(plan.names).toContain("private-helper");
		expect(plan.names).not.toContain("x-helper");
		expect(plan.blocked.find((entry) => entry.name === "x-helper")?.reason).toBe(
			"persona_mismatch",
		);
	});

	it("loads nested user-authored skills by Hermes runtime name", () => {
		writeSkill(skillCatalog, "software-development/plan");

		const inventory = listSkillInventory(projectRoot);
		expect(
			inventory.find((entry) => entry.relativeDir === "software-development/plan"),
		).toMatchObject({
			name: "plan",
			relativeDir: "software-development/plan",
			provenance: { kind: "user" },
		});

		const plan = buildSkillLoadPlan(
			{ kind: "social", serviceId: "xtwitter" },
			{ cwd: projectRoot },
		);
		expect(plan.names).toContain("plan");
		expect(plan.names).not.toContain("software-development/plan");
	});

	it("blocks colliding runtime names in the active persona", () => {
		writeSkill(skillCatalog, "software-development/plan");
		writeSkill(skillCatalog, "agent/telegram/plan");

		const plan = buildSkillLoadPlan({ kind: "telegram" }, { cwd: projectRoot });
		expect(plan.names).not.toContain("plan");
		expect(
			plan.blocked
				.filter((entry) => entry.name === "plan")
				.map((entry) => ({ relativeDir: entry.relativeDir, reason: entry.reason }))
				.sort((left, right) => left.relativeDir.localeCompare(right.relativeDir)),
		).toEqual([
			{ relativeDir: "agent/telegram/plan", reason: "name_collision" },
			{ relativeDir: "software-development/plan", reason: "name_collision" },
		]);
	});

	it("blocks colliding runtime names even when the other identity is persona-blocked", () => {
		writeSkill(skillCatalog, "software-development/plan");
		writeSkill(skillCatalog, "agent/social/xtwitter/plan");

		const plan = buildSkillLoadPlan({ kind: "telegram" }, { cwd: projectRoot });
		expect(plan.names).not.toContain("plan");
		expect(
			plan.blocked
				.filter((entry) => entry.name === "plan")
				.map((entry) => ({ relativeDir: entry.relativeDir, reason: entry.reason }))
				.sort((left, right) => left.relativeDir.localeCompare(right.relativeDir)),
		).toEqual([
			{ relativeDir: "agent/social/xtwitter/plan", reason: "name_collision" },
			{ relativeDir: "software-development/plan", reason: "name_collision" },
		]);
	});

	it("keeps same-path trusted overlays loadable and below catalog precedence", () => {
		writeSkill(skillCatalog, "memory");
		writeSkill(path.join(projectRoot, ".claude"), "memory");

		const plan = buildSkillLoadPlan({ kind: "telegram" }, { cwd: projectRoot });
		expect(plan.names).toContain("memory");
		expect(plan.userAuthored.find((entry) => entry.name === "memory")?.root).toBe(
			path.join(skillCatalog, "skills"),
		);
		expect(plan.blocked.filter((entry) => entry.name === "memory")).toEqual([]);
	});

	it("keeps workspace same-path skills from shadowing trusted bundled skills", () => {
		delete process.env.TELCLAUDE_SKILL_CATALOG_DIR;
		writeSkill(path.join(projectRoot, ".claude"), "memory");

		const plan = buildSkillLoadPlan({ kind: "telegram" }, { cwd: projectRoot });
		expect(plan.names).toContain("memory");
		expect(plan.userAuthored.find((entry) => entry.name === "memory")?.root).not.toBe(
			path.join(projectRoot, ".claude", "skills"),
		);
		expect(plan.blocked.filter((entry) => entry.name === "memory")).toEqual([]);
	});

	it("loads social agent skills only for the matching service and explicit allowlist", () => {
		writeSkill(skillCatalog, "memory");
		writeSkill(skillCatalog, "agent/telegram/private-helper");
		writeSkill(skillCatalog, "agent/social/xtwitter/x-helper");
		writeSkill(skillCatalog, "agent/social/moltbook/m-helper");
		writeSkill(skillCatalog, "agent/social/xtwitter/archived/old-helper");

		const defaultPlan = buildSkillLoadPlan(
			{ kind: "social", serviceId: "xtwitter" },
			{ cwd: projectRoot },
		);
		expect(defaultPlan.names).toContain("memory");
		expect(defaultPlan.names).not.toContain("x-helper");
		expect(defaultPlan.blocked.find((entry) => entry.name === "x-helper")?.reason).toBe(
			"agent_skill_not_allowed",
		);
		expect(defaultPlan.blocked.find((entry) => entry.name === "private-helper")?.reason).toBe(
			"persona_mismatch",
		);

		const allowedPlan = buildSkillLoadPlan(
			{ kind: "social", serviceId: "xtwitter", allowedAgentSkills: ["x-helper"] },
			{ cwd: projectRoot },
		);
		expect(allowedPlan.names).toContain("memory");
		expect(allowedPlan.names).toContain("x-helper");
		expect(allowedPlan.names).not.toContain("m-helper");
		expect(allowedPlan.names).not.toContain("old-helper");
		expect(allowedPlan.blocked.find((entry) => entry.name === "m-helper")?.reason).toBe(
			"service_mismatch",
		);
	});
});
