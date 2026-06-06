import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { buildSdkOptions, probeSkillAllowlistPreToolUse } from "../../src/sdk/client.js";
import { closeDb, resetDatabase } from "../../src/storage/db.js";
import { listSkillInvocations } from "../../src/storage/skill-telemetry.js";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;
const ORIGINAL_SKILL_CATALOG_DIR = process.env.TELCLAUDE_SKILL_CATALOG_DIR;
let tempDir: string | null = null;

type PreToolUseDecision = {
	permissionDecision: "allow" | "deny";
	permissionDecisionReason?: string;
	updatedInput?: Record<string, unknown>;
};

async function runPreToolUse(
	sdkOpts: Awaited<ReturnType<typeof buildSdkOptions>>,
	toolName: string,
	toolInput: Record<string, unknown>,
): Promise<PreToolUseDecision> {
	const hooks = sdkOpts.hooks?.PreToolUse ?? [];

	let currentInput: Record<string, unknown> = toolInput;

	for (const matcher of hooks) {
		if ("matcher" in matcher && matcher.matcher && matcher.matcher !== toolName) {
			continue;
		}
		for (const hook of matcher.hooks) {
			const res = await hook({
				hook_event_name: "PreToolUse",
				tool_name: toolName,
				tool_input: currentInput,
			} as any);

			const out = (res as any)?.hookSpecificOutput;
			if (!out) continue;

			if (out.permissionDecision === "deny") {
				return {
					permissionDecision: "deny",
					permissionDecisionReason: out.permissionDecisionReason,
				};
			}

			if (out.permissionDecision === "allow" && out.updatedInput) {
				currentInput = out.updatedInput;
			}
		}
	}

	return { permissionDecision: "allow", updatedInput: currentInput };
}

function writeCatalogSkill(relativeDir: string): void {
	if (!tempDir) throw new Error("tempDir not initialized");
	const skillDir = path.join(tempDir, "skill-catalog", "skills", relativeDir);
	fs.mkdirSync(skillDir, { recursive: true });
	fs.writeFileSync(
		path.join(skillDir, "SKILL.md"),
		["---", `name: ${path.basename(skillDir)}`, "description: test", "---", "", "Body."].join(
			"\n",
		),
		"utf8",
	);
	process.env.TELCLAUDE_SKILL_CATALOG_DIR = path.join(tempDir, "skill-catalog");
}

describe("createSkillAllowlistHook (PreToolUse)", () => {
	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-skill-telemetry-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		resetDatabase();
	});

	afterEach(() => {
		closeDb();
		if (tempDir) {
			fs.rmSync(tempDir, { recursive: true, force: true });
			tempDir = null;
		}
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
		if (ORIGINAL_SKILL_CATALOG_DIR === undefined) {
			delete process.env.TELCLAUDE_SKILL_CATALOG_DIR;
		} else {
			process.env.TELCLAUDE_SKILL_CATALOG_DIR = ORIGINAL_SKILL_CATALOG_DIR;
		}
	});

	it("allows Skill when skill is in allowedSkills", async () => {
		const sdkOpts = await buildSdkOptions({
			cwd: "/tmp",
			tier: "SOCIAL",
			enableSkills: true,
			allowedSkills: ["memory", "summarize", "social-posting"],
			userId: "social:xtwitter:proactive",
			poolKey: "xtwitter:proactive",
		});

		const res = await runPreToolUse(sdkOpts, "Skill", {
			skill: "memory",
			secret: "raw-secret-must-not-be-stored",
		});
		expect(res.permissionDecision).toBe("allow");

		const rows = listSkillInvocations();
		expect(rows).toHaveLength(1);
		expect(rows[0]).toMatchObject({
			sessionKey: "xtwitter:proactive",
			skillName: "memory",
			decision: "allow",
			denyReason: null,
			source: "social",
			serviceId: "xtwitter",
		});
		expect(JSON.stringify(rows[0])).not.toContain("raw-secret-must-not-be-stored");
	});

	it("denies Skill when skill is NOT in allowedSkills", async () => {
		const sdkOpts = await buildSdkOptions({
			cwd: "/tmp",
			tier: "SOCIAL",
			enableSkills: true,
			allowedSkills: ["memory", "summarize"],
			userId: "social:xtwitter:proactive",
			poolKey: "xtwitter:proactive",
		});

		const res = await runPreToolUse(sdkOpts, "Skill", { skill: "external-provider" });
		expect(res.permissionDecision).toBe("deny");
		expect(res.permissionDecisionReason).toContain("external-provider");
		expect(res.permissionDecisionReason).toContain("not in the allowedSkills");

		const rows = listSkillInvocations();
		expect(rows).toHaveLength(1);
		expect(rows[0]).toMatchObject({
			sessionKey: "xtwitter:proactive",
			skillName: "external-provider",
			decision: "deny",
			source: "social",
			serviceId: "xtwitter",
		});
		expect(rows[0]?.denyReason).toContain("not in the allowedSkills");
	});

	it("denies ALL skills when allowedSkills is empty array", async () => {
		const sdkOpts = await buildSdkOptions({
			cwd: "/tmp",
			tier: "SOCIAL",
			enableSkills: true,
			allowedSkills: [],
			userId: "social:xtwitter:proactive",
		});

		const res = await runPreToolUse(sdkOpts, "Skill", { skill: "memory" });
		expect(res.permissionDecision).toBe("deny");
		expect(res.permissionDecisionReason).toContain("not in the allowedSkills");
	});

	it("denies when tool_input shape is unexpected (fail-closed)", async () => {
		const sdkOpts = await buildSdkOptions({
			cwd: "/tmp",
			tier: "SOCIAL",
			enableSkills: true,
			allowedSkills: ["memory"],
			userId: "social:xtwitter:proactive",
		});

		// No skill/name/command key in input
		const res = await runPreToolUse(sdkOpts, "Skill", { unknown_key: "foo" });
		expect(res.permissionDecision).toBe("deny");
		expect(res.permissionDecisionReason).toContain("could not determine skill name");
	});

	it("extracts skill name from 'name' key", async () => {
		const sdkOpts = await buildSdkOptions({
			cwd: "/tmp",
			tier: "SOCIAL",
			enableSkills: true,
			allowedSkills: ["summarize"],
			userId: "social:xtwitter:proactive",
		});

		const res = await runPreToolUse(sdkOpts, "Skill", { name: "summarize" });
		expect(res.permissionDecision).toBe("allow");
	});

	it("extracts skill name from 'command' key", async () => {
		const sdkOpts = await buildSdkOptions({
			cwd: "/tmp",
			tier: "SOCIAL",
			enableSkills: true,
			allowedSkills: ["social-posting"],
			userId: "social:xtwitter:proactive",
		});

		const res = await runPreToolUse(sdkOpts, "Skill", { command: "social-posting" });
		expect(res.permissionDecision).toBe("allow");
	});

	it("denies all skills when SOCIAL tier has enableSkills but no allowedSkills (fail-closed)", async () => {
		const sdkOpts = await buildSdkOptions({
			cwd: "/tmp",
			tier: "SOCIAL",
			enableSkills: true,
			// no allowedSkills — SOCIAL tier must fail-closed
			userId: "social:xtwitter:proactive",
			poolKey: "xtwitter:proactive",
		});

		const res = await runPreToolUse(sdkOpts, "Skill", { skill: "memory" });
		expect(res.permissionDecision).toBe("deny");
		expect(res.permissionDecisionReason).toContain("not in the allowedSkills");

		const rows = listSkillInvocations();
		expect(rows).toHaveLength(1);
		expect(rows[0]).toMatchObject({
			sessionKey: "xtwitter:proactive",
			skillName: "memory",
			decision: "deny",
			source: "social",
			serviceId: "xtwitter",
		});
	});

	it("probes the registered PreToolUse Skill matcher directly", async () => {
		writeCatalogSkill("memory");
		const allowed = await probeSkillAllowlistPreToolUse({
			cwd: tempDir ?? "/tmp",
			tier: "SOCIAL",
			skillName: "memory",
			allowedSkills: ["memory"],
		});
		expect(allowed).toMatchObject({ hookRegistered: true, decision: "allow" });

		const nonAllowlisted = await probeSkillAllowlistPreToolUse({
			cwd: tempDir ?? "/tmp",
			tier: "SOCIAL",
			skillName: "external-provider",
			allowedSkills: ["memory"],
		});
		expect(nonAllowlisted.hookRegistered).toBe(true);
		expect(nonAllowlisted.decision).toBe("deny");

		const missingAllowlist = await probeSkillAllowlistPreToolUse({
			cwd: tempDir ?? "/tmp",
			tier: "SOCIAL",
			skillName: "memory",
			omitAllowedSkills: true,
		});
		expect(missingAllowlist.hookRegistered).toBe(true);
		expect(missingAllowlist.decision).toBe("deny");

		const emptyAllowlist = await probeSkillAllowlistPreToolUse({
			cwd: tempDir ?? "/tmp",
			tier: "SOCIAL",
			skillName: "memory",
			allowedSkills: [],
		});
		expect(emptyAllowlist.hookRegistered).toBe(true);
		expect(emptyAllowlist.decision).toBe("deny");
	});

	it("probes nested user-authored Skill runtime names through the registered matcher", async () => {
		writeCatalogSkill("software-development/plan");
		writeCatalogSkill("software-development/test-driven-development");
		const allowed = await probeSkillAllowlistPreToolUse({
			cwd: tempDir ?? "/tmp",
			tier: "SOCIAL",
			skillName: "plan",
			allowedSkills: ["plan"],
		});
		expect(allowed).toMatchObject({ hookRegistered: true, decision: "allow" });

		const relativePathAllowlist = await probeSkillAllowlistPreToolUse({
			cwd: tempDir ?? "/tmp",
			tier: "SOCIAL",
			skillName: "plan",
			allowedSkills: ["software-development/plan"],
		});
		expect(relativePathAllowlist).toMatchObject({ hookRegistered: true, decision: "deny" });

		const loadableButNotAllowlisted = await probeSkillAllowlistPreToolUse({
			cwd: tempDir ?? "/tmp",
			tier: "SOCIAL",
			skillName: "test-driven-development",
			allowedSkills: ["plan"],
		});
		expect(loadableButNotAllowlisted).toMatchObject({
			hookRegistered: true,
			decision: "deny",
		});
		expect(loadableButNotAllowlisted.reason).toContain("not in the allowedSkills");
	});

	it("reports no registered PreToolUse Skill matcher when skills are disabled", async () => {
		const result = await probeSkillAllowlistPreToolUse({
			cwd: tempDir ?? "/tmp",
			tier: "SOCIAL",
			skillName: "memory",
			allowedSkills: ["memory"],
			enableSkills: false,
		});
		expect(result).toMatchObject({ hookRegistered: false, decision: "deny" });
	});

	it("allows all skills for non-SOCIAL tier without allowedSkills (private agent)", async () => {
		const sdkOpts = await buildSdkOptions({
			cwd: "/tmp",
			tier: "WRITE_LOCAL",
			enableSkills: true,
			// no allowedSkills — private agents are trusted
			userId: "tg:123",
			poolKey: "tg:123",
		});

		const res = await runPreToolUse(sdkOpts, "Skill", { skill: "external-provider" });
		expect(res.permissionDecision).toBe("allow");

		const rows = listSkillInvocations();
		expect(rows).toHaveLength(1);
		expect(rows[0]).toMatchObject({
			sessionKey: "tg:123",
			skillName: "external-provider",
			decision: "allow",
			source: "telegram",
			serviceId: null,
		});
	});

	it("denies social-agent-authored skills in the telegram persona", async () => {
		writeCatalogSkill("agent/social/xtwitter/social-owned");
		const sdkOpts = await buildSdkOptions({
			cwd: tempDir ?? "/tmp",
			tier: "WRITE_LOCAL",
			enableSkills: true,
			userId: "tg:123",
			poolKey: "tg:123",
		});

		expect(sdkOpts.skills).not.toContain("social-owned");
		const res = await runPreToolUse(sdkOpts, "Skill", { skill: "social-owned" });
		expect(res.permissionDecision).toBe("deny");
		expect(res.permissionDecisionReason).toContain("not loadable in this persona");
	});

	it("does not let SOCIAL allowedSkills auto-include agent-authored service skills", async () => {
		writeCatalogSkill("memory");
		writeCatalogSkill("agent/social/xtwitter/x-helper");
		const sdkOpts = await buildSdkOptions({
			cwd: tempDir ?? "/tmp",
			tier: "SOCIAL",
			enableSkills: true,
			allowedSkills: ["memory", "x-helper"],
			userId: "social:xtwitter:proactive",
			poolKey: "xtwitter:proactive",
			telemetryServiceId: "xtwitter",
		});

		expect(sdkOpts.skills).toContain("memory");
		expect(sdkOpts.skills).not.toContain("x-helper");
		const res = await runPreToolUse(sdkOpts, "Skill", { skill: "x-helper" });
		expect(res.permissionDecision).toBe("deny");
		expect(res.permissionDecisionReason).toContain("not loadable in this persona");
	});

	it("allows SOCIAL service agent skills only through agentSkillsAllowed", async () => {
		writeCatalogSkill("memory");
		writeCatalogSkill("agent/social/xtwitter/x-helper");
		writeCatalogSkill("agent/social/moltbook/m-helper");
		const sdkOpts = await buildSdkOptions({
			cwd: tempDir ?? "/tmp",
			tier: "SOCIAL",
			enableSkills: true,
			allowedSkills: ["memory"],
			agentSkillsAllowed: ["x-helper"],
			userId: "social:xtwitter:proactive",
			poolKey: "xtwitter:proactive",
			telemetryServiceId: "xtwitter",
		});

		expect(sdkOpts.skills).toContain("memory");
		expect(sdkOpts.skills).toContain("x-helper");
		expect(sdkOpts.skills).not.toContain("m-helper");
		const allowed = await runPreToolUse(sdkOpts, "Skill", { skill: "x-helper" });
		expect(allowed.permissionDecision).toBe("allow");
		const denied = await runPreToolUse(sdkOpts, "Skill", { skill: "m-helper" });
		expect(denied.permissionDecision).toBe("deny");
		expect(denied.permissionDecisionReason).toContain("not loadable in this persona");
	});

	it("denies when conflicting skill names across keys (fail-closed)", async () => {
		const sdkOpts = await buildSdkOptions({
			cwd: "/tmp",
			tier: "SOCIAL",
			enableSkills: true,
			allowedSkills: ["memory", "external-provider"],
			userId: "social:xtwitter:proactive",
		});

		// Both skill and command present with different values
		const res = await runPreToolUse(sdkOpts, "Skill", {
			skill: "memory",
			command: "external-provider",
		});
		expect(res.permissionDecision).toBe("deny");
		expect(res.permissionDecisionReason).toContain("could not determine skill name");
	});

	it("allows when multiple keys carry the same skill name", async () => {
		const sdkOpts = await buildSdkOptions({
			cwd: "/tmp",
			tier: "SOCIAL",
			enableSkills: true,
			allowedSkills: ["memory"],
			userId: "social:xtwitter:proactive",
		});

		const res = await runPreToolUse(sdkOpts, "Skill", {
			skill: "memory",
			name: "memory",
		});
		expect(res.permissionDecision).toBe("allow");
	});

	it("does not interfere with non-Skill tools", async () => {
		const sdkOpts = await buildSdkOptions({
			cwd: "/tmp",
			tier: "SOCIAL",
			enableSkills: true,
			allowedSkills: ["memory"],
			userId: "social:xtwitter:proactive",
		});

		// WebSearch is used here since it bypasses sensitive path checks (server-side requests)
		const res = await runPreToolUse(sdkOpts, "WebSearch", { query: "hello world" });
		expect(res.permissionDecision).toBe("allow");
		expect(listSkillInvocations()).toHaveLength(0);
	});

	it("works alongside existing social tool restriction hook", async () => {
		const sdkOpts = await buildSdkOptions({
			cwd: "/tmp",
			tier: "SOCIAL",
			enableSkills: true,
			allowedSkills: ["memory"],
			userId: "social:xtwitter", // untrusted actor
		});

		// Bash should still be denied by social tool restriction (untrusted actor)
		const bashRes = await runPreToolUse(sdkOpts, "Bash", { command: "echo ok" });
		expect(bashRes.permissionDecision).toBe("deny");

		// Skill not in allowlist should be denied by skill allowlist hook
		const skillRes = await runPreToolUse(sdkOpts, "Skill", { skill: "integration-test" });
		expect(skillRes.permissionDecision).toBe("deny");
	});
});
