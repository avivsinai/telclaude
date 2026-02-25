import { describe, expect, it } from "vitest";

import { buildSdkOptions } from "../../src/sdk/client.js";

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

describe("createSkillAllowlistHook (PreToolUse)", () => {
	it("allows Skill when skill is in allowedSkills", async () => {
		const sdkOpts = await buildSdkOptions({
			cwd: "/tmp",
			tier: "SOCIAL",
			enableSkills: true,
			allowedSkills: ["memory", "summarize", "social-posting"],
			userId: "social:xtwitter:proactive",
		});

		const res = await runPreToolUse(sdkOpts, "Skill", { skill: "memory" });
		expect(res.permissionDecision).toBe("allow");
	});

	it("denies Skill when skill is NOT in allowedSkills", async () => {
		const sdkOpts = await buildSdkOptions({
			cwd: "/tmp",
			tier: "SOCIAL",
			enableSkills: true,
			allowedSkills: ["memory", "summarize"],
			userId: "social:xtwitter:proactive",
		});

		const res = await runPreToolUse(sdkOpts, "Skill", { skill: "external-provider" });
		expect(res.permissionDecision).toBe("deny");
		expect(res.permissionDecisionReason).toContain("external-provider");
		expect(res.permissionDecisionReason).toContain("not in the allowedSkills");
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
		});

		const res = await runPreToolUse(sdkOpts, "Skill", { skill: "memory" });
		expect(res.permissionDecision).toBe("deny");
		expect(res.permissionDecisionReason).toContain("not in the allowedSkills");
	});

	it("allows all skills for non-SOCIAL tier without allowedSkills (private agent)", async () => {
		const sdkOpts = await buildSdkOptions({
			cwd: "/tmp",
			tier: "WRITE_LOCAL",
			enableSkills: true,
			// no allowedSkills — private agents are trusted
			userId: "tg:123",
		});

		const res = await runPreToolUse(sdkOpts, "Skill", { skill: "external-provider" });
		expect(res.permissionDecision).toBe("allow");
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
