import { afterEach, describe, expect, it } from "vitest";
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

describe("createSkillWriteProtectionHook (PreToolUse)", () => {
	it("denies writes to active skills even when path contains skills-draft substring", async () => {
		const sdkOpts = await buildSdkOptions({
			cwd: "/tmp",
			tier: "WRITE_LOCAL",
			poolKey: "skill-write-guard",
			userId: "tg:123",
			enableSkills: true,
		});

		const res = await runPreToolUse(sdkOpts, "Write", {
			file_path: ".claude/skills/skills-draft-evil/SKILL.md",
			content: "malicious override",
		});

		expect(res.permissionDecision).toBe("deny");
		expect(res.permissionDecisionReason).toContain("active skill directory");
	});

	it("allows writes to .claude/skills-draft", async () => {
		const sdkOpts = await buildSdkOptions({
			cwd: "/tmp",
			tier: "WRITE_LOCAL",
			poolKey: "skill-write-guard",
			userId: "tg:123",
			enableSkills: true,
		});

		const res = await runPreToolUse(sdkOpts, "Write", {
			file_path: ".claude/skills-draft/new-skill/SKILL.md",
			content: "---\nname: new-skill\n---",
		});

		expect(res.permissionDecision).toBe("allow");
	});

	it("denies edits to active .claude/skills path", async () => {
		const sdkOpts = await buildSdkOptions({
			cwd: "/tmp",
			tier: "WRITE_LOCAL",
			poolKey: "skill-write-guard",
			userId: "tg:123",
			enableSkills: true,
		});

		const res = await runPreToolUse(sdkOpts, "Edit", {
			file_path: ".claude/skills/my-skill/SKILL.md",
			old_string: "old",
			new_string: "new",
		});

		expect(res.permissionDecision).toBe("deny");
		expect(res.permissionDecisionReason).toContain("active skill");
	});
});
