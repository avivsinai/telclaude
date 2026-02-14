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
		// The SDK only invokes matchers for the specific tool (when matcher is provided).
		if ("matcher" in matcher && matcher.matcher && matcher.matcher !== toolName) {
			continue;
		}
		for (const hook of matcher.hooks) {
			// Minimal HookInput shape used by our hooks.
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

describe("createSocialToolRestrictionHook (PreToolUse)", () => {
	it("denies Bash for untrusted social actors (notifications)", async () => {
		const sdkOpts = await buildSdkOptions({
			cwd: "/tmp",
			tier: "SOCIAL",
			poolKey: "xtwitter:social",
			userId: "social:xtwitter",
			enableSkills: false,
		});

		const res = await runPreToolUse(sdkOpts, "Bash", { command: "echo ok" });
		expect(res.permissionDecision).toBe("deny");
		expect(res.permissionDecisionReason).toContain("Bash is not available");
	});

	it("allows Bash for trusted social actors (proactive — user-promoted content)", async () => {
		const sdkOpts = await buildSdkOptions({
			cwd: "/tmp",
			tier: "SOCIAL",
			poolKey: "xtwitter:proactive",
			userId: "social:xtwitter:proactive",
			enableSkills: true,
		});

		const res = await runPreToolUse(sdkOpts, "Bash", { command: "echo ok" });
		expect(res.permissionDecision).toBe("allow");
	});

	it("allows Bash for trusted social actors (operator)", async () => {
		const sdkOpts = await buildSdkOptions({
			cwd: "/tmp",
			tier: "SOCIAL",
			poolKey: "xtwitter:operator-query",
			userId: "social:xtwitter:operator",
			enableSkills: true,
		});

		const res = await runPreToolUse(sdkOpts, "Bash", { command: "echo ok" });
		expect(res.permissionDecision).toBe("allow");
	});

	it("allows Bash for trusted social actors (autonomous)", async () => {
		const sdkOpts = await buildSdkOptions({
			cwd: "/tmp",
			tier: "SOCIAL",
			poolKey: "xtwitter:autonomous",
			userId: "social:xtwitter:autonomous",
			enableSkills: false,
		});

		const res = await runPreToolUse(sdkOpts, "Bash", { command: "echo ok" });
		expect(res.permissionDecision).toBe("allow");
	});

	it("denies Write to /home/telclaude-skills for all social actors (skill poisoning)", async () => {
		const sdkOpts = await buildSdkOptions({
			cwd: "/tmp",
			tier: "SOCIAL",
			poolKey: "xtwitter:social",
			userId: "social:xtwitter:operator",
			enableSkills: true,
		});

		const res = await runPreToolUse(sdkOpts, "Write", {
			file_path: "/home/telclaude-skills/skills/browser-automation/SKILL.md",
			content: "pwned",
		});
		expect(res.permissionDecision).toBe("deny");
		expect(res.permissionDecisionReason).toContain("writing to this location is not permitted");
	});
});

