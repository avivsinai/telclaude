import { describe, expect, it } from "vitest";

import { buildSdkOptions } from "../../src/sdk/client.js";
import { TIER_TOOLS } from "../../src/security/permissions.js";

const baseOpts = {
	cwd: "/tmp",
	systemPromptAppend: undefined,
	model: undefined,
	maxTurns: undefined,
	includePartialMessages: undefined,
	resumeSessionId: undefined,
	permissionMode: undefined,
	enableSkills: false,
	abortController: undefined,
	timeoutMs: undefined,
} as const;

describe("buildSdkOptions", () => {
	it("READ_ONLY allowlists built-in tools and adds Skill when enabled", async () => {
		const opts = await buildSdkOptions({ ...baseOpts, tier: "READ_ONLY", enableSkills: true });

		expect(opts.tools).toEqual([...TIER_TOOLS.READ_ONLY, "Skill"]);
		expect(opts.allowedTools).toEqual([...TIER_TOOLS.READ_ONLY, "Skill"]);
		expect(opts.permissionMode).toBe("acceptEdits");
		expect(opts.betas).toBeUndefined();
	});

	it("WRITE_LOCAL allowlists built-in tools without Skill when disabled", async () => {
		const opts = await buildSdkOptions({ ...baseOpts, tier: "WRITE_LOCAL", enableSkills: false });

		expect(opts.tools).toEqual(TIER_TOOLS.WRITE_LOCAL);
		expect(opts.allowedTools).toEqual(TIER_TOOLS.WRITE_LOCAL);
		expect(opts.permissionMode).toBe("acceptEdits");
	});

	it("FULL_ACCESS leaves tools undefined and keeps permission controls intact", async () => {
		const opts = await buildSdkOptions({ ...baseOpts, tier: "FULL_ACCESS" });

		expect(opts.tools).toBeUndefined();
		expect(opts.allowedTools).toBeUndefined();
		expect(opts.permissionMode).toBe("acceptEdits");
		expect(opts.allowDangerouslySkipPermissions).toBe(false);
	});

	it("passes through beta headers when provided", async () => {
		const betas = ["context-1m-2025-08-07"] as const;
		const opts = await buildSdkOptions({ ...baseOpts, tier: "READ_ONLY", betas });
		expect(opts.betas).toEqual(betas);
	});

	it("creates an AbortController when timeoutMs is set", async () => {
		const opts = await buildSdkOptions({ ...baseOpts, tier: "READ_ONLY", timeoutMs: 10 });
		expect(opts.abortController).toBeInstanceOf(AbortController);
	});
});
