import { afterEach, describe, expect, it } from "vitest";

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

const ORIGINAL_DOCKER_ENV = process.env.TELCLAUDE_DOCKER;
const ORIGINAL_OPENAI_KEY = process.env.OPENAI_API_KEY;
const ORIGINAL_GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const ORIGINAL_GH_TOKEN = process.env.GH_TOKEN;

afterEach(() => {
	if (ORIGINAL_DOCKER_ENV === undefined) {
		delete process.env.TELCLAUDE_DOCKER;
	} else {
		process.env.TELCLAUDE_DOCKER = ORIGINAL_DOCKER_ENV;
	}
	if (ORIGINAL_OPENAI_KEY === undefined) {
		delete process.env.OPENAI_API_KEY;
	} else {
		process.env.OPENAI_API_KEY = ORIGINAL_OPENAI_KEY;
	}
	if (ORIGINAL_GITHUB_TOKEN === undefined) {
		delete process.env.GITHUB_TOKEN;
	} else {
		process.env.GITHUB_TOKEN = ORIGINAL_GITHUB_TOKEN;
	}
	if (ORIGINAL_GH_TOKEN === undefined) {
		delete process.env.GH_TOKEN;
	} else {
		process.env.GH_TOKEN = ORIGINAL_GH_TOKEN;
	}
});

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

	it("does not inject raw OPENAI or GitHub credentials into Docker sandbox env", async () => {
		process.env.TELCLAUDE_DOCKER = "1";
		process.env.OPENAI_API_KEY = "openai-secret";
		process.env.GITHUB_TOKEN = "github-secret";
		process.env.GH_TOKEN = "gh-secret";

		const opts = await buildSdkOptions({ ...baseOpts, tier: "FULL_ACCESS" });
		const env = opts.env as Record<string, string> | undefined;

		expect(env).toBeDefined();
		expect(env?.OPENAI_API_KEY).toBeUndefined();
		expect(env?.GITHUB_TOKEN).toBeUndefined();
		expect(env?.GH_TOKEN).toBeUndefined();
	});
});
