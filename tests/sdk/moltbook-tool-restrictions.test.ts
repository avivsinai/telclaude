import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { checkPrivateNetworkAccess } = vi.hoisted(() => ({
	checkPrivateNetworkAccess: vi.fn(() =>
		Promise.resolve({ allowed: true, matchedEndpoint: undefined }),
	),
}));

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		debug: vi.fn(),
	}),
}));

vi.mock("../../src/sandbox/network-proxy.js", async () => {
	const actual = await vi.importActual<typeof import("../../src/sandbox/network-proxy.js")>(
		"../../src/sandbox/network-proxy.js",
	);
	return {
		...actual,
		checkPrivateNetworkAccess,
	};
});

import { buildSdkOptions } from "../../src/sdk/client.js";

const baseOpts = {
	cwd: "/tmp",
	tier: "READ_ONLY" as const,
	enableSkills: false,
} satisfies Parameters<typeof buildSdkOptions>[0];

const ORIGINAL_ENV = {
	MOLTBOOK_RPC_SECRET: process.env.MOLTBOOK_RPC_SECRET,
	TELEGRAM_RPC_SECRET: process.env.TELEGRAM_RPC_SECRET,
	TELCLAUDE_NETWORK_MODE: process.env.TELCLAUDE_NETWORK_MODE,
};

type HookDecision = { decision: "allow" | "deny"; reason?: string };

async function runPreToolUseHooks(
	sdkOpts: Awaited<ReturnType<typeof buildSdkOptions>>,
	toolName: string,
	toolInput: Record<string, unknown>,
): Promise<HookDecision> {
	const hooks = sdkOpts.hooks?.PreToolUse ?? [];
	let currentInput: Record<string, unknown> = { ...toolInput };

	for (const hookMatcher of hooks) {
		const matcher = hookMatcher as {
			matcher?: string | string[];
			hooks?: Array<(input: unknown) => Promise<unknown>>;
		};
		if (matcher.matcher) {
			const matches =
				typeof matcher.matcher === "string"
					? matcher.matcher === toolName
					: matcher.matcher.includes(toolName);
			if (!matches) {
				continue;
			}
		}

		for (const hookFn of matcher.hooks ?? []) {
			const rawResult = (await hookFn({
				hook_event_name: "PreToolUse",
				tool_name: toolName,
				tool_input: currentInput,
			})) as {
				hookSpecificOutput?: {
					permissionDecision?: string;
					permissionDecisionReason?: string;
					updatedInput?: Record<string, unknown>;
				};
			};
			const output = rawResult.hookSpecificOutput;
			if (output?.permissionDecision === "deny") {
				return { decision: "deny", reason: output.permissionDecisionReason };
			}
			if (output?.updatedInput) {
				currentInput = output.updatedInput;
			}
		}
	}

	return { decision: "allow" };
}

beforeEach(() => {
	checkPrivateNetworkAccess.mockReset();
	checkPrivateNetworkAccess.mockResolvedValue({ allowed: true, matchedEndpoint: undefined });
});

afterEach(() => {
	if (ORIGINAL_ENV.MOLTBOOK_RPC_SECRET === undefined) {
		delete process.env.MOLTBOOK_RPC_SECRET;
	} else {
		process.env.MOLTBOOK_RPC_SECRET = ORIGINAL_ENV.MOLTBOOK_RPC_SECRET;
	}

	if (ORIGINAL_ENV.TELEGRAM_RPC_SECRET === undefined) {
		delete process.env.TELEGRAM_RPC_SECRET;
	} else {
		process.env.TELEGRAM_RPC_SECRET = ORIGINAL_ENV.TELEGRAM_RPC_SECRET;
	}

	if (ORIGINAL_ENV.TELCLAUDE_NETWORK_MODE === undefined) {
		delete process.env.TELCLAUDE_NETWORK_MODE;
	} else {
		process.env.TELCLAUDE_NETWORK_MODE = ORIGINAL_ENV.TELCLAUDE_NETWORK_MODE;
	}
});

describe("moltbook tool restrictions", () => {
	it("blocks file tools in moltbook context", async () => {
		process.env.MOLTBOOK_RPC_SECRET = "moltbook";
		delete process.env.TELEGRAM_RPC_SECRET;
		process.env.TELCLAUDE_NETWORK_MODE = "permissive";

		const sdkOpts = await buildSdkOptions({ ...baseOpts, userId: "moltbook:agent" });
		const fileTools = ["Read", "Write", "Edit", "Glob", "Grep"];

		for (const toolName of fileTools) {
			const res = await runPreToolUseHooks(sdkOpts, toolName, { file_path: "/tmp/file.txt" });
			expect(res.decision).toBe("deny");
			expect(res.reason).toContain("Moltbook context");
		}
	});

	it("blocks Bash, Skill, Task, and NotebookEdit in moltbook context", async () => {
		process.env.MOLTBOOK_RPC_SECRET = "moltbook";
		delete process.env.TELEGRAM_RPC_SECRET;
		process.env.TELCLAUDE_NETWORK_MODE = "permissive";

		const sdkOpts = await buildSdkOptions({ ...baseOpts, userId: "moltbook:agent" });
		const blockedTools = ["Bash", "Skill", "Task", "NotebookEdit"];

		for (const toolName of blockedTools) {
			const input = toolName === "Bash" ? { command: "echo ok" } : {};
			const res = await runPreToolUseHooks(sdkOpts, toolName, input);
			expect(res.decision).toBe("deny");
			expect(res.reason).toContain("Moltbook context");
		}
	});

	it("allows WebFetch and WebSearch in moltbook context", async () => {
		process.env.MOLTBOOK_RPC_SECRET = "moltbook";
		delete process.env.TELEGRAM_RPC_SECRET;
		process.env.TELCLAUDE_NETWORK_MODE = "permissive";

		const sdkOpts = await buildSdkOptions({ ...baseOpts, userId: "moltbook:agent" });

		const webFetch = await runPreToolUseHooks(sdkOpts, "WebFetch", {
			url: "https://example.com",
		});
		expect(webFetch.decision).toBe("allow");

		const webSearch = await runPreToolUseHooks(sdkOpts, "WebSearch", {
			query: "hello world",
		});
		expect(webSearch.decision).toBe("allow");
	});

	it("telegram context allows file tools and Bash", async () => {
		process.env.TELEGRAM_RPC_SECRET = "telegram";
		delete process.env.MOLTBOOK_RPC_SECRET;
		process.env.TELCLAUDE_NETWORK_MODE = "permissive";

		const sdkOpts = await buildSdkOptions({ ...baseOpts, userId: "telegram:agent" });

		const readRes = await runPreToolUseHooks(sdkOpts, "Read", {
			file_path: "/workspace/file.txt",
		});
		expect(readRes.decision).toBe("allow");

		const bashRes = await runPreToolUseHooks(sdkOpts, "Bash", { command: "echo ok" });
		expect(bashRes.decision).toBe("allow");
	});
});
