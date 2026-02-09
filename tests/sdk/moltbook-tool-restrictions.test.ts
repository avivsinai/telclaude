import fs from "node:fs";
import os from "node:os";
import path from "node:path";

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
	MOLTBOOK_RPC_RELAY_PUBLIC_KEY: process.env.MOLTBOOK_RPC_RELAY_PUBLIC_KEY,
	TELEGRAM_RPC_RELAY_PUBLIC_KEY: process.env.TELEGRAM_RPC_RELAY_PUBLIC_KEY,
	TELCLAUDE_NETWORK_MODE: process.env.TELCLAUDE_NETWORK_MODE,
	TELCLAUDE_MOLTBOOK_AGENT_WORKDIR: process.env.TELCLAUDE_MOLTBOOK_AGENT_WORKDIR,
};
let tempRoot: string | null = null;
let sandboxRoot: string | null = null;

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
	tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "moltbook-sandbox-"));
	sandboxRoot = path.join(tempRoot, "sandbox");
	fs.mkdirSync(sandboxRoot, { recursive: true });
	process.env.TELCLAUDE_MOLTBOOK_AGENT_WORKDIR = sandboxRoot;
});

afterEach(() => {
	if (ORIGINAL_ENV.MOLTBOOK_RPC_RELAY_PUBLIC_KEY === undefined) {
		delete process.env.MOLTBOOK_RPC_RELAY_PUBLIC_KEY;
	} else {
		process.env.MOLTBOOK_RPC_RELAY_PUBLIC_KEY = ORIGINAL_ENV.MOLTBOOK_RPC_RELAY_PUBLIC_KEY;
	}

	if (ORIGINAL_ENV.TELEGRAM_RPC_RELAY_PUBLIC_KEY === undefined) {
		delete process.env.TELEGRAM_RPC_RELAY_PUBLIC_KEY;
	} else {
		process.env.TELEGRAM_RPC_RELAY_PUBLIC_KEY = ORIGINAL_ENV.TELEGRAM_RPC_RELAY_PUBLIC_KEY;
	}

	if (ORIGINAL_ENV.TELCLAUDE_NETWORK_MODE === undefined) {
		delete process.env.TELCLAUDE_NETWORK_MODE;
	} else {
		process.env.TELCLAUDE_NETWORK_MODE = ORIGINAL_ENV.TELCLAUDE_NETWORK_MODE;
	}

	if (ORIGINAL_ENV.TELCLAUDE_MOLTBOOK_AGENT_WORKDIR === undefined) {
		delete process.env.TELCLAUDE_MOLTBOOK_AGENT_WORKDIR;
	} else {
		process.env.TELCLAUDE_MOLTBOOK_AGENT_WORKDIR =
			ORIGINAL_ENV.TELCLAUDE_MOLTBOOK_AGENT_WORKDIR;
	}

	if (tempRoot) {
		fs.rmSync(tempRoot, { recursive: true, force: true });
	}
	tempRoot = null;
	sandboxRoot = null;
});

describe("moltbook tool restrictions", () => {
	it("allows file tools within the moltbook sandbox", async () => {
		process.env.MOLTBOOK_RPC_RELAY_PUBLIC_KEY = "moltbook";
		delete process.env.TELEGRAM_RPC_RELAY_PUBLIC_KEY;
		process.env.TELCLAUDE_NETWORK_MODE = "permissive";

		const sdkOpts = await buildSdkOptions({ ...baseOpts, userId: "moltbook:agent" });
		const sandboxPath = path.join(sandboxRoot ?? "/moltbook/sandbox", "notes.txt");

		const readRes = await runPreToolUseHooks(sdkOpts, "Read", { file_path: sandboxPath });
		expect(readRes.decision).toBe("allow");

		const writeRes = await runPreToolUseHooks(sdkOpts, "Write", {
			file_path: sandboxPath,
			content: "hi",
		});
		expect(writeRes.decision).toBe("allow");

		const editRes = await runPreToolUseHooks(sdkOpts, "Edit", {
			file_path: sandboxPath,
			old_string: "hi",
			new_string: "hello",
		});
		expect(editRes.decision).toBe("allow");

		const globRes = await runPreToolUseHooks(sdkOpts, "Glob", {
			path: sandboxRoot ?? "/moltbook/sandbox",
			pattern: "*.txt",
		});
		expect(globRes.decision).toBe("allow");

		const grepRes = await runPreToolUseHooks(sdkOpts, "Grep", {
			path: sandboxRoot ?? "/moltbook/sandbox",
			pattern: "hello",
		});
		expect(grepRes.decision).toBe("allow");
	});

	it("blocks file tools outside the moltbook sandbox", async () => {
		process.env.MOLTBOOK_RPC_RELAY_PUBLIC_KEY = "moltbook";
		delete process.env.TELEGRAM_RPC_RELAY_PUBLIC_KEY;
		process.env.TELCLAUDE_NETWORK_MODE = "permissive";

		const sdkOpts = await buildSdkOptions({ ...baseOpts, userId: "moltbook:agent" });
		const fileTools = ["Read", "Write", "Edit", "Glob", "Grep"];
		const outsidePath = path.join(path.dirname(sandboxRoot ?? "/moltbook/sandbox"), "outside");

		for (const toolName of fileTools) {
			let input: Record<string, unknown>;
			switch (toolName) {
				case "Write":
					input = { file_path: `${outsidePath}/file.txt`, content: "hi" };
					break;
				case "Edit":
					input = { file_path: `${outsidePath}/file.txt`, old_string: "hi", new_string: "hello" };
					break;
				case "Glob":
					input = { path: outsidePath, pattern: "*.txt" };
					break;
				case "Grep":
					input = { path: outsidePath, pattern: "hello" };
					break;
				default:
					input = { file_path: `${outsidePath}/file.txt` };
			}
			const res = await runPreToolUseHooks(sdkOpts, toolName, input);
			expect(res.decision).toBe("deny");
			expect(res.reason).toContain("Moltbook context");
		}
	});

	it("blocks path traversal outside the sandbox", async () => {
		process.env.MOLTBOOK_RPC_RELAY_PUBLIC_KEY = "moltbook";
		delete process.env.TELEGRAM_RPC_RELAY_PUBLIC_KEY;
		process.env.TELCLAUDE_NETWORK_MODE = "permissive";

		const sdkOpts = await buildSdkOptions({ ...baseOpts, userId: "moltbook:agent" });
		const res = await runPreToolUseHooks(sdkOpts, "Write", {
			file_path: path.join(sandboxRoot ?? "/moltbook/sandbox", "../tmp/pwn.txt"),
			content: "oops",
		});
		expect(res.decision).toBe("deny");
		expect(res.reason).toContain("Moltbook context");
	});

	it("blocks symlink parent escapes", async () => {
		if (process.platform === "win32") {
			expect(true).toBe(true);
			return;
		}
		const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "moltbook-sandbox-"));
		const sandboxRoot = path.join(tempRoot, "sandbox");
		const outsideRoot = path.join(tempRoot, "outside");
		fs.mkdirSync(sandboxRoot, { recursive: true });
		fs.mkdirSync(outsideRoot, { recursive: true });
		const linkPath = path.join(sandboxRoot, "link");
		try {
			fs.symlinkSync(outsideRoot, linkPath);
		} catch (err) {
			fs.rmSync(tempRoot, { recursive: true, force: true });
			throw err;
		}

		process.env.MOLTBOOK_RPC_RELAY_PUBLIC_KEY = "moltbook";
		delete process.env.TELEGRAM_RPC_RELAY_PUBLIC_KEY;
		process.env.TELCLAUDE_NETWORK_MODE = "permissive";
		process.env.TELCLAUDE_MOLTBOOK_AGENT_WORKDIR = sandboxRoot;

		const sdkOpts = await buildSdkOptions({ ...baseOpts, userId: "moltbook:agent" });
		const res = await runPreToolUseHooks(sdkOpts, "Write", {
			file_path: path.join(linkPath, "new.txt"),
			content: "escape",
		});
		expect(res.decision).toBe("deny");
		expect(res.reason).toContain("Moltbook context");

		fs.rmSync(tempRoot, { recursive: true, force: true });
	});

	it("blocks glob traversal patterns", async () => {
		process.env.MOLTBOOK_RPC_RELAY_PUBLIC_KEY = "moltbook";
		delete process.env.TELEGRAM_RPC_RELAY_PUBLIC_KEY;
		process.env.TELCLAUDE_NETWORK_MODE = "permissive";

		const sdkOpts = await buildSdkOptions({ ...baseOpts, userId: "moltbook:agent" });
		const res = await runPreToolUseHooks(sdkOpts, "Glob", {
			pattern: "../**/*.txt",
		});
		expect(res.decision).toBe("deny");
		expect(res.reason).toContain("traversal");
	});

	it("blocks bash network egress tools in moltbook context", async () => {
		process.env.MOLTBOOK_RPC_RELAY_PUBLIC_KEY = "moltbook";
		delete process.env.TELEGRAM_RPC_RELAY_PUBLIC_KEY;
		process.env.TELCLAUDE_NETWORK_MODE = "permissive";

		const sdkOpts = await buildSdkOptions({ ...baseOpts, userId: "moltbook:agent" });
		const curlRes = await runPreToolUseHooks(sdkOpts, "Bash", { command: "curl https://example.com" });
		expect(curlRes.decision).toBe("deny");
		expect(curlRes.reason).toContain("direct network egress");

		const pyRes = await runPreToolUseHooks(sdkOpts, "Bash", {
			command: "python -c 'import requests; requests.get(\"https://example.com\")'",
		});
		expect(pyRes.decision).toBe("deny");

		const nodeRes = await runPreToolUseHooks(sdkOpts, "Bash", {
			command: "node -e 'fetch(\"https://example.com\")'",
		});
		expect(nodeRes.decision).toBe("deny");
	});

	it("allows Bash, Skill, and Task but blocks NotebookEdit in moltbook context", async () => {
		process.env.MOLTBOOK_RPC_RELAY_PUBLIC_KEY = "moltbook";
		delete process.env.TELEGRAM_RPC_RELAY_PUBLIC_KEY;
		process.env.TELCLAUDE_NETWORK_MODE = "permissive";

		const sdkOpts = await buildSdkOptions({
			...baseOpts,
			enableSkills: true,
			userId: "moltbook:agent",
		});

		const bashRes = await runPreToolUseHooks(sdkOpts, "Bash", { command: "echo ok" });
		expect(bashRes.decision).toBe("allow");

		const skillRes = await runPreToolUseHooks(sdkOpts, "Skill", {});
		expect(skillRes.decision).toBe("allow");

		const taskRes = await runPreToolUseHooks(sdkOpts, "Task", {});
		expect(taskRes.decision).toBe("allow");

		const blockedTools = ["NotebookEdit"];
		for (const toolName of blockedTools) {
			const res = await runPreToolUseHooks(sdkOpts, toolName, {});
			expect(res.decision).toBe("deny");
			expect(res.reason).toContain("Moltbook context");
		}
	});

	it("allows WebFetch and WebSearch in moltbook context", async () => {
		process.env.MOLTBOOK_RPC_RELAY_PUBLIC_KEY = "moltbook";
		delete process.env.TELEGRAM_RPC_RELAY_PUBLIC_KEY;
		process.env.TELCLAUDE_NETWORK_MODE = "permissive";

		const sdkOpts = await buildSdkOptions({ ...baseOpts, userId: "moltbook:agent" });

		const webFetch = await runPreToolUseHooks(sdkOpts, "WebFetch", {
			url: "https://api.github.com/repos",
		});
		expect(webFetch.decision).toBe("allow");

		const webSearch = await runPreToolUseHooks(sdkOpts, "WebSearch", {
			query: "hello world",
		});
		expect(webSearch.decision).toBe("allow");
	});

	it("telegram context allows file tools and Bash", async () => {
		process.env.TELEGRAM_RPC_RELAY_PUBLIC_KEY = "telegram";
		delete process.env.MOLTBOOK_RPC_RELAY_PUBLIC_KEY;
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
