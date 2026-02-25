import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Hoist shared mocks
const { containsBlockedCommand, isSensitivePath, checkPrivateNetworkAccess } = vi.hoisted(() => ({
	containsBlockedCommand: vi.fn<string | null, [string]>(() => null),
	isSensitivePath: vi.fn<boolean, [string]>(() => false),
	checkPrivateNetworkAccess: vi.fn(() =>
		Promise.resolve({ allowed: true, matchedEndpoint: undefined }),
	),
}));

vi.mock("../../src/security/permissions.js", async () => {
	const actual = await vi.importActual<typeof import("../../src/security/permissions.js")>(
		"../../src/security/permissions.js",
	);
	return {
		...actual,
		TIER_TOOLS: {
			READ_ONLY: ["Read", "Glob", "Grep", "WebFetch", "WebSearch"],
			WRITE_LOCAL: ["Read", "Glob", "Grep", "WebFetch", "WebSearch", "Write", "Edit", "Bash"],
			SOCIAL: ["Read", "Write", "Edit", "Glob", "Grep", "Bash", "WebFetch", "WebSearch", "Task"],
			FULL_ACCESS: [],
		},
		containsBlockedCommand,
		isSensitivePath,
	};
});

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

// Save original env
let originalNetworkMode: string | undefined;

beforeEach(() => {
	originalNetworkMode = process.env.TELCLAUDE_NETWORK_MODE;
});

afterEach(() => {
	containsBlockedCommand.mockReset();
	isSensitivePath.mockReset();
	checkPrivateNetworkAccess.mockReset();
		checkPrivateNetworkAccess.mockResolvedValue({ allowed: true, matchedEndpoint: undefined });
	// Restore original env
	if (originalNetworkMode === undefined) {
		delete process.env.TELCLAUDE_NETWORK_MODE;
	} else {
		process.env.TELCLAUDE_NETWORK_MODE = originalNetworkMode;
	}
});

describe("buildSdkOptions.canUseTool", () => {
	it("denies Read on sensitive path", async () => {
		isSensitivePath.mockReturnValueOnce(true);
		const sdkOpts = await buildSdkOptions({ ...baseOpts });
		const res = await sdkOpts.canUseTool?.("Read", { file_path: "/secret" });
		expect(res?.behavior).toBe("deny");
	});

	it("denies Bash with blocked command in WRITE_LOCAL", async () => {
		containsBlockedCommand.mockReturnValueOnce("rm");
		const sdkOpts = await buildSdkOptions({ ...baseOpts, tier: "WRITE_LOCAL" });
		const res = await sdkOpts.canUseTool?.("Bash", { command: "rm -rf /" });
		expect(res?.behavior).toBe("deny");
		expect(res?.message).toContain("blocked operation");
	});

it("allows Bash without altering the command (SDK sandbox handles isolation)", async () => {
	// SDK sandbox handles OS-level isolation for Bash; no command wrapping required.
	const sdkOpts = await buildSdkOptions({ ...baseOpts, tier: "WRITE_LOCAL" });
	const res = await sdkOpts.canUseTool?.("Bash", { command: "echo ok" });
	expect(res?.behavior).toBe("allow");
	// Command is passed through unchanged - SDK sandbox handles isolation
	expect((res as any).updatedInput.command).toBe("echo ok");
});

	it("only scans path-bearing fields, not arbitrary nested paths", async () => {
		// Changed behavior: we now only scan known path-bearing fields (file_path, path, pattern, command)
		// to avoid false positives on content fields like Write.content or Edit.new_string.
		// Arbitrary nested paths like meta.path are NOT scanned.
		isSensitivePath.mockReturnValue(true);
		const sdkOpts = await buildSdkOptions({ ...baseOpts });
		const res = await sdkOpts.canUseTool?.("Read", { meta: { path: "/very/secret" } });
		expect(res?.behavior).toBe("allow"); // Not blocked because meta.path is not a path-bearing field
	});

	it("allows non-sensitive Read", async () => {
		const sdkOpts = await buildSdkOptions({ ...baseOpts });
		const res = await sdkOpts.canUseTool?.("Read", { file_path: "/safe/path.txt" });
		expect(res?.behavior).toBe("allow");
	});
});

describe("buildSdkOptions.canUseTool network filtering", () => {
	describe("strict mode (default)", () => {
		beforeEach(() => {
			delete process.env.TELCLAUDE_NETWORK_MODE;
		});

		it("allows WebFetch to allowlisted domain", async () => {
			const sdkOpts = await buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebFetch", { url: "https://api.github.com/repos" });
			expect(res?.behavior).toBe("allow");
		});

		it("denies WebFetch to non-allowlisted domain", async () => {
			const sdkOpts = await buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebFetch", { url: "https://evil.example.com/data" });
			expect(res?.behavior).toBe("deny");
			expect((res as any)?.message).toContain("not in allowlist");
		});

		it("denies WebFetch to private network (localhost)", async () => {
			checkPrivateNetworkAccess.mockResolvedValueOnce({
				allowed: false,
				reason: "Private IP is not in the allowlist",
			});
			const sdkOpts = await buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebFetch", { url: "http://127.0.0.1:8080/api" });
			expect(res?.behavior).toBe("deny");
			expect((res as any)?.message).toContain("not in the allowlist");
		});

		it("denies WebFetch to metadata endpoint", async () => {
			checkPrivateNetworkAccess.mockResolvedValueOnce({
				allowed: false,
				reason: "Private IP is not in the allowlist",
			});
			const sdkOpts = await buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebFetch", { url: "http://169.254.169.254/latest/meta-data" });
			expect(res?.behavior).toBe("deny");
			expect((res as any)?.message).toContain("not in the allowlist");
		});

		it("denies WebFetch to non-HTTP protocol", async () => {
			const sdkOpts = await buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebFetch", { url: "file:///etc/passwd" });
			expect(res?.behavior).toBe("deny");
			expect((res as any)?.message).toContain("HTTP/HTTPS");
		});

		it("allows WebSearch (uses query, not url - server-side requests)", async () => {
			// WebSearch uses `query` parameter, not `url`. Requests are made server-side by Anthropic.
			// We don't filter WebSearch because we can't control Anthropic's search service.
			const sdkOpts = await buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebSearch", { query: "how to hack servers" });
			expect(res?.behavior).toBe("allow");
		});
	});

	describe("permissive mode (TELCLAUDE_NETWORK_MODE=permissive)", () => {
		beforeEach(() => {
			process.env.TELCLAUDE_NETWORK_MODE = "permissive";
		});

		it("allows WebFetch to allowlisted domain", async () => {
			const sdkOpts = await buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebFetch", { url: "https://api.github.com/repos" });
			expect(res?.behavior).toBe("allow");
		});

		it("allows WebFetch to non-allowlisted public domain", async () => {
			const sdkOpts = await buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebFetch", { url: "https://random-website.example.com/data" });
			expect(res?.behavior).toBe("allow");
		});

		it("still denies WebFetch to private network (localhost)", async () => {
			checkPrivateNetworkAccess.mockResolvedValueOnce({
				allowed: false,
				reason: "Private IP is not in the allowlist",
			});
			const sdkOpts = await buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebFetch", { url: "http://127.0.0.1:8080/api" });
			expect(res?.behavior).toBe("deny");
			expect((res as any)?.message).toContain("not in the allowlist");
		});

		it("still denies WebFetch to RFC1918 addresses", async () => {
			checkPrivateNetworkAccess.mockResolvedValueOnce({
				allowed: false,
				reason: "Private IP is not in the allowlist",
			});
			const sdkOpts = await buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebFetch", { url: "http://192.168.1.1/admin" });
			expect(res?.behavior).toBe("deny");
			expect((res as any)?.message).toContain("not in the allowlist");
		});

		it("still denies WebFetch to metadata endpoint", async () => {
			checkPrivateNetworkAccess.mockResolvedValueOnce({
				allowed: false,
				reason: "Private IP is not in the allowlist",
			});
			const sdkOpts = await buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebFetch", { url: "http://169.254.169.254/latest/meta-data" });
			expect(res?.behavior).toBe("deny");
			expect((res as any)?.message).toContain("not in the allowlist");
		});

		it("still denies WebFetch to non-HTTP protocol", async () => {
			const sdkOpts = await buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebFetch", { url: "file:///etc/passwd" });
			expect(res?.behavior).toBe("deny");
			expect((res as any)?.message).toContain("HTTP/HTTPS");
		});

		it("allows WebSearch (server-side, uses query not url)", async () => {
			// WebSearch uses `query` parameter, not `url`. Requests are made server-side by Anthropic.
			// We don't filter WebSearch because we can't control Anthropic's search service.
			const sdkOpts = await buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebSearch", { query: "private network 10.0.0.1" });
			expect(res?.behavior).toBe("allow");
		});
	});

	describe("open mode (TELCLAUDE_NETWORK_MODE=open)", () => {
		beforeEach(() => {
			process.env.TELCLAUDE_NETWORK_MODE = "open";
		});

		it("allows WebFetch to non-allowlisted public domain", async () => {
			const sdkOpts = await buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebFetch", { url: "https://any-domain.example.org/api" });
			expect(res?.behavior).toBe("allow");
		});

		it("still denies WebFetch to private network", async () => {
			checkPrivateNetworkAccess.mockResolvedValueOnce({
				allowed: false,
				reason: "Private IP is not in the allowlist",
			});
			const sdkOpts = await buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebFetch", { url: "http://172.16.0.1/admin" });
			expect(res?.behavior).toBe("deny");
			expect((res as any)?.message).toContain("not in the allowlist");
		});

		it("allows WebSearch (server-side, uses query not url)", async () => {
			// WebSearch is not filtered in any mode - requests are made server-side by Anthropic
			const sdkOpts = await buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebSearch", { query: "anything goes" });
			expect(res?.behavior).toBe("allow");
		});
	});
});

describe("buildSdkOptions PreToolUse hook", () => {
	// Helper to invoke the PreToolUse hook directly
	async function invokeWebFetchHook(
		sdkOpts: ReturnType<typeof buildSdkOptions>,
		url: string,
	): Promise<{ continue?: boolean; decision?: string; reason?: string }> {
		const hooks = sdkOpts.hooks?.PreToolUse;
		if (!hooks || hooks.length === 0) {
			return { continue: true };
		}
		// Network hook is the first hook
		const hookMatcher = hooks[0] as { hooks: Array<(input: unknown) => Promise<unknown>> };
		const hookFn = hookMatcher.hooks[0];
		const rawResult = (await hookFn({
			hook_event_name: "PreToolUse",
			tool_name: "WebFetch",
			tool_input: { url },
		})) as {
			hookSpecificOutput?: {
				hookEventName?: string;
				permissionDecision?: string;
				permissionDecisionReason?: string;
			};
		};

		// Map new format to old test format for compatibility
		const hookOutput = rawResult.hookSpecificOutput;
		if (!hookOutput) {
			return { continue: true };
		}

		if (hookOutput.permissionDecision === "deny") {
			return { decision: "block", reason: hookOutput.permissionDecisionReason };
		}
		if (hookOutput.permissionDecision === "allow") {
			return { continue: true };
		}

		return { continue: true };
	}

	beforeEach(() => {
		delete process.env.TELCLAUDE_NETWORK_MODE;
	});

	afterEach(() => {
		checkPrivateNetworkAccess.mockReset();
		checkPrivateNetworkAccess.mockResolvedValue({ allowed: true, matchedEndpoint: undefined });
	});

	describe("hook runs unconditionally (defense-in-depth)", () => {
		it("blocks private network via hook even if canUseTool would allow", async () => {
			checkPrivateNetworkAccess.mockResolvedValueOnce({
				allowed: false,
				reason: "Private IP is not in the allowlist",
			});
			const sdkOpts = await buildSdkOptions({ ...baseOpts });
			const res = await invokeWebFetchHook(sdkOpts, "http://127.0.0.1:8080/api");
			expect(res.decision).toBe("block");
			expect(res.reason).toContain("not in the allowlist");
		});

		it("blocks metadata endpoint via hook", async () => {
			checkPrivateNetworkAccess.mockResolvedValueOnce({
				allowed: false,
				reason: "Private IP is not in the allowlist",
			});
			const sdkOpts = await buildSdkOptions({ ...baseOpts });
			const res = await invokeWebFetchHook(sdkOpts, "http://169.254.169.254/latest/meta-data");
			expect(res.decision).toBe("block");
			expect(res.reason).toContain("not in the allowlist");
		});

		it("blocks non-HTTP protocol via hook", async () => {
			const sdkOpts = await buildSdkOptions({ ...baseOpts });
			const res = await invokeWebFetchHook(sdkOpts, "file:///etc/passwd");
			expect(res.decision).toBe("block");
			expect(res.reason).toContain("HTTP/HTTPS");
		});

		it("blocks invalid URL via hook", async () => {
			const sdkOpts = await buildSdkOptions({ ...baseOpts });
			const res = await invokeWebFetchHook(sdkOpts, "not-a-valid-url");
			expect(res.decision).toBe("block");
			expect(res.reason).toContain("Invalid URL");
		});
	});

	describe("strict mode (default)", () => {
		it("blocks non-allowlisted domain via hook", async () => {
			const sdkOpts = await buildSdkOptions({ ...baseOpts });
			const res = await invokeWebFetchHook(sdkOpts, "https://evil.example.com/data");
			expect(res.decision).toBe("block");
			expect(res.reason).toContain("not in allowlist");
		});

		it("allows allowlisted domain via hook", async () => {
			const sdkOpts = await buildSdkOptions({ ...baseOpts });
			const res = await invokeWebFetchHook(sdkOpts, "https://api.github.com/repos");
			expect(res.continue).toBe(true);
		});
	});

	describe("permissive mode", () => {
		beforeEach(() => {
			process.env.TELCLAUDE_NETWORK_MODE = "permissive";
		});

		it("allows non-allowlisted public domain via hook", async () => {
			const sdkOpts = await buildSdkOptions({ ...baseOpts });
			const res = await invokeWebFetchHook(sdkOpts, "https://random-site.example.com/api");
			expect(res.continue).toBe(true);
		});

		it("still blocks private network via hook", async () => {
			checkPrivateNetworkAccess.mockResolvedValueOnce({
				allowed: false,
				reason: "Private IP 192.168.1.1 is not in the allowlist",
			});
			const sdkOpts = await buildSdkOptions({ ...baseOpts });
			const res = await invokeWebFetchHook(sdkOpts, "http://192.168.1.1/admin");
			expect(res.decision).toBe("block");
			expect(res.reason).toContain("not in the allowlist");
		});
	});

	describe("hook only applies to WebFetch", () => {
		it("continues for non-WebFetch tools", async () => {
			const sdkOpts = await buildSdkOptions({ ...baseOpts });
			const hooks = sdkOpts.hooks?.PreToolUse;
			const hookMatcher = hooks?.[0] as { hooks: Array<(input: unknown) => Promise<unknown>> };
			const hookFn = hookMatcher?.hooks[0];
			if (!hookFn) return;

			// WebSearch should pass through (network hook only applies to WebFetch)
			const res = (await hookFn({
				hook_event_name: "PreToolUse",
				tool_name: "WebSearch",
				tool_input: { query: "anything" },
			})) as {
				hookSpecificOutput?: {
					permissionDecision?: string;
				};
			};
			// Network hook returns "allow" for non-WebFetch tools
			expect(res.hookSpecificOutput?.permissionDecision).toBe("allow");
		});
	});

	describe("skill allowlist canUseTool fallback", () => {
		it("denies Skill when not in allowedSkills via canUseTool", async () => {
			const sdkOpts = await buildSdkOptions({
				cwd: "/tmp",
				tier: "SOCIAL",
				enableSkills: true,
				allowedSkills: ["memory"],
				userId: "social:xtwitter:proactive",
			});
			const res = await sdkOpts.canUseTool!("Skill", { skill: "external-provider" });
			expect(res.behavior).toBe("deny");
			expect(res.message).toContain("not in the allowedSkills");
		});

		it("allows Skill when in allowedSkills via canUseTool", async () => {
			const sdkOpts = await buildSdkOptions({
				cwd: "/tmp",
				tier: "SOCIAL",
				enableSkills: true,
				allowedSkills: ["memory"],
				userId: "social:xtwitter:proactive",
			});
			const res = await sdkOpts.canUseTool!("Skill", { skill: "memory" });
			expect(res.behavior).toBe("allow");
		});

		it("denies Skill for SOCIAL tier without allowedSkills via canUseTool (fail-closed)", async () => {
			const sdkOpts = await buildSdkOptions({
				cwd: "/tmp",
				tier: "SOCIAL",
				enableSkills: true,
				// no allowedSkills
				userId: "social:xtwitter:proactive",
			});
			const res = await sdkOpts.canUseTool!("Skill", { skill: "memory" });
			expect(res.behavior).toBe("deny");
		});
	});

	describe("settingSources prevents user bypass", () => {
		it("loads only project settings by default to prevent disableAllHooks bypass", async () => {
			// SECURITY: Without enableSkills, settingSources must be ["project"] to prevent:
			// - User settings with disableAllHooks: true
			// - User settings with permissive WebFetch rules
			const sdkOptsWithoutSkills = await buildSdkOptions({ ...baseOpts, enableSkills: false });
			expect(sdkOptsWithoutSkills.settingSources).toEqual(["project"]);
		});

		it("includes user settings when skills are enabled for skill discovery", async () => {
			// When enableSkills is true, we need "user" in settingSources so the SDK
			// discovers skills at $CLAUDE_CONFIG_DIR/skills/.
			// Safe because isSensitivePath blocks writes to $CLAUDE_CONFIG_DIR/settings*.json.
			const sdkOptsWithSkills = await buildSdkOptions({ ...baseOpts, enableSkills: true });
			expect(sdkOptsWithSkills.settingSources).toEqual(["user", "project"]);
		});
	});
});
