import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Hoist shared mocks
const { containsBlockedCommand, isSensitivePath, isSandboxInitialized, wrapCommand, isBlockedHost } = vi.hoisted(
	() => ({
		containsBlockedCommand: vi.fn<string | null, [string]>(() => null),
		isSensitivePath: vi.fn<boolean, [string]>(() => false),
		isSandboxInitialized: vi.fn<boolean, []>(() => false),
		wrapCommand: vi.fn<Promise<string>, [string]>(),
		isBlockedHost: vi.fn<Promise<boolean>, [string]>(() => Promise.resolve(false)),
	}),
);

vi.mock("../../src/security/permissions.js", async () => {
	const actual = await vi.importActual<typeof import("../../src/security/permissions.js")>(
		"../../src/security/permissions.js",
	);
	return {
		...actual,
		TIER_TOOLS: {
			READ_ONLY: ["Read", "Glob", "Grep", "WebFetch", "WebSearch"],
			WRITE_LOCAL: ["Read", "Glob", "Grep", "WebFetch", "WebSearch", "Write", "Edit", "Bash"],
			FULL_ACCESS: [],
		},
		containsBlockedCommand,
		isSensitivePath,
	};
});

vi.mock("../../src/sandbox/index.js", async () => {
	const actual = await vi.importActual<typeof import("../../src/sandbox/index.js")>(
		"../../src/sandbox/index.js",
	);
	return {
		...actual,
		isSandboxInitialized,
		wrapCommand,
		getSandboxConfigForTier: vi.fn(() => ({})),
		updateSandboxConfig: vi.fn(),
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
		isBlockedHost,
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
	isSandboxInitialized.mockReset();
	wrapCommand.mockReset();
	isBlockedHost.mockReset();
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
		const sdkOpts = buildSdkOptions({ ...baseOpts });
		const res = await sdkOpts.canUseTool?.("Read", { file_path: "/secret" });
		expect(res?.behavior).toBe("deny");
	});

	it("denies Bash with blocked command in WRITE_LOCAL", async () => {
		containsBlockedCommand.mockReturnValueOnce("rm");
		const sdkOpts = buildSdkOptions({ ...baseOpts, tier: "WRITE_LOCAL" });
		const res = await sdkOpts.canUseTool?.("Bash", { command: "rm -rf /" });
		expect(res?.behavior).toBe("deny");
		expect(res?.message).toContain("blocked operation");
	});

	it("allows Bash without wrapping (SDK sandbox handles isolation)", async () => {
		// SDK sandbox handles OS-level sandboxing directly - no wrapCommand() call needed
		const sdkOpts = buildSdkOptions({ ...baseOpts, tier: "WRITE_LOCAL" });
		const res = await sdkOpts.canUseTool?.("Bash", { command: "echo ok" });
		expect(res?.behavior).toBe("allow");
		// Command is passed through unchanged - SDK sandbox handles isolation
		expect((res as any).updatedInput.command).toBe("echo ok");
		expect(wrapCommand).not.toHaveBeenCalled();
	});

	it("only scans path-bearing fields, not arbitrary nested paths", async () => {
		// Changed behavior: we now only scan known path-bearing fields (file_path, path, pattern, command)
		// to avoid false positives on content fields like Write.content or Edit.new_string.
		// Arbitrary nested paths like meta.path are NOT scanned.
		isSensitivePath.mockReturnValue(true);
		const sdkOpts = buildSdkOptions({ ...baseOpts });
		const res = await sdkOpts.canUseTool?.("Read", { meta: { path: "/very/secret" } });
		expect(res?.behavior).toBe("allow"); // Not blocked because meta.path is not a path-bearing field
	});

	it("allows non-sensitive Read", async () => {
		const sdkOpts = buildSdkOptions({ ...baseOpts });
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
			const sdkOpts = buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebFetch", { url: "https://api.github.com/repos" });
			expect(res?.behavior).toBe("allow");
		});

		it("denies WebFetch to non-allowlisted domain", async () => {
			const sdkOpts = buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebFetch", { url: "https://evil.example.com/data" });
			expect(res?.behavior).toBe("deny");
			expect((res as any)?.message).toContain("not in allowlist");
		});

		it("denies WebFetch to private network (localhost)", async () => {
			isBlockedHost.mockResolvedValueOnce(true);
			const sdkOpts = buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebFetch", { url: "http://127.0.0.1:8080/api" });
			expect(res?.behavior).toBe("deny");
			expect((res as any)?.message).toContain("private networks");
		});

		it("denies WebFetch to metadata endpoint", async () => {
			isBlockedHost.mockResolvedValueOnce(true);
			const sdkOpts = buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebFetch", { url: "http://169.254.169.254/latest/meta-data" });
			expect(res?.behavior).toBe("deny");
			expect((res as any)?.message).toContain("private networks");
		});

		it("denies WebFetch to non-HTTP protocol", async () => {
			const sdkOpts = buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebFetch", { url: "file:///etc/passwd" });
			expect(res?.behavior).toBe("deny");
			expect((res as any)?.message).toContain("HTTP/HTTPS");
		});

		it("allows WebSearch (uses query, not url - server-side requests)", async () => {
			// WebSearch uses `query` parameter, not `url`. Requests are made server-side by Anthropic.
			// We don't filter WebSearch because we can't control Anthropic's search service.
			const sdkOpts = buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebSearch", { query: "how to hack servers" });
			expect(res?.behavior).toBe("allow");
		});
	});

	describe("permissive mode (TELCLAUDE_NETWORK_MODE=permissive)", () => {
		beforeEach(() => {
			process.env.TELCLAUDE_NETWORK_MODE = "permissive";
		});

		it("allows WebFetch to allowlisted domain", async () => {
			const sdkOpts = buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebFetch", { url: "https://api.github.com/repos" });
			expect(res?.behavior).toBe("allow");
		});

		it("allows WebFetch to non-allowlisted public domain", async () => {
			const sdkOpts = buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebFetch", { url: "https://random-website.example.com/data" });
			expect(res?.behavior).toBe("allow");
		});

		it("still denies WebFetch to private network (localhost)", async () => {
			isBlockedHost.mockResolvedValueOnce(true);
			const sdkOpts = buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebFetch", { url: "http://127.0.0.1:8080/api" });
			expect(res?.behavior).toBe("deny");
			expect((res as any)?.message).toContain("private networks");
		});

		it("still denies WebFetch to RFC1918 addresses", async () => {
			isBlockedHost.mockResolvedValueOnce(true);
			const sdkOpts = buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebFetch", { url: "http://192.168.1.1/admin" });
			expect(res?.behavior).toBe("deny");
			expect((res as any)?.message).toContain("private networks");
		});

		it("still denies WebFetch to metadata endpoint", async () => {
			isBlockedHost.mockResolvedValueOnce(true);
			const sdkOpts = buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebFetch", { url: "http://169.254.169.254/latest/meta-data" });
			expect(res?.behavior).toBe("deny");
			expect((res as any)?.message).toContain("private networks");
		});

		it("still denies WebFetch to non-HTTP protocol", async () => {
			const sdkOpts = buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebFetch", { url: "file:///etc/passwd" });
			expect(res?.behavior).toBe("deny");
			expect((res as any)?.message).toContain("HTTP/HTTPS");
		});

		it("allows WebSearch (server-side, uses query not url)", async () => {
			// WebSearch uses `query` parameter, not `url`. Requests are made server-side by Anthropic.
			// We don't filter WebSearch because we can't control Anthropic's search service.
			const sdkOpts = buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebSearch", { query: "private network 10.0.0.1" });
			expect(res?.behavior).toBe("allow");
		});
	});

	describe("open mode (TELCLAUDE_NETWORK_MODE=open)", () => {
		beforeEach(() => {
			process.env.TELCLAUDE_NETWORK_MODE = "open";
		});

		it("allows WebFetch to non-allowlisted public domain", async () => {
			const sdkOpts = buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebFetch", { url: "https://any-domain.example.org/api" });
			expect(res?.behavior).toBe("allow");
		});

		it("still denies WebFetch to private network", async () => {
			isBlockedHost.mockResolvedValueOnce(true);
			const sdkOpts = buildSdkOptions({ ...baseOpts });
			const res = await sdkOpts.canUseTool?.("WebFetch", { url: "http://172.16.0.1/admin" });
			expect(res?.behavior).toBe("deny");
			expect((res as any)?.message).toContain("private networks");
		});

		it("allows WebSearch (server-side, uses query not url)", async () => {
			// WebSearch is not filtered in any mode - requests are made server-side by Anthropic
			const sdkOpts = buildSdkOptions({ ...baseOpts });
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
		isBlockedHost.mockReset();
	});

	describe("hook runs unconditionally (defense-in-depth)", () => {
		it("blocks private network via hook even if canUseTool would allow", async () => {
			isBlockedHost.mockResolvedValueOnce(true);
			const sdkOpts = buildSdkOptions({ ...baseOpts });
			const res = await invokeWebFetchHook(sdkOpts, "http://127.0.0.1:8080/api");
			expect(res.decision).toBe("block");
			expect(res.reason).toContain("private networks");
		});

		it("blocks metadata endpoint via hook", async () => {
			isBlockedHost.mockResolvedValueOnce(true);
			const sdkOpts = buildSdkOptions({ ...baseOpts });
			const res = await invokeWebFetchHook(sdkOpts, "http://169.254.169.254/latest/meta-data");
			expect(res.decision).toBe("block");
			expect(res.reason).toContain("private networks");
		});

		it("blocks non-HTTP protocol via hook", async () => {
			const sdkOpts = buildSdkOptions({ ...baseOpts });
			const res = await invokeWebFetchHook(sdkOpts, "file:///etc/passwd");
			expect(res.decision).toBe("block");
			expect(res.reason).toContain("HTTP/HTTPS");
		});

		it("blocks invalid URL via hook", async () => {
			const sdkOpts = buildSdkOptions({ ...baseOpts });
			const res = await invokeWebFetchHook(sdkOpts, "not-a-valid-url");
			expect(res.decision).toBe("block");
			expect(res.reason).toContain("Invalid URL");
		});
	});

	describe("strict mode (default)", () => {
		it("blocks non-allowlisted domain via hook", async () => {
			const sdkOpts = buildSdkOptions({ ...baseOpts });
			const res = await invokeWebFetchHook(sdkOpts, "https://evil.example.com/data");
			expect(res.decision).toBe("block");
			expect(res.reason).toContain("not in allowlist");
		});

		it("allows allowlisted domain via hook", async () => {
			const sdkOpts = buildSdkOptions({ ...baseOpts });
			const res = await invokeWebFetchHook(sdkOpts, "https://api.github.com/repos");
			expect(res.continue).toBe(true);
		});
	});

	describe("permissive mode", () => {
		beforeEach(() => {
			process.env.TELCLAUDE_NETWORK_MODE = "permissive";
		});

		it("allows non-allowlisted public domain via hook", async () => {
			const sdkOpts = buildSdkOptions({ ...baseOpts });
			const res = await invokeWebFetchHook(sdkOpts, "https://random-site.example.com/api");
			expect(res.continue).toBe(true);
		});

		it("still blocks private network via hook", async () => {
			isBlockedHost.mockResolvedValueOnce(true);
			const sdkOpts = buildSdkOptions({ ...baseOpts });
			const res = await invokeWebFetchHook(sdkOpts, "http://192.168.1.1/admin");
			expect(res.decision).toBe("block");
			expect(res.reason).toContain("private networks");
		});
	});

	describe("hook only applies to WebFetch", () => {
		it("continues for non-WebFetch tools", async () => {
			const sdkOpts = buildSdkOptions({ ...baseOpts });
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

	describe("settingSources prevents user bypass", () => {
		it("always loads only project settings to prevent disableAllHooks bypass", () => {
			// SECURITY: settingSources must always be ["project"] to prevent:
			// - User settings with disableAllHooks: true
			// - User settings with permissive WebFetch rules
			const sdkOptsWithSkills = buildSdkOptions({ ...baseOpts, enableSkills: true });
			expect(sdkOptsWithSkills.settingSources).toEqual(["project"]);

			const sdkOptsWithoutSkills = buildSdkOptions({ ...baseOpts, enableSkills: false });
			expect(sdkOptsWithoutSkills.settingSources).toEqual(["project"]);
		});
	});
});
