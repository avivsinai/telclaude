import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock modules before imports
vi.mock("../../src/storage/db.js", () => ({
	getDb: vi.fn(() => ({
		prepare: vi.fn(() => ({
			run: vi.fn(),
			get: vi.fn(),
			all: vi.fn(() => []),
		})),
		transaction: vi.fn((fn: () => void) => fn),
	})),
}));

vi.mock("../../src/config/config.js", () => ({
	loadConfig: vi.fn(() => ({
		providers: [],
	})),
}));

vi.mock("../../src/sandbox/private-endpoints.js", () => ({
	checkPrivateNetworkAccess: vi.fn(() => ({ allowed: true })),
}));

describe("moltbook tool restrictions", () => {
	const originalEnv = process.env;

	beforeEach(() => {
		vi.resetModules();
		process.env = { ...originalEnv };
	});

	afterEach(() => {
		process.env = originalEnv;
		vi.restoreAllMocks();
	});

	describe("isMoltbookContext detection", () => {
		it("detects moltbook context from userId prefix", async () => {
			process.env.TELEGRAM_RPC_SECRET = "telegram-secret";
			process.env.MOLTBOOK_RPC_SECRET = "moltbook-secret";
			process.env.TELCLAUDE_NETWORK_MODE = "permissive";

			const { buildSdkOptions } = await import("../../src/sdk/client.js");

			// With moltbook: prefix, should be moltbook context even with both secrets
			const opts = await buildSdkOptions({
				tier: "FULL_ACCESS",
				userId: "moltbook:social",
				poolKey: "test",
			});

			// The hook should exist and block Read tool
			const preToolUseHooks = opts.hooks?.PreToolUse ?? [];
			expect(preToolUseHooks.length).toBeGreaterThan(0);

			// Simulate calling the hooks with a Read tool
			for (const hookMatcher of preToolUseHooks) {
				for (const hook of hookMatcher.hooks) {
					const result = await hook({
						session_id: "test",
						hook_event_name: "PreToolUse",
						tool_name: "Read",
						tool_input: { file_path: "/test.txt" },
					});
					if (
						result?.hookSpecificOutput?.permissionDecision === "deny" &&
						result.hookSpecificOutput.permissionDecisionReason?.includes("Moltbook context")
					) {
						// Found the moltbook hook blocking Read
						expect(result.hookSpecificOutput.permissionDecisionReason).toContain("Read");
						return;
					}
				}
			}
			throw new Error("Expected moltbook hook to block Read tool");
		});

		it("detects moltbook context from env vars", async () => {
			// Only MOLTBOOK secret, no TELEGRAM secret = moltbook container
			process.env.MOLTBOOK_RPC_SECRET = "moltbook-secret";
			delete process.env.TELEGRAM_RPC_SECRET;
			process.env.TELCLAUDE_NETWORK_MODE = "permissive";

			const { buildSdkOptions } = await import("../../src/sdk/client.js");

			const opts = await buildSdkOptions({
				tier: "FULL_ACCESS",
				userId: "agent", // No moltbook: prefix
				poolKey: "test",
			});

			const preToolUseHooks = opts.hooks?.PreToolUse ?? [];

			// Should still block Bash in moltbook context
			for (const hookMatcher of preToolUseHooks) {
				for (const hook of hookMatcher.hooks) {
					const result = await hook({
						session_id: "test",
						hook_event_name: "PreToolUse",
						tool_name: "Bash",
						tool_input: { command: "ls" },
					});
					if (
						result?.hookSpecificOutput?.permissionDecision === "deny" &&
						result.hookSpecificOutput.permissionDecisionReason?.includes("Moltbook context")
					) {
						expect(result.hookSpecificOutput.permissionDecisionReason).toContain("Bash");
						return;
					}
				}
			}
			throw new Error("Expected moltbook hook to block Bash tool");
		});

		it("allows WebFetch and WebSearch in moltbook context", async () => {
			process.env.MOLTBOOK_RPC_SECRET = "moltbook-secret";
			delete process.env.TELEGRAM_RPC_SECRET;
			process.env.TELCLAUDE_NETWORK_MODE = "permissive";

			const { buildSdkOptions } = await import("../../src/sdk/client.js");

			const opts = await buildSdkOptions({
				tier: "MOLTBOOK_SOCIAL",
				userId: "moltbook:social",
				poolKey: "test",
			});

			const preToolUseHooks = opts.hooks?.PreToolUse ?? [];

			// WebFetch should NOT be blocked by moltbook hook
			for (const hookMatcher of preToolUseHooks) {
				for (const hook of hookMatcher.hooks) {
					const result = await hook({
						session_id: "test",
						hook_event_name: "PreToolUse",
						tool_name: "WebFetch",
						tool_input: { url: "https://example.com", prompt: "test" },
					});
					// Should not have a deny from moltbook context
					if (
						result?.hookSpecificOutput?.permissionDecision === "deny" &&
						result.hookSpecificOutput.permissionDecisionReason?.includes("Moltbook context")
					) {
						throw new Error("WebFetch should not be blocked by moltbook hook");
					}
				}
			}

			// WebSearch should also be allowed
			for (const hookMatcher of preToolUseHooks) {
				for (const hook of hookMatcher.hooks) {
					const result = await hook({
						session_id: "test",
						hook_event_name: "PreToolUse",
						tool_name: "WebSearch",
						tool_input: { query: "test" },
					});
					if (
						result?.hookSpecificOutput?.permissionDecision === "deny" &&
						result.hookSpecificOutput.permissionDecisionReason?.includes("Moltbook context")
					) {
						throw new Error("WebSearch should not be blocked by moltbook hook");
					}
				}
			}
		});

		it("allows all tools in telegram context", async () => {
			process.env.TELEGRAM_RPC_SECRET = "telegram-secret";
			delete process.env.MOLTBOOK_RPC_SECRET;
			process.env.TELCLAUDE_NETWORK_MODE = "permissive";

			const { buildSdkOptions } = await import("../../src/sdk/client.js");

			const opts = await buildSdkOptions({
				tier: "FULL_ACCESS",
				userId: "tg:123456",
				poolKey: "test",
			});

			const preToolUseHooks = opts.hooks?.PreToolUse ?? [];

			// Read should NOT be blocked in telegram context
			for (const hookMatcher of preToolUseHooks) {
				for (const hook of hookMatcher.hooks) {
					const result = await hook({
						session_id: "test",
						hook_event_name: "PreToolUse",
						tool_name: "Read",
						tool_input: { file_path: "/test.txt" },
					});
					if (
						result?.hookSpecificOutput?.permissionDecision === "deny" &&
						result.hookSpecificOutput.permissionDecisionReason?.includes("Moltbook context")
					) {
						throw new Error("Read should not be blocked in telegram context");
					}
				}
			}
		});
	});
});
