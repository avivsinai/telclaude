import { afterEach, describe, expect, it, vi } from "vitest";

// Hoist shared mocks
const { containsBlockedCommand, isSensitivePath, isSandboxInitialized, wrapCommand } = vi.hoisted(() => ({
	containsBlockedCommand: vi.fn<string | null, [string]>(() => null),
	isSensitivePath: vi.fn<boolean, [string]>(() => false),
	isSandboxInitialized: vi.fn<boolean, []>(() => false),
	wrapCommand: vi.fn<Promise<string>, [string]>(),
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

import { buildSdkOptions } from "../../src/sdk/client.js";

const baseOpts = {
	cwd: "/tmp",
	tier: "READ_ONLY" as const,
	enableSkills: false,
} satisfies Parameters<typeof buildSdkOptions>[0];

afterEach(() => {
	containsBlockedCommand.mockReset();
	isSensitivePath.mockReset();
	isSandboxInitialized.mockReset();
	wrapCommand.mockReset();
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

	it("wraps Bash when sandbox is initialized", async () => {
		isSandboxInitialized.mockReturnValue(true);
		wrapCommand.mockResolvedValue("sandboxed cmd");
		const sdkOpts = buildSdkOptions({ ...baseOpts, tier: "WRITE_LOCAL" });
		const res = await sdkOpts.canUseTool?.("Bash", { command: "echo ok" });
		expect(res?.behavior).toBe("allow");
		expect((res as any).updatedInput.command).toBe("sandboxed cmd");
		expect(wrapCommand).toHaveBeenCalledWith("echo ok");
	});

	it("denies any tool input containing sensitive path string deeply", async () => {
		isSensitivePath.mockReturnValue(true);
		const sdkOpts = buildSdkOptions({ ...baseOpts });
		const res = await sdkOpts.canUseTool?.("Read", { meta: { path: "/very/secret" } });
		expect(res?.behavior).toBe("deny");
	});

	it("allows non-sensitive Read", async () => {
		const sdkOpts = buildSdkOptions({ ...baseOpts });
		const res = await sdkOpts.canUseTool?.("Read", { file_path: "/safe/path.txt" });
		expect(res?.behavior).toBe("allow");
	});
});
