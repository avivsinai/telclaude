import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const requestApprovalScopeCardMock = vi.hoisted(() => vi.fn());
const waitForToolApprovalMock = vi.hoisted(() => vi.fn());

vi.mock("../../src/agent/approval-client.js", () => ({
	requestApprovalScopeCard: requestApprovalScopeCardMock,
}));

vi.mock("../../src/security/approval-wait.js", () => ({
	waitForToolApproval: waitForToolApprovalMock,
}));

type PreToolUseDecision = {
	permissionDecision: "allow" | "deny";
	permissionDecisionReason?: string;
	updatedInput?: Record<string, unknown>;
};

let buildSdkOptions: typeof import("../../src/sdk/client.js").buildSdkOptions;
let resetDatabase: typeof import("../../src/storage/db.js").resetDatabase;
let grantAllowlist: typeof import("../../src/security/approvals.js").grantAllowlist;
let listAllowlist: typeof import("../../src/security/approvals.js").listAllowlist;

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;
const ORIGINAL_CAPABILITIES_URL = process.env.TELCLAUDE_CAPABILITIES_URL;

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

describe("createGraduatedApprovalHook (PreToolUse)", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-grad-approval-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		process.env.TELCLAUDE_CAPABILITIES_URL = "http://relay";
		requestApprovalScopeCardMock.mockReset().mockResolvedValue({ ok: true, cardId: "card-1" });
		waitForToolApprovalMock.mockReset();

		vi.resetModules();
		({ buildSdkOptions } = await import("../../src/sdk/client.js"));
		({ resetDatabase } = await import("../../src/storage/db.js"));
		({ grantAllowlist, listAllowlist } = await import("../../src/security/approvals.js"));
		resetDatabase();
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
		if (ORIGINAL_CAPABILITIES_URL === undefined) {
			delete process.env.TELCLAUDE_CAPABILITIES_URL;
		} else {
			process.env.TELCLAUDE_CAPABILITIES_URL = ORIGINAL_CAPABILITIES_URL;
		}
	});

	it("emits an approval card for medium-risk tools and consumes a once grant on retry", async () => {
		waitForToolApprovalMock.mockImplementation(async () => {
			grantAllowlist({
				userId: "tg:123",
				tier: "WRITE_LOCAL",
				toolKey: "Write",
				scope: "once",
				sessionKey: null,
				chatId: 123,
			});
			return { status: "approved", scope: "once", source: "card" };
		});

		const sdkOpts = await buildSdkOptions({
			cwd: "/tmp",
			tier: "WRITE_LOCAL",
			poolKey: "tg:123",
			userId: "123",
			chatId: 123,
			actorId: 123,
			threadId: 77,
		});

		const res = await runPreToolUse(sdkOpts, "Write", {
			file_path: "notes.txt",
			content: "hello",
		});

		expect(res.permissionDecision).toBe("allow");
		expect(requestApprovalScopeCardMock).toHaveBeenCalledTimes(1);
		expect(requestApprovalScopeCardMock).toHaveBeenCalledWith(
			expect.objectContaining({
				chatId: 123,
				actorId: 123,
				threadId: 77,
				toolKey: "Write",
				riskTier: "medium",
				scopesEnabled: ["once", "session", "always"],
			}),
		);
		expect(listAllowlist({ userId: "tg:123" })).toHaveLength(0);
	});

	it("keeps a session grant active for the same session and prompts again in another session", async () => {
		waitForToolApprovalMock.mockImplementationOnce(async () => {
			grantAllowlist({
				userId: "tg:124",
				tier: "WRITE_LOCAL",
				toolKey: "Edit",
				scope: "session",
				sessionKey: "tg:124",
				chatId: 124,
			});
			return { status: "approved", scope: "session", source: "card" };
		});
		waitForToolApprovalMock.mockResolvedValueOnce({
			status: "denied",
			source: "timeout",
			reason: "Tool approval timed out.",
		});

		const sameSessionOpts = await buildSdkOptions({
			cwd: "/tmp",
			tier: "WRITE_LOCAL",
			poolKey: "tg:124",
			userId: "124",
			chatId: 124,
			actorId: 124,
		});

		const first = await runPreToolUse(sameSessionOpts, "Edit", {
			file_path: "README.md",
			old_string: "old",
			new_string: "new",
		});
		const second = await runPreToolUse(sameSessionOpts, "Edit", {
			file_path: "README.md",
			old_string: "older",
			new_string: "newer",
		});

		expect(first.permissionDecision).toBe("allow");
		expect(second.permissionDecision).toBe("allow");
		expect(requestApprovalScopeCardMock).toHaveBeenCalledTimes(1);

		const otherSessionOpts = await buildSdkOptions({
			cwd: "/tmp",
			tier: "WRITE_LOCAL",
			poolKey: "tg:other-session",
			userId: "124",
			chatId: 124,
			actorId: 124,
		});
		const third = await runPreToolUse(otherSessionOpts, "Edit", {
			file_path: "README.md",
			old_string: "x",
			new_string: "y",
		});

		expect(third.permissionDecision).toBe("deny");
		expect(third.permissionDecisionReason).toContain("timed out");
		expect(requestApprovalScopeCardMock).toHaveBeenCalledTimes(2);
	});

	it("limits high-risk approvals to once and denies cleanly on timeout", async () => {
		grantAllowlist({
			userId: "tg:125",
			tier: "WRITE_LOCAL",
			toolKey: "Bash",
			scope: "always",
			sessionKey: null,
			chatId: 125,
		});
		waitForToolApprovalMock.mockResolvedValue({
			status: "denied",
			source: "timeout",
			reason: "Tool approval timed out.",
		});

		const sdkOpts = await buildSdkOptions({
			cwd: "/tmp",
			tier: "WRITE_LOCAL",
			poolKey: "tg:125",
			userId: "125",
			chatId: 125,
			actorId: 125,
		});

		const res = await runPreToolUse(sdkOpts, "Bash", { command: "git push --force origin main" });

		expect(res.permissionDecision).toBe("deny");
		expect(res.permissionDecisionReason).toContain("timed out");
		expect(requestApprovalScopeCardMock).toHaveBeenCalledWith(
			expect.objectContaining({
				toolKey: "Bash",
				riskTier: "high",
				scopesEnabled: ["once"],
			}),
		);
	});
});
