import type { Api } from "grammy";
import { beforeEach, describe, expect, it, vi } from "vitest";

let sendSkillsSignCommand: typeof import("../../src/telegram/control-command-actions.js").sendSkillsSignCommand;
let signSkillByNameMock: ReturnType<typeof vi.fn>;
let isAdminMock: ReturnType<typeof vi.fn>;

function makeApi() {
	return {
		sendMessage: vi.fn(async () => ({ message_id: 1 })),
	};
}

describe("telegram /skills sign command", () => {
	beforeEach(async () => {
		vi.resetModules();
		signSkillByNameMock = vi.fn(async () => ({
			ok: true,
			skillName: "alpha",
			digest: "a".repeat(64),
			signature: "sig12345678901234567890",
			sigPath: "/tmp/alpha/SKILL.md.sig",
		}));
		isAdminMock = vi.fn(() => true);
		vi.doMock("../../src/commands/skills-sign.js", () => ({
			signSkillByName: signSkillByNameMock,
		}));
		vi.doMock("../../src/security/linking.js", () => ({
			isAdmin: isAdminMock,
		}));
		({ sendSkillsSignCommand } = await import("../../src/telegram/control-command-actions.js"));
	});

	it("signs a skill for admin chats", async () => {
		const api = makeApi();

		const result = await sendSkillsSignCommand(api as unknown as Api, {
			chatId: 100,
			threadId: 7,
			skillName: "alpha",
		});

		expect(signSkillByNameMock).toHaveBeenCalledWith("alpha");
		expect(result.callbackText).toBe("Signed alpha");
		expect(api.sendMessage).toHaveBeenCalledWith(
			100,
			expect.stringContaining(`digest: sha256:${"a".repeat(64)}`),
			{ message_thread_id: 7 },
		);
		expect(api.sendMessage.mock.calls[0]?.[1]).toContain("/tmp/alpha/SKILL.md.sig");
	});

	it("blocks non-admin chats", async () => {
		isAdminMock.mockReturnValue(false);
		const api = makeApi();

		const result = await sendSkillsSignCommand(api as unknown as Api, {
			chatId: 100,
			skillName: "alpha",
		});

		expect(result.callbackAlert).toBe(true);
		expect(signSkillByNameMock).not.toHaveBeenCalled();
		expect(api.sendMessage.mock.calls[0]?.[1]).toContain("Only admin can sign skills.");
	});

	it("shows usage when the name is missing", async () => {
		const api = makeApi();

		const result = await sendSkillsSignCommand(api as unknown as Api, { chatId: 100 });

		expect(result.callbackAlert).toBe(true);
		expect(signSkillByNameMock).not.toHaveBeenCalled();
		expect(api.sendMessage.mock.calls[0]?.[1]).toContain("Usage: `/skills sign <name>`");
	});

	it("surfaces vault or signing failures without throwing", async () => {
		signSkillByNameMock.mockResolvedValueOnce({
			ok: false,
			skillName: "alpha",
			error: "Vault sign-skill failed",
		});
		const api = makeApi();

		const result = await sendSkillsSignCommand(api as unknown as Api, {
			chatId: 100,
			skillName: "alpha",
		});

		expect(result.callbackAlert).toBe(true);
		expect(api.sendMessage.mock.calls[0]?.[1]).toContain(
			"Skill signing failed: Vault sign-skill failed",
		);
	});
});
