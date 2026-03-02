import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const quarantineIdeaImpl = vi.hoisted(() => vi.fn());

vi.mock("../../src/services/memory.js", () => ({
	quarantineIdea: (...args: unknown[]) => quarantineIdeaImpl(...args),
}));

import { registerMemoryCommands } from "../../src/commands/memory.js";

const ORIGINAL_CHAT_ID = process.env.TELCLAUDE_CHAT_ID;

async function runMemoryCli(args: string[]): Promise<void> {
	const program = new Command();
	registerMemoryCommands(program);
	await program.parseAsync(args, { from: "user" });
}

describe("memory command", () => {
	beforeEach(() => {
		quarantineIdeaImpl.mockReset();
		process.exitCode = undefined;
		delete process.env.TELCLAUDE_CHAT_ID;
		vi.spyOn(console, "log").mockImplementation(() => {});
		vi.spyOn(console, "error").mockImplementation(() => {});
	});

	afterEach(() => {
		vi.restoreAllMocks();
		process.exitCode = undefined;
		if (ORIGINAL_CHAT_ID === undefined) {
			delete process.env.TELCLAUDE_CHAT_ID;
		} else {
			process.env.TELCLAUDE_CHAT_ID = ORIGINAL_CHAT_ID;
		}
	});

	it("requires chat id for quarantine", async () => {
		await runMemoryCli(["memory", "quarantine", "post idea", "--id", "idea-no-chat"]);

		expect(quarantineIdeaImpl).not.toHaveBeenCalled();
		expect(process.exitCode).toBe(1);
		expect(console.error).toHaveBeenCalledWith(
			expect.stringContaining("Chat ID is required for quarantine"),
		);
	});

	it("uses explicit --chat-id for quarantine", async () => {
		quarantineIdeaImpl.mockResolvedValueOnce({ entry: { id: "idea-explicit" } });

		await runMemoryCli([
			"memory",
			"quarantine",
			"post idea",
			"--id",
			"idea-explicit",
			"--chat-id",
			" 12345 ",
		]);

		expect(quarantineIdeaImpl).toHaveBeenCalledWith("idea-explicit", "post idea", {
			userId: undefined,
			chatId: "12345",
		});
		expect(process.exitCode).toBeUndefined();
	});

	it("uses TELCLAUDE_CHAT_ID when chat id flag is omitted", async () => {
		process.env.TELCLAUDE_CHAT_ID = "chat-from-env";
		quarantineIdeaImpl.mockResolvedValueOnce({ entry: { id: "idea-env" } });

		await runMemoryCli(["memory", "quarantine", "post idea", "--id", "idea-env"]);

		expect(quarantineIdeaImpl).toHaveBeenCalledWith("idea-env", "post idea", {
			userId: undefined,
			chatId: "chat-from-env",
		});
		expect(process.exitCode).toBeUndefined();
	});
});
