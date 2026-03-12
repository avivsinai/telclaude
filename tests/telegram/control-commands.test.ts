import { describe, expect, it } from "vitest";

import {
	formatTelegramHelp,
	getTelegramMenuCommands,
	hasTelegramControlCommand,
	matchTelegramControlCommand,
	resolveTelegramSystemIntent,
} from "../../src/telegram/control-commands.js";

describe("telegram control command registry", () => {
	it("matches canonical commands and aliases", () => {
		expect(matchTelegramControlCommand("/help")?.command.id).toBe("help");
		expect(matchTelegramControlCommand("/reset")?.command.id).toBe("new");
		expect(matchTelegramControlCommand("/reset")?.aliasUsed).toBe("reset");
	});

	it("supports explicit bot usernames for matching", () => {
		expect(
			matchTelegramControlCommand("/status@telclaude_bot", {
				botUsername: "telclaude_bot",
			})?.command.id,
		).toBe("status");
		expect(
			matchTelegramControlCommand("/status@other_bot", {
				botUsername: "telclaude_bot",
			}),
		).toBeNull();
	});

	it("detects known commands for inbound gating", () => {
		expect(hasTelegramControlCommand("/commands")).toBe(true);
		expect(hasTelegramControlCommand("/nope")).toBe(false);
	});

	it("formats topic help for natural-language queries", () => {
		const help = formatTelegramHelp("reset session");

		expect(help).toContain("Reset Session");
		expect(help).toContain("/new");
		expect(help).toContain("/reset");
	});

	it("maps natural-language system questions to safe handlers", () => {
		expect(resolveTelegramSystemIntent("who am i linked as?")).toEqual({
			kind: "command",
			commandId: "whoami",
		});
		expect(resolveTelegramSystemIntent("when is the next heartbeat?")).toEqual({
			kind: "command",
			commandId: "cron",
		});
		expect(resolveTelegramSystemIntent("how do approvals work?")).toEqual({
			kind: "help",
			query: "how do approvals work?",
		});
	});

	it("exposes only the safe command menu entries", () => {
		expect(getTelegramMenuCommands()).toEqual([
			{ command: "help", description: "Explain commands and topics" },
			{ command: "commands", description: "List available commands" },
			{ command: "system", description: "Ask about system state" },
			{ command: "status", description: "Show runtime status" },
			{ command: "sessions", description: "Inspect chat sessions" },
			{ command: "cron", description: "Inspect cron jobs" },
			{ command: "whoami", description: "Show linked identity" },
			{ command: "new", description: "Start a fresh session" },
		]);
	});
});
