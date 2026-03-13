import { describe, expect, it } from "vitest";

import {
	formatTelegramHelp,
	getTelegramMenuCommands,
	hasTelegramControlCommand,
	matchTelegramControlCommand,
	resolveTelegramSystemIntent,
} from "../../src/telegram/control-commands.js";

describe("telegram control command registry", () => {
	describe("hierarchical command matching", () => {
		it("matches domain root commands", () => {
			expect(matchTelegramControlCommand("/system")?.command.id).toBe("system");
			expect(matchTelegramControlCommand("/me")?.command.id).toBe("me");
			expect(matchTelegramControlCommand("/help")?.command.id).toBe("help");
		});

		it("matches domain subcommands", () => {
			expect(matchTelegramControlCommand("/system sessions")?.command.id).toBe("system:sessions");
			expect(matchTelegramControlCommand("/system cron")?.command.id).toBe("system:cron");
			expect(matchTelegramControlCommand("/system ask what is running?")?.command.id).toBe(
				"system:ask",
			);
			expect(matchTelegramControlCommand("/me link ABCD")?.command.id).toBe("me:link");
			expect(matchTelegramControlCommand("/me unlink")?.command.id).toBe("me:unlink");
			expect(matchTelegramControlCommand("/auth setup")?.command.id).toBe("auth:setup");
			expect(matchTelegramControlCommand("/auth verify 123456")?.command.id).toBe("auth:verify");
			expect(matchTelegramControlCommand("/auth logout")?.command.id).toBe("auth:logout");
			expect(matchTelegramControlCommand("/auth disable")?.command.id).toBe("auth:disable");
			expect(matchTelegramControlCommand("/auth skip")?.command.id).toBe("auth:skip");
			expect(matchTelegramControlCommand("/auth force-reauth")?.command.id).toBe(
				"auth:force-reauth",
			);
			expect(matchTelegramControlCommand("/social queue")?.command.id).toBe("social:queue");
			expect(matchTelegramControlCommand("/social promote post_123")?.command.id).toBe(
				"social:promote",
			);
			expect(matchTelegramControlCommand("/social run xtwitter")?.command.id).toBe("social:run");
			expect(matchTelegramControlCommand("/social log xtwitter 12")?.command.id).toBe(
				"social:log",
			);
			expect(matchTelegramControlCommand("/social ask what did you post?")?.command.id).toBe(
				"social:ask",
			);
			expect(matchTelegramControlCommand("/skills drafts")?.command.id).toBe("skills:drafts");
			expect(matchTelegramControlCommand("/skills promote my-skill")?.command.id).toBe(
				"skills:promote",
			);
			expect(matchTelegramControlCommand("/skills reload")?.command.id).toBe("skills:reload");
			expect(matchTelegramControlCommand("/help commands")?.command.id).toBe("help:commands");
		});

		it("passes remaining args correctly for subcommands", () => {
			const match = matchTelegramControlCommand("/system ask what is running?");
			expect(match?.command.id).toBe("system:ask");
			expect(match?.rawArgs).toBe("what is running?");

			const linkMatch = matchTelegramControlCommand("/me link ABCD-1234");
			expect(linkMatch?.command.id).toBe("me:link");
			expect(linkMatch?.args).toEqual(["ABCD-1234"]);

			const verifyMatch = matchTelegramControlCommand("/auth verify 123456");
			expect(verifyMatch?.command.id).toBe("auth:verify");
			expect(verifyMatch?.args).toEqual(["123456"]);
		});

		it("routes unknown subcommands to ask for domains with ask subcommand", () => {
			// "/system foobar" should route to system:ask (NL routing)
			const match = matchTelegramControlCommand("/system foobar");
			expect(match?.command.id).toBe("system:ask");
			expect(match?.rawArgs).toBe("foobar");
		});
	});

	describe("fast-path shortcuts", () => {
		it("matches shortcuts", () => {
			const approveMatch = matchTelegramControlCommand("/approve 123456");
			expect(approveMatch?.command.id).toBe("approve");

			const denyMatch = matchTelegramControlCommand("/deny");
			expect(denyMatch?.command.id).toBe("deny");

			const newMatch = matchTelegramControlCommand("/new");
			expect(newMatch?.command.id).toBe("new");

			const resetMatch = matchTelegramControlCommand("/reset");
			expect(resetMatch?.command.id).toBe("new");
			expect(resetMatch?.aliasUsed).toBe("reset");
		});

		it("matches otp", () => {
			const otpMatch = matchTelegramControlCommand("/otp github 123456");
			expect(otpMatch?.command.id).toBe("otp");
		});
	});

	it("supports explicit bot usernames for matching", () => {
		expect(
			matchTelegramControlCommand("/system@telclaude_bot", {
				botUsername: "telclaude_bot",
			})?.command.id,
		).toBe("system");
		expect(
			matchTelegramControlCommand("/system@other_bot", {
				botUsername: "telclaude_bot",
			}),
		).toBeNull();
		expect(matchTelegramControlCommand("/system@other_bot")).toBeNull();
	});

	it("detects known commands for inbound gating", () => {
		expect(hasTelegramControlCommand("/help commands")).toBe(true);
		expect(hasTelegramControlCommand("/system sessions")).toBe(true);
		expect(hasTelegramControlCommand("/me")).toBe(true);
		expect(hasTelegramControlCommand("/auth setup")).toBe(true);
		// Unknown (including removed legacy flat commands)
		expect(hasTelegramControlCommand("/commands")).toBe(false);
		expect(hasTelegramControlCommand("/status")).toBe(false);
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
			commandId: "me",
		});
		expect(resolveTelegramSystemIntent("when is the next heartbeat?")).toEqual({
			kind: "command",
			commandId: "system:cron",
		});
		expect(resolveTelegramSystemIntent("how do approvals work?")).toEqual({
			kind: "help",
			query: "how do approvals work?",
		});
	});

	describe("scoped menu commands", () => {
		it("exposes all domain roots and shortcuts for private chat", () => {
			expect(getTelegramMenuCommands("private")).toEqual([
				{ command: "help", description: "Explain commands and topics" },
				{ command: "me", description: "Identity management" },
				{ command: "auth", description: "Two-factor authentication" },
				{ command: "system", description: "System introspection" },
				{ command: "social", description: "Social persona management" },
				{ command: "skills", description: "Skill management" },
				{ command: "approve", description: "Approve a pending request" },
				{ command: "new", description: "Start a fresh session" },
			]);
		});

		it("exposes minimal commands for group chat", () => {
			expect(getTelegramMenuCommands("group")).toEqual([
				{ command: "help", description: "Explain commands and topics" },
				{ command: "new", description: "Start a fresh session" },
			]);
		});

		it("defaults to private scope when no scope provided", () => {
			expect(getTelegramMenuCommands()).toEqual(getTelegramMenuCommands("private"));
		});
	});
});
