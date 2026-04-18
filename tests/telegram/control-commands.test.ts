import { describe, expect, it } from "vitest";

import {
	formatTelegramCommandCatalog,
	formatTelegramHelp,
	getTelegramMenuCommands,
	hasTelegramControlCommand,
	listTelegramControlCommands,
	matchTelegramControlCommand,
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
			expect(matchTelegramControlCommand("/skills list")?.command.id).toBe("skills:list");
			expect(matchTelegramControlCommand("/skills new my-skill")?.command.id).toBe(
				"skills:new",
			);
			expect(matchTelegramControlCommand("/skills import")?.command.id).toBe("skills:import");
			expect(matchTelegramControlCommand("/skills scan")?.command.id).toBe("skills:scan");
			expect(matchTelegramControlCommand("/skills doctor")?.command.id).toBe("skills:doctor");
			expect(matchTelegramControlCommand("/help commands")?.command.id).toBe("help:commands");
		});

		it("passes remaining args correctly for subcommands", () => {
			const linkMatch = matchTelegramControlCommand("/me link ABCD-1234");
			expect(linkMatch?.command.id).toBe("me:link");
			expect(linkMatch?.args).toEqual(["ABCD-1234"]);

			const verifyMatch = matchTelegramControlCommand("/auth verify 123456");
			expect(verifyMatch?.command.id).toBe("auth:verify");
			expect(verifyMatch?.args).toEqual(["123456"]);
		});

		it("returns null for unknown subcommands in strict domains", () => {
			expect(matchTelegramControlCommand("/system foobar")).toBeNull();
			expect(matchTelegramControlCommand("/system crno")).toBeNull();
			expect(matchTelegramControlCommand("/system status")).toBeNull();
			expect(matchTelegramControlCommand("/auth bogus")).toBeNull();
			expect(matchTelegramControlCommand("/me show")).toBeNull();
			expect(matchTelegramControlCommand("/skills nope")).toBeNull();
		});

		it("routes freeform args to domain default for acceptsFreeformArgs domains", () => {
			// "/help approvals" routes to help default with rawArgs
			const match = matchTelegramControlCommand("/help approvals");
			expect(match?.command.id).toBe("help");
			expect(match?.rawArgs).toBe("approvals");

			const multiWord = matchTelegramControlCommand("/help reset session");
			expect(multiWord?.command.id).toBe("help");
			expect(multiWord?.rawArgs).toBe("reset session");
		});

		it("routes bare domain to default", () => {
			const match = matchTelegramControlCommand("/system");
			expect(match?.command.id).toBe("system");
			expect(match?.rawArgs).toBe("");
		});

		it("routes unknown /social subcommands to social:ask", () => {
			// "/social foobar" routes to social:ask (social domain has ask subcommand)
			const match = matchTelegramControlCommand("/social foobar");
			expect(match?.command.id).toBe("social:ask");
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

	describe("scoped menu commands", () => {
		it("exposes all domain roots and shortcuts for private chat", () => {
			const entries = getTelegramMenuCommands("private");
			const commands = entries.map((e) => e.command);
			for (const required of [
				"help",
				"me",
				"auth",
				"system",
				"social",
				"skills",
				"approve",
				"new",
			]) {
				expect(commands).toContain(required);
			}
			for (const entry of entries) {
				expect(entry.description.length).toBeGreaterThan(0);
			}
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

	describe("skills catalog visibility", () => {
		it("surfaces the /skills domain root and its core subcommands", () => {
			const all = listTelegramControlCommands();
			const skillsRoot = all.find((cmd) => cmd.id === "skills");
			expect(skillsRoot?.hideFromCatalog).not.toBe(true);

			const visible = new Set(
				all.filter((cmd) => cmd.hideFromCatalog !== true).map((cmd) => cmd.id),
			);
			// Core lifecycle subcommands must appear in the catalog.
			for (const id of [
				"skills",
				"skills:list",
				"skills:new",
				"skills:import",
				"skills:scan",
				"skills:doctor",
				"skills:drafts",
				"skills:promote",
				"skills:reload",
			] as const) {
				expect(visible.has(id)).toBe(true);
			}
		});

		it("renders the /skills commands in the command catalog", () => {
			const catalog = formatTelegramCommandCatalog();
			expect(catalog).toContain("/skills list");
			expect(catalog).toContain("/skills new");
			expect(catalog).toContain("/skills doctor");
			expect(catalog).toContain("/skills drafts");
			expect(catalog).toContain("/skills promote");
			expect(catalog).toContain("/skills reload");
		});
	});
});
