import { describe, expect, it } from "vitest";

import {
	formatTelegramCommandCatalog,
	formatTelegramHelp,
	formatUnknownTelegramCommandReply,
	getTelegramMenuCommands,
	hasTelegramControlCommand,
	listTelegramControlCommands,
	matchTelegramControlCommand,
	parseTelegramBotCommandToken,
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
			expect(matchTelegramControlCommand("/profile list")?.command.id).toBe("profile:list");
			expect(matchTelegramControlCommand("/profile show")?.command.id).toBe("profile:show");
			expect(matchTelegramControlCommand("/profile switch engineer")?.command.id).toBe(
				"profile:switch",
			);
			expect(matchTelegramControlCommand("/model reset")?.command.id).toBe("model:reset");
			expect(matchTelegramControlCommand("/learn Aviv likes direct answers")?.command.id).toBe(
				"learn",
			);
			expect(matchTelegramControlCommand("/learn list")?.command.id).toBe("learn:list");
			expect(matchTelegramControlCommand("/learn forget mem-123")?.command.id).toBe("learn:forget");
			expect(matchTelegramControlCommand("/social queue")?.command.id).toBe("social:queue");
			expect(matchTelegramControlCommand("/social promote post_123")?.command.id).toBe(
				"social:promote",
			);
			expect(matchTelegramControlCommand("/social run xtwitter")?.command.id).toBe("social:run");
			expect(matchTelegramControlCommand("/social log xtwitter 12")?.command.id).toBe("social:log");
			expect(matchTelegramControlCommand("/social ask what did you post?")?.command.id).toBe(
				"social:ask",
			);
			expect(matchTelegramControlCommand("/skills drafts")?.command.id).toBe("skills:drafts");
			expect(matchTelegramControlCommand("/skills promote my-skill")?.command.id).toBe(
				"skills:promote",
			);
			expect(matchTelegramControlCommand("/skills sign my-skill")?.command.id).toBe("skills:sign");
			expect(matchTelegramControlCommand("/skills reload")?.command.id).toBe("skills:reload");
			expect(matchTelegramControlCommand("/skills list")?.command.id).toBe("skills:list");
			expect(matchTelegramControlCommand("/skills new my-skill")?.command.id).toBe("skills:new");
			expect(matchTelegramControlCommand("/skills import")?.command.id).toBe("skills:import");
			expect(matchTelegramControlCommand("/skills scan")?.command.id).toBe("skills:scan");
			expect(matchTelegramControlCommand("/skills doctor")?.command.id).toBe("skills:doctor");
			expect(matchTelegramControlCommand("/codex review the diff")?.command.id).toBe("codex");
			expect(matchTelegramControlCommand("/help commands")?.command.id).toBe("help:commands");
			expect(matchTelegramControlCommand("/curator")?.command.id).toBe("curator");
			expect(matchTelegramControlCommand("/providers enroll clalit")?.command.id).toBe(
				"providers:enroll",
			);
			expect(matchTelegramControlCommand("/provider enroll clalit")?.command.id).toBe(
				"providers:enroll",
			);
		});

		it("passes remaining args correctly for subcommands", () => {
			const linkMatch = matchTelegramControlCommand("/me link ABCD-1234");
			expect(linkMatch?.command.id).toBe("me:link");
			expect(linkMatch?.args).toEqual(["ABCD-1234"]);

			const verifyMatch = matchTelegramControlCommand("/auth verify 123456");
			expect(verifyMatch?.command.id).toBe("auth:verify");
			expect(verifyMatch?.args).toEqual(["123456"]);

			const providerEnrollMatch = matchTelegramControlCommand("/provider enroll clalit");
			expect(providerEnrollMatch?.command.id).toBe("providers:enroll");
			expect(providerEnrollMatch?.args).toEqual(["clalit"]);
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

			const learn = matchTelegramControlCommand("/learn Aviv prefers terse status updates");
			expect(learn?.command.id).toBe("learn");
			expect(learn?.rawArgs).toBe("Aviv prefers terse status updates");
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
			const sethomeMatch = matchTelegramControlCommand("/sethome");
			expect(sethomeMatch?.command.id).toBe("sethome");

			const stopMatch = matchTelegramControlCommand("/stop");
			expect(stopMatch?.command.id).toBe("stop");

			const stopJobMatch = matchTelegramControlCommand("/stop a1b2c3d4");
			expect(stopJobMatch?.command.id).toBe("stop");
			expect(stopJobMatch?.args).toEqual(["a1b2c3d4"]);

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

	it("formats unknown command suggestions without catching slash paths", () => {
		expect(formatUnknownTelegramCommandReply("systm")).toContain("Did you mean /system?");
		expect(formatUnknownTelegramCommandReply("definitelyunknown")).toContain("Use /help commands");
		expect(parseTelegramBotCommandToken("/etc/hosts")).toBeNull();
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
				"profile",
				"learn",
				"sethome",
				"social",
				"skills",
				"background",
				"codex",
				"curator",
				"stop",
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
				"skills:sign",
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
			expect(catalog).toContain("/skills sign");
			expect(catalog).toContain("/skills reload");
		});
	});

	describe("/stop command help", () => {
		it("documents supported active-work cancellation", () => {
			const help = formatTelegramHelp("background");
			expect(help).toContain("/stop");
			expect(help).toContain("/codex");
			expect(help).toContain("background jobs");
		});
	});

	describe("/codex command help", () => {
		it("surfaces Codex in help and catalog", () => {
			expect(formatTelegramHelp("codex")).toContain("Codex");
			expect(formatTelegramHelp()).toContain("/codex");
			expect(formatTelegramCommandCatalog()).toContain("/codex");
		});
	});

	describe("/curator command help", () => {
		it("surfaces curator in help and catalog", () => {
			expect(formatTelegramHelp("curator")).toContain("Curator");
			expect(formatTelegramHelp()).toContain("/curator");
			expect(formatTelegramCommandCatalog()).toContain("/curator");
		});
	});

	describe("/learn command help", () => {
		it("surfaces learn in help, catalog, and private menu", () => {
			expect(formatTelegramHelp("learn")).toContain("/learn");
			expect(formatTelegramHelp()).toContain("/learn");
			expect(formatTelegramCommandCatalog()).toContain("/learn");
			expect(getTelegramMenuCommands("private").map((entry) => entry.command)).toContain("learn");
		});
	});
});
