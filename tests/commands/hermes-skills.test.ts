import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { registerHermesSkillsCommand } from "../../src/commands/hermes-skills.js";
import { decideCuratorItem, upsertVerifiedCuratorItem } from "../../src/curator/store.js";
import { listCatalog } from "../../src/hermes/skills-catalog.js";
import { resetDatabase } from "../../src/storage/db.js";

const ORIGINAL_ENV = {
	dataDir: process.env.TELCLAUDE_DATA_DIR,
	catalogDir: process.env.TELCLAUDE_HERMES_SKILL_CATALOG_DIR,
	socialCatalogDir: process.env.TELCLAUDE_HERMES_SOCIAL_SKILL_CATALOG_DIR,
	upstreamDir: process.env.TELCLAUDE_HERMES_UPSTREAM_SKILLS_DIR,
};

let tempRoot = "";
let catalogRoot = "";
let socialCatalogRoot = "";
let logSpy: ReturnType<typeof vi.spyOn>;
let errorSpy: ReturnType<typeof vi.spyOn>;

async function runCli(args: string[]): Promise<void> {
	const program = new Command();
	program.exitOverride();
	registerHermesSkillsCommand(program);
	await program.parseAsync(["hermes-skills", ...args], { from: "user" });
}

function writeSkill(name: string, body?: string): string {
	const dir = path.join(tempRoot, "src", name);
	fs.mkdirSync(dir, { recursive: true });
	fs.writeFileSync(
		path.join(dir, "SKILL.md"),
		`---\nname: ${name}\ndescription: Helps with ${name}\n---\n\n${body ?? "A harmless guide."}\n`,
	);
	return dir;
}

beforeEach(() => {
	tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-hermes-skills-cli-"));
	catalogRoot = path.join(tempRoot, "catalog");
	socialCatalogRoot = path.join(tempRoot, "social-catalog");
	process.env.TELCLAUDE_DATA_DIR = path.join(tempRoot, "data");
	process.env.TELCLAUDE_HERMES_SKILL_CATALOG_DIR = catalogRoot;
	process.env.TELCLAUDE_HERMES_SOCIAL_SKILL_CATALOG_DIR = socialCatalogRoot;
	delete process.env.TELCLAUDE_HERMES_UPSTREAM_SKILLS_DIR;
	resetDatabase();
	logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
	errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
	vi.restoreAllMocks();
	process.exitCode = undefined;
	for (const [key, value] of [
		["TELCLAUDE_DATA_DIR", ORIGINAL_ENV.dataDir],
		["TELCLAUDE_HERMES_SKILL_CATALOG_DIR", ORIGINAL_ENV.catalogDir],
		["TELCLAUDE_HERMES_SOCIAL_SKILL_CATALOG_DIR", ORIGINAL_ENV.socialCatalogDir],
		["TELCLAUDE_HERMES_UPSTREAM_SKILLS_DIR", ORIGINAL_ENV.upstreamDir],
	] as const) {
		if (value === undefined) delete process.env[key];
		else process.env[key] = value;
	}
	fs.rmSync(tempRoot, { recursive: true, force: true });
});

describe("hermes-skills install/list/remove/verify", () => {
	it("installs a valid skill and lists it", async () => {
		await runCli(["install", writeSkill("daily-brief"), "--origin", "test:fixture"]);
		expect(process.exitCode).toBeUndefined();

		const entries = listCatalog({ catalogRoot });
		expect(entries).toHaveLength(1);
		expect(entries[0]).toMatchObject({ name: "daily-brief", origin: "test:fixture" });

		await runCli(["list", "--json"]);
		const jsonOut = logSpy.mock.calls.at(-1)?.[0] as string;
		expect(JSON.parse(jsonOut).skills[0].name).toBe("daily-brief");
	});

	it("targets the social Hermes catalog when requested", async () => {
		await runCli(["install", writeSkill("social-brief"), "--catalog", "social"]);
		expect(process.exitCode).toBeUndefined();

		expect(listCatalog({ catalogRoot })).toEqual([]);
		expect(listCatalog({ catalogRoot: socialCatalogRoot })[0]).toMatchObject({
			name: "social-brief",
		});

		await runCli(["list", "--catalog", "social", "--json"]);
		const jsonOut = logSpy.mock.calls.at(-1)?.[0] as string;
		expect(JSON.parse(jsonOut).skills[0].name).toBe("social-brief");
	});

	it("fails closed on an invalid skill", async () => {
		const dir = writeSkill("scripted");
		fs.mkdirSync(path.join(dir, "scripts"));
		fs.writeFileSync(path.join(dir, "scripts", "x.py"), "print()\n");

		await runCli(["install", dir]);
		expect(process.exitCode).toBe(1);
		expect(String(errorSpy.mock.calls.at(-1)?.[0])).toContain("scripts/ directory not allowed");
		expect(listCatalog({ catalogRoot })).toEqual([]);
	});

	it("removes an installed skill and errors on unknown names", async () => {
		await runCli(["install", writeSkill("daily-brief")]);
		await runCli(["remove", "daily-brief"]);
		expect(process.exitCode).toBeUndefined();
		expect(listCatalog({ catalogRoot })).toEqual([]);

		await runCli(["remove", "daily-brief"]);
		expect(process.exitCode).toBe(1);
	});

	it("verify reports drift with a non-zero exit", async () => {
		await runCli(["install", writeSkill("daily-brief")]);
		await runCli(["verify", "--json"]);
		expect(process.exitCode).toBeUndefined();

		fs.appendFileSync(path.join(catalogRoot, "skills", "daily-brief", "SKILL.md"), "\ntampered\n");
		await runCli(["verify", "--json"]);
		expect(process.exitCode).toBe(1);
		const out = JSON.parse(logSpy.mock.calls.at(-1)?.[0] as string);
		expect(out.skills[0]).toMatchObject({ name: "daily-brief", status: "drift" });
	});
});

describe("hermes-skills install-upstream", () => {
	it("refuses to run without an explicit upstream root", async () => {
		await runCli(["install-upstream", "productivity/daily-brief"]);
		expect(process.exitCode).toBe(1);
		expect(String(errorSpy.mock.calls.at(-1)?.[0])).toContain("--upstream-root");
	});

	it("installs from an explicit upstream root and rejects traversal", async () => {
		const upstreamRoot = path.join(tempRoot, "upstream");
		const skillDir = path.join(upstreamRoot, "productivity", "daily-brief");
		fs.mkdirSync(skillDir, { recursive: true });
		fs.writeFileSync(
			path.join(skillDir, "SKILL.md"),
			"---\nname: daily-brief\ndescription: Helps with briefs\n---\n\nA harmless guide.\n",
		);

		await runCli(["install-upstream", "productivity/daily-brief", "--upstream-root", upstreamRoot]);
		expect(process.exitCode).toBeUndefined();
		expect(listCatalog({ catalogRoot })[0]).toMatchObject({
			name: "daily-brief",
			origin: "upstream:productivity/daily-brief",
		});

		await runCli(["install-upstream", "../escape", "--upstream-root", upstreamRoot]);
		expect(process.exitCode).toBe(1);
		expect(String(errorSpy.mock.calls.at(-1)?.[0])).toContain("invalid upstream skill path");
	});
});

describe("hermes-skills install-from-curator", () => {
	function createSkillReviewItem(sourceDir: string): string {
		const item = upsertVerifiedCuratorItem({
			fingerprint: `skill-review:${path.basename(sourceDir)}`,
			kind: "skill_review",
			severity: "low",
			source: "test",
			title: "Catalog a skill",
			summary: "Install a reviewed skill into the Hermes catalog.",
			entityRef: `skill:${path.basename(sourceDir)}`,
			proposedAction: { catalogInstall: { sourceDir } },
			evidence: { reason: "test fixture" },
		});
		return item.id;
	}

	it("installs from an accepted item and records the curator linkage", async () => {
		const id = createSkillReviewItem(writeSkill("daily-brief"));
		decideCuratorItem({ id, status: "accepted", actor: "cli:test" });

		await runCli(["install-from-curator", id]);
		expect(process.exitCode).toBeUndefined();
		expect(listCatalog({ catalogRoot })[0]).toMatchObject({
			name: "daily-brief",
			origin: `curator:${id}`,
		});
	});

	it("refuses open and rejected items", async () => {
		const openId = createSkillReviewItem(writeSkill("open-skill"));
		await runCli(["install-from-curator", openId]);
		expect(process.exitCode).toBe(1);
		expect(String(errorSpy.mock.calls.at(-1)?.[0])).toContain("is open");

		process.exitCode = undefined;
		const rejectedId = createSkillReviewItem(writeSkill("rejected-skill"));
		decideCuratorItem({ id: rejectedId, status: "rejected", actor: "cli:test" });
		await runCli(["install-from-curator", rejectedId]);
		expect(process.exitCode).toBe(1);
		expect(String(errorSpy.mock.calls.at(-1)?.[0])).toContain("is rejected");
		expect(listCatalog({ catalogRoot })).toEqual([]);
	});

	it("refuses non-skill_review items and unknown ids", async () => {
		const item = upsertVerifiedCuratorItem({
			fingerprint: "cron:not-a-skill",
			kind: "cron_hardening",
			severity: "low",
			source: "test",
			title: "Harden a cron job",
			summary: "Not a skill item.",
			entityRef: "cron:x",
			proposedAction: { catalogInstall: { sourceDir: "/nowhere" } },
			evidence: {},
		});
		decideCuratorItem({ id: item.id, status: "accepted", actor: "cli:test" });
		await runCli(["install-from-curator", item.id]);
		expect(process.exitCode).toBe(1);
		expect(String(errorSpy.mock.calls.at(-1)?.[0])).toContain("not skill_review");

		process.exitCode = undefined;
		await runCli(["install-from-curator", "curator-does-not-exist"]);
		expect(process.exitCode).toBe(1);
		expect(String(errorSpy.mock.calls.at(-1)?.[0])).toContain("unknown curator item");
	});

	it("requires exactly one of sourceDir or upstreamRel", async () => {
		const item = upsertVerifiedCuratorItem({
			fingerprint: "skill-review:ambiguous",
			kind: "skill_review",
			severity: "low",
			source: "test",
			title: "Ambiguous install",
			summary: "Carries both source kinds.",
			entityRef: "skill:ambiguous",
			proposedAction: { catalogInstall: { sourceDir: "/a", upstreamRel: "b/c" } },
			evidence: {},
		});
		decideCuratorItem({ id: item.id, status: "accepted", actor: "cli:test" });
		await runCli(["install-from-curator", item.id]);
		expect(process.exitCode).toBe(1);
		expect(String(errorSpy.mock.calls.at(-1)?.[0])).toContain("exactly one of");
	});
});
