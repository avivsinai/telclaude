import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("curator collectors", () => {
	let tempDir: string;
	let projectRoot: string;

	function writeSkill(relativeDir: string, name: string, mtimeMs: number): string {
		const skillDir = path.join(projectRoot, ".claude", "skills", relativeDir);
		const skillPath = path.join(skillDir, "SKILL.md");
		fs.mkdirSync(skillDir, { recursive: true });
		fs.writeFileSync(
			skillPath,
			["---", `name: ${name}`, "description: test skill", "---", "", `# ${name}`, ""].join("\n"),
			"utf8",
		);
		const date = new Date(mtimeMs);
		fs.utimesSync(skillPath, date, date);
		return skillPath;
	}

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-curator-collect-"));
		projectRoot = path.join(tempDir, "project");
		fs.mkdirSync(projectRoot, { recursive: true });
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		vi.resetModules();
		const { resetDatabase } = await import("../../src/storage/db.js");
		resetDatabase();
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("flags agent-prompt cron jobs without storing raw prompt text", async () => {
		const { addCronJob } = await import("../../src/cron/store.js");
		const { runCuratorScan } = await import("../../src/curator/actions.js");
		const { listCuratorItems } = await import("../../src/curator/store.js");
		const now = Date.parse("2026-02-21T10:00:00.000Z");
		const secretPrompt = "Summarize using token ghp_abcdefghijklmnopqrstuvwxyz1234567890";

		addCronJob(
			{
				id: "cron-risky",
				name: "risky digest ghp_abcdefghijklmnopqrstuvwxyz1234567890",
				schedule: { kind: "every", everyMs: 60_000 },
				action: { kind: "agent-prompt", prompt: secretPrompt },
			},
			now,
		);

		const result = runCuratorScan();
		const items = listCuratorItems({ status: "open" });
		const serialized = JSON.stringify(items);

		expect(result.createdOrUpdated).toBe(1);
		expect(items).toHaveLength(1);
		expect(items[0].kind).toBe("cron_hardening");
		expect(items[0].evidence).toMatchObject({
			jobId: "cron-risky",
			hasAllowedSkills: false,
			hasPreprocess: false,
		});
		expect(serialized).not.toContain(secretPrompt);
		expect(serialized).not.toContain("ghp_abcdefghijklmnopqrstuvwxyz1234567890");
	});

	it("does not flag scheduled prompts that already have explicit allowed skills", async () => {
		const { addCronJob } = await import("../../src/cron/store.js");
		const { runCuratorScan } = await import("../../src/curator/actions.js");
		const { listCuratorItems } = await import("../../src/curator/store.js");
		const now = Date.parse("2026-02-21T10:00:00.000Z");

		addCronJob(
			{
				id: "cron-hardened",
				name: "safe digest",
				schedule: { kind: "every", everyMs: 60_000 },
				action: {
					kind: "agent-prompt",
					prompt: "summarize local status",
					allowedSkills: ["summarize"],
				},
			},
			now,
		);

		const result = runCuratorScan();
		expect(result.createdOrUpdated).toBe(0);
		expect(listCuratorItems({ status: "open" })).toHaveLength(0);
	});

	it("suggests archiving old agent-authored skills with no allowed invocations", async () => {
		const { runCuratorScan } = await import("../../src/curator/actions.js");
		const { listCuratorItems } = await import("../../src/curator/store.js");
		const now = Date.parse("2026-05-16T00:00:00.000Z");
		writeSkill("agent/telegram/old-helper", "old-helper", now - 10 * 24 * 60 * 60 * 1000);

		const result = runCuratorScan({
			cwd: projectRoot,
			nowMs: now,
			unusedSkillStaleAfterMs: 7 * 24 * 60 * 60 * 1000,
		});
		const items = listCuratorItems({ status: "open", kind: "skill_review" });

		expect(result.byKind.skill_review).toBe(1);
		expect(items).toHaveLength(1);
		expect(items[0]).toMatchObject({
			kind: "skill_review",
			severity: "low",
			source: "skills",
			entityRef: "skill:agent:telegram:old-helper",
			proposedAction: {
				type: "archive_managed_skill",
			},
			evidence: {
				skillName: "old-helper",
				persona: "telegram",
				allowedInvocations: 0,
			},
		});
		expect(String(items[0].proposedAction.command)).toContain(
			"telclaude skill-manage archive --name old-helper --persona telegram",
		);
		expect(String(items[0].proposedAction.command)).toContain("--expected-sha256");
	});

	it("uses persona-scoped telemetry when deciding whether a skill is stale", async () => {
		const { runCuratorScan } = await import("../../src/curator/actions.js");
		const { listCuratorItems } = await import("../../src/curator/store.js");
		const { recordSkillInvocation } = await import("../../src/storage/skill-telemetry.js");
		const now = Date.parse("2026-05-16T00:00:00.000Z");
		const old = now - 10 * 24 * 60 * 60 * 1000;
		const recent = now - 1 * 24 * 60 * 60 * 1000;
		writeSkill("agent/telegram/recent-helper", "recent-helper", old);
		writeSkill("agent/social/xtwitter/stale-social", "stale-social", old);
		await recordSkillInvocation({
			sessionKey: "s1",
			skillName: "recent-helper",
			decision: "allow",
			source: "telegram",
			createdAt: recent,
		});
		await recordSkillInvocation({
			sessionKey: "s2",
			skillName: "stale-social",
			decision: "allow",
			source: "social",
			serviceId: "xtwitter",
			createdAt: old,
		});

		runCuratorScan({
			cwd: projectRoot,
			nowMs: now,
			unusedSkillStaleAfterMs: 7 * 24 * 60 * 60 * 1000,
		});
		const items = listCuratorItems({ status: "open", kind: "skill_review" });

		expect(items.map((item) => item.entityRef)).toEqual([
			"skill:agent:social:xtwitter:stale-social",
		]);
		expect(String(items[0].proposedAction.command)).toContain(
			"--persona social --service-id xtwitter",
		);
		expect(items[0].evidence).toMatchObject({
			lastAllowedAt: old,
			allowedInvocations: 1,
			persona: "social:xtwitter",
		});
	});
});
