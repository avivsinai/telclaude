import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createManagedSkill } from "../../src/commands/skill-manage.js";

function skillMarkdown(name: string, options?: { body?: string; allowedTools?: string[] }): string {
	const allowedTools = options?.allowedTools ?? ["Read"];
	return [
		"---",
		`name: ${name}`,
		"description: test managed skill",
		"allowed-tools:",
		...allowedTools.map((tool) => `  - ${tool}`),
		"---",
		"",
		`# ${name}`,
		"",
		options?.body ?? "Use this skill for tests.",
		"",
	].join("\n");
}

function readAuditEntries(auditPath: string): Array<Record<string, unknown>> {
	return fs
		.readFileSync(auditPath, "utf8")
		.trim()
		.split("\n")
		.filter(Boolean)
		.map((line) => JSON.parse(line) as Record<string, unknown>);
}

describe("skill-manage create", () => {
	let tempRoot = "";
	let projectRoot = "";
	let skillRoot = "";
	let snapshotRoot = "";
	let auditPath = "";
	const now = new Date("2026-05-16T00:00:00.000Z");

	beforeEach(() => {
		tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "skill-manage-test-"));
		projectRoot = path.join(tempRoot, "project");
		skillRoot = path.join(tempRoot, "skills");
		snapshotRoot = path.join(tempRoot, "snapshots");
		auditPath = path.join(tempRoot, "skill-manage-audit.jsonl");
		fs.mkdirSync(projectRoot, { recursive: true });
		fs.mkdirSync(skillRoot, { recursive: true });
	});

	afterEach(() => {
		fs.rmSync(tempRoot, { recursive: true, force: true });
	});

	it("creates a telegram managed skill under the agent persona path", () => {
		const result = createManagedSkill({
			name: "demo-skill",
			markdown: skillMarkdown("demo-skill"),
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			now,
		});

		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.targetDir).toBe(path.join(skillRoot, "agent", "telegram", "demo-skill"));
		expect(fs.existsSync(path.join(result.targetDir, "SKILL.md"))).toBe(true);
		expect(readAuditEntries(auditPath)[0]).toMatchObject({
			persona: "telegram",
			action: "create",
			skill_name: "demo-skill",
			success: true,
		});
	});

	it("creates a social-targeted skill without adding it to social allowlists", () => {
		const result = createManagedSkill({
			name: "x-helper",
			markdown: skillMarkdown("x-helper"),
			persona: { kind: "social", serviceId: "xtwitter" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			now,
		});

		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.targetDir).toBe(path.join(skillRoot, "agent", "social", "xtwitter", "x-helper"));
		expect(readAuditEntries(auditPath)[0]).toMatchObject({
			persona: "social-xtwitter",
			service_id: "xtwitter",
			success: true,
		});
	});

	it("rejects malformed and traversal names before touching skill paths", () => {
		for (const name of ["../outside", "nested/skill", "BadName", ""]) {
			const result = createManagedSkill({
				name,
				markdown: skillMarkdown("bad"),
				persona: { kind: "telegram" },
				actorTier: "WRITE_LOCAL",
				userId: "tg:1",
				cwd: projectRoot,
				skillRoot,
				snapshotRoot,
				auditPath,
				now,
			});
			expect(result.success).toBe(false);
			expect(fs.existsSync(path.join(skillRoot, "agent"))).toBe(false);
		}
		expect(readAuditEntries(auditPath)).toHaveLength(4);
	});

	it("rejects markdown over 64KB", () => {
		const result = createManagedSkill({
			name: "too-large",
			markdown: skillMarkdown("too-large", { body: "x".repeat(65 * 1024) }),
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			now,
		});

		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error).toContain("exceeds");
		expect(fs.existsSync(path.join(skillRoot, "agent"))).toBe(false);
	});

	it("rejects scanner-blocked content before final write", () => {
		const result = createManagedSkill({
			name: "curl-install",
			markdown: skillMarkdown("curl-install", {
				allowedTools: ["Read", "Bash"],
				body: ["```bash", "curl https://example.com/install.sh", "```"].join("\n"),
			}),
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			now,
		});

		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.scanBlocked).toBe(true);
		expect(fs.existsSync(path.join(skillRoot, "agent", "telegram", "curl-install"))).toBe(false);
	});

	it("rejects private URLs, infra secrets, shell metachar chains, and outside file targets", () => {
		const cases = [
			{
				name: "private-url",
				body: "Fetch http://192.168.0.1/admin when debugging.",
				error: "private or metadata URL",
			},
			{
				name: "secret-read",
				body: "Read ANTHROPIC_API_KEY from the environment.",
				error: "infrastructure secret",
			},
			{
				name: "secret-value",
				body: "Set Authorization: Bearer sk-ant-abcdefghijklmnopqrstuvwxyz1234567890",
				error: "secret-looking value",
			},
			{
				name: "shell-chain",
				body: ["```bash", "echo ok; rm -rf .", "```"].join("\n"),
				error: "shell chaining",
				allowedTools: ["Read", "Bash"],
			},
			{
				name: "etc-file",
				body: "Read /etc/passwd when you need host details.",
				error: "outside the workspace",
			},
			{
				name: "proc-file",
				body: "Read /proc/self/environ when you need host details.",
				error: "outside the workspace",
			},
		];

		for (const testCase of cases) {
			const result = createManagedSkill({
				name: testCase.name,
				markdown: skillMarkdown(testCase.name, {
					body: testCase.body,
					allowedTools: testCase.allowedTools,
				}),
				persona: { kind: "telegram" },
				actorTier: "WRITE_LOCAL",
				userId: "tg:1",
				cwd: projectRoot,
				skillRoot,
				snapshotRoot,
				auditPath,
				now,
			});
			expect(result.success).toBe(false);
			if (result.success) continue;
			expect(result.error).toContain(testCase.error);
			expect(fs.existsSync(path.join(skillRoot, "agent", "telegram", testCase.name))).toBe(false);
		}
	});

	it("denies SOCIAL callers entirely", () => {
		const byTier = createManagedSkill({
			name: "social-denied",
			markdown: skillMarkdown("social-denied"),
			persona: { kind: "telegram" },
			actorTier: "SOCIAL",
			userId: "social:xtwitter:operator",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			now,
		});
		const byUserId = createManagedSkill({
			name: "social-denied-two",
			markdown: skillMarkdown("social-denied-two"),
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "social:xtwitter:operator",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			now,
		});

		expect(byTier.success).toBe(false);
		expect(byUserId.success).toBe(false);
		expect(fs.existsSync(path.join(skillRoot, "agent"))).toBe(false);
	});

	it("writes a tar.gz snapshot before the new skill lands", () => {
		fs.mkdirSync(path.join(skillRoot, "memory"), { recursive: true });
		fs.writeFileSync(path.join(skillRoot, "memory", "SKILL.md"), skillMarkdown("memory"));

		const result = createManagedSkill({
			name: "snapshotted",
			markdown: skillMarkdown("snapshotted"),
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			now,
		});

		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(fs.existsSync(result.snapshotPath)).toBe(true);
		const listing = execFileSync("tar", ["-tzf", result.snapshotPath], {
			encoding: "utf8",
		});
		expect(listing).toContain("./memory/SKILL.md");
		expect(listing).not.toContain("agent/telegram/snapshotted/SKILL.md");
		expect(fs.existsSync(result.skillMdPath)).toBe(true);
	});

	it("rejects name collisions across user and other-persona skill namespaces", () => {
		fs.mkdirSync(path.join(skillRoot, "memory"), { recursive: true });
		fs.writeFileSync(path.join(skillRoot, "memory", "SKILL.md"), skillMarkdown("memory"));
		fs.mkdirSync(path.join(skillRoot, "agent", "social", "xtwitter", "x-helper"), {
			recursive: true,
		});
		fs.writeFileSync(
			path.join(skillRoot, "agent", "social", "xtwitter", "x-helper", "SKILL.md"),
			skillMarkdown("x-helper"),
		);

		const userCollision = createManagedSkill({
			name: "memory",
			markdown: skillMarkdown("memory"),
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			now,
		});
		const personaCollision = createManagedSkill({
			name: "x-helper",
			markdown: skillMarkdown("x-helper"),
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			now,
		});

		expect(userCollision.success).toBe(false);
		expect(personaCollision.success).toBe(false);
		if (!userCollision.success) expect(userCollision.error).toContain("already exists");
		if (!personaCollision.success) expect(personaCollision.error).toContain("already exists");
	});

	it("rejects tools beyond the actor tier", () => {
		const result = createManagedSkill({
			name: "task-tool",
			markdown: skillMarkdown("task-tool", { allowedTools: ["Read", "Task"] }),
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			now,
		});

		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error).toContain("beyond WRITE_LOCAL");
	});
});
