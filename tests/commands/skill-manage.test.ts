import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	archiveManagedSkill,
	cleanupManagedSkillHousekeeping,
	createManagedSkill,
	patchManagedSkill,
	pinManagedSkill,
	renameManagedSkill,
} from "../../src/commands/skill-manage.js";

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

function sha256(content: string): string {
	return crypto.createHash("sha256").update(content).digest("hex");
}

function mutatingSnapshotDate(mutate: () => void): Date {
	const mutatingNow = new Date("2026-05-16T00:00:00.000Z");
	let mutated = false;
	vi.spyOn(mutatingNow, "toISOString").mockImplementation(() => {
		if (!mutated) {
			mutated = true;
			mutate();
		}
		return "2026-05-16T00:00:00.000Z";
	});
	return mutatingNow;
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
		vi.restoreAllMocks();
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
			target_relative_dir: path.join("agent", "telegram", "demo-skill"),
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
			target_relative_dir: path.join("agent", "social", "xtwitter", "x-helper"),
			success: true,
		});
	});

	it("rejects malformed, reserved, and traversal names before touching skill paths", () => {
		for (const name of ["../outside", "nested/skill", "BadName", "", "archived"]) {
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
		expect(readAuditEntries(auditPath)).toHaveLength(5);
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

	it("accepts neutral credential placeholders in managed skill examples", () => {
		const result = createManagedSkill({
			name: "placeholder-examples",
			markdown: skillMarkdown("placeholder-examples", {
				body: [
					'Use Authorization: "Bearer <provider-token-placeholder>" in examples.',
					"Use sk-... for API-key-shaped examples.",
					"Use ghp_xxxxxxxxxxxxxxxxxxxx for GitHub-token-shaped examples.",
					"Use example-token-placeholder or redacted for opaque values.",
				].join("\n"),
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

		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(fs.existsSync(path.join(result.targetDir, "SKILL.md"))).toBe(true);
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

	it("rejects create when a name collision appears between snapshot and write", () => {
		const collisionDir = path.join(skillRoot, "race-create");

		const result = createManagedSkill({
			name: "race-create",
			markdown: skillMarkdown("race-create"),
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			now: mutatingSnapshotDate(() => {
				fs.mkdirSync(collisionDir, { recursive: true });
				fs.writeFileSync(path.join(collisionDir, "SKILL.md"), skillMarkdown("race-create"));
			}),
		});

		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error).toContain("already exists");
			expect(result.snapshotPath).toBeDefined();
		}
		expect(fs.existsSync(collisionDir)).toBe(true);
		expect(fs.existsSync(path.join(skillRoot, "agent", "telegram", "race-create"))).toBe(false);
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

	it("patches an existing managed skill after snapshotting the old version", () => {
		const targetDir = path.join(skillRoot, "agent", "telegram", "patch-me");
		const original = skillMarkdown("patch-me", { body: "Original instructions." });
		const replacement = skillMarkdown("patch-me", { body: "Updated instructions." });
		fs.mkdirSync(targetDir, { recursive: true });
		fs.writeFileSync(path.join(targetDir, "SKILL.md"), original, "utf8");

		const result = patchManagedSkill({
			name: "patch-me",
			markdown: replacement,
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			expectedSha256: sha256(original),
			now,
		});

		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(fs.readFileSync(result.skillMdPath, "utf8")).toBe(replacement);
		const snapshotSkill = execFileSync(
			"tar",
			["-xOf", result.snapshotPath, "./agent/telegram/patch-me/SKILL.md"],
			{ encoding: "utf8" },
		);
		expect(snapshotSkill).toBe(original);
		expect(readAuditEntries(auditPath).at(-1)).toMatchObject({
			action: "patch",
			skill_name: "patch-me",
			previous_sha256: sha256(original),
			new_sha256: sha256(replacement),
			expected_sha256: sha256(original),
			target_relative_dir: path.join("agent", "telegram", "patch-me"),
			success: true,
		});
	});

	it("rejects missing, stale, static-unsafe, or scanner-blocked patches without modifying the managed skill", () => {
		const targetDir = path.join(skillRoot, "agent", "telegram", "steady");
		const original = skillMarkdown("steady", { body: "Keep this body." });
		fs.mkdirSync(targetDir, { recursive: true });
		fs.writeFileSync(path.join(targetDir, "SKILL.md"), original, "utf8");

		const missingExpected = patchManagedSkill({
			name: "steady",
			markdown: skillMarkdown("steady", { body: "Replacement." }),
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			now,
		});
		const stale = patchManagedSkill({
			name: "steady",
			markdown: skillMarkdown("steady", { body: "Replacement." }),
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			expectedSha256: "0".repeat(64),
			now,
		});
		const unsafe = patchManagedSkill({
			name: "steady",
			markdown: skillMarkdown("steady", {
				body: "Read ANTHROPIC_API_KEY from the environment.",
			}),
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			expectedSha256: sha256(original),
			now,
		});
		const scannerBlocked = patchManagedSkill({
			name: "steady",
			markdown: skillMarkdown("steady", {
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
			expectedSha256: sha256(original),
			now,
		});

		expect(missingExpected.success).toBe(false);
		if (!missingExpected.success) expect(missingExpected.error).toContain("--expected-sha256");
		expect(stale.success).toBe(false);
		if (!stale.success) expect(stale.error).toContain("does not match expected");
		expect(unsafe.success).toBe(false);
		if (!unsafe.success) expect(unsafe.error).toContain("infrastructure secret");
		expect(scannerBlocked.success).toBe(false);
		if (!scannerBlocked.success) expect(scannerBlocked.scanBlocked).toBe(true);
		expect(fs.readFileSync(path.join(targetDir, "SKILL.md"), "utf8")).toBe(original);
	});

	it("rejects patches when SKILL.md changes between the first hash check and final rename", () => {
		const targetDir = path.join(skillRoot, "agent", "telegram", "race-patch");
		const original = skillMarkdown("race-patch", { body: "Original." });
		const replacement = skillMarkdown("race-patch", { body: "Replacement." });
		const concurrent = skillMarkdown("race-patch", { body: "Concurrent edit." });
		fs.mkdirSync(targetDir, { recursive: true });
		fs.writeFileSync(path.join(targetDir, "SKILL.md"), original, "utf8");

		const result = patchManagedSkill({
			name: "race-patch",
			markdown: replacement,
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			expectedSha256: sha256(original),
			now: mutatingSnapshotDate(() => {
				fs.writeFileSync(path.join(targetDir, "SKILL.md"), concurrent, "utf8");
			}),
		});

		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error).toContain("does not match expected");
			expect(result.snapshotPath).toBeDefined();
		}
		expect(fs.readFileSync(path.join(targetDir, "SKILL.md"), "utf8")).toBe(concurrent);
	});

	it("archives a managed social skill into the service archive after snapshotting", () => {
		const targetDir = path.join(skillRoot, "agent", "social", "xtwitter", "x-helper");
		const original = skillMarkdown("x-helper", { body: "Social helper." });
		fs.mkdirSync(targetDir, { recursive: true });
		fs.writeFileSync(path.join(targetDir, "SKILL.md"), original, "utf8");

		const result = archiveManagedSkill({
			name: "x-helper",
			persona: { kind: "social", serviceId: "xtwitter" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			expectedSha256: sha256(original),
			now,
		});

		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(fs.existsSync(targetDir)).toBe(false);
		expect(result.archiveDir).toContain(path.join("agent", "social", "xtwitter", "archived"));
		expect(fs.readFileSync(path.join(result.archiveDir, "SKILL.md"), "utf8")).toBe(original);
		const listing = execFileSync("tar", ["-tzf", result.snapshotPath], { encoding: "utf8" });
		expect(listing).toContain("./agent/social/xtwitter/x-helper/SKILL.md");
		expect(readAuditEntries(auditPath).at(-1)).toMatchObject({
			action: "archive",
			persona: "social-xtwitter",
			service_id: "xtwitter",
			previous_sha256: sha256(original),
			expected_sha256: sha256(original),
			source_relative_dir: path.join("agent", "social", "xtwitter", "x-helper"),
			archive_relative_dir: path.relative(skillRoot, result.archiveDir),
			success: true,
		});
	});

	it("rejects archive when SKILL.md changes between the first hash check and final move", () => {
		const targetDir = path.join(skillRoot, "agent", "telegram", "race-archive");
		const original = skillMarkdown("race-archive", { body: "Original." });
		const concurrent = skillMarkdown("race-archive", { body: "Concurrent edit." });
		fs.mkdirSync(targetDir, { recursive: true });
		fs.writeFileSync(path.join(targetDir, "SKILL.md"), original, "utf8");

		const result = archiveManagedSkill({
			name: "race-archive",
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			expectedSha256: sha256(original),
			now: mutatingSnapshotDate(() => {
				fs.writeFileSync(path.join(targetDir, "SKILL.md"), concurrent, "utf8");
			}),
		});

		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error).toContain("does not match expected");
			expect(result.snapshotPath).toBeDefined();
		}
		expect(fs.readFileSync(path.join(targetDir, "SKILL.md"), "utf8")).toBe(concurrent);
	});

	it("rejects archive when a pin marker appears between snapshot and final move", () => {
		const targetDir = path.join(skillRoot, "agent", "telegram", "race-pin-archive");
		const original = skillMarkdown("race-pin-archive", { body: "Original." });
		fs.mkdirSync(targetDir, { recursive: true });
		fs.writeFileSync(path.join(targetDir, "SKILL.md"), original, "utf8");
		const metadataPath = path.join(targetDir, ".telclaude-managed.json");

		const result = archiveManagedSkill({
			name: "race-pin-archive",
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			expectedSha256: sha256(original),
			now: mutatingSnapshotDate(() => {
				fs.writeFileSync(metadataPath, JSON.stringify({ schema_version: 1, pinned: true }));
			}),
		});

		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error).toContain("pinned");
			expect(result.snapshotPath).toBeDefined();
		}
		expect(fs.existsSync(targetDir)).toBe(true);
		expect(fs.existsSync(metadataPath)).toBe(true);
	});

	it("refuses to patch or archive the user-authored skill namespace", () => {
		const userDir = path.join(skillRoot, "memory");
		const memoryMarkdown = skillMarkdown("memory");
		fs.mkdirSync(userDir, { recursive: true });
		fs.writeFileSync(path.join(userDir, "SKILL.md"), memoryMarkdown, "utf8");

		const patch = patchManagedSkill({
			name: "memory",
			markdown: skillMarkdown("memory", { body: "Replacement." }),
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			expectedSha256: sha256(memoryMarkdown),
			now,
		});
		const archive = archiveManagedSkill({
			name: "memory",
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			expectedSha256: sha256(memoryMarkdown),
			now,
		});

		expect(patch.success).toBe(false);
		expect(archive.success).toBe(false);
		expect(fs.existsSync(path.join(skillRoot, "agent", "telegram", "memory"))).toBe(false);
		expect(fs.existsSync(path.join(userDir, "SKILL.md"))).toBe(true);
	});

	it("rejects managed target paths that resolve through parent symlinks outside the skill root", () => {
		const outsideRoot = path.join(tempRoot, "outside-skills");
		fs.mkdirSync(path.join(skillRoot, "agent"), { recursive: true });
		fs.mkdirSync(outsideRoot, { recursive: true });
		fs.symlinkSync(outsideRoot, path.join(skillRoot, "agent", "telegram"), "dir");

		const create = createManagedSkill({
			name: "escape",
			markdown: skillMarkdown("escape"),
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			now,
		});
		expect(create.success).toBe(false);
		if (!create.success) expect(create.error).toContain("outside the managed skill root");
		expect(fs.existsSync(path.join(outsideRoot, "escape", "SKILL.md"))).toBe(false);

		const original = skillMarkdown("escape", { body: "Outside target." });
		fs.mkdirSync(path.join(outsideRoot, "escape"), { recursive: true });
		fs.writeFileSync(path.join(outsideRoot, "escape", "SKILL.md"), original, "utf8");

		const patch = patchManagedSkill({
			name: "escape",
			markdown: skillMarkdown("escape", { body: "Replacement." }),
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			expectedSha256: sha256(original),
			now,
		});
		const archive = archiveManagedSkill({
			name: "escape",
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			expectedSha256: sha256(original),
			now,
		});

		expect(patch.success).toBe(false);
		if (!patch.success) expect(patch.error).toContain("outside the managed skill root");
		expect(archive.success).toBe(false);
		if (!archive.success) expect(archive.error).toContain("outside the managed skill root");
		expect(fs.readFileSync(path.join(outsideRoot, "escape", "SKILL.md"), "utf8")).toBe(original);
	});

	it("does not follow a preexisting symlink at the patch temp path", () => {
		const targetDir = path.join(skillRoot, "agent", "telegram", "temp-safe");
		const original = skillMarkdown("temp-safe", { body: "Original." });
		const replacement = skillMarkdown("temp-safe", { body: "Replacement." });
		fs.mkdirSync(targetDir, { recursive: true });
		fs.writeFileSync(path.join(targetDir, "SKILL.md"), original, "utf8");
		const outsideFile = path.join(tempRoot, "outside-file");
		fs.symlinkSync(outsideFile, path.join(targetDir, `.SKILL.md.${process.pid}.fixed-temp.tmp`));
		vi.spyOn(crypto, "randomUUID").mockReturnValue(
			"fixed-temp" as ReturnType<typeof crypto.randomUUID>,
		);

		const result = patchManagedSkill({
			name: "temp-safe",
			markdown: replacement,
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			expectedSha256: sha256(original),
			now,
		});

		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toContain("Failed to patch");
		expect(fs.existsSync(outsideFile)).toBe(false);
		expect(fs.readFileSync(path.join(targetDir, "SKILL.md"), "utf8")).toBe(original);
	});

	it("pins and unpins a managed skill, while pinned archive and rename fail closed", () => {
		const targetDir = path.join(skillRoot, "agent", "telegram", "pinned-skill");
		const original = skillMarkdown("pinned-skill", { body: "Pinned body." });
		fs.mkdirSync(targetDir, { recursive: true });
		fs.writeFileSync(path.join(targetDir, "SKILL.md"), original, "utf8");

		const pin = pinManagedSkill({
			name: "pinned-skill",
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			expectedSha256: sha256(original),
			pinned: true,
			now,
		});

		expect(pin.success).toBe(true);
		if (!pin.success) return;
		expect(JSON.parse(fs.readFileSync(pin.metadataPath, "utf8"))).toMatchObject({
			schema_version: 1,
			pinned: true,
			pinned_by: "tg:1",
		});
		const snapshotListing = execFileSync("tar", ["-tzf", pin.snapshotPath], {
			encoding: "utf8",
		});
		expect(snapshotListing).not.toContain(".telclaude-managed.json");

		const archive = archiveManagedSkill({
			name: "pinned-skill",
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			expectedSha256: sha256(original),
			now,
		});
		const rename = renameManagedSkill({
			name: "pinned-skill",
			newName: "renamed-pinned",
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			expectedSha256: sha256(original),
			now,
		});

		expect(archive.success).toBe(false);
		if (!archive.success) expect(archive.error).toContain("pinned");
		expect(rename.success).toBe(false);
		if (!rename.success) expect(rename.error).toContain("pinned");

		const patched = skillMarkdown("pinned-skill", { body: "Patched while pinned." });
		const patch = patchManagedSkill({
			name: "pinned-skill",
			markdown: patched,
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			expectedSha256: sha256(original),
			now,
		});
		expect(patch.success).toBe(true);
		expect(fs.existsSync(pin.metadataPath)).toBe(true);

		const unpin = pinManagedSkill({
			name: "pinned-skill",
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			expectedSha256: sha256(patched),
			pinned: false,
			now,
		});

		expect(unpin.success).toBe(true);
		expect(fs.existsSync(pin.metadataPath)).toBe(false);
		expect(readAuditEntries(auditPath).map((entry) => entry.action)).toContain("unpin");
	});

	it("treats malformed pin metadata as pinned and unpin removes symlink markers only", () => {
		const targetDir = path.join(skillRoot, "agent", "telegram", "weird-pin");
		const original = skillMarkdown("weird-pin", { body: "Original." });
		fs.mkdirSync(targetDir, { recursive: true });
		fs.writeFileSync(path.join(targetDir, "SKILL.md"), original, "utf8");
		const outsideTarget = path.join(tempRoot, "outside-marker-target");
		fs.writeFileSync(outsideTarget, "keep me", "utf8");
		const metadataPath = path.join(targetDir, ".telclaude-managed.json");
		fs.symlinkSync(outsideTarget, metadataPath);

		const archive = archiveManagedSkill({
			name: "weird-pin",
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			expectedSha256: sha256(original),
			now,
		});
		expect(archive.success).toBe(false);
		if (!archive.success) expect(archive.error).toContain("pinned");

		const unpin = pinManagedSkill({
			name: "weird-pin",
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			expectedSha256: sha256(original),
			pinned: false,
			now,
		});

		expect(unpin.success).toBe(true);
		expect(fs.existsSync(metadataPath)).toBe(false);
		expect(fs.readFileSync(outsideTarget, "utf8")).toBe("keep me");

		fs.writeFileSync(metadataPath, JSON.stringify({ schema_version: 1, pinned: false }), "utf8");
		const malformedArchive = archiveManagedSkill({
			name: "weird-pin",
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			expectedSha256: sha256(original),
			now,
		});
		expect(malformedArchive.success).toBe(false);
		if (!malformedArchive.success) expect(malformedArchive.error).toContain("pinned");
	});

	it("renames a managed skill, rewriting only frontmatter name after snapshotting", () => {
		const sourceDir = path.join(skillRoot, "agent", "telegram", "old-name");
		const original = [
			"---",
			"name: old-name",
			"description: test managed skill",
			"allowed-tools:",
			"  - Read",
			"---",
			"",
			"# old-name",
			"",
			"Body mentions name: old-name and should remain unchanged.",
			"",
		].join("\n");
		fs.mkdirSync(sourceDir, { recursive: true });
		fs.writeFileSync(path.join(sourceDir, "SKILL.md"), original, "utf8");

		const result = renameManagedSkill({
			name: "old-name",
			newName: "new-name",
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			expectedSha256: sha256(original),
			now,
		});

		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(fs.existsSync(sourceDir)).toBe(false);
		expect(result.targetDir).toBe(path.join(skillRoot, "agent", "telegram", "new-name"));
		const renamed = fs.readFileSync(result.skillMdPath, "utf8");
		expect(renamed).toContain("name: new-name");
		expect(renamed).toContain("# old-name");
		expect(renamed).toContain("Body mentions name: old-name");
		const snapshotSkill = execFileSync(
			"tar",
			["-xOf", result.snapshotPath, "./agent/telegram/old-name/SKILL.md"],
			{ encoding: "utf8" },
		);
		expect(snapshotSkill).toBe(original);
		expect(readAuditEntries(auditPath).at(-1)).toMatchObject({
			action: "rename",
			skill_name: "old-name",
			new_skill_name: "new-name",
			source_relative_dir: path.join("agent", "telegram", "old-name"),
			target_relative_dir: path.join("agent", "telegram", "new-name"),
			success: true,
		});
	});

	it("scans bundled skill resources before activating a rename", () => {
		const sourceDir = path.join(skillRoot, "agent", "telegram", "resource-rename");
		const original = skillMarkdown("resource-rename", { body: "Original." });
		fs.mkdirSync(path.join(sourceDir, "scripts"), { recursive: true });
		fs.writeFileSync(path.join(sourceDir, "SKILL.md"), original, "utf8");
		fs.writeFileSync(
			path.join(sourceDir, "scripts", "hazard.js"),
			'import { execSync } from "node:child_process";\nexecSync("whoami");\n',
			"utf8",
		);

		const result = renameManagedSkill({
			name: "resource-rename",
			newName: "resource-renamed",
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			expectedSha256: sha256(original),
			now,
		});

		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.scanBlocked).toBe(true);
			expect(result.error).toContain("Direct process execution");
			expect(result.snapshotPath).toBeDefined();
		}
		expect(fs.existsSync(sourceDir)).toBe(true);
		expect(fs.existsSync(path.join(skillRoot, "agent", "telegram", "resource-renamed"))).toBe(
			false,
		);
	});

	it("rejects rename collisions and stale or concurrent edits without moving the source", () => {
		const sourceDir = path.join(skillRoot, "agent", "telegram", "rename-steady");
		const original = skillMarkdown("rename-steady", { body: "Original." });
		fs.mkdirSync(sourceDir, { recursive: true });
		fs.writeFileSync(path.join(sourceDir, "SKILL.md"), original, "utf8");
		fs.mkdirSync(path.join(skillRoot, "existing-user"), { recursive: true });
		fs.writeFileSync(
			path.join(skillRoot, "existing-user", "SKILL.md"),
			skillMarkdown("existing-user"),
			"utf8",
		);

		const collision = renameManagedSkill({
			name: "rename-steady",
			newName: "existing-user",
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			expectedSha256: sha256(original),
			now,
		});
		const stale = renameManagedSkill({
			name: "rename-steady",
			newName: "rename-stale",
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			expectedSha256: "0".repeat(64),
			now,
		});
		const concurrent = skillMarkdown("rename-steady", { body: "Concurrent edit." });
		const raced = renameManagedSkill({
			name: "rename-steady",
			newName: "rename-raced",
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			expectedSha256: sha256(original),
			now: mutatingSnapshotDate(() => {
				fs.writeFileSync(path.join(sourceDir, "SKILL.md"), concurrent, "utf8");
			}),
		});

		expect(collision.success).toBe(false);
		if (!collision.success) expect(collision.error).toContain("also exists");
		expect(stale.success).toBe(false);
		if (!stale.success) expect(stale.error).toContain("does not match expected");
		expect(raced.success).toBe(false);
		if (!raced.success) expect(raced.error).toContain("does not match expected");
		expect(fs.existsSync(sourceDir)).toBe(true);
		expect(fs.readFileSync(path.join(sourceDir, "SKILL.md"), "utf8")).toBe(concurrent);
		expect(fs.existsSync(path.join(skillRoot, "agent", "telegram", "rename-raced"))).toBe(false);
	});

	it("does not rename user-authored skills outside the managed namespace", () => {
		const userDir = path.join(skillRoot, "user-owned");
		const original = skillMarkdown("user-owned", { body: "User namespace." });
		fs.mkdirSync(userDir, { recursive: true });
		fs.writeFileSync(path.join(userDir, "SKILL.md"), original, "utf8");

		const result = renameManagedSkill({
			name: "user-owned",
			newName: "agent-owned",
			persona: { kind: "telegram" },
			actorTier: "WRITE_LOCAL",
			userId: "tg:1",
			cwd: projectRoot,
			skillRoot,
			snapshotRoot,
			auditPath,
			expectedSha256: sha256(original),
			now,
		});

		expect(result.success).toBe(false);
		if (!result.success) expect(result.error).toContain("Managed skill target does not exist");
		expect(fs.existsSync(userDir)).toBe(true);
		expect(fs.readFileSync(path.join(userDir, "SKILL.md"), "utf8")).toBe(original);
		expect(fs.existsSync(path.join(skillRoot, "agent", "telegram", "agent-owned"))).toBe(false);
	});

	it("cleans stale managed skill locks and mutation artifacts only", () => {
		const lockRoot = path.join(tempRoot, "locks");
		const staleLock = path.join(lockRoot, "telegram-stale.lock");
		const freshLock = path.join(lockRoot, "telegram-fresh.lock");
		const skillDir = path.join(skillRoot, "agent", "telegram", "cleanup-target");
		const personaDir = path.dirname(skillDir);
		const uuid = "11111111-1111-4111-8111-111111111111";
		const staleTmp = path.join(skillDir, `.SKILL.md.123.${uuid}.tmp`);
		const staleBak = path.join(skillDir, `.SKILL.md.123.${uuid}.bak`);
		const staleMetadataTmp = path.join(skillDir, `..telclaude-managed.json.123.${uuid}.tmp`);
		const freshTmp = path.join(skillDir, `.SKILL.md.456.${uuid}.tmp`);
		const unrelated = path.join(skillDir, ".SKILL.md.not-a-managed-temp.tmp");
		const symlinkTarget = path.join(tempRoot, "outside-target");
		const symlinkArtifact = path.join(skillDir, `.SKILL.md.789.${uuid}.tmp`);
		const staleRenameTmp = path.join(personaDir, ".telclaude-rename-new-name.tmp-abcdef");
		const staleRenameBak = path.join(personaDir, `.telclaude-rename-old-name.bak-123-${uuid}`);
		const staleTempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-skill-manage-"));
		const oldDate = new Date(now.getTime() - 2 * 60 * 60 * 1000);

		fs.mkdirSync(staleLock, { recursive: true });
		fs.mkdirSync(freshLock, { recursive: true });
		fs.mkdirSync(skillDir, { recursive: true });
		fs.writeFileSync(staleTmp, "old", "utf8");
		fs.writeFileSync(staleBak, "old", "utf8");
		fs.writeFileSync(staleMetadataTmp, "old", "utf8");
		fs.writeFileSync(freshTmp, "fresh", "utf8");
		fs.writeFileSync(unrelated, "keep", "utf8");
		fs.writeFileSync(symlinkTarget, "outside", "utf8");
		fs.symlinkSync(symlinkTarget, symlinkArtifact);
		fs.mkdirSync(staleRenameTmp, { recursive: true });
		fs.mkdirSync(staleRenameBak, { recursive: true });

		for (const stalePath of [
			staleLock,
			staleTmp,
			staleBak,
			staleMetadataTmp,
			symlinkArtifact,
			staleRenameTmp,
			staleRenameBak,
			staleTempRoot,
		]) {
			fs.utimesSync(stalePath, oldDate, oldDate);
		}

		const result = cleanupManagedSkillHousekeeping({
			skillRoot,
			auditPath,
			lockRoot,
			now,
			staleMs: 60 * 60 * 1000,
		});

		expect(result.staleLocks).toBe(1);
		expect(result.staleArtifacts).toBe(5);
		expect(result.staleTempRoots).toBeGreaterThanOrEqual(1);
		expect(fs.existsSync(staleLock)).toBe(false);
		expect(fs.existsSync(staleTmp)).toBe(false);
		expect(fs.existsSync(staleBak)).toBe(false);
		expect(fs.existsSync(staleMetadataTmp)).toBe(false);
		expect(fs.existsSync(staleRenameTmp)).toBe(false);
		expect(fs.existsSync(staleRenameBak)).toBe(false);
		expect(fs.existsSync(staleTempRoot)).toBe(false);
		expect(fs.existsSync(freshLock)).toBe(true);
		expect(fs.readFileSync(freshTmp, "utf8")).toBe("fresh");
		expect(fs.readFileSync(unrelated, "utf8")).toBe("keep");
		expect(fs.lstatSync(symlinkArtifact).isSymbolicLink()).toBe(true);
		expect(fs.readFileSync(symlinkTarget, "utf8")).toBe("outside");
	});

	it("rotates managed skill audit logs with bounded retention", () => {
		const auditDir = path.dirname(auditPath);
		const oldRotated = `${auditPath}.2026-05-15T00-00-00-000Z`;
		const olderRotated = `${auditPath}.2026-05-14T00-00-00-000Z`;
		const manualBackup = `${auditPath}.manual-backup`;
		fs.mkdirSync(auditDir, { recursive: true });
		fs.writeFileSync(auditPath, "x".repeat(32), "utf8");
		fs.writeFileSync(oldRotated, "old", "utf8");
		fs.writeFileSync(olderRotated, "older", "utf8");
		fs.writeFileSync(manualBackup, "manual", "utf8");
		fs.utimesSync(auditPath, now, now);
		fs.utimesSync(
			oldRotated,
			new Date("2026-05-15T00:00:00.000Z"),
			new Date("2026-05-15T00:00:00.000Z"),
		);
		fs.utimesSync(
			olderRotated,
			new Date("2026-05-14T00:00:00.000Z"),
			new Date("2026-05-14T00:00:00.000Z"),
		);

		const result = cleanupManagedSkillHousekeeping({
			skillRoot,
			auditPath,
			lockRoot: path.join(tempRoot, "locks"),
			now,
			auditMaxBytes: 16,
			auditRetainedFiles: 1,
		});

		expect(result.auditLog.rotated).toBe(true);
		expect(result.auditLog.rotatedPath).toBeDefined();
		expect(result.auditLog.pruned).toBe(2);
		expect(fs.existsSync(auditPath)).toBe(false);
		expect(fs.existsSync(result.auditLog.rotatedPath ?? "")).toBe(true);
		expect(fs.existsSync(oldRotated)).toBe(false);
		expect(fs.existsSync(olderRotated)).toBe(false);
		expect(fs.readFileSync(manualBackup, "utf8")).toBe("manual");
	});
});
