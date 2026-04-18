import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { scanSkill } from "../../src/security/skill-scanner.js";

/**
 * Tests for the skill-scanner symlink-root rule.
 *
 * Bug #13: the original rule flagged any symlinked skill directory as
 * `symlink-root: critical`. This repo intentionally uses
 * `.claude/skills/<name>` → `.agents/skills/<name>` symlinks so skills
 * can be authored once and surfaced via the SDK-discovered mount point.
 *
 * The relaxed rule:
 *   - A symlink whose realpath stays inside the repo root: no finding.
 *   - A symlink whose realpath escapes the repo root: still critical.
 *   - Regular (non-symlink) directories: unaffected.
 */
describe("skill-scanner symlink-root rule (bug #13)", () => {
	let repoRoot = "";
	let outsideDir = "";

	function writeSkillDir(dir: string): void {
		fs.mkdirSync(dir, { recursive: true });
		fs.writeFileSync(
			path.join(dir, "SKILL.md"),
			[
				"---",
				`name: ${path.basename(dir)}`,
				"description: A benign skill used for symlink-rule tests.",
				"allowed-tools: [Read]",
				"---",
				"",
				"Body.",
			].join("\n"),
			"utf8",
		);
	}

	function symlinkFindings(result: ReturnType<typeof scanSkill>): typeof result.findings {
		return result.findings.filter((f) => f.rule === "symlink-root");
	}

	beforeEach(() => {
		repoRoot = fs.mkdtempSync(path.join(os.tmpdir(), "skill-scanner-repo-"));
		outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), "skill-scanner-outside-"));

		fs.mkdirSync(path.join(repoRoot, ".claude", "skills"), { recursive: true });
		fs.mkdirSync(path.join(repoRoot, ".agents", "skills"), { recursive: true });
	});

	afterEach(() => {
		for (const dir of [repoRoot, outsideDir]) {
			if (dir && fs.existsSync(dir)) {
				fs.rmSync(dir, { recursive: true, force: true });
			}
		}
	});

	it("does not flag a symlink whose realpath stays inside the repo", () => {
		// Canonical layout: .claude/skills/demo → ../../.agents/skills/demo.
		const realSkill = path.join(repoRoot, ".agents", "skills", "demo");
		writeSkillDir(realSkill);

		const mounted = path.join(repoRoot, ".claude", "skills", "demo");
		fs.symlinkSync(path.join("..", "..", ".agents", "skills", "demo"), mounted);

		const result = scanSkill(mounted);

		expect(symlinkFindings(result)).toHaveLength(0);
		expect(result.counts.critical).toBe(0);
		expect(result.blocked).toBe(false);
	});

	it("flags a symlink whose absolute target escapes the repo root as critical", () => {
		const externalSkill = path.join(outsideDir, "evil");
		writeSkillDir(externalSkill);

		const mounted = path.join(repoRoot, ".claude", "skills", "evil");
		fs.symlinkSync(externalSkill, mounted); // absolute target → outside repoRoot

		const result = scanSkill(mounted);

		const hits = symlinkFindings(result);
		expect(hits).toHaveLength(1);
		expect(hits[0].severity).toBe("critical");
		expect(result.counts.critical).toBeGreaterThanOrEqual(1);
		expect(result.blocked).toBe(true);
	});

	it("flags a symlink with a relative traversal target that escapes the repo as critical", () => {
		// Symlink target uses ../../../../etc/passwd — relative traversal
		// that walks out of the repo. The scanner must resolve the realpath
		// (not just inspect the target string) to catch this, and must
		// handle broken targets too: even if /etc/passwd does not exist on
		// the host (e.g., Windows CI), the readlink fallback still resolves
		// the target to an absolute path outside the repo.
		const mounted = path.join(repoRoot, ".claude", "skills", "traverse");
		fs.symlinkSync(path.join("..", "..", "..", "..", "etc", "passwd"), mounted);

		const result = scanSkill(mounted);

		const hits = symlinkFindings(result);
		expect(hits).toHaveLength(1);
		expect(hits[0].severity).toBe("critical");
		expect(result.blocked).toBe(true);
	});

	it("leaves regular (non-symlink) skill directories unaffected", () => {
		const skillDir = path.join(repoRoot, ".claude", "skills", "plain");
		writeSkillDir(skillDir);

		const result = scanSkill(skillDir);

		expect(symlinkFindings(result)).toHaveLength(0);
		expect(result.counts.critical).toBe(0);
		expect(result.blocked).toBe(false);
	});

	it("honours an explicit repoRoot override", () => {
		// Simulate a caller (e.g. scanAllSkills) that passes a non-default
		// repoRoot. The symlink points inside `repoRoot` but the override
		// tells scanSkill that the "real" repo root is `outsideDir`, so the
		// symlink now escapes that boundary and must be flagged.
		const realSkill = path.join(repoRoot, ".agents", "skills", "demo");
		writeSkillDir(realSkill);

		const mounted = path.join(repoRoot, ".claude", "skills", "demo");
		fs.symlinkSync(path.join("..", "..", ".agents", "skills", "demo"), mounted);

		const result = scanSkill(mounted, { repoRoot: outsideDir });

		const hits = symlinkFindings(result);
		expect(hits).toHaveLength(1);
		expect(hits[0].severity).toBe("critical");
	});
});
