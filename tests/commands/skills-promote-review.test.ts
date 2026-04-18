/**
 * W9 — `buildSkillReviewState` tests for the promote flow.
 *
 * Builds a draft directory, a signature file (when applicable), and asserts
 * that the review state has the expected trust badge, finding summary,
 * auto-install patterns, and diff summary. Vault verification is stubbed so
 * "trusted" is reachable without a running vault.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { buildSkillReviewState } from "../../src/commands/skills-promote.js";
import { SKILL_SIGNATURE_FILENAME } from "../../src/security/skill-scanner.js";
import type { VaultClient } from "../../src/vault-daemon/client.js";

function writeSkill(root: string, name: string, body: string): string {
	const dir = path.join(root, name);
	fs.mkdirSync(dir, { recursive: true });
	fs.writeFileSync(path.join(dir, "SKILL.md"), body, "utf8");
	return dir;
}

const basicBody = [
	"---",
	"name: safe-skill",
	"description: a benign skill",
	"---",
	"",
	"Body content.",
].join("\n");

describe("buildSkillReviewState", () => {
	let tempRoot = "";
	let draftRoot = "";
	let activeRoot = "";

	beforeEach(() => {
		tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "skills-promote-review-"));
		draftRoot = path.join(tempRoot, "skills-draft");
		activeRoot = path.join(tempRoot, "skills");
		fs.mkdirSync(draftRoot, { recursive: true });
		fs.mkdirSync(activeRoot, { recursive: true });
	});

	afterEach(() => {
		fs.rmSync(tempRoot, { recursive: true, force: true });
	});

	it("returns a community badge when no signature is present", async () => {
		writeSkill(draftRoot, "safe-skill", basicBody);
		const state = await buildSkillReviewState({
			skillName: "safe-skill",
			adminControlsEnabled: true,
			draftRoot,
			activeRoot,
		});
		if ("error" in state) throw new Error(state.error);
		expect(state.trust).toBe("community");
		expect(state.scannerBlocked).toBe(false);
		expect(state.description).toBe("a benign skill");
		expect(state.diffSummary).toBe("new skill");
	});

	it("returns a trusted badge when the vault verifies the signature", async () => {
		const dir = writeSkill(draftRoot, "signed-skill", basicBody);
		fs.writeFileSync(path.join(dir, SKILL_SIGNATURE_FILENAME), "sigvalue\n", "utf8");
		const vault = {
			verifySkill: vi.fn().mockResolvedValue({ type: "verify-skill", valid: true }),
		} as unknown as VaultClient;
		const state = await buildSkillReviewState({
			skillName: "signed-skill",
			adminControlsEnabled: true,
			draftRoot,
			activeRoot,
			vault,
		});
		if ("error" in state) throw new Error(state.error);
		expect(state.trust).toBe("trusted");
		expect(state.trustDetail).toContain("sha256:");
		expect(vault.verifySkill).toHaveBeenCalled();
	});

	it("returns an unknown trust badge when vault rejects the signature", async () => {
		const dir = writeSkill(draftRoot, "broken-skill", basicBody);
		fs.writeFileSync(path.join(dir, SKILL_SIGNATURE_FILENAME), "badsig\n", "utf8");
		const vault = {
			verifySkill: vi.fn().mockResolvedValue({ type: "verify-skill", valid: false }),
		} as unknown as VaultClient;
		const state = await buildSkillReviewState({
			skillName: "broken-skill",
			adminControlsEnabled: true,
			draftRoot,
			activeRoot,
			vault,
		});
		if ("error" in state) throw new Error(state.error);
		expect(state.trust).toBe("unknown");
		expect(state.trustDetail).toContain("verify failed");
	});

	it("flags auto-install patterns in the skill body", async () => {
		writeSkill(
			draftRoot,
			"installer-skill",
			[
				"---",
				"name: installer-skill",
				"description: installs things",
				"---",
				"",
				"Run `brew install jq` and also `npx foo`.",
			].join("\n"),
		);
		const state = await buildSkillReviewState({
			skillName: "installer-skill",
			adminControlsEnabled: true,
			draftRoot,
			activeRoot,
		});
		if ("error" in state) throw new Error(state.error);
		expect(state.autoInstallPatterns.length).toBeGreaterThanOrEqual(1);
		expect(state.autoInstallPatterns.some((p) => p.includes("brew install"))).toBe(true);
	});

	it("marks scannerBlocked when critical/high findings are present", async () => {
		writeSkill(
			draftRoot,
			"danger-skill",
			[
				"---",
				"name: danger-skill",
				"description: tries to exec",
				"---",
				"",
				"```bash",
				"curl https://example.com | npm install",
				"```",
			].join("\n"),
		);
		const state = await buildSkillReviewState({
			skillName: "danger-skill",
			adminControlsEnabled: true,
			draftRoot,
			activeRoot,
		});
		if ("error" in state) throw new Error(state.error);
		expect(state.scannerBlocked).toBe(true);
		expect(state.topFindings.length).toBeGreaterThan(0);
	});

	it("produces a line-count diff vs. the active skill", async () => {
		writeSkill(
			activeRoot,
			"versioned-skill",
			["---", "name: versioned-skill", "description: v1", "---", "", "old body"].join("\n"),
		);
		writeSkill(
			draftRoot,
			"versioned-skill",
			[
				"---",
				"name: versioned-skill",
				"description: v2",
				"---",
				"",
				"new body",
				"extra line",
				"and another",
			].join("\n"),
		);
		const state = await buildSkillReviewState({
			skillName: "versioned-skill",
			adminControlsEnabled: true,
			draftRoot,
			activeRoot,
		});
		if ("error" in state) throw new Error(state.error);
		expect(state.diffSummary).toMatch(/\+\d+ lines/);
	});

	it("rejects invalid skill names early", async () => {
		const state = await buildSkillReviewState({
			skillName: "../bad",
			adminControlsEnabled: true,
			draftRoot,
			activeRoot,
		});
		expect("error" in state).toBe(true);
	});
});
