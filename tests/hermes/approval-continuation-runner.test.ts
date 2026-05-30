import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { evaluateApprovalContinuationEvidence } from "../../src/hermes/approval-continuation.js";
import {
	runHermesApprovalContinuationProbe,
	writeApprovalContinuationArtifacts,
} from "../../src/hermes/approval-continuation-runner.js";

const cleanupDirs = new Set<string>();
const hermes = { version: "0.15.1" };

afterEach(() => {
	for (const dir of cleanupDirs) {
		fs.rmSync(dir, { recursive: true, force: true });
	}
	cleanupDirs.clear();
});

describe("Hermes approval-continuation live runner", () => {
	it("does not run or write artifacts without --allow-run", async () => {
		const tempDir = tempPath("approval-continuation-runner-");
		const outPath = path.join(tempDir, "approval-continuation.json");
		const run = await runHermesApprovalContinuationProbe({ allowRun: false, hermes });
		const written = writeApprovalContinuationArtifacts(run, {
			evidencePath: outPath,
			fixtureEvidenceDir: path.join(tempDir, "fixtures"),
		});

		expect(run).toMatchObject({ status: "pending", ran: false });
		expect(written.evidencePath).toBeUndefined();
		expect(fs.existsSync(outPath)).toBe(false);
		expect(fs.existsSync(path.join(tempDir, "fixtures"))).toBe(false);
	});

	it("passes only after the real vault, registry, ledger, verifier, and JTI path is observed", async () => {
		const tempDir = tempPath("approval-continuation-runner-");
		const run = await runHermesApprovalContinuationProbe({
			allowRun: true,
			hermes,
			jtiDataDir: tempDir,
		});
		const serialized = JSON.stringify(run);
		const observations = run.fixtures.flatMap((fixture) => fixture.observations);

		expect(run.status).toBe("pass");
		expect(run.ran).toBe(true);
		expect(run.evidence).toMatchObject({
			schemaVersion: 1,
			hermes,
			native: {
				responds_to_blocked_run: false,
				wrong_actor_denied: true,
				stale_request_denied: true,
				replay_denied: true,
				mutated_decision_denied: true,
			},
			fallback: {
				strategy: "cross_turn_prepare_approve_execute",
			},
		});
		expect(run.evidence?.fallback?.fixtures.map((fixture) => fixture.status)).toEqual([
			"pass",
			"pass",
			"pass",
			"pass",
		]);
		expect(observations).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ name: "wrong_actor_denied", status: "pass" }),
				expect.objectContaining({ name: "stale_request_denied", status: "pass" }),
				expect.objectContaining({ name: "replay_denied", status: "pass" }),
				expect.objectContaining({ name: "mutated_decision_denied", status: "pass" }),
			]),
		);
		expect(readRecordedJtis(tempDir)).toEqual(
			expect.arrayContaining([
				"jti-provider-fixture",
				"jti-outbound-fixture",
				"jti-cron-fixture",
				"jti-long-running-fixture",
				"jti-wrong-actor",
				"jti-replay",
				"jti-mutated-decision",
			]),
		);
		expect(serialized).not.toContain("v1.");
		expect(serialized).not.toContain("approvalToken");
		expect(serialized).not.toContain("signature");
	});

	it("writes the existing approval-continuation evidence schema and fixture artifacts", async () => {
		const tempDir = tempPath("approval-continuation-runner-");
		const outPath = path.join(tempDir, "approval-continuation.json");
		const fixtureDir = path.join(tempDir, "fixtures");
		const run = await runHermesApprovalContinuationProbe({ allowRun: true, hermes });
		const written = writeApprovalContinuationArtifacts(run, {
			evidencePath: outPath,
			fixtureEvidenceDir: fixtureDir,
		});

		expect(written.evidencePath).toBe(outPath);
		expect(fs.existsSync(outPath)).toBe(true);
		for (const fixture of written.evidence?.fallback?.fixtures ?? []) {
			expect(fixture.evidence_path.startsWith(fixtureDir)).toBe(true);
			expect(fs.existsSync(fixture.evidence_path)).toBe(true);
		}
		expect(
			evaluateApprovalContinuationEvidence(JSON.parse(fs.readFileSync(outPath, "utf8"))),
		).toMatchObject({
			status: "pass",
			mode: "cross_turn_fallback",
			productionEnable: true,
		});
	});
});

function tempPath(prefix: string): string {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
	cleanupDirs.add(tempDir);
	return tempDir;
}

function readRecordedJtis(dataDir: string): string[] {
	const db = new Database(path.join(dataDir, "jti", "hermes_mcp_side_effect_approval_jti.sqlite"), {
		readonly: true,
	});
	try {
		const rows = db
			.prepare("SELECT jti FROM used_hermes_mcp_side_effect_approval_tokens ORDER BY jti")
			.all() as Array<{ jti: string }>;
		return rows.map((row) => row.jti);
	} finally {
		db.close();
	}
}
