import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it, vi } from "vitest";
import { evaluateApprovalContinuationEvidence } from "../../src/hermes/approval-continuation.js";
import {
	runHermesApprovalContinuationProbe,
	writeApprovalContinuationArtifacts,
} from "../../src/hermes/approval-continuation-runner.js";

const cleanupDirs = new Set<string>();
const hermes = { version: "0.15.1" };

afterEach(() => {
	vi.doUnmock("../../src/hermes/mcp/approval-token.js");
	vi.resetModules();
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
		const recordedJtis = readRecordedJtis(tempDir);
		const recordedJtiCounts = readRecordedJtiCounts(tempDir);
		expect(observations).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ name: "wrong_actor_denied", status: "pass" }),
				expect.objectContaining({ name: "stale_request_denied", status: "pass" }),
				expect.objectContaining({ name: "replay_denied", status: "pass" }),
				expect.objectContaining({ name: "mutated_decision_denied", status: "pass" }),
			]),
		);
		expect(recordedJtis).toEqual(
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
		expect(recordedJtis).not.toContain("jti-stale");
		expect(recordedJtiCounts["jti-replay"]).toBe(1);
		expect(recordedJtiCounts["jti-mutated-decision"]).toBe(1);
		expect(recordedJtiCounts["jti-stale"]).toBeUndefined();
		expect(serialized).not.toContain("v1.");
		expect(serialized).not.toContain("approvalToken");
		expect(serialized).not.toContain("signature");
	});

	it("fails closed when replay verification stops rejecting a reused JTI", async () => {
		const tempDir = tempPath("approval-continuation-runner-");

		vi.resetModules();
		vi.doMock("../../src/hermes/mcp/approval-token.js", async (importOriginal) => {
			const actual =
				await importOriginal<typeof import("../../src/hermes/mcp/approval-token.js")>();
			return {
				...actual,
				createTelclaudeMcpSideEffectApprovalVerifier: (
					options: Parameters<typeof actual.createTelclaudeMcpSideEffectApprovalVerifier>[0],
				) => {
					const verify = actual.createTelclaudeMcpSideEffectApprovalVerifier(options);
					return async (...args: Parameters<typeof verify>) => {
						const result = await verify(...args);
						if (!result.ok && result.code === "approval_replayed") {
							return { ok: true, approvalId: "broken-replay-accepted" };
						}
						return result;
					};
				},
			};
		});

		const { runHermesApprovalContinuationProbe: runWithBrokenVerifier } = await import(
			"../../src/hermes/approval-continuation-runner.js"
		);
		const run = await runWithBrokenVerifier({
			allowRun: true,
			hermes,
			jtiDataDir: tempDir,
		});
		const observations = run.fixtures.flatMap((fixture) => fixture.observations);
		const replayObservation = observations.find(
			(observation) => observation.name === "replay_denied",
		);
		const report = evaluateApprovalContinuationEvidence(run.evidence);

		expect(run.status).toBe("fail");
		expect(run.evidence?.native).toMatchObject({
			wrong_actor_denied: true,
			stale_request_denied: true,
			replay_denied: false,
			mutated_decision_denied: true,
		});
		expect(run.evidence?.fallback?.fixtures.map((fixture) => fixture.status)).toEqual([
			"pass",
			"pass",
			"pass",
			"pass",
		]);
		expect(replayObservation).toMatchObject({ name: "replay_denied", status: "fail" });
		expect(replayObservation?.detail).toContain("expected approval_replayed");
		expect(replayObservation?.detail).toContain("broken-replay-accepted");
		expect(report).toMatchObject({
			status: "fail",
			mode: "blocked",
			productionEnable: false,
		});
		expect(
			report.gates.find((gate) => gate.name === "approvalContinuation.replayDefenses")?.detail,
		).toContain("approval replay denial is unproven");
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

function readRecordedJtiCounts(dataDir: string): Record<string, number> {
	const db = new Database(path.join(dataDir, "jti", "hermes_mcp_side_effect_approval_jti.sqlite"), {
		readonly: true,
	});
	try {
		const rows = db
			.prepare(
				"SELECT jti, COUNT(*) as count FROM used_hermes_mcp_side_effect_approval_tokens GROUP BY jti",
			)
			.all() as Array<{ jti: string; count: number }>;
		return Object.fromEntries(rows.map((row) => [row.jti, row.count]));
	} finally {
		db.close();
	}
}
