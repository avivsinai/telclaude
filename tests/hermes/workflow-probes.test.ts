import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	collectFeatureProbeEvidence,
	type FeatureProbeMatrix,
} from "../../src/hermes/foundation.js";
import {
	HERMES_WORKFLOW_SURFACE_IDS,
	type HermesWorkflowSurfaceId,
	runHermesWorkflowProbe,
	workflowProbeEvidenceFailure,
} from "../../src/hermes/workflow-probes.js";
import { generateKeyPair } from "../../src/internal-auth.js";

const ORIGINAL_ENV = {
	OPERATOR_RPC_RELAY_PRIVATE_KEY: process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY,
	OPERATOR_RPC_RELAY_PUBLIC_KEY: process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY,
};

describe("Hermes workflow probes", () => {
	beforeEach(() => {
		const relayKeys = generateKeyPair();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;
	});

	afterEach(() => {
		vi.useRealTimers();
		restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY");
		restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY");
	});

	it.each(
		HERMES_WORKFLOW_SURFACE_IDS,
	)("passes %s only after workflow ledger controls are observed", (surfaceId: HermesWorkflowSurfaceId) => {
		const evidence = runHermesWorkflowProbe({
			surfaceId,
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(evidence.status).toBe("pass");
		expect(evidence.ran).toBe(true);
		expect(evidence.runnerAttestation).toMatchObject({
			source: "telclaude-workflow-run-ledger-probe-runner",
			runner: "telclaude-workflow-run-ledger-probe",
			probeId: surfaceId,
			status: "pass",
			ran: true,
			evidenceSource: "telclaude-workflow-run-ledger-harness",
			signature: expect.objectContaining({
				version: "v1",
				scope: "operator",
				path: "/v1/hermes.workflow-run-ledger.attestation",
			}),
		});
		expect(evidence.observations).not.toEqual({});
		expect(workflowProbeEvidenceFailure(surfaceId, evidence)).toBeNull();
	});

	it("rejects stale signed workflow attestations in live mode only", () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-06-01T09:00:00.000Z"));
		const evidence = runHermesWorkflowProbe({
			surfaceId: "workflow.cron",
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		vi.setSystemTime(new Date("2026-06-10T09:00:00.000Z"));

		expect(workflowProbeEvidenceFailure("workflow.cron", evidence)).toBeNull();
		expect(
			workflowProbeEvidenceFailure("workflow.cron", evidence, {
				allowStaleAttestations: false,
				now: new Date("2026-06-10T09:00:00.000Z"),
			}),
		).toContain("runnerAttestation observedAt is stale or future-dated");
	});

	it("threads live freshness through collected workflow feature-probe evidence", () => {
		vi.useFakeTimers();
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-workflow-live-"));
		const evidencePath = path.join(tempDir, "workflow-cron.json");
		vi.setSystemTime(new Date("2026-06-01T09:00:00.000Z"));
		const evidence = runHermesWorkflowProbe({
			surfaceId: "workflow.cron",
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});
		fs.writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));
		const matrix: FeatureProbeMatrix = {
			schemaVersion: 1,
			probes: [
				{
					surface_id: "workflow.cron",
					hermes_pin: { version: "0.15.1" },
					documented_seam: "Hermes workflow ledger",
					probe_command: "pnpm dev hermes workflow-probes --surface workflow.cron",
					expected_result: "workflow ledger runner proof passes",
					negative_probe: "stale workflow runner proof fails live cutover",
					evidence_path: evidencePath,
					lockfile_key: "featureProbes.workflow.cron",
					security_scope: "workflow-ledger",
					approval_equivalent: true,
					failure_outcome: "disable",
					status: "pass",
				},
			],
		};

		vi.setSystemTime(new Date("2026-06-10T09:00:00.000Z"));

		expect(collectFeatureProbeEvidence(matrix)?.results[0]).toMatchObject({
			surface_id: "workflow.cron",
			status: "pass",
		});
		const live = collectFeatureProbeEvidence(matrix, {
			allowStaleAttestations: false,
			now: new Date("2026-06-10T09:00:00.000Z"),
		});
		expect(live?.results[0]).toMatchObject({
			surface_id: "workflow.cron",
			status: "fail",
		});
		expect(live?.results[0]?.detail).toContain(
			"runnerAttestation observedAt is stale or future-dated",
		);
	});

	it("proves cron background delivery, authority binding, and duplicate denial", () => {
		const evidence = runHermesWorkflowProbe({
			surfaceId: "workflow.cron",
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(evidence.observations.startRecordHash).toMatch(/^sha256:/);
		expect(evidence.observations.completedRecordHash).toMatch(/^sha256:/);
		expect(evidence.observations.duplicateRecordHash).toMatch(/^sha256:/);
		expect(evidence.checks).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					name: "workflow.cron.server-derived-authority",
					status: "pass",
				}),
				expect.objectContaining({
					name: "workflow.cron.background-delivery-completed",
					status: "pass",
				}),
				expect.objectContaining({
					name: "workflow.cron.duplicate-delivery-deduped",
					status: "pass",
				}),
			]),
		);
	});

	it("proves longrun approval resume, stale denial, retry, and terminal cancellation", () => {
		const evidence = runHermesWorkflowProbe({
			surfaceId: "workflow.longrun",
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(evidence.observations.approvalWaitRecordHash).toMatch(/^sha256:/);
		expect(evidence.observations.resumedRecordHash).toMatch(/^sha256:/);
		expect(evidence.observations.staleFailureHash).toMatch(/^sha256:/);
		expect(evidence.observations.retryRecordHash).toMatch(/^sha256:/);
		expect(evidence.observations.cancelledRecordHash).toMatch(/^sha256:/);
		expect(evidence.observations.terminalDenialCode).toBe("run_terminal");
		expect(evidence.checks).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					name: "workflow.longrun.approval-resume-resolved",
					status: "pass",
				}),
				expect.objectContaining({
					name: "workflow.longrun.stale-resume-denied",
					status: "pass",
				}),
				expect.objectContaining({
					name: "workflow.longrun.retry-backoff-recorded",
					status: "pass",
				}),
				expect.objectContaining({
					name: "workflow.longrun.cancellation-terminal",
					status: "pass",
				}),
			]),
		);
	});

	it("rejects evidence produced without --allow-run", () => {
		const evidence = runHermesWorkflowProbe({
			surfaceId: "workflow.longrun",
			allowRun: false,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(evidence.status).toBe("fail");
		expect(workflowProbeEvidenceFailure("workflow.longrun", evidence)).toContain(
			"harness did not run",
		);
	});

	it("rejects pass-looking workflow evidence without a signed runner attestation", () => {
		const evidence = runHermesWorkflowProbe({
			surfaceId: "workflow.longrun",
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});
		const { runnerAttestation: _attestation, ...unsignedEvidence } = evidence;

		expect(workflowProbeEvidenceFailure("workflow.longrun", unsignedEvidence)).toContain(
			"runnerAttestation is missing",
		);
	});

	it("rejects mutated workflow observations after signing", () => {
		const evidence = runHermesWorkflowProbe({
			surfaceId: "workflow.longrun",
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(
			workflowProbeEvidenceFailure("workflow.longrun", {
				...evidence,
				observations: {
					...evidence.observations,
					terminalDenialCode: "run_not_found",
				},
			}),
		).toContain("runnerAttestation observationsSha256 mismatch");
	});

	it("rejects workflow attestations signed by an untrusted relay key", () => {
		const trustedPublicKey = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		const attackerKeys = generateKeyPair();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = attackerKeys.privateKey;
		const forgedEvidence = runHermesWorkflowProbe({
			surfaceId: "workflow.cron",
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});
		if (trustedPublicKey) process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = trustedPublicKey;

		expect(workflowProbeEvidenceFailure("workflow.cron", forgedEvidence)).toContain(
			"runnerAttestation signature is invalid: signature verification failed",
		);
	});

});

function restoreEnv(key: keyof typeof ORIGINAL_ENV): void {
	const value = ORIGINAL_ENV[key];
	if (value === undefined) {
		delete process.env[key];
	} else {
		process.env[key] = value;
	}
}
