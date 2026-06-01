import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
	buildHermesWorkflowFixtureEvidenceBundle,
	HERMES_WORKFLOW_SURFACE_IDS,
	type HermesWorkflowSurfaceId,
	runHermesWorkflowProbe,
	workflowFixtureEvidenceFailure,
	workflowProbeEvidenceFailure,
} from "../../src/hermes/workflow-probes.js";

describe("Hermes workflow probes", () => {
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
		expect(evidence.observations).not.toEqual({});
		expect(workflowProbeEvidenceFailure(surfaceId, evidence)).toBeNull();
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

	it("builds fixture evidence bound to workflow probe artifacts", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "workflow-fixtures-"));
		const probePaths = writeWorkflowProbeArtifacts(tempDir);
		const bundle = buildHermesWorkflowFixtureEvidenceBundle({
			evidenceDir: path.join(tempDir, "fixtures"),
			probePaths,
			observedAt: "2026-06-01T09:10:00.000Z",
		});

		expect(bundle.results).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ id: "fixture.cron.background.delivery", status: "pass" }),
				expect.objectContaining({ id: "fixture.cron.duplicate-deny", status: "pass" }),
				expect.objectContaining({ id: "fixture.longrun.approval-resume", status: "pass" }),
				expect.objectContaining({ id: "fixture.longrun.stale-resume-deny", status: "pass" }),
			]),
		);
		const approvalResumeEvidence = bundle.evidence.find(
			(evidence) => evidence.id === "fixture.longrun.approval-resume",
		);
		expect(
			workflowFixtureEvidenceFailure("fixture.longrun.approval-resume", approvalResumeEvidence),
		).toBeNull();
	});

	it("rejects workflow fixture evidence when the bound probe artifact changes", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "workflow-fixtures-"));
		const probePaths = writeWorkflowProbeArtifacts(tempDir);
		const bundle = buildHermesWorkflowFixtureEvidenceBundle({
			evidenceDir: path.join(tempDir, "fixtures"),
			probePaths,
			observedAt: "2026-06-01T09:10:00.000Z",
		});
		const cronEvidence = bundle.evidence.find(
			(evidence) => evidence.id === "fixture.cron.background.delivery",
		);

		fs.writeFileSync(probePaths["workflow.cron"], JSON.stringify({ changed: true }), "utf8");

		expect(
			workflowFixtureEvidenceFailure("fixture.cron.background.delivery", cronEvidence),
		).toContain("probeSha256 does not match");
	});
});

function writeWorkflowProbeArtifacts(tempDir: string): Record<HermesWorkflowSurfaceId, string> {
	const probePaths = {
		"workflow.cron": path.join(tempDir, "workflow-cron.json"),
		"workflow.longrun": path.join(tempDir, "workflow-longrun.json"),
	} satisfies Record<HermesWorkflowSurfaceId, string>;
	for (const surfaceId of HERMES_WORKFLOW_SURFACE_IDS) {
		const evidence = runHermesWorkflowProbe({
			surfaceId,
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});
		fs.writeFileSync(probePaths[surfaceId], JSON.stringify(evidence, null, 2), "utf8");
	}
	return probePaths;
}
