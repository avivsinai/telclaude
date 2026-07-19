import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	collectFeatureProbeEvidence,
	hermesAdapterSignatureFilesForSurface,
} from "../../src/hermes/foundation.js";
import { signHouseholdReminderAttestation } from "../../src/hermes/household-reminder-attestation.js";
import {
	householdReminderProbeEvidenceFailure,
	runHouseholdReminderProbe,
} from "../../src/hermes/household-reminder-probe.js";
import { generateKeyPair } from "../../src/internal-auth.js";

const ORIGINAL_PRIVATE_KEY = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
const ORIGINAL_PUBLIC_KEY = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;

describe("household reminder Hermes probe", () => {
	beforeEach(() => {
		const keys = generateKeyPair();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = keys.privateKey;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = keys.publicKey;
	});

	afterEach(() => {
		restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY", ORIGINAL_PRIVATE_KEY);
		restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", ORIGINAL_PUBLIC_KEY);
	});

	it("emits signed sanitized evidence for the full Phase 0 acceptance matrix", async () => {
		const evidence = await runHouseholdReminderProbe({
			allowRun: true,
			observedAt: "2026-07-18T09:00:00.000Z",
		});

		expect(evidence).toMatchObject({
			probeId: "household.reminders",
			status: "pass",
			ran: true,
			observations: {
				parentCount: 2,
				deliveredCount: 1,
				whatsappSendCount: 1,
				telegramSendCount: 0,
				hermesSendCount: 0,
			},
			runnerAttestation: expect.objectContaining({
				evidenceSha256: expect.stringMatching(/^sha256:/),
			}),
		});
		expect(householdReminderProbeEvidenceFailure(evidence, { allowStaleAttestations: true })).toBe(
			null,
		);
		const serialized = JSON.stringify(evidence);
		expect(serialized).not.toMatch(
			/תזכורת|מסמכים|"(?:body|destination|recipient|address|actorId|subjectUserId)"\s*:/,
		);
	});

	it("fails closed on missing or mismatched runner evidence", async () => {
		const evidence = await runHouseholdReminderProbe({
			allowRun: true,
			observedAt: "2026-07-18T09:00:00.000Z",
		});
		const { runnerAttestation: _attestation, ...unsigned } = evidence;
		expect(
			householdReminderProbeEvidenceFailure(unsigned, { allowStaleAttestations: true }),
		).toContain("runnerAttestation is missing");
		expect(
			householdReminderProbeEvidenceFailure(
				{
					...evidence,
					observations: { ...evidence.observations, whatsappSendCount: 2 },
				},
				{ allowStaleAttestations: true },
			),
		).toContain("runnerAttestation observationsSha256 mismatch");
	});

	it("verifies the runner envelope before scanning only the evidence body", async () => {
		const { runnerAttestation: _attestation, ...body } = await runHouseholdReminderProbe({
			allowRun: true,
			observedAt: "2026-07-18T09:00:00.000Z",
		});
		const unsafeBody = { ...body, summary: "תזכורת leaked into evidence" };
		const unsignedFailure = householdReminderProbeEvidenceFailure(unsafeBody, {
			allowStaleAttestations: true,
		});

		expect(unsignedFailure).toMatch(/^runnerAttestation is missing;/);
		expect(unsignedFailure).toContain(
			"artifact contains non-sanitized reminder or routing content",
		);

		const signedFailure = householdReminderProbeEvidenceFailure(
			{
				...unsafeBody,
				runnerAttestation: signHouseholdReminderAttestation(unsafeBody),
			},
			{ allowStaleAttestations: true },
		);
		expect(signedFailure).toBe("artifact contains non-sanitized reminder or routing content");
	});

	it("does not self-report a pass without explicit run authority", async () => {
		const evidence = await runHouseholdReminderProbe({
			allowRun: false,
			observedAt: "2026-07-18T09:00:00.000Z",
		});

		expect(evidence).toMatchObject({ status: "fail", ran: false });
		expect(
			householdReminderProbeEvidenceFailure(evidence, { allowStaleAttestations: true }),
		).toContain("harness did not run");
	});

	it("registers signed evidence and the complete reminder adapter signature surface", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "household-reminder-matrix-"));
		const evidencePath = path.join(tempDir, "household-reminders.json");
		const evidence = await runHouseholdReminderProbe({
			allowRun: true,
			observedAt: "2026-07-18T09:00:00.000Z",
		});
		fs.writeFileSync(evidencePath, `${JSON.stringify(evidence)}\n`);

		const bundle = collectFeatureProbeEvidence(
			{
				schemaVersion: 1,
				probes: [
					{
						surface_id: "household.reminders",
						hermes_pin: { version: "0.15.1" },
						documented_seam: "household reminder acceptance",
						probe_command: "telclaude hermes probe household.reminders --allow-run",
						expected_result: "signed acceptance passes",
						negative_probe: "unsafe lifecycle paths fail closed",
						evidence_path: evidencePath,
						lockfile_key: "featureProbes.household.reminders",
						security_scope: "household-reminder",
						approval_equivalent: true,
						failure_outcome: "disable",
						status: "pass",
					},
				],
			},
			{ allowStaleAttestations: true },
		);

		expect(bundle?.results).toEqual([
			expect.objectContaining({ surface_id: "household.reminders", status: "pass" }),
		]);
		expect(hermesAdapterSignatureFilesForSurface("household.reminders")).toEqual(
			expect.arrayContaining([
				"src/household-reminders/store.ts",
				"src/household-reminders/fire-executor.ts",
				"src/relay/whatsapp-reminder-confirmation-interceptor.ts",
				"src/whatsapp-bridge/idempotency-journal.ts",
				"src/hermes/household-reminder-probe.ts",
			]),
		);
		fs.rmSync(tempDir, { recursive: true, force: true });
	});
});

function restoreEnv(key: string, value: string | undefined): void {
	if (value === undefined) delete process.env[key];
	else process.env[key] = value;
}
