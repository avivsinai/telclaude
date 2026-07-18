import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	collectFeatureProbeEvidence,
	hermesAdapterSignatureFilesForSurface,
} from "../../src/hermes/foundation.js";
import {
	HOUSEHOLD_MEDIA_PROBE_REQUIRED_CHECKS,
	householdMediaProbeEvidenceFailure,
	runHouseholdMediaProbe,
} from "../../src/hermes/household-media-probe.js";
import { generateKeyPair } from "../../src/internal-auth.js";

const ORIGINAL_PRIVATE_KEY = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
const ORIGINAL_PUBLIC_KEY = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;

const EXPECTED_REQUIRED_CHECKS = [
	"media.parents-isolated",
	"media.quarantine-bounded",
	"media.voice-confidence-weighted",
	"media.document-static-bounded",
	"media.action-classified",
	"media.confirmation-bound-once",
	"media.execution-fresh-turn-bound",
	"media.outbound-named-pdf-bound",
	"media.denials-fail-closed",
	"media.artifact-sanitized",
] as const;

describe("household media Hermes probe", () => {
	beforeEach(() => {
		const keys = generateKeyPair();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = keys.privateKey;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = keys.publicKey;
	});

	afterEach(() => {
		restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY", ORIGINAL_PRIVATE_KEY);
		restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", ORIGINAL_PUBLIC_KEY);
	});

	it("pins the ten-property catalog independently of the evaluator", () => {
		expect(HOUSEHOLD_MEDIA_PROBE_REQUIRED_CHECKS).toEqual(EXPECTED_REQUIRED_CHECKS);
	});

	it("emits signed sanitized evidence for the two-parent golden acceptance", async () => {
		const evidence = await runHouseholdMediaProbe({
			allowRun: true,
			observedAt: "2026-07-18T12:00:00.000Z",
		});

		expect(evidence).toMatchObject({
			probeId: "household.media",
			status: "pass",
			ran: true,
			observations: {
				parentCount: 2,
				voiceDerivationCount: 1,
				documentDerivationCount: 1,
				confirmedActionCount: 2,
				executedActionCount: 2,
				namedPdfDeliveryCount: 2,
				deletionReceiptCount: 3,
				artifactSanitized: true,
			},
			runnerAttestation: expect.objectContaining({
				evidenceSha256: expect.stringMatching(/^sha256:/),
			}),
		});
		expect(householdMediaProbeEvidenceFailure(evidence, { allowStaleAttestations: true })).toBe(
			null,
		);
		expect(JSON.stringify(evidence)).not.toMatch(
			/OpusHead|raw-parent|private\/tmp|quarantineId|providerId|EXIF|filename|bytes|actorId|subjectUserId|conversationId/i,
		);
	});

	it.each([
		["parentsIsolated", false, "media.parents-isolated"],
		["quarantineBounded", false, "media.quarantine-bounded"],
		["voiceConfidenceWeighted", false, "media.voice-confidence-weighted"],
		["documentStaticBounded", false, "media.document-static-bounded"],
		["actionClassified", false, "media.action-classified"],
		["confirmationBoundOnce", false, "media.confirmation-bound-once"],
		["freshTurnExecutionBound", false, "media.execution-fresh-turn-bound"],
		["namedPdfBound", false, "media.outbound-named-pdf-bound"],
		["denialsFailClosed", false, "media.denials-fail-closed"],
		["artifactSanitized", false, "media.artifact-sanitized"],
	] as const)("rejects pass-looking evidence when %s drifts", async (field, value, check) => {
		const evidence = await runHouseholdMediaProbe({
			allowRun: true,
			observedAt: "2026-07-18T12:00:00.000Z",
		});
		const mutated = {
			...evidence,
			observations: { ...evidence.observations, [field]: value },
		};

		expect(householdMediaProbeEvidenceFailure(mutated, { allowStaleAttestations: true })).toContain(
			check,
		);
	});

	it("fails closed without explicit run authority", async () => {
		const evidence = await runHouseholdMediaProbe({
			allowRun: false,
			observedAt: "2026-07-18T12:00:00.000Z",
		});
		expect(evidence).toMatchObject({ status: "fail", ran: false });
		expect(
			householdMediaProbeEvidenceFailure(evidence, { allowStaleAttestations: true }),
		).toContain("harness did not run");
	});

	it("registers signed evidence and the complete M3 signature surface", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "household-media-matrix-"));
		const evidencePath = path.join(tempDir, "household-media.json");
		const evidence = await runHouseholdMediaProbe({
			allowRun: true,
			observedAt: "2026-07-18T12:00:00.000Z",
		});
		fs.writeFileSync(evidencePath, `${JSON.stringify(evidence)}\n`);

		const bundle = collectFeatureProbeEvidence(
			{
				schemaVersion: 1,
				probes: [
					{
						surface_id: "household.media",
						hermes_pin: { version: "0.15.1" },
						documented_seam: "household media acceptance",
						probe_command: "telclaude hermes probe household.media --allow-run",
						expected_result: "signed acceptance passes",
						negative_probe: "unsafe media paths fail closed",
						evidence_path: evidencePath,
						lockfile_key: "featureProbes.household.media",
						security_scope: "household-media",
						approval_equivalent: true,
						failure_outcome: "disable",
						status: "pass",
					},
				],
			},
			{ allowStaleAttestations: true },
		);

		expect(bundle?.results).toEqual([
			expect.objectContaining({ surface_id: "household.media", status: "pass" }),
		]);
		expect(hermesAdapterSignatureFilesForSurface("household.media")).toEqual(
			expect.arrayContaining([
				"src/relay/attachment-quarantine-store.ts",
				"src/relay/inbound-media-processor.ts",
				"src/relay/media-action-confirmation-store.ts",
				"src/relay/outbound-delivery-dispatcher.ts",
				"src/relay/whatsapp-edge-channel-connector.ts",
				"src/whatsapp-bridge/contract.ts",
				"src/hermes/household-media-probe.ts",
			]),
		);
		fs.rmSync(tempDir, { recursive: true, force: true });
	});
});

function restoreEnv(key: string, value: string | undefined): void {
	if (value === undefined) delete process.env[key];
	else process.env[key] = value;
}
