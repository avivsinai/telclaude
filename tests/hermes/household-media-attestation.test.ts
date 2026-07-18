import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	householdMediaAttestationFieldsForEvidence,
	householdMediaAttestationSignatureFailure,
	signHouseholdMediaAttestation,
} from "../../src/hermes/household-media-attestation.js";
import { generateKeyPair } from "../../src/internal-auth.js";

const ORIGINAL_PRIVATE_KEY = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
const ORIGINAL_PUBLIC_KEY = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;

describe("household media probe attestation", () => {
	beforeEach(() => {
		const keys = generateKeyPair();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = keys.privateKey;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = keys.publicKey;
	});

	afterEach(() => {
		restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY", ORIGINAL_PRIVATE_KEY);
		restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", ORIGINAL_PUBLIC_KEY);
	});

	it("binds status, freshness timestamp, checks, observations, and the full evidence digest", () => {
		const evidence = fixtureEvidence();
		const attestation = signHouseholdMediaAttestation(evidence);

		expect(attestation).toEqual({
			...householdMediaAttestationFieldsForEvidence(evidence),
			signature: expect.objectContaining({
				version: "v1",
				scope: "operator",
				path: "/v1/hermes.household-media.attestation",
			}),
		});
		expect(householdMediaAttestationSignatureFailure(attestation, { allowStale: true })).toBeNull();
	});

	it("fails closed when any digest-bound field drifts", () => {
		const evidence = fixtureEvidence();
		const attestation = signHouseholdMediaAttestation(evidence);

		expect(
			householdMediaAttestationSignatureFailure(
				{ ...attestation, observationsSha256: `sha256:${"0".repeat(64)}` },
				{ allowStale: true },
			),
		).not.toBeNull();
	});
});

function fixtureEvidence() {
	return {
		schemaVersion: "telclaude.hermes.household-media-probe.v1" as const,
		probeId: "household.media" as const,
		status: "pass" as const,
		ran: true,
		observedAt: "2026-07-18T12:00:00.000Z",
		source: "telclaude-household-media-acceptance-harness",
		checks: [{ name: "media.parents-isolated", status: "pass", detail: "passed" }],
		observations: { parentCount: 2, artifactSanitized: true },
	};
}

function restoreEnv(key: string, value: string | undefined): void {
	if (value === undefined) delete process.env[key];
	else process.env[key] = value;
}
