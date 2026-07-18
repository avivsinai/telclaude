import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { generateKeyPair } from "../../src/internal-auth.js";
import {
	householdReminderAttestationFieldsForEvidence,
	householdReminderAttestationSignatureFailure,
	signHouseholdReminderAttestation,
} from "../../src/hermes/household-reminder-attestation.js";

const ORIGINAL_PRIVATE_KEY = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
const ORIGINAL_PUBLIC_KEY = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;

describe("household reminder runner attestation", () => {
	beforeAll(() => {
		const keys = generateKeyPair();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = keys.privateKey;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = keys.publicKey;
	});

	afterAll(() => {
		restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY", ORIGINAL_PRIVATE_KEY);
		restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", ORIGINAL_PUBLIC_KEY);
	});

	it("binds the checks and sanitized observations to the operator relay key", () => {
		const evidence = evidenceFixture();
		const attestation = signHouseholdReminderAttestation(evidence);

		expect(householdReminderAttestationSignatureFailure(attestation, { allowStale: true })).toBe(
			null,
		);
		expect(attestation).toMatchObject(householdReminderAttestationFieldsForEvidence(evidence));
	});

	it("rejects a post-signature field mutation", () => {
		const attestation = signHouseholdReminderAttestation(evidenceFixture());

		expect(
			householdReminderAttestationSignatureFailure(
				{ ...attestation, observationsSha256: `sha256:${"f".repeat(64)}` },
				{ allowStale: true },
			),
		).toMatch(/digest mismatch|signature verification failed/);
	});
});

function evidenceFixture() {
	return {
		schemaVersion: "telclaude.hermes.household-reminder-probe.v1",
		probeId: "household.reminders",
		status: "pass",
		ran: true,
		observedAt: "2026-07-18T09:00:00.000Z",
		source: "telclaude-household-reminder-acceptance-harness",
		checks: [{ name: "household-reminder.fixture", status: "pass", detail: "fixture passed" }],
		observations: { whatsappSendCount: 1 },
	} as const;
}

function restoreEnv(key: string, value: string | undefined): void {
	if (value === undefined) delete process.env[key];
	else process.env[key] = value;
}
