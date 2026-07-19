import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	HOUSEHOLD_CLALIT_PROBE_REQUIRED_CHECKS,
	HOUSEHOLD_REPLY_PROBE_REQUIRED_CHECKS,
	PROVIDER_CHALLENGE_PROBE_REQUIRED_CHECKS,
	runTelclaudeMcpSideEffectLedgerProbe,
	sideEffectLedgerProbeEvidenceFailure,
} from "../../src/hermes/mcp/side-effect-ledger-probe.js";
import { generateKeyPair } from "../../src/internal-auth.js";

const ORIGINAL_ENV = {
	OPERATOR_RPC_RELAY_PRIVATE_KEY: process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY,
	OPERATOR_RPC_RELAY_PUBLIC_KEY: process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY,
};

const EXPECTED_HOUSEHOLD_REPLY_CHECKS = [
	"ledger.household.binding-evidence-hash-bound",
	"ledger.household.same-subject-delivery",
	"ledger.household.parent-isolation-denied",
	"ledger.household.binding-revocation-denied",
	"ledger.household.step-up-escalation-denied",
	"ledger.household.artifact-redacted",
] as const;

const EXPECTED_PROVIDER_CHALLENGE_CHECKS = [
	"challenge.turn.abort-and-block",
	"challenge.audio.stays-armed",
	"challenge.parent-isolation",
	"challenge.claim-one-shot",
	"challenge.artifact-redacted",
] as const;

const EXPECTED_HOUSEHOLD_CLALIT_CHECKS = [
	"clalit.household.action-allowlist-enforced",
	"clalit.household.two-parent-binding-isolated",
	"clalit.household.wrong-parent-denied",
	"clalit.household.renewal-approved-once",
	"clalit.household.changed-params-denied",
	"clalit.household.expired-denied",
	"clalit.household.self-approval-denied",
	"clalit.household.artifact-redacted",
] as const;

describe("Telclaude MCP side-effect ledger probe", () => {
	beforeEach(() => {
		const relayKeys = generateKeyPair();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;
	});

	afterEach(() => {
		restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY");
		restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY");
	});

	it("pins the household reply property catalog independently of the evaluator", () => {
		expect(HOUSEHOLD_REPLY_PROBE_REQUIRED_CHECKS).toEqual(EXPECTED_HOUSEHOLD_REPLY_CHECKS);
	});

	it("pins the provider challenge property catalog independently of the evaluator", () => {
		expect(PROVIDER_CHALLENGE_PROBE_REQUIRED_CHECKS).toEqual(EXPECTED_PROVIDER_CHALLENGE_CHECKS);
	});

	it("pins the household Clalit matrix independently of the evaluator", () => {
		expect(HOUSEHOLD_CLALIT_PROBE_REQUIRED_CHECKS).toEqual(EXPECTED_HOUSEHOLD_CLALIT_CHECKS);
	});

	it("passes only after exercising prepare, execute, proxy, and denial paths", async () => {
		const evidence = await runTelclaudeMcpSideEffectLedgerProbe({
			allowRun: true,
			observedAt: "2026-05-31T09:00:00.000Z",
		});

		expect(evidence.status).toBe("pass");
		expect(evidence.runnerAttestation).toMatchObject({
			source: "telclaude-mcp-sideeffect-ledger-probe-runner",
			runner: "telclaude-mcp-sideeffect-ledger-probe",
			probeId: "sideeffect.ledger",
			status: "pass",
			ran: true,
			signature: expect.objectContaining({
				version: "v1",
				scope: "operator",
				path: "/v1/hermes.sideeffect-ledger.attestation",
			}),
		});
		expect(evidence.observations.verifierCallCount).toBeGreaterThanOrEqual(3);
		expect(evidence.observations.providerProxyCallCount).toBe(1);
		expect(evidence.observations.outboundDeliveryCallCount).toBe(1);
		expect(evidence.observations.outboundEdgePreparedRef).toBe("edge-outbound-ledger-probe");
		expect(evidence.observations.outboundDeliveryOutboundRef).toBe(
			evidence.observations.outboundEdgePreparedRef,
		);
		expect(evidence.observations.outboundDeliveryIdempotencyKey).toBe("idem-outbound-ledger-probe");
		expect(evidence.observations.householdDeliveryCallCount).toBe(1);
		expect(evidence.observations.householdBindingResolverCallCount).toBe(3);
		expect(evidence.observations.householdParentAContentHash).not.toBe(
			evidence.observations.householdParentBContentHash,
		);
		expect(evidence.observations.challengeResponderCallCount).toBe(1);
		expect(evidence.observations.challengeControlSendCount).toBe(4);
		expect(evidence.observations.householdClalitWriteCallCount).toBe(1);
		expect(evidence.observations.householdClalitParentAContentHash).not.toBe(
			evidence.observations.householdClalitParentBContentHash,
		);
		expect(evidence.checks.filter((check) => check.name.startsWith("challenge."))).toEqual(
			EXPECTED_PROVIDER_CHALLENGE_CHECKS.map((name) =>
				expect.objectContaining({ name, status: "pass" }),
			),
		);
		expect(evidence.checks.filter((check) => check.name.startsWith("ledger.household."))).toEqual(
			EXPECTED_HOUSEHOLD_REPLY_CHECKS.map((name) =>
				expect.objectContaining({ name, status: "pass" }),
			),
		);
		expect(evidence.checks.filter((check) => check.name.startsWith("clalit.household."))).toEqual(
			EXPECTED_HOUSEHOLD_CLALIT_CHECKS.map((name) =>
				expect.objectContaining({ name, status: "pass" }),
			),
		);
		expect(sideEffectLedgerProbeEvidenceFailure("sideeffect.ledger", evidence)).toBeNull();
	});

	it("isolates durable state across consecutive full probe runs", async () => {
		const first = await runTelclaudeMcpSideEffectLedgerProbe({
			allowRun: true,
			observedAt: "2026-05-31T09:00:00.000Z",
		});
		const second = await runTelclaudeMcpSideEffectLedgerProbe({
			allowRun: true,
			observedAt: "2026-05-31T09:00:01.000Z",
		});

		expect([first.status, second.status]).toEqual(["pass", "pass"]);
	});

	it("rejects evidence missing a required denial control", async () => {
		const evidence = await runTelclaudeMcpSideEffectLedgerProbe({
			allowRun: true,
			observedAt: "2026-05-31T09:00:00.000Z",
		});
		const withoutReplayDenial = {
			...evidence,
			checks: evidence.checks.filter((check) => check.name !== "ledger.replay-denied"),
		};

		expect(
			sideEffectLedgerProbeEvidenceFailure("sideeffect.ledger", withoutReplayDenial),
		).toContain("runnerAttestation checksSha256 mismatch");
	});

	it("rejects pass-looking evidence that did not verify enough approval paths", async () => {
		const evidence = await runTelclaudeMcpSideEffectLedgerProbe({
			allowRun: true,
			observedAt: "2026-05-31T09:00:00.000Z",
		});

		expect(
			sideEffectLedgerProbeEvidenceFailure("sideeffect.ledger", {
				...evidence,
				observations: {
					...evidence.observations,
					verifierCallCount: 1,
				},
			}),
		).toContain("runnerAttestation observationsSha256 mismatch");
	});

	it("rejects pass-looking evidence that did not observe outbound delivery dispatch", async () => {
		const evidence = await runTelclaudeMcpSideEffectLedgerProbe({
			allowRun: true,
			observedAt: "2026-05-31T09:00:00.000Z",
		});

		expect(
			sideEffectLedgerProbeEvidenceFailure("sideeffect.ledger", {
				...evidence,
				observations: {
					...evidence.observations,
					outboundDeliveryCallCount: 0,
					outboundDeliveryOutboundRef: "wrong-outbound-ref",
				},
			}),
		).toContain("runnerAttestation observationsSha256 mismatch");
		expect(
			sideEffectLedgerProbeEvidenceFailure("sideeffect.ledger", {
				...evidence,
				runnerAttestation: undefined,
				observations: {
					...evidence.observations,
					outboundDeliveryCallCount: 0,
					outboundDeliveryOutboundRef: "wrong-outbound-ref",
				},
			}),
		).toContain("outboundDeliveryCallCount is 0");
	});

	it("rejects pass-looking evidence without a signed runner attestation", async () => {
		const evidence = await runTelclaudeMcpSideEffectLedgerProbe({
			allowRun: true,
			observedAt: "2026-05-31T09:00:00.000Z",
		});
		const { runnerAttestation: _attestation, ...unsignedEvidence } = evidence;

		expect(sideEffectLedgerProbeEvidenceFailure("sideeffect.ledger", unsignedEvidence)).toContain(
			"runnerAttestation is missing",
		);
	});

	it("rejects runner attestations signed by an untrusted relay key", async () => {
		const trustedPublicKey = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		const attackerKeys = generateKeyPair();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = attackerKeys.privateKey;
		const forgedEvidence = await runTelclaudeMcpSideEffectLedgerProbe({
			allowRun: true,
			observedAt: "2026-05-31T09:00:00.000Z",
		});
		if (trustedPublicKey) process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = trustedPublicKey;

		expect(sideEffectLedgerProbeEvidenceFailure("sideeffect.ledger", forgedEvidence)).toContain(
			"runnerAttestation signature is invalid: signature verification failed",
		);
	});

	it("rejects evidence produced without --allow-run", async () => {
		const evidence = await runTelclaudeMcpSideEffectLedgerProbe({
			allowRun: false,
			observedAt: "2026-05-31T09:00:00.000Z",
		});

		expect(evidence.status).toBe("fail");
		expect(sideEffectLedgerProbeEvidenceFailure("sideeffect.ledger", evidence)).toContain(
			"harness did not run",
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
