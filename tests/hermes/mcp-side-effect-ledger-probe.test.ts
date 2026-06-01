import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	runTelclaudeMcpSideEffectLedgerProbe,
	sideEffectLedgerProbeEvidenceFailure,
} from "../../src/hermes/mcp/side-effect-ledger-probe.js";
import { generateKeyPair } from "../../src/internal-auth.js";

const ORIGINAL_ENV = {
	OPERATOR_RPC_RELAY_PRIVATE_KEY: process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY,
	OPERATOR_RPC_RELAY_PUBLIC_KEY: process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY,
};

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
		expect(sideEffectLedgerProbeEvidenceFailure("sideeffect.ledger", evidence)).toBeNull();
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
