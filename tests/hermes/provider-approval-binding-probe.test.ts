import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	providerApprovalBindingProbeEvidenceFailure,
	runTelclaudeProviderApprovalBindingProbe,
} from "../../src/hermes/provider-approval-binding-probe.js";
import { generateKeyPair } from "../../src/internal-auth.js";

const ORIGINAL_ENV = {
	OPERATOR_RPC_RELAY_PRIVATE_KEY: process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY,
	OPERATOR_RPC_RELAY_PUBLIC_KEY: process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY,
};

describe("Hermes provider approval-binding probe", () => {
	beforeEach(() => {
		const relayKeys = generateKeyPair();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;
	});

	afterEach(() => {
		restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY");
		restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY");
	});

	it("passes only after exercising provider approval, proxy, mismatch, and replay paths", async () => {
		const evidence = await runTelclaudeProviderApprovalBindingProbe({
			allowRun: true,
			observedAt: "2026-05-31T09:00:00.000Z",
		});

		expect(evidence.status).toBe("pass");
		expect(evidence.runnerAttestation).toMatchObject({
			source: "telclaude-provider-approval-binding-probe-runner",
			runner: "telclaude-provider-approval-binding-probe",
			probeId: "providers.approval-binding",
			status: "pass",
			ran: true,
			signature: expect.objectContaining({
				version: "v1",
				scope: "operator",
				path: "/v1/hermes.providers.approval-binding.attestation",
			}),
		});
		expect(evidence.observations.verifierCallCount).toBeGreaterThanOrEqual(5);
		expect(evidence.observations.providerProxyCallCount).toBe(1);
		expect(providerApprovalBindingProbeEvidenceFailure(evidence)).toBeNull();
	});

	it("rejects evidence missing the duplicate-JTI denial", async () => {
		const evidence = await runTelclaudeProviderApprovalBindingProbe({
			allowRun: true,
			observedAt: "2026-05-31T09:00:00.000Z",
		});

		expect(
			providerApprovalBindingProbeEvidenceFailure({
				...evidence,
				checks: evidence.checks.filter(
					(check) => check.name !== "provider.approval-binding.duplicate-jti-denied",
				),
			}),
		).toContain("runnerAttestation checksSha256 mismatch");
	});

	it("rejects pass-looking evidence without a provider proxy call", async () => {
		const evidence = await runTelclaudeProviderApprovalBindingProbe({
			allowRun: true,
			observedAt: "2026-05-31T09:00:00.000Z",
		});

		expect(
			providerApprovalBindingProbeEvidenceFailure({
				...evidence,
				observations: {
					...evidence.observations,
					providerProxyCallCount: 0,
				},
			}),
		).toContain("runnerAttestation observationsSha256 mismatch");
	});

	it("rejects pass-looking evidence without a signed runner attestation", async () => {
		const evidence = await runTelclaudeProviderApprovalBindingProbe({
			allowRun: true,
			observedAt: "2026-05-31T09:00:00.000Z",
		});
		const { runnerAttestation: _attestation, ...unsignedEvidence } = evidence;

		expect(providerApprovalBindingProbeEvidenceFailure(unsignedEvidence)).toContain(
			"runnerAttestation is missing",
		);
	});

	it("rejects runner attestations signed by an untrusted relay key", async () => {
		const trustedPublicKey = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		const attackerKeys = generateKeyPair();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = attackerKeys.privateKey;
		const forgedEvidence = await runTelclaudeProviderApprovalBindingProbe({
			allowRun: true,
			observedAt: "2026-05-31T09:00:00.000Z",
		});
		if (trustedPublicKey) process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = trustedPublicKey;

		expect(providerApprovalBindingProbeEvidenceFailure(forgedEvidence)).toContain(
			"runnerAttestation signature is invalid: signature verification failed",
		);
	});

	it("rejects evidence produced without --allow-run", async () => {
		const evidence = await runTelclaudeProviderApprovalBindingProbe({
			allowRun: false,
			observedAt: "2026-05-31T09:00:00.000Z",
		});

		expect(evidence.status).toBe("fail");
		expect(providerApprovalBindingProbeEvidenceFailure(evidence)).toContain("harness did not run");
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
