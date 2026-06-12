import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	googleProviderProbeEvidenceFailure,
	runTelclaudeGoogleProviderProbe,
} from "../../src/hermes/provider-google-probe.js";
import { generateKeyPair } from "../../src/internal-auth.js";

let restoreOperatorRelayKeys: (() => void) | undefined;

describe("Hermes Google provider probe", () => {
	beforeEach(() => {
		restoreOperatorRelayKeys = installOperatorRelayKeys();
	});

	afterEach(() => {
		restoreOperatorRelayKeys?.();
		restoreOperatorRelayKeys = undefined;
	});

	it("passes only after exercising Google read, prepare, approved execute, actor, replay, and credential checks", async () => {
		const evidence = await runTelclaudeGoogleProviderProbe({
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(evidence.status).toBe("pass");
		expect(evidence.observations.providerProxyCallCount).toBe(2);
		expect(evidence.observations.approvalVerifierCallCount).toBeGreaterThanOrEqual(1);
		expect(evidence.observations.sidecarVerifierCallCount).toBeGreaterThanOrEqual(2);
		expect(evidence.observations.sidecarReplayCode).toBe("approval_replayed");
		expect(evidence.observations.ledgerReplayCode).toBe("effect_already_executed");
		expect(evidence.observations.rawOAuthObserved).toBe(false);
		expect(googleProviderProbeEvidenceFailure(evidence)).toBeNull();
	});

	it("rejects evidence missing wrong-actor denial", async () => {
		const evidence = await runTelclaudeGoogleProviderProbe({
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(
			googleProviderProbeEvidenceFailure({
				...evidence,
				checks: evidence.checks.filter((check) => check.name !== "google.wrong-actor-denied"),
			}),
		).toContain("check google.wrong-actor-denied is missing");
	});

	it("rejects pass-looking evidence without the Google provider proxy calls", async () => {
		const evidence = await runTelclaudeGoogleProviderProbe({
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(
			googleProviderProbeEvidenceFailure({
				...evidence,
				observations: {
					...evidence.observations,
					providerProxyCallCount: 1,
				},
			}),
		).toContain("providerProxyCallCount is 1");
	});

	it("rejects evidence produced without --allow-run", async () => {
		const evidence = await runTelclaudeGoogleProviderProbe({
			allowRun: false,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(evidence.status).toBe("fail");
		expect(googleProviderProbeEvidenceFailure(evidence)).toContain("harness did not run");
	});

});

function installOperatorRelayKeys(): () => void {
	const originalPrivateKey = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
	const originalPublicKey = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
	const relayKeys = generateKeyPair();
	process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
	process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;
	return () => {
		if (originalPrivateKey === undefined) {
			delete process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
		} else {
			process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = originalPrivateKey;
		}
		if (originalPublicKey === undefined) {
			delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		} else {
			process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = originalPublicKey;
		}
	};
}
