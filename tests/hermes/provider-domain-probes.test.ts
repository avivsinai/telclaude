import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	PROVIDER_DOMAIN_SURFACE_IDS,
	type ProviderDomainSurfaceId,
	providerDomainProbeEvidenceFailure,
	runTelclaudeProviderDomainProbe,
} from "../../src/hermes/provider-domain-probes.js";
import { generateKeyPair } from "../../src/internal-auth.js";

let restoreOperatorRelayKeys: (() => void) | undefined;

describe("Hermes provider-domain probes", () => {
	beforeEach(() => {
		restoreOperatorRelayKeys = installOperatorRelayKeys();
	});

	afterEach(() => {
		restoreOperatorRelayKeys?.();
		restoreOperatorRelayKeys = undefined;
	});

	it.each(
		PROVIDER_DOMAIN_SURFACE_IDS,
	)("passes %s only after read, prepare, approved execute, scope, replay, and credential checks", async (surfaceId: ProviderDomainSurfaceId) => {
		const evidence = await runTelclaudeProviderDomainProbe({
			surfaceId,
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(evidence.status).toBe("pass");
		expect(evidence.observations.providerProxyCallCount).toBe(2);
		expect(evidence.observations.approvalVerifierCallCount).toBeGreaterThanOrEqual(1);
		expect(evidence.observations.sidecarTokenIssuerCallCount).toBe(1);
		expect(evidence.observations.wrongActorCode).toBe("effect_authority_mismatch");
		expect(evidence.observations.wrongProviderScopeCode).toBe("effect_authority_mismatch");
		expect(evidence.observations.ledgerReplayCode).toBe("effect_already_executed");
		expect(evidence.observations.rawCredentialObserved).toBe(false);
		expect(evidence.checks).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					name: `${evidence.observations.providerId}.catalog-registered`,
					status: "pass",
				}),
			]),
		);
		expect(providerDomainProbeEvidenceFailure(surfaceId, evidence)).toBeNull();
	});

	it("proves Clalit emergency-language escalation denial", async () => {
		const evidence = await runTelclaudeProviderDomainProbe({
			surfaceId: "providers.clalit",
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(evidence.observations.emergencyEscalationCode).toContain(
			"urgent_health_escalation_required",
		);
		expect(evidence.checks).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					name: "clalit.emergency-escalation-denied",
					status: "pass",
				}),
			]),
		);
	});

	it("rejects evidence missing wrong-provider-scope denial", async () => {
		const evidence = await runTelclaudeProviderDomainProbe({
			surfaceId: "providers.bank",
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(
			providerDomainProbeEvidenceFailure("providers.bank", {
				...evidence,
				checks: evidence.checks.filter(
					(check) => check.name !== "bank.wrong-provider-scope-denied",
				),
			}),
		).toContain("check bank.wrong-provider-scope-denied is missing");
	});

	it("rejects provider-domain evidence missing catalog registration proof", async () => {
		const evidence = await runTelclaudeProviderDomainProbe({
			surfaceId: "providers.bank",
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(
			providerDomainProbeEvidenceFailure("providers.bank", {
				...evidence,
				checks: evidence.checks.filter((check) => check.name !== "bank.catalog-registered"),
			}),
		).toContain("check bank.catalog-registered is missing");
	});

	it("rejects pass-looking evidence with raw provider credential material", async () => {
		const evidence = await runTelclaudeProviderDomainProbe({
			surfaceId: "providers.government",
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(
			providerDomainProbeEvidenceFailure("providers.government", {
				...evidence,
				observations: {
					...evidence.observations,
					rawCredentialObserved: true,
				},
			}),
		).toContain("raw provider credential material was observed");
	});

	it("rejects evidence produced without --allow-run", async () => {
		const evidence = await runTelclaudeProviderDomainProbe({
			surfaceId: "providers.clalit",
			allowRun: false,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(evidence.status).toBe("fail");
		expect(providerDomainProbeEvidenceFailure("providers.clalit", evidence)).toContain(
			"harness did not run",
		);
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
