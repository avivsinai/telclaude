import { describe, expect, it } from "vitest";
import {
	providerReleasePolicyProbeEvidenceFailure,
	runTelclaudeProviderReleasePolicyProbe,
} from "../../src/hermes/provider-release-policy-probe.js";

describe("Hermes provider release-policy probe", () => {
	it("passes only after proving release audit and release-policy denial paths", () => {
		const evidence = runTelclaudeProviderReleasePolicyProbe({
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(evidence.status).toBe("pass");
		expect(evidence.observations.releaseCount).toBe(2);
		expect(evidence.observations.auditCount).toBe(2);
		expect(evidence.observations.deniedCount).toBeGreaterThanOrEqual(7);
		expect(evidence.observations.rawProviderSecretObserved).toBe(false);
		expect(evidence.observations.deniedControls).toEqual(
			expect.arrayContaining([
				"household.cross-recipient-denied",
				"household.strong-link-required",
				"provider.urgent-health-misclassification-denied",
				"household.private-memory-denied",
				"provider.sensitive-release-approval-required",
			]),
		);
		expect(evidence.checks).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					name: "provider.release.prepare-write-benign-denied",
					status: "pass",
				}),
			]),
		);
		expect(providerReleasePolicyProbeEvidenceFailure(evidence)).toBeNull();
	});

	it("rejects evidence missing urgent health misclassification denial", () => {
		const evidence = runTelclaudeProviderReleasePolicyProbe({
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(
			providerReleasePolicyProbeEvidenceFailure({
				...evidence,
				checks: evidence.checks.filter(
					(check) => check.name !== "provider.release.urgent-health-misclassification-denied",
				),
			}),
		).toContain("check provider.release.urgent-health-misclassification-denied is missing");
	});

	it("rejects pass-looking evidence with raw provider credential material", () => {
		const evidence = runTelclaudeProviderReleasePolicyProbe({
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(
			providerReleasePolicyProbeEvidenceFailure({
				...evidence,
				observations: {
					...evidence.observations,
					rawProviderSecretObserved: true,
				},
			}),
		).toContain("raw provider secret material was observed");
	});

	it("rejects evidence produced without --allow-run", () => {
		const evidence = runTelclaudeProviderReleasePolicyProbe({
			allowRun: false,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(evidence.status).toBe("fail");
		expect(providerReleasePolicyProbeEvidenceFailure(evidence)).toContain("harness did not run");
	});
});
