import { describe, expect, it } from "vitest";
import {
	providerApprovalBindingProbeEvidenceFailure,
	runTelclaudeProviderApprovalBindingProbe,
} from "../../src/hermes/provider-approval-binding-probe.js";

describe("Hermes provider approval-binding probe", () => {
	it("passes only after exercising provider approval, proxy, mismatch, and replay paths", async () => {
		const evidence = await runTelclaudeProviderApprovalBindingProbe({
			allowRun: true,
			observedAt: "2026-05-31T09:00:00.000Z",
		});

		expect(evidence.status).toBe("pass");
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
		).toContain("check provider.approval-binding.duplicate-jti-denied is missing");
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
		).toContain("providerProxyCallCount is 0");
	});

	it("rejects evidence produced without --allow-run", async () => {
		const evidence = await runTelclaudeProviderApprovalBindingProbe({
			allowRun: false,
			observedAt: "2026-05-31T09:00:00.000Z",
		});

		expect(evidence.status).toBe("fail");
		expect(providerApprovalBindingProbeEvidenceFailure(evidence)).toContain(
			"harness did not run",
		);
	});
});
