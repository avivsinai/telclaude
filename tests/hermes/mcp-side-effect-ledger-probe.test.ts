import { describe, expect, it } from "vitest";
import {
	runTelclaudeMcpSideEffectLedgerProbe,
	sideEffectLedgerProbeEvidenceFailure,
} from "../../src/hermes/mcp/side-effect-ledger-probe.js";

describe("Telclaude MCP side-effect ledger probe", () => {
	it("passes only after exercising prepare, execute, proxy, and denial paths", async () => {
		const evidence = await runTelclaudeMcpSideEffectLedgerProbe({
			allowRun: true,
			observedAt: "2026-05-31T09:00:00.000Z",
		});

		expect(evidence.status).toBe("pass");
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
		).toContain("check ledger.replay-denied is missing");
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
		).toContain("verifierCallCount is too low");
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
