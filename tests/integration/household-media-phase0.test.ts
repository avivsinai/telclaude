import { describe, expect, it } from "vitest";
import { runHouseholdMediaPhase0AcceptanceScenario } from "../../src/hermes/household-media-probe.js";

describe("household media Phase 0 acceptance", () => {
	it("covers two parents from bounded derivation through exact confirmation and named PDF delivery", async () => {
		const result = await runHouseholdMediaPhase0AcceptanceScenario();

		expect(result).toMatchObject({
			parentCount: 2,
			voiceDerivationCount: 1,
			documentDerivationCount: 1,
			confirmedActionCount: 2,
			executedActionCount: 2,
			namedPdfDeliveryCount: 2,
			deletionReceiptCount: 3,
			parentsIsolated: true,
			quarantineBounded: true,
			voiceConfidenceWeighted: true,
			documentStaticBounded: true,
			actionClassified: true,
			confirmationBoundOnce: true,
			freshTurnExecutionBound: true,
			namedPdfBound: true,
			denialsFailClosed: true,
			artifactSanitized: true,
		});
		expect(result.parentChainHashes).toHaveLength(2);
		expect(new Set(result.parentChainHashes).size).toBe(2);
		expect(result.namedPdfHashes).toHaveLength(2);
	});
});
