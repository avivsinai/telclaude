import { describe, expect, it, vi } from "vitest";
import { runHouseholdReminderPhase0AcceptanceScenario } from "../../src/hermes/household-reminder-probe.js";

describe("household reminder Phase 0 acceptance", () => {
	it("covers two parents, lifecycle denials, restart recovery, and frozen-time delivery", async () => {
		const currentTzdataValidator = vi.fn(() => {
			throw new Error("simulated current-tzdata drift");
		});

		const result = await runHouseholdReminderPhase0AcceptanceScenario({
			currentTzdataValidator,
		});

		expect(result).toMatchObject({
			parentCount: 2,
			createdCount: 3,
			updatedCount: 1,
			cancelledCount: 1,
			revokedBeforeFireCount: 1,
			deliveredCount: 1,
			whatsappSendCount: 1,
			telegramSendCount: 0,
			hermesSendCount: 0,
			receiptPendingRestartRecovered: true,
			receiptMismatchDenied: true,
			journalPendingRestartRecovered: true,
			journalCompletedReplaySwallowed: true,
			journalDigestMismatchDenied: true,
			dstGapRejected: true,
			dstOverlapRejected: true,
			currentTzdataDriftRejected: true,
		});
		expect(result.fireIdHash).toMatch(/^sha256:[a-f0-9]{64}$/);
		expect(result.receiptIdHash).toMatch(/^sha256:[a-f0-9]{64}$/);
		expect(result.restartMessageIdHash).toMatch(/^sha256:[a-f0-9]{64}$/);
		expect(result.dstAdjacentInstantHashes).toHaveLength(4);
		expect(currentTzdataValidator).toHaveBeenCalledTimes(1);
	});
});
