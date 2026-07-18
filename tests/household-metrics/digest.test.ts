import { describe, expect, it, vi } from "vitest";
import {
	createHouseholdMetricsDigestExecutor,
	priorJerusalemCalendarDayWindow,
	resolveNextJerusalemDigestAt,
} from "../../src/household-metrics/digest.js";

describe("household metrics digest", () => {
	it("resolves the next fixed Jerusalem wall-clock fire across DST", () => {
		const before = Date.parse("2026-03-27T04:30:00.000Z");
		const next = resolveNextJerusalemDigestAt(before, 8);

		expect(
			new Intl.DateTimeFormat("en-CA", {
				timeZone: "Asia/Jerusalem",
				dateStyle: "short",
				timeStyle: "short",
				hourCycle: "h23",
			}).format(next),
		).toContain("08:00");
		expect(next).toBeGreaterThan(before);
	});

	it("summarizes the prior Jerusalem calendar day, not a rolling 24 hours", () => {
		const window = priorJerusalemCalendarDayWindow(Date.parse("2026-07-18T05:00:00.000Z"));

		expect(window.localDate).toBe("2026-07-17");
		expect(new Date(window.fromMs).toISOString()).toBe("2026-07-16T21:00:00.000Z");
		expect(new Date(window.toMs).toISOString()).toBe("2026-07-17T21:00:00.000Z");
	});

	it("sends a deterministic content-free admin digest without an LLM", async () => {
		const sendAdminAlert = vi.fn(async () => undefined);
		const collectRollups = vi.fn(() => [
			{ bindingKey: "mom", metricKind: "inbound_received" as const, count: 4 },
			{ bindingKey: "mom", metricKind: "proposal_confirmed" as const, count: 1 },
		]);
		const execute = createHouseholdMetricsDigestExecutor({
			nowMs: () => Date.parse("2026-07-18T05:00:00.000Z"),
			collectRollups,
			sendAdminAlert,
		});

		await expect(execute()).resolves.toEqual({
			ok: true,
			message: "household metrics digest sent for 2026-07-17",
		});
		expect(sendAdminAlert).toHaveBeenCalledWith({
			level: "info",
			title: "Household metrics — 2026-07-17",
			message: expect.stringContaining("mom"),
		});
		expect(sendAdminAlert.mock.calls[0]?.[0].message).not.toContain("+972");
	});
});
