import { describe, expect, it, vi } from "vitest";

const collectRollupsMock = vi.hoisted(() => vi.fn());

vi.mock("../../src/household-metrics/store.js", () => ({
	collectHouseholdMetricRollups: collectRollupsMock,
}));

import {
	collectHouseholdStatsRows,
	formatHouseholdStatsRows,
} from "../../src/commands/household.js";

describe("household stats command", () => {
	it("collects operator-readable per-binding counters", () => {
		collectRollupsMock.mockReturnValue([
			{ bindingKey: "mom", metricKind: "inbound_received", count: 7 },
		]);

		expect(collectHouseholdStatsRows()).toEqual([
			{ bindingKey: "mom", metricKind: "inbound_received", count: 7 },
		]);
	});

	it("formats only binding, fixed metric kind, and count", () => {
		const output = formatHouseholdStatsRows([
			{ bindingKey: "mom", metricKind: "inbound_received", count: 7 },
			{ bindingKey: "mom", metricKind: "approval_latency_le_30s", count: 2 },
		]);

		expect(output).toContain("BINDING");
		expect(output).toContain("mom");
		expect(output).toContain("approval_latency_le_30s");
		expect(output).not.toContain("message");
	});
});
