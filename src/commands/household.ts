import type { Command } from "commander";
import {
	collectHouseholdMetricRollups,
	type HouseholdMetricRollup,
} from "../household-metrics/store.js";

export type HouseholdStatsRow = HouseholdMetricRollup;

export function collectHouseholdStatsRows(): HouseholdStatsRow[] {
	return collectHouseholdMetricRollups();
}

export function formatHouseholdStatsRows(rows: readonly HouseholdStatsRow[]): string {
	if (rows.length === 0) return "No household metrics recorded.";
	const bindingWidth = Math.max("BINDING".length, ...rows.map((row) => row.bindingKey.length));
	const metricWidth = Math.max("METRIC".length, ...rows.map((row) => row.metricKind.length));
	return [
		`${"BINDING".padEnd(bindingWidth)}  ${"METRIC".padEnd(metricWidth)}  COUNT`,
		...rows.map(
			(row) =>
				`${row.bindingKey.padEnd(bindingWidth)}  ${row.metricKind.padEnd(metricWidth)}  ${row.count}`,
		),
	].join("\n");
}

export function registerHouseholdStatsCommand(parent: Command): void {
	parent
		.command("stats")
		.description("Show content-free household product counters")
		.option("--json", "Output JSON")
		.action((options: { json?: boolean }) => {
			const rows = collectHouseholdStatsRows();
			console.log(options.json ? JSON.stringify(rows, null, 2) : formatHouseholdStatsRows(rows));
		});
}
