import type Database from "better-sqlite3";
import { getChildLogger } from "../logging.js";
import { isValidHouseholdBindingId } from "../memory/source.js";
import { getDb } from "../storage/db.js";

const logger = getChildLogger({ module: "household-metrics" });
const METRIC_WINDOW_MS = 60 * 60 * 1_000;

export const HOUSEHOLD_METRIC_KINDS = [
	"inbound_received",
	"proposal_confirmed",
	"proposal_rejected",
	"proposal_expired",
	"confirmation_shown",
	"confirmation_confirmed",
	"confirmation_rejected",
	"confirmation_expired",
	"read_succeeded",
	"auth_required",
	"prescription_renewal_prepared",
	"prescription_renewal_executed",
	"fire_started",
	"delivery_succeeded",
	"delivery_failed",
	"approval_latency_le_30s",
	"approval_latency_le_60s",
	"approval_latency_le_300s",
	"approval_latency_gt_300s",
] as const;

export type HouseholdMetricKind = (typeof HOUSEHOLD_METRIC_KINDS)[number];

export type HouseholdMetricRollup = {
	readonly bindingKey: string;
	readonly metricKind: HouseholdMetricKind;
	readonly count: number;
};

type MetricDatabase = Pick<Database.Database, "prepare">;
let recordingEnabled = false;

export function configureHouseholdMetrics(options: { readonly enabled: boolean }): void {
	recordingEnabled = options.enabled;
}

export function recordHouseholdMetric(
	metricKind: HouseholdMetricKind,
	bindingKey: string,
	nowMs = Date.now(),
	dependencies: { readonly database?: MetricDatabase } = {},
): boolean {
	if (!recordingEnabled) return false;
	try {
		if (!isHouseholdMetricKind(metricKind) || !isValidHouseholdBindingId(bindingKey)) return false;
		if (!Number.isSafeInteger(nowMs) || nowMs < 0) return false;
		const windowStart = Math.floor(nowMs / METRIC_WINDOW_MS) * METRIC_WINDOW_MS;
		(dependencies.database ?? getDb())
			.prepare(
				`INSERT INTO household_metrics (metric_kind, binding_key, window_start, count)
				 VALUES (?, ?, ?, 1)
				 ON CONFLICT(metric_kind, binding_key, window_start)
				 DO UPDATE SET count = count + 1`,
			)
			.run(metricKind, bindingKey, windowStart);
		return true;
	} catch {
		logger.warn({ metricKind }, "household metric write failed");
		return false;
	}
}

export function collectHouseholdMetricRollups(
	options: {
		readonly fromMs?: number;
		readonly toMs?: number;
		readonly database?: MetricDatabase;
	} = {},
): HouseholdMetricRollup[] {
	const predicates: string[] = [];
	const params: number[] = [];
	if (options.fromMs !== undefined) {
		predicates.push("window_start >= ?");
		params.push(options.fromMs);
	}
	if (options.toMs !== undefined) {
		predicates.push("window_start < ?");
		params.push(options.toMs);
	}
	const where = predicates.length > 0 ? ` WHERE ${predicates.join(" AND ")}` : "";
	const rows = (options.database ?? getDb())
		.prepare(
			`SELECT binding_key, metric_kind, SUM(count) AS count
			 FROM household_metrics${where}
			 GROUP BY binding_key, metric_kind
			 ORDER BY binding_key, metric_kind`,
		)
		.all(...params) as Array<{ binding_key: string; metric_kind: string; count: number }>;
	return rows.flatMap((row) =>
		isHouseholdMetricKind(row.metric_kind) && isValidHouseholdBindingId(row.binding_key)
			? [{ bindingKey: row.binding_key, metricKind: row.metric_kind, count: row.count }]
			: [],
	);
}

export function householdMetricBindingKeyFromSubject(subjectUserId: string): string | null {
	const prefix = "household:";
	if (!subjectUserId.startsWith(prefix)) return null;
	const bindingKey = subjectUserId.slice(prefix.length);
	return isValidHouseholdBindingId(bindingKey) ? bindingKey : null;
}

export function approvalLatencyMetricKind(latencyMs: number): HouseholdMetricKind {
	if (latencyMs <= 30_000) return "approval_latency_le_30s";
	if (latencyMs <= 60_000) return "approval_latency_le_60s";
	if (latencyMs <= 300_000) return "approval_latency_le_300s";
	return "approval_latency_gt_300s";
}

function isHouseholdMetricKind(value: string): value is HouseholdMetricKind {
	return (HOUSEHOLD_METRIC_KINDS as readonly string[]).includes(value);
}
