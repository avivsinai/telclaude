/**
 * Structured activity log for social services.
 *
 * SECURITY: Returns metadata only (counts, timestamps, action types).
 * No content fields, no raw LLM output, no social memory text.
 * Zero injection risk — no untrusted content touches any LLM.
 */

import { getChildLogger } from "../logging.js";
import { getDb } from "../storage/db.js";

const logger = getChildLogger({ module: "activity-log" });

export type ActivityLogEntry = {
	type: "notification" | "reply" | "post" | "autonomous";
	timestamp: number;
	serviceId: string;
};

/**
 * Log a social activity event to SQLite.
 */
export function logSocialActivity(entry: ActivityLogEntry): void {
	try {
		const db = getDb();
		db.prepare(
			`INSERT INTO social_activity_log (type, timestamp, service_id)
			 VALUES (?, ?, ?)`,
		).run(entry.type, entry.timestamp, entry.serviceId);
	} catch (err) {
		logger.debug({ error: String(err) }, "failed to log social activity (table may not exist)");
	}
}

/**
 * Get a summary of social activity for a service within a time window.
 *
 * Returns metadata only — no content or LLM output.
 */
export function getActivitySummary(
	serviceId?: string,
	hours = 4,
): { serviceId: string; type: string; count: number }[] {
	const db = getDb();
	const cutoff = Date.now() - hours * 3600_000;

	try {
		const query = serviceId
			? db.prepare(
					`SELECT service_id, type, COUNT(*) as count
				 FROM social_activity_log
				 WHERE timestamp > ? AND service_id = ?
				 GROUP BY service_id, type
				 ORDER BY service_id, type`,
				)
			: db.prepare(
					`SELECT service_id, type, COUNT(*) as count
				 FROM social_activity_log
				 WHERE timestamp > ?
				 GROUP BY service_id, type
				 ORDER BY service_id, type`,
				);

		const rows = serviceId
			? (query.all(cutoff, serviceId) as Array<{
					service_id: string;
					type: string;
					count: number;
				}>)
			: (query.all(cutoff) as Array<{ service_id: string; type: string; count: number }>);

		return rows.map((r) => ({
			serviceId: r.service_id,
			type: r.type,
			count: r.count,
		}));
	} catch (err) {
		logger.debug({ error: String(err) }, "failed to query activity log (table may not exist)");
		return [];
	}
}

/**
 * Format activity summary for Telegram display (human-readable, metadata only).
 */
export function formatActivityLog(
	summary: { serviceId: string; type: string; count: number }[],
	hours: number,
): string {
	if (summary.length === 0) {
		return `No social activity in the last ${hours}h.`;
	}

	// Group by serviceId
	const byService = new Map<string, { type: string; count: number }[]>();
	for (const entry of summary) {
		const existing = byService.get(entry.serviceId) ?? [];
		existing.push({ type: entry.type, count: entry.count });
		byService.set(entry.serviceId, existing);
	}

	const lines: string[] = [];
	for (const [svc, entries] of byService) {
		const details = entries.map((e) => `${e.count} ${e.type}(s)`).join(", ");
		lines.push(`${svc} (last ${hours}h): ${details}`);
	}

	return lines.join("\n");
}

/**
 * Ensure the activity log table exists.
 * Called during relay startup.
 */
export function ensureActivityLogTable(): void {
	try {
		const db = getDb();
		db.exec(`
			CREATE TABLE IF NOT EXISTS social_activity_log (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				type TEXT NOT NULL,
				timestamp INTEGER NOT NULL,
				service_id TEXT NOT NULL
			)
		`);
		db.exec(`
			CREATE INDEX IF NOT EXISTS idx_activity_log_time
			ON social_activity_log (timestamp, service_id)
		`);
	} catch (err) {
		logger.warn({ error: String(err) }, "failed to create activity log table");
	}
}
