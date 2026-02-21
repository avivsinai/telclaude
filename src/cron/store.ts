import crypto from "node:crypto";
import { getDb } from "../storage/db.js";
import { computeNextRunAtMs } from "./parse.js";
import type {
	CronAction,
	CronAddInput,
	CronCoverage,
	CronJob,
	CronSchedule,
	CronStatusSummary,
} from "./types.js";

type CronJobRow = {
	id: string;
	name: string;
	enabled: number;
	running: number;
	schedule_kind: string;
	schedule_at: number | null;
	schedule_every_ms: number | null;
	schedule_cron: string | null;
	action_kind: string;
	action_service_id: string | null;
	next_run_at: number | null;
	last_run_at: number | null;
	last_status: string | null;
	last_error: string | null;
	created_at: number;
	updated_at: number;
};

function parseSchedule(row: CronJobRow): CronSchedule {
	switch (row.schedule_kind) {
		case "at": {
			if (typeof row.schedule_at !== "number") {
				throw new Error(`cron job ${row.id} is missing at timestamp`);
			}
			return { kind: "at", at: new Date(row.schedule_at).toISOString() };
		}
		case "every": {
			if (typeof row.schedule_every_ms !== "number" || row.schedule_every_ms <= 0) {
				throw new Error(`cron job ${row.id} has invalid everyMs`);
			}
			return { kind: "every", everyMs: row.schedule_every_ms };
		}
		case "cron": {
			if (!row.schedule_cron) {
				throw new Error(`cron job ${row.id} is missing cron expression`);
			}
			return { kind: "cron", expr: row.schedule_cron };
		}
		default:
			throw new Error(`cron job ${row.id} has unsupported schedule kind '${row.schedule_kind}'`);
	}
}

function parseAction(row: CronJobRow): CronAction {
	switch (row.action_kind) {
		case "social-heartbeat":
			return {
				kind: "social-heartbeat",
				...(row.action_service_id ? { serviceId: row.action_service_id } : {}),
			};
		case "private-heartbeat":
			return { kind: "private-heartbeat" };
		default:
			throw new Error(`cron job ${row.id} has unsupported action kind '${row.action_kind}'`);
	}
}

function rowToJob(row: CronJobRow): CronJob {
	return {
		id: row.id,
		name: row.name,
		enabled: row.enabled === 1,
		running: row.running === 1,
		schedule: parseSchedule(row),
		action: parseAction(row),
		nextRunAtMs: row.next_run_at,
		lastRunAtMs: row.last_run_at,
		lastStatus:
			row.last_status === "success" || row.last_status === "error" || row.last_status === "skipped"
				? row.last_status
				: null,
		lastError: row.last_error,
		createdAtMs: row.created_at,
		updatedAtMs: row.updated_at,
	};
}

function encodeSchedule(schedule: CronSchedule): {
	scheduleKind: "at" | "every" | "cron";
	scheduleAt: number | null;
	scheduleEveryMs: number | null;
	scheduleCron: string | null;
} {
	switch (schedule.kind) {
		case "at":
			return {
				scheduleKind: "at",
				scheduleAt: Date.parse(schedule.at),
				scheduleEveryMs: null,
				scheduleCron: null,
			};
		case "every":
			return {
				scheduleKind: "every",
				scheduleAt: null,
				scheduleEveryMs: schedule.everyMs,
				scheduleCron: null,
			};
		case "cron":
			return {
				scheduleKind: "cron",
				scheduleAt: null,
				scheduleEveryMs: null,
				scheduleCron: schedule.expr,
			};
		default: {
			const exhaustiveCheck: never = schedule;
			throw new Error(`Unsupported schedule: ${String(exhaustiveCheck)}`);
		}
	}
}

function encodeAction(action: CronAction): {
	actionKind: string;
	actionServiceId: string | null;
} {
	switch (action.kind) {
		case "social-heartbeat":
			return {
				actionKind: "social-heartbeat",
				actionServiceId: action.serviceId ?? null,
			};
		case "private-heartbeat":
			return {
				actionKind: "private-heartbeat",
				actionServiceId: null,
			};
		default: {
			const exhaustiveCheck: never = action;
			throw new Error(`Unsupported action: ${String(exhaustiveCheck)}`);
		}
	}
}

function validateAddInput(input: CronAddInput, nowMs: number): number | null {
	const nextRunAtMs = computeNextRunAtMs(input.schedule, nowMs);
	if (input.schedule.kind === "at" && nextRunAtMs === null) {
		throw new Error("--at timestamp must be in the future");
	}
	if (input.schedule.kind === "every" && input.schedule.everyMs <= 0) {
		throw new Error("everyMs must be positive");
	}
	return nextRunAtMs;
}

export function listCronJobs(options?: { includeDisabled?: boolean }): CronJob[] {
	const db = getDb();
	const rows = (
		options?.includeDisabled
			? db.prepare("SELECT * FROM cron_jobs ORDER BY created_at DESC").all()
			: db.prepare("SELECT * FROM cron_jobs WHERE enabled = 1 ORDER BY created_at DESC").all()
	) as CronJobRow[];
	return rows.map(rowToJob);
}

export function getCronJob(id: string): CronJob | null {
	const db = getDb();
	const row = db.prepare("SELECT * FROM cron_jobs WHERE id = ?").get(id) as CronJobRow | undefined;
	if (!row) {
		return null;
	}
	return rowToJob(row);
}

export function addCronJob(input: CronAddInput, nowMs = Date.now()): CronJob {
	const db = getDb();
	const id = input.id?.trim() || `cron-${crypto.randomUUID().slice(0, 12)}`;
	const name = input.name.trim();
	if (!name) {
		throw new Error("Job name is required");
	}
	const nextRunAtMs = validateAddInput(input, nowMs);
	const { scheduleKind, scheduleAt, scheduleEveryMs, scheduleCron } = encodeSchedule(
		input.schedule,
	);
	const { actionKind, actionServiceId } = encodeAction(input.action);
	const enabled = input.enabled !== false;

	db.prepare(
		`INSERT INTO cron_jobs (
			id, name, enabled, running,
			schedule_kind, schedule_at, schedule_every_ms, schedule_cron,
			action_kind, action_service_id,
			next_run_at, last_run_at, last_status, last_error,
			created_at, updated_at
		)
		VALUES (?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?)`,
	).run(
		id,
		name,
		enabled ? 1 : 0,
		scheduleKind,
		scheduleAt,
		scheduleEveryMs,
		scheduleCron,
		actionKind,
		actionServiceId,
		enabled ? nextRunAtMs : null,
		nowMs,
		nowMs,
	);

	const created = getCronJob(id);
	if (!created) {
		throw new Error("Failed to create cron job");
	}
	return created;
}

export function removeCronJob(id: string): boolean {
	const db = getDb();
	const result = db.prepare("DELETE FROM cron_jobs WHERE id = ?").run(id);
	return result.changes > 0;
}

export function setCronJobEnabled(
	id: string,
	enabled: boolean,
	nowMs = Date.now(),
): CronJob | null {
	const db = getDb();
	const existing = getCronJob(id);
	if (!existing) {
		return null;
	}
	const nextRunAtMs = enabled ? computeNextRunAtMs(existing.schedule, nowMs) : null;

	db.prepare(
		`UPDATE cron_jobs
		 SET enabled = ?, running = 0, next_run_at = ?, updated_at = ?
		 WHERE id = ?`,
	).run(enabled ? 1 : 0, nextRunAtMs, nowMs, id);

	return getCronJob(id);
}

export function getCronStatusSummary(): CronStatusSummary {
	const db = getDb();
	const row = db
		.prepare(
			`SELECT
				COUNT(*) AS total_jobs,
				SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) AS enabled_jobs,
				SUM(CASE WHEN running = 1 THEN 1 ELSE 0 END) AS running_jobs,
				MIN(CASE WHEN enabled = 1 THEN next_run_at END) AS next_run_at
			 FROM cron_jobs`,
		)
		.get() as {
		total_jobs: number | null;
		enabled_jobs: number | null;
		running_jobs: number | null;
		next_run_at: number | null;
	};

	return {
		totalJobs: row.total_jobs ?? 0,
		enabledJobs: row.enabled_jobs ?? 0,
		runningJobs: row.running_jobs ?? 0,
		nextRunAtMs: row.next_run_at ?? null,
	};
}

export function getCronCoverage(): CronCoverage {
	const db = getDb();
	const rows = db
		.prepare(
			"SELECT action_kind, action_service_id FROM cron_jobs WHERE enabled = 1 AND next_run_at IS NOT NULL",
		)
		.all() as Array<{ action_kind: string; action_service_id: string | null }>;

	let allSocial = false;
	let hasPrivateHeartbeat = false;
	const socialServiceIds = new Set<string>();

	for (const row of rows) {
		if (row.action_kind === "private-heartbeat") {
			hasPrivateHeartbeat = true;
			continue;
		}
		if (row.action_kind !== "social-heartbeat") {
			continue;
		}
		if (!row.action_service_id) {
			allSocial = true;
			continue;
		}
		socialServiceIds.add(row.action_service_id);
	}

	return {
		allSocial,
		hasPrivateHeartbeat,
		socialServiceIds: [...socialServiceIds],
	};
}

export function resetRunningCronJobs(): number {
	const db = getDb();
	const result = db
		.prepare("UPDATE cron_jobs SET running = 0, updated_at = ? WHERE running = 1")
		.run(Date.now());
	return result.changes;
}

export function claimDueCronJobs(nowMs = Date.now(), limit = 20): CronJob[] {
	const db = getDb();
	return db.transaction(() => {
		const rows = db
			.prepare(
				`SELECT * FROM cron_jobs
				 WHERE enabled = 1
				   AND running = 0
				   AND next_run_at IS NOT NULL
				   AND next_run_at <= ?
				 ORDER BY next_run_at ASC
				 LIMIT ?`,
			)
			.all(nowMs, limit) as CronJobRow[];

		if (rows.length === 0) {
			return [];
		}

		const claimStmt = db.prepare(
			"UPDATE cron_jobs SET running = 1, updated_at = ? WHERE id = ? AND running = 0",
		);
		const claimed: CronJob[] = [];
		for (const row of rows) {
			const result = claimStmt.run(nowMs, row.id);
			if (result.changes > 0) {
				claimed.push(rowToJob({ ...row, running: 1, updated_at: nowMs }));
			}
		}
		return claimed;
	})();
}

export function claimCronJobById(id: string, nowMs = Date.now()): CronJob | null {
	const db = getDb();
	return db.transaction(() => {
		const row = db.prepare("SELECT * FROM cron_jobs WHERE id = ?").get(id) as
			| CronJobRow
			| undefined;
		if (!row) {
			return null;
		}
		if (row.running === 1) {
			return null;
		}
		const result = db
			.prepare("UPDATE cron_jobs SET running = 1, updated_at = ? WHERE id = ? AND running = 0")
			.run(nowMs, id);
		if (result.changes === 0) {
			return null;
		}
		return rowToJob({ ...row, running: 1, updated_at: nowMs });
	})();
}

export function completeClaimedCronJob(params: {
	job: CronJob;
	startedAtMs: number;
	finishedAtMs?: number;
	status: "success" | "error" | "skipped";
	message: string;
}): CronJob | null {
	const db = getDb();
	const finishedAtMs = params.finishedAtMs ?? Date.now();
	let nextRunAtMs: number | null = null;
	let enabled = params.job.enabled;

	if (params.job.schedule.kind === "at") {
		enabled = false;
		nextRunAtMs = null;
	} else if (enabled) {
		nextRunAtMs = computeNextRunAtMs(params.job.schedule, finishedAtMs);
	}

	db.transaction(() => {
		db.prepare(
			`INSERT INTO cron_runs (job_id, started_at, finished_at, status, message)
			 VALUES (?, ?, ?, ?, ?)`,
		).run(params.job.id, params.startedAtMs, finishedAtMs, params.status, params.message);

		db.prepare(
			`UPDATE cron_jobs
			 SET enabled = ?,
			     running = 0,
			     next_run_at = ?,
			     last_run_at = ?,
			     last_status = ?,
			     last_error = ?,
			     updated_at = ?
			 WHERE id = ?`,
		).run(
			enabled ? 1 : 0,
			nextRunAtMs,
			finishedAtMs,
			params.status,
			params.status === "error" ? params.message : null,
			finishedAtMs,
			params.job.id,
		);
	})();

	return getCronJob(params.job.id);
}

export function listCronRuns(
	jobId: string,
	limit = 20,
): Array<{
	jobId: string;
	startedAtMs: number;
	finishedAtMs: number | null;
	status: string;
	message: string;
}> {
	const db = getDb();
	const rows = db
		.prepare(
			`SELECT job_id, started_at, finished_at, status, message
			 FROM cron_runs
			 WHERE job_id = ?
			 ORDER BY started_at DESC
			 LIMIT ?`,
		)
		.all(jobId, Math.max(1, limit)) as Array<{
		job_id: string;
		started_at: number;
		finished_at: number | null;
		status: string;
		message: string;
	}>;

	return rows.map((row) => ({
		jobId: row.job_id,
		startedAtMs: row.started_at,
		finishedAtMs: row.finished_at,
		status: row.status,
		message: row.message,
	}));
}
