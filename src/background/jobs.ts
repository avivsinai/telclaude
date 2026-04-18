/**
 * Background job store — SQLite-backed CRUD for background jobs.
 *
 * Mirrors the claim/complete pattern from `src/cron/store.ts` so the runner
 * can atomically pick up queued work without double-execution. Terminal
 * statuses are sticky; once a job is `completed`, `failed`, `cancelled`, or
 * `interrupted`, it cannot be reclaimed by the runner.
 *
 * Persistence invariant: callers must `createJob()` successfully before
 * returning the job id to the operator. If the caller crashes after persisting
 * but before dispatching, the runner will still pick the job up. If the relay
 * crashes mid-execution, `markInterruptedOnStartup()` converts stuck `running`
 * jobs to `interrupted` so the operator is notified instead of the job silently
 * vanishing.
 */

import crypto from "node:crypto";
import type { PermissionTier } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { getDb } from "../storage/db.js";
import {
	type BackgroundJob,
	type BackgroundJobCreateInput,
	type BackgroundJobPayload,
	BackgroundJobPayloadSchema,
	type BackgroundJobResult,
	BackgroundJobResultSchema,
	type BackgroundJobStatus,
} from "./types.js";

const logger = getChildLogger({ module: "background-jobs" });

type BackgroundJobRow = {
	id: string;
	short_id: string;
	user_id: string;
	chat_id: number | null;
	thread_id: number | null;
	tier: string;
	title: string;
	description: string | null;
	status: BackgroundJobStatus;
	payload_json: string;
	result_json: string | null;
	error: string | null;
	created_at: number;
	started_at: number | null;
	completed_at: number | null;
	cancelled_at: number | null;
};

const VALID_TIERS: PermissionTier[] = ["READ_ONLY", "WRITE_LOCAL", "SOCIAL", "FULL_ACCESS"];
const VALID_STATUSES: BackgroundJobStatus[] = [
	"queued",
	"running",
	"completed",
	"failed",
	"cancelled",
	"interrupted",
];

function rowToJob(row: BackgroundJobRow): BackgroundJob {
	const tier = VALID_TIERS.includes(row.tier as PermissionTier)
		? (row.tier as PermissionTier)
		: "READ_ONLY";
	const status = VALID_STATUSES.includes(row.status) ? row.status : "queued";

	let payload: BackgroundJobPayload;
	try {
		payload = BackgroundJobPayloadSchema.parse(JSON.parse(row.payload_json));
	} catch (err) {
		logger.warn(
			{ jobId: row.id, error: String(err) },
			"background job payload failed to parse, defaulting to noop",
		);
		payload = { kind: "noop", message: "payload parse error" };
	}

	let result: BackgroundJobResult | null = null;
	if (row.result_json) {
		try {
			result = BackgroundJobResultSchema.parse(JSON.parse(row.result_json));
		} catch (err) {
			logger.warn({ jobId: row.id, error: String(err) }, "background job result failed to parse");
			result = { message: "result parse error" };
		}
	}

	return {
		id: row.id,
		shortId: row.short_id,
		userId: row.user_id,
		chatId: row.chat_id,
		threadId: row.thread_id,
		tier,
		title: row.title,
		description: row.description,
		status,
		payload,
		result,
		error: row.error,
		createdAtMs: row.created_at,
		startedAtMs: row.started_at,
		completedAtMs: row.completed_at,
		cancelledAtMs: row.cancelled_at,
	};
}

function generateShortId(): string {
	return crypto.randomBytes(4).toString("hex");
}

/**
 * Create a new background job in `queued` state.
 *
 * Retries short-id generation up to 10 times to avoid rare collisions; callers
 * can pass an explicit short id (useful for tests and scripted jobs).
 */
export function createJob(input: BackgroundJobCreateInput, nowMs = Date.now()): BackgroundJob {
	const db = getDb();
	const id = `bg-${crypto.randomUUID()}`;
	const title = input.title.trim();
	if (!title) {
		throw new Error("Background job title is required");
	}
	// Validate payload up-front so we fail fast.
	const payload = BackgroundJobPayloadSchema.parse(input.payload);
	const payloadJson = JSON.stringify(payload);

	const insert = db.prepare(
		`INSERT INTO background_jobs (
			id, short_id, user_id, chat_id, thread_id, tier, title, description,
			status, payload_json, result_json, error,
			created_at, started_at, completed_at, cancelled_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, NULL, NULL, ?, NULL, NULL, NULL)`,
	);

	for (let attempt = 0; attempt < 10; attempt++) {
		const shortId = generateShortId();
		try {
			insert.run(
				id,
				shortId,
				input.userId,
				input.chatId ?? null,
				input.threadId ?? null,
				input.tier,
				title,
				input.description?.trim() || null,
				payloadJson,
				nowMs,
			);
			const created = getJob(id);
			if (!created) {
				throw new Error("Failed to persist background job");
			}
			logger.info(
				{
					jobId: id,
					shortId,
					tier: input.tier,
					payloadKind: payload.kind,
					chatId: input.chatId ?? null,
				},
				"background job created",
			);
			return created;
		} catch (err) {
			const msg = String(err);
			if (msg.includes("UNIQUE") && msg.includes("short_id")) {
				continue;
			}
			throw err;
		}
	}

	throw new Error("Failed to generate a collision-free background job short id");
}

export function getJob(id: string): BackgroundJob | null {
	const db = getDb();
	const row = db.prepare("SELECT * FROM background_jobs WHERE id = ?").get(id) as
		| BackgroundJobRow
		| undefined;
	return row ? rowToJob(row) : null;
}

export function getJobByShortId(shortId: string): BackgroundJob | null {
	const db = getDb();
	const row = db.prepare("SELECT * FROM background_jobs WHERE short_id = ?").get(shortId) as
		| BackgroundJobRow
		| undefined;
	return row ? rowToJob(row) : null;
}

export type ListJobsFilter = {
	/** Limit results. Default 50. */
	limit?: number;
	/** Only include jobs in these statuses. */
	statuses?: BackgroundJobStatus[];
	/** Only include jobs created after this timestamp. */
	sinceMs?: number;
	/** Restrict to a chat. */
	chatId?: number;
	/** Restrict to a user. */
	userId?: string;
};

export function listJobs(filter: ListJobsFilter = {}): BackgroundJob[] {
	const db = getDb();
	const clauses: string[] = [];
	const params: unknown[] = [];

	if (filter.statuses && filter.statuses.length > 0) {
		clauses.push(`status IN (${filter.statuses.map(() => "?").join(",")})`);
		params.push(...filter.statuses);
	}
	if (filter.sinceMs !== undefined) {
		clauses.push("created_at >= ?");
		params.push(filter.sinceMs);
	}
	if (filter.chatId !== undefined) {
		clauses.push("chat_id = ?");
		params.push(filter.chatId);
	}
	if (filter.userId) {
		clauses.push("user_id = ?");
		params.push(filter.userId);
	}

	const where = clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : "";
	const limit = Math.max(1, Math.min(filter.limit ?? 50, 500));
	const rows = db
		.prepare(`SELECT * FROM background_jobs ${where} ORDER BY created_at DESC LIMIT ${limit}`)
		.all(...params) as BackgroundJobRow[];
	return rows.map(rowToJob);
}

/**
 * Claim up to `limit` queued jobs by transitioning them to `running` atomically.
 * Sets `started_at` so the runner can enforce timeouts.
 */
export function claimQueuedJobs(nowMs = Date.now(), limit = 5): BackgroundJob[] {
	const db = getDb();
	const effectiveLimit = Math.max(1, Math.min(limit, 25));
	return db.transaction(() => {
		const rows = db
			.prepare(
				`SELECT * FROM background_jobs
				 WHERE status = 'queued'
				 ORDER BY created_at ASC
				 LIMIT ?`,
			)
			.all(effectiveLimit) as BackgroundJobRow[];
		if (rows.length === 0) {
			return [];
		}
		const claimStmt = db.prepare(
			`UPDATE background_jobs
			 SET status = 'running', started_at = ?
			 WHERE id = ? AND status = 'queued'`,
		);
		const claimed: BackgroundJob[] = [];
		for (const row of rows) {
			const result = claimStmt.run(nowMs, row.id);
			if (result.changes > 0) {
				claimed.push(
					rowToJob({
						...row,
						status: "running",
						started_at: nowMs,
					}),
				);
			}
		}
		return claimed;
	})();
}

export type CompleteJobInput = {
	jobId: string;
	status: "completed" | "failed";
	result?: BackgroundJobResult;
	error?: string;
	finishedAtMs?: number;
};

/**
 * Mark a running job as complete (success or failure). No-op if the job is
 * already terminal (e.g. it was cancelled while the executor was running).
 *
 * Returns the persisted state so callers can decide whether to emit a
 * completion notification (only when the transition happened).
 */
export function completeJob(input: CompleteJobInput): {
	job: BackgroundJob | null;
	transitioned: boolean;
} {
	const db = getDb();
	const finishedAtMs = input.finishedAtMs ?? Date.now();
	const resultJson = input.result ? JSON.stringify(input.result) : null;
	const errorText = input.error ?? null;

	const result = db
		.prepare(
			`UPDATE background_jobs
			 SET status = ?, result_json = ?, error = ?, completed_at = ?
			 WHERE id = ? AND status = 'running'`,
		)
		.run(input.status, resultJson, errorText, finishedAtMs, input.jobId);

	const job = getJob(input.jobId);
	return { job, transitioned: result.changes > 0 };
}

/**
 * Mark a job as cancelled. Valid from `queued` or `running`; no-op if terminal.
 *
 * Returns whether the cancellation actually transitioned the job.
 */
export function cancelJob(
	jobId: string,
	nowMs = Date.now(),
): { job: BackgroundJob | null; transitioned: boolean } {
	const db = getDb();
	const result = db
		.prepare(
			`UPDATE background_jobs
			 SET status = 'cancelled', cancelled_at = ?, completed_at = ?
			 WHERE id = ? AND status IN ('queued', 'running')`,
		)
		.run(nowMs, nowMs, jobId);

	const job = getJob(jobId);
	return { job, transitioned: result.changes > 0 };
}

/**
 * On relay startup, flip any `running` jobs to `interrupted` so we surface
 * them to the operator instead of losing them silently. Returns the affected
 * jobs so the caller can emit notification cards.
 */
export function markInterruptedOnStartup(
	nowMs = Date.now(),
	reason = "Relay restarted while job was running",
): BackgroundJob[] {
	const db = getDb();
	return db.transaction(() => {
		const rows = db
			.prepare("SELECT * FROM background_jobs WHERE status = 'running'")
			.all() as BackgroundJobRow[];
		if (rows.length === 0) {
			return [];
		}
		const stmt = db.prepare(
			`UPDATE background_jobs
			 SET status = 'interrupted', error = ?, completed_at = ?
			 WHERE id = ? AND status = 'running'`,
		);
		const changed: BackgroundJob[] = [];
		for (const row of rows) {
			const result = stmt.run(reason, nowMs, row.id);
			if (result.changes > 0) {
				changed.push(
					rowToJob({
						...row,
						status: "interrupted",
						error: reason,
						completed_at: nowMs,
					}),
				);
			}
		}
		return changed;
	})();
}

/**
 * Delete background jobs older than `cutoffMs` in terminal status. Safe
 * housekeeping call — intended to be invoked from the existing cleanup sweep.
 */
export function pruneOldJobs(cutoffMs: number): number {
	const db = getDb();
	const result = db
		.prepare(
			`DELETE FROM background_jobs
			 WHERE status IN ('completed', 'failed', 'cancelled', 'interrupted')
			   AND COALESCE(completed_at, cancelled_at, created_at) < ?`,
		)
		.run(cutoffMs);
	return result.changes;
}

export function getActiveJobCount(): number {
	const db = getDb();
	const row = db
		.prepare("SELECT COUNT(*) AS count FROM background_jobs WHERE status IN ('queued', 'running')")
		.get() as { count: number };
	return row.count ?? 0;
}
