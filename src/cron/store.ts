import crypto from "node:crypto";
import { resolveNextJerusalemDigestAt } from "../household-metrics/digest.js";
import { getDb } from "../storage/db.js";
import { computeNextRunAtMs } from "./parse.js";
import type {
	CronAction,
	CronAddInput,
	CronCoverage,
	CronDeliveryTarget,
	CronJob,
	CronPreprocessCommand,
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
	action_prompt: string | null;
	action_allowed_skills_json: string | null;
	action_preprocess_json: string | null;
	action_reminder_id: string | null;
	action_reminder_revision: number | null;
	action_digest_at_hour: number | null;
	owner_id: string | null;
	delivery_target_kind: string | null;
	delivery_chat_id: number | null;
	delivery_thread_id: number | null;
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
		case "curator-scan":
			return { kind: "curator-scan" };
		case "household-reminder":
			if (
				!row.action_reminder_id ||
				!Number.isInteger(row.action_reminder_revision) ||
				(row.action_reminder_revision ?? 0) < 1
			) {
				throw new Error(`cron job ${row.id} is missing household reminder authority`);
			}
			return {
				kind: "household-reminder",
				reminderId: row.action_reminder_id,
				revision: row.action_reminder_revision as number,
			};
		case "household-metrics-digest":
			if (
				!Number.isInteger(row.action_digest_at_hour) ||
				(row.action_digest_at_hour ?? -1) < 0 ||
				(row.action_digest_at_hour ?? 24) > 23
			) {
				throw new Error(`cron job ${row.id} has an invalid household digest hour`);
			}
			return {
				kind: "household-metrics-digest",
				atHour: row.action_digest_at_hour as number,
			};
		case "agent-prompt":
			if (!row.action_prompt) {
				throw new Error(`cron job ${row.id} is missing action prompt`);
			}
			return {
				kind: "agent-prompt",
				prompt: row.action_prompt,
				...parseAllowedSkills(row),
				...parsePreprocess(row),
			};
		default:
			throw new Error(`cron job ${row.id} has unsupported action kind '${row.action_kind}'`);
	}
}

function parseAllowedSkills(row: CronJobRow): { allowedSkills?: string[] } {
	if (row.action_allowed_skills_json === null) {
		return {};
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(row.action_allowed_skills_json);
	} catch {
		throw new Error(`cron job ${row.id} has invalid allowed skills JSON`);
	}
	if (!Array.isArray(parsed) || parsed.some((item) => typeof item !== "string")) {
		throw new Error(`cron job ${row.id} has invalid allowed skills`);
	}
	return { allowedSkills: parsed.map((item) => item.trim()).filter(Boolean) };
}

function parsePreprocess(row: CronJobRow): { preprocess?: CronPreprocessCommand } {
	if (row.action_preprocess_json === null) {
		return {};
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(row.action_preprocess_json);
	} catch {
		throw new Error(`cron job ${row.id} has invalid preprocess JSON`);
	}
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
		throw new Error(`cron job ${row.id} has invalid preprocess config`);
	}
	const raw = parsed as Record<string, unknown>;
	if (typeof raw.command !== "string" || !raw.command.trim()) {
		throw new Error(`cron job ${row.id} has invalid preprocess command`);
	}
	const args = Array.isArray(raw.args)
		? raw.args.map((arg) => {
				if (typeof arg !== "string") {
					throw new Error(`cron job ${row.id} has invalid preprocess args`);
				}
				return arg;
			})
		: undefined;
	const cwd = typeof raw.cwd === "string" && raw.cwd.trim() ? raw.cwd : undefined;
	const timeoutMs = typeof raw.timeoutMs === "number" ? raw.timeoutMs : undefined;
	const maxStdoutBytes = typeof raw.maxStdoutBytes === "number" ? raw.maxStdoutBytes : undefined;
	return {
		preprocess: {
			command: raw.command,
			...(args === undefined ? {} : { args }),
			...(cwd === undefined ? {} : { cwd }),
			...(timeoutMs === undefined ? {} : { timeoutMs }),
			...(maxStdoutBytes === undefined ? {} : { maxStdoutBytes }),
		},
	};
}

function parseDeliveryTarget(row: CronJobRow): CronDeliveryTarget {
	switch (row.delivery_target_kind ?? "origin") {
		case "home":
			return { kind: "home" };
		case "chat":
			if (typeof row.delivery_chat_id !== "number") {
				throw new Error(`cron job ${row.id} is missing delivery chat id`);
			}
			return {
				kind: "chat",
				chatId: row.delivery_chat_id,
				...(row.delivery_thread_id === null ? {} : { threadId: row.delivery_thread_id }),
			};
		case "origin":
			return {
				kind: "origin",
				...(typeof row.delivery_chat_id === "number" ? { chatId: row.delivery_chat_id } : {}),
				...(row.delivery_thread_id === null ? {} : { threadId: row.delivery_thread_id }),
			};
		default:
			throw new Error(
				`cron job ${row.id} has unsupported delivery target '${row.delivery_target_kind}'`,
			);
	}
}

function rowToJob(row: CronJobRow): CronJob {
	return {
		id: row.id,
		name: row.name,
		enabled: row.enabled === 1,
		running: row.running === 1,
		ownerId: row.owner_id,
		deliveryTarget: parseDeliveryTarget(row),
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
	actionPrompt: string | null;
	actionAllowedSkillsJson: string | null;
	actionPreprocessJson: string | null;
	actionReminderId: string | null;
	actionReminderRevision: number | null;
	actionDigestAtHour: number | null;
} {
	switch (action.kind) {
		case "social-heartbeat":
			return {
				actionKind: "social-heartbeat",
				actionServiceId: action.serviceId ?? null,
				actionPrompt: null,
				actionAllowedSkillsJson: null,
				actionPreprocessJson: null,
				actionReminderId: null,
				actionReminderRevision: null,
				actionDigestAtHour: null,
			};
		case "private-heartbeat":
			return {
				actionKind: "private-heartbeat",
				actionServiceId: null,
				actionPrompt: null,
				actionAllowedSkillsJson: null,
				actionPreprocessJson: null,
				actionReminderId: null,
				actionReminderRevision: null,
				actionDigestAtHour: null,
			};
		case "curator-scan":
			return {
				actionKind: "curator-scan",
				actionServiceId: null,
				actionPrompt: null,
				actionAllowedSkillsJson: null,
				actionPreprocessJson: null,
				actionReminderId: null,
				actionReminderRevision: null,
				actionDigestAtHour: null,
			};
		case "household-reminder":
			return {
				actionKind: "household-reminder",
				actionServiceId: null,
				actionPrompt: null,
				actionAllowedSkillsJson: null,
				actionPreprocessJson: null,
				actionReminderId: action.reminderId,
				actionReminderRevision: action.revision,
				actionDigestAtHour: null,
			};
		case "household-metrics-digest":
			return {
				actionKind: "household-metrics-digest",
				actionServiceId: null,
				actionPrompt: null,
				actionAllowedSkillsJson: null,
				actionPreprocessJson: null,
				actionReminderId: null,
				actionReminderRevision: null,
				actionDigestAtHour: action.atHour,
			};
		case "agent-prompt":
			return {
				actionKind: "agent-prompt",
				actionServiceId: null,
				actionPrompt: action.prompt,
				actionAllowedSkillsJson:
					action.allowedSkills === undefined ? null : JSON.stringify(action.allowedSkills),
				actionPreprocessJson:
					action.preprocess === undefined ? null : JSON.stringify(action.preprocess),
				actionReminderId: null,
				actionReminderRevision: null,
				actionDigestAtHour: null,
			};
		default: {
			const exhaustiveCheck: never = action;
			throw new Error(`Unsupported action: ${String(exhaustiveCheck)}`);
		}
	}
}

function encodeDeliveryTarget(target: CronDeliveryTarget | undefined): {
	deliveryTargetKind: "home" | "origin" | "chat";
	deliveryChatId: number | null;
	deliveryThreadId: number | null;
} {
	if (!target) {
		return {
			deliveryTargetKind: "origin",
			deliveryChatId: null,
			deliveryThreadId: null,
		};
	}

	switch (target.kind) {
		case "home":
			return {
				deliveryTargetKind: "home",
				deliveryChatId: null,
				deliveryThreadId: null,
			};
		case "origin":
			return {
				deliveryTargetKind: "origin",
				deliveryChatId: target.chatId ?? null,
				deliveryThreadId: target.threadId ?? null,
			};
		case "chat":
			return {
				deliveryTargetKind: "chat",
				deliveryChatId: target.chatId,
				deliveryThreadId: target.threadId ?? null,
			};
		default: {
			const exhaustiveCheck: never = target;
			throw new Error(`Unsupported delivery target: ${String(exhaustiveCheck)}`);
		}
	}
}

function validateAddInput(input: CronAddInput, nowMs: number): number | null {
	if (input.action.kind === "agent-prompt" && !input.action.prompt.trim()) {
		throw new Error("agent prompt cron jobs require a prompt");
	}
	if (input.action.kind === "agent-prompt") {
		if (
			input.action.allowedSkills?.some((skill) => !skill.trim() || /[\0\r\n]/.test(skill)) === true
		) {
			throw new Error("allowed skill names must be non-empty single-line strings");
		}
	}
	if (input.action.kind === "household-reminder") {
		if (!input.action.reminderId.trim()) throw new Error("household reminder id is required");
		if (!Number.isInteger(input.action.revision) || input.action.revision < 1) {
			throw new Error("household reminder revision must be a positive integer");
		}
		if (input.schedule.kind !== "at") {
			throw new Error("household reminder wake-ups must use an at schedule");
		}
	}
	if (input.deliveryTarget?.kind === "home" && !input.ownerId?.trim()) {
		throw new Error("home delivery requires ownerId");
	}
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
	const {
		actionKind,
		actionServiceId,
		actionPrompt,
		actionAllowedSkillsJson,
		actionPreprocessJson,
		actionReminderId,
		actionReminderRevision,
		actionDigestAtHour,
	} = encodeAction(input.action);
	const { deliveryTargetKind, deliveryChatId, deliveryThreadId } = encodeDeliveryTarget(
		input.deliveryTarget,
	);
	const enabled = input.enabled !== false;
	const ownerId = input.ownerId?.trim() || null;

	db.prepare(
		`INSERT INTO cron_jobs (
			id, name, enabled, running,
			schedule_kind, schedule_at, schedule_every_ms, schedule_cron,
			action_kind, action_service_id, action_prompt, action_allowed_skills_json, action_preprocess_json,
			action_reminder_id, action_reminder_revision, action_digest_at_hour,
			owner_id, delivery_target_kind, delivery_chat_id, delivery_thread_id,
			next_run_at, last_run_at, last_status, last_error,
			created_at, updated_at
		)
		VALUES (
			?, ?, ?, 0,
			?, ?, ?, ?,
			?, ?, ?, ?, ?, ?, ?, ?,
			?, ?, ?, ?,
			?, NULL, NULL, NULL,
			?, ?
		)`,
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
		actionPrompt,
		actionAllowedSkillsJson,
		actionPreprocessJson,
		actionReminderId,
		actionReminderRevision,
		actionDigestAtHour,
		ownerId,
		deliveryTargetKind,
		deliveryChatId,
		deliveryThreadId,
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

export function upsertHouseholdReminderCronWakeup(input: {
	readonly reminderId: string;
	readonly revision: number;
	readonly resolvedAtMs: number;
	readonly nowMs: number;
}): CronJob {
	const reminderId = input.reminderId.trim();
	if (!reminderId) throw new Error("household reminder id is required");
	if (!Number.isInteger(input.revision) || input.revision < 1) {
		throw new Error("household reminder revision must be a positive integer");
	}
	if (!Number.isSafeInteger(input.resolvedAtMs) || input.resolvedAtMs <= input.nowMs) {
		throw new Error("household reminder wake-up must be in the future");
	}
	const id = `household-reminder:${reminderId}`;
	getDb()
		.prepare(
			`INSERT INTO cron_jobs (
			 id, name, enabled, running,
			 schedule_kind, schedule_at, schedule_every_ms, schedule_cron,
			 action_kind, action_service_id, action_prompt, action_allowed_skills_json,
			 action_preprocess_json, action_reminder_id, action_reminder_revision,
			 owner_id, delivery_target_kind, delivery_chat_id, delivery_thread_id,
			 next_run_at, last_run_at, last_status, last_error, created_at, updated_at
			) VALUES (?, 'household reminder wake-up', 1, 0,
			 'at', ?, NULL, NULL,
			 'household-reminder', NULL, NULL, NULL, NULL, ?, ?,
			 NULL, 'origin', NULL, NULL,
			 ?, NULL, NULL, NULL, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				 name = excluded.name, enabled = 1,
			 schedule_kind = 'at', schedule_at = excluded.schedule_at,
			 schedule_every_ms = NULL, schedule_cron = NULL,
			 action_kind = 'household-reminder', action_service_id = NULL,
			 action_prompt = NULL, action_allowed_skills_json = NULL,
			 action_preprocess_json = NULL,
			 action_reminder_id = excluded.action_reminder_id,
			 action_reminder_revision = excluded.action_reminder_revision,
			 owner_id = NULL, delivery_target_kind = 'origin',
			 delivery_chat_id = NULL, delivery_thread_id = NULL,
			 next_run_at = excluded.next_run_at,
			 last_run_at = NULL, last_status = NULL, last_error = NULL,
			 updated_at = excluded.updated_at`,
		)
		.run(
			id,
			input.resolvedAtMs,
			reminderId,
			input.revision,
			input.resolvedAtMs,
			input.nowMs,
			input.nowMs,
		);
	const job = getCronJob(id);
	if (!job) throw new Error("household reminder wake-up persistence failure");
	return job;
}

export function pauseHouseholdReminderCronWakeup(
	reminderIdInput: string,
	nowMs = Date.now(),
): boolean {
	const reminderId = reminderIdInput.trim();
	if (!reminderId) throw new Error("household reminder id is required");
	return (
		getDb()
			.prepare(
				`UPDATE cron_jobs SET enabled = 0, next_run_at = NULL, updated_at = ?
				 WHERE id = ? AND action_kind = 'household-reminder' AND action_reminder_id = ?`,
			)
			.run(nowMs, `household-reminder:${reminderId}`, reminderId).changes > 0
	);
}

export function syncHouseholdMetricsDigestCron(input: {
	readonly enabled: boolean;
	readonly atHour: number;
	readonly nowMs?: number;
}): CronJob | null {
	const nowMs = input.nowMs ?? Date.now();
	if (!input.enabled) {
		getDb()
			.prepare(
				`UPDATE cron_jobs SET enabled = 0, running = 0, next_run_at = NULL, updated_at = ?
				 WHERE id = 'household-metrics-digest'
				   AND action_kind = 'household-metrics-digest'`,
			)
			.run(nowMs);
		return getCronJob("household-metrics-digest");
	}
	const nextRunAtMs = resolveNextJerusalemDigestAt(nowMs, input.atHour);
	getDb()
		.prepare(
			`INSERT INTO cron_jobs (
			 id, name, enabled, running,
			 schedule_kind, schedule_at, schedule_every_ms, schedule_cron,
			 action_kind, action_service_id, action_prompt, action_allowed_skills_json,
			 action_preprocess_json, action_reminder_id, action_reminder_revision,
			 action_digest_at_hour, owner_id, delivery_target_kind,
			 delivery_chat_id, delivery_thread_id, next_run_at,
			 last_run_at, last_status, last_error, created_at, updated_at
			) VALUES (
			 'household-metrics-digest', 'household metrics daily digest', ?, 0,
			 'at', ?, NULL, NULL,
			 'household-metrics-digest', NULL, NULL, NULL, NULL, NULL, NULL,
			 ?, NULL, 'origin', NULL, NULL, ?, NULL, NULL, NULL, ?, ?
			)
			ON CONFLICT(id) DO UPDATE SET
			 name = excluded.name, enabled = excluded.enabled, running = 0,
			 schedule_kind = 'at', schedule_at = excluded.schedule_at,
			 schedule_every_ms = NULL, schedule_cron = NULL,
			 action_kind = 'household-metrics-digest', action_service_id = NULL,
			 action_prompt = NULL, action_allowed_skills_json = NULL,
			 action_preprocess_json = NULL, action_reminder_id = NULL,
			 action_reminder_revision = NULL,
			 action_digest_at_hour = excluded.action_digest_at_hour,
			 owner_id = NULL, delivery_target_kind = 'origin',
			 delivery_chat_id = NULL, delivery_thread_id = NULL,
			 next_run_at = excluded.next_run_at, updated_at = excluded.updated_at`,
		)
		.run(1, nextRunAtMs, input.atHour, nextRunAtMs, nowMs, nowMs);
	const job = getCronJob("household-metrics-digest");
	if (!job) throw new Error("household metrics digest cron persistence failure");
	return job;
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

	// Do not touch `running` here. If the scheduler is mid-execution on this job,
	// clearing `running` would make it re-claimable and run concurrently with the
	// in-flight execution. The running flag is reset by completeClaimedCronJob when
	// the active run finishes (or by resetRunningCronJobs on startup).
	db.prepare(
		`UPDATE cron_jobs
		 SET enabled = ?, next_run_at = ?, updated_at = ?
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
	retryAtMs?: number;
}): CronJob | null {
	const db = getDb();
	const finishedAtMs = params.finishedAtMs ?? Date.now();

	db.transaction(() => {
		// Re-read the current enabled state inside the transaction. A disable issued
		// mid-run (setCronJobEnabled) must not be resurrected from the claim-time
		// snapshot in params.job.
		const current = db
			.prepare("SELECT enabled, action_kind, action_reminder_revision FROM cron_jobs WHERE id = ?")
			.get(params.job.id) as
			| { enabled: number; action_kind: string; action_reminder_revision: number | null }
			| undefined;
		const wakeupWasReplaced =
			params.job.action.kind === "household-reminder" &&
			current !== undefined &&
			(current.action_kind !== "household-reminder" ||
				current.action_reminder_revision !== params.job.action.revision);
		if (wakeupWasReplaced) {
			db.prepare(
				`INSERT INTO cron_runs (job_id, started_at, finished_at, status, message)
				 VALUES (?, ?, ?, ?, ?)`,
			).run(params.job.id, params.startedAtMs, finishedAtMs, params.status, params.message);
			db.prepare("UPDATE cron_jobs SET running = 0, updated_at = ? WHERE id = ?").run(
				finishedAtMs,
				params.job.id,
			);
			return;
		}

		let enabled = current ? current.enabled === 1 : params.job.enabled;
		let nextRunAtMs: number | null = null;

		let nextScheduleAtMs: number | null = null;
		if (
			enabled &&
			params.job.schedule.kind === "at" &&
			params.job.action.kind === "household-metrics-digest"
		) {
			nextRunAtMs = resolveNextJerusalemDigestAt(finishedAtMs, params.job.action.atHour);
			nextScheduleAtMs = nextRunAtMs;
		} else if (params.job.schedule.kind === "at") {
			const retryAtMs = params.retryAtMs;
			if (
				enabled &&
				params.job.action.kind === "household-reminder" &&
				params.status === "error" &&
				Number.isSafeInteger(retryAtMs) &&
				(retryAtMs as number) > finishedAtMs
			) {
				nextRunAtMs = retryAtMs as number;
			} else {
				enabled = false;
				nextRunAtMs = null;
			}
		} else if (enabled) {
			nextRunAtMs = computeNextRunAtMs(params.job.schedule, finishedAtMs);
		}

		db.prepare(
			`INSERT INTO cron_runs (job_id, started_at, finished_at, status, message)
			 VALUES (?, ?, ?, ?, ?)`,
		).run(params.job.id, params.startedAtMs, finishedAtMs, params.status, params.message);

		db.prepare(
			`UPDATE cron_jobs
			 SET enabled = ?,
			     running = 0,
			     schedule_at = COALESCE(?, schedule_at),
			     next_run_at = ?,
			     last_run_at = ?,
			     last_status = ?,
			     last_error = ?,
			     updated_at = ?
			 WHERE id = ?`,
		).run(
			enabled ? 1 : 0,
			nextScheduleAtMs,
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
