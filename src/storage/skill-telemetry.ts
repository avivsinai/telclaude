import { getChildLogger } from "../logging.js";
import { getDb } from "./db.js";

const logger = getChildLogger({ module: "skill-telemetry" });

export type SkillInvocationSource = "telegram" | "social";
export type SkillInvocationDecision = "allow" | "deny";
export type SkillInvocationResultStatus = "success" | "error" | "unknown";

export type RecordSkillInvocationInput = {
	sessionKey: string;
	turnIndex?: number;
	skillName: string;
	decision: SkillInvocationDecision;
	denyReason?: string;
	source: SkillInvocationSource;
	serviceId?: string;
	durationMs?: number;
	resultStatus?: SkillInvocationResultStatus;
	createdAt?: number;
};

export type SkillInvocationRow = {
	id: number;
	sessionKey: string;
	turnIndex: number | null;
	skillName: string;
	decision: SkillInvocationDecision;
	denyReason: string | null;
	source: SkillInvocationSource;
	serviceId: string | null;
	durationMs: number | null;
	resultStatus: SkillInvocationResultStatus | null;
	createdAt: number;
};

export type SkillInvocationSummary = {
	skillName: string;
	source: SkillInvocationSource;
	serviceId: string | null;
	totalCount: number;
	allowedCount: number;
	deniedCount: number;
	lastInvokedAt: number;
	lastAllowedAt: number | null;
};

const MAX_TEXT_LENGTH = 512;

function clampText(value: string | undefined): string | null {
	if (!value) return null;
	return value.length > MAX_TEXT_LENGTH ? value.slice(0, MAX_TEXT_LENGTH) : value;
}

function normalizeSource(source: string): SkillInvocationSource | null {
	if (source === "telegram" || source === "social") return source;
	return null;
}

/**
 * Record metadata-only Skill invocation telemetry.
 *
 * This is intentionally best-effort: storage failures must never affect
 * security enforcement in the PreToolUse hook.
 */
export async function recordSkillInvocation(input: RecordSkillInvocationInput): Promise<void> {
	try {
		const source = normalizeSource(input.source);
		if (!source) {
			logger.warn({ source: input.source }, "dropping skill telemetry with invalid source");
			return;
		}

		const sessionKey = input.sessionKey.trim();
		const skillName = input.skillName.trim();
		if (!sessionKey || !skillName) {
			logger.warn(
				{ hasSessionKey: Boolean(sessionKey), hasSkillName: Boolean(skillName) },
				"dropping incomplete skill telemetry",
			);
			return;
		}

		getDb()
			.prepare(
				`INSERT INTO skill_invocations (
					session_key,
					turn_index,
					skill_name,
					decision,
					deny_reason,
					source,
					service_id,
					duration_ms,
					result_status,
					created_at
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			)
			.run(
				sessionKey,
				input.turnIndex ?? null,
				clampText(skillName) ?? "unknown",
				input.decision,
				clampText(input.denyReason),
				source,
				clampText(input.serviceId),
				input.durationMs ?? null,
				input.resultStatus ?? null,
				input.createdAt ?? Date.now(),
			);
	} catch (error) {
		logger.warn({ error: String(error) }, "failed to record skill telemetry");
	}
}

export function listSkillInvocations(limit = 100): SkillInvocationRow[] {
	const rows = getDb()
		.prepare(
			`SELECT
				id,
				session_key,
				turn_index,
				skill_name,
				decision,
				deny_reason,
				source,
				service_id,
				duration_ms,
				result_status,
				created_at
			FROM skill_invocations
			ORDER BY created_at DESC, id DESC
			LIMIT ?`,
		)
		.all(Math.max(1, Math.min(limit, 1000))) as Array<{
		id: number;
		session_key: string;
		turn_index: number | null;
		skill_name: string;
		decision: SkillInvocationDecision;
		deny_reason: string | null;
		source: SkillInvocationSource;
		service_id: string | null;
		duration_ms: number | null;
		result_status: SkillInvocationResultStatus | null;
		created_at: number;
	}>;

	return rows.map((row) => ({
		id: row.id,
		sessionKey: row.session_key,
		turnIndex: row.turn_index,
		skillName: row.skill_name,
		decision: row.decision,
		denyReason: row.deny_reason,
		source: row.source,
		serviceId: row.service_id,
		durationMs: row.duration_ms,
		resultStatus: row.result_status,
		createdAt: row.created_at,
	}));
}

export function listSkillInvocationSummaries(): SkillInvocationSummary[] {
	const rows = getDb()
		.prepare(
			`SELECT
				skill_name,
				source,
				service_id,
				COUNT(*) AS total_count,
				SUM(CASE WHEN decision = 'allow' THEN 1 ELSE 0 END) AS allowed_count,
				SUM(CASE WHEN decision = 'deny' THEN 1 ELSE 0 END) AS denied_count,
				MAX(created_at) AS last_invoked_at,
				MAX(CASE WHEN decision = 'allow' THEN created_at ELSE NULL END) AS last_allowed_at
			FROM skill_invocations
			GROUP BY skill_name, source, service_id`,
		)
		.all() as Array<{
		skill_name: string;
		source: SkillInvocationSource;
		service_id: string | null;
		total_count: number;
		allowed_count: number | null;
		denied_count: number | null;
		last_invoked_at: number;
		last_allowed_at: number | null;
	}>;

	return rows.map((row) => ({
		skillName: row.skill_name,
		source: row.source,
		serviceId: row.service_id,
		totalCount: row.total_count,
		allowedCount: row.allowed_count ?? 0,
		deniedCount: row.denied_count ?? 0,
		lastInvokedAt: row.last_invoked_at,
		lastAllowedAt: row.last_allowed_at,
	}));
}
