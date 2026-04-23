import fs from "node:fs";
import type { FastifyInstance } from "fastify";
import { cancelJob, getJobByShortId, listJobs } from "../../background/index.js";
import type { BackgroundJob, BackgroundJobStatus } from "../../background/types.js";
import { collectSessionRows, type SessionListRow } from "../../commands/sessions.js";
import { loadConfig, type TelclaudeConfig } from "../../config/config.js";
import {
	getCronCoverage,
	getCronStatusSummary,
	listCronJobs,
	listCronRuns,
} from "../../cron/store.js";
import type { CronAction, CronDeliveryTarget, CronJob, CronSchedule } from "../../cron/types.js";
import { getChildLogger, getResolvedLoggerSettings } from "../../logging.js";
import { getEntries } from "../../memory/store.js";
import type { MemoryCategory, MemoryEntry, MemorySource } from "../../memory/types.js";
import {
	type ConnectorHealth,
	checkProviderHealth,
	type HealthAlert,
	type HealthCheckResult,
} from "../../providers/provider-health.js";
import { createAuditLogger } from "../../security/audit.js";
import { redactSecrets } from "../../security/output-filter.js";
import type { AuditEntry } from "../../security/types.js";
import { collectPersonaStatus, type PersonaStatus } from "../../status/personas.js";

const logger = getChildLogger({ module: "dashboard-operator" });

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;
const LOG_TAIL_BYTES = 512 * 1024;
const STRING_LIMIT = 180;

const BACKGROUND_STATUSES: readonly BackgroundJobStatus[] = [
	"queued",
	"running",
	"completed",
	"failed",
	"cancelled",
	"interrupted",
];

const LOG_LEVELS = new Map<number, string>([
	[10, "trace"],
	[20, "debug"],
	[30, "info"],
	[40, "warn"],
	[50, "error"],
	[60, "fatal"],
]);

const LOG_LEVEL_VALUES = new Map<string, number>(
	[...LOG_LEVELS.entries()].map(([value, name]) => [name, value]),
);

const SAFE_LOG_CONTEXT_KEYS = new Set([
	"action",
	"attempt",
	"chatId",
	"connector",
	"health",
	"jobId",
	"level",
	"module",
	"poolKey",
	"provider",
	"providerId",
	"requestId",
	"scope",
	"service",
	"serviceId",
	"shortId",
	"state",
	"status",
	"tier",
	"userId",
]);

type QueryMap = Record<string, string | undefined>;

type DashboardLogEntry = {
	timestamp: string | null;
	level: string;
	component: string;
	message: string;
	context: Record<string, string | number | boolean | null>;
};

function parseLimit(raw: string | undefined, fallback = DEFAULT_LIMIT): number {
	if (!raw) return fallback;
	const n = Number.parseInt(raw, 10);
	if (!Number.isFinite(n) || n <= 0) return fallback;
	return Math.min(n, MAX_LIMIT);
}

function clampText(value: string | null | undefined, limit = STRING_LIMIT): string | null {
	if (!value) return null;
	const redacted = redactSecrets(value).replace(/\s+/g, " ").trim();
	if (!redacted) return null;
	return redacted.length <= limit ? redacted : `${redacted.slice(0, limit - 3)}...`;
}

function compactRef(value: string): string {
	if (value.length <= 16) return value;
	return `${value.slice(0, 6)}...${value.slice(-6)}`;
}

function statusFromAge(ageMs: number): "active" | "idle" | "stale" {
	if (ageMs <= 30 * 60_000) return "active";
	if (ageMs <= 24 * 60 * 60_000) return "idle";
	return "stale";
}

function sessionPersona(_row: SessionListRow): "private" {
	return "private";
}

function summarizeSession(row: SessionListRow) {
	return {
		key: row.key,
		source: row.kind,
		persona: sessionPersona(row),
		model: null,
		status: statusFromAge(row.ageMs),
		updatedAtMs: row.updatedAt,
		ageMs: row.ageMs,
		systemSent: row.systemSent,
		sessionRef: compactRef(row.sessionId),
		errorSummary: null,
	};
}

function runStatusFromOutcome(outcome: AuditEntry["outcome"]) {
	switch (outcome) {
		case "success":
			return "completed";
		case "blocked":
			return "blocked";
		case "timeout":
			return "timeout";
		case "rate_limited":
			return "rate_limited";
		case "error":
			return "error";
	}
}

function summarizeAuditRun(entry: AuditEntry) {
	const finishedAtMs = entry.timestamp.getTime();
	const durationMs = entry.executionTimeMs ?? null;
	const startedAtMs = durationMs === null ? null : Math.max(0, finishedAtMs - durationMs);
	return {
		id: entry.requestId,
		source: "telegram",
		persona: "private",
		model: null,
		status: runStatusFromOutcome(entry.outcome),
		startedAtMs,
		finishedAtMs,
		durationMs,
		errorSummary: clampText(
			entry.errorType ?? (entry.outcome === "success" ? null : entry.outcome),
		),
		tier: entry.permissionTier,
	};
}

function parseStatuses(raw: string | undefined): BackgroundJobStatus[] | undefined {
	if (!raw) return undefined;
	const requested = raw
		.split(",")
		.map((part) => part.trim())
		.filter(Boolean);
	if (requested.length === 0) return undefined;
	const valid = requested.filter((status): status is BackgroundJobStatus =>
		BACKGROUND_STATUSES.includes(status as BackgroundJobStatus),
	);
	return valid.length > 0 ? valid : undefined;
}

function summarizeBackgroundJob(job: BackgroundJob) {
	return {
		id: job.id,
		shortId: job.shortId,
		title: clampText(job.title) ?? "(untitled)",
		description: clampText(job.description),
		status: job.status,
		tier: job.tier,
		userId: clampText(job.userId, 80),
		chatId: job.chatId,
		threadId: job.threadId,
		payloadKind: job.payload.kind,
		createdAtMs: job.createdAtMs,
		startedAtMs: job.startedAtMs,
		completedAtMs: job.completedAtMs,
		cancelledAtMs: job.cancelledAtMs,
		errorSummary: clampText(job.error ?? job.result?.message ?? null),
		canCancel: job.status === "queued" || job.status === "running",
	};
}

function formatSchedule(schedule: CronSchedule): string {
	switch (schedule.kind) {
		case "at":
			return `at ${schedule.at}`;
		case "every":
			return `every ${Math.round(schedule.everyMs / 60_000)}m`;
		case "cron":
			return `cron ${schedule.expr}`;
	}
}

function summarizeAction(action: CronAction): {
	actionKind: CronAction["kind"];
	actionSummary: string;
} {
	switch (action.kind) {
		case "social-heartbeat":
			return {
				actionKind: action.kind,
				actionSummary: action.serviceId
					? `social heartbeat (${action.serviceId})`
					: "social heartbeat (all)",
			};
		case "private-heartbeat":
			return { actionKind: action.kind, actionSummary: "private heartbeat" };
		case "agent-prompt":
			return { actionKind: action.kind, actionSummary: "agent prompt (redacted)" };
	}
}

function summarizeDelivery(target: CronDeliveryTarget): string {
	switch (target.kind) {
		case "home":
			return "home";
		case "origin":
			return target.chatId ? "origin chat" : "origin";
		case "chat":
			return "chat";
	}
}

function summarizeCronJob(job: CronJob) {
	const action = summarizeAction(job.action);
	return {
		id: job.id,
		name: clampText(job.name) ?? "(unnamed)",
		enabled: job.enabled,
		running: job.running,
		ownerId: clampText(job.ownerId, 80),
		delivery: summarizeDelivery(job.deliveryTarget),
		schedule: formatSchedule(job.schedule),
		...action,
		nextRunAtMs: job.nextRunAtMs,
		lastRunAtMs: job.lastRunAtMs,
		lastStatus: job.lastStatus,
		lastErrorSummary: clampText(job.lastError),
		createdAtMs: job.createdAtMs,
		updatedAtMs: job.updatedAtMs,
		recentRuns: listCronRuns(job.id, 3).map((run) => ({
			jobId: run.jobId,
			startedAtMs: run.startedAtMs,
			finishedAtMs: run.finishedAtMs,
			status: run.status,
			message: clampText(run.message),
		})),
	};
}

function queueStatus(entry: MemoryEntry): "awaiting_promotion" | "awaiting_heartbeat" | "posted" {
	if (entry._provenance.postedAt) return "posted";
	if (entry._provenance.trust === "trusted" && entry._provenance.promotedAt) {
		return "awaiting_heartbeat";
	}
	return "awaiting_promotion";
}

function summarizeQueueEntry(entry: MemoryEntry) {
	return {
		id: entry.id,
		source: entry._provenance.source,
		trust: entry._provenance.trust,
		status: queueStatus(entry),
		createdAtMs: entry._provenance.createdAt,
		promotedAtMs: entry._provenance.promotedAt ?? null,
		postedAtMs: entry._provenance.postedAt ?? null,
		metadataKind:
			entry.metadata && typeof entry.metadata.action === "string" ? entry.metadata.action : null,
		nextAction:
			entry._provenance.trust === "trusted"
				? "wait for heartbeat or run /social run"
				: `/social promote ${entry.id}`,
	};
}

function getMemoryEntries(query: {
	categories: MemoryCategory[];
	trust: Array<MemoryEntry["_provenance"]["trust"]>;
	sources: MemorySource[];
	promoted?: boolean;
	posted?: boolean;
	limit?: number;
	order?: "asc" | "desc";
}): MemoryEntry[] {
	try {
		return getEntries(query);
	} catch (err) {
		logger.warn({ error: String(err) }, "dashboard memory query failed");
		return [];
	}
}

function countIdentityEntries(
	source: MemorySource,
): Record<"profile" | "interests" | "meta", number> {
	const entries = getMemoryEntries({
		categories: ["profile", "interests", "meta"],
		trust: ["trusted"],
		sources: [source],
		limit: 200,
	});
	return {
		profile: entries.filter((entry) => entry.category === "profile").length,
		interests: entries.filter((entry) => entry.category === "interests").length,
		meta: entries.filter((entry) => entry.category === "meta").length,
	};
}

function summarizeSocialService(service: NonNullable<TelclaudeConfig["socialServices"]>[number]) {
	return {
		id: service.id,
		type: service.type,
		enabled: service.enabled,
		hasHandle: Boolean(service.handle),
		displayName: clampText(service.displayName, 80),
		heartbeatEnabled: service.heartbeatEnabled,
		heartbeatIntervalHours: service.heartbeatIntervalHours,
		notifyOnHeartbeat: service.notifyOnHeartbeat,
		enableSkills: service.enableSkills,
		allowedSkillsCount: service.allowedSkills?.length ?? 0,
		hasAgentUrl: Boolean(service.agentUrl),
	};
}

function summarizePersonaForDashboard(
	status: PersonaStatus,
	memoryCounts: Record<"profile" | "interests" | "meta", number>,
	services: ReturnType<typeof summarizeSocialService>[] = [],
) {
	return {
		status: status.health,
		source: status.memory.source,
		summary: status.summary,
		memoryCounts,
		profile: {
			configured: status.profile.configured,
			claudeHome: status.profile.claudeHome,
			source: status.profile.source,
		},
		agent: {
			configured: status.agent.configured,
			source: status.agent.source,
			endpoint: status.agent.endpoint,
			reachability: status.agent.reachability,
			checkedAt: status.agent.checkedAt,
			error: status.agent.error,
		},
		skills: {
			policy: status.skills.policy,
			effectiveCount: status.skills.effective.length,
			activeCatalogCount: status.skills.activeCatalog.length,
			allowedCount: status.skills.allowed.length,
			failClosed: status.skills.failClosed,
		},
		plugins: {
			configured: status.plugins.configured,
			enabledCount: status.plugins.enabled.length,
			installedCount: status.plugins.installed.length,
			error: status.plugins.error,
		},
		filesystem: status.filesystem,
		providers: {
			summary: status.providers.summary,
			providerIds: status.providers.providerIds,
			serviceIds: status.providers.serviceIds,
			privateEndpointCount: status.providers.privateEndpointCount,
			directProviderFetch: status.providers.directProviderFetch,
			relayProxied: status.providers.relayProxied,
		},
		operations: status.operations,
		boundaries: status.boundaries,
		...(services.length ? { services } : {}),
	};
}

function primitiveContextValue(value: unknown): string | number | boolean | null | undefined {
	if (value === null) return null;
	if (typeof value === "string") return clampText(value, 120);
	if (typeof value === "number" || typeof value === "boolean") return value;
	return undefined;
}

function parsePinoLine(line: string): DashboardLogEntry | null {
	try {
		const parsed = JSON.parse(line) as Record<string, unknown>;
		const levelNumber = typeof parsed.level === "number" ? parsed.level : null;
		const level =
			levelNumber === null
				? typeof parsed.level === "string"
					? parsed.level
					: "info"
				: (LOG_LEVELS.get(levelNumber) ?? "info");
		const component =
			typeof parsed.module === "string" && parsed.module.trim() ? parsed.module.trim() : "unknown";
		const message = clampText(typeof parsed.msg === "string" ? parsed.msg : "", 240) ?? "";
		const context: Record<string, string | number | boolean | null> = {};
		for (const [key, value] of Object.entries(parsed)) {
			if (!SAFE_LOG_CONTEXT_KEYS.has(key) || key === "module" || key === "level") continue;
			const safe = primitiveContextValue(value);
			if (safe !== undefined) context[key] = safe;
		}
		return {
			timestamp: typeof parsed.time === "string" ? parsed.time : null,
			level,
			component,
			message,
			context,
		};
	} catch {
		return null;
	}
}

async function readTail(filePath: string, maxBytes = LOG_TAIL_BYTES): Promise<string> {
	const handle = await fs.promises.open(filePath, "r");
	try {
		const stat = await handle.stat();
		const start = Math.max(0, stat.size - maxBytes);
		const length = stat.size - start;
		const buf = Buffer.alloc(length);
		await handle.read(buf, 0, length, start);
		const text = buf.toString("utf8");
		if (start === 0) return text;
		const firstNewline = text.indexOf("\n");
		return firstNewline >= 0 ? text.slice(firstNewline + 1) : text;
	} finally {
		await handle.close();
	}
}

async function readLogEntries(options: {
	limit: number;
	component?: string;
	level?: string;
	minLevel?: string;
}): Promise<DashboardLogEntry[]> {
	const settings = getResolvedLoggerSettings();
	let content = "";
	try {
		content = await readTail(settings.file);
	} catch {
		return [];
	}
	const minLevelValue = options.minLevel ? LOG_LEVEL_VALUES.get(options.minLevel) : undefined;
	const entries = content
		.split(/\r?\n/)
		.filter(Boolean)
		.map(parsePinoLine)
		.filter((entry): entry is DashboardLogEntry => entry !== null)
		.filter((entry) => {
			if (options.component && entry.component !== options.component) return false;
			if (options.level && entry.level !== options.level) return false;
			if (minLevelValue !== undefined) {
				const entryLevel = LOG_LEVEL_VALUES.get(entry.level) ?? 30;
				if (entryLevel < minLevelValue) return false;
			}
			return true;
		});
	return entries.slice(-options.limit).reverse();
}

function summarizeConnector(name: string, connector: ConnectorHealth) {
	return {
		name,
		status: connector.status,
		lastSuccess: clampText(connector.lastSuccess, 80),
		lastAttempt: clampText(connector.lastAttempt, 80),
		failureCount: connector.failureCount ?? 0,
		driftSignals: connector.driftSignals?.slice(0, 5).map((signal) => clampText(signal, 80) ?? ""),
	};
}

function summarizeAlert(alert: HealthAlert) {
	return {
		level: alert.level,
		connector: clampText(alert.connector, 80),
		since: clampText(alert.since, 80),
	};
}

function summarizeProvider(result: HealthCheckResult) {
	const connectors = Object.entries(result.response?.connectors ?? {}).map(([name, connector]) =>
		summarizeConnector(name, connector),
	);
	const alerts = (result.response?.alerts ?? []).map(summarizeAlert);
	return {
		id: result.providerId,
		reachable: result.reachable,
		status: result.response?.status ?? (result.reachable ? "unknown" : "unreachable"),
		errorSummary: clampText(result.error),
		failureCount:
			(result.reachable ? 0 : 1) +
			alerts.length +
			connectors.filter((connector) => connector.status !== "ok").length,
		connectors,
		alerts,
	};
}

async function readProviderTransitions(limit = 20) {
	const entries = await readLogEntries({
		limit: Math.min(limit * 4, MAX_LIMIT),
		component: "provider-health",
	});
	return entries
		.filter((entry) => /provider (healthy|not healthy|health check failed)/i.test(entry.message))
		.slice(0, limit)
		.map((entry) => ({
			timestamp: entry.timestamp,
			level: entry.level,
			provider: entry.context.provider ?? entry.context.providerId ?? null,
			status: entry.context.status ?? null,
			message: entry.message,
		}));
}

export async function registerOperatorRoutes(server: FastifyInstance): Promise<void> {
	server.get("/api/operator/sessions-runs", async (request, reply) => {
		try {
			const query = request.query as QueryMap;
			const limit = parseLimit(query.limit);
			const cfg = loadConfig();
			const sessions = collectSessionRows({ limit }).map(summarizeSession);
			const auditLogger = createAuditLogger({
				enabled: cfg.security?.audit?.enabled !== false,
				logFile: cfg.security?.audit?.logFile,
			});
			const runs = (await auditLogger.readRecent(limit)).map(summarizeAuditRun).reverse();
			return reply.send({ ok: true, sessions, runs });
		} catch (err) {
			logger.warn({ error: String(err) }, "operator sessions-runs failed");
			return reply.status(500).send({ ok: false, error: "failed to load session summaries" });
		}
	});

	server.get("/api/operator/logs", async (request, reply) => {
		const query = request.query as QueryMap;
		const component = query.component?.trim() || undefined;
		const level = query.level?.trim() || undefined;
		const minLevel = query.minLevel?.trim() || undefined;
		const limit = parseLimit(query.limit, 100);
		const entries = await readLogEntries({ limit, component, level, minLevel });
		return reply.send({
			ok: true,
			filters: {
				component: component ?? null,
				level: level ?? null,
				minLevel: minLevel ?? null,
				limit,
			},
			entries,
		});
	});

	server.get("/api/operator/background-jobs", async (request, reply) => {
		try {
			const query = request.query as QueryMap;
			const limit = parseLimit(query.limit);
			const statuses = parseStatuses(query.status);
			const jobs = listJobs({ limit, ...(statuses ? { statuses } : {}) }).map(
				summarizeBackgroundJob,
			);
			return reply.send({ ok: true, jobs });
		} catch (err) {
			logger.warn({ error: String(err) }, "operator background jobs failed");
			return reply.status(500).send({ ok: false, error: "failed to load background jobs" });
		}
	});

	server.post("/api/operator/background-jobs/:shortId/cancel", async (request, reply) => {
		try {
			const params = request.params as { shortId?: string };
			const shortId = params.shortId?.trim();
			if (!shortId) {
				return reply.status(400).send({ ok: false, error: "missing job id" });
			}
			const existing = getJobByShortId(shortId);
			if (!existing) {
				return reply.status(404).send({ ok: false, error: "background job not found" });
			}
			const { transitioned, job } = cancelJob(existing.id);
			return reply.send({
				ok: true,
				transitioned,
				job: job ? summarizeBackgroundJob(job) : null,
			});
		} catch (err) {
			logger.warn({ error: String(err) }, "operator background cancel failed");
			return reply.status(500).send({ ok: false, error: "failed to cancel background job" });
		}
	});

	server.get("/api/operator/cron", async (_request, reply) => {
		try {
			const cfg = loadConfig();
			const jobs = listCronJobs({ includeDisabled: true }).map(summarizeCronJob);
			return reply.send({
				ok: true,
				config: {
					enabled: cfg.cron.enabled,
					pollIntervalSeconds: cfg.cron.pollIntervalSeconds,
					timeoutSeconds: cfg.cron.timeoutSeconds,
				},
				summary: getCronStatusSummary(),
				coverage: getCronCoverage(),
				jobs,
			});
		} catch (err) {
			logger.warn({ error: String(err) }, "operator cron failed");
			return reply.status(500).send({ ok: false, error: "failed to load cron jobs" });
		}
	});

	server.get("/api/operator/social-queue", async (_request, reply) => {
		try {
			const cfg = loadConfig();
			const pending = [
				...getMemoryEntries({
					categories: ["posts"],
					trust: ["quarantined"],
					sources: ["telegram"],
					posted: false,
					limit: 20,
					order: "desc",
				}),
				...getMemoryEntries({
					categories: ["posts"],
					trust: ["untrusted"],
					sources: ["social"],
					posted: false,
					limit: 20,
					order: "desc",
				}),
			]
				.sort((a, b) => b._provenance.createdAt - a._provenance.createdAt)
				.slice(0, 20)
				.map(summarizeQueueEntry);
			const promoted = getMemoryEntries({
				categories: ["posts"],
				trust: ["trusted"],
				sources: ["telegram", "social"],
				promoted: true,
				posted: false,
				limit: 20,
				order: "asc",
			}).map(summarizeQueueEntry);
			const services = (cfg.socialServices ?? []).map(summarizeSocialService);
			const nextOperatorAction =
				pending.length > 0
					? "/social queue"
					: promoted.length > 0
						? "/social run"
						: services.some((svc) => svc.enabled)
							? "monitor"
							: "configure socialServices";
			return reply.send({
				ok: true,
				summary: {
					pending: pending.length,
					promoted: promoted.length,
					enabledServices: services.filter((svc) => svc.enabled).length,
				},
				nextOperatorAction,
				services,
				pending,
				promoted,
			});
		} catch (err) {
			logger.warn({ error: String(err) }, "operator social queue failed");
			return reply.status(500).send({ ok: false, error: "failed to load social queue" });
		}
	});

	server.get("/api/operator/personas", async (_request, reply) => {
		try {
			const cfg = loadConfig();
			const services = (cfg.socialServices ?? []).map(summarizeSocialService);
			const personaSnapshot = await collectPersonaStatus({ config: cfg, probeAgents: false });
			return reply.send({
				ok: true,
				securityProfile: cfg.security?.profile ?? "simple",
				personaSnapshot,
				privatePersona: {
					...summarizePersonaForDashboard(
						personaSnapshot.personas.private,
						countIdentityEntries("telegram"),
					),
					heartbeatEnabled: cfg.telegram.heartbeat?.enabled ?? false,
					heartbeatIntervalHours: cfg.telegram.heartbeat?.intervalHours ?? null,
				},
				socialPersona: summarizePersonaForDashboard(
					personaSnapshot.personas.social,
					countIdentityEntries("social"),
					services,
				),
			});
		} catch (err) {
			logger.warn({ error: String(err) }, "operator personas failed");
			return reply.status(500).send({ ok: false, error: "failed to load persona status" });
		}
	});

	server.get("/api/operator/provider-health", async (_request, reply) => {
		try {
			const cfg = loadConfig();
			const results = await Promise.all(
				(cfg.providers ?? []).map((provider) => checkProviderHealth(provider.id, provider.baseUrl)),
			);
			const providers = results.map(summarizeProvider);
			return reply.send({
				ok: true,
				providers,
				transitions: await readProviderTransitions(),
			});
		} catch (err) {
			logger.warn({ error: String(err) }, "operator provider health failed");
			return reply.status(500).send({ ok: false, error: "failed to load provider health" });
		}
	});
}
