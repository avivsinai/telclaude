import crypto from "node:crypto";
import fs from "node:fs";
import { type CronOverview, collectCronOverview } from "../commands/cron.js";
import { collectSessionRows, type SessionListRow } from "../commands/sessions.js";
import {
	type ExternalProviderConfig,
	getConfigPath,
	loadConfig,
	type SocialServiceConfig,
	type TelclaudeConfig,
} from "../config/config.js";
import { resolveRuntimeConfigPath } from "../config/path.js";
import { getActivitySummary } from "../social/activity-log.js";
import { getDb } from "../storage/db.js";
import { CONFIG_DIR, normalizeTelegramId } from "../utils.js";

export type HermesInventoryStatus = "complete" | "partial";
export type HermesInventoryTrustDomain = "private" | "social" | "provider" | "system" | "unknown";

export type HermesInventoryWorkflow = {
	workflow_id: string;
	owner: string;
	trust_domain: HermesInventoryTrustDomain;
	active: boolean;
	current_surface: string;
	hermes_target: string;
	status: "inventory_only" | "included" | "disabled" | "blocked";
	p_class: "unclassified" | "P0" | "P1" | "P2";
	source_refs: string[];
	queue_refs: string[];
	fixture_ids: string[];
	unresolved_decision_ids: string[];
	risk_notes: string[];
};

export type HermesInventorySnapshot = {
	schemaVersion: 1;
	generatedAt: string;
	status: HermesInventoryStatus;
	source: {
		configPath: string;
		runtimeConfigPath: string;
		privateConfigPresent: boolean;
		dataDir: string;
	};
	summary: {
		workflows: number;
		actors: number;
		sessions: number;
		providers: number;
		socialServices: number;
		cronJobs: number;
		pendingQueues: HermesPendingQueueSummary;
		issues: number;
	};
	config: {
		security: {
			profile: string;
			defaultTier: string;
			userOverrides: number;
			privateEndpoints: number;
		};
		telegram: {
			botTokenPresent: boolean;
			allowedChatCount: number;
			webhookConfigured: boolean;
			heartbeatEnabled: boolean;
			groupChatEnabled: boolean;
		};
		profiles: Array<{
			id: string;
			label: string;
			allowedSkillCount: number | null;
			soulPathPresent: boolean;
			defaultModelPresent: boolean;
		}>;
		cron: {
			enabled: boolean;
			pollIntervalSeconds: number;
			timeoutSeconds: number;
		};
		network: {
			mode: string;
			privateEndpointCount: number;
		};
		dashboard: {
			enabled: boolean;
			port: number | null;
		};
		webhooks: {
			enabled: boolean;
			port: number;
		};
	};
	actors: Array<{
		id: string;
		kind: "telegram-chat" | "operator-profile" | "social-service" | "provider" | "system";
		trust_domain: HermesInventoryTrustDomain;
		source_ref: string;
	}>;
	sessions: {
		rows: Array<{
			keyRef: string;
			kind: SessionListRow["kind"];
			sessionRef: string;
			updatedAt: string;
			ageMs: number;
			systemSent: boolean;
		}>;
		staleCount: number;
	};
	cron: {
		config: {
			enabled: boolean;
			pollIntervalSeconds: number;
			timeoutSeconds: number;
		};
		summary: CronOverview["summary"];
		coverage: CronOverview["coverage"];
		jobs: Array<{
			id: string;
			name: string;
			enabled: boolean;
			running: boolean;
			ownerRef: string | null;
			deliveryTargetKind: string;
			scheduleKind: string;
			action: {
				kind: string;
				serviceId?: string;
				promptPresent: boolean;
				allowedSkillCount: number | null;
				preprocessPresent: boolean;
			};
			nextRunAt: string | null;
			lastRunAt: string | null;
			lastStatus: string | null;
		}>;
	};
	social: {
		services: Array<{
			id: string;
			type: string;
			enabled: boolean;
			handlePresent: boolean;
			displayNamePresent: boolean;
			apiKeyPresent: boolean;
			agentUrlPresent: boolean;
			heartbeatEnabled: boolean;
			enableSkills: boolean;
			allowedSkillCount: number | null;
			agentSkillCount: number;
			notifyOnHeartbeat: string;
		}>;
		activity: Array<{ serviceId: string; type: string; count: number }>;
	};
	providers: Array<{
		id: string;
		services: string[];
		descriptionPresent: boolean;
		endpoint: {
			scheme: string | null;
			host: string | null;
			port: string | null;
			baseUrlPresent: boolean;
			parseError: string | null;
		};
	}>;
	queues: HermesQueueSnapshot;
	workflows: HermesInventoryWorkflow[];
	risks: string[];
	collectorErrors: Array<{ collector: string; error: string }>;
};

export type HermesPendingQueueSummary = {
	approvals: number;
	planApprovals: number;
	cards: number;
	backgroundJobs: number;
	socialItems: number;
	curatorItems: number;
	pairingPendingRequests: number;
	pairingActiveLockouts: number;
};

export type HermesQueueSnapshot = {
	approvals: { pending: number; expired: number };
	planApprovals: { pending: number; expired: number };
	cards: { active: number; expired: number; byStatus: Record<string, number> };
	backgroundJobs: { active: number; byStatus: Record<string, number> };
	pairing: { pendingRequests: number; activePairs: number; activeLockouts: number };
	allowlist: { active: number; total: number };
	curator: { open: number; byStatus: Record<string, number> };
	social: { activeItems: number };
	webhooks: { enabled: number; total: number };
	memory: { entries: number; episodes: number };
};

type InventoryBuildInput = {
	config: TelclaudeConfig;
	source: HermesInventorySnapshot["source"];
	sessions: SessionListRow[];
	cron: CronOverview;
	queues: HermesQueueSnapshot;
	socialActivity: Array<{ serviceId: string; type: string; count: number }>;
	generatedAt?: Date;
	redactionSalt?: string;
	collectorErrors?: Array<{ collector: string; error: string }>;
};

const DEFAULT_QUEUE_SNAPSHOT: HermesQueueSnapshot = {
	approvals: { pending: 0, expired: 0 },
	planApprovals: { pending: 0, expired: 0 },
	cards: { active: 0, expired: 0, byStatus: {} },
	backgroundJobs: { active: 0, byStatus: {} },
	pairing: { pendingRequests: 0, activePairs: 0, activeLockouts: 0 },
	allowlist: { active: 0, total: 0 },
	curator: { open: 0, byStatus: {} },
	social: { activeItems: 0 },
	webhooks: { enabled: 0, total: 0 },
	memory: { entries: 0, episodes: 0 },
};

export function collectHermesInventory(): HermesInventorySnapshot {
	const collectorErrors: Array<{ collector: string; error: string }> = [];
	const config = loadConfig();
	const configPath = getConfigPath();
	const source = {
		configPath,
		runtimeConfigPath: resolveRuntimeConfigPath(configPath),
		privateConfigPresent: privateConfigPresent(),
		dataDir: process.env.TELCLAUDE_DATA_DIR || CONFIG_DIR,
	};

	return buildHermesInventorySnapshot({
		config,
		source,
		sessions: collectSafely("sessions", () => collectSessionRows(), [], collectorErrors),
		cron: collectSafely(
			"cron",
			() => collectCronOverview({ includeDisabled: true }),
			emptyCron(config),
			collectorErrors,
		),
		queues: collectSafely(
			"queues",
			() => collectQueueSnapshot(),
			DEFAULT_QUEUE_SNAPSHOT,
			collectorErrors,
		),
		socialActivity: collectSafely(
			"social.activity",
			() => getActivitySummary(undefined, 24),
			[],
			collectorErrors,
		),
		collectorErrors,
	});
}

export function buildHermesInventorySnapshot(input: InventoryBuildInput): HermesInventorySnapshot {
	const refKey = input.redactionSalt ?? resolveInventoryRefKey(input.config);
	const actors = collectActors(input.config, refKey);
	const workflows = collectWorkflows(input.config, input.cron, input.queues, refKey);
	const risks = collectRisks(input.config, input.queues, workflows);
	const pendingQueues = summarizePendingQueues(input.queues);
	const generatedAt = input.generatedAt ?? new Date();

	return {
		schemaVersion: 1,
		generatedAt: generatedAt.toISOString(),
		status: input.collectorErrors && input.collectorErrors.length > 0 ? "partial" : "complete",
		source: input.source,
		summary: {
			workflows: workflows.length,
			actors: actors.length,
			sessions: input.sessions.length,
			providers: input.config.providers.length,
			socialServices: input.config.socialServices.length,
			cronJobs: input.cron.jobs.length,
			pendingQueues,
			issues: risks.length + (input.collectorErrors?.length ?? 0),
		},
		config: {
			security: {
				profile: stringOrUnknown(input.config.security.profile),
				defaultTier: stringOrUnknown(input.config.security.permissions?.defaultTier ?? "READ_ONLY"),
				userOverrides: Object.keys(input.config.security.permissions?.users ?? {}).length,
				privateEndpoints: input.config.security.network?.privateEndpoints?.length ?? 0,
			},
			telegram: {
				botTokenPresent: Boolean(input.config.telegram.botToken),
				allowedChatCount: input.config.telegram.allowedChats?.length ?? 0,
				webhookConfigured: Boolean(input.config.telegram.webhook),
				heartbeatEnabled: input.config.telegram.heartbeat?.enabled === true,
				groupChatEnabled: Boolean(input.config.telegram.groupChat),
			},
			profiles: input.config.profiles.map((profile) => ({
				id: profile.id,
				label: profile.label,
				allowedSkillCount: profile.allowedSkills?.length ?? null,
				soulPathPresent: Boolean(profile.soulPath),
				defaultModelPresent: Boolean(profile.defaultModel),
			})),
			cron: {
				enabled: input.config.cron.enabled,
				pollIntervalSeconds: input.config.cron.pollIntervalSeconds,
				timeoutSeconds: input.config.cron.timeoutSeconds,
			},
			network: {
				mode: process.env.TELCLAUDE_NETWORK_MODE || "restricted",
				privateEndpointCount: input.config.security.network?.privateEndpoints?.length ?? 0,
			},
			dashboard: {
				enabled: input.config.dashboard.enabled,
				port: input.config.dashboard.port ?? null,
			},
			webhooks: {
				enabled: input.config.webhooks.enabled,
				port: input.config.webhooks.port,
			},
		},
		actors,
		sessions: {
			rows: input.sessions.map((row) => sanitizeSessionRow(row, refKey)),
			staleCount: input.sessions.filter((session) => session.ageMs > 24 * 60 * 60 * 1000).length,
		},
		cron: {
			config: {
				enabled: input.cron.enabled,
				pollIntervalSeconds: input.cron.pollIntervalSeconds,
				timeoutSeconds: input.cron.timeoutSeconds,
			},
			summary: input.cron.summary,
			coverage: input.cron.coverage,
			jobs: input.cron.jobs.map((job) => sanitizeCronJob(job, refKey)),
		},
		social: {
			services: input.config.socialServices.map(sanitizeSocialService),
			activity: input.socialActivity,
		},
		providers: input.config.providers.map(sanitizeProvider),
		queues: input.queues,
		workflows,
		risks,
		collectorErrors: input.collectorErrors ?? [],
	};
}

function collectActors(config: TelclaudeConfig, refKey: string): HermesInventorySnapshot["actors"] {
	const actors: HermesInventorySnapshot["actors"] = [];
	for (const chat of config.telegram.allowedChats ?? []) {
		actors.push({
			id: telegramChatRef(chat, refKey),
			kind: "telegram-chat",
			trust_domain: "private",
			source_ref: "config.telegram.allowedChats",
		});
	}
	for (const profile of config.profiles) {
		actors.push({
			id: profile.id,
			kind: "operator-profile",
			trust_domain: "private",
			source_ref: "config.profiles",
		});
	}
	for (const service of config.socialServices) {
		actors.push({
			id: service.id,
			kind: "social-service",
			trust_domain: "social",
			source_ref: "config.socialServices",
		});
	}
	for (const provider of config.providers) {
		actors.push({
			id: provider.id,
			kind: "provider",
			trust_domain: "provider",
			source_ref: "config.providers",
		});
	}
	return actors;
}

function collectWorkflows(
	config: TelclaudeConfig,
	cron: CronOverview,
	queues: HermesQueueSnapshot,
	refKey: string,
): HermesInventoryWorkflow[] {
	const workflows: HermesInventoryWorkflow[] = [];
	for (const chat of config.telegram.allowedChats ?? []) {
		const owner = telegramChatRef(chat, refKey);
		workflows.push({
			workflow_id: workflowId("telegram.chat", owner),
			owner,
			trust_domain: "private",
			active: true,
			current_surface: "Telclaude Telegram relay",
			hermes_target: "Hermes private profile behind Telclaude edge",
			status: "inventory_only",
			p_class: "P0",
			source_refs: ["config.telegram.allowedChats"],
			queue_refs: [],
			fixture_ids: [],
			unresolved_decision_ids: ["D-private-execution-contract"],
			risk_notes: ["Requires identity, approval, and session replay fixtures before inclusion."],
		});
	}
	for (const profile of config.profiles) {
		workflows.push({
			workflow_id: workflowId("telegram.profile", profile.id),
			owner: `profile:${profile.id}`,
			trust_domain: "private",
			active: true,
			current_surface: "Telclaude operator profile",
			hermes_target: "Hermes profile with generated prompt/toolset overlays",
			status: "inventory_only",
			p_class: "P0",
			source_refs: ["config.profiles"],
			queue_refs: [],
			fixture_ids: [],
			unresolved_decision_ids: ["D-profile-generation"],
			risk_notes: [],
		});
	}
	for (const job of cron.jobs) {
		const owner = job.ownerId ? ownerRef(job.ownerId, refKey) : "system";
		workflows.push({
			workflow_id: workflowId("cron.job", job.id),
			owner,
			trust_domain: cronTrustDomain(job.action.kind),
			active: job.enabled,
			current_surface: "Telclaude cron scheduler",
			hermes_target: "Hermes cron/background job routed through Telclaude edge",
			status: job.enabled ? "inventory_only" : "disabled",
			p_class: "P1",
			source_refs: ["sqlite.cron_jobs"],
			queue_refs: [],
			fixture_ids: [],
			unresolved_decision_ids: ["D-cron-idempotency"],
			risk_notes:
				job.action.kind === "agent-prompt" ? ["Cron prompt is redacted from inventory."] : [],
		});
	}
	for (const service of config.socialServices) {
		workflows.push({
			workflow_id: workflowId("social.service", service.id),
			owner: `social:${service.id}`,
			trust_domain: "social",
			active: service.enabled,
			current_surface: "Telclaude social service",
			hermes_target: "Hermes social profile isolated behind Telclaude edge",
			status: service.enabled ? "inventory_only" : "disabled",
			p_class: "P1",
			source_refs: ["config.socialServices"],
			queue_refs: queues.social.activeItems > 0 ? ["sqlite.memory_entries.social"] : [],
			fixture_ids: [],
			unresolved_decision_ids: ["D-social-persona-isolation"],
			risk_notes: [],
		});
	}
	for (const provider of config.providers) {
		for (const service of provider.services) {
			workflows.push({
				workflow_id: workflowId("provider.service", provider.id, service),
				owner: `provider:${provider.id}`,
				trust_domain: "provider",
				active: true,
				current_surface: "Telclaude provider sidecar",
				hermes_target: "Hermes tool adapter routed through Telclaude provider proxy",
				status: "inventory_only",
				p_class: "P0",
				source_refs: ["config.providers"],
				queue_refs: [],
				fixture_ids: [],
				unresolved_decision_ids: ["D-provider-envelope"],
				risk_notes: [
					"Requires direct-provider-denied and approval-token fixtures before inclusion.",
				],
			});
		}
	}
	if (queues.webhooks.total > 0) {
		workflows.push({
			workflow_id: "webhooks.signed-inbound",
			owner: "system:webhooks",
			trust_domain: "system",
			active: queues.webhooks.enabled > 0,
			current_surface: "Telclaude signed webhook receiver",
			hermes_target: "Telclaude edge queues Hermes background jobs",
			status: queues.webhooks.enabled > 0 ? "inventory_only" : "disabled",
			p_class: "P1",
			source_refs: ["sqlite.webhooks"],
			queue_refs: ["sqlite.webhook_hits", "sqlite.webhook_deliveries"],
			fixture_ids: [],
			unresolved_decision_ids: ["D-webhook-delivery"],
			risk_notes: [],
		});
	}
	return workflows.sort((left, right) => left.workflow_id.localeCompare(right.workflow_id));
}

function collectRisks(
	config: TelclaudeConfig,
	queues: HermesQueueSnapshot,
	workflows: HermesInventoryWorkflow[],
): string[] {
	const risks: string[] = [];
	if (workflows.length === 0) risks.push("no workflows discovered");
	if (config.telegram.allowedChats?.length === 0) risks.push("telegram allowedChats is empty");
	if (queues.approvals.pending > 0) risks.push("pending tool approvals exist");
	if (queues.planApprovals.pending > 0) risks.push("pending plan approvals exist");
	if (queues.backgroundJobs.active > 0) risks.push("active background jobs exist");
	if (queues.cards.active > 0) risks.push("active Telegram cards exist");
	if (queues.pairing.pendingRequests > 0) risks.push("pending pairing requests exist");
	if (queues.pairing.activeLockouts > 0) risks.push("active pairing lockouts exist");
	if (queues.webhooks.enabled > 0) risks.push("enabled webhooks require cutover review");
	return risks;
}

function collectQueueSnapshot(): HermesQueueSnapshot {
	const now = Date.now();
	const cardsByStatus = countByColumn("card_instances", "status");
	const backgroundByStatus = countByColumn("background_jobs", "status");
	const curatorByStatus = countByColumn("curator_items", "status");
	return {
		approvals: {
			pending: countRows("approvals", "expires_at > ?", [now]),
			expired: countRows("approvals", "expires_at <= ?", [now]),
		},
		planApprovals: {
			pending: countRows("plan_approvals", "expires_at > ?", [now]),
			expired: countRows("plan_approvals", "expires_at <= ?", [now]),
		},
		cards: {
			active: countRows("card_instances", "status = 'active' AND expires_at > ?", [now]),
			expired: countRows("card_instances", "status = 'active' AND expires_at <= ?", [now]),
			byStatus: cardsByStatus,
		},
		backgroundJobs: {
			active: countRows("background_jobs", "status IN ('queued', 'running')"),
			byStatus: backgroundByStatus,
		},
		pairing: {
			pendingRequests: countRows("pairing_requests", "status = 'pending' AND expires_at > ?", [
				now,
			]),
			activePairs: countRows("paired_chats"),
			activeLockouts: countRows("pairing_lockouts", "locked_until > ?", [now]),
		},
		allowlist: {
			active: countRows("approval_allowlist", "expires_at IS NULL OR expires_at > ?", [now]),
			total: countRows("approval_allowlist"),
		},
		curator: {
			open: countRows("curator_items", "status = 'open'"),
			byStatus: curatorByStatus,
		},
		social: {
			activeItems: countRows("memory_entries", "source LIKE 'social:%' AND posted_at IS NULL"),
		},
		webhooks: {
			enabled: countRows("webhooks", "enabled = 1"),
			total: countRows("webhooks"),
		},
		memory: {
			entries: countRows("memory_entries"),
			episodes: countRows("memory_episodes"),
		},
	};
}

function sanitizeSessionRow(
	row: SessionListRow,
	refKey: string,
): HermesInventorySnapshot["sessions"]["rows"][number] {
	return {
		keyRef: stableRef("session-key", row.key, refKey),
		kind: row.kind,
		sessionRef: stableRef("session", row.sessionId, refKey),
		updatedAt: new Date(row.updatedAt).toISOString(),
		ageMs: row.ageMs,
		systemSent: row.systemSent,
	};
}

function sanitizeCronJob(
	job: CronOverview["jobs"][number],
	refKey: string,
): HermesInventorySnapshot["cron"]["jobs"][number] {
	return {
		id: job.id,
		name: job.name,
		enabled: job.enabled,
		running: job.running,
		ownerRef: job.ownerId ? ownerRef(job.ownerId, refKey) : null,
		deliveryTargetKind: job.deliveryTarget.kind,
		scheduleKind: job.schedule.kind,
		action: {
			kind: job.action.kind,
			...("serviceId" in job.action && job.action.serviceId
				? { serviceId: job.action.serviceId }
				: {}),
			promptPresent: "prompt" in job.action && Boolean(job.action.prompt),
			allowedSkillCount:
				"allowedSkills" in job.action && job.action.allowedSkills
					? job.action.allowedSkills.length
					: null,
			preprocessPresent: "preprocess" in job.action && Boolean(job.action.preprocess),
		},
		nextRunAt: millisToIso(job.nextRunAtMs),
		lastRunAt: millisToIso(job.lastRunAtMs),
		lastStatus: job.lastStatus,
	};
}

function sanitizeSocialService(
	service: SocialServiceConfig,
): HermesInventorySnapshot["social"]["services"][number] {
	return {
		id: service.id,
		type: service.type,
		enabled: service.enabled,
		handlePresent: Boolean(service.handle),
		displayNamePresent: Boolean(service.displayName),
		apiKeyPresent: Boolean(service.apiKey),
		agentUrlPresent: Boolean(service.agentUrl),
		heartbeatEnabled: service.heartbeatEnabled,
		enableSkills: service.enableSkills,
		allowedSkillCount: service.allowedSkills?.length ?? null,
		agentSkillCount: service.agentSkillsAllowed.length,
		notifyOnHeartbeat: service.notifyOnHeartbeat,
	};
}

function sanitizeProvider(
	provider: ExternalProviderConfig,
): HermesInventorySnapshot["providers"][number] {
	return {
		id: provider.id,
		services: provider.services,
		descriptionPresent: Boolean(provider.description),
		endpoint: parseEndpoint(provider.baseUrl),
	};
}

function parseEndpoint(baseUrl: string): HermesInventorySnapshot["providers"][number]["endpoint"] {
	try {
		const parsed = new URL(baseUrl);
		return {
			scheme: parsed.protocol.replace(/:$/, "") || null,
			host: parsed.hostname || null,
			port: parsed.port || null,
			baseUrlPresent: true,
			parseError: null,
		};
	} catch {
		return {
			scheme: null,
			host: null,
			port: null,
			baseUrlPresent: Boolean(baseUrl),
			parseError: "unparseable baseUrl",
		};
	}
}

// Table names, columns, and where clauses are static in this module; keep these helpers private.
function countRows(table: string, where?: string, params: unknown[] = []): number {
	const sql = where
		? `SELECT COUNT(*) as count FROM ${table} WHERE ${where}`
		: `SELECT COUNT(*) as count FROM ${table}`;
	const row = getDb()
		.prepare(sql)
		.get(...params) as { count: number } | undefined;
	return row?.count ?? 0;
}

function countByColumn(table: string, column: string): Record<string, number> {
	const rows = getDb()
		.prepare(`SELECT ${column} as key, COUNT(*) as count FROM ${table} GROUP BY ${column}`)
		.all() as Array<{ key: string | null; count: number }>;
	return Object.fromEntries(rows.map((row) => [row.key ?? "null", row.count]));
}

function summarizePendingQueues(queues: HermesQueueSnapshot): HermesPendingQueueSummary {
	return {
		approvals: queues.approvals.pending,
		planApprovals: queues.planApprovals.pending,
		cards: queues.cards.active,
		backgroundJobs: queues.backgroundJobs.active,
		socialItems: queues.social.activeItems,
		curatorItems: queues.curator.open,
		pairingPendingRequests: queues.pairing.pendingRequests,
		pairingActiveLockouts: queues.pairing.activeLockouts,
	};
}

function emptyCron(config: TelclaudeConfig): CronOverview {
	return {
		enabled: config.cron.enabled,
		pollIntervalSeconds: config.cron.pollIntervalSeconds,
		timeoutSeconds: config.cron.timeoutSeconds,
		summary: { totalJobs: 0, enabledJobs: 0, runningJobs: 0, nextRunAtMs: null },
		coverage: { allSocial: false, socialServiceIds: [], hasPrivateHeartbeat: false },
		jobs: [],
	};
}

function collectSafely<T>(
	collector: string,
	fn: () => T,
	fallback: T,
	errors: Array<{ collector: string; error: string }>,
): T {
	try {
		return fn();
	} catch (error) {
		errors.push({ collector, error: error instanceof Error ? error.message : String(error) });
		return fallback;
	}
}

function privateConfigPresent(): boolean {
	const privatePath = process.env.TELCLAUDE_PRIVATE_CONFIG;
	return Boolean(privatePath && fs.existsSync(privatePath));
}

function resolveInventoryRefKey(config: TelclaudeConfig): string {
	return (
		process.env.TELCLAUDE_HERMES_INVENTORY_SALT ||
		config.telegram.botToken ||
		crypto.randomBytes(32).toString("hex")
	);
}

function stableRef(prefix: string, value: string, refKey: string): string {
	const digest = crypto.createHmac("sha256", refKey).update(value).digest("hex").slice(0, 20);
	return `${prefix}:${digest}`;
}

function telegramChatRef(chat: string | number, refKey: string): string {
	return stableRef("telegram-chat", normalizeTelegramId(chat) ?? String(chat), refKey);
}

function ownerRef(ownerId: string, refKey: string): string {
	return stableRef("owner", ownerId, refKey);
}

function workflowId(...parts: string[]): string {
	return parts
		.map((part) =>
			part
				.toLowerCase()
				.replace(/[^a-z0-9]+/g, "-")
				.replace(/^-|-$/g, ""),
		)
		.join(".");
}

function cronTrustDomain(actionKind: string): HermesInventoryTrustDomain {
	if (actionKind === "social-heartbeat") return "social";
	if (actionKind === "agent-prompt" || actionKind === "private-heartbeat") return "private";
	if (actionKind === "curator-scan") return "system";
	return "unknown";
}

function millisToIso(value: number | null): string | null {
	return value === null ? null : new Date(value).toISOString();
}

function stringOrUnknown(value: unknown): string {
	return typeof value === "string" && value.trim() ? value : "unknown";
}
