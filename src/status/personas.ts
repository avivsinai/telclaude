import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { listManagedPlugins, type PluginPersona } from "../commands/plugins.js";
import { getAllSkillRoots } from "../commands/skill-path.js";
import { loadConfig, type TelclaudeConfig } from "../config/config.js";
import { listCronJobs } from "../cron/store.js";
import type { CronJob } from "../cron/types.js";
import { redactSecretsWithConfig } from "../security/output-filter.js";
import { getDb } from "../storage/db.js";

export type PersonaKind = "private" | "social";
export type PersonaHealth = "ok" | "degraded" | "not_configured";
export type RuntimeReachability = "configured" | "not_configured" | "unknown";
export type SkillPolicy = "trusted_all_active" | "disabled" | "explicit_allowlist" | "fail_closed";

export type PersonaRuntimeStatus = {
	configured: boolean;
	source: string;
	endpoint: string | null;
	reachability: RuntimeReachability;
	checkedAt: string | null;
	error: string | null;
};

export type PersonaProfileStatus = {
	configured: boolean;
	claudeHome: string | null;
	source: string;
};

export type PersonaPluginStatus = {
	configured: boolean;
	enabled: string[];
	installed: string[];
	error: string | null;
};

export type PersonaSkillStatus = {
	policy: SkillPolicy;
	activeCatalog: string[];
	effective: string[];
	allowed: string[];
	failClosed: boolean;
	servicePolicies: Array<{
		serviceId: string;
		enabled: boolean;
		enableSkills: boolean;
		policy: SkillPolicy;
		allowed: string[];
		failClosed: boolean;
	}>;
};

export type PersonaMemoryStatus = {
	source: "telegram" | "social";
	summary: string;
	contentsExposed: false;
};

export type PersonaFilesystemStatus = {
	workspace: "mounted" | "not_mounted";
	summary: string;
	mounts: string[];
};

export type PersonaProviderAccessStatus = {
	summary: string;
	providerIds: string[];
	serviceIds: string[];
	privateEndpointCount: number;
	directProviderFetch: "blocked" | "not_applicable";
	relayProxied: boolean;
};

export type PersonaOperationsStatus = {
	lastHeartbeatAt: string | null;
	lastSocialRunAt: string | null;
	lastError: string | null;
};

export type PersonaStatus = {
	persona: PersonaKind;
	health: PersonaHealth;
	summary: string;
	profile: PersonaProfileStatus;
	runtime: PersonaRuntimeStatus;
	modelProvider: {
		hermesModel: string;
		inferenceProvider: string;
		anthropicProxy: "configured" | "not_configured";
		credentialProxy: "configured" | "not_configured";
	};
	skills: PersonaSkillStatus;
	plugins: PersonaPluginStatus;
	memory: PersonaMemoryStatus;
	filesystem: PersonaFilesystemStatus;
	providers: PersonaProviderAccessStatus;
	operations: PersonaOperationsStatus;
	boundaries: {
		privateProcessesSocialMemory: false;
		socialHasWorkspaceMount: boolean;
		profileCloning: false;
	};
	services?: Array<{
		id: string;
		type: string;
		enabled: boolean;
		heartbeatEnabled: boolean;
		runtimeConfigured: boolean;
		runtimeSource: string;
		enableSkills: boolean;
		allowedSkills: string[];
		skillFailClosed: boolean;
	}>;
};

export type PersonaStatusSnapshot = {
	collectedAt: string;
	overallHealth: PersonaHealth;
	issueCount: number;
	personas: {
		private: PersonaStatus;
		social: PersonaStatus;
	};
};

export type PersonaStatusBuildInput = {
	config: TelclaudeConfig;
	env?: NodeJS.ProcessEnv;
	cwd?: string;
	nowMs?: number;
	activeSkillNames?: string[];
	privatePlugins?: PersonaPluginStatus;
	socialPlugins?: PersonaPluginStatus;
	cronJobs?: CronJob[];
	latestSocialActivityAtMs?: number | null;
	runtimeReachability?: Partial<Record<PersonaKind, PersonaRuntimeStatus>>;
};

export type PersonaStatusCollectOptions = {
	config?: TelclaudeConfig;
	env?: NodeJS.ProcessEnv;
	cwd?: string;
	nowMs?: number;
	probeRuntime?: boolean;
	probeTimeoutMs?: number;
};

type ProfileResolution = {
	configured: boolean;
	claudeHome: string | null;
	source: string;
};

type RuntimeResolution = {
	configured: boolean;
	source: string;
	url: string | null;
};

const DEFAULT_PRIVATE_WORKDIR = "/workspace";
const DEFAULT_SOCIAL_SANDBOX_DIR = "/social/sandbox";

function normalizeDir(raw: string): string {
	return raw.replace(/[/\\]+$/, "");
}

function resolvePath(raw: string): string {
	return normalizeDir(path.resolve(raw));
}

function resolvePrivateClaudeHome(env: NodeJS.ProcessEnv = process.env): ProfileResolution {
	if (env.TELCLAUDE_PRIVATE_CLAUDE_HOME) {
		return {
			configured: true,
			claudeHome: resolvePath(env.TELCLAUDE_PRIVATE_CLAUDE_HOME),
			source: "TELCLAUDE_PRIVATE_CLAUDE_HOME",
		};
	}
	if (env.CLAUDE_CONFIG_DIR) {
		return {
			configured: true,
			claudeHome: resolvePath(env.CLAUDE_CONFIG_DIR),
			source: "CLAUDE_CONFIG_DIR",
		};
	}
	if (env.TELCLAUDE_CLAUDE_HOME) {
		return {
			configured: true,
			claudeHome: resolvePath(env.TELCLAUDE_CLAUDE_HOME),
			source: "TELCLAUDE_CLAUDE_HOME",
		};
	}
	return {
		configured: true,
		claudeHome: normalizeDir(path.join(os.homedir(), ".claude")),
		source: "default ~/.claude",
	};
}

function resolveSocialClaudeHome(env: NodeJS.ProcessEnv = process.env): ProfileResolution {
	return {
		configured: true,
		claudeHome: env.TELCLAUDE_HERMES_HOME ? resolvePath(env.TELCLAUDE_HERMES_HOME) : null,
		source: env.TELCLAUDE_HERMES_HOME ? "TELCLAUDE_HERMES_HOME" : "Hermes social profile",
	};
}

function resolveHermesRuntime(
	env: NodeJS.ProcessEnv = process.env,
	domain: PersonaKind = "private",
): RuntimeResolution {
	const baseUrlEnv =
		domain === "social" ? "TELCLAUDE_HERMES_SOCIAL_API_BASE_URL" : "TELCLAUDE_HERMES_API_BASE_URL";
	const apiKeyEnv =
		domain === "social" ? "TELCLAUDE_HERMES_SOCIAL_API_KEY" : "TELCLAUDE_HERMES_API_KEY";
	const label = domain === "social" ? "Hermes social runtime" : "Hermes runtime";
	const baseUrl = env[baseUrlEnv]?.trim() ?? "";
	const apiKey = env[apiKeyEnv]?.trim() ?? "";
	const url = baseUrl || null;
	return {
		configured: Boolean(baseUrl && apiKey),
		source: baseUrl && apiKey ? `${baseUrlEnv} + ${apiKeyEnv}` : `${label} not configured`,
		url,
	};
}

function resolveSocialRuntimeForService(
	service: TelclaudeConfig["socialServices"][number],
	env: NodeJS.ProcessEnv = process.env,
): RuntimeResolution {
	const runtime = resolveHermesRuntime(env, "social");
	return {
		...runtime,
		source: runtime.configured ? `Hermes social runtime for social:${service.id}` : runtime.source,
	};
}

function resolveSocialRuntime(
	config: TelclaudeConfig,
	env: NodeJS.ProcessEnv = process.env,
): RuntimeResolution {
	const service = config.socialServices.find((entry) => entry.enabled) ?? config.socialServices[0];
	if (service) {
		return resolveSocialRuntimeForService(service, env);
	}
	return resolveHermesRuntime(env, "social");
}

function summarizeEndpoint(url: string | null, config: TelclaudeConfig): string | null {
	if (!url) return null;
	try {
		return new URL(url).origin;
	} catch {
		return redactSecretsWithConfig(url, config.security?.secretFilter);
	}
}

function defaultRuntimeStatus(
	resolution: RuntimeResolution,
	config: TelclaudeConfig,
): PersonaRuntimeStatus {
	return {
		configured: resolution.configured,
		source: resolution.source,
		endpoint: summarizeEndpoint(resolution.url, config),
		reachability: resolution.configured ? "configured" : "not_configured",
		checkedAt: null,
		error: null,
	};
}

async function probeRuntime(
	resolution: RuntimeResolution,
	nowMs: number,
	timeoutMs: number,
	config: TelclaudeConfig,
): Promise<PersonaRuntimeStatus> {
	if (!resolution.url) {
		return defaultRuntimeStatus(resolution, config);
	}

	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);
	try {
		const healthUrl = new URL("/health", resolution.url);
		const response = await fetch(healthUrl, { signal: controller.signal });
		return {
			configured: resolution.configured,
			source: resolution.source,
			endpoint: summarizeEndpoint(resolution.url, config),
			reachability: response.ok && resolution.configured ? "configured" : "not_configured",
			checkedAt: new Date(nowMs).toISOString(),
			error: response.ok ? null : `health returned HTTP ${response.status}`,
		};
	} catch (err) {
		return {
			configured: resolution.configured,
			source: resolution.source,
			endpoint: summarizeEndpoint(resolution.url, config),
			reachability: "not_configured",
			checkedAt: new Date(nowMs).toISOString(),
			error: redactStatusText(String(err), config),
		};
	} finally {
		clearTimeout(timer);
	}
}

function isSkillDirEntry(root: string, entry: fs.Dirent): boolean {
	if (entry.name.startsWith(".")) return false;
	if (entry.isDirectory()) return true;
	if (!entry.isSymbolicLink()) return false;
	try {
		return fs.statSync(path.join(root, entry.name)).isDirectory();
	} catch {
		return false;
	}
}

function listActiveSkillNames(cwd: string): string[] {
	const seen = new Set<string>();
	for (const root of getAllSkillRoots(cwd)) {
		let entries: fs.Dirent[];
		try {
			entries = fs.readdirSync(root, { withFileTypes: true });
		} catch {
			continue;
		}
		for (const entry of entries) {
			if (isSkillDirEntry(root, entry) && fs.existsSync(path.join(root, entry.name, "SKILL.md"))) {
				seen.add(entry.name);
			}
		}
	}
	return [...seen].sort((left, right) => left.localeCompare(right));
}

function collectPluginsForPersona(
	persona: PluginPersona,
	env: NodeJS.ProcessEnv,
	config: TelclaudeConfig,
): PersonaPluginStatus {
	try {
		const [entry] = listManagedPlugins({ persona, env });
		if (!entry) {
			return {
				configured: false,
				enabled: [],
				installed: [],
				error: `${persona} plugin profile not found`,
			};
		}
		return {
			configured: true,
			enabled: entry.plugins
				.filter((plugin) => plugin.enabled)
				.map((plugin) => plugin.pluginId)
				.sort((left, right) => left.localeCompare(right)),
			installed: entry.plugins
				.filter((plugin) => plugin.installed)
				.map((plugin) => plugin.pluginId)
				.sort((left, right) => left.localeCompare(right)),
			error: null,
		};
	} catch (err) {
		return {
			configured: false,
			enabled: [],
			installed: [],
			error: redactStatusText(err instanceof Error ? err.message : String(err), config),
		};
	}
}

function hermesSocialPluginStatus(): PersonaPluginStatus {
	return {
		configured: true,
		enabled: [],
		installed: [],
		error: null,
	};
}

function collectLatestSocialActivityAtMs(): number | null {
	try {
		const row = getDb()
			.prepare("SELECT MAX(timestamp) AS last_run_at FROM social_activity_log")
			.get() as { last_run_at: number | null } | undefined;
		return row?.last_run_at ?? null;
	} catch {
		return null;
	}
}

function redactStatusText(text: string | null | undefined, config: TelclaudeConfig): string | null {
	if (!text) return null;
	return redactSecretsWithConfig(text, config.security?.secretFilter);
}

function isoOrNull(ms: number | null | undefined): string | null {
	return typeof ms === "number" && Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}

function latestCronJob(jobs: CronJob[], predicate: (job: CronJob) => boolean): CronJob | null {
	return (
		jobs
			.filter(predicate)
			.filter((job) => typeof job.lastRunAtMs === "number")
			.sort((left, right) => (right.lastRunAtMs ?? 0) - (left.lastRunAtMs ?? 0))[0] ?? null
	);
}

function latestCronError(
	jobs: CronJob[],
	predicate: (job: CronJob) => boolean,
	config: TelclaudeConfig,
): string | null {
	const latest =
		jobs
			.filter(predicate)
			.filter((job) => job.lastStatus === "error" && Boolean(job.lastError))
			.sort((left, right) => (right.lastRunAtMs ?? 0) - (left.lastRunAtMs ?? 0))[0] ?? null;
	return redactStatusText(latest?.lastError, config);
}

function providerAccessForPersona(
	persona: PersonaKind,
	config: TelclaudeConfig,
): PersonaProviderAccessStatus {
	const providerIds = config.providers.map((provider) => provider.id).sort();
	const serviceIds = Array.from(
		new Set(config.providers.flatMap((provider) => provider.services)),
	).sort((left, right) => left.localeCompare(right));
	const privateEndpointCount = config.security?.network?.privateEndpoints?.length ?? 0;
	return {
		summary:
			providerIds.length === 0
				? "no external providers configured"
				: `${providerIds.length} provider(s), ${serviceIds.length} service id(s), relay metadata only`,
		providerIds,
		serviceIds,
		privateEndpointCount,
		directProviderFetch: persona === "private" ? "blocked" : "not_applicable",
		relayProxied: providerIds.length > 0,
	};
}

function buildPrivateSkills(activeCatalog: string[]): PersonaSkillStatus {
	return {
		policy: "trusted_all_active",
		activeCatalog,
		effective: activeCatalog,
		allowed: [],
		failClosed: false,
		servicePolicies: [],
	};
}

function socialServiceSkillPolicy(service: TelclaudeConfig["socialServices"][number]): {
	policy: SkillPolicy;
	allowed: string[];
	failClosed: boolean;
} {
	if (!service.enableSkills) {
		return { policy: "disabled", allowed: [], failClosed: false };
	}
	if (!service.allowedSkills) {
		return { policy: "fail_closed", allowed: [], failClosed: true };
	}
	return {
		policy: "explicit_allowlist",
		allowed: [...service.allowedSkills].sort((left, right) => left.localeCompare(right)),
		failClosed: false,
	};
}

function buildSocialSkills(
	config: TelclaudeConfig,
	activeCatalog: string[],
	socialProfileConfigured: boolean,
): PersonaSkillStatus {
	const servicePolicies = config.socialServices.map((service) => {
		const policy = socialServiceSkillPolicy(service);
		return {
			serviceId: service.id,
			enabled: service.enabled,
			enableSkills: service.enableSkills,
			...policy,
		};
	});
	const allowed = Array.from(new Set(servicePolicies.flatMap((policy) => policy.allowed))).sort(
		(left, right) => left.localeCompare(right),
	);
	const failClosed =
		!socialProfileConfigured || servicePolicies.some((policy) => policy.failClosed);
	const anySkillsEnabled = servicePolicies.some((policy) => policy.enableSkills);
	const policy: SkillPolicy = failClosed
		? "fail_closed"
		: anySkillsEnabled
			? "explicit_allowlist"
			: "disabled";

	return {
		policy,
		activeCatalog,
		effective: policy === "explicit_allowlist" ? allowed : [],
		allowed,
		failClosed,
		servicePolicies,
	};
}

function buildModelProviderStatus(env: NodeJS.ProcessEnv) {
	return {
		hermesModel:
			env.HERMES_INFERENCE_MODEL ?? env.TELCLAUDE_HERMES_INFERENCE_MODEL ?? "Hermes default",
		inferenceProvider: env.HERMES_INFERENCE_PROVIDER ?? "openai-codex",
		anthropicProxy:
			env.ANTHROPIC_BASE_URL || env.ANTHROPIC_AUTH_TOKEN ? "configured" : "not_configured",
		credentialProxy: env.TELCLAUDE_CREDENTIAL_PROXY_URL ? "configured" : "not_configured",
	} as PersonaStatus["modelProvider"];
}

function buildPrivateFilesystem(env: NodeJS.ProcessEnv, cwd: string): PersonaFilesystemStatus {
	const workspace = env.TELCLAUDE_WORKDIR ?? (env.WORKSPACE_PATH ? DEFAULT_PRIVATE_WORKDIR : cwd);
	const mounts = [
		`workspace:${workspace}:rw`,
		env.TELCLAUDE_MEDIA_INBOX_DIR ? "media-inbox:configured" : "media-inbox:default/unknown",
		env.TELCLAUDE_MEDIA_OUTBOX_DIR ? "media-outbox:configured" : "media-outbox:default/unknown",
	];
	return {
		workspace: "mounted",
		summary: "workspace and media volumes available to private persona",
		mounts,
	};
}

function buildSocialFilesystem(env: NodeJS.ProcessEnv): PersonaFilesystemStatus {
	const sandbox = env.TELCLAUDE_SOCIAL_SANDBOX_DIR ?? DEFAULT_SOCIAL_SANDBOX_DIR;
	return {
		workspace: "not_mounted",
		summary: "no workspace mount; isolated social sandbox only",
		mounts: [
			`social-sandbox:${sandbox}:rw`,
			env.TELCLAUDE_SKILL_CATALOG_DIR
				? "skill-catalog:configured:ro"
				: "skill-catalog:default/unknown:ro",
		],
	};
}

function socialServicesStatus(config: TelclaudeConfig, env: NodeJS.ProcessEnv) {
	return config.socialServices.map((service) => {
		const runtime = resolveSocialRuntimeForService(service, env);
		const skillPolicy = socialServiceSkillPolicy(service);
		return {
			id: service.id,
			type: service.type,
			enabled: service.enabled,
			heartbeatEnabled: service.heartbeatEnabled,
			runtimeConfigured: runtime.configured,
			runtimeSource: runtime.source,
			enableSkills: service.enableSkills,
			allowedSkills: skillPolicy.allowed,
			skillFailClosed: skillPolicy.failClosed,
		};
	});
}

function chooseOverallHealth(
	privateStatus: PersonaStatus,
	socialStatus: PersonaStatus,
): PersonaHealth {
	if (privateStatus.health === "not_configured" || socialStatus.health === "not_configured") {
		return "not_configured";
	}
	if (privateStatus.health === "degraded" || socialStatus.health === "degraded") {
		return "degraded";
	}
	return "ok";
}

function countIssues(statuses: PersonaStatus[]): number {
	return statuses.filter((status) => status.health !== "ok").length;
}

function summarizePrivate(status: {
	runtime: PersonaRuntimeStatus;
	plugins: PersonaPluginStatus;
}): string {
	if (status.runtime.reachability === "not_configured")
		return "private Hermes runtime not configured";
	if (status.plugins.error) return "private plugin metadata has errors";
	return "private persona metadata healthy";
}

function summarizeSocial(status: {
	profile: PersonaProfileStatus;
	runtime: PersonaRuntimeStatus;
	skills: PersonaSkillStatus;
	plugins: PersonaPluginStatus;
}): string {
	if (!status.profile.configured) return "social profile is not configured; fail-closed";
	if (status.runtime.reachability === "not_configured")
		return "social Hermes runtime not configured";
	if (status.skills.failClosed) return "social skills are fail-closed";
	if (status.plugins.error) return "social plugin metadata has errors";
	return "social persona metadata healthy";
}

function privateHealth(runtime: PersonaRuntimeStatus, plugins: PersonaPluginStatus): PersonaHealth {
	if (runtime.reachability === "not_configured" || plugins.error) return "degraded";
	return "ok";
}

function socialHealth(
	profile: PersonaProfileStatus,
	runtime: PersonaRuntimeStatus,
	skills: PersonaSkillStatus,
	plugins: PersonaPluginStatus,
): PersonaHealth {
	if (!profile.configured) return "not_configured";
	if (runtime.reachability === "not_configured" || skills.failClosed || plugins.error)
		return "degraded";
	return "ok";
}

export function buildPersonaStatusSnapshot(input: PersonaStatusBuildInput): PersonaStatusSnapshot {
	const env = input.env ?? process.env;
	const cwd = input.cwd ?? process.cwd();
	const nowMs = input.nowMs ?? Date.now();
	const config = input.config;
	const activeSkillNames = input.activeSkillNames ?? [];
	const cronJobs = input.cronJobs ?? [];
	const privateProfile = resolvePrivateClaudeHome(env);
	const socialProfile = resolveSocialClaudeHome(env);

	const privateRuntimeResolution = resolveHermesRuntime(env);
	const socialRuntimeResolution = resolveSocialRuntime(config, env);
	const privateRuntime =
		input.runtimeReachability?.private ?? defaultRuntimeStatus(privateRuntimeResolution, config);
	const socialRuntime =
		input.runtimeReachability?.social ?? defaultRuntimeStatus(socialRuntimeResolution, config);
	const privatePlugins = input.privatePlugins ?? collectPluginsForPersona("private", env, config);
	const socialPlugins = input.socialPlugins ?? hermesSocialPluginStatus();
	const privateSkills = buildPrivateSkills(activeSkillNames);
	const socialSkills = buildSocialSkills(config, activeSkillNames, socialProfile.configured);

	const privateHeartbeat = latestCronJob(
		cronJobs,
		(job) => job.action.kind === "private-heartbeat",
	);
	const socialHeartbeat = latestCronJob(cronJobs, (job) => job.action.kind === "social-heartbeat");
	const privateStatusBase = {
		profile: privateProfile,
		runtime: privateRuntime,
		plugins: privatePlugins,
	};
	const socialStatusBase = {
		profile: socialProfile,
		runtime: socialRuntime,
		skills: socialSkills,
		plugins: socialPlugins,
	};

	const privateStatus: PersonaStatus = {
		persona: "private",
		health: privateHealth(privateRuntime, privatePlugins),
		summary: summarizePrivate(privateStatusBase),
		profile: privateProfile,
		runtime: privateRuntime,
		modelProvider: buildModelProviderStatus(env),
		skills: privateSkills,
		plugins: privatePlugins,
		memory: {
			source: "telegram",
			summary: "telegram semantic memory plus private episodic archive; contents not included",
			contentsExposed: false,
		},
		filesystem: buildPrivateFilesystem(env, cwd),
		providers: providerAccessForPersona("private", config),
		operations: {
			lastHeartbeatAt: isoOrNull(privateHeartbeat?.lastRunAtMs),
			lastSocialRunAt: null,
			lastError: latestCronError(
				cronJobs,
				(job) => job.action.kind === "private-heartbeat",
				config,
			),
		},
		boundaries: {
			privateProcessesSocialMemory: false,
			socialHasWorkspaceMount: false,
			profileCloning: false,
		},
	};

	const socialFilesystem = buildSocialFilesystem(env);
	const socialStatus: PersonaStatus = {
		persona: "social",
		health: socialHealth(socialProfile, socialRuntime, socialSkills, socialPlugins),
		summary: summarizeSocial(socialStatusBase),
		profile: socialProfile,
		runtime: socialRuntime,
		modelProvider: buildModelProviderStatus(env),
		skills: socialSkills,
		plugins: socialPlugins,
		memory: {
			source: "social",
			summary: "public social memory only; contents not included",
			contentsExposed: false,
		},
		filesystem: socialFilesystem,
		providers: providerAccessForPersona("social", config),
		operations: {
			lastHeartbeatAt: isoOrNull(socialHeartbeat?.lastRunAtMs),
			lastSocialRunAt: isoOrNull(input.latestSocialActivityAtMs),
			lastError: latestCronError(cronJobs, (job) => job.action.kind === "social-heartbeat", config),
		},
		boundaries: {
			privateProcessesSocialMemory: false,
			socialHasWorkspaceMount: socialFilesystem.workspace === "mounted",
			profileCloning: false,
		},
		services: socialServicesStatus(config, env),
	};

	const statuses = [privateStatus, socialStatus];
	return {
		collectedAt: new Date(nowMs).toISOString(),
		overallHealth: chooseOverallHealth(privateStatus, socialStatus),
		issueCount: countIssues(statuses),
		personas: {
			private: privateStatus,
			social: socialStatus,
		},
	};
}

export async function collectPersonaStatus(
	options: PersonaStatusCollectOptions = {},
): Promise<PersonaStatusSnapshot> {
	const config = options.config ?? loadConfig();
	const env = options.env ?? process.env;
	const cwd = options.cwd ?? process.cwd();
	const nowMs = options.nowMs ?? Date.now();
	const privateRuntimeResolution = resolveHermesRuntime(env);
	const socialRuntimeResolution = resolveSocialRuntime(config, env);
	let runtimeReachability: Partial<Record<PersonaKind, PersonaRuntimeStatus>> | undefined;

	if (options.probeRuntime !== false) {
		const timeoutMs = options.probeTimeoutMs ?? 1500;
		const [privateRuntime, socialRuntime] = await Promise.all([
			probeRuntime(privateRuntimeResolution, nowMs, timeoutMs, config),
			probeRuntime(socialRuntimeResolution, nowMs, timeoutMs, config),
		]);
		runtimeReachability = { private: privateRuntime, social: socialRuntime };
	}

	let cronJobs: CronJob[] = [];
	try {
		cronJobs = listCronJobs({ includeDisabled: true });
	} catch {
		cronJobs = [];
	}

	return buildPersonaStatusSnapshot({
		config,
		env,
		cwd,
		nowMs,
		activeSkillNames: listActiveSkillNames(cwd),
		cronJobs,
		latestSocialActivityAtMs: collectLatestSocialActivityAtMs(),
		runtimeReachability,
	});
}

function formatList(values: string[], emptyLabel: string, limit = 8): string {
	if (values.length === 0) return emptyLabel;
	const shown = values.slice(0, limit).join(", ");
	const remaining = values.length - limit;
	return remaining > 0 ? `${shown}, +${remaining} more` : shown;
}

function formatRuntime(runtime: PersonaRuntimeStatus): string {
	const suffix = runtime.error ? `; error=${runtime.error}` : "";
	const endpoint = runtime.endpoint ? `; endpoint=${runtime.endpoint}` : "";
	return `${runtime.reachability} via ${runtime.source}${endpoint}${suffix}`;
}

function formatProfile(profile: PersonaProfileStatus): string {
	return profile.claudeHome ? `${profile.claudeHome} (${profile.source})` : profile.source;
}

function formatOperations(ops: PersonaOperationsStatus): string {
	const parts = [
		`heartbeat=${ops.lastHeartbeatAt ?? "never"}`,
		...(ops.lastSocialRunAt ? [`social-run=${ops.lastSocialRunAt}`] : []),
		...(ops.lastError ? [`last-error=${ops.lastError}`] : []),
	];
	return parts.join("; ");
}

function formatPersona(status: PersonaStatus): string[] {
	const indent = "  ";
	const lines = [
		`${status.persona}: ${status.health} (${status.summary})`,
		`${indent}Claude home: ${formatProfile(status.profile)}`,
		`${indent}Runtime: ${formatRuntime(status.runtime)}`,
		`${indent}Model/provider: model=${status.modelProvider.hermesModel}; provider=${
			status.modelProvider.inferenceProvider
		}; anthropicProxy=${status.modelProvider.anthropicProxy}; credentialProxy=${
			status.modelProvider.credentialProxy
		}`,
		`${indent}Memory: source=${status.memory.source}; contents=hidden; ${status.memory.summary}`,
		`${indent}Filesystem: ${status.filesystem.summary}; mounts=${formatList(
			status.filesystem.mounts,
			"none",
		)}`,
		`${indent}Skills: policy=${status.skills.policy}; effective=${formatList(
			status.skills.effective,
			"none",
		)}; catalog=${status.skills.activeCatalog.length}`,
		`${indent}Plugins: enabled=${formatList(status.plugins.enabled, "none")}; installed=${
			status.plugins.installed.length
		}${status.plugins.error ? `; error=${status.plugins.error}` : ""}`,
		`${indent}Providers: ${status.providers.summary}; ids=${formatList(
			status.providers.providerIds,
			"none",
		)}; directFetch=${status.providers.directProviderFetch}`,
		`${indent}Operations: ${formatOperations(status.operations)}`,
		`${indent}Boundaries: privateProcessesSocialMemory=${
			status.boundaries.privateProcessesSocialMemory
		}; socialHasWorkspaceMount=${status.boundaries.socialHasWorkspaceMount}; profileCloning=${
			status.boundaries.profileCloning
		}`,
	];
	if (status.services && status.services.length > 0) {
		lines.push(
			`${indent}Services: ${status.services
				.map((service) => {
					const skillState = service.skillFailClosed
						? "skills=fail-closed"
						: service.enableSkills
							? `skills=${service.allowedSkills.length}`
							: "skills=disabled";
					return `${service.id}:${service.enabled ? "enabled" : "disabled"}:${skillState}:runtime=${
						service.runtimeConfigured ? service.runtimeSource : "not configured"
					}`;
				})
				.join("; ")}`,
		);
	}
	return lines;
}

export function formatPersonaStatusSnapshot(
	snapshot: PersonaStatusSnapshot,
	_options: { telegram?: boolean } = {},
): string {
	const lines = [
		`Personas: ${snapshot.overallHealth} (${snapshot.issueCount} issue${
			snapshot.issueCount === 1 ? "" : "s"
		})`,
		...formatPersona(snapshot.personas.private),
		...formatPersona(snapshot.personas.social),
	];
	return lines.join("\n");
}
