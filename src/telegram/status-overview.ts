import { getActiveJobCount } from "../background/jobs.js";
import { collectTelclaudeStatus } from "../commands/status.js";
import { loadConfig } from "../config/config.js";
import { getAllSessions } from "../config/sessions.js";
import { listCronJobs } from "../cron/store.js";
import { getChildLogger } from "../logging.js";
import { listServices as listOAuthServices } from "../oauth/registry.js";
import { checkProviderHealth, type HealthCheckResult } from "../providers/provider-health.js";
import { getVaultClient, isVaultAvailable } from "../vault-daemon/client.js";
import type { ListEntry } from "../vault-daemon/protocol.js";
import type { RemediationKey } from "./remediation-commands.js";

const logger = getChildLogger({ module: "telegram-status-overview" });

export type StatusOverview = {
	summary: string;
	details: string[];
	providerIssues: HealthCheckResult[];
};

/** A single health signal surfaced on the `/system health` card. */
export type HealthStatus = "ok" | "degraded" | "auth_expired" | "unreachable" | "unknown";

export type HealthItem = {
	id: string;
	label: string;
	status: HealthStatus;
	/** Human-readable detail (one line; renderer will escape). */
	detail?: string;
	/** Remediation key to look up in `remediation-commands.ts`. */
	remediation?: RemediationKey;
	/** Optional ISO timestamp for "updated X ago" rendering. */
	observedAtMs?: number;
};

export type SystemHealthSnapshot = {
	overallStatus: HealthStatus;
	collectedAtMs: number;
	items: HealthItem[];
	/** Number of distinct failing or degraded items (for summary line). */
	issueCount: number;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Provider health helpers (existing behaviour)
// ═══════════════════════════════════════════════════════════════════════════════

function formatProviderIssue(result: HealthCheckResult): string {
	return `${result.providerId}: ${result.response?.status ?? result.error ?? "unreachable"}`;
}

export async function collectProviderHealthIssues(): Promise<HealthCheckResult[]> {
	const cfg = loadConfig();
	const providers = cfg.providers ?? [];

	if (providers.length === 0) {
		return [];
	}

	const results = await Promise.all(
		providers.map((provider) => checkProviderHealth(provider.id, provider.baseUrl)),
	);

	return results.filter(
		(result) =>
			!result.reachable ||
			(result.response?.status !== "healthy" && result.response?.status !== "ok"),
	);
}

export async function collectStatusOverview(
	options: { localUserId?: string; includeProviderHealth?: boolean } = {},
): Promise<StatusOverview> {
	const status = await collectTelclaudeStatus();
	const details: string[] = [];

	if (options.localUserId) {
		details.push(`Identity: ${options.localUserId}`);
	}

	details.push(`Security profile: ${status.security?.profile ?? "unknown"}`);
	details.push(
		`Cron: ${status.operations.cron.enabledJobs}/${status.operations.cron.totalJobs} enabled`,
	);
	details.push(`Sessions: ${status.operations.sessions.total} tracked`);
	details.push(
		`Social services: ${status.services.enabledSocialServices}/${status.services.socialServices} enabled`,
	);

	if (status.audit) {
		details.push(
			`Audit: ${status.audit.success} ok, ${status.audit.blocked} blocked, ${status.audit.errors} errors`,
		);
	}

	let providerIssues: HealthCheckResult[] = [];
	if (options.includeProviderHealth) {
		providerIssues = await collectProviderHealthIssues();
		if (providerIssues.length === 0) {
			details.push("Providers: healthy");
		} else {
			details.push(...providerIssues.map(formatProviderIssue));
		}
	}

	const summary = options.includeProviderHealth
		? providerIssues.length === 0
			? "Health check passed."
			: providerIssues.length === 1
				? `Provider issue: ${providerIssues[0].providerId} — ${providerIssues[0].response?.status ?? providerIssues[0].error ?? "unreachable"}`
				: `${providerIssues.length} provider issues: ${providerIssues.map((r) => r.providerId).join(", ")}`
		: options.localUserId
			? `Linked as ${options.localUserId}. System overview ready.`
			: "System overview ready.";

	return {
		summary,
		details,
		providerIssues,
	};
}

export function summarizeProviderIssues(results: HealthCheckResult[]): string[] {
	return results.map(formatProviderIssue);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Live health snapshot (W10)
// ═══════════════════════════════════════════════════════════════════════════════

/** 5-min buffer matches vault-oauth/EXPIRY_BUFFER_MS. */
const OAUTH_EXPIRY_BUFFER_MS = 5 * 60 * 1000;
/** Consider a cron job "lagging" if it is more than 2x its expected interval overdue. */
const CRON_LAG_TOLERANCE_MS = 2 * 60 * 1000;
/** Session stale cutoff mirrors status-overview's existing "staleOver24h". */
const SESSION_STALE_CUTOFF_MS = 24 * 60 * 60 * 1000;

function pickOverall(items: HealthItem[]): HealthStatus {
	if (items.some((item) => item.status === "unreachable")) return "unreachable";
	if (items.some((item) => item.status === "auth_expired")) return "auth_expired";
	if (items.some((item) => item.status === "degraded")) return "degraded";
	if (items.every((item) => item.status === "ok" || item.status === "unknown")) return "ok";
	return "degraded";
}

function countIssues(items: HealthItem[]): number {
	return items.filter((item) => item.status !== "ok" && item.status !== "unknown").length;
}

/**
 * Map a provider health result into a normalized health item.
 */
function buildProviderItem(result: HealthCheckResult): HealthItem {
	const base = {
		id: `provider:${result.providerId}`,
		label: `Provider ${result.providerId}`,
	};
	if (!result.reachable) {
		return {
			...base,
			status: "unreachable",
			detail: result.error ?? "sidecar unreachable",
			remediation: "provider_unreachable",
		};
	}
	const respStatus = result.response?.status;
	const connectors = result.response?.connectors;
	// Surface auth_expired even if overall status is healthy (rare but defensive).
	const hasAuthExpired = connectors
		? Object.values(connectors).some((c) => c.status === "auth_expired")
		: false;
	if (hasAuthExpired) {
		return {
			...base,
			status: "auth_expired",
			detail: "connector auth expired",
			remediation: "provider_auth_expired",
		};
	}
	if (respStatus === "unhealthy") {
		return {
			...base,
			status: "unreachable",
			detail: "reported unhealthy",
			remediation: "provider_unreachable",
		};
	}
	if (respStatus === "degraded") {
		return {
			...base,
			status: "degraded",
			detail: "sidecar reports degraded",
			remediation: "provider_degraded",
		};
	}
	return {
		...base,
		status: "ok",
		detail: respStatus ?? "healthy",
	};
}

/**
 * Collect OAuth token health from the vault. Each configured OAuth2 entry is
 * surfaced as one HealthItem. Google OAuth refresh-token health gets a
 * dedicated remediation key.
 */
async function collectOAuthHealthItems(): Promise<HealthItem[]> {
	const items: HealthItem[] = [];
	const vaultUp = await isVaultAvailable({ timeout: 1500 }).catch(() => false);
	if (!vaultUp) {
		return items; // Vault unreachable is surfaced separately.
	}

	let entries: ListEntry[];
	try {
		const client = getVaultClient();
		const list = await client.list("http");
		entries = list.entries.filter((entry) => entry.credentialType === "oauth2");
	} catch (err) {
		logger.debug({ error: String(err) }, "failed to list vault entries");
		return items;
	}

	const services = listOAuthServices();
	const serviceByTarget = new Map(services.map((svc) => [svc.vaultTarget, svc]));

	const now = Date.now();
	for (const entry of entries) {
		const svc = serviceByTarget.get(entry.target);
		const serviceId = svc?.id ?? entry.target;
		const label = `OAuth ${svc?.displayName ?? serviceId}`;

		// Try to get a live token — this exercises the refresh path without
		// forcing it (cached tokens return early).
		try {
			const tokenResult = await getVaultClient().getToken(entry.target);
			if (tokenResult.ok) {
				const remainingMs = tokenResult.expiresAt - now;
				const detail =
					remainingMs > 0
						? `expires in ${Math.max(1, Math.round(remainingMs / 60_000))}m`
						: "expired";
				items.push({
					id: `oauth:${serviceId}`,
					label,
					status: remainingMs > OAUTH_EXPIRY_BUFFER_MS ? "ok" : "degraded",
					detail,
					observedAtMs: now,
					remediation:
						remainingMs > OAUTH_EXPIRY_BUFFER_MS
							? undefined
							: serviceId === "google"
								? "google_oauth_expired"
								: "provider_auth_expired",
				});
			} else {
				items.push({
					id: `oauth:${serviceId}`,
					label,
					status: "auth_expired",
					detail: tokenResult.error,
					observedAtMs: now,
					remediation: serviceId === "google" ? "google_oauth_expired" : "provider_auth_expired",
				});
			}
		} catch (err) {
			items.push({
				id: `oauth:${serviceId}`,
				label,
				status: "unknown",
				detail: `vault error: ${String(err).slice(0, 80)}`,
			});
		}
	}

	// Google OAuth missing entirely (not in vault) is a first-class signal.
	const google = services.find((s) => s.id === "google");
	if (google && !serviceByTarget.has(google.vaultTarget)) {
		items.push({
			id: "oauth:google",
			label: "OAuth Google",
			status: "auth_expired",
			detail: "not configured",
			remediation: "google_oauth_missing",
		});
	}

	return items;
}

/**
 * Aggregate the complete system-health snapshot for the `/system` card.
 *
 * This intentionally fans out multiple async probes (vault ping, provider
 * health, OAuth refresh) in parallel but is resilient: any probe that fails
 * degrades its own item rather than poisoning the entire snapshot.
 */
export async function collectSystemHealth(): Promise<SystemHealthSnapshot> {
	const cfg = loadConfig();
	const collectedAtMs = Date.now();

	// Core status (cron, sessions, audit counts, services).
	const status = await collectTelclaudeStatus().catch((err) => {
		logger.warn({ error: String(err) }, "status collection failed");
		return null;
	});

	const items: HealthItem[] = [];

	// ── Model / tier ──────────────────────────────────────────────────
	const defaultTier = cfg.security?.permissions?.defaultTier ?? "READ_ONLY";
	items.push({
		id: "tier:default",
		label: "Default tier",
		status: defaultTier ? "ok" : "degraded",
		detail: defaultTier,
		remediation: defaultTier ? undefined : "tier_misconfigured",
	});

	// Model / fallback state: we only expose what we know without an SDK call.
	// Model overrides live per-session, not in top-level config — surface the
	// SDK default and note if any SDK betas are active as a proxy signal.
	const sdkBetas = cfg.sdk?.betas ?? [];
	items.push({
		id: "model:active",
		label: "Model",
		status: "ok",
		detail: sdkBetas.length === 0 ? "SDK default" : `SDK default (+${sdkBetas.length} betas)`,
	});

	// ── Vault ─────────────────────────────────────────────────────────
	const vaultUp = await isVaultAvailable({ timeout: 1500 }).catch(() => false);
	items.push({
		id: "vault:daemon",
		label: "Vault",
		status: vaultUp ? "ok" : "unreachable",
		detail: vaultUp ? "socket reachable" : "socket not responding",
		remediation: vaultUp ? undefined : "vault_unreachable",
		observedAtMs: collectedAtMs,
	});

	// ── OAuth tokens (Anthropic/OpenAI/Google via vault) ─────────────
	const oauthItems = await collectOAuthHealthItems().catch((err) => {
		logger.debug({ error: String(err) }, "oauth health probe failed");
		return [] as HealthItem[];
	});
	items.push(...oauthItems);

	// ── Provider sidecars ────────────────────────────────────────────
	const providers = cfg.providers ?? [];
	if (providers.length === 0) {
		items.push({
			id: "providers:none",
			label: "Providers",
			status: "ok",
			detail: "none configured",
		});
	} else {
		try {
			const results = await Promise.all(providers.map((p) => checkProviderHealth(p.id, p.baseUrl)));
			for (const result of results) {
				items.push(buildProviderItem(result));
			}
		} catch (err) {
			items.push({
				id: "providers:error",
				label: "Providers",
				status: "unknown",
				detail: `probe failed: ${String(err).slice(0, 80)}`,
			});
		}
	}

	// ── Cron scheduler + lag ─────────────────────────────────────────
	try {
		const cronJobs = listCronJobs({ includeDisabled: true });
		const enabledJobs = cronJobs.filter((j) => j.enabled);
		const totalJobs = cronJobs.length;
		const cronConfigEnabled = cfg.cron?.enabled ?? true;

		// Count enabled jobs whose nextRun is in the past by more than tolerance.
		const laggingJobs = enabledJobs.filter(
			(j) => j.nextRunAtMs !== null && j.nextRunAtMs + CRON_LAG_TOLERANCE_MS < collectedAtMs,
		);

		items.push({
			id: "cron:scheduler",
			label: "Cron",
			status: !cronConfigEnabled ? "degraded" : laggingJobs.length > 0 ? "degraded" : "ok",
			detail: !cronConfigEnabled
				? "disabled in config"
				: laggingJobs.length > 0
					? `${laggingJobs.length}/${enabledJobs.length} lagging`
					: `${enabledJobs.length}/${totalJobs} enabled`,
			remediation: !cronConfigEnabled
				? "cron_disabled"
				: laggingJobs.length > 0
					? "cron_lagging"
					: undefined,
			observedAtMs: collectedAtMs,
		});

		// Heartbeat last/next run (private heartbeat only).
		const privateHeartbeat = cronJobs.find((j) => j.action.kind === "private-heartbeat");
		if (privateHeartbeat) {
			const lastRun = privateHeartbeat.lastRunAtMs;
			const nextRun = privateHeartbeat.nextRunAtMs;
			const lastPart = lastRun ? `last ${new Date(lastRun).toISOString().slice(11, 16)}` : "never";
			const nextPart = nextRun ? `next ${new Date(nextRun).toISOString().slice(11, 16)}` : "none";
			const stale =
				privateHeartbeat.enabled &&
				nextRun !== null &&
				nextRun + CRON_LAG_TOLERANCE_MS < collectedAtMs;
			items.push({
				id: "heartbeat:private",
				label: "Heartbeat",
				status: !privateHeartbeat.enabled ? "degraded" : stale ? "degraded" : "ok",
				detail: !privateHeartbeat.enabled ? "disabled" : `${lastPart}, ${nextPart}`,
				remediation: !privateHeartbeat.enabled
					? "heartbeat_disabled"
					: stale
						? "heartbeat_stale"
						: undefined,
				observedAtMs: collectedAtMs,
			});
		} else {
			items.push({
				id: "heartbeat:private",
				label: "Heartbeat",
				status: "degraded",
				detail: "no private-heartbeat cron",
				remediation: "heartbeat_disabled",
			});
		}
	} catch (err) {
		items.push({
			id: "cron:scheduler",
			label: "Cron",
			status: "unknown",
			detail: `probe failed: ${String(err).slice(0, 80)}`,
		});
	}

	// ── Active sessions ──────────────────────────────────────────────
	try {
		const sessions = Object.values(getAllSessions());
		const stale = sessions.filter(
			(entry) => collectedAtMs - entry.updatedAt > SESSION_STALE_CUTOFF_MS,
		).length;
		items.push({
			id: "sessions:active",
			label: "Sessions",
			status: stale > 0 ? "degraded" : "ok",
			detail:
				sessions.length === 0
					? "none"
					: stale > 0
						? `${sessions.length} total, ${stale} stale >24h`
						: `${sessions.length} active`,
			remediation: stale > 0 ? "session_stale" : undefined,
		});
	} catch (err) {
		items.push({
			id: "sessions:active",
			label: "Sessions",
			status: "unknown",
			detail: String(err).slice(0, 80),
		});
	}

	// ── Background jobs ──────────────────────────────────────────────
	try {
		const activeJobs = getActiveJobCount();
		items.push({
			id: "background:jobs",
			label: "Background jobs",
			status: "ok",
			detail: activeJobs === 0 ? "idle" : `${activeJobs} active`,
			remediation: activeJobs > 0 ? "active_background_jobs" : undefined,
		});
	} catch (err) {
		items.push({
			id: "background:jobs",
			label: "Background jobs",
			status: "unknown",
			detail: String(err).slice(0, 80),
		});
	}

	// ── Pending approvals (count across all allowed chats) ──────────
	try {
		const { getPendingApprovalsForChat } = await import("../security/approvals.js");
		const chats = cfg.telegram?.allowedChats ?? [];
		let total = 0;
		for (const chat of chats) {
			const chatId = typeof chat === "number" ? chat : Number.parseInt(String(chat), 10);
			if (Number.isNaN(chatId)) continue;
			total += getPendingApprovalsForChat(chatId).length;
		}
		items.push({
			id: "approvals:pending",
			label: "Pending approvals",
			status: total > 0 ? "degraded" : "ok",
			detail: total === 0 ? "none" : `${total} awaiting response`,
			remediation: total > 0 ? "pending_approvals" : undefined,
		});
	} catch (err) {
		items.push({
			id: "approvals:pending",
			label: "Pending approvals",
			status: "unknown",
			detail: String(err).slice(0, 80),
		});
	}

	// ── Audit health ─────────────────────────────────────────────────
	if (status?.audit) {
		const { success, blocked, errors, total } = status.audit;
		const errorRate = total > 0 ? errors / total : 0;
		items.push({
			id: "audit:health",
			label: "Audit",
			status: errorRate > 0.1 ? "degraded" : "ok",
			detail: `${success} ok, ${blocked} blocked, ${errors} errors`,
		});
	}

	return {
		overallStatus: pickOverall(items),
		collectedAtMs,
		items,
		issueCount: countIssues(items),
	};
}
