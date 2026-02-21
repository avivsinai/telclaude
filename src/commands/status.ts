import { execSync } from "node:child_process";
import fs from "node:fs";
import type { Command } from "commander";
import { getConfigPath, loadConfig } from "../config/config.js";
import { getAllSessions } from "../config/sessions.js";
import { getCronStatusSummary } from "../cron/store.js";
import { getChildLogger } from "../logging.js";
import { createAuditLogger } from "../security/audit.js";
import { buildRuntimeSnapshot } from "../system-metadata.js";

const logger = getChildLogger({ module: "cmd-status" });
const STATUS_STARTED_AT = Date.now();

export type StatusOptions = {
	json?: boolean;
};

export type TelclaudeStatus = {
	config: {
		path: string;
		exists: boolean;
	};
	environment: {
		telegramToken: string;
		claudeCli: string;
	};
	security: {
		profile: string;
		observer: string;
		audit: string;
		rateLimiting: string;
		permissions?: {
			defaultTier?: string;
			userOverrides?: number;
		} | null;
	} | null;
	telegram: {
		allowedChats: Array<string | number>;
	} | null;
	audit: {
		total: number;
		success: number;
		blocked: number;
		rateLimited: number;
		errors: number;
	} | null;
	services: {
		externalProviders: number;
		socialServices: number;
		enabledSocialServices: number;
	};
	runtime: {
		version: string;
		revision: string;
		startedAt: string;
		uptimeMs: number;
		uptimeSeconds: number;
	};
	operations: {
		sessions: {
			total: number;
			staleOver24h: number;
			recent: Array<{
				key: string;
				updatedAt: string;
				ageSeconds: number;
			}>;
		};
		cron: {
			enabled: boolean;
			totalJobs: number;
			enabledJobs: number;
			runningJobs: number;
			nextRunAt: string | null;
		};
	};
};

function formatUptime(seconds: number): string {
	const minutes = Math.floor(seconds / 60);
	const hours = Math.floor(minutes / 60);
	const remainingMinutes = minutes % 60;
	const remainingSeconds = seconds % 60;

	if (hours > 0) {
		return `${hours}h ${remainingMinutes}m ${remainingSeconds}s`;
	}

	if (minutes > 0) {
		return `${minutes}m ${remainingSeconds}s`;
	}

	return `${remainingSeconds}s`;
}

function formatAgeShort(seconds: number): string {
	if (seconds < 60) {
		return `${seconds}s`;
	}
	const minutes = Math.floor(seconds / 60);
	if (minutes < 60) {
		return `${minutes}m`;
	}
	const hours = Math.floor(minutes / 60);
	if (hours < 24) {
		return `${hours}h`;
	}
	const days = Math.floor(hours / 24);
	return `${days}d`;
}

export async function collectTelclaudeStatus(): Promise<TelclaudeStatus> {
	const configPath = getConfigPath();
	const hasConfig = fs.existsSync(configPath);
	const cfg = hasConfig ? loadConfig() : null;

	const tokenFromConfig = cfg?.telegram?.botToken;
	const tokenFromEnv = process.env.TELEGRAM_BOT_TOKEN;
	const telegramToken = tokenFromConfig
		? { status: "set" as const, source: "config" as const }
		: null;
	const telegramTokenResolved =
		telegramToken ?? (tokenFromEnv ? { status: "set" as const, source: "env" as const } : null);

	let claudeCli = "missing";
	try {
		const version = execSync("claude --version", {
			encoding: "utf8",
			stdio: ["ignore", "pipe", "pipe"],
		}).trim();
		claudeCli = version || "installed";
	} catch {
		// best-effort check only
	}

	// Get audit stats if enabled
	let auditStats = null;
	if (cfg?.security?.audit?.enabled !== false) {
		// Best-effort; AuditLogger initializes securely but does not create the log file.
		const auditLogger = createAuditLogger({
			enabled: true,
			logFile: cfg?.security?.audit?.logFile,
		});
		auditStats = await auditLogger.getStats();
	}

	const serviceCounts = {
		externalProviders: cfg?.providers?.length ?? 0,
		socialServices: cfg?.socialServices?.length ?? 0,
		enabledSocialServices: (cfg?.socialServices ?? []).filter((svc) => svc.enabled).length,
	};

	const runtime = buildRuntimeSnapshot(STATUS_STARTED_AT);
	const sessions = Object.entries(getAllSessions())
		.map(([key, entry]) => {
			const ageSeconds = Math.max(0, Math.floor((Date.now() - entry.updatedAt) / 1000));
			return {
				key,
				updatedAt: new Date(entry.updatedAt).toISOString(),
				ageSeconds,
			};
		})
		.sort((a, b) => a.ageSeconds - b.ageSeconds);
	const cronSummary = getCronStatusSummary();

	return {
		config: {
			path: configPath,
			exists: hasConfig,
		},
		environment: {
			telegramToken: telegramTokenResolved
				? `${telegramTokenResolved.status} (${telegramTokenResolved.source})`
				: "not set",
			claudeCli,
		},
		security: cfg
			? {
					profile: cfg.security?.profile ?? "simple",
					observer: cfg.security?.observer?.enabled !== false ? "enabled" : "disabled",
					audit: cfg.security?.audit?.enabled !== false ? "enabled" : "disabled",
					rateLimiting: "enabled",
					permissions: cfg.security?.permissions
						? {
								defaultTier: cfg.security.permissions.defaultTier,
								userOverrides: Object.keys(cfg.security.permissions.users ?? {}).length,
							}
						: null,
				}
			: null,
		telegram: cfg
			? {
					allowedChats: cfg.telegram?.allowedChats ?? [],
				}
			: null,
		audit: auditStats,
		services: serviceCounts,
		runtime: {
			version: runtime.version,
			revision: runtime.revision,
			startedAt: runtime.startedAt,
			uptimeMs: runtime.uptimeMs,
			uptimeSeconds: runtime.uptimeSeconds,
		},
		operations: {
			sessions: {
				total: sessions.length,
				staleOver24h: sessions.filter((session) => session.ageSeconds > 24 * 3600).length,
				recent: sessions.slice(0, 5),
			},
			cron: {
				enabled: cfg?.cron?.enabled ?? true,
				totalJobs: cronSummary.totalJobs,
				enabledJobs: cronSummary.enabledJobs,
				runningJobs: cronSummary.runningJobs,
				nextRunAt: cronSummary.nextRunAtMs ? new Date(cronSummary.nextRunAtMs).toISOString() : null,
			},
		},
	};
}

export function formatTelclaudeStatus(status: TelclaudeStatus, telegram = false): string {
	if (telegram) {
		const lines: string[] = [
			"=== Telclaude Status ===",
			"",
			"Runtime:",
			`  Version: ${status.runtime.version}`,
			`  Revision: ${status.runtime.revision}`,
			`  CLI Started: ${status.runtime.startedAt}`,
			`  CLI Uptime: ${formatUptime(status.runtime.uptimeSeconds)}`,
			"",
			"Services:",
			`  External Providers: ${status.services.externalProviders}`,
			`  Social Services: ${status.services.enabledSocialServices}/${status.services.socialServices}`,
			"",
			"Operations:",
			`  Sessions: ${status.operations.sessions.total} total (${status.operations.sessions.staleOver24h} stale >24h)`,
			`  Cron: ${status.operations.cron.enabledJobs}/${status.operations.cron.totalJobs} enabled${status.operations.cron.runningJobs > 0 ? ` (${status.operations.cron.runningJobs} running)` : ""}`,
			"",
			"Security:",
			`  Profile: ${status.security?.profile ?? "unknown"}`,
			`  Observer: ${status.security?.observer ?? "unknown"}`,
			`  Audit: ${status.security?.audit ?? "unknown"}`,
			`  Rate Limiting: ${status.security?.rateLimiting ?? "unknown"}`,
			"",
			"Configuration:",
			`  Path: ${status.config.path}`,
			`  Exists: ${status.config.exists ? "yes" : "no"}`,
			"",
			"Environment:",
			`  Telegram token: ${status.environment.telegramToken}`,
			`  Claude CLI: ${status.environment.claudeCli}`,
		];

		if (status.telegram?.allowedChats?.length) {
			lines.push("");
			lines.push("Telegram:");
			lines.push(`  Allowed Chats: ${status.telegram.allowedChats.length}`);
		}

		if (status.audit) {
			lines.push("", "Audit:");
			lines.push(`  Total requests: ${status.audit.total}`);
			lines.push(`  Successful: ${status.audit.success}`);
			lines.push(`  Blocked: ${status.audit.blocked}`);
			lines.push(`  Rate Limited: ${status.audit.rateLimited}`);
			lines.push(`  Errors: ${status.audit.errors}`);
		}

		return lines.join("\n");
	}

	const lines: string[] = [];
	lines.push("=== Telclaude Status ===");
	lines.push("Runtime:");
	lines.push(`  Version: ${status.runtime.version}`);
	lines.push(`  Revision: ${status.runtime.revision}`);
	lines.push(`  CLI Started: ${status.runtime.startedAt}`);
	lines.push(`  CLI Uptime: ${formatUptime(status.runtime.uptimeSeconds)}`);
	lines.push("");
	lines.push("Configuration:");
	lines.push(`  Path: ${status.config.path}`);
	lines.push(`  Exists: ${status.config.exists ? "yes" : "no"}`);
	lines.push("");
	lines.push("Services:");
	lines.push(`  External Providers: ${status.services.externalProviders}`);
	lines.push(
		`  Social Services: ${status.services.enabledSocialServices}/${status.services.socialServices}`,
	);
	lines.push("");
	lines.push("Operations:");
	lines.push(
		`  Sessions: ${status.operations.sessions.total} total (${status.operations.sessions.staleOver24h} stale >24h)`,
	);
	if (status.operations.sessions.recent.length > 0) {
		for (const recent of status.operations.sessions.recent) {
			lines.push(`    ${recent.key} (${formatAgeShort(recent.ageSeconds)} ago)`);
		}
	}
	lines.push(
		`  Cron: ${status.operations.cron.enabled ? "enabled" : "disabled"} in config, ${status.operations.cron.enabledJobs}/${status.operations.cron.totalJobs} jobs enabled`,
	);
	if (status.operations.cron.nextRunAt) {
		lines.push(`    Next run: ${status.operations.cron.nextRunAt}`);
	}
	lines.push("");
	lines.push("Environment:");
	lines.push(`  TELEGRAM_BOT_TOKEN: ${status.environment.telegramToken}`);
	lines.push(`  Claude CLI: ${status.environment.claudeCli}`);
	lines.push("");

	if (status.security) {
		lines.push("Security:");
		lines.push(`  Profile: ${status.security.profile}`);
		lines.push(`  Observer: ${status.security.observer}`);
		lines.push(`  Audit: ${status.security.audit}`);
		lines.push(`  Rate Limiting: ${status.security.rateLimiting}`);
		if (status.security.permissions) {
			lines.push(`  Default Tier: ${status.security.permissions.defaultTier}`);
			lines.push(`  User Overrides: ${status.security.permissions.userOverrides}`);
		}
		lines.push("");
	}

	if (status.telegram) {
		lines.push("Telegram:");
		if (status.telegram.allowedChats.length > 0) {
			lines.push(`  Allowed Chats: ${status.telegram.allowedChats.join(", ")}`);
		} else {
			// SECURITY: Empty allowedChats means DENY ALL, not allow all (fail-closed)
			lines.push(
				"  Allowed Chats: none (security fail-closed; configure allowedChats to permit access)",
			);
		}
		lines.push("");
	}

	if (status.audit) {
		lines.push("Audit Statistics:");
		lines.push(`  Total requests: ${status.audit.total}`);
		lines.push(`  Successful: ${status.audit.success}`);
		lines.push(`  Blocked: ${status.audit.blocked}`);
		lines.push(`  Rate Limited: ${status.audit.rateLimited}`);
		lines.push(`  Errors: ${status.audit.errors}`);
	}

	return lines.join("\n");
}

export function registerStatusCommand(program: Command): void {
	program
		.command("status")
		.description("Show Telclaude status and configuration")
		.option("--json", "Output as JSON")
		.action(async (opts: StatusOptions) => {
			try {
				const status = await collectTelclaudeStatus();

				if (opts.json) {
					console.log(JSON.stringify(status, null, 2));
				} else {
					console.log(formatTelclaudeStatus(status, false));
				}
			} catch (err) {
				logger.error({ error: String(err) }, "status command failed");
				console.error(`Error: ${err}`);
				process.exit(1);
			}
		});
}
