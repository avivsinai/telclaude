import { execSync } from "node:child_process";
import fs from "node:fs";
import type { Command } from "commander";
import { getConfigPath, loadConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { createAuditLogger } from "../security/audit.js";

const logger = getChildLogger({ module: "cmd-status" });

export type StatusOptions = {
	json?: boolean;
};

export function registerStatusCommand(program: Command): void {
	program
		.command("status")
		.description("Show Telclaude status and configuration")
		.option("--json", "Output as JSON")
		.action(async (opts: StatusOptions) => {
			try {
				const configPath = getConfigPath();
				const hasConfig = fs.existsSync(configPath);
				const cfg = hasConfig ? loadConfig() : null;

				const tokenFromConfig = cfg?.telegram?.botToken;
				const tokenFromEnv = process.env.TELEGRAM_BOT_TOKEN;
				const telegramToken = tokenFromConfig
					? { status: "set" as const, source: "config" as const }
					: null;
				const telegramTokenResolved =
					telegramToken ??
					(tokenFromEnv ? { status: "set" as const, source: "env" as const } : null);

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

				const status = {
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
				};

				if (opts.json) {
					console.log(JSON.stringify(status, null, 2));
				} else {
					console.log("=== Telclaude Status ===\n");

					console.log("Configuration:");
					console.log(`  Path: ${status.config.path}`);
					console.log(`  Exists: ${status.config.exists ? "yes" : "no"}`);
					console.log();

					console.log("Environment:");
					console.log(`  TELEGRAM_BOT_TOKEN: ${status.environment.telegramToken}`);
					console.log(`  Claude CLI: ${status.environment.claudeCli}`);
					console.log();

					if (status.security) {
						console.log("Security:");
						console.log(`  Profile: ${status.security.profile}`);
						console.log(`  Observer: ${status.security.observer}`);
						console.log(`  Audit: ${status.security.audit}`);
						console.log(`  Rate Limiting: ${status.security.rateLimiting}`);
						if (status.security.permissions) {
							console.log(`  Default Tier: ${status.security.permissions.defaultTier}`);
							console.log(`  User Overrides: ${status.security.permissions.userOverrides}`);
						}
						console.log();
					}

					if (status.telegram) {
						console.log("Telegram:");
						if (status.telegram.allowedChats.length > 0) {
							console.log(`  Allowed Chats: ${status.telegram.allowedChats.join(", ")}`);
						} else {
							// SECURITY: Empty allowedChats means DENY ALL, not allow all (fail-closed)
							console.log(
								"  Allowed Chats: none (security fail-closed; configure allowedChats to permit access)",
							);
						}
						console.log();
					}

					if (status.audit) {
						console.log("Audit Statistics:");
						console.log(`  Total requests: ${status.audit.total}`);
						console.log(`  Successful: ${status.audit.success}`);
						console.log(`  Blocked: ${status.audit.blocked}`);
						console.log(`  Rate Limited: ${status.audit.rateLimited}`);
						console.log(`  Errors: ${status.audit.errors}`);
					}
				}
			} catch (err) {
				logger.error({ error: String(err) }, "status command failed");
				console.error(`Error: ${err}`);
				process.exit(1);
			}
		});
}
