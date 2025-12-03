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

				const token = process.env.TELEGRAM_BOT_TOKEN;
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
						telegramToken: token ? "set" : "not set",
						claudeCli,
					},
					security: cfg
						? {
								observer: cfg.security?.observer?.enabled !== false ? "enabled" : "disabled",
								audit: cfg.security?.audit?.enabled !== false ? "enabled" : "disabled",
								rateLimiting: "enabled",
								permissionTiers: cfg.security?.permissions
									? Object.keys(cfg.security.permissions)
									: [],
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
						console.log(`  Observer: ${status.security.observer}`);
						console.log(`  Audit: ${status.security.audit}`);
						console.log(`  Rate Limiting: ${status.security.rateLimiting}`);
						if (status.security.permissionTiers.length > 0) {
							console.log(`  Permission Tiers: ${status.security.permissionTiers.join(", ")}`);
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
