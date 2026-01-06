/**
 * CLI command for checking external provider health status.
 *
 * Commands:
 * - telclaude provider-health - Check all providers
 * - telclaude provider-health <provider-id> - Check specific provider
 * - telclaude provider-health --json - Output as JSON
 * - telclaude provider-health --alert-telegram - Send Telegram alert if degraded
 *
 * Exit codes:
 * - 0: All providers healthy
 * - 1: At least one provider degraded (warn-level)
 * - 2: At least one provider unhealthy (error-level)
 */

import type { Command } from "commander";
import { loadConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import {
	checkProviderHealth,
	computeProviderHealthExitCode,
	type HealthCheckResult,
} from "../providers/provider-health.js";

const logger = getChildLogger({ module: "cmd-provider-health" });

function formatHealthOutput(results: HealthCheckResult[], json: boolean): string {
	if (json) {
		return JSON.stringify(results, null, 2);
	}

	const lines: string[] = [];

	for (const result of results) {
		const statusIcon = result.reachable
			? result.response?.status === "healthy"
				? "✓"
				: result.response?.status === "degraded"
					? "⚠"
					: "✗"
			: "✗";

		lines.push(`${statusIcon} ${result.providerId} (${result.baseUrl})`);

		if (!result.reachable) {
			lines.push(`  Error: ${result.error}`);
			continue;
		}

		const resp = result.response;
		if (!resp) continue;

		lines.push(`  Status: ${resp.status}`);

		// Show connector statuses
		if (resp.connectors) {
			for (const [name, connector] of Object.entries(resp.connectors)) {
				const connIcon =
					connector.status === "ok"
						? "✓"
						: connector.status === "auth_expired"
							? "🔑"
							: connector.status === "drift_detected"
								? "⚠"
								: "✗";
				lines.push(`  ${connIcon} ${name}: ${connector.status}`);
				if (connector.lastSuccess) {
					lines.push(`    Last success: ${connector.lastSuccess}`);
				}
				if (connector.driftSignals?.length) {
					lines.push(`    Drift signals: ${connector.driftSignals.join(", ")}`);
				}
			}
		}

		// Show alerts
		if (resp.alerts?.length) {
			lines.push("  Alerts:");
			for (const alert of resp.alerts) {
				const alertIcon = alert.level === "error" ? "✗" : "⚠";
				lines.push(`    ${alertIcon} [${alert.connector}] ${alert.message}`);
			}
		}
	}

	return lines.join("\n");
}

export function registerProviderHealthCommand(program: Command): void {
	program
		.command("provider-health")
		.description("Check health status of configured external providers")
		.argument("[provider-id]", "Specific provider to check (default: all)")
		.option("--json", "Output as JSON")
		.option("--alert-telegram", "Send Telegram alert if any provider is degraded/unhealthy")
		.action(
			async (
				providerId: string | undefined,
				options: { json?: boolean; alertTelegram?: boolean },
			) => {
				const cfg = loadConfig();
				const providers = cfg.providers ?? [];

				if (providers.length === 0) {
					if (options.json) {
						console.log(JSON.stringify({ error: "No providers configured" }));
					} else {
						console.log("No providers configured.");
						console.log("Add providers to telclaude.json under 'providers' array.");
					}
					process.exitCode = 0;
					return;
				}

				// Filter to specific provider if requested
				const toCheck = providerId ? providers.filter((p) => p.id === providerId) : providers;

				if (toCheck.length === 0) {
					if (options.json) {
						console.log(JSON.stringify({ error: `Provider '${providerId}' not found` }));
					} else {
						console.log(`Provider '${providerId}' not found.`);
						console.log(`Available providers: ${providers.map((p) => p.id).join(", ")}`);
					}
					process.exitCode = 1;
					return;
				}

				// Check all providers
				const results: HealthCheckResult[] = [];
				for (const provider of toCheck) {
					const result = await checkProviderHealth(provider.id, provider.baseUrl);
					results.push(result);
				}

				// Output results
				console.log(formatHealthOutput(results, options.json ?? false));

				// Compute exit code
				const exitCode = computeProviderHealthExitCode(results);
				process.exitCode = exitCode;

				// Send Telegram alert if requested and there are issues
				if (options.alertTelegram && exitCode > 0) {
					try {
						// Dynamic import to avoid circular deps and keep command lightweight
						const { sendAdminAlert } = await import("../telegram/admin-alert.js");
						const alertLevel = exitCode === 2 ? "error" : "warn";
						const summary = results
							.filter((r) => !r.reachable || r.response?.status !== "healthy")
							.map((r) => `${r.providerId}: ${r.response?.status ?? r.error}`)
							.join("\n");

						await sendAdminAlert({
							level: alertLevel,
							title: "Provider Health Alert",
							message: summary,
						});

						if (!options.json) {
							console.log("\nTelegram alert sent to admin.");
						}
					} catch (err) {
						logger.warn({ error: String(err) }, "Failed to send Telegram alert");
						if (!options.json) {
							console.log(`\nFailed to send Telegram alert: ${err}`);
						}
					}
				}
			},
		);
}
