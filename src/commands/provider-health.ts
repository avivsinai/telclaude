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
	cachedDNSLookup,
	checkPrivateNetworkAccess,
	isPrivateIP,
} from "../sandbox/network-proxy.js";

const logger = getChildLogger({ module: "cmd-provider-health" });

// Health response from provider
interface ConnectorHealth {
	status: "ok" | "auth_expired" | "drift_detected" | "error";
	lastSuccess?: string;
	lastAttempt?: string;
	failureCount?: number;
	driftSignals?: string[];
}

interface HealthAlert {
	level: "warn" | "error";
	connector: string;
	message: string;
	since?: string;
}

interface ProviderHealthResponse {
	status: "healthy" | "degraded" | "unhealthy";
	connectors?: Record<string, ConnectorHealth>;
	alerts?: HealthAlert[];
	error?: string;
}

interface HealthCheckResult {
	providerId: string;
	baseUrl: string;
	reachable: boolean;
	response?: ProviderHealthResponse;
	error?: string;
}

async function checkProviderHealth(
	providerId: string,
	baseUrl: string,
): Promise<HealthCheckResult> {
	const result: HealthCheckResult = {
		providerId,
		baseUrl,
		reachable: false,
	};

	try {
		// Parse and validate URL
		const url = new URL("/v1/health", baseUrl);
		const port = url.port ? Number.parseInt(url.port, 10) : url.protocol === "https:" ? 443 : 80;

		// Verify it's in private endpoint allowlist
		const cfg = loadConfig();
		const endpoints = cfg.security?.network?.privateEndpoints ?? [];

		const privateCheck = await checkPrivateNetworkAccess(url.hostname, port, endpoints);
		if (!privateCheck.allowed) {
			result.error = `Provider URL not in private endpoints allowlist: ${privateCheck.reason}`;
			return result;
		}

		// Verify IPs are private
		const resolved = await cachedDNSLookup(url.hostname);
		const ips = resolved && resolved.length > 0 ? resolved : [url.hostname];
		const nonPrivate = ips.filter((ip) => !isPrivateIP(ip));
		if (nonPrivate.length > 0) {
			result.error = `Provider resolves to non-private IPs: ${nonPrivate.join(", ")}`;
			return result;
		}

		// Make health check request
		const controller = new AbortController();
		const timeout = setTimeout(() => controller.abort(), 10000);

		try {
			const response = await fetch(url.toString(), {
				method: "GET",
				headers: {
					accept: "application/json",
				},
				signal: controller.signal,
			});

			if (!response.ok) {
				result.error = `HTTP ${response.status}: ${response.statusText}`;
				return result;
			}

			const text = await response.text();
			try {
				result.response = JSON.parse(text) as ProviderHealthResponse;
				result.reachable = true;
			} catch {
				result.error = "Invalid JSON response from health endpoint";
			}
		} finally {
			clearTimeout(timeout);
		}
	} catch (err) {
		if (err instanceof Error && err.name === "AbortError") {
			result.error = "Request timeout (10s)";
		} else {
			result.error = String(err);
		}
	}

	return result;
}

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

function computeExitCode(results: HealthCheckResult[]): number {
	let hasError = false;
	let hasWarn = false;

	for (const result of results) {
		if (!result.reachable) {
			hasError = true;
			continue;
		}

		const status = result.response?.status;
		if (status === "unhealthy") {
			hasError = true;
		} else if (status === "degraded") {
			hasWarn = true;
		}

		// Also check for error-level alerts
		for (const alert of result.response?.alerts ?? []) {
			if (alert.level === "error") {
				hasError = true;
			} else if (alert.level === "warn") {
				hasWarn = true;
			}
		}
	}

	if (hasError) return 2;
	if (hasWarn) return 1;
	return 0;
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
				const exitCode = computeExitCode(results);
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
