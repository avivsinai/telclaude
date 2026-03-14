import { collectTelclaudeStatus } from "../commands/status.js";
import { loadConfig } from "../config/config.js";
import { checkProviderHealth, type HealthCheckResult } from "../providers/provider-health.js";

export type StatusOverview = {
	summary: string;
	details: string[];
	providerIssues: HealthCheckResult[];
};

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
