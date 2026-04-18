import type { Command } from "commander";
import { type ExternalProviderConfig, loadConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import {
	getCatalogOAuthService,
	getProviderCatalogEntry,
	listProviderCatalogEntries,
} from "../providers/catalog.js";
import { checkProviderHealth } from "../providers/provider-health.js";
import { buildSchemaMarkdown, fetchProviderSchema } from "../providers/provider-skill.js";
import { validateProviderBaseUrl } from "../providers/provider-validation.js";
import { relayProviderProxy } from "../relay/capabilities-client.js";
import { getVaultClient, isVaultAvailable } from "../vault-daemon/index.js";
import { requireRelay } from "./cli-guards.js";
import type { ProviderQueryOptions } from "./provider-query.js";

const logger = getChildLogger({ module: "cmd-providers" });

type ProviderDoctorStatus = "pass" | "warn" | "fail";

export type ProviderDoctorCheck = {
	name: string;
	status: ProviderDoctorStatus;
	detail: string;
};

export type ProviderDoctorResult = {
	providerId: string;
	baseUrl: string;
	checks: ProviderDoctorCheck[];
};

function formatProvidersList(providers: ExternalProviderConfig[]): string {
	if (providers.length === 0) {
		const available = listProviderCatalogEntries().map((entry) => entry.id);
		const lines = ["No providers configured."];
		if (available.length > 0) {
			lines.push(`Automated setup available for: ${available.join(", ")}`);
		}
		return lines.join("\n");
	}

	return providers
		.map((provider) => {
			const services = provider.services.length > 0 ? provider.services.join(", ") : "(none)";
			const description = provider.description ? `\n  ${provider.description}` : "";
			return `${provider.id}\n  Base URL: ${provider.baseUrl}\n  Services: ${services}${description}`;
		})
		.join("\n\n");
}

function formatProviderDoctor(results: ProviderDoctorResult[]): string {
	const lines: string[] = [];
	for (const result of results) {
		lines.push(`${result.providerId} (${result.baseUrl})`);
		for (const check of result.checks) {
			const icon = check.status === "pass" ? "✓" : check.status === "warn" ? "⚠" : "✗";
			lines.push(`  ${icon} ${check.name}: ${check.detail}`);
		}
		lines.push("");
	}
	return lines.join("\n").trim();
}

function computeDoctorExitCode(results: ProviderDoctorResult[]): number {
	const statuses = results.flatMap((result) => result.checks.map((check) => check.status));
	if (statuses.includes("fail")) return 2;
	if (statuses.includes("warn")) return 1;
	return 0;
}

export async function collectProviderDoctorResults(
	providerId?: string,
): Promise<ProviderDoctorResult[]> {
	const config = loadConfig();
	const configured = config.providers ?? [];
	const selected = providerId
		? configured.filter((provider) => provider.id === providerId)
		: configured;

	const results: ProviderDoctorResult[] = [];
	for (const provider of selected) {
		const checks: ProviderDoctorCheck[] = [];

		try {
			const { url, port } = await validateProviderBaseUrl(provider.baseUrl);
			checks.push({
				name: "network",
				status: "pass",
				detail: `allowlisted private endpoint ${url.hostname}:${port}`,
			});
		} catch (err) {
			checks.push({
				name: "network",
				status: "fail",
				detail: err instanceof Error ? err.message : String(err),
			});
		}

		const health = await checkProviderHealth(provider.id, provider.baseUrl);
		if (!health.reachable) {
			checks.push({
				name: "health",
				status: "fail",
				detail: health.error ?? "provider unreachable",
			});
		} else if (health.response?.status === "degraded") {
			checks.push({ name: "health", status: "warn", detail: "provider reported degraded" });
		} else {
			checks.push({
				name: "health",
				status: "pass",
				detail: health.response?.status ?? "healthy",
			});
		}

		const schema = await fetchProviderSchema(provider, 0);
		if (schema.error) {
			checks.push({ name: "schema", status: "fail", detail: schema.error });
		} else {
			const services = Array.isArray(
				(schema.schema as { services?: unknown[] } | undefined)?.services,
			)
				? ((schema.schema as { services?: unknown[] }).services?.length ?? 0)
				: provider.services.length;
			checks.push({
				name: "schema",
				status: "pass",
				detail: `${services} service definition(s) available`,
			});
		}

		const catalogEntry = getProviderCatalogEntry(provider.id);
		const oauthService = catalogEntry?.oauthServiceId
			? getCatalogOAuthService(catalogEntry.oauthServiceId)
			: undefined;
		if (oauthService) {
			if (!(await isVaultAvailable())) {
				checks.push({
					name: "oauth",
					status: "warn",
					detail: "vault unavailable; cannot verify OAuth credentials",
				});
			} else {
				const client = getVaultClient();
				const entry = await client.get("http", oauthService.vaultTarget);
				checks.push({
					name: "oauth",
					status: entry.ok ? "pass" : "fail",
					detail: entry.ok ? "credentials stored in vault" : "credentials missing from vault",
				});
			}
		}

		results.push({ providerId: provider.id, baseUrl: provider.baseUrl, checks });
	}

	return results;
}

async function runProvidersQuery(
	providerId: string,
	service: string,
	action: string,
	options: ProviderQueryOptions,
): Promise<void> {
	requireRelay();

	let params: Record<string, unknown> = {};
	if (options.params) {
		try {
			params = JSON.parse(options.params) as Record<string, unknown>;
		} catch (parseErr) {
			console.error(`Error: Invalid JSON in --params: ${String(parseErr)}`);
			process.exitCode = 1;
			return;
		}
	}

	const requestBody: Record<string, unknown> = { service, action, params };
	if (options.subjectUserId?.trim()) {
		requestBody.subjectUserId = options.subjectUserId.trim();
	}
	if (options.idempotencyKey?.trim()) {
		requestBody.idempotencyKey = options.idempotencyKey.trim();
	}

	const result = await relayProviderProxy({
		providerId,
		path: "/v1/fetch",
		method: "POST",
		body: JSON.stringify(requestBody),
		userId: options.userId ?? process.env.TELCLAUDE_REQUEST_USER_ID,
		approvalToken: options.approvalToken?.trim(),
	});

	if (result.status !== "ok") {
		if (result.errorCode === "approval_required" && result.approvalNonce) {
			console.log(
				JSON.stringify(
					{
						status: "approval_required",
						error: result.error,
						approvalNonce: result.approvalNonce,
					},
					null,
					2,
				),
			);
			process.exitCode = 2;
			return;
		}
		console.log(
			JSON.stringify(
				{
					status: "error",
					error: result.error,
					errorCode: result.errorCode,
				},
				null,
				2,
			),
		);
		process.exitCode = 1;
		return;
	}

	console.log(JSON.stringify(result.data, null, 2));
}

export function registerProvidersCommandGroup(parent: Command): void {
	parent
		.command("list")
		.description("List configured external providers")
		.option("--json", "Output as JSON")
		.action((options: { json?: boolean }) => {
			const providers = loadConfig().providers ?? [];
			if (options.json) {
				console.log(JSON.stringify(providers, null, 2));
				return;
			}
			console.log(formatProvidersList(providers));
		});

	parent
		.command("schema")
		.description("Fetch provider schema for one provider or all configured providers")
		.argument("[provider-id]", "Specific provider to inspect")
		.option("--json", "Output raw JSON instead of markdown")
		.action(async (providerId: string | undefined, options: { json?: boolean }) => {
			const configured = loadConfig().providers ?? [];
			const selected = providerId
				? configured.filter((provider) => provider.id === providerId)
				: configured;
			if (selected.length === 0) {
				console.error(
					providerId
						? `Provider '${providerId}' not found in telclaude config.`
						: "No providers configured.",
				);
				process.exitCode = 1;
				return;
			}

			const results = await Promise.all(
				selected.map((provider) => fetchProviderSchema(provider, 0)),
			);
			if (options.json) {
				const body = results.map((result) => ({
					providerId: result.provider.id,
					baseUrl: result.provider.baseUrl,
					schema: result.schema ?? null,
					error: result.error,
				}));
				console.log(JSON.stringify(body, null, 2));
				process.exitCode = results.some((result) => result.error) ? 1 : 0;
				return;
			}

			console.log(buildSchemaMarkdown(results));
			process.exitCode = results.some((result) => result.error) ? 1 : 0;
		});

	parent
		.command("query")
		.description("Query a configured provider through the relay proxy")
		.argument("<provider-id>", "Configured provider ID")
		.argument("<service>", "Service ID")
		.argument("<action>", "Action ID")
		.option("--params <json>", "Optional JSON parameters")
		.option("--user-id <id>", "Actor user ID (defaults to TELCLAUDE_REQUEST_USER_ID when set)")
		.option("--subject-user-id <id>", "Subject user ID for delegated requests")
		.option("--idempotency-key <key>", "Idempotency key for write operations")
		.option("--approval-token <token>", "Signed approval token for action-type requests")
		.action(
			async (
				providerId: string,
				service: string,
				action: string,
				options: ProviderQueryOptions,
			) => {
				try {
					await runProvidersQuery(providerId, service, action, options);
				} catch (err) {
					logger.error(
						{ error: String(err), providerId, service, action },
						"providers query failed",
					);
					console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
					process.exit(1);
				}
			},
		);

	parent
		.command("doctor")
		.description("Run health, network, schema, and auth checks for providers")
		.argument("[provider-id]", "Specific provider to inspect")
		.option("--json", "Output structured JSON")
		.action(async (providerId: string | undefined, options: { json?: boolean }) => {
			const configured = loadConfig().providers ?? [];
			if (configured.length === 0) {
				console.log(options.json ? JSON.stringify([]) : "No providers configured.");
				return;
			}

			const results = await collectProviderDoctorResults(providerId);
			if (results.length === 0) {
				console.error(`Provider '${providerId}' not found.`);
				process.exitCode = 1;
				return;
			}

			if (options.json) {
				console.log(JSON.stringify(results, null, 2));
			} else {
				console.log(formatProviderDoctor(results));
			}
			process.exitCode = computeDoctorExitCode(results);
		});
}
