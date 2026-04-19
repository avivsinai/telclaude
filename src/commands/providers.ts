import fs from "node:fs";
import type { Command } from "commander";
import JSON5 from "json5";
import {
	type ExternalProviderConfig,
	getConfigPath,
	loadConfig,
	type PrivateEndpoint,
	resetConfigCache,
} from "../config/config.js";
import { resolveRuntimeConfigPath } from "../config/path.js";
import { getChildLogger } from "../logging.js";
import {
	getCatalogOAuthService,
	getProviderCatalogEntry,
	listProviderCatalogEntries,
	type ProviderCatalogEntry,
} from "../providers/catalog.js";
import { checkProviderHealth } from "../providers/provider-health.js";
import {
	buildSchemaMarkdown,
	clearProviderSkillState,
	fetchProviderSchema,
	refreshExternalProviderSkill,
} from "../providers/provider-skill.js";
import {
	validateProviderBaseUrl,
	validateProviderBaseUrlInput,
} from "../providers/provider-validation.js";
import {
	relayProviderProxy,
	relayRefreshProviders,
	relayRemoveProvider,
	relayUpsertProvider,
} from "../relay/capabilities-client.js";
import { getVaultClient, isVaultAvailable } from "../vault-daemon/index.js";
import { requireRelay } from "./cli-guards.js";
import { promptLine, promptYesNo } from "./cli-prompt.js";
import type { ProviderQueryOptions } from "./provider-query.js";
import { GOOGLE_SCOPE_BUNDLES, runGoogleOAuthSetup } from "./setup-google.js";

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

export type ProviderConfigInput = {
	id: string;
	baseUrl: string;
	services: string[];
	description?: string;
	displayName?: string;
	oauthServiceId?: string;
	setupCommand?: string;
	endpointLabel?: string;
	endpointDescription?: string;
};

type ProviderMutationMode = "add" | "edit" | "setup";

export type ProviderMutationInput = {
	baseUrl: string;
	services: string[];
	description?: string | null;
};

export type ProviderMutationResult = {
	provider: ProviderConfigInput;
	providers: ExternalProviderConfig[];
	refresh: { providerCount: number; cleared: boolean };
	doctorResults: ProviderDoctorResult[];
};

export type ProviderRemovalResult = {
	providerId: string;
	removedProvider: boolean;
	removedPrivateEndpoint: boolean;
	providers: ExternalProviderConfig[];
	refresh: { providerCount: number; cleared: boolean };
};

const PROVIDER_ID_PATTERN = /^[a-z0-9][a-z0-9-]*$/;

function readConfigFile(): Record<string, unknown> {
	const configPath = getConfigPath();
	const runtimePath = resolveRuntimeConfigPath(configPath);
	try {
		const policy = JSON5.parse(fs.readFileSync(configPath, "utf8")) as Record<string, unknown>;
		try {
			const runtime = JSON5.parse(fs.readFileSync(runtimePath, "utf8")) as Record<string, unknown>;
			return deepMerge(policy, runtime);
		} catch {
			return policy;
		}
	} catch {
		try {
			return JSON5.parse(fs.readFileSync(runtimePath, "utf8")) as Record<string, unknown>;
		} catch {
			return {};
		}
	}
}

function writeConfigFile(config: Record<string, unknown>): void {
	const configPath = resolveRuntimeConfigPath(getConfigPath());
	const configDir = configPath.replace(/[/\\][^/\\]+$/, "");
	fs.mkdirSync(configDir, { recursive: true });
	const tmpPath = `${configPath}.tmp.${process.pid}.${Date.now()}`;
	fs.writeFileSync(tmpPath, JSON.stringify(config, null, 2), "utf8");
	fs.renameSync(tmpPath, configPath);
	resetConfigCache();
}

function deepMerge(
	target: Record<string, unknown>,
	source: Record<string, unknown>,
): Record<string, unknown> {
	const result = { ...target };
	for (const key of Object.keys(source)) {
		const tVal = target[key];
		const sVal = source[key];
		if (isPlainObject(tVal) && isPlainObject(sVal)) {
			result[key] = deepMerge(tVal as Record<string, unknown>, sVal as Record<string, unknown>);
		} else {
			result[key] = sVal;
		}
	}
	return result;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function ensureProviderConfigArray(rawConfig: Record<string, unknown>): ExternalProviderConfig[] {
	if (!Array.isArray(rawConfig.providers)) {
		rawConfig.providers = [];
	}
	return rawConfig.providers as ExternalProviderConfig[];
}

function ensurePrivateEndpointsArray(rawConfig: Record<string, unknown>): PrivateEndpoint[] {
	if (!rawConfig.security || typeof rawConfig.security !== "object") {
		rawConfig.security = {};
	}
	const security = rawConfig.security as Record<string, unknown>;
	if (!security.network || typeof security.network !== "object") {
		security.network = {};
	}
	const network = security.network as Record<string, unknown>;
	if (!Array.isArray(network.privateEndpoints)) {
		network.privateEndpoints = [];
	}
	return network.privateEndpoints as PrivateEndpoint[];
}

function defaultPortForUrl(url: URL): number {
	if (url.port) {
		return Number.parseInt(url.port, 10);
	}
	return url.protocol === "https:" ? 443 : 80;
}

function normalizeBaseUrl(baseUrl: string): string {
	const parsed = new URL(baseUrl);
	return parsed.toString().replace(/\/$/, "");
}

function normalizeProviderServices(services: string[]): string[] {
	return Array.from(
		new Set(services.map((service) => service.trim()).filter((service) => service.length > 0)),
	);
}

function assertProviderServices(services: string[]): string[] {
	const normalized = normalizeProviderServices(services);
	if (normalized.length === 0) {
		throw new Error("At least one service is required.");
	}
	return normalized;
}

function defaultEndpointLabel(providerId: string): string {
	return `provider-${providerId}`;
}

export function buildCatalogProviderInput(
	entry: ProviderCatalogEntry,
	baseUrl: string,
): ProviderConfigInput {
	return {
		id: entry.id,
		baseUrl: normalizeBaseUrl(baseUrl),
		services: [...entry.services],
		description: entry.description,
		displayName: entry.displayName,
		oauthServiceId: entry.oauthServiceId,
		setupCommand: entry.setupCommand,
		endpointLabel: defaultEndpointLabel(entry.id),
		endpointDescription: `${entry.displayName} provider sidecar`,
	};
}

export function buildCustomProviderInput(input: {
	id: string;
	baseUrl: string;
	services: string[];
	description?: string;
}): ProviderConfigInput {
	const id = input.id.trim();
	return {
		id,
		baseUrl: normalizeBaseUrl(input.baseUrl),
		services: normalizeProviderServices(input.services),
		description: input.description?.trim() || undefined,
		displayName: input.description?.trim() || id,
		endpointLabel: defaultEndpointLabel(id),
		endpointDescription: input.description?.trim() || `${id} provider sidecar`,
	};
}

export function upsertConfiguredProvider(
	rawConfig: Record<string, unknown>,
	input: ProviderConfigInput,
): void {
	const providers = ensureProviderConfigArray(rawConfig);
	const next: ExternalProviderConfig = {
		id: input.id,
		baseUrl: normalizeBaseUrl(input.baseUrl),
		services: normalizeProviderServices(input.services),
		description: input.description,
	};
	const existingIndex = providers.findIndex((provider) => provider.id === input.id);
	if (existingIndex === -1) {
		providers.push(next);
	} else {
		providers[existingIndex] = next;
	}
}

export function upsertProviderPrivateEndpoint(
	rawConfig: Record<string, unknown>,
	input: ProviderConfigInput,
): void {
	const parsed = new URL(input.baseUrl);
	const endpoints = ensurePrivateEndpointsArray(rawConfig);
	const label = input.endpointLabel?.trim() || defaultEndpointLabel(input.id);
	const next: PrivateEndpoint = {
		label,
		host: parsed.hostname,
		ports: [defaultPortForUrl(parsed)],
		description:
			input.endpointDescription?.trim() || input.description || `${input.id} provider sidecar`,
	};
	const existingIndex = endpoints.findIndex((endpoint) => endpoint.label === label);
	if (existingIndex === -1) {
		endpoints.push(next);
	} else {
		endpoints[existingIndex] = next;
	}
}

export function removeConfiguredProvider(
	rawConfig: Record<string, unknown>,
	providerId: string,
): { removedProvider: boolean; removedPrivateEndpoint: boolean } {
	const providers = ensureProviderConfigArray(rawConfig);
	const nextProviders = providers.filter((provider) => provider.id !== providerId);
	const removedProvider = nextProviders.length !== providers.length;
	rawConfig.providers = nextProviders;

	const endpoints = ensurePrivateEndpointsArray(rawConfig);
	const label = defaultEndpointLabel(providerId);
	const nextEndpoints = endpoints.filter((endpoint) => endpoint.label !== label);
	const removedPrivateEndpoint = nextEndpoints.length !== endpoints.length;
	(rawConfig.security as Record<string, unknown>).network = {
		...((rawConfig.security as Record<string, unknown>).network as Record<string, unknown>),
		privateEndpoints: nextEndpoints,
	};

	return { removedProvider, removedPrivateEndpoint };
}

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

export async function refreshConfiguredProviders(
	providers: ExternalProviderConfig[] = loadConfig().providers ?? [],
): Promise<{ providerCount: number; cleared: boolean }> {
	if (process.env.TELCLAUDE_CAPABILITIES_URL) {
		try {
			const result = await relayRefreshProviders();
			return {
				providerCount: result.providers.length,
				cleared: result.providers.length === 0,
			};
		} catch (error) {
			logger.warn({ error: String(error) }, "relay provider refresh failed; falling back locally");
		}
	}

	if (providers.length === 0) {
		await clearProviderSkillState();
		return { providerCount: 0, cleared: true };
	}

	await refreshExternalProviderSkill(providers);
	return { providerCount: providers.length, cleared: false };
}

function getConfiguredProvider(providerId: string): ExternalProviderConfig | undefined {
	return (loadConfig().providers ?? []).find((provider) => provider.id === providerId);
}

export function validateProviderId(providerId: string): string {
	const trimmed = providerId.trim();
	if (!PROVIDER_ID_PATTERN.test(trimmed)) {
		throw new Error("Provider id must use lowercase letters, digits, and hyphens only.");
	}
	return trimmed;
}

function parseServicesArg(value: string): string[] {
	return normalizeProviderServices(value.split(","));
}

async function promptProviderBaseUrl(defaultValue?: string): Promise<string> {
	const promptLabel = defaultValue
		? `Provider base URL [${defaultValue}]: `
		: "Provider base URL: ";
	const provided = (await promptLine(promptLabel))?.trim();
	const next = provided || defaultValue || "";
	if (!next) {
		throw new Error("Provider base URL is required.");
	}
	return normalizeBaseUrl(next);
}

async function promptProviderServices(defaultValue: string[]): Promise<string[]> {
	const label =
		defaultValue.length > 0
			? `Services (comma-separated) [${defaultValue.join(", ")}]: `
			: "Services (comma-separated): ";
	const provided = (await promptLine(label))?.trim();
	const next = provided ? parseServicesArg(provided) : defaultValue;
	if (next.length === 0) {
		throw new Error("At least one service is required.");
	}
	return next;
}

async function promptProviderDescription(defaultValue?: string): Promise<string | undefined> {
	const label = defaultValue ? `Description [${defaultValue}]: ` : "Description (optional): ";
	const provided = (await promptLine(label))?.trim();
	return provided || defaultValue;
}

function buildCustomProviderInputFromExisting(
	providerId: string,
	existing: ExternalProviderConfig | undefined,
	input: { baseUrl: string; services: string[]; description?: string | null },
): ProviderConfigInput {
	const catalogEntry = getProviderCatalogEntry(providerId);
	const normalizedDescription =
		input.description === undefined
			? (existing?.description ?? catalogEntry?.description)
			: input.description === null
				? undefined
				: input.description.trim() || undefined;
	if (catalogEntry) {
		return {
			...buildCatalogProviderInput(catalogEntry, input.baseUrl),
			description: normalizedDescription,
		};
	}

	return buildCustomProviderInput({
		id: providerId,
		baseUrl: input.baseUrl,
		services: input.services.length > 0 ? input.services : (existing?.services ?? []),
		description: normalizedDescription,
	});
}

async function configureProvider(
	mode: ProviderMutationMode,
	providerId: string,
	input: ProviderMutationInput,
): Promise<ProviderMutationResult> {
	const provider = buildCustomProviderInputFromExisting(
		providerId,
		getConfiguredProvider(providerId),
		input,
	);
	await validateProviderBaseUrlInput(provider.baseUrl);

	if (process.env.TELCLAUDE_CAPABILITIES_URL) {
		const result = await relayUpsertProvider({ provider });
		logger.info(
			{ mode, providerId: provider.id, baseUrl: provider.baseUrl },
			"provider configured",
		);
		return {
			provider,
			providers: result.providers,
			refresh: {
				providerCount: result.providers.length,
				cleared: result.providers.length === 0,
			},
			doctorResults: result.doctorResults,
		};
	}

	const rawConfig = readConfigFile();

	upsertConfiguredProvider(rawConfig, provider);
	upsertProviderPrivateEndpoint(rawConfig, provider);
	writeConfigFile(rawConfig);

	const refreshed = await refreshConfiguredProviders();
	const doctorResults = await collectProviderDoctorResults(provider.id);
	const providers = loadConfig().providers ?? [];
	logger.info({ mode, providerId: provider.id, baseUrl: provider.baseUrl }, "provider configured");
	return { provider, providers, refresh: refreshed, doctorResults };
}

export async function addConfiguredProvider(
	providerId: string,
	input: ProviderMutationInput,
): Promise<ProviderMutationResult> {
	const normalizedId = validateProviderId(providerId);
	if (getConfiguredProvider(normalizedId)) {
		throw new Error(
			`Provider '${normalizedId}' already exists. Use \`telclaude providers edit ${normalizedId}\`.`,
		);
	}
	const catalogEntry = getProviderCatalogEntry(normalizedId);
	if (catalogEntry?.oauthServiceId) {
		throw new Error(
			`Provider '${normalizedId}' is catalog-backed with OAuth. Use \`telclaude providers setup ${normalizedId}\`.`,
		);
	}

	return configureProvider("add", normalizedId, {
		baseUrl: normalizeBaseUrl(input.baseUrl),
		services: assertProviderServices(input.services),
		description: input.description,
	});
}

export async function editConfiguredProvider(
	providerId: string,
	input: ProviderMutationInput,
): Promise<ProviderMutationResult> {
	const normalizedId = validateProviderId(providerId);
	const existing = getConfiguredProvider(normalizedId);
	if (!existing) {
		throw new Error(
			`Provider '${normalizedId}' is not configured. Use \`telclaude providers add ${normalizedId}\`.`,
		);
	}

	return configureProvider("edit", normalizedId, {
		baseUrl: normalizeBaseUrl(input.baseUrl),
		services: assertProviderServices(input.services),
		description: input.description,
	});
}

export async function removeConfiguredProviderById(
	providerId: string,
): Promise<ProviderRemovalResult> {
	const normalizedId = validateProviderId(providerId);
	const existing = getConfiguredProvider(normalizedId);
	if (!existing) {
		throw new Error(`Provider '${normalizedId}' is not configured.`);
	}

	let removed: { removedProvider: boolean; removedPrivateEndpoint: boolean };
	let refreshed: { providerCount: number; cleared: boolean };
	let providers: ExternalProviderConfig[];
	if (process.env.TELCLAUDE_CAPABILITIES_URL) {
		const result = await relayRemoveProvider({ providerId: normalizedId });
		removed = {
			removedProvider: result.removedProvider,
			removedPrivateEndpoint: result.removedPrivateEndpoint,
		};
		providers = result.providers;
		refreshed = {
			providerCount: result.providers.length,
			cleared: result.providers.length === 0,
		};
	} else {
		const rawConfig = readConfigFile();
		removed = removeConfiguredProvider(rawConfig, normalizedId);
		writeConfigFile(rawConfig);
		refreshed = await refreshConfiguredProviders();
		providers = loadConfig().providers ?? [];
	}

	return {
		providerId: normalizedId,
		removedProvider: removed.removedProvider,
		removedPrivateEndpoint: removed.removedPrivateEndpoint,
		providers,
		refresh: refreshed,
	};
}

async function runProviderAdd(
	providerId: string,
	options: { baseUrl?: string; services?: string; description?: string },
): Promise<void> {
	const normalizedId = validateProviderId(providerId);
	const catalogEntry = getProviderCatalogEntry(normalizedId);

	const baseUrl = options.baseUrl?.trim()
		? normalizeBaseUrl(options.baseUrl)
		: await promptProviderBaseUrl(catalogEntry?.defaultBaseUrl);
	const services =
		options.services?.trim() !== undefined && options.services?.trim() !== ""
			? parseServicesArg(options.services)
			: await promptProviderServices(catalogEntry?.services ?? []);
	const description =
		options.description?.trim() !== undefined && options.description?.trim() !== ""
			? options.description.trim()
			: await promptProviderDescription(catalogEntry?.description);

	const result = await addConfiguredProvider(normalizedId, { baseUrl, services, description });
	console.log(`Configured provider '${result.provider.id}' at ${result.provider.baseUrl}.`);
	console.log(`Added/updated private endpoint allowlist: ${result.provider.endpointLabel}`);
	console.log();
	console.log(formatProviderDoctor(result.doctorResults));
	process.exitCode = computeDoctorExitCode(result.doctorResults);
}

async function runProviderEdit(
	providerId: string,
	options: { baseUrl?: string; services?: string; description?: string },
): Promise<void> {
	const normalizedId = validateProviderId(providerId);
	const existing = getConfiguredProvider(normalizedId);
	if (!existing) {
		throw new Error(
			`Provider '${normalizedId}' is not configured. Use \`telclaude providers add ${normalizedId}\`.`,
		);
	}

	const baseUrl = options.baseUrl?.trim()
		? normalizeBaseUrl(options.baseUrl)
		: await promptProviderBaseUrl(existing.baseUrl);
	const services =
		options.services?.trim() !== undefined && options.services?.trim() !== ""
			? parseServicesArg(options.services)
			: await promptProviderServices(existing.services);
	const description =
		options.description?.trim() !== undefined && options.description?.trim() !== ""
			? options.description.trim()
			: await promptProviderDescription(existing.description);

	const result = await editConfiguredProvider(normalizedId, { baseUrl, services, description });
	console.log(`Updated provider '${result.provider.id}' at ${result.provider.baseUrl}.`);
	console.log();
	console.log(formatProviderDoctor(result.doctorResults));
	process.exitCode = computeDoctorExitCode(result.doctorResults);
}

async function runProviderRemove(providerId: string, options: { yes?: boolean }): Promise<void> {
	const normalizedId = validateProviderId(providerId);
	const existing = getConfiguredProvider(normalizedId);
	if (!existing) {
		throw new Error(`Provider '${normalizedId}' is not configured.`);
	}

	if (!options.yes) {
		const confirmed = await promptYesNo(
			`Remove provider '${normalizedId}' and its private endpoint allowlist entry?`,
		);
		if (!confirmed) {
			console.log("Cancelled.");
			return;
		}
	}

	const result = await removeConfiguredProviderById(normalizedId);

	console.log(
		result.removedProvider
			? `Removed provider '${normalizedId}'.`
			: `Provider '${normalizedId}' was not present in config.`,
	);
	if (result.removedPrivateEndpoint) {
		console.log(`Removed private endpoint allowlist: ${defaultEndpointLabel(normalizedId)}`);
	}
	if (result.refresh.cleared) {
		console.log("Provider runtime state cleared.");
	}
}

async function runProviderRefresh(): Promise<void> {
	const refreshed = await refreshConfiguredProviders();
	if (refreshed.cleared) {
		console.log("No providers configured. Cleared cached provider schema and summary.");
		return;
	}

	console.log(`Refreshed provider schema + summary for ${refreshed.providerCount} provider(s).`);
}

async function resolveProviderSetupBaseUrl(
	entry: ProviderCatalogEntry,
	explicit?: string,
): Promise<string> {
	if (explicit?.trim()) {
		return normalizeBaseUrl(explicit.trim());
	}

	const promptLabel = entry.defaultBaseUrl
		? `Provider base URL [${entry.defaultBaseUrl}]: `
		: "Provider base URL: ";
	const provided = (await promptLine(promptLabel))?.trim();
	return normalizeBaseUrl(provided || entry.defaultBaseUrl || "");
}

async function runProviderSetup(
	providerId: string,
	options: {
		baseUrl?: string;
		skipOauth?: boolean;
		scopes: string;
		port: string;
		browser: boolean;
	},
): Promise<void> {
	const entry = getProviderCatalogEntry(providerId);
	if (!entry) {
		const known = listProviderCatalogEntries()
			.map((provider) => provider.id)
			.join(", ");
		console.error(`Unknown provider: ${providerId}`);
		console.error(`Known providers: ${known || "(none)"}`);
		process.exitCode = 1;
		return;
	}

	if (!options.skipOauth && entry.oauthServiceId === "google") {
		console.log("Google OAuth2 Setup");
		console.log("===================");
		console.log(
			`Scope bundle: ${options.scopes} (${GOOGLE_SCOPE_BUNDLES[options.scopes]?.length ?? 0} scopes)`,
		);
		console.log();
		await runGoogleOAuthSetup({
			scopes: options.scopes,
			port: options.port,
			browser: options.browser,
		});
		console.log("Google credentials stored in vault.");
		console.log();
	}

	const baseUrl = await resolveProviderSetupBaseUrl(entry, options.baseUrl);
	if (!baseUrl) {
		console.error("Provider base URL is required.");
		process.exitCode = 1;
		return;
	}

	const result = await configureProvider("setup", providerId, {
		baseUrl,
		services: entry.services,
		description: entry.description,
	});

	console.log(`Configured provider '${result.provider.id}' at ${result.provider.baseUrl}.`);
	console.log(`Added/updated private endpoint allowlist: ${result.provider.endpointLabel}`);
	console.log();
	console.log(formatProviderDoctor(result.doctorResults));
	process.exitCode = computeDoctorExitCode(result.doctorResults);
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
		.command("add")
		.description("Add a custom provider to config, allowlist, and runtime skill state")
		.argument("<provider-id>", "Custom provider ID")
		.option("--base-url <url>", "Provider base URL")
		.option("--services <csv>", "Comma-separated service IDs")
		.option("--description <text>", "Human-readable description")
		.action(
			async (
				providerId: string,
				options: { baseUrl?: string; services?: string; description?: string },
			) => {
				try {
					await runProviderAdd(providerId, options);
				} catch (err) {
					logger.error({ error: String(err), providerId }, "providers add failed");
					console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
					process.exit(1);
				}
			},
		);

	parent
		.command("edit")
		.description("Edit an existing provider and refresh runtime skill state")
		.argument("<provider-id>", "Configured provider ID")
		.option("--base-url <url>", "Provider base URL")
		.option("--services <csv>", "Comma-separated service IDs")
		.option("--description <text>", "Human-readable description")
		.action(
			async (
				providerId: string,
				options: { baseUrl?: string; services?: string; description?: string },
			) => {
				try {
					await runProviderEdit(providerId, options);
				} catch (err) {
					logger.error({ error: String(err), providerId }, "providers edit failed");
					console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
					process.exit(1);
				}
			},
		);

	parent
		.command("remove")
		.description("Remove a provider from config, allowlist, and runtime skill state")
		.argument("<provider-id>", "Configured provider ID")
		.option("-y, --yes", "Skip the confirmation prompt")
		.action(async (providerId: string, options: { yes?: boolean }) => {
			try {
				await runProviderRemove(providerId, options);
			} catch (err) {
				logger.error({ error: String(err), providerId }, "providers remove failed");
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exit(1);
			}
		});

	parent
		.command("refresh")
		.description("Refresh provider schema + prompt summary without restarting the relay or agent")
		.action(async () => {
			try {
				await runProviderRefresh();
			} catch (err) {
				logger.error({ error: String(err) }, "providers refresh failed");
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exit(1);
			}
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

	parent
		.command("setup")
		.description("Configure a provider end-to-end (OAuth, config, network allowlist, doctor)")
		.argument("<provider-id>", "Known provider catalog ID")
		.option("--base-url <url>", "Provider base URL to register in config")
		.option("--skip-oauth", "Skip the OAuth step and only update config/network")
		.option(
			"--scopes <bundle>",
			`Google scope bundle: ${Object.keys(GOOGLE_SCOPE_BUNDLES).join(", ")}`,
			"read_core",
		)
		.option("--port <port>", "Callback server port", "3000")
		.option("--no-browser", "Print authorization URL instead of opening browser")
		.action(
			async (
				providerId: string,
				options: {
					baseUrl?: string;
					skipOauth?: boolean;
					scopes: string;
					port: string;
					browser: boolean;
				},
			) => {
				try {
					await runProviderSetup(providerId, options);
				} catch (err) {
					logger.error({ error: String(err), providerId }, "providers setup failed");
					console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
					process.exit(1);
				}
			},
		);
}
