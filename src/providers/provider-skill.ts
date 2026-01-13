import { constants as fsConstants } from "node:fs";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { ExternalProviderConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { validateProviderBaseUrl } from "./provider-validation.js";

const logger = getChildLogger({ module: "provider-skill" });

const SKILL_DIR = "external-provider";
const SKILL_FILE = "SKILL.md";
const SCHEMA_REFERENCE_FILE = path.join("references", "provider-schema.md");

type ActionDoc = {
	id: string;
	description?: string;
	method?: string;
	mode?: string;
	requiresAuth?: boolean;
	params?: Record<
		string,
		{
			type?: string;
			required?: boolean;
			default?: unknown;
			description?: string;
		}
	>;
};

type CredentialFieldDoc = {
	field: string;
	label?: string;
	secret?: boolean;
	optional?: boolean;
};

type ServiceDoc = {
	id: string;
	name?: string;
	description?: string;
	category?: string;
	credentials?: string[];
	credentialFields?: CredentialFieldDoc[];
	actions: ActionDoc[];
};

type ProviderSchemaResult = {
	provider: ExternalProviderConfig;
	schema?: unknown;
	error?: string;
};

function coerceDescription(value: unknown): string | undefined {
	if (typeof value === "string") {
		const trimmed = value.trim();
		return trimmed.length > 0 ? trimmed : undefined;
	}
	return undefined;
}

function parseActionDocString(text: string): ActionDoc {
	const trimmed = text.trim();
	const parts = trimmed.split(/\s[-–—]\s/);
	const id = parts[0]?.trim() ?? trimmed;
	const description = parts.length > 1 ? parts.slice(1).join(" - ").trim() : undefined;
	return { id, description: description || undefined };
}

function normalizeActions(value: unknown): ActionDoc[] {
	if (!value) return [];
	if (Array.isArray(value)) {
		return value
			.map((entry) => {
				if (typeof entry === "string") return parseActionDocString(entry);
				if (entry && typeof entry === "object") {
					const record = entry as Record<string, unknown>;
					const id =
						coerceDescription(record.id) ??
						coerceDescription(record.name) ??
						coerceDescription(record.action) ??
						coerceDescription(record.key);
					if (!id) return null;
					const params =
						record.params && typeof record.params === "object"
							? (record.params as ActionDoc["params"])
							: undefined;
					return {
						id,
						description:
							coerceDescription(record.description) ??
							coerceDescription(record.summary) ??
							coerceDescription(record.label),
						method: coerceDescription(record.method) ?? coerceDescription(record.httpMethod),
						mode: coerceDescription(record.mode),
						requiresAuth:
							typeof record.requiresAuth === "boolean" ? record.requiresAuth : undefined,
						params,
					};
				}
				return null;
			})
			.filter((entry): entry is ActionDoc => Boolean(entry));
	}
	if (typeof value === "object") {
		return Object.entries(value as Record<string, unknown>).map(([key, entry]) => {
			const record = entry && typeof entry === "object" ? (entry as Record<string, unknown>) : null;
			const description = record
				? (coerceDescription(record.description) ??
					coerceDescription(record.summary) ??
					coerceDescription(record.label))
				: undefined;
			const params =
				record?.params && typeof record.params === "object"
					? (record.params as ActionDoc["params"])
					: undefined;
			return {
				id: key,
				description,
				method: record
					? (coerceDescription(record.method) ?? coerceDescription(record.httpMethod))
					: undefined,
				mode: record ? coerceDescription(record.mode) : undefined,
				requiresAuth:
					record && typeof record.requiresAuth === "boolean" ? record.requiresAuth : undefined,
				params,
			};
		});
	}
	return [];
}

function normalizeCredentialFields(value: unknown): CredentialFieldDoc[] {
	if (!Array.isArray(value)) return [];
	const results: CredentialFieldDoc[] = [];
	for (const entry of value) {
		if (!entry || typeof entry !== "object") continue;
		const record = entry as Record<string, unknown>;
		const field = coerceDescription(record.field) ?? coerceDescription(record.id);
		if (!field) continue;
		const doc: CredentialFieldDoc = { field };
		const label = coerceDescription(record.label) ?? coerceDescription(record.name);
		if (label) doc.label = label;
		if (typeof record.secret === "boolean") doc.secret = record.secret;
		if (typeof record.optional === "boolean") doc.optional = record.optional;
		results.push(doc);
	}
	return results;
}

function extractServiceDocs(schema: unknown): ServiceDoc[] {
	if (!schema || typeof schema !== "object") return [];
	const record = schema as Record<string, unknown>;
	const container =
		record.services ?? record.connectors ?? record.providers ?? record.service ?? record.connector;
	if (!container) return [];

	const services: ServiceDoc[] = [];

	if (Array.isArray(container)) {
		for (const entry of container) {
			if (!entry || typeof entry !== "object") continue;
			const service = entry as Record<string, unknown>;
			const id =
				coerceDescription(service.id) ??
				coerceDescription(service.service) ??
				coerceDescription(service.name);
			if (!id) continue;
			const docs = (service.$docs ?? service.docs) as Record<string, unknown> | undefined;
			const availableActions = docs?.available_actions ?? docs?.availableActions;
			const actionCandidates = [
				normalizeActions(service.actions),
				normalizeActions(service.endpoints),
				normalizeActions(availableActions),
			];
			const credentialFields = normalizeCredentialFields(service.credentialFields);
			const credentials = Array.isArray(service.credentials)
				? service.credentials.filter((item): item is string => typeof item === "string")
				: undefined;
			const actions = actionCandidates.find((list) => list.length > 0) ?? [];
			services.push({
				id,
				name: coerceDescription(service.name) ?? coerceDescription(service.label),
				description: coerceDescription(service.description) ?? coerceDescription(docs?.description),
				category: coerceDescription(service.category),
				credentials,
				credentialFields: credentialFields.length > 0 ? credentialFields : undefined,
				actions,
			});
		}
	} else if (typeof container === "object") {
		for (const [id, entry] of Object.entries(container as Record<string, unknown>)) {
			if (!entry || typeof entry !== "object") {
				services.push({ id, actions: [] });
				continue;
			}
			const service = entry as Record<string, unknown>;
			const docs = (service.$docs ?? service.docs) as Record<string, unknown> | undefined;
			const availableActions = docs?.available_actions ?? docs?.availableActions;
			const actionCandidates = [
				normalizeActions(service.actions),
				normalizeActions(service.endpoints),
				normalizeActions(availableActions),
			];
			const credentialFields = normalizeCredentialFields(service.credentialFields);
			const credentials = Array.isArray(service.credentials)
				? service.credentials.filter((item): item is string => typeof item === "string")
				: undefined;
			const actions = actionCandidates.find((list) => list.length > 0) ?? [];
			services.push({
				id,
				name: coerceDescription(service.name) ?? coerceDescription(service.label),
				description: coerceDescription(service.description) ?? coerceDescription(docs?.description),
				category: coerceDescription(service.category),
				credentials,
				credentialFields: credentialFields.length > 0 ? credentialFields : undefined,
				actions,
			});
		}
	}

	return services;
}

async function fetchProviderSchema(
	provider: ExternalProviderConfig,
): Promise<ProviderSchemaResult> {
	try {
		const { url: base } = await validateProviderBaseUrl(provider.baseUrl);
		const endpoint = new URL("/v1/schema", base);

		const controller = new AbortController();
		const timeout = setTimeout(() => controller.abort(), 10000);

		try {
			const response = await fetch(endpoint.toString(), {
				method: "GET",
				headers: {
					accept: "application/json",
				},
				signal: controller.signal,
			});

			if (!response.ok) {
				return {
					provider,
					error: `HTTP ${response.status}: ${response.statusText}`,
				};
			}

			const text = await response.text();
			try {
				return { provider, schema: JSON.parse(text) };
			} catch {
				return { provider, error: "Invalid JSON response from schema endpoint" };
			}
		} finally {
			clearTimeout(timeout);
		}
	} catch (err) {
		const message =
			err instanceof Error && err.name === "AbortError"
				? "Request timeout (10s)"
				: err instanceof Error && err.message
					? err.message
					: String(err);
		return { provider, error: message };
	}
}

function formatServiceDoc(service: ServiceDoc): string[] {
	const lines: string[] = [];
	const description = service.description || service.name;
	const meta: string[] = [];
	if (service.category) meta.push(`category: ${service.category}`);
	if (description) {
		const suffix = meta.length > 0 ? ` (${meta.join(", ")})` : "";
		lines.push(`- ${service.id} — ${description}${suffix}`);
	} else {
		const suffix = meta.length > 0 ? ` (${meta.join(", ")})` : "";
		lines.push(`- ${service.id}${suffix}`);
	}

	const credentialFields = service.credentialFields?.length ? service.credentialFields : undefined;
	const credentials = service.credentials?.length ? service.credentials : undefined;
	if (credentialFields || credentials) {
		const items =
			credentialFields?.map((field) => {
				const details: string[] = [];
				if (field.label) details.push(field.label);
				if (field.secret) details.push("secret");
				if (field.optional) details.push("optional");
				const detailText = details.length > 0 ? ` (${details.join(", ")})` : "";
				return `\`${field.field}\`${detailText}`;
			}) ??
			credentials?.map((field) => `\`${field}\``) ??
			[];
		if (items.length > 0) {
			lines.push(`  - credentials: ${items.join(", ")}`);
		}
	}

	if (service.actions.length > 0) {
		for (const action of service.actions) {
			const actionDesc = action.description ? ` — ${action.description}` : "";
			const meta: string[] = [];
			if (action.mode) meta.push(`mode: ${action.mode}`);
			if (action.method) meta.push(`http: ${action.method}`);
			if (typeof action.requiresAuth === "boolean") {
				meta.push(`auth: ${action.requiresAuth ? "required" : "none"}`);
			}
			if (action.params && Object.keys(action.params).length > 0) {
				meta.push(`params: ${Object.keys(action.params).join(", ")}`);
			}
			const metaText = meta.length > 0 ? ` (${meta.join(", ")})` : "";
			lines.push(`  - /v1/${service.id}/${action.id}${actionDesc}${metaText}`);
		}
	}
	return lines;
}

function buildSchemaMarkdown(results: ProviderSchemaResult[]): string {
	const lines: string[] = [];
	lines.push("# Provider Schemas (auto-generated)");
	lines.push("");
	lines.push(`Last updated: ${new Date().toISOString()}`);
	lines.push("");

	if (results.length === 0) {
		lines.push("No providers configured.");
		return lines.join("\n");
	}

	for (const result of results) {
		lines.push(`### Provider: ${result.provider.id}`);
		lines.push(`Base URL: ${result.provider.baseUrl}`);

		if (result.error) {
			lines.push(`Schema fetch failed: ${result.error}`);
			lines.push("");
			continue;
		}

		if (result.schema && typeof result.schema === "object") {
			const schemaRecord = result.schema as Record<string, unknown>;
			const version = coerceDescription(schemaRecord.version);
			const generatedAt = coerceDescription(schemaRecord.generatedAt);
			if (version) lines.push(`Schema version: ${version}`);
			if (generatedAt) lines.push(`Schema generated at: ${generatedAt}`);
		}

		const services = extractServiceDocs(result.schema);
		if (services.length === 0) {
			lines.push("Schema retrieved, but no structured services/actions detected.");
			lines.push("Refer to /v1/schema for full details.");
			lines.push("");
			continue;
		}

		lines.push("Services:");
		for (const service of services) {
			lines.push(...formatServiceDoc(service));
		}
		lines.push("");
	}

	return lines.join("\n");
}

type SkillLocation = {
	rootDir: string;
	skillPath: string;
	referencePath: string;
};

async function resolveSkillLocation(): Promise<SkillLocation | null> {
	const candidates = [
		path.join(process.cwd(), ".claude", "skills", SKILL_DIR),
		path.join("/workspace", ".claude", "skills", SKILL_DIR),
		path.join(os.homedir(), ".claude", "skills", SKILL_DIR),
		path.join("/app", ".claude", "skills", SKILL_DIR),
	];

	for (const rootDir of candidates) {
		const skillPath = path.join(rootDir, SKILL_FILE);
		try {
			await fs.access(skillPath, fsConstants.R_OK);
			await fs.access(rootDir, fsConstants.W_OK);
			return {
				rootDir,
				skillPath,
				referencePath: path.join(rootDir, SCHEMA_REFERENCE_FILE),
			};
		} catch {
			// skip
		}
	}

	return null;
}

export async function refreshExternalProviderSkill(
	providers: ExternalProviderConfig[],
): Promise<void> {
	const skillLocation = await resolveSkillLocation();
	if (!skillLocation) {
		logger.warn("external-provider skill not found or not writable; skipping schema update");
		return;
	}

	const results: ProviderSchemaResult[] = [];
	for (const provider of providers) {
		results.push(await fetchProviderSchema(provider));
	}

	const section = buildSchemaMarkdown(results);

	try {
		await fs.mkdir(path.dirname(skillLocation.referencePath), { recursive: true });
		await fs.writeFile(skillLocation.referencePath, section, "utf8");
	} catch (err) {
		logger.warn(
			{ error: String(err), path: skillLocation.referencePath },
			"failed to update external provider schema reference",
		);
	}
}
