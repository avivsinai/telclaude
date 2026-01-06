import { constants as fsConstants } from "node:fs";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { ExternalProviderConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { validateProviderBaseUrl } from "./provider-validation.js";

const logger = getChildLogger({ module: "provider-skill" });

const SKILL_FILE = "external-provider.md";
const SCHEMA_MARKER_START = "<!-- PROVIDER_SCHEMA_START -->";
const SCHEMA_MARKER_END = "<!-- PROVIDER_SCHEMA_END -->";

type ActionDoc = {
	id: string;
	description?: string;
};

type ServiceDoc = {
	id: string;
	name?: string;
	description?: string;
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
					return {
						id,
						description:
							coerceDescription(record.description) ??
							coerceDescription(record.summary) ??
							coerceDescription(record.label),
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
				? coerceDescription(record.description) ??
					coerceDescription(record.summary) ??
					coerceDescription(record.label)
				: undefined;
			return { id: key, description };
		});
	}
	return [];
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
			const actions = actionCandidates.find((list) => list.length > 0) ?? [];
			services.push({
				id,
				name: coerceDescription(service.name) ?? coerceDescription(service.label),
				description:
					coerceDescription(service.description) ?? coerceDescription(docs?.description),
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
			const actions = actionCandidates.find((list) => list.length > 0) ?? [];
			services.push({
				id,
				name: coerceDescription(service.name) ?? coerceDescription(service.label),
				description:
					coerceDescription(service.description) ?? coerceDescription(docs?.description),
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
	if (description) {
		lines.push(`- ${service.id} — ${description}`);
	} else {
		lines.push(`- ${service.id}`);
	}

	if (service.actions.length > 0) {
		for (const action of service.actions) {
			const actionDesc = action.description ? ` — ${action.description}` : "";
			lines.push(`  - /v1/${service.id}/${action.id}${actionDesc}`);
		}
	}
	return lines;
}

function buildSchemaMarkdown(results: ProviderSchemaResult[]): string {
	const lines: string[] = [];
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

function upsertSchemaSection(content: string, section: string): string {
	const start = content.indexOf(SCHEMA_MARKER_START);
	const end = content.indexOf(SCHEMA_MARKER_END);

	if (start !== -1 && end !== -1 && end > start) {
		const before = content.slice(0, start + SCHEMA_MARKER_START.length);
		const after = content.slice(end);
		return `${before}\n${section}\n${after}`;
	}

	const suffix = content.endsWith("\n") ? "" : "\n";
	return (
		`${content}${suffix}\n## Provider Schemas (auto-generated)\n` +
		`${SCHEMA_MARKER_START}\n${section}\n${SCHEMA_MARKER_END}\n`
	);
}

async function resolveSkillPath(): Promise<string | null> {
	const candidates = [
		path.join(process.cwd(), ".claude", "skills", SKILL_FILE),
		path.join("/workspace", ".claude", "skills", SKILL_FILE),
		path.join(os.homedir(), ".claude", "skills", SKILL_FILE),
		path.join("/app", ".claude", "skills", SKILL_FILE),
	];

	for (const candidate of candidates) {
		try {
			await fs.access(candidate, fsConstants.W_OK);
			return candidate;
		} catch {
			// skip
		}
	}

	return null;
}

export async function refreshExternalProviderSkill(
	providers: ExternalProviderConfig[],
): Promise<void> {
	const skillPath = await resolveSkillPath();
	if (!skillPath) {
		logger.warn("external-provider skill not found; skipping schema injection");
		return;
	}

	const results: ProviderSchemaResult[] = [];
	for (const provider of providers) {
		results.push(await fetchProviderSchema(provider));
	}

	const section = buildSchemaMarkdown(results);

	try {
		const existing = await fs.readFile(skillPath, "utf8");
		const updated = upsertSchemaSection(existing, section);
		if (updated !== existing) {
			await fs.writeFile(skillPath, updated, "utf8");
		}
	} catch (err) {
		logger.warn({ error: String(err), skillPath }, "failed to update external provider skill");
	}
}
