import net from "node:net";
import { z } from "zod";
import { memorySourceFamily, validateMemorySource } from "../memory/source.js";
import { redactSecrets } from "../security/output-filter.js";
import {
	type HermesSignedEvidenceValidationOptions,
	hermesAllowsStaleAttestations,
	hermesAttestationFreshnessFailure,
	hermesRequiresRunnerAttestation,
} from "./attestation-validation.js";
import { type HermesArtifactWriteOptions, writeHermesJsonArtifact } from "./foundation.js";
import { DEFAULT_SERVED_MCP_CONTAINED_CONTAINER_NAME } from "./served-mcp-containment.js";
import {
	INSTRUCTION_WRITE_PROBE_CONTENT,
	SECRET_WRITE_PROBE_CONTENT,
} from "./served-mcp-memory.js";
import {
	ServedMcpMemoryAttestationSchema,
	servedMcpMemoryAttestationFieldsForEvidence,
	servedMcpMemoryAttestationSignatureFailure,
	signServedMcpMemoryAttestation,
} from "./served-mcp-memory-attestation.js";

export const SERVED_MCP_HOUSEHOLD_MEMORY_SCHEMA_VERSION =
	"telclaude.hermes.served-mcp-household-memory.v1";
export const SERVED_MCP_HOUSEHOLD_MEMORY_PROBE_ID = "served_mcp.household_memory";
export const DEFAULT_SERVED_MCP_HOUSEHOLD_MEMORY_EVIDENCE_PATH =
	"artifacts/hermes/probes/served-mcp-household-memory.json";
export const SERVED_MCP_HOUSEHOLD_MEMORY_REPORT_SCHEMA_VERSION =
	"telclaude.hermes.served-mcp-household-memory-report.v1";

export const SERVED_MCP_HOUSEHOLD_MEMORY_REQUIRED_PROPERTIES = [
	"parent_a_authority_observed",
	"parent_b_authority_observed",
	"parent_a_write_recall",
	"parent_b_write_recall",
	"parent_a_sibling_read_denied",
	"parent_b_sibling_read_denied",
	"client_source_denied",
	"secret_write_rejected",
	"instruction_like_write_rejected",
	"artifact_redacted",
] as const;

type HouseholdMemoryProperty = (typeof SERVED_MCP_HOUSEHOLD_MEMORY_REQUIRED_PROPERTIES)[number];
const PropertySchema = z.enum(SERVED_MCP_HOUSEHOLD_MEMORY_REQUIRED_PROPERTIES);
const NonEmptyString = z.string().trim().min(1);

const AuthorityObservationSchema = z
	.object({
		observedPeerAddress: NonEmptyString.optional(),
		domain: NonEmptyString.optional(),
		memorySource: NonEmptyString.optional(),
	})
	.strict();

const OriginSchema = z
	.object({
		kind: z.enum(["contained-peer", "unknown"]),
		containerName: NonEmptyString.optional(),
		expectedPeerAddress: NonEmptyString.optional(),
		expectedPeerSource: z.literal("configured-contained-ip").optional(),
		parentA: AuthorityObservationSchema,
		parentB: AuthorityObservationSchema,
		detail: NonEmptyString,
	})
	.strict();

const CheckSchema = z
	.object({
		name: PropertySchema,
		status: z.enum(["pass", "fail"]),
		detail: NonEmptyString,
		observedResultCount: z.number().int().nonnegative().optional(),
		rpcErrorCode: z.number().int().optional(),
		rpcErrorMessage: NonEmptyString.optional(),
		clientSourceWriteRpcErrorCode: z.number().int().optional(),
		clientSourceWriteRpcErrorMessage: NonEmptyString.optional(),
		clientSourceSearchRpcErrorCode: z.number().int().optional(),
		clientSourceSearchRpcErrorMessage: NonEmptyString.optional(),
	})
	.strict();

const PropertiesSchema = z
	.object(
		Object.fromEntries(
			SERVED_MCP_HOUSEHOLD_MEMORY_REQUIRED_PROPERTIES.map((name) => [name, z.boolean().optional()]),
		) as Record<HouseholdMemoryProperty, z.ZodOptional<z.ZodBoolean>>,
	)
	.strict();

export const ServedMcpHouseholdMemoryEvidenceSchema = z
	.object({
		schemaVersion: z.literal(SERVED_MCP_HOUSEHOLD_MEMORY_SCHEMA_VERSION),
		probeId: z.literal(SERVED_MCP_HOUSEHOLD_MEMORY_PROBE_ID),
		status: z.enum(["pass", "fail", "pending"]),
		ran: z.boolean(),
		generatedAt: NonEmptyString,
		summary: NonEmptyString,
		memorySource: NonEmptyString,
		siblingMemorySource: NonEmptyString,
		origin: OriginSchema,
		properties: PropertiesSchema,
		checks: z.array(CheckSchema),
		runnerAttestation: ServedMcpMemoryAttestationSchema.optional(),
	})
	.strict();

export type ServedMcpHouseholdMemoryEvidence = z.infer<
	typeof ServedMcpHouseholdMemoryEvidenceSchema
>;

export type ServedMcpHouseholdMemoryReport = {
	readonly schemaVersion: typeof SERVED_MCP_HOUSEHOLD_MEMORY_REPORT_SCHEMA_VERSION;
	readonly status: "pass" | "fail" | "input_error";
	readonly productionEnable: boolean;
	readonly gates: readonly {
		readonly name: string;
		readonly status: "pass" | "fail";
		readonly detail: string;
	}[];
};

export type RunServedMcpHouseholdMemoryProbeOptions = {
	readonly allowRun: boolean;
	readonly parentAEndpoint?: ServedMcpEndpoint;
	readonly parentBEndpoint?: ServedMcpEndpoint;
	readonly parentAMemorySource?: string;
	readonly parentBMemorySource?: string;
	readonly expectedPeerAddress?: string;
	readonly fetchImpl?: typeof fetch;
	readonly now?: Date;
	readonly timeoutMs?: number;
};

type ServedMcpEndpoint = {
	readonly url: string;
	readonly headers?: Readonly<Record<string, string>>;
};

type RpcObservation = {
	readonly body?: unknown;
	readonly observedPeerAddress?: string;
	readonly authority?: { readonly domain?: string; readonly memorySource?: string };
	readonly transportError?: string;
};

export function evaluateServedMcpHouseholdMemoryEvidence(
	evidence: unknown,
	options: HermesSignedEvidenceValidationOptions = {},
): ServedMcpHouseholdMemoryReport {
	const parsed = ServedMcpHouseholdMemoryEvidenceSchema.safeParse(evidence);
	if (!parsed.success)
		return inputError(parsed.error.issues.map((issue) => issue.message).join("; "));
	const data = parsed.data;
	const gates: ServedMcpHouseholdMemoryReport["gates"][number][] = [];
	const addGate = (name: string, pass: boolean, detail: string) =>
		gates.push({ name, status: pass ? "pass" : "fail", detail });

	const sourcesValid =
		validateMemorySource(data.memorySource) === null &&
		validateMemorySource(data.siblingMemorySource) === null &&
		memorySourceFamily(data.memorySource) === "household" &&
		memorySourceFamily(data.siblingMemorySource) === "household" &&
		data.memorySource !== data.siblingMemorySource;
	addGate(
		"household-memory.sources",
		sourcesValid,
		sourcesValid
			? "two distinct household memory sources are bound"
			: "probe requires two distinct valid household memory sources",
	);

	const originValid =
		data.origin.kind === "contained-peer" &&
		data.origin.containerName === DEFAULT_SERVED_MCP_CONTAINED_CONTAINER_NAME &&
		data.origin.expectedPeerSource === "configured-contained-ip" &&
		Boolean(data.origin.expectedPeerAddress) &&
		net.isIP(data.origin.expectedPeerAddress ?? "") !== 0 &&
		data.origin.parentA.observedPeerAddress === data.origin.expectedPeerAddress &&
		data.origin.parentB.observedPeerAddress === data.origin.expectedPeerAddress &&
		data.origin.parentA.domain === "household" &&
		data.origin.parentB.domain === "household" &&
		data.origin.parentA.memorySource === data.memorySource &&
		data.origin.parentB.memorySource === data.siblingMemorySource;
	addGate(
		"household-memory.origin",
		originValid,
		originValid
			? "both authorities were observed from the expected contained peer"
			: "both household authorities must be server-observed from the expected contained peer",
	);

	const freshnessFailure = hermesAttestationFreshnessFailure(
		"served-MCP household memory generatedAt",
		data.generatedAt,
		options,
	);
	if (freshnessFailure) addGate("household-memory.freshness", false, freshnessFailure);
	const attestationFailure = householdAttestationFailure(data, options);
	if (attestationFailure) {
		addGate("household-memory.attestation", false, attestationFailure);
	}
	addGate(
		"household-memory.status",
		data.status === "pass" && data.ran,
		data.status === "pass" && data.ran
			? "probe ran and passed"
			: `probe status=${data.status} ran=${String(data.ran)}`,
	);

	const checks = new Map<HouseholdMemoryProperty, ServedMcpHouseholdMemoryEvidence["checks"]>();
	for (const check of data.checks) {
		checks.set(check.name, [...(checks.get(check.name) ?? []), check]);
	}
	const serialized = JSON.stringify(data);
	const artifactLeaked = redactSecrets(serialized) !== serialized;
	for (const property of SERVED_MCP_HOUSEHOLD_MEMORY_REQUIRED_PROPERTIES) {
		const matches = checks.get(property) ?? [];
		let evidenceBacked = matches.length > 0 && matches.every((check) => check.status === "pass");
		if (property.endsWith("sibling_read_denied")) {
			evidenceBacked = evidenceBacked && matches.every((check) => check.observedResultCount === 0);
		}
		if (property === "secret_write_rejected" || property === "instruction_like_write_rejected") {
			evidenceBacked =
				evidenceBacked &&
				matches.every(
					(check) =>
						typeof check.rpcErrorCode === "number" && typeof check.rpcErrorMessage === "string",
				);
		}
		if (property === "client_source_denied") {
			evidenceBacked =
				evidenceBacked &&
				matches.every(
					(check) =>
						typeof check.clientSourceWriteRpcErrorCode === "number" &&
						typeof check.clientSourceWriteRpcErrorMessage === "string" &&
						typeof check.clientSourceSearchRpcErrorCode === "number" &&
						typeof check.clientSourceSearchRpcErrorMessage === "string",
				);
		}
		if (property === "artifact_redacted" && artifactLeaked) evidenceBacked = false;
		const proven = data.properties[property] === true && evidenceBacked;
		addGate(
			`household-memory.${property}`,
			proven,
			proven ? `${property} is check-backed` : `${property} is missing valid backing evidence`,
		);
	}

	const productionEnable = gates.every((gate) => gate.status === "pass");
	return {
		schemaVersion: SERVED_MCP_HOUSEHOLD_MEMORY_REPORT_SCHEMA_VERSION,
		status: productionEnable ? "pass" : "fail",
		productionEnable,
		gates,
	};
}

export async function runServedMcpHouseholdMemoryProbe(
	options: RunServedMcpHouseholdMemoryProbeOptions,
): Promise<ServedMcpHouseholdMemoryEvidence> {
	const generatedAt = (options.now ?? new Date()).toISOString();
	const memorySource = options.parentAMemorySource ?? "household:parent-a";
	const siblingMemorySource = options.parentBMemorySource ?? "household:parent-b";
	const properties = falseProperties();
	if (!options.allowRun || !options.parentAEndpoint || !options.parentBEndpoint) {
		return {
			schemaVersion: SERVED_MCP_HOUSEHOLD_MEMORY_SCHEMA_VERSION,
			probeId: SERVED_MCP_HOUSEHOLD_MEMORY_PROBE_ID,
			status: "pending",
			ran: false,
			generatedAt,
			summary: options.allowRun
				? "household memory probe requires two authorized endpoints"
				: "household memory probe requires --allow-run",
			memorySource,
			siblingMemorySource,
			origin: {
				kind: "unknown",
				parentA: {},
				parentB: {},
				detail: "probe did not run",
			},
			properties,
			checks: [],
		};
	}

	const fetcher = options.fetchImpl ?? fetch;
	const parentAInit = await postRpc(
		fetcher,
		options.parentAEndpoint,
		initializeCall("a"),
		options.timeoutMs,
	);
	const parentBInit = await postRpc(
		fetcher,
		options.parentBEndpoint,
		initializeCall("b"),
		options.timeoutMs,
	);
	const expectedPeerAddress = options.expectedPeerAddress;
	const origin: ServedMcpHouseholdMemoryEvidence["origin"] = {
		kind:
			expectedPeerAddress &&
			parentAInit.observedPeerAddress === expectedPeerAddress &&
			parentBInit.observedPeerAddress === expectedPeerAddress
				? "contained-peer"
				: "unknown",
		...(expectedPeerAddress
			? {
					containerName: DEFAULT_SERVED_MCP_CONTAINED_CONTAINER_NAME,
					expectedPeerAddress,
					expectedPeerSource: "configured-contained-ip" as const,
				}
			: {}),
		parentA: {
			...(parentAInit.observedPeerAddress
				? { observedPeerAddress: parentAInit.observedPeerAddress }
				: {}),
			...(parentAInit.authority?.domain ? { domain: parentAInit.authority.domain } : {}),
			...(parentAInit.authority?.memorySource
				? { memorySource: parentAInit.authority.memorySource }
				: {}),
		},
		parentB: {
			...(parentBInit.observedPeerAddress
				? { observedPeerAddress: parentBInit.observedPeerAddress }
				: {}),
			...(parentBInit.authority?.domain ? { domain: parentBInit.authority.domain } : {}),
			...(parentBInit.authority?.memorySource
				? { memorySource: parentBInit.authority.memorySource }
				: {}),
		},
		detail: "server-echoed household authority and peer metadata",
	};
	const checks: ServedMcpHouseholdMemoryEvidence["checks"] = [];
	for (const [name, observation, expectedSource] of [
		["parent_a_authority_observed", parentAInit, memorySource],
		["parent_b_authority_observed", parentBInit, siblingMemorySource],
	] as const) {
		const pass =
			observation.authority?.domain === "household" &&
			observation.authority.memorySource === expectedSource &&
			observation.observedPeerAddress === expectedPeerAddress;
		checks.push({
			name,
			status: pass ? "pass" : "fail",
			detail: pass ? `observed ${expectedSource}` : `did not observe ${expectedSource}`,
		});
	}

	const nonce = Date.now().toString(36);
	const parentAContent = `household parent A probe ${nonce}`;
	const parentBContent = `household parent B probe ${nonce}`;
	const parentAWrite = await postRpc(
		fetcher,
		options.parentAEndpoint,
		memoryToolCall("tc_memory_write", {
			id: `probe.household.parent-a.${nonce}`,
			category: "meta",
			content: parentAContent,
			metadata: {},
		}),
		options.timeoutMs,
	);
	const parentBWrite = await postRpc(
		fetcher,
		options.parentBEndpoint,
		memoryToolCall("tc_memory_write", {
			id: `probe.household.parent-b.${nonce}`,
			category: "meta",
			content: parentBContent,
			metadata: {},
		}),
		options.timeoutMs,
	);
	for (const [name, endpoint, content, write] of [
		["parent_a_write_recall", options.parentAEndpoint, parentAContent, parentAWrite],
		["parent_b_write_recall", options.parentBEndpoint, parentBContent, parentBWrite],
	] as const) {
		const recall = await postRpc(
			fetcher,
			endpoint,
			memoryToolCall("tc_memory_search", { query: content }),
			options.timeoutMs,
		);
		const count = resultCount(recall);
		const pass = resultOk(write) && count !== undefined && count > 0;
		checks.push({
			name,
			status: pass ? "pass" : "fail",
			detail: pass ? `own recall returned ${count} row(s)` : "own write/recall failed",
			...(count !== undefined ? { observedResultCount: count } : {}),
		});
	}
	for (const [name, endpoint, siblingContent] of [
		["parent_a_sibling_read_denied", options.parentAEndpoint, parentBContent],
		["parent_b_sibling_read_denied", options.parentBEndpoint, parentAContent],
	] as const) {
		const result = await postRpc(
			fetcher,
			endpoint,
			memoryToolCall("tc_memory_search", { query: siblingContent }),
			options.timeoutMs,
		);
		const count = resultCount(result);
		const pass = count === 0 && !rpcError(result);
		checks.push({
			name,
			status: pass ? "pass" : "fail",
			detail: pass ? "sibling query returned an empty scoped result" : "sibling data was visible",
			...(count !== undefined ? { observedResultCount: count } : {}),
		});
	}

	const clientSourceWrite = await postRpc(
		fetcher,
		options.parentAEndpoint,
		memoryToolCall("tc_memory_write", {
			id: "probe.household.client-source",
			category: "meta",
			content: "client source must fail",
			memorySource: siblingMemorySource,
		}),
		options.timeoutMs,
	);
	const clientSourceSearch = await postRpc(
		fetcher,
		options.parentAEndpoint,
		memoryToolCall("tc_memory_search", {
			query: parentBContent,
			memorySource: siblingMemorySource,
		}),
		options.timeoutMs,
	);
	const clientWriteError = rpcError(clientSourceWrite);
	const clientSearchError = rpcError(clientSourceSearch);
	checks.push({
		name: "client_source_denied",
		status: clientWriteError && clientSearchError ? "pass" : "fail",
		detail:
			clientWriteError && clientSearchError
				? "client-supplied sibling source was denied for write and search"
				: "client-supplied sibling source was not fully denied",
		...(clientWriteError
			? {
					clientSourceWriteRpcErrorCode: clientWriteError.code,
					clientSourceWriteRpcErrorMessage: redactSecrets(clientWriteError.message),
				}
			: {}),
		...(clientSearchError
			? {
					clientSourceSearchRpcErrorCode: clientSearchError.code,
					clientSourceSearchRpcErrorMessage: redactSecrets(clientSearchError.message),
				}
			: {}),
	});

	for (const [name, content] of [
		["secret_write_rejected", SECRET_WRITE_PROBE_CONTENT],
		["instruction_like_write_rejected", INSTRUCTION_WRITE_PROBE_CONTENT],
	] as const) {
		const result = await postRpc(
			fetcher,
			options.parentAEndpoint,
			memoryToolCall("tc_memory_write", {
				id: `probe.household.${name}`,
				category: "meta",
				content,
				metadata: {},
			}),
			options.timeoutMs,
		);
		const error = rpcError(result);
		checks.push({
			name,
			status: error ? "pass" : "fail",
			detail: error ? `write rejected: ${redactSecrets(error.message)}` : "write was accepted",
			...(error ? { rpcErrorCode: error.code, rpcErrorMessage: redactSecrets(error.message) } : {}),
		});
	}

	for (const check of checks) properties[check.name] = check.status === "pass";
	properties.artifact_redacted = true;
	checks.push({
		name: "artifact_redacted",
		status: "pass",
		detail: "producer redacted observed errors; evaluator re-scans artifact bytes",
	});
	const allPass = checks.every((check) => check.status === "pass");
	const evidence: ServedMcpHouseholdMemoryEvidence = {
		schemaVersion: SERVED_MCP_HOUSEHOLD_MEMORY_SCHEMA_VERSION,
		probeId: SERVED_MCP_HOUSEHOLD_MEMORY_PROBE_ID,
		status: allPass ? "pass" : "fail",
		ran: true,
		generatedAt,
		summary: allPass
			? "served-MCP household sibling memory isolation proven"
			: "served-MCP household sibling memory probe recorded failures",
		memorySource,
		siblingMemorySource,
		origin,
		properties,
		checks,
	};
	return { ...evidence, runnerAttestation: signServedMcpMemoryAttestation(evidence) };
}

export function writeServedMcpHouseholdMemoryEvidence(
	evidence: ServedMcpHouseholdMemoryEvidence,
	filePath: string,
	options: HermesArtifactWriteOptions = {},
): void {
	writeHermesJsonArtifact(filePath, evidence, options);
}

function householdAttestationFailure(
	data: ServedMcpHouseholdMemoryEvidence,
	options: HermesSignedEvidenceValidationOptions,
): string | null {
	const attestation = data.runnerAttestation;
	if (!attestation) {
		return hermesRequiresRunnerAttestation(options) ? "runnerAttestation is missing" : null;
	}
	const signatureFailure = servedMcpMemoryAttestationSignatureFailure(attestation, {
		allowStale: hermesAllowsStaleAttestations(options),
		relayPublicKey: options.relayPublicKey,
	});
	if (signatureFailure) return `runnerAttestation signature is invalid: ${signatureFailure}`;
	const expected = servedMcpMemoryAttestationFieldsForEvidence(data);
	for (const field of [
		"probeEvidenceSchemaVersion",
		"probeId",
		"status",
		"ran",
		"generatedAt",
		"memorySource",
		"originSha256",
		"propertiesSha256",
		"checksSha256",
		"evidenceSha256",
	] as const) {
		if (attestation[field] !== expected[field]) return `runnerAttestation ${field} mismatch`;
	}
	return null;
}

function falseProperties(): ServedMcpHouseholdMemoryEvidence["properties"] {
	return Object.fromEntries(
		SERVED_MCP_HOUSEHOLD_MEMORY_REQUIRED_PROPERTIES.map((name) => [name, false]),
	) as Record<HouseholdMemoryProperty, boolean>;
}

function inputError(detail: string): ServedMcpHouseholdMemoryReport {
	return {
		schemaVersion: SERVED_MCP_HOUSEHOLD_MEMORY_REPORT_SCHEMA_VERSION,
		status: "input_error",
		productionEnable: false,
		gates: [{ name: "household-memory.evidence", status: "fail", detail }],
	};
}

function initializeCall(suffix: string): Record<string, unknown> {
	return { jsonrpc: "2.0", id: `household-memory-initialize-${suffix}`, method: "initialize" };
}

function memoryToolCall(name: string, args: Record<string, unknown>): Record<string, unknown> {
	return {
		jsonrpc: "2.0",
		id: `household-memory-${name}`,
		method: "tools/call",
		params: { name, arguments: args },
	};
}

async function postRpc(
	fetcher: typeof fetch,
	endpoint: ServedMcpEndpoint,
	payload: unknown,
	timeoutMs: number | undefined,
): Promise<RpcObservation> {
	const controller = timeoutMs ? new AbortController() : undefined;
	const timeout = controller
		? setTimeout(
				() => controller.abort(new Error(`household memory probe timed out after ${timeoutMs}ms`)),
				timeoutMs,
			)
		: undefined;
	try {
		const response = await fetcher(endpoint.url, {
			method: "POST",
			headers: { "Content-Type": "application/json", ...(endpoint.headers ?? {}) },
			body: JSON.stringify(payload),
			signal: controller?.signal,
		});
		const text = await response.text();
		let body: unknown;
		try {
			body = JSON.parse(text) as unknown;
		} catch {
			body = { parseError: "response JSON parse error" };
		}
		const authority = extractAuthority(body);
		return {
			body,
			...(response.headers.get("x-telclaude-live-mcp-observed-peer-address")
				? {
						observedPeerAddress:
							response.headers.get("x-telclaude-live-mcp-observed-peer-address") ?? undefined,
					}
				: {}),
			...(authority ? { authority } : {}),
		};
	} catch (error) {
		return {
			transportError: redactSecrets(error instanceof Error ? error.message : String(error)),
		};
	} finally {
		if (timeout) clearTimeout(timeout);
	}
}

function extractAuthority(body: unknown): RpcObservation["authority"] | undefined {
	if (!body || typeof body !== "object") return undefined;
	const result = (body as { result?: unknown }).result;
	if (!result || typeof result !== "object") return undefined;
	const authority = (result as { telclaudeProbeAuthority?: unknown }).telclaudeProbeAuthority;
	if (!authority || typeof authority !== "object") return undefined;
	const fields = authority as { domain?: unknown; memorySource?: unknown };
	return {
		...(typeof fields.domain === "string" ? { domain: fields.domain } : {}),
		...(typeof fields.memorySource === "string" ? { memorySource: fields.memorySource } : {}),
	};
}

function rpcError(
	observation: RpcObservation,
): { readonly code: number; readonly message: string } | undefined {
	if (!observation.body || typeof observation.body !== "object") return undefined;
	const error = (observation.body as { error?: unknown }).error;
	if (!error || typeof error !== "object") return undefined;
	const fields = error as { code?: unknown; message?: unknown };
	return typeof fields.code === "number" && typeof fields.message === "string"
		? { code: fields.code, message: fields.message }
		: undefined;
}

function resultPayload(observation: RpcObservation): Record<string, unknown> | undefined {
	if (!observation.body || typeof observation.body !== "object") return undefined;
	const result = (observation.body as { result?: unknown }).result;
	if (!result || typeof result !== "object") return undefined;
	const structured = (result as { structuredContent?: unknown }).structuredContent;
	return (structured && typeof structured === "object" ? structured : result) as Record<
		string,
		unknown
	>;
}

function resultCount(observation: RpcObservation): number | undefined {
	const entries = resultPayload(observation)?.entries;
	return Array.isArray(entries) ? entries.length : undefined;
}

function resultOk(observation: RpcObservation): boolean {
	return resultPayload(observation) !== undefined && rpcError(observation) === undefined;
}
