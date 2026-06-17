// Served-MCP ENDPOINT containment probe.
//
// SCOPE: this proves the relay's live MCP *server* (the `telclaudeRelay`
// endpoint) is contained — it exposes only the `tc_*` served tool surface,
// strips client-supplied authority/connection/provenance, re-resolves authority
// server-side from the opaque peer-bound handle, and fails closed on forged
// authority, wrong connection, off-domain peer, or unauthenticated callers.
//
// NOT IN SCOPE: this says nothing about the contained runtime's *own* native
// tool surface. Scoping only the MCP server's tool list never disables Hermes's
// native toolsets (terminal, file, code_execution, browser, cronjob, memory,
// web, …), which remain additive to the served tools unless the runtime config
// explicitly allowlists them. The agent's resolved native toolset
// (`[skills, telclaudeRelay, todo]`) and the `skill_manage` write-denial are
// proven separately by `verify-live`'s `runtime.toolset_inventory` /
// `runtime.skill_manage_write_denied` gates. A clean served endpoint with an
// over-broad native surface is NOT a contained runtime — both proofs are
// required, and they must not be conflated.
import net from "node:net";
import type { ZodError } from "zod";
import { redactSecrets } from "../security/output-filter.js";
import { type HermesArtifactWriteOptions, writeHermesJsonArtifact } from "./foundation.js";
import { TELCLAUDE_MCP_TOOL_NAMES } from "./mcp/bridge.js";
import { TELCLAUDE_LIVE_MCP_OBSERVED_PEER_HEADER } from "./mcp/live-server.js";

export {
	SERVED_MCP_CONTAINMENT_SCHEMA_VERSION,
	SERVED_MCP_REQUIRED_PROPERTY_NAMES,
	type ServedMcpContainmentCheck,
	type ServedMcpContainmentEvidence,
	ServedMcpContainmentEvidenceSchema,
	type ServedMcpPropertyName,
} from "./served-mcp-containment-schema.js";

import {
	SERVED_MCP_CONTAINMENT_SCHEMA_VERSION,
	SERVED_MCP_REQUIRED_PROPERTY_NAMES,
	type ServedMcpContainmentCheck,
	type ServedMcpContainmentEvidence,
	ServedMcpContainmentEvidenceSchema,
	type ServedMcpPropertyName,
} from "./served-mcp-containment-schema.js";

export const DEFAULT_SERVED_MCP_CONTAINMENT_EVIDENCE_PATH =
	"artifacts/hermes/probes/execution-served-mcp-containment.json";
export const DEFAULT_SERVED_MCP_CONTAINED_CONTAINER_NAME = "tc-hermes-contained";

export type ServedMcpEndpoint = {
	readonly url: string;
	readonly headers?: Readonly<Record<string, string>>;
};

export type ServedMcpProbeOriginInput = {
	readonly containerName?: string;
	readonly expectedPeerAddress?: string;
	readonly relayPeerAddress?: string;
};

export type RunServedMcpContainmentProbeOptions = {
	readonly allowRun: boolean;
	readonly endpoint?: ServedMcpEndpoint;
	readonly offDomainPeerEndpoint?: ServedMcpEndpoint;
	readonly forgedAuthorityEndpoint?: ServedMcpEndpoint;
	readonly wrongConnectionEndpoint?: ServedMcpEndpoint;
	readonly unauthenticatedEndpoint?: ServedMcpEndpoint;
	readonly origin?: ServedMcpProbeOriginInput;
	readonly now?: Date;
	readonly fetchImpl?: typeof fetch;
	readonly timeoutMs?: number;
};

export type ServedMcpContainmentGate = {
	readonly name: string;
	readonly status: "pass" | "fail";
	readonly detail: string;
};

export type ServedMcpContainmentReport = {
	readonly schemaVersion: "telclaude.hermes.served-mcp-containment-report.v1";
	readonly status: "pass" | "fail" | "input_error";
	readonly productionEnable: boolean;
	readonly gates: ServedMcpContainmentGate[];
};

type RpcObservation = {
	readonly httpStatus?: number;
	readonly body?: unknown;
	readonly transportError?: string;
	readonly observedPeerAddress?: string;
	readonly observedPeerSource?: "server-peer-echo";
};

type ServedMcpOriginObservation =
	| {
			readonly ok: true;
			readonly observedPeerAddress: string;
			readonly observedPeerSource: "server-peer-echo";
	  }
	| {
			readonly ok: false;
			readonly detail: string;
	  };

const UNAUTHORIZED_OUTBOUND_CONVERSATION_TOKEN = `conv_${"0".repeat(32)}`;

export async function runServedMcpContainmentProbe(
	options: RunServedMcpContainmentProbeOptions,
): Promise<ServedMcpContainmentEvidence> {
	if (!options.allowRun) {
		return buildEvidence({
			status: "pending",
			ran: false,
			generatedAt: generatedAt(options.now),
			summary: "Hermes served-MCP containment probe requires --allow-run",
			origin: normalizeOrigin(options.origin),
			checks: [],
			properties: falseProperties(),
		});
	}

	const missingConfig = missingEndpointConfig(options);
	if (missingConfig.length > 0) {
		return buildEvidence({
			status: "fail",
			ran: false,
			generatedAt: generatedAt(options.now),
			summary: `Served MCP containment probe is not fully configured: ${missingConfig.join(", ")}`,
			origin: normalizeOrigin(options.origin),
			checks: SERVED_MCP_REQUIRED_PROPERTY_NAMES.map((name) =>
				failCheck(
					name,
					`served-MCP probe endpoint configuration is missing: ${missingConfig.join(", ")}`,
				),
			),
			properties: falseProperties(),
		});
	}

	const fetcher = options.fetchImpl ?? fetch;
	const endpoint = requiredEndpoint(options.endpoint, "endpoint");
	const offDomainPeerEndpoint = requiredEndpoint(
		options.offDomainPeerEndpoint,
		"offDomainPeerEndpoint",
	);
	const forgedEndpoint = requiredEndpoint(
		options.forgedAuthorityEndpoint,
		"forgedAuthorityEndpoint",
	);
	const wrongEndpoint = requiredEndpoint(
		options.wrongConnectionEndpoint,
		"wrongConnectionEndpoint",
	);
	const unauthenticatedEndpoint = options.unauthenticatedEndpoint ?? {
		url: endpoint.url,
	};
	const timeoutMs = options.timeoutMs;
	const checks: ServedMcpContainmentCheck[] = [];
	const origin = normalizeOrigin(
		options.origin,
		await observeServedMcpOrigin(fetcher, endpoint, timeoutMs),
	);

	const initialize = await postJson(
		fetcher,
		endpoint,
		rpc("initialize", { protocolVersion: "2024-11-05" }),
		timeoutMs,
	);
	checks.push(
		passIf(
			"positive_initialize_tools_only",
			initializeToolsOnly(initialize),
			"initialize returned only the MCP tools capability set",
			"initialize did not return the tools-only capability set",
			initialize,
		),
	);

	const toolsList = await postJson(fetcher, endpoint, rpc("tools/list"), timeoutMs);
	checks.push(
		passIf(
			"positive_tools_list_exact",
			exactToolsList(toolsList),
			"tools/list returned the exact Telclaude tc_ tool set",
			"tools/list did not return the exact Telclaude tc_ tool set",
			toolsList,
		),
	);

	for (const [property, method, resultKey] of [
		["positive_resources_empty", "resources/list", "resources"],
		["positive_prompts_empty", "prompts/list", "prompts"],
		["positive_roots_empty", "roots/list", "roots"],
	] as const) {
		const observed = await postJson(fetcher, endpoint, rpc(method), timeoutMs);
		checks.push(
			passIf(
				property,
				emptyArrayResult(observed, resultKey),
				`${method} returned an empty surface`,
				`${method} did not return an empty surface`,
				observed,
			),
		);
	}

	const sampling = await postJson(fetcher, endpoint, rpc("sampling/createMessage"), timeoutMs);
	checks.push(
		passIf(
			"sampling_disabled",
			expectedRpcError(sampling, -32001, "disabled"),
			"sampling/createMessage was specifically refused",
			"sampling/createMessage did not return the expected disabled denial",
			sampling,
		),
	);

	const forgedAuthority = await postJson(
		fetcher,
		forgedEndpoint,
		toolCall("tc_provider_read", {
			service: "bank",
			action: "balances.list",
			params: {},
		}),
		timeoutMs,
	);
	checks.push(
		passIf(
			"handle_forgery_denied",
			expectedAuthorityDenial(forgedAuthority, "not registered"),
			"forged transport authority was specifically denied as unregistered",
			"forged transport authority was not specifically denied as unregistered",
			forgedAuthority,
		),
	);

	const wrongConnection = await postJson(
		fetcher,
		wrongEndpoint,
		toolCall("tc_provider_read", {
			service: "bank",
			action: "balances.list",
			params: {},
		}),
		timeoutMs,
	);
	checks.push(
		passIf(
			"wrong_connection_denied",
			expectedAuthorityDenial(wrongConnection, "connection mismatch"),
			"wrong-connection authority was specifically denied",
			"wrong-connection authority was not specifically denied",
			wrongConnection,
		),
	);

	const offDomainPeer = await postJson(
		fetcher,
		offDomainPeerEndpoint,
		rpc("tools/list"),
		timeoutMs,
	);
	checks.push(
		passIf(
			"off_domain_peer_denied",
			expectedRpcError(offDomainPeer, -32001, "not authorized", 403),
			"off-domain peer-bound token was denied at HTTP auth",
			"off-domain peer-bound token was not denied at HTTP auth",
			offDomainPeer,
		),
	);

	const crossDomainMemory = await postJson(
		fetcher,
		endpoint,
		toolCall("tc_memory_search", {
			query: "family",
			filters: { source: "social", profileId: "social" },
		}),
		timeoutMs,
	);
	checks.push(
		passIf(
			"cross_domain_memory_denied",
			expectedRpcError(crossDomainMemory, -32001, "memory authority fields"),
			"cross-domain memory authority injection was specifically denied",
			"cross-domain memory authority injection was not specifically denied",
			crossDomainMemory,
		),
	);

	const outOfScopeProvider = await postJson(
		fetcher,
		endpoint,
		toolCall("tc_provider_read", {
			service: "clalit",
			action: "appointments.list",
			params: {},
		}),
		timeoutMs,
	);
	checks.push(
		passIf(
			"out_of_scope_provider_denied",
			expectedRpcError(outOfScopeProvider, -32001, "provider scope denied"),
			"out-of-scope provider read was specifically denied",
			"out-of-scope provider read was not specifically denied",
			outOfScopeProvider,
		),
	);

	const outOfScopeOutbound = await postJson(
		fetcher,
		endpoint,
		toolCall("tc_outbound_prepare", {
			conversationToken: UNAUTHORIZED_OUTBOUND_CONVERSATION_TOKEN,
			body: "hello",
		}),
		timeoutMs,
	);
	checks.push(
		passIf(
			"out_of_scope_outbound_denied",
			expectedRpcError(outOfScopeOutbound, -32001, "outbound conversation unavailable"),
			"out-of-scope outbound prepare was specifically denied",
			"out-of-scope outbound prepare was not specifically denied",
			outOfScopeOutbound,
		),
	);

	const providerExecuteWithoutLedger = await postJson(
		fetcher,
		endpoint,
		toolCall("tc_provider_execute_write", {
			actionRef: "tc_probe_missing_provider_ref",
		}),
		timeoutMs,
	);
	const providerLedgerDenialCode = ledgerDenialCode(providerExecuteWithoutLedger);
	checks.push(
		passIf(
			"provider_execute_without_ledger_denied",
			providerLedgerDenialCode !== null,
			providerLedgerDenialCode
				? `provider execute without a prepared ledger record was specifically denied with ${providerLedgerDenialCode}`
				: "provider execute without a prepared ledger record was specifically denied",
			"provider execute without a prepared ledger record was not specifically denied",
			providerExecuteWithoutLedger,
		),
	);

	const outboundExecuteWithoutLedger = await postJson(
		fetcher,
		endpoint,
		toolCall("tc_outbound_execute", {
			outboundRef: "tc_probe_missing_outbound_ref",
		}),
		timeoutMs,
	);
	const outboundLedgerDenialCode = ledgerDenialCode(outboundExecuteWithoutLedger);
	checks.push(
		passIf(
			"outbound_execute_without_ledger_denied",
			outboundLedgerDenialCode !== null,
			outboundLedgerDenialCode
				? `outbound execute without a prepared ledger record was specifically denied with ${outboundLedgerDenialCode}`
				: "outbound execute without a prepared ledger record was specifically denied",
			"outbound execute without a prepared ledger record was not specifically denied",
			outboundExecuteWithoutLedger,
		),
	);

	const malformed = await postRaw(fetcher, endpoint, "{not-json", timeoutMs);
	checks.push(
		passIf(
			"malformed_json_denied",
			expectedRpcError(malformed, -32700, "parse error", 400),
			"malformed JSON was specifically denied with parse error",
			"malformed JSON was not specifically denied with parse error",
			malformed,
		),
	);

	const unauthenticated = await postJson(
		fetcher,
		unauthenticatedEndpoint,
		rpc("tools/list"),
		timeoutMs,
	);
	checks.push(
		passIf(
			"unauthenticated_denied",
			expectedRpcError(unauthenticated, -32001, "not authorized", 403),
			"unauthenticated HTTP request was specifically denied",
			"unauthenticated HTTP request was not specifically denied",
			unauthenticated,
		),
	);

	const batch = await postJson(fetcher, endpoint, [], timeoutMs);
	checks.push(
		passIf(
			"batch_denied",
			expectedRpcError(batch, -32600, "batch"),
			"JSON-RPC batch request was specifically denied",
			"JSON-RPC batch request was not specifically denied",
			batch,
		),
	);

	const prototypeKey = await postJson(
		fetcher,
		endpoint,
		toolCall(
			"tc_provider_read",
			JSON.parse(
				'{"service":"bank","action":"balances.list","params":{"nested":{"__proto__":{"polluted":true}}}}',
			) as Record<string, unknown>,
		),
		timeoutMs,
	);
	checks.push(
		passIf(
			"prototype_key_denied",
			expectedRpcError(prototypeKey, -32602, "prototype key"),
			"prototype-pollution key was specifically denied before bridge dispatch",
			"prototype-pollution key was not specifically denied before bridge dispatch",
			prototypeKey,
		),
	);

	const nonRedactionProperties = propertiesFromChecks(checks);
	const candidate = buildEvidence({
		status: checks.every((check) => check.status === "pass") ? "pass" : "fail",
		ran: true,
		generatedAt: generatedAt(options.now),
		summary: checks.every((check) => check.status === "pass")
			? "Served MCP containment probe passed"
			: "Served MCP containment probe failed",
		origin,
		checks,
		properties: { ...nonRedactionProperties, artifact_redacted: true },
	});
	const redactionPass = !containsSensitiveNeedle(
		JSON.stringify(candidate),
		sensitiveNeedles(options),
	);
	checks.push(
		redactionPass
			? passCheck(
					"artifact_redacted",
					"persisted evidence omits raw endpoint, handle, header, token, and signature material",
				)
			: failCheck(
					"artifact_redacted",
					"persisted evidence contains raw endpoint, handle, header, token, or signature material",
				),
	);

	const properties = propertiesFromChecks(checks);
	const status = checks.every((check) => check.status === "pass") ? "pass" : "fail";
	return buildEvidence({
		status,
		ran: true,
		generatedAt: generatedAt(options.now),
		summary:
			status === "pass"
				? "Served MCP containment probe passed"
				: "Served MCP containment probe failed",
		origin,
		checks,
		properties,
	});
}

export function evaluateServedMcpContainmentEvidence(
	evidence: unknown,
	options: { missingPath?: string } = {},
): ServedMcpContainmentReport {
	if (evidence === undefined) {
		return {
			schemaVersion: "telclaude.hermes.served-mcp-containment-report.v1",
			status: "input_error",
			productionEnable: false,
			gates: [
				{
					name: "servedMcp.evidence",
					status: "fail",
					detail: `required served-MCP containment evidence is missing: ${options.missingPath ?? DEFAULT_SERVED_MCP_CONTAINMENT_EVIDENCE_PATH}`,
				},
			],
		};
	}
	const parsed = ServedMcpContainmentEvidenceSchema.safeParse(evidence);
	if (!parsed.success) {
		return {
			schemaVersion: "telclaude.hermes.served-mcp-containment-report.v1",
			status: "input_error",
			productionEnable: false,
			gates: [
				{
					name: "servedMcp.evidence",
					status: "fail",
					detail: flattenZodError(parsed.error),
				},
			],
		};
	}

	const gates: ServedMcpContainmentGate[] = [];
	const originGate = originGateFor(parsed.data.origin);
	gates.push(originGate);
	const negativeControls = [
		["forgedAuthorityDenied", parsed.data.negativeControls.forgedAuthorityDenied],
		["wrongConnectionDenied", parsed.data.negativeControls.wrongConnectionDenied],
		["offDomainPeerDenied", parsed.data.negativeControls.offDomainPeerDenied],
	] as const;
	for (const [name, value] of negativeControls) {
		gates.push({
			name: `servedMcp.negative.${name}`,
			status: value === true ? "pass" : "fail",
			detail:
				value === true
					? `served-MCP negative control ${name} is proven`
					: `served-MCP negative control ${name} is ${value === undefined ? "missing" : "false"}`,
		});
	}
	if (parsed.data.status !== "pass") {
		gates.push({
			name: "servedMcp.status",
			status: "fail",
			detail: `served-MCP evidence status is ${parsed.data.status}`,
		});
	}
	if (parsed.data.ran !== true) {
		gates.push({
			name: "servedMcp.ran",
			status: "fail",
			detail: `served-MCP evidence ran is ${String(parsed.data.ran)}`,
		});
	}
	for (const property of SERVED_MCP_REQUIRED_PROPERTY_NAMES) {
		const value = parsed.data.properties[property];
		gates.push({
			name: `servedMcp.property.${property}`,
			status: value === true ? "pass" : "fail",
			detail:
				value === true
					? `served-MCP property ${property} is proven`
					: `served-MCP property ${property} is ${value === undefined ? "missing" : "false"}`,
		});
	}
	const productionEnable = gates.every((gate) => gate.status === "pass");
	return {
		schemaVersion: "telclaude.hermes.served-mcp-containment-report.v1",
		status: productionEnable ? "pass" : "fail",
		productionEnable,
		gates,
	};
}

export function writeServedMcpContainmentEvidence(
	evidence: ServedMcpContainmentEvidence,
	filePath: string,
	options: HermesArtifactWriteOptions = {},
): void {
	writeHermesJsonArtifact(filePath, evidence, options);
}

function buildEvidence(input: {
	status: ServedMcpContainmentEvidence["status"];
	ran: boolean;
	generatedAt: string;
	summary: string;
	origin: ServedMcpContainmentEvidence["origin"];
	checks: ServedMcpContainmentCheck[];
	properties: ServedMcpContainmentEvidence["properties"];
}): ServedMcpContainmentEvidence {
	return {
		schemaVersion: SERVED_MCP_CONTAINMENT_SCHEMA_VERSION,
		probeId: "execution.served_mcp_containment",
		status: input.status,
		ran: input.ran,
		generatedAt: input.generatedAt,
		summary: redactDetail(input.summary),
		endpoint: {
			transport: "http",
			target: "redacted-http-mcp-endpoint",
		},
		placement: {
			loadBearing: false,
			detail:
				"Placement metadata is informational; relay-internal bind enforcement remains a deployment live-run gate.",
		},
		origin: input.origin,
		negativeControls: negativeControlsFromChecks(input.checks),
		properties: input.properties,
		checks: input.checks.map((check) => ({
			...check,
			detail: redactDetail(check.detail),
			...(check.rpcErrorMessage ? { rpcErrorMessage: redactDetail(check.rpcErrorMessage) } : {}),
		})),
	};
}

function missingEndpointConfig(options: RunServedMcpContainmentProbeOptions): string[] {
	const missing = [];
	if (!options.endpoint?.url.trim()) missing.push("endpoint");
	if (!options.offDomainPeerEndpoint?.url.trim()) missing.push("offDomainPeerEndpoint");
	if (!options.forgedAuthorityEndpoint?.url.trim()) missing.push("forgedAuthorityEndpoint");
	if (!options.wrongConnectionEndpoint?.url.trim()) missing.push("wrongConnectionEndpoint");
	return missing;
}

function requiredEndpoint(
	endpoint: ServedMcpEndpoint | undefined,
	name: string,
): ServedMcpEndpoint {
	if (!endpoint) throw new Error(`served-MCP probe ${name} is missing after validation`);
	return endpoint;
}

async function observeServedMcpOrigin(
	fetcher: typeof fetch,
	endpoint: ServedMcpEndpoint,
	timeoutMs: number | undefined,
): Promise<ServedMcpOriginObservation> {
	const observation = await postJson(
		fetcher,
		endpoint,
		rpc("initialize", { protocolVersion: "2024-11-05" }),
		timeoutMs,
	);
	if (observation.transportError) {
		return {
			ok: false,
			detail: `served-MCP peer origin probe transport failed: ${observation.transportError}`,
		};
	}
	const observedPeerAddress = normalizeObservedPeerAddress(observation.observedPeerAddress);
	if (observedPeerAddress) {
		if (net.isIP(observedPeerAddress) !== 0) {
			return {
				ok: true,
				observedPeerAddress,
				observedPeerSource: "server-peer-echo",
			};
		}
		return { ok: false, detail: "served-MCP peer origin header returned a non-IP peer address" };
	}
	const error = rpcError(observation);
	return {
		ok: false,
		detail: error
			? `served-MCP peer origin observation failed: ${error.message}`
			: "served-MCP peer origin observation did not include the live server peer header",
	};
}

async function postJson(
	fetcher: typeof fetch,
	endpoint: ServedMcpEndpoint,
	payload: unknown,
	timeoutMs: number | undefined,
): Promise<RpcObservation> {
	return postRaw(fetcher, endpoint, JSON.stringify(payload), timeoutMs);
}

async function postRaw(
	fetcher: typeof fetch,
	endpoint: ServedMcpEndpoint,
	body: string,
	timeoutMs: number | undefined,
): Promise<RpcObservation> {
	const controller = timeoutMs ? new AbortController() : undefined;
	const timeout = controller
		? setTimeout(
				() => controller.abort(new Error(`served-MCP probe timed out after ${timeoutMs}ms`)),
				timeoutMs,
			)
		: undefined;
	try {
		const response = await fetcher(endpoint.url, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				...(endpoint.headers ?? {}),
			},
			body,
			signal: controller?.signal,
		});
		const text = await response.text();
		let parsed: unknown;
		try {
			parsed = JSON.parse(text) as unknown;
		} catch {
			parsed = { parseError: "response JSON parse error" };
		}
		const observedPeerAddress =
			response.headers.get(TELCLAUDE_LIVE_MCP_OBSERVED_PEER_HEADER) ?? undefined;
		return {
			httpStatus: response.status,
			body: parsed,
			...(observedPeerAddress
				? { observedPeerAddress, observedPeerSource: "server-peer-echo" as const }
				: {}),
		};
	} catch (error) {
		return { transportError: redactDetail(error instanceof Error ? error.message : String(error)) };
	} finally {
		if (timeout) clearTimeout(timeout);
	}
}

function rpc(method: string, params?: unknown): Record<string, unknown> {
	return {
		jsonrpc: "2.0",
		id: `probe-${method}`,
		method,
		...(params !== undefined ? { params } : {}),
	};
}

function toolCall(name: string, args: Record<string, unknown>): Record<string, unknown> {
	return rpc("tools/call", { name, arguments: args });
}

function initializeToolsOnly(observation: RpcObservation): boolean {
	const result = rpcResult(observation);
	if (!isRecord(result)) return false;
	const capabilities = result.capabilities;
	if (!isRecord(capabilities)) return false;
	return sameJson(capabilities, { tools: { listChanged: false } });
}

function exactToolsList(observation: RpcObservation): boolean {
	const result = rpcResult(observation);
	if (!isRecord(result) || !Array.isArray(result.tools)) return false;
	const names = result.tools.map((tool) =>
		isRecord(tool) && typeof tool.name === "string" ? tool.name : null,
	);
	return (
		names.every((name): name is string => typeof name === "string") &&
		sameJson(names, [...TELCLAUDE_MCP_TOOL_NAMES])
	);
}

function emptyArrayResult(observation: RpcObservation, key: string): boolean {
	const result = rpcResult(observation);
	return isRecord(result) && Array.isArray(result[key]) && result[key].length === 0;
}

function expectedRpcError(
	observation: RpcObservation,
	code: number,
	messageIncludes: string,
	httpStatus?: number,
): boolean {
	if (httpStatus !== undefined && observation.httpStatus !== httpStatus) return false;
	const error = rpcError(observation);
	return (
		error?.code === code &&
		typeof error.message === "string" &&
		error.message.toLowerCase().includes(messageIncludes.toLowerCase())
	);
}

function expectedAuthorityDenial(
	observation: RpcObservation,
	bridgeMessageIncludes: string,
): boolean {
	return (
		expectedRpcError(observation, -32001, bridgeMessageIncludes) ||
		expectedRpcError(observation, -32001, "not authorized", 403)
	);
}

function ledgerDenialCode(observation: RpcObservation): string | null {
	// tools/call results are MCP CallToolResults: the bridge payload (ok/code)
	// lives in structuredContent. Fall back to the bare result for forward-compat.
	const raw = rpcResult(observation);
	if (!isRecord(raw)) return null;
	const structured = raw.structuredContent;
	const result = isRecord(structured) ? structured : raw;
	if (result.ok !== false || typeof result.code !== "string") return null;
	return result.code === "effect_not_found" || result.code === "approval_required"
		? result.code
		: null;
}

function passIf(
	name: ServedMcpPropertyName,
	condition: boolean,
	passDetail: string,
	failDetail: string,
	observation?: RpcObservation,
): ServedMcpContainmentCheck {
	if (condition) return passCheck(name, passDetail, observation);
	return failCheck(name, `${failDetail}; observed ${observedSummary(observation)}`, observation);
}

function passCheck(
	name: ServedMcpPropertyName,
	detail: string,
	observation?: RpcObservation,
): ServedMcpContainmentCheck {
	return withObservation({ name, status: "pass", detail }, observation);
}

function failCheck(
	name: ServedMcpPropertyName,
	detail: string,
	observation?: RpcObservation,
): ServedMcpContainmentCheck {
	return withObservation({ name, status: "fail", detail }, observation);
}

function withObservation(
	check: Pick<ServedMcpContainmentCheck, "name" | "status" | "detail">,
	observation?: RpcObservation,
): ServedMcpContainmentCheck {
	const error = observation ? rpcError(observation) : undefined;
	return {
		...check,
		detail: redactDetail(check.detail),
		...(observation?.httpStatus !== undefined ? { httpStatus: observation.httpStatus } : {}),
		...(error?.code !== undefined ? { rpcErrorCode: error.code } : {}),
		...(error?.message ? { rpcErrorMessage: redactDetail(error.message) } : {}),
	};
}

function observedSummary(observation: RpcObservation | undefined): string {
	if (!observation) return "no observation";
	if (observation.transportError)
		return `transportError=${redactDetail(observation.transportError)}`;
	const error = rpcError(observation);
	if (error) {
		return `http=${observation.httpStatus ?? "missing"} rpcError=${error.code} ${redactDetail(error.message)}`;
	}
	const result = rpcResult(observation);
	return `http=${observation.httpStatus ?? "missing"} result=${result === undefined ? "missing" : "present"}`;
}

function rpcResult(observation: RpcObservation): unknown {
	if (observation.httpStatus === undefined || !isRecord(observation.body)) return undefined;
	if (observation.body.jsonrpc !== "2.0" || !Object.hasOwn(observation.body, "result")) {
		return undefined;
	}
	return observation.body.result;
}

function rpcError(
	observation: RpcObservation,
): { readonly code: number; readonly message: string } | undefined {
	if (!isRecord(observation.body)) return undefined;
	const error = observation.body.error;
	if (!isRecord(error) || typeof error.code !== "number" || typeof error.message !== "string") {
		return undefined;
	}
	return { code: error.code, message: error.message };
}

function propertiesFromChecks(
	checks: readonly ServedMcpContainmentCheck[],
): ServedMcpContainmentEvidence["properties"] {
	const properties = falseProperties();
	for (const check of checks) {
		properties[check.name] = check.status === "pass";
	}
	return properties;
}

function falseProperties(): Record<ServedMcpPropertyName, boolean> {
	return Object.fromEntries(
		SERVED_MCP_REQUIRED_PROPERTY_NAMES.map((property) => [property, false]),
	) as Record<ServedMcpPropertyName, boolean>;
}

function normalizeOrigin(
	input: ServedMcpProbeOriginInput | undefined,
	observation?: ServedMcpOriginObservation,
): ServedMcpContainmentEvidence["origin"] {
	const containerName = clean(input?.containerName);
	const observedPeerAddress =
		observation?.ok === true ? observation.observedPeerAddress : undefined;
	const expectedPeerAddress = clean(input?.expectedPeerAddress);
	const relayPeerAddress = clean(input?.relayPeerAddress);
	const kind = observedPeerAddress
		? relayPeerAddress && observedPeerAddress === relayPeerAddress
			? "relay-self-smoke"
			: "contained-peer"
		: "unknown";
	return {
		kind,
		...(containerName ? { containerName } : {}),
		...(observedPeerAddress ? { observedPeerAddress } : {}),
		...(observation?.ok === true ? { observedPeerSource: observation.observedPeerSource } : {}),
		...(expectedPeerAddress ? { expectedPeerAddress } : {}),
		...(expectedPeerAddress ? { expectedPeerSource: "configured-contained-ip" as const } : {}),
		detail:
			kind === "contained-peer"
				? "probe peer origin was observed by live MCP server"
				: kind === "relay-self-smoke"
					? "probe peer origin matched the relay namespace and is smoke-only"
					: observation?.ok === false
						? observation.detail
						: "probe origin was not observed",
	};
}

function originGateFor(origin: ServedMcpContainmentEvidence["origin"]): ServedMcpContainmentGate {
	if (origin.kind === "relay-self-smoke") {
		return {
			name: "servedMcp.origin",
			status: "fail",
			detail:
				"served-MCP evidence originated from relay-self smoke and is not production containment evidence",
		};
	}
	const matchesPeer =
		origin.observedPeerAddress !== undefined &&
		origin.expectedPeerAddress !== undefined &&
		origin.observedPeerSource === "server-peer-echo" &&
		origin.expectedPeerSource === "configured-contained-ip" &&
		net.isIP(origin.observedPeerAddress) !== 0 &&
		net.isIP(origin.expectedPeerAddress) !== 0 &&
		origin.observedPeerAddress === origin.expectedPeerAddress;
	if (
		origin.kind === "contained-peer" &&
		origin.containerName === DEFAULT_SERVED_MCP_CONTAINED_CONTAINER_NAME &&
		matchesPeer
	) {
		return {
			name: "servedMcp.origin",
			status: "pass",
			detail:
				"served-MCP evidence originated from tc-hermes-contained at the expected peer address",
		};
	}
	return {
		name: "servedMcp.origin",
		status: "fail",
		detail:
			"served-MCP evidence must include a server-observed contained peer IP from tc-hermes-contained matching the configured contained IP",
	};
}

function negativeControlsFromChecks(
	checks: readonly ServedMcpContainmentCheck[],
): ServedMcpContainmentEvidence["negativeControls"] {
	const byName = new Map(checks.map((check) => [check.name, check.status === "pass"]));
	return {
		forgedAuthorityDenied: byName.get("handle_forgery_denied") === true,
		wrongConnectionDenied: byName.get("wrong_connection_denied") === true,
		offDomainPeerDenied: byName.get("off_domain_peer_denied") === true,
	};
}

function clean(value: string | undefined): string | undefined {
	const trimmed = value?.trim();
	return trimmed ? trimmed : undefined;
}

function normalizeObservedPeerAddress(value: string | undefined): string | undefined {
	const trimmed = value?.trim();
	if (!trimmed) return undefined;
	const normalized = trimmed.startsWith("::ffff:") ? trimmed.slice("::ffff:".length) : trimmed;
	return normalized || undefined;
}

function sensitiveNeedles(options: RunServedMcpContainmentProbeOptions): string[] {
	const endpoints = [
		options.endpoint,
		options.offDomainPeerEndpoint,
		options.forgedAuthorityEndpoint,
		options.wrongConnectionEndpoint,
		options.unauthenticatedEndpoint,
	].filter((endpoint): endpoint is ServedMcpEndpoint => endpoint !== undefined);
	const endpointNeedles = endpoints.flatMap((endpoint) => {
		const needles = Object.values(endpoint.headers ?? {});
		try {
			const url = new URL(endpoint.url);
			needles.push(url.host);
		} catch {
			needles.push(endpoint.url);
		}
		return needles;
	});
	return ["approvalToken", "signature", "tc_mcp_", ...endpointNeedles].filter(
		(needle) => needle.trim().length >= 3,
	);
}

function containsSensitiveNeedle(serialized: string, needles: readonly string[]): boolean {
	return needles.some((needle) => serialized.includes(needle));
}

function generatedAt(now: Date | undefined): string {
	return (now ?? new Date()).toISOString();
}

function redactDetail(detail: string): string {
	return redactSecrets(detail).replace(/\s+/g, " ").trim();
}

function flattenZodError(error: ZodError): string {
	return error.issues
		.map((issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`)
		.join("; ");
}

function sameJson(left: unknown, right: unknown): boolean {
	return JSON.stringify(left) === JSON.stringify(right);
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}
