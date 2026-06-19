import http from "node:http";
import type { OutboundDeliveryDispatcher } from "../../relay/outbound-delivery-dispatcher.js";
import { type ProviderProxyRequest, proxyProviderRequest } from "../../relay/provider-proxy.js";
import {
	createTelclaudeMcpBridgeForRegisteredConnection,
	type TelclaudeMcpAuthorityConnection,
	type TelclaudeMcpAuthorityRegistry,
} from "./authority-registry.js";
import {
	TELCLAUDE_MCP_TOOL_NAMES,
	type TelclaudeMcpAuthority,
	type TelclaudeMcpBridge,
	type TelclaudeMcpBridgeDependencies,
	type TelclaudeMcpToolName,
} from "./bridge.js";
import type {
	BrowserWriteCommitter,
	TelclaudeMcpInboundTurnAuthorityResolver,
	TelclaudeMcpOutboundConversationResolver,
	TelclaudeMcpProviderSidecarApprovalTokenIssuer,
	TelclaudeMcpSideEffectApprovalTokenResolver,
} from "./ledger-execute.js";
import { createTelclaudeMcpLedgerExecuteDependencies } from "./ledger-execute.js";
import type { TelclaudeMcpSideEffectLedger } from "./side-effect-ledger.js";
import { telclaudeMcpToolDefinitions } from "./tool-schemas.js";

export const TELCLAUDE_LIVE_MCP_TRANSPORT = "http_relay_internal_network";
export const TELCLAUDE_LIVE_MCP_OBSERVED_PEER_HEADER = "x-telclaude-live-mcp-observed-peer-address";
export const TELCLAUDE_LIVE_MCP_PLACEMENT_SIDE_HEADER = "x-telclaude-live-mcp-placement-side";

export const TELCLAUDE_LIVE_MCP_DEPENDENCY_SURFACE = [
	"providerRead",
	"providerPrepareWrite",
	"memorySearch",
	"memoryWrite",
	"attachmentGet",
	"outboundPrepare",
	"auditNote",
	"webFetch",
	"webSearch",
	"imageGenerate",
	"tts",
	"skillRequest",
	"sideEffectLedger",
] as const;

export type TelclaudeLiveMcpRelayClients = Omit<
	TelclaudeMcpBridgeDependencies,
	"providerExecuteWrite" | "outboundExecute" | "browseActExecute"
>;

export type TelclaudeLiveMcpConnectionContext = {
	readonly authorityHandle?: string;
	readonly connection?: TelclaudeMcpAuthorityConnection;
	readonly authority?: TelclaudeMcpAuthority;
	readonly observedPeerAddress?: string;
};

type JsonRpcId = string | number | null;

export type TelclaudeLiveMcpJsonRpcRequest = {
	readonly jsonrpc: "2.0";
	readonly id?: JsonRpcId;
	readonly method: string;
	readonly params?: unknown;
};

export type TelclaudeLiveMcpJsonRpcResponse =
	| {
			readonly jsonrpc: "2.0";
			readonly id?: JsonRpcId;
			readonly result: unknown;
	  }
	| {
			readonly jsonrpc: "2.0";
			readonly id?: JsonRpcId;
			readonly error: {
				readonly code: number;
				readonly message: string;
				readonly data?: unknown;
			};
	  };

export type TelclaudeLiveMcpRelayHttpServer = {
	readonly transport: typeof TELCLAUDE_LIVE_MCP_TRANSPORT;
	readonly placement: {
		readonly side: "relay";
		readonly runsInHermesContainer: false;
		readonly transport: "http";
		readonly networkExposure: "relay_internal_only";
		readonly bindHost: string;
		readonly networkName: string;
	};
	readonly dependencySurface: typeof TELCLAUDE_LIVE_MCP_DEPENDENCY_SURFACE;
	handleJsonRpc(
		request: unknown,
		context?: TelclaudeLiveMcpConnectionContext | null,
	): Promise<TelclaudeLiveMcpJsonRpcResponse>;
};

export type CreateTelclaudeLiveMcpRelayHttpServerOptions = {
	readonly registry: TelclaudeMcpAuthorityRegistry;
	readonly ledger: TelclaudeMcpSideEffectLedger;
	readonly relayClients: TelclaudeLiveMcpRelayClients;
	readonly providerProxy?: (
		request: ProviderProxyRequest,
	) => ReturnType<typeof proxyProviderRequest>;
	readonly sideEffectApprovalTokenResolver?: TelclaudeMcpSideEffectApprovalTokenResolver;
	readonly resolveAuthorizedOutboundConversation?: TelclaudeMcpOutboundConversationResolver;
	readonly resolveAuthorizedInboundTurn?: TelclaudeMcpInboundTurnAuthorityResolver;
	readonly outboundDeliveryDispatcher?: OutboundDeliveryDispatcher;
	readonly providerApprovalTokenIssuer?: TelclaudeMcpProviderSidecarApprovalTokenIssuer;
	/**
	 * Commits an approved browser write (S3) against the live interactive page held
	 * relay-side. Injected like the provider proxy / outbound dispatcher so the
	 * ledger never imports the broker. Omitted → tc_browse_act_execute fails closed
	 * with a typed `browser_write_committer_missing` terminal error.
	 */
	readonly browserWriteCommitter?: BrowserWriteCommitter;
	readonly bindHost: string;
	readonly networkName: string;
	readonly nowMs?: () => number;
};

export type CreateTelclaudeLiveMcpNodeHttpServerOptions = {
	readonly resolveConnection: (
		request: http.IncomingMessage,
	) => TelclaudeLiveMcpConnectionContext | null | Promise<TelclaudeLiveMcpConnectionContext | null>;
	readonly path?: string;
};

const EMPTY_SURFACES: Record<string, { readonly [key: string]: readonly unknown[] }> = {
	"resources/list": { resources: [] },
	"prompts/list": { prompts: [] },
	"roots/list": { roots: [] },
};

const CLIENT_AUTHORITY_KEYS = new Set([
	"authority",
	"authorityHandle",
	"connection",
	"sessionKey",
	"actorId",
	"profileId",
	"domain",
	"memorySource",
	"source",
	"sources",
	"sourceFamilies",
	"trust",
	"namespace",
	"writableNamespace",
	"providerAuthority",
	"capabilityScopes",
	"endpointId",
	"networkNamespace",
	"peerAddress",
]);

const PROTOTYPE_POLLUTION_KEYS = new Set(["__proto__", "prototype", "constructor"]);

const MAX_HTTP_BODY_BYTES = 1024 * 1024;

export function createTelclaudeLiveMcpRelayHttpServer(
	options: CreateTelclaudeLiveMcpRelayHttpServerOptions,
): TelclaudeLiveMcpRelayHttpServer {
	const ledgerExecute = createTelclaudeMcpLedgerExecuteDependencies({
		ledger: options.ledger,
		providerProxy: options.providerProxy ?? proxyProviderRequest,
		sideEffectApprovalTokenResolver: options.sideEffectApprovalTokenResolver,
		resolveAuthorizedOutboundConversation: options.resolveAuthorizedOutboundConversation,
		resolveAuthorizedInboundTurn: options.resolveAuthorizedInboundTurn,
		outboundDeliveryDispatcher: options.outboundDeliveryDispatcher,
		providerApprovalTokenIssuer: options.providerApprovalTokenIssuer,
		...(options.browserWriteCommitter
			? { browserWriteCommitter: options.browserWriteCommitter }
			: {}),
		nowMs: options.nowMs,
	});
	const dependencies: TelclaudeMcpBridgeDependencies = {
		...options.relayClients,
		providerExecuteWrite: ledgerExecute.providerExecuteWrite,
		outboundExecute: ledgerExecute.outboundExecute,
		// tc_browse_act_execute is served by the ledger's browser-write executor —
		// verify→single-flight-claim→recapture→re-verify→commit. Mirrors the
		// provider/outbound execute seam; the runtime supplies only the actionRef.
		browseActExecute: ledgerExecute.browseActExecute,
	};

	return {
		transport: TELCLAUDE_LIVE_MCP_TRANSPORT,
		placement: {
			side: "relay",
			runsInHermesContainer: false,
			transport: "http",
			networkExposure: "relay_internal_only",
			bindHost: requiredTrimmed(options.bindHost, "bindHost"),
			networkName: requiredTrimmed(options.networkName, "networkName"),
		},
		dependencySurface: TELCLAUDE_LIVE_MCP_DEPENDENCY_SURFACE,

		async handleJsonRpc(request, context) {
			const parsedRequest = parseJsonRpcRequest(request);
			if (!parsedRequest.ok) {
				return jsonError(parsedRequest.id, parsedRequest.code, parsedRequest.reason);
			}
			const { id, method, params } = parsedRequest.request;

			if (method === "initialize") {
				return jsonResult(id, {
					protocolVersion: "2024-11-05",
					serverInfo: {
						name: "telclaude-live-mcp-relay",
						version: "1",
					},
					capabilities: {
						tools: { listChanged: false },
					},
					...(context?.authority
						? { telclaudeProbeAuthority: probeAuthorityMetadata(context.authority) }
						: {}),
				});
			}

			if (method === "tools/list") {
				return jsonResult(id, {
					tools: telclaudeMcpToolDefinitions(),
				});
			}

			const emptySurface = emptySurfaceForMethod(method);
			if (emptySurface) {
				return jsonResult(id, emptySurface);
			}

			if (method.startsWith("sampling/")) {
				return jsonError(id, -32001, "MCP sampling is disabled");
			}

			if (method !== "tools/call") {
				return jsonError(id, -32601, "MCP method denied");
			}

			const call = parseToolCall(params);
			if (!call.ok) return jsonError(id, call.code, call.reason);
			if (!isTelclaudeToolName(call.name)) {
				return jsonError(id, -32601, "MCP tool denied");
			}
			if (!context?.authorityHandle || !context.connection) {
				return jsonError(id, -32001, "MCP runtime authority is not active");
			}
			if (containsPrototypePollutionKey(call.args)) {
				return jsonError(id, -32602, "MCP tools/call arguments contain forbidden prototype key");
			}
			if (isMemoryTool(call.name) && containsClientAuthorityField(call.args)) {
				return jsonError(id, -32001, "MCP client cannot supply memory authority fields");
			}

			const registered = createTelclaudeMcpBridgeForRegisteredConnection({
				registry: options.registry,
				handle: context.authorityHandle,
				connection: context.connection,
				dependencies,
				nowMs: options.nowMs?.(),
			});
			if (!registered.ok) return jsonError(id, -32001, registered.reason);

			try {
				const result = await callBridgeTool(
					registered.bridge,
					call.name,
					stripClientAuthorityEnvelope(call.args),
				);
				return jsonResult(id, toCallToolResult(result));
			} catch (error) {
				return jsonError(id, -32001, errorMessage(error));
			}
		},
	};
}

export function createTelclaudeLiveMcpNodeHttpServer(
	server: TelclaudeLiveMcpRelayHttpServer,
	options: CreateTelclaudeLiveMcpNodeHttpServerOptions,
): http.Server {
	const path = options.path ?? "/mcp";
	return http.createServer(async (request, response) => {
		if (request.method !== "POST" || request.url?.split("?")[0] !== path) {
			writeHttpJson(response, 404, jsonError(null, -32601, "MCP endpoint denied"));
			return;
		}

		let payload: unknown;
		try {
			payload = JSON.parse(await readHttpBody(request));
		} catch {
			writeHttpJson(response, 400, jsonError(null, -32700, "MCP JSON parse error"));
			return;
		}

		let context: TelclaudeLiveMcpConnectionContext | null;
		try {
			context = await options.resolveConnection(request);
		} catch {
			context = null;
		}
		if (!context) {
			writeHttpJson(
				response,
				403,
				jsonError(
					jsonRpcId(isRecord(payload) ? payload.id : undefined),
					-32001,
					"MCP connection is not authorized",
				),
			);
			return;
		}

		const observedPeerAddress = normalizeObservedPeerAddress(request.socket.remoteAddress);
		const rpcResponse = await server.handleJsonRpc(payload, {
			...context,
			...(observedPeerAddress ? { observedPeerAddress } : {}),
		});
		const observationHeaders = liveMcpObservationHeaders(request, server);
		writeHttpJson(response, httpStatusForRpcResponse(rpcResponse), rpcResponse, observationHeaders);
	});
}

function probeAuthorityMetadata(authority: TelclaudeMcpAuthority): {
	readonly domain: TelclaudeMcpAuthority["domain"];
	readonly memorySource: string;
	readonly profileId: string;
	readonly endpointId: string;
	readonly networkNamespace: string;
} {
	return {
		domain: authority.domain,
		memorySource: authority.memorySource,
		profileId: authority.profileId,
		endpointId: authority.endpointId,
		networkNamespace: authority.networkNamespace,
	};
}

function parseJsonRpcRequest(value: unknown):
	| { readonly ok: true; readonly request: TelclaudeLiveMcpJsonRpcRequest }
	| {
			readonly ok: false;
			readonly id?: JsonRpcId;
			readonly code: number;
			readonly reason: string;
	  } {
	if (Array.isArray(value)) {
		return {
			ok: false,
			code: -32600,
			reason: "MCP JSON-RPC batch requests are not supported",
		};
	}
	if (!isRecord(value)) {
		return { ok: false, code: -32600, reason: "MCP JSON-RPC request must be an object" };
	}

	const id = jsonRpcId(value.id);
	if (value.jsonrpc !== "2.0") {
		return { ok: false, id, code: -32600, reason: "MCP JSON-RPC version must be 2.0" };
	}
	if (hasOwn(value, "id") && id === undefined) {
		return { ok: false, code: -32600, reason: "MCP JSON-RPC id is invalid" };
	}
	if (typeof value.method !== "string" || !value.method.trim()) {
		return { ok: false, id, code: -32600, reason: "MCP JSON-RPC method is required" };
	}

	return {
		ok: true,
		request: {
			jsonrpc: "2.0",
			...(id !== undefined ? { id } : {}),
			method: value.method.trim(),
			params: value.params,
		},
	};
}

function parseToolCall(
	params: unknown,
):
	| { readonly ok: true; readonly name: string; readonly args: Record<string, unknown> }
	| { readonly ok: false; readonly code: number; readonly reason: string } {
	if (!isRecord(params)) {
		return { ok: false, code: -32602, reason: "MCP tools/call params must be an object" };
	}
	const name = params.name;
	if (typeof name !== "string" || !name.trim()) {
		return { ok: false, code: -32602, reason: "MCP tools/call name is required" };
	}
	const args = params.arguments;
	if (args === undefined) return { ok: true, name: name.trim(), args: {} };
	if (!isRecord(args)) {
		return { ok: false, code: -32602, reason: "MCP tools/call arguments must be an object" };
	}
	return { ok: true, name: name.trim(), args };
}

async function callBridgeTool(
	bridge: TelclaudeMcpBridge,
	name: TelclaudeMcpToolName,
	args: Record<string, unknown>,
): Promise<unknown> {
	return bridge[name](args);
}

function isTelclaudeToolName(name: string): name is TelclaudeMcpToolName {
	return (TELCLAUDE_MCP_TOOL_NAMES as readonly string[]).includes(name);
}

function isMemoryTool(name: TelclaudeMcpToolName): boolean {
	return name === "tc_memory_search" || name === "tc_memory_write";
}

function containsClientAuthorityField(value: unknown): boolean {
	if (Array.isArray(value)) {
		return value.some(containsClientAuthorityField);
	}
	if (!isRecord(value)) return false;
	return Object.entries(value).some(
		([key, child]) => CLIENT_AUTHORITY_KEYS.has(key) || containsClientAuthorityField(child),
	);
}

function containsPrototypePollutionKey(value: unknown): boolean {
	if (Array.isArray(value)) {
		return value.some(containsPrototypePollutionKey);
	}
	if (!isRecord(value)) return false;
	return Object.entries(value).some(
		([key, child]) => PROTOTYPE_POLLUTION_KEYS.has(key) || containsPrototypePollutionKey(child),
	);
}

function stripClientAuthorityEnvelope(input: Record<string, unknown>): Record<string, unknown> {
	const stripped = Object.create(null) as Record<string, unknown>;
	for (const [key, value] of Object.entries(input)) {
		if (!CLIENT_AUTHORITY_KEYS.has(key)) stripped[key] = value;
	}
	return stripped;
}

function emptySurfaceForMethod(
	method: string,
): { readonly [key: string]: readonly unknown[] } | undefined {
	return hasOwn(EMPTY_SURFACES, method) ? EMPTY_SURFACES[method] : undefined;
}

function jsonResult(id: JsonRpcId | undefined, result: unknown): TelclaudeLiveMcpJsonRpcResponse {
	return { jsonrpc: "2.0", ...(id !== undefined ? { id } : {}), result };
}

/**
 * Wrap a bridge tool result in an MCP `CallToolResult`. The MCP spec requires a
 * tools/call result to carry a `content` array; the upstream Hermes MCP client
 * (pydantic) rejects a bare payload with "content Field required" and, after a
 * few rejections, marks the whole relay server unreachable. We expose the data
 * both as a JSON text block (model-visible) and as `structuredContent`.
 */
function toCallToolResult(result: unknown): {
	readonly content: readonly { readonly type: "text"; readonly text: string }[];
	readonly structuredContent?: Record<string, unknown>;
} {
	const text = typeof result === "string" ? result : JSON.stringify(result ?? {});
	return {
		content: [{ type: "text", text }],
		...(isRecord(result) ? { structuredContent: result } : {}),
	};
}

function jsonError(
	id: JsonRpcId | undefined,
	code: number,
	message: string,
	data?: unknown,
): TelclaudeLiveMcpJsonRpcResponse {
	return {
		jsonrpc: "2.0",
		...(id !== undefined ? { id } : {}),
		error: {
			code,
			message,
			...(data !== undefined ? { data } : {}),
		},
	};
}

function jsonRpcId(value: unknown): JsonRpcId | undefined {
	return typeof value === "string" || typeof value === "number" || value === null
		? value
		: undefined;
}

function httpStatusForRpcResponse(response: TelclaudeLiveMcpJsonRpcResponse): number {
	if (!("error" in response)) return 200;
	if (response.error.code === -32700) return 400;
	if (response.error.message === "MCP connection is not authorized") return 403;
	return 200;
}

function writeHttpJson(
	response: http.ServerResponse,
	statusCode: number,
	body: TelclaudeLiveMcpJsonRpcResponse,
	headers: Readonly<Record<string, string>> = {},
): void {
	response.writeHead(statusCode, {
		"Content-Type": "application/json; charset=utf-8",
		"Cache-Control": "no-store",
		...headers,
	});
	response.end(`${JSON.stringify(body)}\n`);
}

function liveMcpObservationHeaders(
	request: http.IncomingMessage,
	server: TelclaudeLiveMcpRelayHttpServer,
): Record<string, string> {
	const peerAddress = normalizeObservedPeerAddress(request.socket.remoteAddress);
	return {
		[TELCLAUDE_LIVE_MCP_PLACEMENT_SIDE_HEADER]: server.placement.side,
		...(peerAddress ? { [TELCLAUDE_LIVE_MCP_OBSERVED_PEER_HEADER]: peerAddress } : {}),
	};
}

function normalizeObservedPeerAddress(value: string | undefined): string | undefined {
	const trimmed = value?.trim();
	if (!trimmed) return undefined;
	return trimmed.startsWith("::ffff:") ? trimmed.slice("::ffff:".length) : trimmed;
}

async function readHttpBody(request: http.IncomingMessage): Promise<string> {
	let body = "";
	for await (const chunk of request) {
		body += Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk);
		if (Buffer.byteLength(body, "utf8") > MAX_HTTP_BODY_BYTES) {
			throw new Error("MCP HTTP body is too large");
		}
	}
	return body;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOwn(value: object, key: PropertyKey): boolean {
	return Object.hasOwn(value, key);
}

function requiredTrimmed(value: string, field: string): string {
	const trimmed = value.trim();
	if (!trimmed) throw new Error(`Telclaude live MCP ${field} is required`);
	return trimmed;
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}
