import { spawn } from "node:child_process";
import type { StreamChunk } from "../sdk/client.js";
import { TELCLAUDE_MCP_TOOL_NAMES } from "./mcp/policy.js";
import { buildHermesPrivateRuntimeAdapterFromEnv } from "./private-execute.js";
import {
	executeHermesPrivateRuntime,
	type HermesPrivateRuntimeRequest,
	type HermesRuntimeAdapter,
} from "./private-runtime.js";
import { HermesSessionMap } from "./session-map.js";

/**
 * Behavioral post-deploy verification of the live Hermes private runtime.
 *
 * Unlike the cutover feature probes (which prove the relay's side of every
 * contract), these checks prove the operator-visible capability path:
 * the live MCP server advertises the exact tc_ tool surface WITH usable
 * schemas, and a real turn through the contained Hermes API server actually
 * invokes a relay-served MCP tool. Every check fails closed: a reachable but
 * tool-less runtime is a FAIL, not a warning.
 */

export const HERMES_VERIFY_LIVE_SCHEMA_VERSION = "telclaude.hermes.verify-live.v1";

export const HERMES_VERIFY_LIVE_SENTINEL = "VERIFY-LIVE-OK";

export const HERMES_VERIFY_LIVE_MCP_SERVER_NAME = "telclaude-live-mcp-relay";

export type HermesVerifyLiveCheckStatus = "pass" | "fail" | "skip";

export type HermesVerifyLiveCheck = {
	readonly id: string;
	readonly status: HermesVerifyLiveCheckStatus;
	readonly detail: string;
	readonly evidence?: unknown;
};

export type HermesVerifyLiveReport = {
	readonly schemaVersion: typeof HERMES_VERIFY_LIVE_SCHEMA_VERSION;
	readonly status: "pass" | "fail";
	readonly generatedAtMs: number;
	readonly checks: readonly HermesVerifyLiveCheck[];
};

export class HermesVerifyLiveInputError extends Error {}

export type HermesVerifyLiveRpcRequest = {
	readonly url: string;
	readonly authorizationHeader?: string;
	readonly payload: unknown;
	readonly timeoutMs: number;
};

export type HermesVerifyLiveRpcResponse = {
	readonly status: number;
	readonly body: unknown;
};

export type HermesVerifyLiveRpcTransport = (
	request: HermesVerifyLiveRpcRequest,
) => Promise<HermesVerifyLiveRpcResponse>;

const DEFAULT_RPC_TIMEOUT_MS = 30_000;
const DEFAULT_TURN_TIMEOUT_MS = 180_000;

// ═══════════════════════════════════════════════════════════════════════════
// MCP surface checks (tools/list through the live relay MCP endpoint)
// ═══════════════════════════════════════════════════════════════════════════

export type RunHermesVerifyLiveMcpChecksOptions = {
	readonly endpointUrl: string;
	readonly transport: HermesVerifyLiveRpcTransport;
	readonly authorizationHeader?: string;
	readonly timeoutMs?: number;
};

export async function runHermesVerifyLiveMcpChecks(
	options: RunHermesVerifyLiveMcpChecksOptions,
): Promise<HermesVerifyLiveCheck[]> {
	const timeoutMs = options.timeoutMs ?? DEFAULT_RPC_TIMEOUT_MS;
	const post = async (method: string): Promise<HermesVerifyLiveRpcResponse> =>
		options.transport({
			url: options.endpointUrl,
			authorizationHeader: options.authorizationHeader,
			payload: { jsonrpc: "2.0", id: `verify-live-${method}`, method, params: {} },
			timeoutMs,
		});

	let initialize: HermesVerifyLiveRpcResponse;
	try {
		initialize = await post("initialize");
	} catch (error) {
		const detail = `live MCP initialize transport error: ${errorMessage(error)}`;
		return [
			failCheck("mcp.initialize", detail),
			failCheck("mcp.tools_list_exact", detail),
			failCheck("mcp.tool_schemas", detail),
		];
	}

	const checks: HermesVerifyLiveCheck[] = [];
	const serverName = readPath(initialize.body, ["result", "serverInfo", "name"]);
	if (initialize.status === 200 && serverName === HERMES_VERIFY_LIVE_MCP_SERVER_NAME) {
		checks.push(passCheck("mcp.initialize", `live MCP initialize ok (${serverName})`));
	} else {
		checks.push(
			failCheck(
				"mcp.initialize",
				`live MCP initialize failed (http ${initialize.status}): ${rpcFailureDetail(initialize.body)}`,
				initialize.body,
			),
		);
	}

	let toolsList: HermesVerifyLiveRpcResponse;
	try {
		toolsList = await post("tools/list");
	} catch (error) {
		const detail = `live MCP tools/list transport error: ${errorMessage(error)}`;
		return [
			...checks,
			failCheck("mcp.tools_list_exact", detail),
			failCheck("mcp.tool_schemas", detail),
		];
	}

	const tools = readPath(toolsList.body, ["result", "tools"]);
	if (toolsList.status !== 200 || !Array.isArray(tools)) {
		const detail = `live MCP tools/list failed (http ${toolsList.status}): ${rpcFailureDetail(toolsList.body)}`;
		return [
			...checks,
			failCheck("mcp.tools_list_exact", detail),
			failCheck("mcp.tool_schemas", detail),
		];
	}

	const names = tools
		.map((tool) => (isRecord(tool) && typeof tool.name === "string" ? tool.name : ""))
		.filter((name) => name.length > 0);
	const expected = [...TELCLAUDE_MCP_TOOL_NAMES].sort();
	const observed = [...names].sort();
	if (sameStringArray(expected, observed)) {
		checks.push(
			passCheck(
				"mcp.tools_list_exact",
				`tools/list returned the exact ${expected.length}-tool tc_ surface`,
			),
		);
	} else {
		checks.push(
			failCheck(
				"mcp.tools_list_exact",
				`tools/list mismatch: expected [${expected.join(", ")}], observed [${observed.join(", ")}]`,
				{ expected, observed },
			),
		);
	}

	const schemaless = tools.filter((tool) => !hasUsableToolSchema(tool));
	if (tools.length > 0 && schemaless.length === 0) {
		checks.push(
			passCheck(
				"mcp.tool_schemas",
				"every advertised tool carries a description and an object inputSchema",
			),
		);
	} else {
		const offenders = schemaless
			.map((tool) => (isRecord(tool) && typeof tool.name === "string" ? tool.name : "<unnamed>"))
			.sort();
		checks.push(
			failCheck(
				"mcp.tool_schemas",
				`tools without a usable description+inputSchema: [${offenders.join(", ")}] — the model cannot call these`,
				{ offenders },
			),
		);
	}

	return checks;
}

function hasUsableToolSchema(tool: unknown): boolean {
	if (!isRecord(tool)) return false;
	if (typeof tool.description !== "string" || tool.description.trim().length === 0) return false;
	const schema = tool.inputSchema;
	if (!isRecord(schema)) return false;
	if (schema.type !== "object") return false;
	const properties = schema.properties;
	return isRecord(properties) && Object.keys(properties).length > 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// Behavioral turn checks (a real turn through the Hermes API server)
// ═══════════════════════════════════════════════════════════════════════════

export type HermesVerifyLiveProviderCanary = {
	readonly providerId: string;
	readonly service: string;
	readonly action: string;
};

/**
 * Relay-side canary activation window. The canary turn runs in THIS process,
 * but the contained Hermes resolves its static MCP transport token against
 * the RELAY process's active runtime authority — so the relay must open a
 * scoped activation window for the turn, or every tools/call would be denied
 * even on a healthy deploy. No window client (or a failed open) fails the
 * turn checks closed; the window is always closed in finally, with its TTL as
 * the fail-safe.
 */
export type HermesVerifyLiveCanaryWindowClient = {
	open(input: {
		readonly profileId?: string;
		readonly providerScopes?: readonly string[];
		readonly ttlMs?: number;
	}): Promise<{
		readonly activationId: string;
		readonly authorityHandle: string;
		readonly expiresAtMs: number;
	}>;
	close(input: {
		readonly activationId: string;
		readonly authorityHandle: string;
		readonly reason?: string;
	}): Promise<unknown>;
};

export type RunHermesVerifyLiveTurnChecksOptions = {
	readonly runtime?: HermesRuntimeAdapter;
	readonly env?: NodeJS.ProcessEnv;
	readonly cwd?: string;
	readonly timeoutMs?: number;
	readonly providerCanary?: HermesVerifyLiveProviderCanary;
	readonly canaryWindow?: HermesVerifyLiveCanaryWindowClient;
	readonly nowMs?: number;
};

export function buildHermesVerifyLiveCanaryPrompt(
	providerCanary?: HermesVerifyLiveProviderCanary,
): string {
	const steps = [
		'1. Call the MCP tool tc_memory_search with input {"query": "verify-live-canary", "limit": 1}.',
	];
	if (providerCanary) {
		steps.push(
			`2. Call the MCP tool tc_provider_read with input {"providerId": "${providerCanary.providerId}", "service": "${providerCanary.service}", "action": "${providerCanary.action}"}.`,
		);
	}
	steps.push(
		`${steps.length + 1}. After the tool calls return (success or error), reply with exactly: ${HERMES_VERIFY_LIVE_SENTINEL}`,
	);
	return [
		"This is an automated telclaude verify-live canary turn. Follow the steps exactly and do nothing else.",
		...steps,
		"Do not use any other tools. Do not browse. Do not write memory.",
	].join("\n");
}

export async function runHermesVerifyLiveTurnChecks(
	options: RunHermesVerifyLiveTurnChecksOptions,
): Promise<HermesVerifyLiveCheck[]> {
	const runtime =
		options.runtime ?? buildHermesPrivateRuntimeAdapterFromEnv(options.env ?? process.env);
	if (!runtime) {
		throw new HermesVerifyLiveInputError(
			"Hermes API runtime is not configured: set TELCLAUDE_HERMES_API_BASE_URL and TELCLAUDE_HERMES_API_KEY (or pass --api-base-url)",
		);
	}

	const timeoutMs = options.timeoutMs ?? DEFAULT_TURN_TIMEOUT_MS;
	const nowMs = options.nowMs ?? Date.now();

	const failAllTurnChecks = (detail: string): HermesVerifyLiveCheck[] => [
		failCheck("runtime.turn_completes", detail),
		failCheck("runtime.mcp_tool_invoked", detail),
		failCheck("runtime.canary_acknowledged", detail),
		options.providerCanary
			? failCheck("runtime.provider_read", detail)
			: {
					id: "runtime.provider_read",
					status: "skip" as const,
					detail:
						"no provider canary configured (pass --provider-canary <providerId:service:action>)",
				},
	];

	if (!options.canaryWindow) {
		return failAllTurnChecks(
			"no relay canary activation window client — a standalone canary turn cannot resolve the relay's static MCP transport token without a relay-side activation; provide the admin-socket window client",
		);
	}

	let window: { activationId: string; authorityHandle: string; expiresAtMs: number };
	try {
		window = await options.canaryWindow.open({
			profileId: "verify-live",
			providerScopes: options.providerCanary ? [options.providerCanary.providerId] : [],
			ttlMs: timeoutMs + 30_000,
		});
	} catch (error) {
		return failAllTurnChecks(
			`canary activation window open failed (relay busy with another active turn authority, admin socket disabled, or pre-W0 relay): ${errorMessage(error)}`,
		);
	}

	const controller = new AbortController();
	const timeout = setTimeout(() => controller.abort(), timeoutMs);

	const request: HermesPrivateRuntimeRequest = {
		prompt: buildHermesVerifyLiveCanaryPrompt(options.providerCanary),
		cwd: options.cwd ?? process.cwd(),
		tier: "READ_ONLY",
		sessionKey: `verify-live-${nowMs}`,
		profileId: "verify-live",
		identity: { userId: "verify-live" },
		allowedSkills: [],
		isNewSession: true,
		timeoutMs,
		signal: controller.signal,
	};

	const toolUses: string[] = [];
	const texts: string[] = [];
	let finalResult: {
		success: boolean;
		response: string;
		error?: string;
		durationMs: number;
	} | null = null;
	let streamError: string | null = null;

	try {
		const stream = executeHermesPrivateRuntime({
			runtime,
			sessions: new HermesSessionMap(),
			request,
		});
		for await (const chunk of stream as AsyncIterable<StreamChunk>) {
			switch (chunk.type) {
				case "tool_use":
					toolUses.push(chunk.toolName);
					break;
				case "text":
					texts.push(chunk.content);
					break;
				case "done":
					finalResult = {
						success: chunk.result.success,
						response: chunk.result.response,
						error: chunk.result.error,
						durationMs: chunk.result.durationMs,
					};
					break;
				default:
					break;
			}
		}
	} catch (error) {
		streamError = errorMessage(error);
	} finally {
		clearTimeout(timeout);
		try {
			await options.canaryWindow.close({
				activationId: window.activationId,
				authorityHandle: window.authorityHandle,
				reason: "verify-live canary turn finished",
			});
		} catch {
			// Best-effort: the window TTL is the fail-safe; a close failure
			// must not mask the captured canary result.
		}
	}

	const checks: HermesVerifyLiveCheck[] = [];
	const observedTools = [...new Set(toolUses)].slice(0, 20);

	if (streamError) {
		checks.push(failCheck("runtime.turn_completes", `turn stream error: ${streamError}`));
	} else if (finalResult?.success) {
		checks.push(
			passCheck(
				"runtime.turn_completes",
				`turn completed in ${finalResult.durationMs}ms with a non-empty reply`,
			),
		);
	} else {
		checks.push(
			failCheck(
				"runtime.turn_completes",
				`turn did not complete successfully: ${finalResult?.error ?? "no done event"}`,
			),
		);
	}

	if (observedTools.some((name) => name.includes("tc_memory_search"))) {
		checks.push(
			passCheck("runtime.mcp_tool_invoked", "tc_memory_search was invoked through the served MCP", {
				observedTools,
			}),
		);
	} else {
		checks.push(
			failCheck(
				"runtime.mcp_tool_invoked",
				`tc_memory_search was never invoked — the model toolset has no working served-MCP path (observed tools: [${observedTools.join(", ")}])`,
				{ observedTools },
			),
		);
	}

	const replyText = `${finalResult?.response ?? ""}\n${texts.join("\n")}`;
	if (replyText.includes(HERMES_VERIFY_LIVE_SENTINEL)) {
		checks.push(
			passCheck("runtime.canary_acknowledged", "the canary sentinel came back in the reply"),
		);
	} else {
		checks.push(
			failCheck(
				"runtime.canary_acknowledged",
				`reply did not contain the ${HERMES_VERIFY_LIVE_SENTINEL} sentinel — the runtime is not following the canary protocol`,
			),
		);
	}

	if (!options.providerCanary) {
		checks.push({
			id: "runtime.provider_read",
			status: "skip",
			detail: "no provider canary configured (pass --provider-canary <providerId:service:action>)",
		});
	} else if (observedTools.some((name) => name.includes("tc_provider_read"))) {
		checks.push(
			passCheck("runtime.provider_read", "tc_provider_read was invoked through the served MCP", {
				observedTools,
			}),
		);
	} else {
		checks.push(
			failCheck(
				"runtime.provider_read",
				`tc_provider_read was never invoked for the configured canary (observed tools: [${observedTools.join(", ")}])`,
				{ observedTools },
			),
		);
	}

	return checks;
}

// ═══════════════════════════════════════════════════════════════════════════
// Report assembly
// ═══════════════════════════════════════════════════════════════════════════

export function buildHermesVerifyLiveReport(
	checks: readonly HermesVerifyLiveCheck[],
	nowMs: number = Date.now(),
): HermesVerifyLiveReport {
	return {
		schemaVersion: HERMES_VERIFY_LIVE_SCHEMA_VERSION,
		status: checks.some((check) => check.status === "fail") ? "fail" : "pass",
		generatedAtMs: nowMs,
		checks,
	};
}

// ═══════════════════════════════════════════════════════════════════════════
// RPC transports
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Reads the static MCP transport bearer from the contained container's own
 * generated config.yaml. Using THIS token for the surface check replicates
 * upstream Hermes's discovery path exactly — same origin, same credential —
 * and needs no relay admin socket, so it works from the William gate's host
 * context.
 */
export async function readHermesContainedStaticAuthorizationHeader(
	options: CreateHermesVerifyLiveDockerExecTransportOptions = {},
): Promise<string> {
	const containerName = options.containerName ?? "tc-hermes-contained";
	const output = await execDockerCollect({
		dockerBin: options.dockerBin ?? "docker",
		args: [
			"exec",
			containerName,
			"sed",
			"-n",
			's/.*Authorization: "Bearer \\(.*\\)".*/\\1/p',
			"/home/hermes/.hermes/config.yaml",
		],
		label: "docker exec config read",
	});
	const token = output.split("\n")[0]?.trim();
	if (!token) {
		throw new Error(
			`no static MCP bearer found in ${containerName}:/home/hermes/.hermes/config.yaml mcp_servers headers`,
		);
	}
	return `Bearer ${token}`;
}

export function createHermesVerifyLiveFetchTransport(
	fetchImpl: typeof fetch = fetch,
): HermesVerifyLiveRpcTransport {
	return async (request) => {
		const response = await fetchImpl(request.url, {
			method: "POST",
			headers: {
				"content-type": "application/json",
				...(request.authorizationHeader ? { authorization: request.authorizationHeader } : {}),
			},
			body: JSON.stringify(request.payload),
			signal: AbortSignal.timeout(request.timeoutMs),
		});
		const text = await response.text();
		return { status: response.status, body: parseJsonOrRaw(text) };
	};
}

const DOCKER_EXEC_RPC_PYTHON = [
	"import json,sys,urllib.request,urllib.error",
	"cfg=json.load(sys.stdin)",
	'headers={"content-type":"application/json"}',
	'auth=cfg.get("authorizationHeader")',
	"if auth:",
	'\theaders["authorization"]=auth',
	'req=urllib.request.Request(cfg["url"],data=json.dumps(cfg["payload"]).encode(),headers=headers,method="POST")',
	"try:",
	'\twith urllib.request.urlopen(req,timeout=cfg["timeoutSeconds"]) as r:',
	'\t\tstatus,text=r.getcode(),r.read().decode("utf-8","replace")',
	"except urllib.error.HTTPError as e:",
	'\tstatus,text=e.code,e.read().decode("utf-8","replace")',
	"try:",
	"\tbody=json.loads(text)",
	"except Exception:",
	'\tbody={"raw":text}',
	'print(json.dumps({"status":status,"body":body}))',
].join("\n");

export type CreateHermesVerifyLiveDockerExecTransportOptions = {
	readonly containerName?: string;
	readonly dockerBin?: string;
};

/**
 * Issues the JSON-RPC call from INSIDE the contained Hermes container via
 * docker exec, so the live MCP server observes the allowed contained peer
 * address. Running from the host would be rejected by peer binding — which
 * is the posture working as intended, not a transport bug.
 */
export function createHermesVerifyLiveDockerExecTransport(
	options: CreateHermesVerifyLiveDockerExecTransportOptions = {},
): HermesVerifyLiveRpcTransport {
	const containerName = options.containerName ?? "tc-hermes-contained";
	const dockerBin = options.dockerBin ?? "docker";
	return async (request) => {
		const output = await execDockerCollect({
			dockerBin,
			args: ["exec", "-i", containerName, "python", "-c", DOCKER_EXEC_RPC_PYTHON],
			stdinData: JSON.stringify({
				url: request.url,
				authorizationHeader: request.authorizationHeader,
				payload: request.payload,
				timeoutSeconds: Math.max(1, Math.ceil(request.timeoutMs / 1_000)),
			}),
			timeoutMs: request.timeoutMs + 5_000,
			label: "docker exec RPC",
		});
		const text = output.trim();
		const parsed = parseJsonOrRaw(lastLine(text));
		if (isRecord(parsed) && typeof parsed.status === "number" && Object.hasOwn(parsed, "body")) {
			return { status: parsed.status, body: parsed.body };
		}
		throw new Error(`docker exec RPC returned unparseable output: ${text.slice(0, 200)}`);
	};
}

function execDockerCollect(options: {
	readonly dockerBin: string;
	readonly args: readonly string[];
	readonly stdinData?: string;
	readonly timeoutMs?: number;
	readonly label: string;
}): Promise<string> {
	return new Promise((resolve, reject) => {
		const child = spawn(options.dockerBin, [...options.args], {
			stdio: [options.stdinData === undefined ? "ignore" : "pipe", "pipe", "pipe"],
		});
		const stdout: Buffer[] = [];
		const stderr: Buffer[] = [];
		const timer =
			options.timeoutMs === undefined
				? null
				: setTimeout(() => {
						child.kill("SIGKILL");
						reject(new Error(`${options.label} timed out after ${options.timeoutMs}ms`));
					}, options.timeoutMs);
		child.stdout?.on("data", (data: Buffer) => stdout.push(data));
		child.stderr?.on("data", (data: Buffer) => stderr.push(data));
		child.on("error", (error) => {
			if (timer) clearTimeout(timer);
			reject(error);
		});
		child.on("close", (code) => {
			if (timer) clearTimeout(timer);
			if (code !== 0) {
				reject(
					new Error(
						`${options.label} failed (exit ${code}): ${Buffer.concat(stderr).toString("utf8").trim()}`,
					),
				);
				return;
			}
			resolve(Buffer.concat(stdout).toString("utf8"));
		});
		if (options.stdinData !== undefined) child.stdin?.end(options.stdinData);
	});
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

function passCheck(id: string, detail: string, evidence?: unknown): HermesVerifyLiveCheck {
	return { id, status: "pass", detail, ...(evidence !== undefined ? { evidence } : {}) };
}

function failCheck(id: string, detail: string, evidence?: unknown): HermesVerifyLiveCheck {
	return { id, status: "fail", detail, ...(evidence !== undefined ? { evidence } : {}) };
}

function rpcFailureDetail(body: unknown): string {
	const message = readPath(body, ["error", "message"]);
	if (typeof message === "string" && message.trim()) {
		if (message.includes("not authorized")) {
			return `${message} — issue a probe token via the relay admin socket and run with the docker-exec transport so the request originates from the allowed contained peer`;
		}
		return message;
	}
	return "unexpected response shape";
}

function readPath(value: unknown, path: readonly string[]): unknown {
	let current: unknown = value;
	for (const key of path) {
		if (!isRecord(current)) return undefined;
		current = current[key];
	}
	return current;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function sameStringArray(left: readonly string[], right: readonly string[]): boolean {
	return left.length === right.length && left.every((value, index) => value === right[index]);
}

function parseJsonOrRaw(text: string): unknown {
	try {
		return JSON.parse(text);
	} catch {
		return { raw: text };
	}
}

function lastLine(text: string): string {
	const lines = text.split("\n").filter((line) => line.trim().length > 0);
	return lines[lines.length - 1] ?? "";
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}
