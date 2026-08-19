import { spawnSync } from "node:child_process";
import { redactSecrets } from "../security/output-filter.js";
import {
	NETWORK_EGRESS_BROKER_RUN_REPORT_SCHEMA_VERSION,
	NETWORK_EGRESS_BROKER_RUN_REPORT_SOURCE,
	type NetworkEgressAttemptKind,
	type NetworkEgressBrokerRunAttempt,
	type NetworkEgressBrokerRunReport,
} from "./browser-computer-broker-probes.js";
import { DIRECT_EGRESS_NETWORK_DENIAL_ERROR_CODES } from "./network-probe-semantic-proof.js";
import { DEFAULT_MODEL_PROVIDER_PROBE_URL } from "./network-probes.js";
import { DEFAULT_SERVED_MCP_CONTAINED_CONTAINER_NAME } from "./served-mcp-containment.js";

export const DEFAULT_NETWORK_EGRESS_BROKER_RUN_REPORT_PATH =
	"artifacts/hermes/probes/network-egress-broker.run-report.json";
export const DEFAULT_NETWORK_EGRESS_BROKER_PUBLIC_RESEARCH_URL = "https://example.com/";
export const DEFAULT_NETWORK_EGRESS_BROKER_VAULT_URL = "http://vault:8222/v1/secrets";
export const DEFAULT_NETWORK_EGRESS_BROKER_METADATA_URL = "http://169.254.169.254/latest/meta-data";
export const DEFAULT_NETWORK_EGRESS_BROKER_PRIVATE_NETWORK_URL = "http://10.0.0.12/admin";
export const DEFAULT_NETWORK_EGRESS_BROKER_DOH_URL = "https://dns.google/dns-query";

export const NETWORK_EGRESS_BROKER_CORE_HTTP_KINDS = [
	"provider",
	"model",
	"vault",
	"metadata",
	"private-network",
	"doh",
] as const satisfies readonly NetworkEgressAttemptKind[];

export type NetworkEgressBrokerCoreHttpKind =
	(typeof NETWORK_EGRESS_BROKER_CORE_HTTP_KINDS)[number];

export type NetworkEgressBrokerContainerProbeRequest =
	| {
			readonly mode: "mcp-web-fetch";
			readonly target: string;
			readonly mcpUrl: string;
			readonly headers: Record<string, string>;
			readonly timeoutMs: number;
	  }
	| {
			readonly mode: "http-deny";
			readonly kind: NetworkEgressBrokerCoreHttpKind;
			readonly target: string;
			readonly timeoutMs: number;
	  };

export type NetworkEgressBrokerContainerProbeResult = {
	readonly observed:
		| "reachable"
		| "denied"
		| "policy_denied"
		| "timeout"
		| "inconclusive_error"
		| "invalid_response";
	readonly detail: string;
	readonly httpStatus?: number;
	readonly errorName?: string;
	readonly errorCode?: string;
	readonly durationMs?: number;
};

export type NetworkEgressBrokerRunReportOptions = {
	readonly allowRun: boolean;
	readonly dockerBin?: string;
	readonly containerName?: string;
	readonly timeoutMs?: number;
	readonly now?: Date;
	readonly mcp?: {
		readonly url: string;
		readonly headers: Record<string, string>;
		readonly publicResearchUrl?: string;
	};
	readonly targets: Partial<Record<NetworkEgressBrokerCoreHttpKind, string>>;
	readonly probeContainer?: (
		request: NetworkEgressBrokerContainerProbeRequest,
	) => Promise<NetworkEgressBrokerContainerProbeResult>;
};

const DEFAULT_TIMEOUT_MS = 5_000;

export async function runNetworkEgressBrokerRunReport(
	options: NetworkEgressBrokerRunReportOptions,
): Promise<NetworkEgressBrokerRunReport> {
	if (options.allowRun !== true) {
		throw new Error("network egress-broker report generation requires --allow-run");
	}

	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const probeContainer =
		options.probeContainer ??
		buildDockerExecNetworkEgressBrokerProbe({
			dockerBin: options.dockerBin,
			containerName: options.containerName,
		});
	const attempts: NetworkEgressBrokerRunAttempt[] = [];
	if (options.mcp) {
		const target =
			options.mcp.publicResearchUrl ?? DEFAULT_NETWORK_EGRESS_BROKER_PUBLIC_RESEARCH_URL;
		const result = await probeContainer({
			mode: "mcp-web-fetch",
			target,
			mcpUrl: options.mcp.url,
			headers: options.mcp.headers,
			timeoutMs,
		});
		attempts.push(publicResearchAttempt(target, result));
	}

	for (const kind of NETWORK_EGRESS_BROKER_CORE_HTTP_KINDS) {
		const target = options.targets[kind]?.trim();
		if (!target) continue;
		const result = await probeContainer({ mode: "http-deny", kind, target, timeoutMs });
		attempts.push(httpDenialAttempt(kind, target, result));
	}
	if (attempts.length === 0) {
		throw new Error("network egress-broker report generation has no configured probes to run");
	}

	const passCount = attempts.filter((attempt) => attempt.status === "pass").length;
	return {
		schemaVersion: NETWORK_EGRESS_BROKER_RUN_REPORT_SCHEMA_VERSION,
		surfaceId: "network.egress-broker",
		ran: true,
		observedAt: (options.now ?? new Date()).toISOString(),
		source: NETWORK_EGRESS_BROKER_RUN_REPORT_SOURCE,
		summary:
			passCount === attempts.length
				? `machine-observed egress broker core probes passed (${passCount}/${attempts.length}); report remains partial until all broker kinds are covered`
				: `machine-observed egress broker core probes are partial (${passCount}/${attempts.length} passed)`,
		attempts,
	};
}

export function defaultNetworkEgressBrokerTargets(
	input: Partial<Record<NetworkEgressBrokerCoreHttpKind, string | undefined>>,
): Partial<Record<NetworkEgressBrokerCoreHttpKind, string>> {
	return {
		...(input.provider?.trim() ? { provider: input.provider.trim() } : {}),
		model: input.model?.trim() || DEFAULT_MODEL_PROVIDER_PROBE_URL,
		vault: input.vault?.trim() || DEFAULT_NETWORK_EGRESS_BROKER_VAULT_URL,
		metadata: input.metadata?.trim() || DEFAULT_NETWORK_EGRESS_BROKER_METADATA_URL,
		"private-network":
			input["private-network"]?.trim() || DEFAULT_NETWORK_EGRESS_BROKER_PRIVATE_NETWORK_URL,
		doh: input.doh?.trim() || DEFAULT_NETWORK_EGRESS_BROKER_DOH_URL,
	};
}

export function parseNetworkEgressBrokerMcpAuthHeader(
	value: string | undefined,
): Record<string, string> | undefined {
	if (!value?.trim()) return undefined;
	const separatorIndex = value.indexOf(":");
	if (separatorIndex <= 0) {
		throw new Error("MCP auth header must use 'Name: value' format");
	}
	const name = value.slice(0, separatorIndex).trim();
	const headerValue = value.slice(separatorIndex + 1).trim();
	if (!name || !headerValue) {
		throw new Error("MCP auth header must include a non-empty name and value");
	}
	return { [name]: headerValue };
}

function publicResearchAttempt(
	target: string,
	result: NetworkEgressBrokerContainerProbeResult,
): NetworkEgressBrokerRunAttempt {
	const pass = result.observed === "reachable" && result.httpStatus !== undefined;
	return withOptionalFields({
		name: "public-research-through-broker",
		kind: "public-research",
		target: redactSecrets(target),
		expectation: "allow",
		status: pass ? "pass" : "fail",
		observed: result.observed,
		detail: result.detail,
		route: pass ? "telclaude-egress-broker" : undefined,
		httpStatus: result.httpStatus,
		errorName: result.errorName,
		errorCode: result.errorCode,
		durationMs: result.durationMs,
	});
}

function httpDenialAttempt(
	kind: NetworkEgressBrokerCoreHttpKind,
	target: string,
	result: NetworkEgressBrokerContainerProbeResult,
): NetworkEgressBrokerRunAttempt {
	const pass =
		result.observed === "policy_denied" ||
		(result.observed === "denied" &&
			result.errorCode !== undefined &&
			DIRECT_EGRESS_NETWORK_DENIAL_ERROR_CODES.has(result.errorCode));
	return withOptionalFields({
		name: `${kind}-direct-denied`,
		kind,
		target: redactSecrets(target),
		expectation: "deny",
		status: pass ? "pass" : "fail",
		observed: result.observed,
		detail: result.detail,
		httpStatus: result.httpStatus,
		errorName: result.errorName,
		errorCode: result.errorCode,
		durationMs: result.durationMs,
	});
}

function buildDockerExecNetworkEgressBrokerProbe(options: {
	readonly dockerBin?: string;
	readonly containerName?: string;
}): (
	request: NetworkEgressBrokerContainerProbeRequest,
) => Promise<NetworkEgressBrokerContainerProbeResult> {
	const dockerBin = options.dockerBin?.trim() || process.env.DOCKER_BIN?.trim() || "docker";
	const containerName =
		options.containerName?.trim() ||
		process.env.TELCLAUDE_HERMES_CONTAINED_CONTAINER_NAME?.trim() ||
		DEFAULT_SERVED_MCP_CONTAINED_CONTAINER_NAME;
	return async (request) => {
		const result = spawnSync(
			dockerBin,
			["exec", "-i", containerName, "node", "--input-type=module", "-e", CONTAINER_PROBE_SCRIPT],
			{
				input: JSON.stringify(request),
				encoding: "utf8",
				env: { PATH: process.env.PATH ?? "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin" },
				timeout: request.timeoutMs + 1_000,
			},
		);
		const stdout = result.stdout?.trim() ?? "";
		let parsed: unknown;
		try {
			parsed = stdout ? (JSON.parse(stdout) as unknown) : undefined;
		} catch {
			parsed = undefined;
		}
		if (result.status !== 0 || result.error || !isContainerProbeResult(parsed)) {
			return {
				observed: "invalid_response",
				detail: `docker exec probe failed: ${redactSecrets(
					spawnFailureDetail(result.stderr, result.error) || stdout || "invalid probe output",
				)}`,
			};
		}
		return parsed;
	};
}

const CONTAINER_PROBE_SCRIPT = `
const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const request = JSON.parse(Buffer.concat(chunks).toString("utf8"));
const startedAt = Date.now();
const timeoutMs = Number.isFinite(Number(request.timeoutMs)) ? Number(request.timeoutMs) : 5000;
const controller = new AbortController();
const timer = setTimeout(() => controller.abort(), timeoutMs);
function emit(value) {
  console.log(JSON.stringify({...value, durationMs: Date.now() - startedAt}));
}
function normalizeError(error) {
  const cause = error && typeof error === "object" && "cause" in error ? error.cause : undefined;
  const code = cause && typeof cause === "object" && "code" in cause ? String(cause.code) : undefined;
  return {
    observed: error && error.name === "AbortError" ? "timeout" : "inconclusive_error",
    errorName: error && error.name ? String(error.name) : "Error",
    ...(code ? {errorCode: code} : {}),
    detail: error instanceof Error ? error.message : String(error),
  };
}
async function postJson(url, headers, body) {
  const response = await fetch(String(url), {
    method: "POST",
    headers: {"content-type": "application/json", ...headers},
    body: JSON.stringify(body),
    signal: controller.signal,
  });
  const text = await response.text();
  let parsed;
  try { parsed = text ? JSON.parse(text) : {}; } catch { parsed = {parseError: text.slice(0, 200)}; }
  return {response, parsed};
}
try {
  if (request.mode === "mcp-web-fetch") {
    await postJson(request.mcpUrl, request.headers || {}, {
      jsonrpc: "2.0",
      id: "init",
      method: "initialize",
      params: {protocolVersion: "2024-11-05", capabilities: {}, clientInfo: {name: "telclaude-network-egress-broker-report", version: "0"}}
    });
    const {response, parsed} = await postJson(request.mcpUrl, request.headers || {}, {
      jsonrpc: "2.0",
      id: "fetch",
      method: "tools/call",
      params: {name: "tc_web_fetch", arguments: {url: request.target, maxChars: 256, timeoutMs}}
    });
    if (!response.ok || parsed.error) {
      emit({
        observed: "inconclusive_error",
        httpStatus: response.status,
        detail: parsed.error?.message ? String(parsed.error.message) : "tc_web_fetch JSON-RPC call failed"
      });
    } else {
      const result = parsed.result || {};
      const structured = result.structuredContent || {};
      if (typeof structured.httpStatus !== "number") {
        emit({
          observed: "invalid_response",
          httpStatus: response.status,
          detail: "tc_web_fetch result did not include structuredContent.httpStatus"
        });
      } else {
      emit({
        observed: "reachable",
        httpStatus: structured.httpStatus,
        detail: "tc_web_fetch completed through the served MCP endpoint"
      });
      }
    }
  } else {
    const response = await fetch(String(request.target), {method: "GET", redirect: "manual", signal: controller.signal});
    const policyDenied = response.status === 403 && response.headers.get("x-telclaude-network-policy") === "denied";
    emit({
      observed: policyDenied ? "policy_denied" : "reachable",
      httpStatus: response.status,
      detail: policyDenied
        ? "target was denied by the Telclaude network policy proxy"
        : "target was reachable from the contained runtime"
    });
  }
} catch (error) {
  const normalized = normalizeError(error);
  if (normalized.errorCode && ["ECONNREFUSED", "EHOSTDOWN", "EHOSTUNREACH", "ENETUNREACH", "EACCES", "EPERM"].includes(normalized.errorCode)) {
    normalized.observed = "denied";
  }
  emit(normalized);
} finally {
  clearTimeout(timer);
}
`;

function withOptionalFields(
	attempt: NetworkEgressBrokerRunAttempt & {
		readonly route?: string | undefined;
		readonly httpStatus?: number | undefined;
		readonly errorName?: string | undefined;
		readonly errorCode?: string | undefined;
		readonly durationMs?: number | undefined;
	},
): NetworkEgressBrokerRunAttempt {
	return Object.fromEntries(
		Object.entries(attempt).filter(([, value]) => value !== undefined),
	) as NetworkEgressBrokerRunAttempt;
}

function isContainerProbeResult(value: unknown): value is NetworkEgressBrokerContainerProbeResult {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const record = value as Record<string, unknown>;
	return typeof record.observed === "string" && typeof record.detail === "string";
}

function spawnFailureDetail(stderr: string | Buffer | undefined, error: Error | undefined): string {
	const stderrText = Buffer.isBuffer(stderr) ? stderr.toString("utf8") : (stderr ?? "");
	return stderrText.trim() || error?.message || "";
}
