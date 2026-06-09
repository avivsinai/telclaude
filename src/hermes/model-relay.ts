import { spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { verifyOpenAiCodexPeerBoundProxyToken } from "../relay/openai-codex-proxy.js";
import { redactSecrets } from "../security/output-filter.js";
import {
	type HermesArtifactWriteOptions,
	type NETWORK_PROBE_POSTURES,
	resolveHermesArtifactPath,
	writeHermesJsonArtifact,
} from "./foundation.js";
import { DEFAULT_MODEL_PROVIDER_PROBE_URL } from "./network-probes.js";

export const HERMES_MODEL_RELAY_SCHEMA_VERSION = "telclaude.hermes.model-relay.v1";
export const DEFAULT_MODEL_RELAY_EVIDENCE_PATH = "artifacts/hermes/probes/model-relay.json";
export const DEFAULT_MODEL_RELAY_PROFILE_DIR = "/home/hermes/.hermes";
export const MODEL_RELAY_OBSERVED_PEER_HEADER = "x-telclaude-model-relay-observed-peer-address";
export const DEFAULT_MODEL_RELAY_CONTAINED_CONTAINER_NAME = "tc-hermes-contained";
export const DEFAULT_MODEL_RELAY_POSTURE = "agent-iptables" as const;
const TELCLAUDE_OPENAI_CODEX_RELAY_PROXY_URL = "http://telclaude:8790/v1/openai-codex-proxy";
const HERMES_INFERENCE_MODEL_ENV = "HERMES_INFERENCE_MODEL";
const HERMES_CODEX_BASE_URL_ENV = "HERMES_CODEX_BASE_URL";
const OPENAI_CODEX_PROXY_TOKEN_ENV = "TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN";

type ModelRelayStatus = "pass" | "fail" | "pending";
export type ModelRelayPosture = (typeof NETWORK_PROBE_POSTURES)[number];

type ModelRelayGate = {
	readonly name: string;
	readonly status: "pass" | "fail" | "pending";
	readonly detail: string;
};
type ProfileCustodyEntry = {
	readonly relativePath: string;
	readonly kind?: "directory" | "file" | "other";
	readonly uid?: number;
	readonly mode?: number;
	readonly error?: string;
};
type FetchLike = (
	input: Parameters<typeof fetch>[0],
	init?: Parameters<typeof fetch>[1],
) => ReturnType<typeof fetch>;
type ModelRelayProvider = {
	readonly provider: "openai-codex";
	readonly baseUrl: string;
	readonly baseUrlHost: string;
	readonly model: string;
	readonly modelSource: `env:${typeof HERMES_INFERENCE_MODEL_ENV}` | "missing";
	readonly authLocation: "hermes-auth-store:openai-codex";
	readonly authScope: "relay-openai-codex-subscription-proxy";
	readonly tokenScoping: "static-shared" | "peer-bound";
	readonly auxiliaryAuthSource: "manual:telclaude-relay";
	readonly auxiliaryBaseUrl: string;
	readonly auxiliaryBaseUrlHost: string;
	readonly refreshTokenPolicy: "non-refreshable-placeholder";
};
type ModelRelayOrigin = {
	readonly kind: "contained-peer" | "relay-self-smoke" | "unknown";
	readonly containerName?: string;
	readonly observedPeerAddress?: string;
	readonly observedPeerSource?: "server-peer-echo";
	readonly expectedPeerAddress?: string;
	readonly expectedPeerSource?: "configured-contained-ip";
	readonly detail: string;
};

export type HermesModelRelayReport = {
	readonly schemaVersion: typeof HERMES_MODEL_RELAY_SCHEMA_VERSION;
	readonly probeId: "model.relay";
	readonly posture: ModelRelayPosture;
	readonly status: ModelRelayStatus;
	readonly ran: boolean;
	readonly summary: string;
	readonly generatedAt: string;
	readonly gates: readonly ModelRelayGate[];
	readonly origin: ModelRelayOrigin;
	readonly modelProvider?: ModelRelayProvider;
	readonly observation?: {
		readonly relayUrl?: string;
		readonly directModelUrl: string;
		readonly profileDir?: string;
		readonly scannedProfileFiles?: readonly string[];
	};
};

export type HermesModelRelayProbeOptions = {
	readonly allowRun: boolean;
	readonly relayUrl?: string;
	readonly directModelUrl?: string;
	readonly profileDir?: string;
	readonly runtimeCustodyProfileDir?: string;
	readonly firewallSentinelPath?: string;
	readonly posture?: ModelRelayPosture;
	readonly containerName?: string;
	readonly dockerBin?: string;
	readonly expectedPeerAddress?: string;
	readonly relayPeerAddress?: string;
	readonly timeoutMs?: number;
	readonly fetchImpl?: FetchLike;
	readonly now?: Date;
};

const DEFAULT_TIMEOUT_MS = 3_000;
const POSITIVE_DENIAL_ERROR_CODES = new Set([
	"ECONNREFUSED",
	"EHOSTDOWN",
	"EHOSTUNREACH",
	"ENETUNREACH",
	"EACCES",
	"EPERM",
]);
const MODEL_CREDENTIAL_PATTERNS = [
	/\b(ANTHROPIC|OPENAI|GEMINI|GOOGLE|OPENROUTER|XAI)_API_KEY[ \t]*[:=][ \t]*["']?[A-Za-z0-9._~+/=-]{8,}/i,
	/\b(?:CODEX_HOME|HERMES_CODEX_BASE_URL)[ \t]*[:=][ \t]*["']?https:\/\/chatgpt\.com/i,
	/\b(BEDROCK|AWS)_SECRET_ACCESS_KEY[ \t]*[:=][ \t]*["']?[A-Za-z0-9._~+/=-]{12,}/i,
	/\b(model|llm)[_-]?(api[_-]?key|token|secret)[ \t]*[:=][ \t]*["']?[A-Za-z0-9._~+/=-]{12,}/i,
	/\b(?:openai|anthropic|google|gemini|groq|mistral|model|llm)[_-]?api[_-]?key["']?[ \t]*[:=][ \t]*["']?[A-Za-z0-9._~+/=-]{12,}/i,
	/\bapi[_-]?key["']?[ \t]*[:=][ \t]*["']?sk-[A-Za-z0-9._-]{12,}/i,
	/\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b/i,
	/\b(?:access|refresh|id)[_-]?token["']?[ \t]*[:=][ \t]*["']?[A-Za-z0-9._~+/=-]{20,}/i,
	/\b(?:auth|bearer)[_-]?(?:token|secret|state)?["']?[ \t]*[:=][ \t]*["']?Bearer[ \t]+[A-Za-z0-9._~+/=-]{12,}/i,
	/\b(?:session|cookie|cookies)[_-](?:token|secret|state)["']?[ \t]*[:=][ \t]*["']?[A-Za-z0-9._~+/=-]{12,}/i,
	/\bCookie["']?[ \t]*[:=][ \t]*["']?[^"'\n=]+=[A-Za-z0-9._~+/=-]{16,}/i,
	/\bAuthorization[ \t]*[:=][ \t]*["']?Bearer[ \t]+[A-Za-z0-9._~+/=-]{12,}/i,
	/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
];
const MODEL_CREDENTIAL_FILE_PATTERNS = [
	/(?:^|\/)\.codex(?:\/|$)/i,
	/(?:^|\/)(?:codex|chatgpt|openai)[_-]?(?:auth|oauth|tokens?)(?:\.json)?$/i,
	/(?:^|\/)(?:cookies?|session)(?:\.json|\.sqlite|\.db|\.txt)?$/i,
];
const DIRECT_MODEL_HOST_PATTERNS = [
	/api\.anthropic\.com/i,
	/api\.openai\.com/i,
	/auth\.openai\.com/i,
	/chatgpt\.com\/backend-api\/codex/i,
	/generativelanguage\.googleapis\.com/i,
	/openrouter\.ai\/api/i,
	/api\.x\.ai/i,
];
const DIRECT_MODEL_PROVIDER_HOSTS = new Set([
	"api.anthropic.com",
	"api.openai.com",
	"auth.openai.com",
	"chatgpt.com",
	"generativelanguage.googleapis.com",
	"openrouter.ai",
	"api.x.ai",
]);
const RELAY_RAW_CREDENTIAL_POLICY_PATTERN =
	/(?:\brawCredentialPolicy:\s*relay-owned-only\b|"rawCredentialPolicy"\s*:\s*"relay-owned-only")/i;
const RELAY_TOKEN_BINDING_PATTERN =
	/(?:\brelayTokenBinding:\s*run-peer-bound\b|"relayTokenBinding"\s*:\s*"run-peer-bound")/i;
const MCP_RELAY_TOKEN_FILE_REFERENCE_PATTERN = /"auth"\s*:\s*"relay-token-file"/g;
const PEER_BOUND_OPENAI_CODEX_RELAY_TOKEN_PREFIX = "tc-openai-codex-relay-v1";
const NON_REFRESHABLE_RELAY_TOKEN_PLACEHOLDER = "telclaude-relay-token-is-not-refreshable";
const PROFILE_CONFIG_PATH = "config.yaml";
const PROFILE_AUTH_STORE_PATH = "auth.json";
const PROFILE_SECRET_MANIFEST_PATH = "secret-manifest.json";
const RUNTIME_CUSTODY_PROFILE_FILES = [
	PROFILE_CONFIG_PATH,
	PROFILE_AUTH_STORE_PATH,
	PROFILE_SECRET_MANIFEST_PATH,
] as const;
const MAX_PROFILE_FILES = 5_000;
const MAX_PROFILE_FILE_BYTES = 1_000_000;
const MAX_PROFILE_RUNTIME_STATE_FILE_BYTES = 64 * 1024 * 1024;
const RUNTIME_CODEX_PROVIDER_PATTERN = /^\s*provider:\s*openai-codex\s*$/im;
const RUNTIME_CODEX_API_MODE_PATTERN = /^\s*api_mode:\s*codex_responses\s*$/im;
const RUNTIME_CODEX_RUNTIME_PATTERN = /^\s*openai_runtime:\s*auto\s*$/im;

export async function runHermesModelRelayProbe(
	options: HermesModelRelayProbeOptions,
): Promise<HermesModelRelayReport> {
	const generatedAt = (options.now ?? new Date()).toISOString();
	const posture = options.posture ?? DEFAULT_MODEL_RELAY_POSTURE;
	const directModelUrl = options.directModelUrl?.trim() || DEFAULT_MODEL_PROVIDER_PROBE_URL;
	if (!options.allowRun) {
		return {
			schemaVersion: HERMES_MODEL_RELAY_SCHEMA_VERSION,
			probeId: "model.relay",
			posture,
			status: "pending",
			ran: false,
			generatedAt,
			summary: "Hermes model-relay probe requires --allow-run",
			gates: [pending("modelRelay.allowed", "operator must opt in with --allow-run")],
			origin: unknownOrigin("model-relay probe was not run"),
			observation: { directModelUrl: redactSecrets(directModelUrl) },
		};
	}

	const relayUrl = options.relayUrl?.trim();
	const profileDir = options.profileDir?.trim();
	const gates: ModelRelayGate[] = [];
	gates.push(pass("modelRelay.allowed", "operator allowed live model-relay evidence"));
	const modelProvider = buildModelRelayProvider();
	gates.push(modelRelayProviderGate(modelProvider));
	if (posture === "agent-iptables") {
		gates.push(firewallSentinelGate(options.firewallSentinelPath));
	}
	const contained =
		posture === "contained-internal" && options.containerName && !options.fetchImpl
			? prepareContainedModelRelayProbe({
					containerName: options.containerName,
					dockerBin: options.dockerBin,
					profileDir,
					timeoutMs: options.timeoutMs,
				})
			: undefined;
	try {
		const fetchImpl = options.fetchImpl ?? contained?.fetchImpl;
		const relay = await relayReachableGate(relayUrl, options.timeoutMs, fetchImpl);
		gates.push(relay.gate);
		const origin = modelRelayOrigin({
			containerName: options.containerName,
			expectedPeerAddress: options.expectedPeerAddress,
			relayPeerAddress: options.relayPeerAddress,
			observedPeerAddress: relay.observedPeerAddress,
		});
		gates.push(originGate(origin));
		gates.push(await directModelDeniedGate(directModelUrl, options.timeoutMs, fetchImpl));
		const profileResult = scanProfileDir(
			contained?.hostProfileDir ?? profileDir,
			options.expectedPeerAddress,
			options.runtimeCustodyProfileDir,
			contained?.reportedProfileDir,
			contained?.custodyGate,
		);
		gates.push(...profileResult.gates);

		const status = gates.every((gate) => gate.status === "pass") ? "pass" : "fail";
		return {
			schemaVersion: HERMES_MODEL_RELAY_SCHEMA_VERSION,
			probeId: "model.relay",
			posture,
			status,
			ran: true,
			generatedAt,
			summary:
				status === "pass"
					? "Hermes model relay evidence passed"
					: "Hermes model relay evidence failed",
			gates,
			origin,
			modelProvider,
			observation: {
				...(relayUrl ? { relayUrl: redactSecrets(relayUrl) } : {}),
				directModelUrl: redactSecrets(directModelUrl),
				...(profileResult.profileDir
					? { profileDir: redactSecrets(profileResult.profileDir) }
					: {}),
				...(profileResult.scannedFiles.length > 0
					? { scannedProfileFiles: profileResult.scannedFiles.map((file) => redactSecrets(file)) }
					: {}),
			},
		};
	} finally {
		contained?.cleanup();
	}
}

export function writeHermesModelRelayEvidence(
	report: HermesModelRelayReport,
	outPath: string,
	options: HermesArtifactWriteOptions = {},
): HermesModelRelayReport {
	const resolved = resolveHermesArtifactPath(outPath);
	writeHermesJsonArtifact(resolved, report, options);
	return report;
}

function firewallSentinelGate(sentinelPath: string | undefined): ModelRelayGate {
	if (!sentinelPath?.trim()) {
		return fail("firewall.sentinel", "firewall sentinel path is required for model-relay evidence");
	}
	const present = fs.existsSync(sentinelPath);
	return present
		? pass("firewall.sentinel", "firewall sentinel is present")
		: fail("firewall.sentinel", "firewall sentinel is missing; model-relay evidence is unsafe");
}

function buildModelRelayProvider(): ModelRelayProvider {
	const baseUrl =
		process.env[HERMES_CODEX_BASE_URL_ENV]?.trim() || TELCLAUDE_OPENAI_CODEX_RELAY_PROXY_URL;
	const parsed = safeUrl(baseUrl);
	const model = process.env[HERMES_INFERENCE_MODEL_ENV]?.trim() || "";
	return {
		provider: "openai-codex",
		baseUrl,
		baseUrlHost: parsed?.hostname ?? "",
		model,
		modelSource: model ? `env:${HERMES_INFERENCE_MODEL_ENV}` : "missing",
		authLocation: "hermes-auth-store:openai-codex",
		authScope: "relay-openai-codex-subscription-proxy",
		tokenScoping: "peer-bound",
		auxiliaryAuthSource: "manual:telclaude-relay",
		auxiliaryBaseUrl: baseUrl,
		auxiliaryBaseUrlHost: parsed?.hostname ?? "",
		refreshTokenPolicy: "non-refreshable-placeholder",
	};
}

function modelRelayProviderGate(modelProvider: ModelRelayProvider): ModelRelayGate {
	const failures: string[] = [];
	if (!modelProvider.model.trim()) failures.push("model is missing");
	if (modelProvider.modelSource !== `env:${HERMES_INFERENCE_MODEL_ENV}`) {
		failures.push(`modelSource is ${modelProvider.modelSource}`);
	}
	if (!isRelayOpenAiCodexProxyUrl(modelProvider.baseUrl)) {
		failures.push("baseUrl is not the Telclaude relay OpenAI Codex proxy");
	}
	if (modelProvider.baseUrlHost !== "telclaude") {
		failures.push(`baseUrlHost is ${modelProvider.baseUrlHost}`);
	}
	if (modelProvider.authLocation !== "hermes-auth-store:openai-codex") {
		failures.push(`authLocation is ${modelProvider.authLocation}`);
	}
	if (modelProvider.authScope !== "relay-openai-codex-subscription-proxy") {
		failures.push(`authScope is ${modelProvider.authScope}`);
	}
	if (modelProvider.tokenScoping !== "peer-bound") {
		failures.push(`tokenScoping is ${modelProvider.tokenScoping}`);
	}
	if (modelProvider.auxiliaryAuthSource !== "manual:telclaude-relay") {
		failures.push(`auxiliaryAuthSource is ${modelProvider.auxiliaryAuthSource}`);
	}
	if (!isRelayOpenAiCodexProxyUrl(modelProvider.auxiliaryBaseUrl)) {
		failures.push("auxiliaryBaseUrl is not the Telclaude relay OpenAI Codex proxy");
	}
	if (modelProvider.auxiliaryBaseUrlHost !== "telclaude") {
		failures.push(`auxiliaryBaseUrlHost is ${modelProvider.auxiliaryBaseUrlHost}`);
	}
	if (modelProvider.refreshTokenPolicy !== "non-refreshable-placeholder") {
		failures.push(`refreshTokenPolicy is ${modelProvider.refreshTokenPolicy}`);
	}
	return failures.length === 0
		? pass(
				"modelRelay.modelProvider",
				"model provider config uses peer-bound relay-owned OpenAI Codex credential custody",
			)
		: fail("modelRelay.modelProvider", failures.join("; "));
}

async function relayReachableGate(
	relayUrl: string | undefined,
	timeoutMs: number | undefined,
	fetchImpl: FetchLike | undefined,
): Promise<{ gate: ModelRelayGate; observedPeerAddress?: string }> {
	if (!relayUrl) {
		return { gate: fail("relay.reachable", "model relay URL is required") };
	}
	if (isDirectModelProviderUrl(relayUrl)) {
		return {
			gate: fail("relay.reachable", "model relay URL points at a direct model-provider host"),
		};
	}
	const attempt = await attemptHttp(relayUrl, timeoutMs, fetchImpl);
	if (attempt.ok) {
		if (!isSuccessfulHttpStatus(attempt.httpStatus)) {
			return {
				gate: fail(
					"relay.reachable",
					`model relay endpoint returned HTTP status ${String(attempt.httpStatus)}`,
				),
				...(attempt.observedPeerAddress
					? { observedPeerAddress: attempt.observedPeerAddress }
					: {}),
			};
		}
		return {
			gate: pass(
				"relay.reachable",
				`model relay endpoint reached with HTTP status ${String(attempt.httpStatus)}`,
			),
			...(attempt.observedPeerAddress ? { observedPeerAddress: attempt.observedPeerAddress } : {}),
		};
	}
	return {
		gate: fail("relay.reachable", `model relay endpoint was not reachable: ${attempt.detail}`),
	};
}

async function directModelDeniedGate(
	directModelUrl: string,
	timeoutMs: number | undefined,
	fetchImpl: FetchLike | undefined,
): Promise<ModelRelayGate> {
	if (!isDirectModelProviderUrl(directModelUrl)) {
		return fail("directModel.target", "direct model URL must point at a recognized provider host");
	}
	const attempt = await attemptHttp(directModelUrl, timeoutMs, fetchImpl);
	if (!attempt.ok && attempt.denied) {
		return pass("directModel.denied", `direct model-provider egress denied: ${attempt.detail}`);
	}
	if (!attempt.ok) {
		return fail(
			"directModel.denied",
			`direct model-provider probe failed without a positive denial: ${attempt.detail}`,
		);
	}
	return fail(
		"directModel.denied",
		`direct model-provider egress reached HTTP status ${String(attempt.httpStatus)}`,
	);
}

function prepareContainedModelRelayProbe(options: {
	readonly containerName: string;
	readonly dockerBin?: string;
	readonly profileDir?: string;
	readonly timeoutMs?: number;
}): {
	readonly fetchImpl: FetchLike;
	readonly hostProfileDir?: string;
	readonly reportedProfileDir?: string;
	readonly custodyGate?: ModelRelayGate;
	readonly cleanup: () => void;
} {
	const dockerBin = options.dockerBin?.trim() || process.env.DOCKER_BIN?.trim() || "docker";
	const reportedProfileDir = options.profileDir?.trim();
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-model-relay-profile-"));
	const removeTempDir = () => removeReadOnlyTreeSync(tempDir);
	let hostProfileDir: string | undefined;
	let custodyGate: ModelRelayGate | undefined;
	if (reportedProfileDir) {
		hostProfileDir = path.join(tempDir, "profile");
		fs.mkdirSync(hostProfileDir, { recursive: true });
		custodyGate = containedRuntimeProfileCustodyGate(
			dockerBin,
			options.containerName,
			reportedProfileDir,
			options.timeoutMs,
		);
		const archive = spawnSync(
			dockerBin,
			["exec", options.containerName, "tar", "-C", reportedProfileDir, "-cf", "-", "."],
			{
				encoding: "buffer",
				env: { PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin" },
				maxBuffer: 64 * 1024 * 1024,
				timeout: options.timeoutMs,
			},
		);
		if (archive.status !== 0) {
			removeTempDir();
			throw new Error(
				`failed to archive contained Hermes profile: ${redactSecrets(
					spawnFailureDetail(archive.stderr, archive.error),
				)}`,
			);
		}
		const extract = spawnSync("tar", ["-xf", "-", "-C", hostProfileDir], {
			input: archive.stdout,
			encoding: "buffer",
			env: { PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin" },
			timeout: options.timeoutMs,
		});
		if (extract.status !== 0) {
			removeTempDir();
			throw new Error(
				`failed to extract contained Hermes profile: ${redactSecrets(
					spawnFailureDetail(extract.stderr, extract.error),
				)}`,
			);
		}
	}
	return {
		fetchImpl: dockerExecFetch(dockerBin, options.containerName, options.timeoutMs),
		...(hostProfileDir ? { hostProfileDir } : {}),
		...(reportedProfileDir ? { reportedProfileDir } : {}),
		...(custodyGate ? { custodyGate } : {}),
		cleanup: removeTempDir,
	};
}

function containedRuntimeProfileCustodyGate(
	dockerBin: string,
	containerName: string,
	profileDir: string,
	timeoutMs: number | undefined,
): ModelRelayGate {
	const script = [
		"import json, os, stat, sys",
		"root = sys.argv[1]",
		"targets = [('.', 'directory'), ('config.yaml', 'file'), ('auth.json', 'file'), ('secret-manifest.json', 'file')]",
		"out = []",
		"for rel, expected in targets:",
		"    path = root if rel == '.' else os.path.join(root, rel)",
		"    try:",
		"        st = os.lstat(path)",
		"        if stat.S_ISDIR(st.st_mode): kind = 'directory'",
		"        elif stat.S_ISREG(st.st_mode): kind = 'file'",
		"        else: kind = 'other'",
		"        out.append({'relativePath': rel, 'expectedKind': expected, 'kind': kind, 'uid': st.st_uid, 'mode': stat.S_IMODE(st.st_mode)})",
		"    except Exception as exc:",
		"        out.append({'relativePath': rel, 'expectedKind': expected, 'error': str(exc)})",
		"print(json.dumps(out, sort_keys=True))",
	].join("\n");
	const result = spawnSync(dockerBin, ["exec", containerName, "python", "-c", script, profileDir], {
		encoding: "utf8",
		env: { PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin" },
		timeout: timeoutMs,
	});
	if (result.status !== 0) {
		return fail(
			"profile.runtimeCustody",
			`contained runtime custody stat failed: ${redactSecrets(
				spawnFailureDetail(result.stderr, result.error),
			)}`,
		);
	}
	try {
		const entries = JSON.parse(result.stdout) as ProfileCustodyEntry[];
		return runtimeProfileCustodyEntriesGate(entries);
	} catch (error) {
		return fail(
			"profile.runtimeCustody",
			`contained runtime custody stat was not parseable: ${
				error instanceof Error ? error.message : String(error)
			}`,
		);
	}
}

function dockerExecFetch(
	dockerBin: string,
	containerName: string,
	timeoutMs: number | undefined,
): FetchLike {
	return async (input) => {
		const url = String(input);
		const script = [
			"import json, sys, urllib.error, urllib.request",
			"url = sys.argv[1]",
			"try:",
			"    request = urllib.request.Request(url, method='GET')",
			"    with urllib.request.urlopen(request, timeout=5) as response:",
			"        print(json.dumps({'ok': True, 'status': response.status, 'observedPeerAddress': response.headers.get('x-telclaude-model-relay-observed-peer-address', '')}))",
			"except urllib.error.HTTPError as exc:",
			"    print(json.dumps({'ok': True, 'status': exc.code, 'observedPeerAddress': exc.headers.get('x-telclaude-model-relay-observed-peer-address', '')}))",
			"except Exception as exc:",
			"    reason = getattr(exc, 'reason', None)",
			"    code = getattr(exc, 'errno', '') or getattr(reason, 'errno', '') or getattr(reason, 'strerror', '') or ''",
			"    print(json.dumps({'ok': False, 'error': type(exc).__name__, 'detail': str(exc), 'code': str(code)}))",
		].join("\n");
		const result = spawnSync(dockerBin, ["exec", containerName, "python", "-c", script, url], {
			encoding: "utf8",
			env: { PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin" },
			timeout: timeoutMs,
		});
		if (result.status !== 0) {
			const error = new TypeError(
				`docker exec fetch failed: ${redactSecrets(spawnFailureDetail(result.stderr, result.error))}`,
			) as Error & { cause?: { code?: string } };
			error.cause = { code: "EHOSTUNREACH" };
			throw error;
		}
		const parsed = JSON.parse(result.stdout) as {
			ok: boolean;
			status?: number;
			observedPeerAddress?: string;
			error?: string;
			detail?: string;
			code?: string;
		};
		if (!parsed.ok) {
			const error = new TypeError(
				redactSecrets(`${parsed.error ?? "Error"}: ${parsed.detail ?? "fetch failed"}`),
			) as Error & { cause?: { code?: string } };
			error.cause = { code: positiveDenialCode(parsed.code) };
			throw error;
		}
		const headers = new Headers();
		if (parsed.observedPeerAddress) {
			headers.set(MODEL_RELAY_OBSERVED_PEER_HEADER, parsed.observedPeerAddress);
		}
		return new Response(null, { status: parsed.status ?? 0, headers });
	};
}

function spawnFailureDetail(stderr: string | Buffer | undefined, error: Error | undefined): string {
	const stderrText = Buffer.isBuffer(stderr) ? stderr.toString("utf8") : (stderr ?? "");
	return stderrText.trim() || error?.message || "unknown error";
}

function positiveDenialCode(value: string | undefined): string {
	const normalized = value?.trim().toUpperCase();
	return normalized && POSITIVE_DENIAL_ERROR_CODES.has(normalized) ? normalized : "ENETUNREACH";
}

function scanProfileDir(
	profileDir: string | undefined,
	expectedPeerAddress: string | undefined,
	runtimeCustodyProfileDir = DEFAULT_MODEL_RELAY_PROFILE_DIR,
	reportedProfileDir = profileDir,
	custodyGateOverride?: ModelRelayGate,
): {
	gates: ModelRelayGate[];
	scannedFiles: string[];
	profileDir?: string;
} {
	if (!profileDir) {
		return {
			gates: [
				fail(
					"profile.relayCredentialReference",
					"profile directory is required to prove relay credential reference",
				),
				fail(
					"profile.noRawModelCredentials",
					"profile directory is required to prove model credential absence",
				),
				fail("profile.runtimeCustody", "profile directory is required to prove runtime custody"),
				fail("profile.noDirectModelHosts", "profile directory is required to prove relay routing"),
				fail("profile.scanComplete", "profile directory is required for complete scan proof"),
			],
			scannedFiles: [],
		};
	}
	const resolved = path.resolve(profileDir);
	const reportedRoot = toPortablePath(reportedProfileDir?.trim() || resolved);
	if (!fs.existsSync(resolved) || !fs.statSync(resolved).isDirectory()) {
		return {
			gates: [
				fail(
					"profile.relayCredentialReference",
					`profile directory missing: ${redactSecrets(resolved)}`,
				),
				fail(
					"profile.noRawModelCredentials",
					`profile directory missing: ${redactSecrets(resolved)}`,
				),
				fail("profile.runtimeCustody", `profile directory missing: ${redactSecrets(resolved)}`),
				fail("profile.noDirectModelHosts", `profile directory missing: ${redactSecrets(resolved)}`),
				fail("profile.scanComplete", `profile directory missing: ${redactSecrets(resolved)}`),
			],
			scannedFiles: [],
			profileDir: reportedRoot,
		};
	}

	const custodyGate =
		custodyGateOverride ??
		runtimeProfileCustodyGate(resolved, runtimeCustodyProfileDir, reportedRoot);
	const findings: string[] = [];
	const directHostFindings: string[] = [];
	const scannedFiles: string[] = [];
	const profileContents = new Map<string, string>();
	const inventory = listProfileFiles(resolved);
	for (const filePath of inventory.scannedFiles) {
		scannedFiles.push(filePath);
		const relativePath = path.relative(resolved, filePath);
		if (
			MODEL_CREDENTIAL_FILE_PATTERNS.some((pattern) => pattern.test(toPortablePath(relativePath)))
		) {
			findings.push(relativePath);
			continue;
		}
		const portableRelativePath = toPortablePath(relativePath);
		const content = fs.readFileSync(filePath, "utf8");
		profileContents.set(portableRelativePath, content);
		const credentialScanContent = normalizeAllowedCredentialReferences(
			relativePath,
			content,
			expectedPeerAddress,
		);
		if (credentialScanContent === undefined) {
			findings.push(relativePath);
			for (const pattern of DIRECT_MODEL_HOST_PATTERNS) {
				if (pattern.test(content)) {
					directHostFindings.push(relativePath);
					break;
				}
			}
			continue;
		}
		if (containsRawModelCredential(credentialScanContent)) {
			findings.push(relativePath);
		}
		if (shouldScanForDirectModelHosts(portableRelativePath)) {
			for (const pattern of DIRECT_MODEL_HOST_PATTERNS) {
				if (pattern.test(content)) {
					directHostFindings.push(relativePath);
					break;
				}
			}
		}
	}

	return {
		gates: [
			relayCredentialReferenceGate(profileContents, expectedPeerAddress),
			custodyGate,
			findings.length === 0
				? pass(
						"profile.noRawModelCredentials",
						"scanned profile files contain no raw model credentials",
					)
				: fail(
						"profile.noRawModelCredentials",
						`raw model credential-like config in ${redactSecrets(unique(findings).join(", "))}`,
					),
			directHostFindings.length === 0
				? pass("profile.noDirectModelHosts", "scanned profile files contain no direct model hosts")
				: fail(
						"profile.noDirectModelHosts",
						`direct model-provider host in ${redactSecrets(unique(directHostFindings).join(", "))}`,
					),
			inventory.skippedFiles.length === 0 && inventory.scannedFiles.length > 0
				? pass("profile.scanComplete", "profile scan covered all profile files")
				: fail(
						"profile.scanComplete",
						inventory.scannedFiles.length === 0
							? "profile scan found no scannable files"
							: `profile scan skipped files: ${redactSecrets(
									unique(inventory.skippedFiles).slice(0, 20).join(", "),
								)}`,
					),
		],
		scannedFiles: scannedFiles.map((filePath) =>
			toPortablePath(path.join(reportedRoot, path.relative(resolved, filePath))),
		),
		profileDir: reportedRoot,
	};
}

function normalizeAllowedCredentialReferences(
	relativePath: string,
	content: string,
	expectedPeerAddress: string | undefined,
): string | undefined {
	const portablePath = toPortablePath(relativePath);
	if (portablePath === PROFILE_AUTH_STORE_PATH) {
		const authStore = validateRelayAuthStore(content, expectedPeerAddress);
		return authStore.ok ? authStore.normalizedContent : undefined;
	}
	if (portablePath !== "mcp.json") return content;
	return content.replace(
		MCP_RELAY_TOKEN_FILE_REFERENCE_PATTERN,
		'"auth":"<relay-token-file-reference>"',
	);
}

function shouldScanForDirectModelHosts(relativePath: string): boolean {
	const portablePath = toPortablePath(relativePath);
	if (portablePath.startsWith("skills/")) return false;
	return (
		portablePath === PROFILE_CONFIG_PATH ||
		portablePath === PROFILE_AUTH_STORE_PATH ||
		portablePath === "mcp.json" ||
		/(?:^|\/)\.env(?:$|\.)/i.test(portablePath) ||
		/(?:^|\/)[^/]*(?:config|settings|profile|auth|provider|model|relay)[^/]*\.(?:json|ya?ml|toml|ini|env)$/i.test(
			portablePath,
		)
	);
}

function containsRawModelCredential(content: string): boolean {
	for (const line of content.replace(/\r\n?/g, "\n").split("\n")) {
		if (lineContainsRawModelCredential(line)) return true;
	}
	return false;
}

function lineContainsRawModelCredential(line: string): boolean {
	for (const pattern of MODEL_CREDENTIAL_PATTERNS) {
		const match = pattern.exec(line);
		if (match && !isPlaceholderCredentialMatch(match[0])) return true;
	}
	return false;
}

function isPlaceholderCredentialMatch(value: string): boolean {
	const normalized = value.toLowerCase();
	return (
		normalized.includes("...") ||
		/\b(?:empty|null|placeholder|example|dummy|fake|redacted)\b/.test(normalized) ||
		/(?:your|some)[_-]?(?:api[_-]?key|token|secret)/i.test(value) ||
		/[x_=-]{12,}/i.test(value)
	);
}

function relayCredentialReferenceGate(
	profileContents: ReadonlyMap<string, string>,
	expectedPeerAddress: string | undefined,
): ModelRelayGate {
	const config = profileContents.get(PROFILE_CONFIG_PATH) ?? "";
	const authStore = profileContents.get(PROFILE_AUTH_STORE_PATH) ?? "";
	const secretManifest = profileContents.get(PROFILE_SECRET_MANIFEST_PATH) ?? "";
	const missing: string[] = [];
	if (!profileContents.has(PROFILE_CONFIG_PATH)) missing.push(PROFILE_CONFIG_PATH);
	if (!profileContents.has(PROFILE_AUTH_STORE_PATH)) missing.push(PROFILE_AUTH_STORE_PATH);
	if (!profileContents.has(PROFILE_SECRET_MANIFEST_PATH))
		missing.push(PROFILE_SECRET_MANIFEST_PATH);
	if (!RUNTIME_CODEX_PROVIDER_PATTERN.test(config))
		missing.push("config.yaml openai-codex provider");
	if (!RUNTIME_CODEX_API_MODE_PATTERN.test(config))
		missing.push("config.yaml codex_responses api_mode");
	if (!RUNTIME_CODEX_RUNTIME_PATTERN.test(config)) missing.push("config.yaml auto OpenAI runtime");
	const authValidation = authStore
		? validateRelayAuthStore(authStore, expectedPeerAddress)
		: undefined;
	if (authValidation && !authValidation.ok) {
		missing.push(...authValidation.missing.map((item) => `auth.json ${item}`));
	}
	if (!RELAY_RAW_CREDENTIAL_POLICY_PATTERN.test(secretManifest)) {
		missing.push("secret-manifest.json relay-owned-only rawCredentialPolicy");
	}
	if (!RELAY_TOKEN_BINDING_PATTERN.test(secretManifest)) {
		missing.push("secret-manifest.json run-peer-bound relayTokenBinding");
	}
	return missing.length === 0
		? pass(
				"profile.relayCredentialReference",
				"runtime Hermes profile references peer-bound relay OpenAI Codex credential custody",
			)
		: fail(
				"profile.relayCredentialReference",
				`runtime Hermes profile is missing ${missing.join(", ")}`,
			);
}

type RelayAuthStoreValidation =
	| { ok: true; normalizedContent: string }
	| { ok: false; missing: string[] };

function validateRelayAuthStore(
	content: string,
	expectedPeerAddress: string | undefined,
): RelayAuthStoreValidation {
	let parsed: unknown;
	try {
		parsed = JSON.parse(content);
	} catch {
		return { ok: false, missing: ["parseable JSON"] };
	}
	if (!isRecord(parsed)) return { ok: false, missing: ["object root"] };

	const providers = getRecord(parsed, "providers");
	const credentialPoolRoot = getRecord(parsed, "credential_pool");
	const provider = getRecord(parsed, "providers", "openai-codex");
	const suppressedSources = getArray(parsed, "suppressed_sources", "openai-codex");
	const credentialPool = getArray(parsed, "credential_pool", "openai-codex");
	const credentialEntry = credentialPool.find((entry) => isRecord(entry)) as
		| Record<string, unknown>
		| undefined;
	const poolAccessToken = getString(credentialEntry, "access_token");
	const providerTokens = getRecord(provider, "tokens");
	const providerAccessToken = getString(providerTokens, "access_token");
	const providerRefreshToken = getString(providerTokens, "refresh_token");
	const providerHasBootstrapShape =
		provider !== undefined && hasOnlyKeys(provider, ["auth_mode", "last_refresh"]);
	const providerHasHermesNormalizedShape =
		provider !== undefined &&
		providerTokens !== undefined &&
		hasOnlyKeys(provider, ["auth_mode", "last_refresh", "tokens"]) &&
		hasOnlyKeys(providerTokens, ["access_token", "refresh_token"]) &&
		providerAccessToken === poolAccessToken &&
		providerRefreshToken === NON_REFRESHABLE_RELAY_TOKEN_PLACEHOLDER;
	const missing: string[] = [];
	if (parsed.version !== 1) {
		missing.push("version 1");
	}
	if (getString(parsed, "active_provider") !== "openai-codex") {
		missing.push("active_provider openai-codex");
	}
	const requiredRootKeys = providerHasHermesNormalizedShape
		? ["version", "active_provider", "providers", "credential_pool"]
		: ["version", "active_provider", "providers", "credential_pool", "suppressed_sources"];
	if (
		!hasRequiredKeys(parsed, requiredRootKeys) ||
		!hasOnlyAllowedKeys(parsed, [
			"version",
			"active_provider",
			"providers",
			"credential_pool",
			"suppressed_sources",
			"updated_at",
		])
	) {
		missing.push(
			providerHasHermesNormalizedShape
				? "root fields exactly version/active_provider/providers/credential_pool plus optional suppressed_sources/updated_at"
				: "root fields exactly version/active_provider/providers/credential_pool/suppressed_sources plus optional updated_at",
		);
	}
	if (
		getRecord(parsed, "suppressed_sources") !== undefined &&
		!suppressedSources.includes("device_code")
	) {
		missing.push("suppressed_sources.openai-codex includes device_code");
	}
	if (getRecord(parsed, "suppressed_sources") === undefined && !providerHasHermesNormalizedShape) {
		missing.push("suppressed_sources.openai-codex includes device_code");
	}
	if (!providers || !hasOnlyKeys(providers, ["openai-codex"])) {
		missing.push("providers only openai-codex");
	}
	if (getString(provider, "auth_mode") !== "telclaude-relay") {
		missing.push("providers.openai-codex auth_mode telclaude-relay");
	}
	if (provider && !providerHasBootstrapShape && !providerHasHermesNormalizedShape) {
		missing.push(
			"providers.openai-codex exact relay metadata fields without tokens or Hermes-normalized peer-bound token mirror",
		);
	}
	if (!credentialPoolRoot || !hasOnlyKeys(credentialPoolRoot, ["openai-codex"])) {
		missing.push("credential_pool only openai-codex");
	}
	if (credentialPool.length !== 1) {
		missing.push("credential_pool.openai-codex exactly one entry");
	}
	if (!credentialEntry) {
		missing.push("credential_pool.openai-codex entry");
	} else {
		const requiredCredentialEntryKeys = [
			"id",
			"label",
			"auth_type",
			"priority",
			"source",
			"access_token",
			"base_url",
		];
		const allowedCredentialEntryKeys = [
			...requiredCredentialEntryKeys,
			"last_status",
			"last_status_at",
			"last_error_code",
			"last_error_reason",
			"last_error_message",
			"last_error_reset_at",
			"request_count",
		];
		if (
			!hasRequiredKeys(credentialEntry, requiredCredentialEntryKeys) ||
			!hasOnlyAllowedKeys(credentialEntry, allowedCredentialEntryKeys)
		) {
			missing.push("credential_pool.openai-codex entry exact relay fields");
		}
		if (getString(credentialEntry, "id") !== "telclaude-relay") {
			missing.push("credential_pool.openai-codex id telclaude-relay");
		}
		if (getString(credentialEntry, "source") !== "manual:telclaude-relay") {
			missing.push("credential_pool.openai-codex source manual:telclaude-relay");
		}
		if (getString(credentialEntry, "auth_type") !== "api_key") {
			missing.push("credential_pool.openai-codex auth_type api_key");
		}
		if (getString(credentialEntry, "base_url") !== TELCLAUDE_OPENAI_CODEX_RELAY_PROXY_URL) {
			missing.push("credential_pool.openai-codex Telclaude relay base_url");
		}
		const poolAccessTokenFailure = peerBoundOpenAiCodexRelayTokenFailure(
			poolAccessToken,
			expectedPeerAddress,
		);
		if (poolAccessTokenFailure) {
			missing.push(
				`credential_pool.openai-codex peer-bound access_token (${poolAccessTokenFailure})`,
			);
		}
	}
	if (missing.length > 0) return { ok: false, missing };

	const normalizedAccessToken = poolAccessToken as string;
	return {
		ok: true,
		normalizedContent: content
			.replaceAll(normalizedAccessToken, "<peer-bound-openai-codex-relay-token>")
			.replaceAll(
				NON_REFRESHABLE_RELAY_TOKEN_PLACEHOLDER,
				"<non-refreshable-relay-token-placeholder>",
			),
	};
}

function peerBoundOpenAiCodexRelayTokenFailure(
	value: string | undefined,
	expectedPeerAddress: string | undefined,
): string | null {
	if (!value) return "missing";
	const normalizedExpectedPeerAddress = normalizePeerAddress(expectedPeerAddress);
	if (!normalizedExpectedPeerAddress) return "expected peer address is missing";
	const [prefix, encodedPayload, signature, extra] = value.split(".");
	if (
		prefix !== PEER_BOUND_OPENAI_CODEX_RELAY_TOKEN_PREFIX ||
		!encodedPayload ||
		!signature ||
		extra !== undefined ||
		!/^[A-Za-z0-9_-]+$/.test(encodedPayload) ||
		!/^[A-Za-z0-9_-]{32,}$/.test(signature)
	) {
		return "token is not peer-bound";
	}
	const verifierSecret = process.env[OPENAI_CODEX_PROXY_TOKEN_ENV]?.trim();
	if (!verifierSecret) return `verifier secret ${OPENAI_CODEX_PROXY_TOKEN_ENV} is missing`;
	const verification = verifyOpenAiCodexPeerBoundProxyToken(value, {
		secret: verifierSecret,
		peerAddress: expectedPeerAddress,
	});
	if (!verification.ok) return verification.reason;
	try {
		const payload = JSON.parse(
			Buffer.from(encodedPayload, "base64url").toString("utf8"),
		) as unknown;
		if (!isRecord(payload)) return "payload is invalid";
		const tokenScope = getString(payload, "tokenScope");
		const expiresAt = payload.expiresAt;
		return payload.version === 1 &&
			(tokenScope === "run" || tokenScope === "server") &&
			getString(payload, "runId")?.trim() &&
			normalizePeerAddress(getString(payload, "peerAddress")) === normalizedExpectedPeerAddress &&
			typeof payload.issuedAt === "number" &&
			Number.isFinite(payload.issuedAt) &&
			((typeof expiresAt === "number" && Number.isFinite(expiresAt)) ||
				(tokenScope === "server" && expiresAt === null)) &&
			getString(payload, "nonce")?.trim()
			? null
			: "payload is invalid";
	} catch {
		return "payload is not parseable";
	}
}

function runtimeProfileCustodyGate(
	profileDir: string,
	runtimeCustodyProfileDir = DEFAULT_MODEL_RELAY_PROFILE_DIR,
	reportedProfileDir = profileDir,
): ModelRelayGate {
	if (normalizeProfilePath(reportedProfileDir) !== normalizeProfilePath(runtimeCustodyProfileDir)) {
		return pass(
			"profile.runtimeCustody",
			"non-default test profile does not claim runtime custody",
		);
	}
	const entries: ProfileCustodyEntry[] = [];
	const appendEntry = (relativePath: string, filePath: string): void => {
		try {
			const stat = fs.lstatSync(filePath);
			entries.push({
				relativePath,
				kind: stat.isDirectory() ? "directory" : stat.isFile() ? "file" : "other",
				uid: stat.uid,
				mode: stat.mode & 0o7777,
			});
		} catch (error) {
			entries.push({
				relativePath,
				error: error instanceof Error ? error.message : String(error),
			});
		}
	};
	appendEntry(".", profileDir);
	for (const relativePath of RUNTIME_CUSTODY_PROFILE_FILES) {
		appendEntry(relativePath, path.join(profileDir, relativePath));
	}
	return runtimeProfileCustodyEntriesGate(entries);
}

function runtimeProfileCustodyEntriesGate(entries: readonly ProfileCustodyEntry[]): ModelRelayGate {
	const commonFailures: string[] = [];
	const byPath = new Map(entries.map((entry) => [entry.relativePath, entry]));
	const profileStat = byPath.get(".");
	if (!profileStat) {
		commonFailures.push("profile directory stat missing");
	} else if (profileStat.error) {
		commonFailures.push(`profile directory stat failed: ${profileStat.error}`);
	} else {
		if (profileStat.kind !== "directory") {
			commonFailures.push("profile directory is not a directory");
		}
		const mode = profileStat.mode ?? 0;
		if ((mode & 0o002) !== 0) {
			commonFailures.push(`profile directory is world-writable ${formatMode(mode)}`);
		}
		if ((mode & 0o020) !== 0 && (mode & 0o1000) === 0) {
			commonFailures.push(
				`profile directory is group-writable without sticky bit ${formatMode(mode)}`,
			);
		}
	}
	for (const relativePath of RUNTIME_CUSTODY_PROFILE_FILES) {
		const stat = byPath.get(relativePath);
		if (!stat) {
			commonFailures.push(`${relativePath} stat missing`);
			continue;
		}
		if (stat.error) {
			commonFailures.push(`${relativePath} stat failed: ${stat.error}`);
			continue;
		}
		if (stat.kind !== "file") {
			commonFailures.push(`${relativePath} is not a regular file`);
		}
	}
	const rootFailures = rootOwnedProfileCustodyFailures(byPath);
	const containedFailures = containedRuntimeProfileCustodyFailures(byPath);
	if (commonFailures.length === 0 && rootFailures.length === 0) {
		return pass(
			"profile.runtimeCustody",
			"runtime credential custody files are root-owned and read-only",
		);
	}
	if (commonFailures.length === 0 && containedFailures.length === 0) {
		return pass(
			"profile.runtimeCustody",
			"runtime credential custody files are owned by the contained runtime uid and private",
		);
	}
	return fail(
		"profile.runtimeCustody",
		unique([...commonFailures, ...rootFailures, ...containedFailures]).join("; "),
	);
}

function rootOwnedProfileCustodyFailures(
	byPath: ReadonlyMap<string, ProfileCustodyEntry>,
): string[] {
	const failures: string[] = [];
	const profileStat = byPath.get(".");
	if (profileStat && !profileStat.error) {
		if (profileStat.uid !== 0) {
			failures.push(`profile directory is uid ${String(profileStat.uid)}, expected root`);
		}
	}
	for (const relativePath of RUNTIME_CUSTODY_PROFILE_FILES) {
		const stat = byPath.get(relativePath);
		if (!stat || stat.error) continue;
		if (stat.uid !== 0) {
			failures.push(`${relativePath} is uid ${String(stat.uid)}, expected root`);
		}
		const mode = stat.mode ?? 0;
		if ((mode & 0o222) !== 0) {
			failures.push(`${relativePath} has writable mode ${formatMode(mode)}`);
		}
	}
	return failures;
}

function containedRuntimeProfileCustodyFailures(
	byPath: ReadonlyMap<string, ProfileCustodyEntry>,
): string[] {
	const failures: string[] = [];
	const containedUid = 10_000;
	const profileStat = byPath.get(".");
	if (profileStat && !profileStat.error) {
		if (profileStat.uid !== containedUid) {
			failures.push(
				`profile directory is uid ${String(profileStat.uid)}, expected contained uid ${String(containedUid)}`,
			);
		}
		const mode = profileStat.mode ?? 0;
		if ((mode & 0o077) !== 0) {
			failures.push(`profile directory is not private ${formatMode(mode)}`);
		}
	}
	for (const relativePath of RUNTIME_CUSTODY_PROFILE_FILES) {
		const stat = byPath.get(relativePath);
		if (!stat || stat.error) continue;
		if (stat.uid !== containedUid) {
			failures.push(
				`${relativePath} is uid ${String(stat.uid)}, expected contained uid ${String(containedUid)}`,
			);
		}
		const mode = stat.mode ?? 0;
		if ((mode & 0o077) !== 0) {
			failures.push(`${relativePath} is not private ${formatMode(mode)}`);
		}
	}
	return failures;
}

function formatMode(mode: number): string {
	return `0${(mode & 0o777).toString(8)}`;
}

// The extracted profile copy preserves read-only modes (the curated skills
// tree ships 0550 dirs / 0440 files), which blocks unlink inside those
// directories. Re-own our temp copy before removal; rmSync reports any
// remaining failure.
export function removeReadOnlyTreeSync(root: string): void {
	try {
		makeTreeOwnerWritable(root);
	} catch {
		// best effort — fs.rmSync below surfaces the real failure
	}
	fs.rmSync(root, { recursive: true, force: true });
}

function makeTreeOwnerWritable(entryPath: string): void {
	const stat = fs.lstatSync(entryPath);
	if (stat.isSymbolicLink()) return;
	if (stat.isDirectory()) {
		fs.chmodSync(entryPath, stat.mode | 0o700);
		for (const name of fs.readdirSync(entryPath)) {
			makeTreeOwnerWritable(path.join(entryPath, name));
		}
		return;
	}
	fs.chmodSync(entryPath, stat.mode | 0o600);
}

function hasOnlyKeys(record: Record<string, unknown>, expectedKeys: readonly string[]): boolean {
	const actual = Object.keys(record).sort();
	const expected = [...expectedKeys].sort();
	return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function hasRequiredKeys(
	record: Record<string, unknown>,
	requiredKeys: readonly string[],
): boolean {
	return requiredKeys.every((key) => Object.hasOwn(record, key));
}

function hasOnlyAllowedKeys(
	record: Record<string, unknown>,
	allowedKeys: readonly string[],
): boolean {
	const allowed = new Set(allowedKeys);
	return Object.keys(record).every((key) => allowed.has(key));
}

function normalizeProfilePath(value: string): string {
	return value.replace(/\\/g, "/").replace(/\/+$/, "");
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function getRecord(
	value: unknown,
	...keys: readonly string[]
): Record<string, unknown> | undefined {
	let current: unknown = value;
	for (const key of keys) {
		if (!isRecord(current)) return undefined;
		current = current[key];
	}
	return isRecord(current) ? current : undefined;
}

function getArray(value: unknown, ...keys: readonly string[]): unknown[] {
	let current: unknown = value;
	for (const key of keys) {
		if (!isRecord(current)) return [];
		current = current[key];
	}
	return Array.isArray(current) ? current : [];
}

function getString(value: unknown, key: string): string | undefined {
	return isRecord(value) && typeof value[key] === "string" ? value[key] : undefined;
}

function listProfileFiles(root: string): { scannedFiles: string[]; skippedFiles: string[] } {
	const scannedFiles: string[] = [];
	const skippedFiles: string[] = [];
	const visit = (dir: string) => {
		if (scannedFiles.length >= MAX_PROFILE_FILES) {
			skippedFiles.push(path.relative(root, dir) || ".");
			return;
		}
		for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
			if (scannedFiles.length >= MAX_PROFILE_FILES) {
				skippedFiles.push(path.relative(root, path.join(dir, entry.name)));
				continue;
			}
			const fullPath = path.join(dir, entry.name);
			if (entry.isDirectory()) {
				visit(fullPath);
				continue;
			}
			if (!entry.isFile()) {
				skippedFiles.push(path.relative(root, fullPath));
				continue;
			}
			const stat = fs.statSync(fullPath);
			if (stat.size > MAX_PROFILE_FILE_BYTES) {
				if (
					isBoundedRuntimeStateProfileFile(path.relative(root, fullPath)) &&
					stat.size <= MAX_PROFILE_RUNTIME_STATE_FILE_BYTES
				) {
					scannedFiles.push(fullPath);
					continue;
				}
				skippedFiles.push(path.relative(root, fullPath));
				continue;
			}
			scannedFiles.push(fullPath);
		}
	};
	visit(root);
	return {
		scannedFiles: scannedFiles.sort((left, right) => left.localeCompare(right)),
		skippedFiles: skippedFiles.sort((left, right) => left.localeCompare(right)),
	};
}

function isBoundedRuntimeStateProfileFile(relativePath: string): boolean {
	const portablePath = toPortablePath(relativePath);
	return (
		/(?:^|\/)[^/]+\.db(?:-(?:wal|shm))?$/i.test(portablePath) ||
		/(?:^|\/)logs\/[^/]+\.log$/i.test(portablePath)
	);
}

async function attemptHttp(
	url: string,
	timeoutMs: number | undefined,
	fetchImpl: FetchLike | undefined,
): Promise<
	| { ok: true; httpStatus: number; observedPeerAddress?: string }
	| { ok: false; denied: boolean; detail: string }
> {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs ?? DEFAULT_TIMEOUT_MS);
	try {
		const response = await (fetchImpl ?? fetch)(url, { method: "GET", signal: controller.signal });
		const observedPeerAddress = response.headers.get(MODEL_RELAY_OBSERVED_PEER_HEADER) ?? undefined;
		return {
			ok: true,
			httpStatus: response.status,
			...(observedPeerAddress ? { observedPeerAddress } : {}),
		};
	} catch (error) {
		const detail = cleanError(error);
		const denied = isPositiveDenial(error);
		return { ok: false, denied, detail };
	} finally {
		clearTimeout(timer);
	}
}

function modelRelayOrigin(input: {
	containerName?: string;
	expectedPeerAddress?: string;
	relayPeerAddress?: string;
	observedPeerAddress?: string;
}): ModelRelayOrigin {
	const containerName = clean(input.containerName);
	const observedPeerAddress = normalizePeerAddress(input.observedPeerAddress);
	const expectedPeerAddress = normalizePeerAddress(input.expectedPeerAddress);
	const relayPeerAddress = normalizePeerAddress(input.relayPeerAddress);
	if (!observedPeerAddress) {
		return unknownOrigin("model relay response did not include a server-observed peer header");
	}
	const kind =
		relayPeerAddress && observedPeerAddress === relayPeerAddress
			? "relay-self-smoke"
			: "contained-peer";
	return {
		kind,
		...(containerName ? { containerName } : {}),
		observedPeerAddress,
		observedPeerSource: "server-peer-echo",
		...(expectedPeerAddress ? { expectedPeerAddress } : {}),
		...(expectedPeerAddress ? { expectedPeerSource: "configured-contained-ip" as const } : {}),
		detail:
			kind === "contained-peer"
				? "model relay peer origin was observed by the relay endpoint"
				: "model relay peer origin matched the relay namespace and is smoke-only",
	};
}

function unknownOrigin(detail: string): ModelRelayOrigin {
	return { kind: "unknown", detail };
}

function originGate(origin: ModelRelayOrigin): ModelRelayGate {
	if (origin.kind === "relay-self-smoke") {
		return fail(
			"modelRelay.origin",
			"model-relay evidence originated from relay-self smoke and is not production containment evidence",
		);
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
		origin.containerName === DEFAULT_MODEL_RELAY_CONTAINED_CONTAINER_NAME &&
		matchesPeer
	) {
		return pass(
			"modelRelay.origin",
			"model-relay evidence originated from tc-hermes-contained at the expected peer address",
		);
	}
	return fail(
		"modelRelay.origin",
		"model-relay evidence must include a server-observed contained peer IP from tc-hermes-contained matching the configured contained IP",
	);
}

function isDirectModelProviderUrl(value: string): boolean {
	try {
		return DIRECT_MODEL_PROVIDER_HOSTS.has(new URL(value).hostname.toLowerCase());
	} catch {
		return false;
	}
}

function isRelayOpenAiCodexProxyUrl(value: string): boolean {
	try {
		const parsed = new URL(value);
		return (
			parsed.protocol === "http:" &&
			parsed.hostname === "telclaude" &&
			parsed.port === "8790" &&
			parsed.pathname.replace(/\/+$/, "") === "/v1/openai-codex-proxy" &&
			parsed.search === "" &&
			parsed.hash === "" &&
			value.replace(/\/+$/, "") === TELCLAUDE_OPENAI_CODEX_RELAY_PROXY_URL
		);
	} catch {
		return false;
	}
}

function safeUrl(value: string): URL | undefined {
	try {
		return new URL(value);
	} catch {
		return undefined;
	}
}

function isSuccessfulHttpStatus(status: number): boolean {
	return status >= 200 && status < 300;
}

function isPositiveDenial(error: unknown): boolean {
	const err = error as { code?: unknown; cause?: { code?: unknown }; name?: unknown };
	const code = String(err.code ?? err.cause?.code ?? "");
	if (POSITIVE_DENIAL_ERROR_CODES.has(code)) return true;
	return false;
}

function normalizePeerAddress(value: string | undefined): string | undefined {
	const cleaned = clean(value);
	if (!cleaned) return undefined;
	return cleaned.startsWith("::ffff:") ? cleaned.slice("::ffff:".length) : cleaned;
}

function clean(value: string | undefined): string | undefined {
	const trimmed = value?.trim();
	return trimmed ? trimmed : undefined;
}

function cleanError(error: unknown): string {
	const err = error as {
		code?: unknown;
		cause?: { code?: unknown };
		name?: unknown;
		message?: unknown;
	};
	const code = String(err.code ?? err.cause?.code ?? "");
	const name = String(err.name ?? "Error");
	const message = String(err.message ?? error);
	return redactSecrets([name, code, message].filter(Boolean).join(": "));
}

function pass(name: string, detail: string): ModelRelayGate {
	return { name, status: "pass", detail };
}

function fail(name: string, detail: string): ModelRelayGate {
	return { name, status: "fail", detail };
}

function pending(name: string, detail: string): ModelRelayGate {
	return { name, status: "pending", detail };
}

function unique(values: string[]): string[] {
	return [...new Set(values)];
}

function toPortablePath(value: string): string {
	return value.split(path.sep).join("/");
}
