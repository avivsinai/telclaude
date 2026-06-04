import fs from "node:fs";
import net from "node:net";
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
const NONREFRESHABLE_RELAY_TOKEN_PLACEHOLDER = "telclaude-relay-token-is-not-refreshable";
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
	const relay = await relayReachableGate(relayUrl, options.timeoutMs, options.fetchImpl);
	gates.push(relay.gate);
	const origin = modelRelayOrigin({
		containerName: options.containerName,
		expectedPeerAddress: options.expectedPeerAddress,
		relayPeerAddress: options.relayPeerAddress,
		observedPeerAddress: relay.observedPeerAddress,
	});
	gates.push(originGate(origin));
	gates.push(await directModelDeniedGate(directModelUrl, options.timeoutMs, options.fetchImpl));
	const profileResult = scanProfileDir(
		profileDir,
		options.expectedPeerAddress,
		options.runtimeCustodyProfileDir,
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
			...(profileDir ? { profileDir: redactSecrets(path.resolve(profileDir)) } : {}),
			...(profileResult.scannedFiles.length > 0
				? { scannedProfileFiles: profileResult.scannedFiles.map((file) => redactSecrets(file)) }
				: {}),
		},
	};
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

function scanProfileDir(
	profileDir: string | undefined,
	expectedPeerAddress: string | undefined,
	runtimeCustodyProfileDir = DEFAULT_MODEL_RELAY_PROFILE_DIR,
): {
	gates: ModelRelayGate[];
	scannedFiles: string[];
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
		};
	}

	const custodyGate = runtimeProfileCustodyGate(resolved, runtimeCustodyProfileDir);
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
		const content = fs.readFileSync(filePath, "utf8");
		profileContents.set(toPortablePath(relativePath), content);
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
		for (const pattern of DIRECT_MODEL_HOST_PATTERNS) {
			if (pattern.test(content)) {
				directHostFindings.push(relativePath);
				break;
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
		scannedFiles,
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
	const tokens = getRecord(provider, "tokens");
	const credentialPool = getArray(parsed, "credential_pool", "openai-codex");
	const credentialEntry = credentialPool.find((entry) => isRecord(entry)) as
		| Record<string, unknown>
		| undefined;
	const providerAccessToken = getString(tokens, "access_token");
	const poolAccessToken = getString(credentialEntry, "access_token");
	const missing: string[] = [];
	if (parsed.version !== 1) {
		missing.push("version 1");
	}
	if (getString(parsed, "active_provider") !== "openai-codex") {
		missing.push("active_provider openai-codex");
	}
	if (!hasOnlyKeys(parsed, ["version", "active_provider", "providers", "credential_pool"])) {
		missing.push("root fields exactly version/active_provider/providers/credential_pool");
	}
	if (!providers || !hasOnlyKeys(providers, ["openai-codex"])) {
		missing.push("providers only openai-codex");
	}
	if (getString(provider, "auth_mode") !== "telclaude-relay") {
		missing.push("providers.openai-codex auth_mode telclaude-relay");
	}
	if (provider && !hasOnlyKeys(provider, ["auth_mode", "last_refresh", "tokens"])) {
		missing.push("providers.openai-codex exact fields");
	}
	if (tokens && !hasOnlyKeys(tokens, ["access_token", "refresh_token"])) {
		missing.push("providers.openai-codex tokens exact fields");
	}
	const providerAccessTokenFailure = peerBoundOpenAiCodexRelayTokenFailure(
		providerAccessToken,
		expectedPeerAddress,
	);
	if (providerAccessTokenFailure) {
		missing.push(`providers.openai-codex peer-bound access_token (${providerAccessTokenFailure})`);
	}
	if (getString(tokens, "refresh_token") !== NONREFRESHABLE_RELAY_TOKEN_PLACEHOLDER) {
		missing.push("providers.openai-codex non-refreshable refresh_token placeholder");
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
		if (
			!hasOnlyKeys(credentialEntry, [
				"id",
				"label",
				"auth_type",
				"priority",
				"source",
				"access_token",
				"base_url",
			])
		) {
			missing.push("credential_pool.openai-codex entry exact fields");
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
		if (providerAccessToken && poolAccessToken && providerAccessToken !== poolAccessToken) {
			missing.push("matching provider and credential_pool access_token");
		}
	}
	if (missing.length > 0) return { ok: false, missing };

	const normalizedAccessToken = providerAccessToken as string;
	return {
		ok: true,
		normalizedContent: content
			.replaceAll(normalizedAccessToken, "<peer-bound-openai-codex-relay-token>")
			.replaceAll(
				NONREFRESHABLE_RELAY_TOKEN_PLACEHOLDER,
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
): ModelRelayGate {
	if (normalizeProfilePath(profileDir) !== normalizeProfilePath(runtimeCustodyProfileDir)) {
		return pass(
			"profile.runtimeCustody",
			"non-default test profile does not claim runtime custody",
		);
	}
	const failures: string[] = [];
	try {
		const profileStat = fs.lstatSync(profileDir);
		if (!profileStat.isDirectory()) {
			failures.push("profile directory is not a directory");
		}
		if (profileStat.uid !== 0) {
			failures.push(`profile directory is uid ${profileStat.uid}, expected root`);
		}
		if ((profileStat.mode & 0o002) !== 0) {
			failures.push(`profile directory is world-writable ${formatMode(profileStat.mode)}`);
		}
		if ((profileStat.mode & 0o020) !== 0 && (profileStat.mode & 0o1000) === 0) {
			failures.push(
				`profile directory is group-writable without sticky bit ${formatMode(profileStat.mode)}`,
			);
		}
	} catch (error) {
		failures.push(
			`profile directory stat failed: ${error instanceof Error ? error.message : String(error)}`,
		);
	}
	for (const relativePath of RUNTIME_CUSTODY_PROFILE_FILES) {
		const filePath = path.join(profileDir, relativePath);
		try {
			const stat = fs.lstatSync(filePath);
			if (!stat.isFile()) {
				failures.push(`${relativePath} is not a regular file`);
			}
			if (stat.uid !== 0) {
				failures.push(`${relativePath} is uid ${stat.uid}, expected root`);
			}
			if ((stat.mode & 0o222) !== 0) {
				failures.push(`${relativePath} has writable mode ${formatMode(stat.mode)}`);
			}
		} catch (error) {
			failures.push(
				`${relativePath} stat failed: ${error instanceof Error ? error.message : String(error)}`,
			);
		}
	}
	return failures.length === 0
		? pass(
				"profile.runtimeCustody",
				"runtime credential custody files are root-owned and read-only",
			)
		: fail("profile.runtimeCustody", failures.join("; "));
}

function formatMode(mode: number): string {
	return `0${(mode & 0o777).toString(8)}`;
}

function hasOnlyKeys(record: Record<string, unknown>, expectedKeys: readonly string[]): boolean {
	const actual = Object.keys(record).sort();
	const expected = [...expectedKeys].sort();
	return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
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
