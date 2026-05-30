import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { redactSecrets } from "../security/output-filter.js";
import { type NETWORK_PROBE_POSTURES, resolveHermesArtifactPath } from "./foundation.js";
import { DEFAULT_MODEL_PROVIDER_PROBE_URL } from "./network-probes.js";

export const HERMES_MODEL_RELAY_SCHEMA_VERSION = "telclaude.hermes.model-relay.v1";
export const DEFAULT_MODEL_RELAY_EVIDENCE_PATH = "artifacts/hermes/probes/model-relay.json";
export const MODEL_RELAY_OBSERVED_PEER_HEADER = "x-telclaude-model-relay-observed-peer-address";
export const DEFAULT_MODEL_RELAY_CONTAINED_CONTAINER_NAME = "tc-hermes-contained";
export const DEFAULT_MODEL_RELAY_POSTURE = "agent-iptables" as const;

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
	"EHOSTUNREACH",
	"ENETUNREACH",
	"EACCES",
	"EPERM",
]);
const MODEL_CREDENTIAL_PATTERNS = [
	/\b(ANTHROPIC|OPENAI|GEMINI|GOOGLE|OPENROUTER|XAI)_API_KEY\s*[:=]/i,
	/\b(BEDROCK|AWS)_SECRET_ACCESS_KEY\s*[:=]/i,
	/\b(model|llm)[_-]?(api[_-]?key|token|secret)\s*[:=]/i,
];
const DIRECT_MODEL_HOST_PATTERNS = [
	/api\.anthropic\.com/i,
	/api\.openai\.com/i,
	/generativelanguage\.googleapis\.com/i,
	/openrouter\.ai\/api/i,
	/api\.x\.ai/i,
];
const DIRECT_MODEL_PROVIDER_HOSTS = new Set([
	"api.anthropic.com",
	"api.openai.com",
	"generativelanguage.googleapis.com",
	"openrouter.ai",
	"api.x.ai",
]);
const MAX_PROFILE_FILES = 5_000;
const MAX_PROFILE_FILE_BYTES = 1_000_000;

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
	const profileResult = scanProfileDir(profileDir);
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
): HermesModelRelayReport {
	const resolved = resolveHermesArtifactPath(outPath);
	fs.mkdirSync(path.dirname(resolved), { recursive: true });
	const tmpPath = `${resolved}.tmp.${process.pid}`;
	fs.writeFileSync(tmpPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
	fs.renameSync(tmpPath, resolved);
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

function scanProfileDir(profileDir: string | undefined): {
	gates: ModelRelayGate[];
	scannedFiles: string[];
} {
	if (!profileDir) {
		return {
			gates: [
				fail(
					"profile.noRawModelCredentials",
					"profile directory is required to prove model credential absence",
				),
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
					"profile.noRawModelCredentials",
					`profile directory missing: ${redactSecrets(resolved)}`,
				),
				fail("profile.noDirectModelHosts", `profile directory missing: ${redactSecrets(resolved)}`),
				fail("profile.scanComplete", `profile directory missing: ${redactSecrets(resolved)}`),
			],
			scannedFiles: [],
		};
	}

	const findings: string[] = [];
	const directHostFindings: string[] = [];
	const scannedFiles: string[] = [];
	const inventory = listProfileFiles(resolved);
	for (const filePath of inventory.scannedFiles) {
		scannedFiles.push(filePath);
		const content = fs.readFileSync(filePath, "utf8");
		for (const pattern of MODEL_CREDENTIAL_PATTERNS) {
			if (pattern.test(content)) {
				findings.push(path.relative(resolved, filePath));
				break;
			}
		}
		for (const pattern of DIRECT_MODEL_HOST_PATTERNS) {
			if (pattern.test(content)) {
				directHostFindings.push(path.relative(resolved, filePath));
				break;
			}
		}
	}

	return {
		gates: [
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
