import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http, { type IncomingMessage, type ServerResponse } from "node:http";
import net, { type AddressInfo, type Socket } from "node:net";
import os from "node:os";
import path from "node:path";
import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { shutdownTokenClient } from "../../src/relay/rpc-auth-client.js";
import { registerHermesCommand } from "../../src/commands/hermes.js";
import {
	buildCompatibilityLockfileDraft,
	buildHermesDoctorReport,
	type CompatibilityLockfile,
	computeHermesArtifactDigest,
	DEFAULT_NETWORK_PROBES_PATH,
	type FeatureProbeMatrix,
	HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV,
	HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK_ENV,
	HERMES_TRACKED_SEED_PATHS,
	NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION,
	parseHermesPin,
	REQUIRED_CUTOVER_NETWORK_PROBE_IDS,
	validateCompatibilityLockfile,
	validateFeatureProbeMatrix,
	writeHermesJsonArtifact,
} from "../../src/hermes/foundation.js";
import { startTelclaudeLiveMcpAdminServer } from "../../src/hermes/mcp/live-admin.js";
import type { TelclaudeLiveMcpProbeTokenBundle } from "../../src/hermes/mcp/live-probe-tokens.js";
import { DEFAULT_MODEL_RELAY_PROFILE_DIR } from "../../src/hermes/model-relay.js";
import { signNetworkProbeEvidenceAttestation } from "../../src/hermes/network-probe-attestation.js";
import {
	SERVED_MCP_CONTAINMENT_SCHEMA_VERSION,
	SERVED_MCP_REQUIRED_PROPERTY_NAMES,
} from "../../src/hermes/served-mcp-containment.js";
import { installSkillFromDir } from "../../src/hermes/skills-catalog.js";
import { buildInternalResponseProof, generateKeyPair } from "../../src/internal-auth.js";
import { verifyOpenAiCodexPeerBoundProxyToken } from "../../src/relay/openai-codex-proxy.js";
import {
	type OpenAiCodexRelayProof,
	type OpenAiCodexRelayProofSignedFields,
	openAiCodexRelayProofTokenSha256,
	signOpenAiCodexRelayProof,
} from "../../src/relay/openai-codex-relay-proof.js";

const hermesPin = { version: "0.15.1" };
const CLI_HEADLESS_TEST_RELAY_IP = "10.88.93.10";
const CLI_HEADLESS_TEST_CONTAINED_IP = "10.88.93.11";
const CLI_HEADLESS_WRONG_CONTAINED_IP = "10.88.93.12";
const requiredNetworkProbeIds = [...REQUIRED_CUTOVER_NETWORK_PROBE_IDS];
const cliHeadlessRelaySigningKeys = generateKeyPair();
const HERMES_COMMAND_TEST_ENV_KEYS = [
	"DOCKER_BIN",
	"HERMES_INFERENCE_MODEL",
	"OPERATOR_RPC_AGENT_PRIVATE_KEY",
	"OPERATOR_RPC_AGENT_PUBLIC_KEY",
	"OPERATOR_RPC_RELAY_PRIVATE_KEY",
	"OPERATOR_RPC_RELAY_PUBLIC_KEY",
	"TELCLAUDE_CAPABILITIES_URL",
	"TELCLAUDE_HERMES_BIN",
	"TELCLAUDE_HERMES_CONTAINED_CONTAINER_NAME",
	"TELCLAUDE_HERMES_CONTAINED_IP",
	"TELCLAUDE_HERMES_FIREWALL_SENTINEL",
	"TELCLAUDE_HERMES_HOME",
	"TELCLAUDE_HERMES_LIVE_MCP_ADMIN_SOCKET",
	"TELCLAUDE_HERMES_LIVE_MCP_ALLOWED_PEERS",
	"TELCLAUDE_HERMES_LIVE_MCP_NETWORK",
	"TELCLAUDE_HERMES_MODEL_RELAY_POSTURE",
	"TELCLAUDE_HERMES_MODEL_RELAY_URL",
	"TELCLAUDE_HERMES_NETWORK",
	"TELCLAUDE_HERMES_NETWORK_DNS_URL",
	"TELCLAUDE_HERMES_NETWORK_MODEL_URL",
	"TELCLAUDE_HERMES_NETWORK_POSTURE",
	"TELCLAUDE_HERMES_NETWORK_PROBE_POSTURE",
	"TELCLAUDE_HERMES_NETWORK_PROVIDER_URL",
	"TELCLAUDE_HERMES_NETWORK_RELAY_URL",
	"TELCLAUDE_HERMES_NETWORK_VAULT_URL",
	"TELCLAUDE_HERMES_PIN",
	"TELCLAUDE_HERMES_PROFILE_DIR",
	"TELCLAUDE_HERMES_RELAY_CONTAINER_NAME",
	"TELCLAUDE_HERMES_RELAY_IP",
	"TELCLAUDE_HERMES_RUNTIME_GID",
	"TELCLAUDE_HERMES_RUNTIME_UID",
	"TELCLAUDE_HERMES_CWD",
	"TELCLAUDE_HERMES_SERVED_MCP_AUTH",
	"TELCLAUDE_HERMES_SKILL_CATALOG_DIR",
	"TELCLAUDE_HERMES_SKILL_CATALOG_MOUNT",
	"TELCLAUDE_HERMES_SOCIAL_SKILL_CATALOG_DIR",
	"TELCLAUDE_HERMES_SOCIAL_SKILL_CATALOG_MOUNT",
	"TELCLAUDE_HERMES_SERVED_MCP_FORGED_AUTH",
	"TELCLAUDE_HERMES_SERVED_MCP_OFF_DOMAIN_CONTAINER",
	"TELCLAUDE_HERMES_SERVED_MCP_OFF_DOMAIN_PEER_AUTH",
	"TELCLAUDE_HERMES_SERVED_MCP_OFF_DOMAIN_PEER_IP",
	"TELCLAUDE_HERMES_SERVED_MCP_URL",
	"TELCLAUDE_HERMES_SERVED_MCP_WRONG_CONNECTION_AUTH",
	"TELCLAUDE_HERMES_SKILLS_ALLOWLIST_MODULE",
	HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV,
	HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK_ENV,
] as const;

// The skills-allowlist evaluator resolves the live relay skill catalog state by
// default; pin it to a nonexistent root so a real catalog on the dev machine
// cannot leak a skills.catalog.required gate into seeded cutover evidence.
process.env.TELCLAUDE_HERMES_SKILL_CATALOG_DIR = path.join(
	os.tmpdir(),
	`telclaude-no-catalog-${process.pid}`,
);

let hermesCommandTestEnvSnapshot: Record<string, string | undefined> = {};

function snapshotHermesCommandTestEnv(): void {
	hermesCommandTestEnvSnapshot = Object.fromEntries(
		HERMES_COMMAND_TEST_ENV_KEYS.map((key) => [key, process.env[key]]),
	);
}

function restoreHermesCommandTestEnv(): void {
	for (const [key, value] of Object.entries(hermesCommandTestEnvSnapshot)) {
		restoreEnv(key, value);
	}
	hermesCommandTestEnvSnapshot = {};
}

function freshHermesFixtureTimestamp(offsetMs = 60_000): string {
	return new Date(Date.now() - offsetMs).toISOString();
}

function addMs(timestamp: string, ms: number): string {
	return new Date(Date.parse(timestamp) + ms).toISOString();
}

const featureProbeMatrix: FeatureProbeMatrix = {
	schemaVersion: 1,
	probes: [
		{
			surface_id: "edge.whatsapp.plugin-adapter",
			hermes_pin: hermesPin,
			documented_seam: "Hermes platform plugin adapter",
			probe_command: "pnpm dev hermes parity --whatsapp --edge-adapter",
			expected_result: "sanitized inbound and prepared outbound pass",
			negative_probe: "native WhatsApp credential access fails",
			evidence_path: "artifacts/hermes/whatsapp-edge.json",
			lockfile_key: "featureProbes.edge.whatsapp",
			security_scope: "edge-adapter",
			approval_equivalent: true,
			failure_outcome: "disable",
			status: "pass",
		},
	],
};

const compatLockfile: CompatibilityLockfile = {
	schemaVersion: 1,
	hermes: hermesPin,
	featureProbeMatrixDigest: computeHermesArtifactDigest(featureProbeMatrix),
	featureProbes: [
		{
			surface_id: "edge.whatsapp.plugin-adapter",
			status: "pass",
			evidence_path: "artifacts/hermes/whatsapp-edge.json",
		},
	],
	adapterApiSignatures: {
		"edge.whatsapp": `sha256:${"a".repeat(64)}`,
	},
	capabilities: {
		plugins: ["platform-adapter"],
		mcp: ["stdio"],
		modelProviders: ["custom-provider"],
		memoryProviders: ["custom-memory"],
	},
	requiredUpgradeTests: ["pnpm dev hermes prove --upstream-clean --p0"],
	generatedProfileSchemaVersion: "1",
	wrapperPackageVersion: "0.7.1",
	paritySuiteDigests: {
		p0: `sha256:${"b".repeat(64)}`,
	},
	noForkProofEvidencePath: "artifacts/hermes/no-fork.json",
	sourceDriftSignals: {
		sourceCommit: "abcdef1",
		docsCommit: "1234567",
	},
};

type HermesCommandTestOptions = {
	readonly cwd?: string;
};

let testCwd: string | undefined;

function resolveTestPath(filePath: string): string {
	if (path.isAbsolute(filePath)) return filePath;
	return path.join(testCwd ?? process.cwd(), filePath);
}

const HERMES_COMMAND_PATH_OPTIONS = new Set([
	"--bundle-out",
	"--canary",
	"--checkout",
	"--cwd",
	"--decisions",
	"--evidence",
	"--evidence-dir",
	"--feature-probes",
	"--fixtures",
	"--from-report",
	"--hermes-bin",
	"--hermes-home",
	"--inventory",
	"--lockfile",
	"--network-probes",
	"--nofork",
	"--out",
	"--profile-dir",
	"--profile-proof",
	"--proof-bundle",
	"--proof-out",
	"--queue-snapshot",
	"--report-out",
	"--request",
	"--rollback",
	"--run-report-out",
	"--scope",
	"--selected-file",
	"--test-report",
]);

function normalizeHermesCommandArgsForCwd(args: string[], cwd: string | undefined): string[] {
	if (!cwd) return args;
	const normalized = [...args];
	for (let index = 0; index < normalized.length - 1; index += 1) {
		const option = normalized[index];
		if (!HERMES_COMMAND_PATH_OPTIONS.has(option)) continue;
		const value = normalized[index + 1];
		if (!value || value.startsWith("-") || path.isAbsolute(value) || /^[a-z]+:\/\//i.test(value)) {
			continue;
		}
		normalized[index + 1] = path.join(cwd, value);
		index += 1;
	}
	return normalized;
}

async function runHermesCommand(
	args: string[],
	options: HermesCommandTestOptions = {},
): Promise<{ exitCode: unknown; stdout: string }> {
	const output: string[] = [];
	const logSpy = vi.spyOn(console, "log").mockImplementation((...values: unknown[]) => {
		output.push(values.map(String).join(" "));
	});
	const cwd = options.cwd ?? testCwd;
	const cwdSpy =
		cwd && process.cwd() !== cwd ? vi.spyOn(process, "cwd").mockReturnValue(cwd) : undefined;
	const commandArgs = normalizeHermesCommandArgsForCwd(args, cwd);
	const program = new Command();
	registerHermesCommand(program);
	process.exitCode = undefined;
	try {
		await program.parseAsync(["node", "telclaude", ...commandArgs]);
		return { exitCode: process.exitCode, stdout: output.join("\n") };
	} finally {
		process.exitCode = undefined;
		cwdSpy?.mockRestore();
		logSpy.mockRestore();
	}
}

function privateRuntimeSubcommands(): string[] {
	const program = new Command();
	registerHermesCommand(program);
	const hermes = program.commands.find((command) => command.name() === "hermes");
	const privateRuntime = hermes?.commands.find((command) => command.name() === "private-runtime");
	return privateRuntime?.commands.map((command) => command.name()).sort() ?? [];
}

async function runHermesCommandWithEnv(
	args: string[],
	env: Record<string, string>,
	options: HermesCommandTestOptions = {},
): Promise<{ exitCode: unknown; stdout: string }> {
	return withHermesCommandTestEnv(env, () => runHermesCommand(args, options));
}

async function withHermesCommandTestEnv<T>(
	env: Record<string, string | undefined>,
	callback: () => T | Promise<T>,
): Promise<T> {
	const original = Object.fromEntries(
		Object.keys(env).map((key) => [key, process.env[key] as string | undefined]),
	);
	for (const [key, value] of Object.entries(env)) {
		restoreEnv(key, value);
	}
	try {
		return await callback();
	} finally {
		for (const [key, value] of Object.entries(original)) {
			restoreEnv(key, value);
		}
	}
}

function writeExecutable(tempDir: string, body: string): string {
	const filePath = path.join(tempDir, "fake-hermes.sh");
	fs.writeFileSync(filePath, body, "utf8");
	fs.chmodSync(filePath, 0o755);
	return filePath;
}

function readJson(filePath: string): unknown {
	return JSON.parse(fs.readFileSync(resolveTestPath(filePath), "utf8")) as unknown;
}

function writeJson(filePath: string, value: unknown): void {
	const resolved = resolveTestPath(filePath);
	fs.mkdirSync(path.dirname(resolved), { recursive: true });
	fs.writeFileSync(resolved, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function networkProbeRunReport() {
	const posture = "contained-internal";
	const evidence = requiredNetworkProbeIds.map((id) =>
		passingNetworkProbeEvidence(
			id,
			`artifacts/hermes/network/${id.replace(/^network\./, "")}.json`,
		),
	);
	return {
		schemaVersion: "telclaude.hermes.network-probe-run.v1",
		posture,
		status: "pass",
		ran: true,
		summary: "contained network probes passed",
		bundle: {
			schemaVersion: 1,
			probes: evidence.map((probe) => ({
				id: probe.id,
				status: probe.status,
				evidence_path: probe.evidence_path,
			})),
		},
		evidence,
	};
}

function hermesRuntimeState() {
	return {
		ok: true,
		effectiveMode: "hermes",
		effectiveValue: "1",
		controlMode: "hermes",
		controlSource: "hermes-only",
	};
}

function signedRuntimeStatePayload(
	requestPath: string,
	requestBody: string,
	state: ReturnType<typeof hermesRuntimeState>,
): string {
	const unsignedBody = JSON.stringify(state);
	return JSON.stringify({
		...state,
		relayProof: buildInternalResponseProof("POST", requestPath, requestBody, unsignedBody, {
			scope: "operator",
		}),
	});
}

async function startProbeServer(
	handler: (req: IncomingMessage, res: ServerResponse) => void = (_req, res) => {
		res.statusCode = 204;
		res.end();
	},
): Promise<{ url: string; requests: { count: number }; close: () => Promise<void> }> {
	const requests = { count: 0 };
	const sockets = new Set<Socket>();
	const server = http.createServer((req, res) => {
		requests.count += 1;
		handler(req, res);
	});
	server.on("connection", (socket) => {
		sockets.add(socket);
		socket.on("close", () => sockets.delete(socket));
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const address = server.address() as AddressInfo;
	return {
		url: `http://127.0.0.1:${address.port}/probe`,
		requests,
		close: async () => {
			for (const socket of sockets) socket.destroy();
			await new Promise<void>((resolve, reject) => {
				server.close((error) => (error ? reject(error) : resolve()));
			});
		},
	};
}

async function closedProbeUrl(): Promise<string> {
	const server = net.createServer();
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const address = server.address() as AddressInfo;
	const url = `http://127.0.0.1:${address.port}/probe`;
	await new Promise<void>((resolve, reject) => {
		server.close((error) => (error ? reject(error) : resolve()));
	});
	return url;
}

function requiredProviderUrlCsv(url: string): string {
	return ["bank", "clalit", "government", "google"].map((name) => `${name}=${url}`).join(",");
}

const DETERMINISTIC_DNS_DENIAL_URL = "http://169.254.169.254:444/probe";

function deterministicDnsDenialFetchCause(): Error & { code: string } {
	const cause = new Error("connect EHOSTDOWN 169.254.169.254:444") as Error & {
		code: string;
	};
	cause.code = "EHOSTDOWN";
	return cause;
}

function fetchTarget(input: Parameters<typeof fetch>[0]): string {
	if (typeof input === "string") return input;
	if (input instanceof URL) return input.href;
	return input.url;
}

function spyOnDeterministicDnsDenialFetch(): ReturnType<typeof vi.spyOn> {
	const realFetch = globalThis.fetch;
	return vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
		if (fetchTarget(input) === DETERMINISTIC_DNS_DENIAL_URL) {
			return Promise.reject(
				new TypeError("fetch failed", { cause: deterministicDnsDenialFetchCause() }),
			);
		}
		return realFetch(input, init);
	});
}

async function startLiveMcpAdminSocket(response: TelclaudeLiveMcpProbeTokenBundle): Promise<{
	socketPath: string;
	requests: unknown[];
	close: () => Promise<void>;
}> {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-live-admin-cli-"));
	const socketPath = path.join(tempDir, "admin.sock");
	const requests: unknown[] = [];
	const originalOperatorPrivate = process.env.OPERATOR_RPC_AGENT_PRIVATE_KEY;
	const originalOperatorPublic = process.env.OPERATOR_RPC_AGENT_PUBLIC_KEY;
	const keys = generateKeyPair();
	process.env.OPERATOR_RPC_AGENT_PRIVATE_KEY = keys.privateKey;
	process.env.OPERATOR_RPC_AGENT_PUBLIC_KEY = keys.publicKey;
	const handle = await startTelclaudeLiveMcpAdminServer({
		socketPath,
		issueProbeTokenBundle: (request) => {
			requests.push(request);
			return response;
		},
	});
	return {
		socketPath,
		requests,
		close: async () => {
			await handle.stop();
			fs.rmSync(tempDir, { recursive: true, force: true });
			restoreEnv("OPERATOR_RPC_AGENT_PRIVATE_KEY", originalOperatorPrivate);
			restoreEnv("OPERATOR_RPC_AGENT_PUBLIC_KEY", originalOperatorPublic);
		},
	};
}

function restoreEnv(name: string, value: string | undefined): void {
	if (value === undefined) {
		delete process.env[name];
	} else {
		process.env[name] = value;
	}
}

function writeFirewallSentinel(tempDir: string): string {
	const sentinelPath = path.join(tempDir, "firewall-active");
	fs.writeFileSync(sentinelPath, "active\n", "utf8");
	return sentinelPath;
}

function ensureOperatorRelayKeys(): { privateKey: string; publicKey: string } {
	if (process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY && process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY) {
		return {
			privateKey: process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY,
			publicKey: process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY,
		};
	}
	const relayKeys = generateKeyPair();
	process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
	process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;
	return relayKeys;
}

function passingNetworkProbeEvidence(id: string, evidencePath: string) {
	return withNetworkProbeAttestation({
		schemaVersion: NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION,
		id,
		posture: "contained-internal",
		status: "pass",
		ran: true,
		summary:
			id === "network.relay-control-allowed"
				? `${id} observed expected relay reachability`
				: `${id} observed only expected denials`,
		generatedAt: freshHermesFixtureTimestamp(),
		evidence_path: evidencePath,
		attempts:
			id === "network.direct-provider-denied"
				? passingNetworkProbeAttempts(id)
				: [passingFirewallSentinelAttempt(), ...passingNetworkProbeAttempts(id)],
	});
}

function withNetworkProbeAttestation<
	T extends {
		schemaVersion: string;
		id: string;
		posture?: string;
		status: string;
		ran: boolean;
		summary: string;
		generatedAt: string;
		attempts: readonly unknown[];
	},
>(evidence: T): T & { attestation: ReturnType<typeof signNetworkProbeEvidenceAttestation> } {
	ensureOperatorRelayKeys();
	return {
		...evidence,
		attestation: signNetworkProbeEvidenceAttestation(evidence),
	};
}

function passingModelRelayEvidence(overrides: Record<string, unknown> = {}) {
	return {
		schemaVersion: "telclaude.hermes.model-relay.v1",
		probeId: "model.relay",
		posture: "contained-internal",
		status: "pass",
		ran: true,
		summary: "Hermes model relay evidence passed",
		generatedAt: "2026-05-30T00:00:00.000Z",
		gates: [
			{
				name: "modelRelay.allowed",
				status: "pass",
				detail: "operator allowed live model-relay evidence",
			},
			{
				name: "modelRelay.modelProvider",
				status: "pass",
				detail: "model provider config uses relay-owned OpenAI Codex credential custody",
			},
			{
				name: "relay.reachable",
				status: "pass",
				detail: "model relay endpoint reached with HTTP status 204",
			},
			{
				name: "modelRelay.origin",
				status: "pass",
				detail:
					"model-relay evidence originated from tc-hermes-contained at the expected peer address",
			},
			{
				name: "directModel.denied",
				status: "pass",
				detail: "direct model-provider egress denied",
			},
			{
				name: "profile.relayCredentialReference",
				status: "pass",
				detail:
					"runtime Hermes profile references peer-bound relay OpenAI Codex credential custody",
			},
			{
				name: "profile.runtimeCustody",
				status: "pass",
				detail: "runtime credential custody files are root-owned and read-only",
			},
			{
				name: "profile.noRawModelCredentials",
				status: "pass",
				detail: "scanned profile files contain no raw model credentials",
			},
			{
				name: "profile.noDirectModelHosts",
				status: "pass",
				detail: "scanned profile files contain no direct model hosts",
			},
			{
				name: "profile.scanComplete",
				status: "pass",
				detail: "profile scan covered all profile files",
			},
		],
		origin: {
			kind: "contained-peer",
			containerName: "tc-hermes-contained",
			observedPeerAddress: CLI_HEADLESS_TEST_CONTAINED_IP,
			observedPeerSource: "server-peer-echo",
			expectedPeerAddress: CLI_HEADLESS_TEST_CONTAINED_IP,
			expectedPeerSource: "configured-contained-ip",
			detail: "model relay peer origin was observed by the relay endpoint",
		},
		modelProvider: {
			provider: "openai-codex",
			baseUrl: "http://telclaude:8790/v1/openai-codex-proxy",
			baseUrlHost: "telclaude",
			model: "gpt-5.5",
			modelSource: "env:HERMES_INFERENCE_MODEL",
			authLocation: "hermes-auth-store:openai-codex",
			authScope: "relay-openai-codex-subscription-proxy",
			tokenScoping: "peer-bound",
			auxiliaryAuthSource: "manual:telclaude-relay",
			auxiliaryBaseUrl: "http://telclaude:8790/v1/openai-codex-proxy",
			auxiliaryBaseUrlHost: "telclaude",
			refreshTokenPolicy: "non-refreshable-placeholder",
		},
		observation: {
			relayUrl: "http://telclaude:8790/v1/models",
			directModelUrl: "https://chatgpt.com/backend-api/codex/models?client_version=1.0.0",
			profileDir: DEFAULT_MODEL_RELAY_PROFILE_DIR,
			scannedProfileFiles: [
				`${DEFAULT_MODEL_RELAY_PROFILE_DIR}/auth.json`,
				`${DEFAULT_MODEL_RELAY_PROFILE_DIR}/config.yaml`,
				`${DEFAULT_MODEL_RELAY_PROFILE_DIR}/secret-manifest.json`,
			],
		},
		...overrides,
	};
}

function passingFirewallSentinelAttempt() {
	return {
		name: "firewall-sentinel",
		kind: "firewall_sentinel",
		target: "/run/telclaude/firewall-active",
		expectation: "present",
		status: "pass",
		observed: "present",
		detail: "firewall sentinel is present",
	};
}

function passingNetworkProbeAttempts(id: string) {
	switch (id) {
		case "network.relay-control-allowed":
			return [
				{
					name: "relay-control",
					kind: "http",
					target: "http://127.0.0.1/relay-control",
					expectation: "allow",
					status: "pass",
					observed: "reachable",
					detail: "allowed control reached relay with HTTP status 204",
					durationMs: 1,
					httpStatus: 204,
				},
			];
		case "network.direct-vault-denied":
			return [
				{
					name: "vault-socket",
					kind: "unix_socket",
					target: "/run/vault/vault.sock",
					expectation: "deny",
					status: "pass",
					observed: "absent",
					detail: "vault socket path is absent from the probe environment",
				},
			];
		case "network.dns-exfil-denied":
			return [
				{
					name: "dns-exfil-1",
					kind: "dns_guard",
					target: "http://169.254.169.254/latest/meta-data/",
					expectation: "deny",
					status: "pass",
					observed: "denied",
					detail: "target was actively denied with ECONNREFUSED",
					durationMs: 1,
					errorName: "TypeError",
					errorCode: "ECONNREFUSED",
					resolvedAddresses: [
						{
							address: "169.254.169.254",
							blocked: true,
							nonOverridable: true,
						},
					],
				},
			];
		case "network.direct-provider-denied":
			return ["bank", "clalit", "government", "google"].map((provider) =>
				passingHttpDenialAttempt(
					`provider:${provider}`,
					`https://${provider}.provider.internal/probe`,
				),
			);
		case "network.direct-model-provider-denied":
			return [
				passingHttpDenialAttempt(
					"model-provider",
					"https://chatgpt.com/backend-api/codex/models?client_version=1.0.0",
				),
			];
		default:
			throw new Error(`unsupported network probe fixture ${id}`);
	}
}

function passingHttpDenialAttempt(name: string, target: string) {
	return {
		name,
		kind: "http",
		target,
		expectation: "deny",
		status: "pass",
		observed: "denied",
		detail: "target was actively denied with ECONNREFUSED",
		durationMs: 1,
		errorName: "TypeError",
		errorCode: "ECONNREFUSED",
	};
}

type CliHeadlessEvidenceFixture = Record<string, unknown> & {
	invocation: Record<string, unknown>;
	provenance?: Record<string, unknown>;
	runtime?: Record<string, unknown>;
};

function cliHeadlessEvidence(overrides: Record<string, unknown> = {}): CliHeadlessEvidenceFixture {
	const startedAt = freshHermesFixtureTimestamp();
	const endedAt = addMs(startedAt, 1000);
	const invocation = {
		command: "/usr/local/bin/hermes",
		args: ["chat", "-q", "telclaude probe ok"],
		cwd: "/repo",
		envKeys: [
			"HERMES_HOME",
			"HERMES_CODEX_BASE_URL",
			"HERMES_INFERENCE_PROVIDER",
			"HERMES_INFERENCE_MODEL",
			"NO_COLOR",
		],
	};
	const stdoutPreview = "telclaude probe ok\n";
	const runtime = {
		kind: "contained-docker",
		containerName: "tc-hermes-contained",
		networkName: "telclaude-hermes-private",
		containerId: "tc-hermes-contained-container-id",
		image:
			"nousresearch/hermes-agent@sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7",
		imageDigest: "sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7",
		hostname: "tc-hermes-contained",
		relayHost: "telclaude",
		relayResolvedAddress: CLI_HEADLESS_TEST_RELAY_IP,
		containerIpAddress: CLI_HEADLESS_TEST_CONTAINED_IP,
		observedPeerAddress: CLI_HEADLESS_TEST_CONTAINED_IP,
		provenanceSource: "docker-inspect-container-dns-and-relay-peer",
	};
	const relayProof = cliHeadlessRelayProof({ observedAt: addMs(startedAt, 500) });
	const base = {
		schemaVersion: "telclaude.hermes.probe-result.v1",
		probeId: "execution.cli_headless",
		status: "pass",
		ran: true,
		exitCode: 0,
		summary: "Hermes CLI oneshot probe completed successfully",
		invocation,
		modelProvider: {
			provider: "openai-codex",
			baseUrl: "http://telclaude:8790/v1/openai-codex-proxy",
			baseUrlHost: "telclaude",
			model: "gpt-5.3-codex",
			modelSource: "env:HERMES_INFERENCE_MODEL",
			authLocation: "hermes-auth-store:openai-codex",
			authScope: "relay-openai-codex-subscription-proxy",
			tokenScoping: "peer-bound",
			auxiliaryAuthSource: "manual:telclaude-relay",
			auxiliaryBaseUrl: "http://telclaude:8790/v1/openai-codex-proxy",
			auxiliaryBaseUrlHost: "telclaude",
			refreshTokenPolicy: "non-refreshable-placeholder",
		},
		provenance: {
			runner: "telclaude-hermes-cli-probe",
			source: "live-allow-run",
			startedAt,
			endedAt,
			expectedProofToken: "telclaude probe ok",
			proofTokenObserved: true,
			invocationSha256: computeHermesArtifactDigest(invocation),
			stdoutSha256: computeTextDigest(stdoutPreview),
			stderrSha256: computeTextDigest(""),
			runtimeSha256: computeHermesArtifactDigest(runtime),
			relayProofSha256: computeHermesArtifactDigest(relayProof),
		},
		stdoutPreview,
		stderrPreview: "",
		runtime,
		relayProof,
		findings: [],
	};
	const report = { ...base, ...overrides } as CliHeadlessEvidenceFixture;
	if (typeof overrides.provenance === "object" && overrides.provenance !== null) {
		report.provenance = {
			...base.provenance,
			...(overrides.provenance as Record<string, unknown>),
		};
	} else if (!Object.hasOwn(overrides, "provenance")) {
		report.provenance = {
			...base.provenance,
			runtimeSha256: computeHermesArtifactDigest(report.runtime ?? null),
			relayProofSha256: computeHermesArtifactDigest(report.relayProof ?? null),
		};
	}
	return report;
}

function cliHeadlessRelayProof(
	overrides: Partial<OpenAiCodexRelayProofSignedFields> = {},
): OpenAiCodexRelayProof {
	if (!process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY || !process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY) {
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = cliHeadlessRelaySigningKeys.privateKey;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = cliHeadlessRelaySigningKeys.publicKey;
	}
	return signOpenAiCodexRelayProof({
		schemaVersion: "telclaude.hermes.cli-headless-relay-proof.v1",
		source: "telclaude-openai-codex-proxy",
		requestId: "codex-proof-1",
		method: "POST",
		path: "/backend-api/codex/responses",
		observedPeerAddress: CLI_HEADLESS_TEST_CONTAINED_IP,
		upstreamStatus: 200,
		model: "gpt-5.3-codex",
		requestBodySha256: `sha256:${"a".repeat(64)}`,
		proofTokenSha256: openAiCodexRelayProofTokenSha256("telclaude probe ok"),
		observedAt: freshHermesFixtureTimestamp(30_000),
		...overrides,
	});
}

async function withCwd<T>(cwd: string, callback: () => Promise<T>): Promise<T> {
	const previous = testCwd;
	const cwdSpy = vi.spyOn(process, "cwd").mockReturnValue(cwd);
	testCwd = cwd;
	try {
		return await callback();
	} finally {
		testCwd = previous;
		cwdSpy.mockRestore();
	}
}

function cliRelayEnv(overrides: Record<string, string> = {}): Record<string, string> {
	return {
		HERMES_CODEX_BASE_URL: "http://telclaude:8790/v1/openai-codex-proxy",
		TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN: "relay-scoped-proxy-token",
		HERMES_INFERENCE_PROVIDER: "openai-codex",
		HERMES_INFERENCE_MODEL: "gpt-5.3-codex",
		...overrides,
	};
}

function computeTextDigest(value: string): string {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function computeFileDigest(file: string): string {
	const resolved = resolveTestPath(file);
	if (!fs.existsSync(resolved)) return computeTextDigest(JSON.stringify({ file, missing: true }));
	return `sha256:${crypto.createHash("sha256").update(fs.readFileSync(resolved)).digest("hex")}`;
}

function servedMcpContainmentEvidence(overrides: Record<string, unknown> = {}) {
	const properties = Object.fromEntries(
		SERVED_MCP_REQUIRED_PROPERTY_NAMES.map((property) => [property, true]),
	);
	return {
		schemaVersion: SERVED_MCP_CONTAINMENT_SCHEMA_VERSION,
		probeId: "execution.served_mcp_containment",
		status: "pass",
		ran: true,
		generatedAt: "2026-05-30T00:00:00.000Z",
		summary: "Served MCP containment probe passed",
		endpoint: {
			transport: "http",
			target: "redacted-http-mcp-endpoint",
		},
		placement: {
			loadBearing: false,
			detail: "Placement metadata is informational; bind enforcement is a deployment gate.",
		},
		origin: {
			kind: "contained-peer",
			containerName: "tc-hermes-contained",
			observedPeerAddress: CLI_HEADLESS_TEST_CONTAINED_IP,
			observedPeerSource: "server-peer-echo",
			expectedPeerAddress: CLI_HEADLESS_TEST_CONTAINED_IP,
			expectedPeerSource: "configured-contained-ip",
			detail: "probe peer origin was observed by live MCP server",
		},
		negativeControls: {
			forgedAuthorityDenied: true,
			wrongConnectionDenied: true,
			offDomainPeerDenied: true,
		},
		properties,
		checks: SERVED_MCP_REQUIRED_PROPERTY_NAMES.map((property) => ({
			name: property,
			status: "pass",
			detail: `${property} observed`,
		})),
		...overrides,
	};
}

function liveMcpProbeTokenResponse(): TelclaudeLiveMcpProbeTokenBundle {
	return {
		allowed: {
			token: "tc_mcp_conn_allowed",
			authorizationHeader: "Bearer tc_mcp_conn_allowed",
			issuedAtMs: 1_000,
			expiresAtMs: 61_000,
		},
		offDomainPeer: {
			token: "tc_mcp_conn_off_domain_peer",
			authorizationHeader: "Bearer tc_mcp_conn_off_domain_peer",
			issuedAtMs: 1_000,
			expiresAtMs: 61_000,
		},
		forged: {
			token: "tc_mcp_conn_forged",
			authorizationHeader: "Bearer tc_mcp_conn_forged",
			issuedAtMs: 1_000,
			expiresAtMs: 61_000,
		},
		wrongConnection: {
			token: "tc_mcp_conn_wrong",
			authorizationHeader: "Bearer tc_mcp_conn_wrong",
			issuedAtMs: 1_000,
			expiresAtMs: 61_000,
		},
		metadata: {
			schemaVersion: "telclaude.hermes.live-mcp.probe-token-metadata.v1",
			issuedAtMs: 1_000,
			expiresAtMs: 61_000,
			ttlMs: 60_000,
			tokenPrefix: "tc_mcp_conn_",
			tokenMaterial: "omitted",
			peerBound: false,
			offDomainPeerBound: true,
			privateConnection: {
				profileId: "default",
				endpointId: "tc-hermes-private",
				networkNamespace: "telclaude-hermes-private",
			},
			wrongConnection: {
				profileId: "social",
				endpointId: "tc-hermes-wrong",
				networkNamespace: "telclaude-hermes-private",
			},
		},
	};
}

function ensureOperatorRelaySigningKeys(): void {
	process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY ??= cliHeadlessRelaySigningKeys.privateKey;
	process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY ??= cliHeadlessRelaySigningKeys.publicKey;
}

describe("Hermes wrapper foundation", () => {
	beforeEach(() => {
		snapshotHermesCommandTestEnv();
		process.exitCode = undefined;
		process.env.TELCLAUDE_HERMES_RELAY_IP = CLI_HEADLESS_TEST_RELAY_IP;
		process.env.TELCLAUDE_HERMES_CONTAINED_IP = CLI_HEADLESS_TEST_CONTAINED_IP;
		ensureOperatorRelaySigningKeys();
	});

	afterEach(async () => {
		restoreHermesCommandTestEnv();
		process.exitCode = undefined;
		// Let Vitest worker RPCs flush between the heavy synchronous fixture checks.
		await new Promise<void>((resolve) => setImmediate(resolve));
	});

	it("parses explicit Hermes pins without accepting an empty pin", () => {
		expect(parseHermesPin(undefined)).toBeNull();
		expect(parseHermesPin("abcdef1")).toEqual({ commit: "abcdef1" });
		expect(parseHermesPin("sha256:abc")).toEqual({ imageDigest: "sha256:abc" });
		expect(parseHermesPin("0.15.1")).toEqual({ version: "0.15.1" });
	});

	it("validates feature-probe and compatibility lockfile schemas", () => {
		expect(validateFeatureProbeMatrix(featureProbeMatrix)).toEqual({ valid: true, errors: [] });
		expect(validateCompatibilityLockfile(compatLockfile)).toEqual({ valid: true, errors: [] });

		const invalidProbe = validateFeatureProbeMatrix({
			schemaVersion: 1,
			probes: [{ surface_id: "" }],
		});
		expect(invalidProbe.valid).toBe(false);
		expect(invalidProbe.errors.join("\n")).toContain("hermes_pin");
	});

	it("generates the canonical feature-probe matrix from observed evidence", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-probes-matrix-"));

		await withCwd(tempDir, async () => {
			const result = await runHermesCommand(["hermes", "probes", "--pin", "0.15.1", "--json"]);
			const matrix = JSON.parse(result.stdout) as FeatureProbeMatrix;

			expect(result.exitCode, result.stdout).toBe(1);
			expect(matrix.schemaVersion).toBe(1);
			expect(matrix.probes.length).toBeGreaterThan(20);
			expect(matrix.probes.map((probe) => probe.surface_id)).toEqual(
				expect.arrayContaining([
					"execution.cli_headless",
					"model.relay",
					"edge.whatsapp",
					"providers.google",
					"network.egress-broker",
				]),
			);
			expect(matrix.probes.every((probe) => probe.hermes_pin.version === "0.15.1")).toBe(true);
			expect(matrix.probes.every((probe) => probe.status === "fail")).toBe(true);
			expect(matrix.probes.find((probe) => probe.surface_id === "model.relay")).toMatchObject({
				probe_command: expect.stringContaining(`--profile-dir ${DEFAULT_MODEL_RELAY_PROFILE_DIR}`),
			});
		});
	});

	it("writes compatibility lockfile drafts to an explicit output", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-compat-lock-out-"));
		const featureProbePath = path.join(tempDir, "feature-probes.json");
		const lockfilePath = path.join(tempDir, "hermes-compat.lock.json");
		writeJson(featureProbePath, featureProbeMatrix);

		const result = await runHermesCommand([
			"hermes",
			"compat-lock",
			"--dry-run",
			"--pin",
			"0.15.1",
			"--feature-probes",
			featureProbePath,
			"--out",
			lockfilePath,
			"--json",
		]);
		const written = readJson(lockfilePath) as CompatibilityLockfile;

		expect(result.exitCode, result.stdout).toBeUndefined();
		expect(written.hermes.version).toBe("0.15.1");
		expect(written.featureProbeMatrixDigest).toBe(computeHermesArtifactDigest(featureProbeMatrix));
		expect(written.noForkProofEvidencePath).toBe("docs/hermes/no-fork-proof.json");
	});

	it("binds explicit no-fork evidence paths in compatibility lockfile drafts", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-compat-lock-nofork-"));
		const featureProbePath = path.join(tempDir, "feature-probes.json");
		const lockfilePath = path.join(tempDir, "hermes-compat.lock.json");
		writeJson(featureProbePath, featureProbeMatrix);

		const result = await runHermesCommand([
			"hermes",
			"compat-lock",
			"--dry-run",
			"--pin",
			"0.15.1",
			"--feature-probes",
			featureProbePath,
			"--nofork-proof",
			"artifacts/hermes/no-fork.attested.tokenfree.json",
			"--out",
			lockfilePath,
			"--json",
		]);
		const written = readJson(lockfilePath) as CompatibilityLockfile;

		expect(result.exitCode, result.stdout).toBeUndefined();
		expect(written.noForkProofEvidencePath).toBe(
			"artifacts/hermes/no-fork.attested.tokenfree.json",
		);
	});

	it("allows red canonical seed writes before the seed is tracked by git", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-red-seed-"));
		execFileSync("git", ["init"], { cwd: tempDir, stdio: "ignore" });
		await withCwd(tempDir, async () => {
			const seedPath = path.join(tempDir, "docs/hermes/feature-probes.json");

			writeHermesJsonArtifact(
				seedPath,
				{
					schemaVersion: 1,
					probes: [{ surface_id: "execution.cli_headless", status: "fail" }],
				},
				{ allowTrackedSeedWrite: true },
			);

			expect(readJson(seedPath)).toMatchObject({
				probes: [expect.objectContaining({ status: "fail" })],
			});
		});
	});

	it("refuses green canonical seed writes even with the tracked-seed flag", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-green-seed-"));
		execFileSync("git", ["init"], { cwd: tempDir, stdio: "ignore" });
		await withCwd(tempDir, async () => {
			const greenSeedByPath: Record<(typeof HERMES_TRACKED_SEED_PATHS)[number], unknown> = {
				"docs/hermes/feature-probes.json": {
					probes: [{ surface_id: "execution.cli_headless", status: "pass" }],
				},
				"docs/hermes/hermes-compat.lock.json": {
					featureProbes: [{ surface_id: "execution.cli_headless", status: "pass" }],
				},
				"docs/hermes/cutover-scope.json": {
					workflows: [
						{
							workflow_id: "telegram.private",
							status: "included",
							unresolved_decision_ids: [],
						},
					],
				},
				"docs/hermes/decisions.json": {
					decisions: [{ id: "D-first-cutover-workflow-set", status: "accepted" }],
				},
				"docs/hermes/fixture-results.json": {
					results: [{ fixture_id: "fixture", status: "pass" }],
				},
				"docs/hermes/inventory.json": {
					status: "complete",
					risks: [],
					summary: { pendingQueues: { approvals: 0, backgroundJobs: 0 } },
				},
				"docs/hermes/network-probes.json": {
					probes: [{ id: "relay.allowed", status: "pass" }],
				},
				"docs/hermes/queue-snapshot.json": {
					unownedActiveCount: 0,
				},
				"docs/hermes/no-fork-proof.json": {
					hermesCheckoutClean: true,
					checks: [{ name: "git.diff", status: "pass" }],
				},
				"docs/hermes/cutover-proof-bundle.json": {
					artifacts: { featureProbeMatrix: { status: "pass" } },
				},
				"docs/hermes/profile-generation-proof.json": {
					schemaVersion: "telclaude.hermes.profile-generation-proof.v1",
					status: "pass",
					checks: [{ name: "profile.pin", status: "pass", detail: "green" }],
				},
				"docs/hermes/rollback-rehearsal.json": {
					passed: true,
					checks: [{ name: "rollback.transcript", status: "pass" }],
				},
			};

			expect(Object.keys(greenSeedByPath).sort()).toEqual([...HERMES_TRACKED_SEED_PATHS].sort());
			for (const [seedPath, seedValue] of Object.entries(greenSeedByPath)) {
				const resolved = path.join(tempDir, seedPath);
				expect(() =>
					writeHermesJsonArtifact(resolved, seedValue, { allowTrackedSeedWrite: true }),
				).toThrow("Refusing to write green tracked Hermes seed");
				expect(fs.existsSync(resolved)).toBe(false);
			}
		});
	});

	it("refuses green canonical seed writes by absolute path from another cwd", async () => {
		const repoDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-green-seed-target-"));
		const otherDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-green-seed-cwd-"));
		execFileSync("git", ["init"], { cwd: repoDir, stdio: "ignore" });
		await withCwd(otherDir, async () => {
			const seedPath = path.join(repoDir, "docs/hermes/profile-generation-proof.json");

			expect(() =>
				writeHermesJsonArtifact(
					seedPath,
					{
						schemaVersion: "telclaude.hermes.profile-generation-proof.v1",
						status: "pass",
						checks: [{ name: "profile.pin", status: "pass", detail: "green" }],
					},
					{ allowTrackedSeedWrite: true },
				),
			).toThrow("Refusing to write green tracked Hermes seed");
			expect(fs.existsSync(seedPath)).toBe(false);
		});
	});

	it("fails doctor when no pinned Hermes artifact is supplied", () => {
		const report = buildHermesDoctorReport({ pin: null, featureProbeMatrix });
		expect(report.status).toBe("fail");
		expect(report.checks.find((check) => check.name === "hermes.pin")?.status).toBe("fail");
	});

	it("passes doctor with a pin and valid probe and lockfile artifacts", () => {
		const report = buildHermesDoctorReport({
			pin: hermesPin,
			featureProbeMatrix,
			lockfile: compatLockfile,
		});
		expect(report.status).toBe("pass");
	});

	it("uses the compatibility lockfile Hermes pin as the default doctor pin", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-lockfile-pin-"));
		writeJson(path.join(tempDir, "docs/hermes/hermes-compat.lock.json"), compatLockfile);

		await withCwd(tempDir, async () => {
			const result = await runHermesCommand(["hermes", "doctor", "--json"]);
			const report = JSON.parse(result.stdout) as { status: string; pin: unknown };

			expect(result.exitCode, result.stdout).toBe(0);
			expect(report).toMatchObject({
				status: "pass",
				pin: hermesPin,
			});
		});
	});

	it("refuses to promote network probes into the tracked seed path by default", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-seed-guard-"));
		await withCwd(tempDir, async () => {
			execFileSync("git", ["init", "-q"], { cwd: tempDir });
			execFileSync("git", ["config", "user.email", "hermes-wrapper-test@example.invalid"], {
				cwd: tempDir,
			});
			execFileSync("git", ["config", "user.name", "Hermes Wrapper Test"], { cwd: tempDir });
			const trackedNetworkPath = resolveTestPath(DEFAULT_NETWORK_PROBES_PATH);
			writeJson(trackedNetworkPath, { schemaVersion: 1, probes: [] });
			execFileSync("git", ["add", DEFAULT_NETWORK_PROBES_PATH], { cwd: tempDir });
			execFileSync("git", ["commit", "-q", "-m", "network seed"], { cwd: tempDir });
			const before = fs.readFileSync(trackedNetworkPath, "utf8");
			const reportPath = path.join(tempDir, "network-run.json");
			writeJson(reportPath, networkProbeRunReport());

			const result = await runHermesCommand([
				"hermes",
				"network-probes",
				"--from-report",
				reportPath,
				"--json",
			]);

			expect(result.exitCode).toBe(1);
			expect(fs.readFileSync(trackedNetworkPath, "utf8")).toBe(before);
		});
	});

	it("promotes network probes to explicit temp output without touching the tracked seed", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-temp-out-"));
		await withCwd(tempDir, async () => {
			execFileSync("git", ["init", "-q"], { cwd: tempDir });
			execFileSync("git", ["config", "user.email", "hermes-wrapper-test@example.invalid"], {
				cwd: tempDir,
			});
			execFileSync("git", ["config", "user.name", "Hermes Wrapper Test"], { cwd: tempDir });
			const trackedNetworkPath = resolveTestPath(DEFAULT_NETWORK_PROBES_PATH);
			writeJson(trackedNetworkPath, { schemaVersion: 1, probes: [] });
			execFileSync("git", ["add", DEFAULT_NETWORK_PROBES_PATH], { cwd: tempDir });
			execFileSync("git", ["commit", "-q", "-m", "network seed"], { cwd: tempDir });
			const before = fs.readFileSync(trackedNetworkPath, "utf8");
			const reportPath = path.join(tempDir, "network-run.json");
			const outPath = path.join(tempDir, "network-probes.json");
			const evidenceDir = path.join(tempDir, "network-evidence");
			writeJson(reportPath, networkProbeRunReport());

			const result = await runHermesCommand([
				"hermes",
				"network-probes",
				"--from-report",
				reportPath,
				"--out",
				outPath,
				"--evidence-dir",
				evidenceDir,
				"--json",
			]);
			const bundle = readJson(outPath) as { probes: unknown[] };

			expect(result.exitCode, result.stdout).toBe(0);
			expect(bundle.probes).toHaveLength(requiredNetworkProbeIds.length);
			expect(fs.existsSync(path.join(evidenceDir, "relay-control-allowed.json"))).toBe(true);
			expect(fs.readFileSync(trackedNetworkPath, "utf8")).toBe(before);
		});
	});

	it("fails doctor when feature probes or lockfile evidence are not production-ready", () => {
		const [probe] = featureProbeMatrix.probes;
		const skippedProbes = buildHermesDoctorReport({
			pin: hermesPin,
			featureProbeMatrix: {
				schemaVersion: 1,
				probes: [{ ...probe, status: "skip" }],
			},
		});
		expect(skippedProbes.status).toBe("fail");
		expect(
			skippedProbes.checks.find((check) => check.name === "hermes.featureProbes")?.detail,
		).toContain("status is skip");

		const mismatchedLock = buildHermesDoctorReport({
			pin: hermesPin,
			featureProbeMatrix,
			lockfile: {
				...compatLockfile,
				featureProbeMatrixDigest: "sha256:stale",
			},
		});
		expect(mismatchedLock.status).toBe("fail");
		expect(
			mismatchedLock.checks.find((check) => check.name === "hermes.compatLockfile")?.detail,
		).toContain("digest does not match");

		const failingLockProbe = buildHermesDoctorReport({
			pin: hermesPin,
			lockfile: {
				...compatLockfile,
				featureProbes: [{ ...compatLockfile.featureProbes[0], status: "fail" }],
			},
		});
		expect(failingLockProbe.status).toBe("fail");
		expect(
			failingLockProbe.checks.find((check) => check.name === "hermes.compatLockfile")?.detail,
		).toContain("status is fail");
	});

	it("fails doctor with a distinct missing-artifact reason", () => {
		const report = buildHermesDoctorReport({
			pin: hermesPin,
			featureProbeMatrixMissing: "required feature-probe matrix is missing: /missing.json",
		});
		expect(report.status).toBe("fail");
		expect(report.checks.find((check) => check.name === "hermes.featureProbes")?.detail).toContain(
			"required feature-probe matrix is missing",
		);
	});

	it("generates a compatibility lockfile draft only for a pinned Hermes artifact", () => {
		expect(() =>
			buildCompatibilityLockfileDraft({
				pin: null,
				featureProbeMatrix,
				wrapperPackageVersion: "0.7.1",
			}),
		).toThrow("pinned Hermes artifact");

		const draft = buildCompatibilityLockfileDraft({
			pin: hermesPin,
			featureProbeMatrix: {
				schemaVersion: 1,
				probes: [{ ...featureProbeMatrix.probes[0], status: "skip" }],
			},
			wrapperPackageVersion: "0.7.1",
		});

		expect(draft.featureProbeMatrixDigest).toMatch(/^sha256:/);
		expect(draft.featureProbes).toEqual([
			{
				surface_id: "edge.whatsapp.plugin-adapter",
				status: "fail",
				evidence_path: "artifacts/hermes/whatsapp-edge.json",
			},
		]);
	});

	it("writes machine-observed headless entrypoint proof from focused adapter runtime tests", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-headless-entrypoint-"));
		const evidencePath = path.join(tempDir, "execution-headless-entrypoint.json");

		const result = await runHermesCommand([
			"hermes",
			"probe",
			"execution.headless_entrypoint",
			"--allow-run",
			"--json",
			"--out",
			evidencePath,
		]);
		const report = JSON.parse(result.stdout) as {
			status: string;
			probeId: string;
			testReport?: { reportPath: string; reportSha256: string };
			checks: Array<{ name: string; status: string }>;
		};

		expect(result.exitCode, result.stdout).toBe(0);
		expect(report.status).toBe("pass");
		expect(report.probeId).toBe("execution.headless_entrypoint");
		expect(report.testReport?.reportSha256).toMatch(/^sha256:[a-f0-9]{64}$/);
		expect(fs.existsSync(evidencePath)).toBe(true);
		expect(fs.existsSync(report.testReport?.reportPath ?? "")).toBe(true);
		expect(report.checks).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ name: "stream.delta_before_done", status: "pass" }),
				expect.objectContaining({ name: "session.concurrent_isolation", status: "pass" }),
				expect.objectContaining({ name: "cancellation.stop", status: "pass" }),
			]),
		);
	});

	it("writes edge adapter probe evidence through the CLI harness", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-edge-cli-"));
		const evidencePath = path.join(tempDir, "edge-whatsapp.json");

		const result = await runHermesCommand([
			"hermes",
			"probe",
			"edge.whatsapp",
			"--allow-run",
			"--json",
			"--out",
			evidencePath,
		]);
		const artifact = readJson(evidencePath) as {
			probeId: string;
			status: string;
			source: string;
			controls: Array<{ name: string; status: string }>;
		};

		expect(result.exitCode, result.stdout).toBe(0);
		expect(artifact).toMatchObject({
			probeId: "edge.whatsapp",
			status: "pass",
			source: "telclaude-edge-runtime-harness",
		});
		expect(artifact.controls).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ name: "credentials.raw-denied", status: "pass" }),
				expect.objectContaining({ name: "whatsapp.direct-bridge-denied", status: "pass" }),
			]),
		);
	});

	it("refuses to run signed probe surfaces without the operator relay signing key", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-signed-probe-missing-key-"));
		const originalPrivateKey = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
		const originalPublicKey = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;

		try {
			delete process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
			delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
			for (const [surface, filename] of [
				["edge.whatsapp", "edge-whatsapp.json"],
				["sideeffect.ledger", "sideeffect-ledger.json"],
				["providers.approval-binding", "providers-approval-binding.json"],
				["workflow.cron", "workflow-cron.json"],
				["workflow.longrun", "workflow-longrun.json"],
				["served_mcp.memory", "served-mcp-memory.json"],
				["skills.allowlist", "skills-allowlist.json"],
			] as const) {
				const evidencePath = path.join(tempDir, filename);
				const result = await runHermesCommand([
					"hermes",
					"probe",
					surface,
					"--allow-run",
					"--json",
					"--out",
					evidencePath,
				]);
				const report = JSON.parse(result.stdout) as {
					status: string;
					surface: string;
					detail: string;
				};

				expect(result.exitCode).toBe(1);
				expect(report).toMatchObject({
					status: "input_error",
					surface,
					detail:
						"Missing relay response signing key for operator. Set OPERATOR_RPC_RELAY_PRIVATE_KEY.",
				});
				expect(fs.existsSync(evidencePath)).toBe(false);
			}
		} finally {
			restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY", originalPrivateKey);
			restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", originalPublicKey);
		}
	});

	it("refuses to run signed probe surfaces without the operator relay verification key", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-signed-probe-missing-pub-"));
		const originalPrivateKey = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
		const originalPublicKey = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		const relayKeys = generateKeyPair();

		try {
			process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
			delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
			for (const [surface, filename] of [
				["edge.whatsapp", "edge-whatsapp.json"],
				["workflow.cron", "workflow-cron.json"],
				["workflow.longrun", "workflow-longrun.json"],
				["served_mcp.memory", "served-mcp-memory.json"],
				["skills.allowlist", "skills-allowlist.json"],
			] as const) {
				const evidencePath = path.join(tempDir, filename);
				const result = await runHermesCommand([
					"hermes",
					"probe",
					surface,
					"--allow-run",
					"--json",
					"--out",
					evidencePath,
				]);
				const report = JSON.parse(result.stdout) as {
					status: string;
					surface: string;
					detail: string;
				};

				expect(result.exitCode).toBe(1);
				expect(report).toMatchObject({
					status: "input_error",
					surface,
					detail:
						"Missing relay response verification key for operator. Set OPERATOR_RPC_RELAY_PUBLIC_KEY.",
				});
				expect(fs.existsSync(evidencePath)).toBe(false);
			}
		} finally {
			restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY", originalPrivateKey);
			restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", originalPublicKey);
		}
	});

	it("uses the trusted relay public-key lock for archived feature-probe matrix generation", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-probes-lock-"));
		const evidencePath = "artifacts/hermes/probes/sideeffect-ledger.json";
		const lockPath = path.join(tempDir, "docs/hermes/relay-public-key.lock.json");
		const sourcePath = "docs/hermes/relay-public-key-source.json";
		const sourceAbsolutePath = path.join(tempDir, sourcePath);
		const relayKeys = generateKeyPair();
		const relayPublicKeySha256 = computeTextDigest(relayKeys.publicKey);
		const originalPrivateKey = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
		const originalPublicKey = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		const originalLockPath = process.env[HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK_ENV];

		try {
			writeJson(sourceAbsolutePath, {
				schemaVersion: "telclaude.hermes.rollback-relay-public-key-source.v1",
				keys: [
					{
						scope: "operator",
						envKey: HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV,
						value: relayKeys.publicKey,
						sha256: relayPublicKeySha256,
					},
				],
			});
			writeJson(lockPath, {
				schemaVersion: "telclaude.hermes.rollback-relay-public-key-lock.v1",
				keys: [
					{
						scope: "operator",
						envKey: HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV,
						value: relayKeys.publicKey,
						sha256: relayPublicKeySha256,
						source: sourcePath,
						sourceSha256: computeFileDigest(sourceAbsolutePath),
					},
				],
			});

			process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
			process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;
			process.env[HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK_ENV] = lockPath;
			const signedProbe = await runHermesCommand(
				["hermes", "probe", "sideeffect.ledger", "--allow-run", "--json", "--out", evidencePath],
				{ cwd: tempDir },
			);
			expect(signedProbe.exitCode, signedProbe.stdout).toBe(0);

			delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
			const result = await runHermesCommand(["hermes", "probes", "--json"], { cwd: tempDir });
			const matrix = JSON.parse(result.stdout) as {
				probes: Array<{ surface_id: string; status: string }>;
			};

			expect(result.exitCode).toBe(1);
			expect(matrix.probes.find((probe) => probe.surface_id === "sideeffect.ledger")?.status).toBe(
				"pass",
			);
			expect(matrix.probes.find((probe) => probe.surface_id === "edge.whatsapp")?.status).toBe(
				"fail",
			);
		} finally {
			restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY", originalPrivateKey);
			restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", originalPublicKey);
			restoreEnv(HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK_ENV, originalLockPath);
		}
	});

	it("writes runtime edge probe evidence for runtime-required edge surfaces", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-edge-runtime-cli-"));
		for (const [surface, expectedControl] of [
			["edge.whatsapp", "whatsapp.direct-bridge-denied"],
			["edge.email", "email.direct-mailbox-denied"],
			["edge.agentmail", "agentmail.direct-key-denied"],
			["edge.social", "social.unapproved-posting-denied"],
			["identity.migration", "identity.session-id-not-authority"],
			["household.scopes", "household.number-only-provider-denied"],
			["attachment.quarantine", "attachment.cross-domain-reuse-denied"],
			["outbound.policy", "outbound.replay-denied"],
			["public.social.isolation", "public-social.private-workspace-denied"],
		] as const) {
			const evidencePath = path.join(tempDir, `${surface}.json`);

			const result = await runHermesCommand([
				"hermes",
				"probe",
				surface,
				"--allow-run",
				"--json",
				"--out",
				evidencePath,
			]);
			const artifact = readJson(evidencePath) as {
				probeId: string;
				status: string;
				source: string;
				runtime?: {
					operationTrace: string[];
					checks: Array<{ name: string; status: string }>;
					observations: { ledgerEntries: number };
				};
			};

			expect(result.exitCode, result.stdout).toBe(0);
			expect(artifact).toMatchObject({
				probeId: surface,
				status: "pass",
				source: "telclaude-edge-runtime-harness",
			});
			expect(artifact.runtime?.operationTrace).toEqual(
				expect.arrayContaining(["ingest", "prepareOutbound", "executeOutbound", "status", "ack"]),
			);
			expect(artifact.runtime?.observations.ledgerEntries).toBe(1);
			expect(artifact.runtime?.checks).toEqual(
				expect.arrayContaining([
					expect.objectContaining({ name: expectedControl, status: "pass" }),
				]),
			);
		}
	});

	it("writes side-effect ledger probe evidence through the CLI harness", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-sideeffect-cli-"));
		const evidencePath = path.join(tempDir, "sideeffect-ledger.json");

		const result = await runHermesCommand([
			"hermes",
			"probe",
			"sideeffect.ledger",
			"--allow-run",
			"--json",
			"--out",
			evidencePath,
		]);
		const artifact = readJson(evidencePath) as {
			probeId: string;
			status: string;
			ran: boolean;
			source: string;
			checks: Array<{ name: string; status: string }>;
			observations: { verifierCallCount: number; providerProxyCallCount: number };
		};

		expect(result.exitCode).toBe(0);
		expect(artifact).toMatchObject({
			probeId: "sideeffect.ledger",
			status: "pass",
			ran: true,
			source: "telclaude-mcp-side-effect-ledger-harness",
		});
		expect(artifact.observations.verifierCallCount).toBeGreaterThanOrEqual(3);
		expect(artifact.observations.providerProxyCallCount).toBe(1);
		expect(artifact.checks).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ name: "ledger.provider.execute-authorized", status: "pass" }),
				expect.objectContaining({ name: "ledger.provider.proxy-relay", status: "pass" }),
				expect.objectContaining({ name: "ledger.mutated-binding-denied", status: "pass" }),
				expect.objectContaining({ name: "ledger.replay-denied", status: "pass" }),
			]),
		);
	});

	it("writes provider approval-binding probe evidence through the CLI harness", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-provider-approval-cli-"));
		const evidencePath = path.join(tempDir, "providers-approval-binding.json");

		const result = await runHermesCommand([
			"hermes",
			"probe",
			"providers.approval-binding",
			"--allow-run",
			"--json",
			"--out",
			evidencePath,
		]);
		const artifact = readJson(evidencePath) as {
			probeId: string;
			status: string;
			ran: boolean;
			source: string;
			checks: Array<{ name: string; status: string }>;
			observations: { verifierCallCount: number; providerProxyCallCount: number };
		};

		expect(result.exitCode).toBe(0);
		expect(artifact).toMatchObject({
			probeId: "providers.approval-binding",
			status: "pass",
			ran: true,
			source: "telclaude-provider-approval-binding-harness",
		});
		expect(artifact.observations.verifierCallCount).toBeGreaterThanOrEqual(5);
		expect(artifact.observations.providerProxyCallCount).toBe(1);
		expect(artifact.checks).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					name: "provider.approval-binding.valid-token-executes",
					status: "pass",
				}),
				expect.objectContaining({
					name: "provider.approval-binding.service-action-mismatch-denied",
					status: "pass",
				}),
				expect.objectContaining({
					name: "provider.approval-binding.duplicate-jti-denied",
					status: "pass",
				}),
			]),
		);
	});

	it("writes provider release-policy probe evidence through the CLI harness", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-provider-release-cli-"));
		const evidencePath = path.join(tempDir, "providers-release-policy.json");

		const result = await runHermesCommand([
			"hermes",
			"probe",
			"providers.release-policy",
			"--allow-run",
			"--json",
			"--out",
			evidencePath,
		]);
		const artifact = readJson(evidencePath) as {
			probeId: string;
			status: string;
			ran: boolean;
			source: string;
			checks: Array<{ name: string; status: string }>;
			observations: {
				releaseCount: number;
				deniedCount: number;
				auditCount: number;
				rawProviderSecretObserved: boolean;
				deniedControls: string[];
			};
		};

		expect(result.exitCode, result.stdout).toBe(0);
		expect(artifact).toMatchObject({
			probeId: "providers.release-policy",
			status: "pass",
			ran: true,
			source: "telclaude-provider-release-policy-harness",
		});
		expect(artifact.observations.releaseCount).toBe(2);
		expect(artifact.observations.auditCount).toBe(2);
		expect(artifact.observations.deniedCount).toBeGreaterThanOrEqual(7);
		expect(artifact.observations.rawProviderSecretObserved).toBe(false);
		expect(artifact.observations.deniedControls).toEqual(
			expect.arrayContaining([
				"household.cross-recipient-denied",
				"household.strong-link-required",
				"provider.urgent-health-misclassification-denied",
				"provider.sensitive-release-approval-required",
			]),
		);
		expect(artifact.checks).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					name: "provider.release.allowed-read-audited",
					status: "pass",
				}),
				expect.objectContaining({
					name: "provider.release.prepare-write-audited",
					status: "pass",
				}),
				expect.objectContaining({
					name: "provider.release.urgent-health-misclassification-denied",
					status: "pass",
				}),
				expect.objectContaining({
					name: "provider.release.unapproved-sensitive-denied",
					status: "pass",
				}),
				expect.objectContaining({
					name: "provider.release.prepare-write-benign-denied",
					status: "pass",
				}),
			]),
		);
	});

	it("writes Google provider probe evidence through the CLI harness", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-provider-google-cli-"));
		const evidencePath = path.join(tempDir, "providers-google.json");

		const result = await runHermesCommand([
			"hermes",
			"probe",
			"providers.google",
			"--allow-run",
			"--json",
			"--out",
			evidencePath,
		]);
		const artifact = readJson(evidencePath) as {
			probeId: string;
			status: string;
			ran: boolean;
			source: string;
			checks: Array<{ name: string; status: string }>;
			observations: {
				approvalVerifierCallCount: number;
				providerProxyCallCount: number;
				sidecarVerifierCallCount: number;
				ledgerReplayCode?: string;
				sidecarReplayCode?: string;
				rawOAuthObserved: boolean;
			};
		};

		expect(result.exitCode, result.stdout).toBe(0);
		expect(artifact).toMatchObject({
			probeId: "providers.google",
			status: "pass",
			ran: true,
			source: "telclaude-google-provider-harness",
		});
		expect(artifact.observations.providerProxyCallCount).toBe(2);
		expect(artifact.observations.approvalVerifierCallCount).toBeGreaterThanOrEqual(1);
		expect(artifact.observations.sidecarVerifierCallCount).toBeGreaterThanOrEqual(2);
		expect(artifact.observations.ledgerReplayCode).toBe("effect_already_executed");
		expect(artifact.observations.sidecarReplayCode).toBe("approval_replayed");
		expect(artifact.observations.rawOAuthObserved).toBe(false);
		expect(artifact.checks).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					name: "google.read-through-provider-proxy",
					status: "pass",
				}),
				expect.objectContaining({
					name: "google.approved-write-sidecar-token",
					status: "pass",
				}),
				expect.objectContaining({
					name: "google.wrong-actor-denied",
					status: "pass",
				}),
				expect.objectContaining({
					name: "google.replay-denied",
					status: "pass",
				}),
			]),
		);
	});

	it.each([
		["providers.bank", "bank"],
		["providers.clalit", "clalit"],
		["providers.government", "government"],
	] as const)("writes %s provider-domain probe evidence through the CLI harness", async (surfaceId, providerId) => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), `hermes-provider-${providerId}-cli-`));
		const evidencePath = path.join(tempDir, `${surfaceId.replace(".", "-")}.json`);

		const result = await runHermesCommand([
			"hermes",
			"probe",
			surfaceId,
			"--allow-run",
			"--json",
			"--out",
			evidencePath,
		]);
		const artifact = readJson(evidencePath) as {
			probeId: string;
			status: string;
			ran: boolean;
			source: string;
			checks: Array<{ name: string; status: string }>;
			observations: {
				providerId: string;
				providerProxyCallCount: number;
				approvalVerifierCallCount: number;
				sidecarTokenIssuerCallCount: number;
				ledgerReplayCode?: string;
				wrongActorCode?: string;
				wrongProviderScopeCode?: string;
				emergencyEscalationCode?: string;
				rawCredentialObserved: boolean;
			};
		};

		expect(result.exitCode, result.stdout).toBe(0);
		expect(artifact).toMatchObject({
			probeId: surfaceId,
			status: "pass",
			ran: true,
			source: "telclaude-provider-domain-harness",
		});
		expect(artifact.observations.providerId).toBe(providerId);
		expect(artifact.observations.providerProxyCallCount).toBe(2);
		expect(artifact.observations.approvalVerifierCallCount).toBeGreaterThanOrEqual(1);
		expect(artifact.observations.sidecarTokenIssuerCallCount).toBe(1);
		expect(artifact.observations.ledgerReplayCode).toBe("effect_already_executed");
		expect(artifact.observations.wrongActorCode).toBe("effect_authority_mismatch");
		expect(artifact.observations.wrongProviderScopeCode).toBe("effect_authority_mismatch");
		expect(artifact.observations.rawCredentialObserved).toBe(false);
		expect(artifact.checks).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					name: `${providerId}.read-through-provider-proxy`,
					status: "pass",
				}),
				expect.objectContaining({
					name: `${providerId}.prepare-write-ledger-bound`,
					status: "pass",
				}),
				expect.objectContaining({
					name: `${providerId}.approved-write-relay-sidecar-token`,
					status: "pass",
				}),
				expect.objectContaining({
					name: `${providerId}.wrong-provider-scope-denied`,
					status: "pass",
				}),
			]),
		);
		if (providerId === "clalit") {
			expect(artifact.observations.emergencyEscalationCode).toContain(
				"urgent_health_escalation_required",
			);
		}
	});

	it("derives served-MCP provider-tools evidence from the containment report", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-served-mcp-provider-cli-"));
		const sourcePath = path.join(tempDir, "execution-served-mcp-containment.json");
		const evidencePath = path.join(tempDir, "served-mcp-provider-tools.json");
		writeJson(sourcePath, servedMcpContainmentEvidence());

		const result = await runHermesCommand([
			"hermes",
			"probe",
			"served_mcp.provider-tools",
			"--from-report",
			sourcePath,
			"--json",
			"--out",
			evidencePath,
		]);
		const artifact = readJson(evidencePath) as {
			probeId: string;
			status: string;
			ran: boolean;
			source: string;
			checks: Array<{ name: string; status: string }>;
			observations: { originKind: string; providerTools: string[] };
		};

		expect(result.exitCode, result.stdout).toBe(0);
		expect(artifact).toMatchObject({
			probeId: "served_mcp.provider-tools",
			status: "pass",
			ran: true,
			source: "telclaude-served-mcp-provider-tools-from-containment",
			observations: {
				originKind: "contained-peer",
				providerTools: [
					"tc_provider_read",
					"tc_provider_prepare_write",
					"tc_provider_execute_write",
				],
			},
		});
		expect(artifact.checks).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					name: "served-mcp.provider-tools.exact-tools",
					status: "pass",
				}),
				expect.objectContaining({
					name: "served-mcp.provider-tools.execute-without-ledger-denied",
					status: "pass",
				}),
				expect.objectContaining({
					name: "served-mcp.provider-tools.authority-bound",
					status: "pass",
				}),
			]),
		);
	});

	it("registers the top-level hermes command group", () => {
		const program = new Command();
		registerHermesCommand(program);
		expect(program.commands.map((command) => command.name())).toContain("hermes");
	});

	it("does not write no-fork proof evidence without --upstream-clean", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-prove-"));
		const evidencePath = path.join(tempDir, "no-fork.json");

		const result = await runHermesCommand([
			"hermes",
			"prove",
			"--json",
			"--checkout",
			tempDir,
			"--out",
			evidencePath,
		]);
		const report = JSON.parse(result.stdout) as {
			hermesCheckoutClean: boolean;
			checks: Array<{ name: string; status: string }>;
		};

		expect(result.exitCode).toBe(2);
		expect(report.hermesCheckoutClean).toBe(false);
		expect(report.checks[0]).toMatchObject({
			name: "prove.upstreamClean",
			status: "fail",
		});
		expect(fs.existsSync(evidencePath)).toBe(false);
	});

	it("writes failing no-fork proof evidence from a non-Hermes checkout", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-prove-"));
		const evidencePath = path.join(tempDir, "no-fork.json");

		const result = await runHermesCommand([
			"hermes",
			"prove",
			"--upstream-clean",
			"--json",
			"--checkout",
			tempDir,
			"--out",
			evidencePath,
		]);
		const report = JSON.parse(result.stdout) as { hermesCheckoutClean: boolean };
		const artifact = readJson(evidencePath) as { hermesCheckoutClean: boolean };

		expect(result.exitCode).toBe(1);
		expect(report.hermesCheckoutClean).toBe(false);
		expect(artifact.hermesCheckoutClean).toBe(false);
	});

	it("does not execute or write network-probe artifacts without --allow-run", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-probe-"));
		const relay = await startProbeServer();
		try {
			const result = await runHermesCommand([
				"hermes",
				"network-probes",
				"--json",
				"--relay-url",
				relay.url,
				"--provider-url",
				relay.url,
				"--out",
				path.join(tempDir, "network-probes.json"),
				"--evidence-dir",
				path.join(tempDir, "evidence"),
			]);
			const report = JSON.parse(result.stdout) as { status: string; ran: boolean };

			expect(result.exitCode).toBe(2);
			expect(report).toMatchObject({ status: "pending", ran: false });
			expect(relay.requests.count).toBe(0);
			expect(fs.existsSync(path.join(tempDir, "network-probes.json"))).toBe(false);
			expect(fs.existsSync(path.join(tempDir, "evidence"))).toBe(false);
		} finally {
			await relay.close();
		}
	});

	it("refuses live network-probe signing without operator relay signing keys before network I/O", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-probe-no-key-"));
		const relay = await startProbeServer();
		const originalPrivateKey = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
		const originalPublicKey = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;

		try {
			delete process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
			delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
			const outPath = path.join(tempDir, "network-probes.json");
			const evidenceDir = path.join(tempDir, "evidence");
			const result = await runHermesCommand([
				"hermes",
				"network-probes",
				"--allow-run",
				"--json",
				"--relay-url",
				relay.url,
				"--provider-url",
				relay.url,
				"--out",
				outPath,
				"--evidence-dir",
				evidenceDir,
			]);
			const report = JSON.parse(result.stdout) as {
				status: string;
				ran: boolean;
				summary: string;
			};

			expect(result.exitCode).toBe(1);
			expect(report).toMatchObject({
				status: "fail",
				ran: false,
				summary:
					"Missing relay response signing key for operator. Set OPERATOR_RPC_RELAY_PRIVATE_KEY.",
			});
			expect(relay.requests.count).toBe(0);
			expect(fs.existsSync(outPath)).toBe(false);
			expect(fs.existsSync(evidenceDir)).toBe(false);
		} finally {
			restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY", originalPrivateKey);
			restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", originalPublicKey);
			await relay.close();
		}
	});

	it("writes passing network-probe artifacts from observed denials and a reachable relay control", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-probe-"));
		const relay = await startProbeServer();
		const fetchSpy = spyOnDeterministicDnsDenialFetch();
		try {
			ensureOperatorRelayKeys();
			const outPath = path.join(tempDir, "network-probes.json");
			const evidenceDir = path.join(tempDir, "evidence");
			const deniedProviderUrl = await closedProbeUrl();
			const deniedModelUrl = await closedProbeUrl();

			const result = await runHermesCommand([
				"hermes",
				"network-probes",
				"--allow-run",
				"--json",
				"--relay-url",
				relay.url,
				"--provider-url",
				requiredProviderUrlCsv(deniedProviderUrl),
				"--model-url",
				deniedModelUrl,
				"--dns-url",
				DETERMINISTIC_DNS_DENIAL_URL,
				"--vault-socket",
				path.join(tempDir, "missing-vault.sock"),
				"--firewall-sentinel",
				writeFirewallSentinel(tempDir),
				"--out",
				outPath,
				"--evidence-dir",
				evidenceDir,
			]);
			const report = JSON.parse(result.stdout) as {
				status: string;
				ran: boolean;
				bundlePath: string;
				evidence: Array<{
					id: string;
					status: string;
					attempts: Array<{ name: string; observed: string; errorCode?: string }>;
				}>;
			};
			const bundle = readJson(outPath) as {
				probes: Array<{ id: string; status: string; evidence_path: string }>;
			};

			expect(result.exitCode, result.stdout).toBe(0);
			expect(report).toMatchObject({ status: "pass", ran: true, bundlePath: outPath });
			expect(bundle.probes.map((probe) => probe.id)).toEqual(requiredNetworkProbeIds);
			expect(bundle.probes.every((probe) => probe.status === "pass")).toBe(true);
			for (const probe of bundle.probes) {
				expect(fs.existsSync(probe.evidence_path)).toBe(true);
			}
			expect(
				report.evidence
					.find((probe) => probe.id === "network.direct-provider-denied")
					?.attempts.find((attempt) => attempt.name === "provider:bank"),
			).toMatchObject({ observed: "denied", errorCode: "ECONNREFUSED" });
			expect(
				report.evidence
					.find((probe) => probe.id === "network.direct-provider-denied")
					?.attempts.find((attempt) => attempt.name === "provider:clalit"),
			).toMatchObject({ observed: "denied", errorCode: "ECONNREFUSED" });
			expect(
				report.evidence
					.find((probe) => probe.id === "network.relay-control-allowed")
					?.attempts.find((attempt) => attempt.name === "relay-control"),
			).toMatchObject({ observed: "reachable" });
		} finally {
			fetchSpy.mockRestore();
			await relay.close();
		}
	});

	it("writes contained-internal network-probe artifacts without a firewall sentinel", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-probe-"));
		const relay = await startProbeServer();
		const fetchSpy = spyOnDeterministicDnsDenialFetch();
		try {
			ensureOperatorRelayKeys();
			const result = await runHermesCommand([
				"hermes",
				"network-probes",
				"--allow-run",
				"--json",
				"--posture",
				"contained-internal",
				"--relay-url",
				relay.url,
				"--provider-url",
				requiredProviderUrlCsv(await closedProbeUrl()),
				"--model-url",
				await closedProbeUrl(),
				"--dns-url",
				DETERMINISTIC_DNS_DENIAL_URL,
				"--vault-socket",
				path.join(tempDir, "missing-vault.sock"),
				"--out",
				path.join(tempDir, "network-probes.json"),
				"--evidence-dir",
				path.join(tempDir, "evidence"),
			]);
			const report = JSON.parse(result.stdout) as {
				posture: string;
				status: string;
				evidence: Array<{
					posture: string;
					attempts: Array<{ kind: string; name: string }>;
				}>;
			};

			expect(result.exitCode, result.stdout).toBe(0);
			expect(report).toMatchObject({ posture: "contained-internal", status: "pass" });
			expect(report.evidence.every((probe) => probe.posture === "contained-internal")).toBe(true);
			expect(
				report.evidence.flatMap((probe) =>
					probe.attempts.filter((attempt) => attempt.kind === "firewall_sentinel"),
				),
			).toEqual([]);
		} finally {
			fetchSpy.mockRestore();
			await relay.close();
		}
	});

	it("writes an unsigned network-probe run report when attestation is deferred", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-deferred-"));
		const relay = await startProbeServer();
		try {
			const outPath = path.join(tempDir, "network-probes.json");
			const evidenceDir = path.join(tempDir, "evidence");
			const runReportPath = path.join(tempDir, "network-probes.run-report.json");
			const result = await runHermesCommand([
				"hermes",
				"network-probes",
				"--allow-run",
				"--defer-attestation",
				"--json",
				"--posture",
				"contained-internal",
				"--relay-url",
				relay.url,
				"--provider-url",
				requiredProviderUrlCsv(await closedProbeUrl()),
				"--model-url",
				await closedProbeUrl(),
				"--dns-url",
				await closedProbeUrl(),
				"--vault-socket",
				path.join(tempDir, "missing-vault.sock"),
				"--run-report-out",
				runReportPath,
				"--out",
				outPath,
				"--evidence-dir",
				evidenceDir,
			]);
			const report = JSON.parse(result.stdout) as {
				status: string;
				bundlePath: string;
				evidence: Array<{ attestation?: unknown }>;
			};
			const persisted = readJson(runReportPath) as { evidence: Array<{ attestation?: unknown }> };

			expect(result.exitCode, result.stdout).toBe(0);
			expect(report).toMatchObject({ status: "pass", bundlePath: runReportPath });
			expect(report.evidence.every((probe) => probe.attestation === undefined)).toBe(true);
			expect(persisted.evidence.every((probe) => probe.attestation === undefined)).toBe(true);
			expect(fs.existsSync(outPath)).toBe(false);
			expect(fs.existsSync(evidenceDir)).toBe(false);
		} finally {
			await relay.close();
		}
	});

	it("promotes a machine-observed network-probe run report into canonical artifacts", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-promote-"));
		const sourceDir = path.join(tempDir, "source");
		const outPath = path.join(tempDir, "network-probes.json");
		const evidenceDir = path.join(tempDir, "canonical");
		const evidence = requiredNetworkProbeIds.map((id) => {
			const evidencePath = path.join(sourceDir, `${id.replace(/^network\./, "")}.json`);
			const { attestation: _attestation, ...unsignedEvidence } = passingNetworkProbeEvidence(
				id,
				evidencePath,
			);
			return unsignedEvidence;
		});
		const reportPath = path.join(tempDir, "run-report.json");
		writeJson(reportPath, {
			schemaVersion: "telclaude.hermes.network-probe-run.v1",
			posture: "contained-internal",
			status: "pass",
			ran: true,
			summary: "Hermes network denial probes passed",
			bundlePath: path.join(sourceDir, "network-probes.json"),
			evidenceDir: sourceDir,
			bundle: {
				schemaVersion: 1,
				probes: evidence.map((probe) => ({
					id: probe.id,
					status: "pass",
					evidence_path: probe.evidence_path,
				})),
			},
			evidence,
		});

		const result = await runHermesCommand([
			"hermes",
			"network-probes",
			"--json",
			"--from-report",
			reportPath,
			"--out",
			outPath,
			"--evidence-dir",
			evidenceDir,
		]);
		const promoted = JSON.parse(result.stdout) as {
			status: string;
			bundlePath: string;
			evidence: Array<{ id: string; evidence_path: string }>;
		};
		const bundle = readJson(outPath) as {
			probes: Array<{ id: string; status: string; evidence_path: string }>;
		};

		expect(result.exitCode, result.stdout).toBe(0);
		expect(promoted).toMatchObject({ status: "pass", bundlePath: outPath });
		expect(bundle.probes.map((probe) => probe.id)).toEqual(requiredNetworkProbeIds);
		for (const probe of bundle.probes) {
			expect(probe.evidence_path).toContain(evidenceDir);
			expect(readJson(probe.evidence_path)).toMatchObject({
				id: probe.id,
				status: "pass",
				evidence_path: probe.evidence_path,
				attestation: {
					probeId: probe.id,
					signature: { path: "/v1/hermes.network-probe.attestation" },
				},
			});
		}
		expect(promoted.evidence.map((probe) => probe.evidence_path)).toEqual(
			bundle.probes.map((probe) => probe.evidence_path),
		);
	});

	it("refuses to promote generic provider-denial reports as contained network proof", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-promote-generic-"));
		const sourceDir = path.join(tempDir, "source");
		const outPath = path.join(tempDir, "network-probes.json");
		const evidenceDir = path.join(tempDir, "canonical");
		const evidence = requiredNetworkProbeIds.map((id) => {
			const evidencePath = path.join(sourceDir, `${id.replace(/^network\./, "")}.json`);
			const { attestation: _attestation, ...unsignedEvidence } = passingNetworkProbeEvidence(
				id,
				evidencePath,
			);
			return id === "network.direct-provider-denied"
				? {
						...unsignedEvidence,
						attempts: [
							passingFirewallSentinelAttempt(),
							passingHttpDenialAttempt("provider", "https://provider.internal/probe"),
						],
					}
				: unsignedEvidence;
		});
		const reportPath = path.join(tempDir, "run-report.json");
		writeJson(reportPath, {
			schemaVersion: "telclaude.hermes.network-probe-run.v1",
			posture: "contained-internal",
			status: "pass",
			ran: true,
			summary: "Hermes network denial probes passed",
			evidence,
		});

		const result = await runHermesCommand([
			"hermes",
			"network-probes",
			"--json",
			"--from-report",
			reportPath,
			"--out",
			outPath,
			"--evidence-dir",
			evidenceDir,
		]);
		const report = JSON.parse(result.stdout) as { status: string; summary: string };

		expect(result.exitCode).toBe(1);
		expect(report.status).toBe("fail");
		expect(report.summary).toContain(
			"network probe evidence network.direct-provider-denied provider:bank contained-internal denial proof is missing or not pass",
		);
		expect(fs.existsSync(outPath)).toBe(false);
		expect(fs.existsSync(evidenceDir)).toBe(false);
	});

	it("refuses unsigned network-probe report promotion without operator relay signing keys", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-promote-no-key-"));
		const sourceDir = path.join(tempDir, "source");
		const outPath = path.join(tempDir, "network-probes.json");
		const evidenceDir = path.join(tempDir, "canonical");
		const originalPrivateKey = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
		const originalPublicKey = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		const evidence = requiredNetworkProbeIds.map((id) => {
			const evidencePath = path.join(sourceDir, `${id.replace(/^network\./, "")}.json`);
			const { attestation: _attestation, ...unsignedEvidence } = passingNetworkProbeEvidence(
				id,
				evidencePath,
			);
			return unsignedEvidence;
		});
		const reportPath = path.join(tempDir, "run-report.json");
		writeJson(reportPath, {
			schemaVersion: "telclaude.hermes.network-probe-run.v1",
			posture: "contained-internal",
			status: "pass",
			ran: true,
			summary: "Hermes network denial probes passed",
			evidence,
		});

		try {
			delete process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
			delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
			const result = await runHermesCommand([
				"hermes",
				"network-probes",
				"--json",
				"--from-report",
				reportPath,
				"--out",
				outPath,
				"--evidence-dir",
				evidenceDir,
			]);
			const report = JSON.parse(result.stdout) as { status: string; ran: boolean; summary: string };

			expect(result.exitCode).toBe(1);
			expect(report).toMatchObject({
				status: "fail",
				ran: false,
				summary:
					"Missing relay response signing key for operator. Set OPERATOR_RPC_RELAY_PRIVATE_KEY.",
			});
			expect(fs.existsSync(outPath)).toBe(false);
			expect(fs.existsSync(evidenceDir)).toBe(false);
		} finally {
			restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY", originalPrivateKey);
			restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", originalPublicKey);
		}
	});

	it("refuses network-probe report promotion when any attempt failed", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-promote-fail-"));
		const outPath = path.join(tempDir, "network-probes.json");
		const evidenceDir = path.join(tempDir, "canonical");
		const evidence = requiredNetworkProbeIds.map((id) =>
			passingNetworkProbeEvidence(id, path.join(tempDir, `${id}.json`)),
		);
		evidence[0] = {
			...evidence[0],
			attempts: [{ ...evidence[0].attempts[0], status: "fail", observed: "unsafe" }],
		};
		const reportPath = path.join(tempDir, "run-report.json");
		writeJson(reportPath, {
			schemaVersion: "telclaude.hermes.network-probe-run.v1",
			posture: "contained-internal",
			status: "pass",
			ran: true,
			summary: "Hermes network denial probes passed",
			bundle: {
				schemaVersion: 1,
				probes: evidence.map((probe) => ({
					id: probe.id,
					status: "pass",
					evidence_path: probe.evidence_path,
				})),
			},
			evidence,
		});

		const result = await runHermesCommand([
			"hermes",
			"network-probes",
			"--json",
			"--from-report",
			reportPath,
			"--out",
			outPath,
			"--evidence-dir",
			evidenceDir,
		]);
		const report = JSON.parse(result.stdout) as { status: string; summary: string };

		expect(result.exitCode).toBe(1);
		expect(report.status).toBe("fail");
		expect(report.summary).toContain("attempt 0 status is fail");
		expect(fs.existsSync(outPath)).toBe(false);
		expect(fs.existsSync(evidenceDir)).toBe(false);
	});

	it("promotes a machine-observed model-relay report into canonical evidence", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-model-relay-promote-"));
		const sourcePath = path.join(tempDir, "model-relay-source.json");
		const outPath = path.join(tempDir, "model-relay.json");
		writeJson(sourcePath, passingModelRelayEvidence());

		const result = await runHermesCommand([
			"hermes",
			"probe",
			"model.relay",
			"--json",
			"--from-report",
			sourcePath,
			"--out",
			outPath,
		]);
		const report = JSON.parse(result.stdout) as {
			status: string;
			posture: string;
			origin: { kind: string };
		};
		const promoted = readJson(outPath);

		expect(result.exitCode, result.stdout).toBe(0);
		expect(report).toMatchObject({
			status: "pass",
			posture: "contained-internal",
			origin: { kind: "contained-peer" },
		});
		expect(promoted).toMatchObject({
			probeId: "model.relay",
			status: "pass",
			posture: "contained-internal",
		});
	});

	it("observes private-runtime status through relay operator RPC without a mode setter", async () => {
		const originalUrl = process.env.TELCLAUDE_CAPABILITIES_URL;
		const originalOperatorPrivate = process.env.OPERATOR_RPC_AGENT_PRIVATE_KEY;
		const originalOperatorPublic = process.env.OPERATOR_RPC_AGENT_PUBLIC_KEY;
		const originalOperatorRelayPrivate = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
		const originalOperatorRelayPublic = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		const keys = generateKeyPair();
		const relayKeys = generateKeyPair();
		const requests: string[] = [];
		shutdownTokenClient();
		const relay = await startProbeServer((req, res) => {
			const requestPath = req.url?.split("?")[0] ?? "";
			requests.push(requestPath);
			res.setHeader("Content-Type", "application/json");
			if (requestPath === "/v1/hermes.private-runtime.status") {
				res.end(signedRuntimeStatePayload(requestPath, "{}", hermesRuntimeState()));
				return;
			}
			res.statusCode = 404;
			res.end(JSON.stringify({ error: `not found: ${requestPath}` }));
		});
		process.env.OPERATOR_RPC_AGENT_PRIVATE_KEY = keys.privateKey;
		process.env.OPERATOR_RPC_AGENT_PUBLIC_KEY = keys.publicKey;
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;
		process.env.TELCLAUDE_CAPABILITIES_URL = new URL(relay.url).origin;
		try {
			const statusResult = await runHermesCommand([
				"hermes",
				"private-runtime",
				"status",
				"--json",
			]);

			expect(statusResult.exitCode, statusResult.stdout).toBe(0);
			expect(JSON.parse(statusResult.stdout)).toMatchObject({ effectiveValue: "1" });
			expect(privateRuntimeSubcommands()).toEqual(["status"]);
			expect(requests).toEqual(["/v1/hermes.private-runtime.status"]);
		} finally {
			await relay.close();
			shutdownTokenClient();
			restoreEnv("TELCLAUDE_CAPABILITIES_URL", originalUrl);
			restoreEnv("OPERATOR_RPC_AGENT_PRIVATE_KEY", originalOperatorPrivate);
			restoreEnv("OPERATOR_RPC_AGENT_PUBLIC_KEY", originalOperatorPublic);
			restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY", originalOperatorRelayPrivate);
			restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", originalOperatorRelayPublic);
		}
	});

	it("fails network-probes when a direct provider connection succeeds", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-probe-"));
		const relay = await startProbeServer();
		const provider = await startProbeServer();
		try {
			ensureOperatorRelayKeys();
			const result = await runHermesCommand([
				"hermes",
				"network-probes",
				"--allow-run",
				"--json",
				"--relay-url",
				relay.url,
				"--provider-url",
				provider.url,
				"--model-url",
				await closedProbeUrl(),
				"--dns-url",
				await closedProbeUrl(),
				"--vault-socket",
				path.join(tempDir, "missing-vault.sock"),
				"--firewall-sentinel",
				writeFirewallSentinel(tempDir),
				"--out",
				path.join(tempDir, "network-probes.json"),
				"--evidence-dir",
				path.join(tempDir, "evidence"),
			]);
			const report = JSON.parse(result.stdout) as {
				status: string;
				evidence: Array<{
					id: string;
					status: string;
					attempts: Array<{ name: string; observed: string; httpStatus?: number }>;
				}>;
			};

			expect(result.exitCode).toBe(1);
			expect(report.status).toBe("fail");
			expect(
				report.evidence
					.find((probe) => probe.id === "network.direct-provider-denied")
					?.attempts.find((attempt) => attempt.name === "provider"),
			).toMatchObject({ observed: "reachable", httpStatus: 204 });
		} finally {
			await provider.close();
			await relay.close();
		}
	});

	it("does not count an ambiguous denial timeout as a passing network probe", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-probe-"));
		const relay = await startProbeServer();
		const hangingProvider = await startProbeServer(() => {
			// Intentionally keep the socket open so the probe hits its own timeout path.
		});
		try {
			ensureOperatorRelayKeys();
			const result = await runHermesCommand([
				"hermes",
				"network-probes",
				"--allow-run",
				"--json",
				"--timeout-ms",
				"20",
				"--relay-url",
				relay.url,
				"--provider-url",
				hangingProvider.url,
				"--model-url",
				await closedProbeUrl(),
				"--dns-url",
				await closedProbeUrl(),
				"--vault-socket",
				path.join(tempDir, "missing-vault.sock"),
				"--firewall-sentinel",
				writeFirewallSentinel(tempDir),
				"--out",
				path.join(tempDir, "network-probes.json"),
				"--evidence-dir",
				path.join(tempDir, "evidence"),
			]);
			const report = JSON.parse(result.stdout) as {
				status: string;
				evidence: Array<{
					id: string;
					status: string;
					attempts: Array<{ name: string; observed: string }>;
				}>;
			};

			expect(result.exitCode).toBe(1);
			expect(report.status).toBe("fail");
			expect(
				report.evidence
					.find((probe) => probe.id === "network.direct-provider-denied")
					?.attempts.find((attempt) => attempt.name === "provider"),
			).toMatchObject({ observed: "inconclusive_timeout" });
		} finally {
			await hangingProvider.close();
			await relay.close();
		}
	});

	it("fails network-probes when the allowed relay control cannot connect", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-probe-"));
		ensureOperatorRelayKeys();
		const result = await runHermesCommand([
			"hermes",
			"network-probes",
			"--allow-run",
			"--json",
			"--relay-url",
			await closedProbeUrl(),
			"--provider-url",
			await closedProbeUrl(),
			"--model-url",
			await closedProbeUrl(),
			"--dns-url",
			await closedProbeUrl(),
			"--vault-socket",
			path.join(tempDir, "missing-vault.sock"),
			"--firewall-sentinel",
			writeFirewallSentinel(tempDir),
			"--out",
			path.join(tempDir, "network-probes.json"),
			"--evidence-dir",
			path.join(tempDir, "evidence"),
		]);
		const report = JSON.parse(result.stdout) as {
			status: string;
			evidence: Array<{
				id: string;
				status: string;
				attempts: Array<{ name: string; observed: string }>;
			}>;
		};

		expect(result.exitCode).toBe(1);
		expect(report.status).toBe("fail");
		expect(
			report.evidence
				.find((probe) => probe.id === "network.relay-control-allowed")
				?.attempts.find((attempt) => attempt.name === "relay-control"),
		).toMatchObject({ observed: "unreachable" });
		expect(
			report.evidence.find((probe) => probe.id === "network.direct-provider-denied"),
		).toMatchObject({ status: "pass" });
	});

	it("does not execute or write cli-headless evidence without --allow-run", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cli-probe-"));
		const evidencePath = path.join(tempDir, "evidence.json");
		const markerPath = path.join(tempDir, "ran");
		const hermesBin = writeExecutable(
			tempDir,
			`#!/bin/sh
touch "${markerPath}"
echo should-not-run
`,
		);

		const result = await runHermesCommandWithEnv(
			[
				"hermes",
				"probe",
				"execution.cli_headless",
				"--json",
				"--hermes-bin",
				hermesBin,
				"--hermes-home",
				path.join(tempDir, "home"),
				"--cwd",
				tempDir,
				"--out",
				evidencePath,
			],
			cliRelayEnv(),
		);
		const report = JSON.parse(result.stdout) as {
			status: string;
			ran: boolean;
			invocation: { args: string[] };
		};

		expect(result.exitCode).toBe(2);
		expect(report).toMatchObject({ status: "pending", ran: false });
		expect(report.invocation.args).toEqual([
			"chat",
			"-q",
			"Reply with exactly TELCLAUDE_HERMES_CLI_OK",
		]);
		expect(fs.existsSync(markerPath)).toBe(false);
		expect(fs.existsSync(evidencePath)).toBe(false);
	});

	it("fails cli-headless readiness before execution when relay model env is absent", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cli-probe-"));
		const evidencePath = path.join(tempDir, "evidence.json");
		const markerPath = path.join(tempDir, "ran");
		const hermesBin = writeExecutable(
			tempDir,
			`#!/bin/sh
touch "${markerPath}"
echo should-not-run
`,
		);

		const result = await runHermesCommand([
			"hermes",
			"probe",
			"execution.cli_headless",
			"--allow-run",
			"--json",
			"--hermes-bin",
			hermesBin,
			"--hermes-home",
			path.join(tempDir, "home"),
			"--cwd",
			tempDir,
			"--out",
			evidencePath,
		]);
		const report = JSON.parse(result.stdout) as {
			status: string;
			ran: boolean;
			summary: string;
			readiness: { status: string; gates: Array<{ name: string; status: string }> };
		};

		expect(result.exitCode).toBe(1);
		expect(report).toMatchObject({
			status: "fail",
			ran: false,
			summary: "Hermes CLI probe launch failed readiness checks",
			readiness: {
				status: "fail",
			},
		});
		expect(report.readiness.gates).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ name: "provider.openaiCodex", status: "fail" }),
				expect.objectContaining({ name: "relay.baseUrl", status: "fail" }),
				expect.objectContaining({ name: "model.present", status: "fail" }),
				expect.objectContaining({ name: "auth.relayToken", status: "fail" }),
			]),
		);
		expect(fs.existsSync(markerPath)).toBe(false);
		expect(readJson(evidencePath)).toMatchObject({ status: "fail", ran: false });
	});

	it("fails cli-headless docker exec evidence without relay proof", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cli-docker-exec-"));
		const evidencePath = path.join(tempDir, "evidence.json");
		const callsPath = path.join(tempDir, "docker-calls.txt");
		const authPayloadPath = path.join(tempDir, "auth-payload.json");
		const dockerOnlyCwd = `/container-only/telclaude-runner-${process.pid}`;
		expect(fs.existsSync(dockerOnlyCwd)).toBe(false);
		const dockerBin = writeExecutable(
			tempDir,
			`#!/bin/sh
printf '%s\\n' "$*" >> "${callsPath}"
if [ "$1" = "inspect" ]; then
  printf '%s\\n' '{"Id":"container-id","Image":"sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7","Config":{"Image":"nousresearch/hermes-agent@sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7","Hostname":"tc-hermes-contained"},"NetworkSettings":{"Networks":{"telclaude-hermes-private":{"IPAddress":"${CLI_HEADLESS_TEST_CONTAINED_IP}"}}}}'
  exit 0
fi
if [ "$1" = "exec" ] && [ "$3" = "test" ]; then
  exit 0
fi
case "$*" in
*"socket.gethostbyname"*)
  printf '%s\\n' '{"observedPeerAddress":"${CLI_HEADLESS_TEST_CONTAINED_IP}","relayResolvedAddress":"${CLI_HEADLESS_TEST_RELAY_IP}"}'
  exit 0
  ;;
*"json.load(sys.stdin)"*)
  cat >"${authPayloadPath}"
  exit 0
  ;;
*"relay-proof/latest"*)
  printf '%s\\n' 'proof endpoint unavailable' >&2
  exit 9
  ;;
esac
printf '%s\\n' 'HERMES_OK_DOCKEREXEC'
`,
		);

		const result = await runHermesCommandWithEnv(
			[
				"hermes",
				"probe",
				"execution.cli_headless",
				"--allow-run",
				"--json",
				"--docker-bin",
				dockerBin,
				"--docker-exec-container",
				"tc-hermes-contained",
				"--hermes-bin",
				"/opt/hermes/hermes",
				"--hermes-home",
				"/home/hermes/.hermes",
				"--cwd",
				dockerOnlyCwd,
				"--prompt",
				"Reply with exactly HERMES_OK_DOCKEREXEC",
				"--out",
				evidencePath,
			],
			cliRelayEnv({ HERMES_INFERENCE_MODEL: "gpt-5.5" }),
		);
		const report = JSON.parse(result.stdout) as {
			status: string;
			summary: string;
			stdoutPreview: string;
			readiness: { gates: Array<{ name: string; status: string; detail: string }> };
			relayProof?: unknown;
		};

		expect(result.exitCode).toBe(1);
		expect(report.status).toBe("fail");
		expect(report.stdoutPreview).toContain("HERMES_OK_DOCKEREXEC");
		expect(report.readiness.gates).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					name: "cwd.exists",
					status: "pass",
					detail: "Hermes probe cwd exists inside docker-exec container",
				}),
			]),
		);
		expect(report.summary).toBe(
			"Hermes CLI oneshot probe lacks relay-backed model proof: relay proof is missing",
		);
		expect(report.relayProof).toBeUndefined();
		const authPayload = readJson(authPayloadPath) as {
			suppressed_sources: { "openai-codex": string[] };
			providers: { "openai-codex": Record<string, unknown> };
			credential_pool: {
				"openai-codex": Array<{
					access_token: string;
				}>;
			};
		};
		expect(authPayload.suppressed_sources["openai-codex"]).toContain("device_code");
		expect(authPayload.providers["openai-codex"]).toEqual({
			auth_mode: "telclaude-relay",
			last_refresh: "1970-01-01T00:00:00.000Z",
		});
		const accessToken = authPayload.credential_pool["openai-codex"][0]?.access_token as string;
		expect(accessToken).not.toBe("relay-scoped-proxy-token");
		expect(
			verifyOpenAiCodexPeerBoundProxyToken(accessToken, {
				secret: "relay-scoped-proxy-token",
				peerAddress: CLI_HEADLESS_TEST_CONTAINED_IP,
			}),
		).toMatchObject({ ok: true, tokenScope: "run" });
		expect(
			verifyOpenAiCodexPeerBoundProxyToken(accessToken, {
				secret: "relay-scoped-proxy-token",
				peerAddress: CLI_HEADLESS_WRONG_CONTAINED_IP,
			}),
		).toMatchObject({ ok: false, reason: "peer address mismatch" });
		expect(JSON.stringify(report)).not.toContain("relay-scoped-proxy-token");
		const dockerCalls = fs.readFileSync(callsPath, "utf8");
		expect(dockerCalls).not.toContain("relay-scoped-proxy-token");
		expect(dockerCalls).toContain(
			"HERMES_BUNDLED_SKILLS=/home/hermes/.telclaude-curated-bundled-skills",
		);
		expect(dockerCalls).toContain("HERMES_HOME=/home/hermes/.telclaude-docker-exec/");
		expect(dockerCalls).not.toContain("HERMES_HOME=/home/hermes/.hermes");
		expect(dockerCalls).toContain("config.yaml");
		expect(dockerCalls).toContain("auth.json");
		expect(dockerCalls).toContain("secret-manifest.json");
		expect(dockerCalls).toContain("shutil.rmtree(skills_path)");
		expect(dockerCalls).toContain("shutil.copytree(curated_skills, skills_path)");
		expect(dockerCalls).not.toContain("os.chown(");
		expect(dockerCalls).toContain("os.chmod(home, 0o700)");
		expect(dockerCalls).toContain("runtime_dirs = ('sessions', 'logs', 'cron'");
		expect(dockerCalls).toContain("harden_runtime_dirs()");
		expect(dockerCalls).toContain("os.chmod(runtime_path, 0o700)");
		expect(dockerCalls).toContain("Hermes home is missing before docker exec launch");
		expect(dockerCalls).toContain("auth.lock");
		expect(dockerCalls).toContain("os.unlink(lock_path)");
		expect(dockerCalls).toContain("os.chmod(path, 0o400)");
		expect(readJson(evidencePath)).toMatchObject({
			status: "fail",
			summary: "Hermes CLI oneshot probe lacks relay-backed model proof: relay proof is missing",
		});
	}, 20_000);

	it("does not run cli-headless docker exec when auth-store preparation fails", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cli-docker-exec-"));
		const evidencePath = path.join(tempDir, "evidence.json");
		const callsPath = path.join(tempDir, "docker-calls.txt");
		const markerPath = path.join(tempDir, "ran-hermes");
		const dockerBin = writeExecutable(
			tempDir,
			`#!/bin/sh
printf '%s\\n' "$*" >> "${callsPath}"
if [ "$1" = "inspect" ]; then
  printf '%s\\n' '{"Id":"container-id","Image":"sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7","Config":{"Image":"nousresearch/hermes-agent@sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7","Hostname":"tc-hermes-contained"},"NetworkSettings":{"Networks":{"telclaude-hermes-private":{"IPAddress":"${CLI_HEADLESS_TEST_CONTAINED_IP}"}}}}'
  exit 0
fi
if [ "$1" = "exec" ] && [ "$3" = "test" ]; then
  exit 0
fi
case "$*" in
*"socket.gethostbyname"*)
  printf '%s\\n' '{"observedPeerAddress":"${CLI_HEADLESS_TEST_CONTAINED_IP}","relayResolvedAddress":"${CLI_HEADLESS_TEST_RELAY_IP}"}'
  exit 0
  ;;
esac
if [ "$1" = "exec" ] && [ "$2" = "-i" ] && [ "$4" = "python" ]; then
  cat >&2
  printf '%s\\n' 'auth store write denied' >&2
  exit 7
fi
case "$*" in
*"/opt/hermes/hermes"*)
  touch "${markerPath}"
  printf '%s\\n' 'HERMES_OK_DOCKEREXEC'
  exit 0
  ;;
esac
printf '%s\\n' "unexpected docker args: $*" >&2
exit 99
`,
		);

		const result = await runHermesCommandWithEnv(
			[
				"hermes",
				"probe",
				"execution.cli_headless",
				"--allow-run",
				"--json",
				"--docker-bin",
				dockerBin,
				"--docker-exec-container",
				"tc-hermes-contained",
				"--hermes-bin",
				"/opt/hermes/hermes",
				"--hermes-home",
				"/home/hermes/.hermes",
				"--cwd",
				"/tmp",
				"--prompt",
				"Reply with exactly HERMES_OK_DOCKEREXEC",
				"--out",
				evidencePath,
			],
			cliRelayEnv({ HERMES_INFERENCE_MODEL: "gpt-5.5" }),
		);
		const report = JSON.parse(result.stdout) as {
			status: string;
			summary: string;
			stderrPreview: string;
			stdoutPreview: string;
		};

		expect(result.exitCode).toBe(1);
		expect(report.status).toBe("fail");
		expect(report.summary).toBe(
			"Hermes CLI oneshot probe reported runtime failure: relay OpenAI Codex auth store is not configured",
		);
		expect(report.stdoutPreview).toBe("");
		expect(report.stderrPreview).toContain("failed to prepare docker exec Hermes auth store");
		expect(report.stderrPreview).toContain("[REDACTED]");
		expect(fs.existsSync(markerPath)).toBe(false);
		expect(JSON.stringify(report)).not.toContain("relay-scoped-proxy-token");
		expect(fs.readFileSync(callsPath, "utf8")).not.toContain("relay-scoped-proxy-token");
		expect(readJson(evidencePath)).toMatchObject({
			status: "fail",
			summary:
				"Hermes CLI oneshot probe reported runtime failure: relay OpenAI Codex auth store is not configured",
		});
	}, 20_000);

	it("rejects cli-headless docker exec relay proof observed after the child exits", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cli-docker-exec-"));
		const evidencePath = path.join(tempDir, "evidence.json");
		const proofPath = path.join(tempDir, "relay-proof.json");
		const callsPath = path.join(tempDir, "docker-calls.txt");
		const originalRelayPrivateKey = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
		const originalRelayPublicKey = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = cliHeadlessRelaySigningKeys.privateKey;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = cliHeadlessRelaySigningKeys.publicKey;
		fs.writeFileSync(
			proofPath,
			`${JSON.stringify(
				cliHeadlessRelayProof({
					requestId: "codex-proof-after-exit",
					model: "gpt-5.5",
					proofTokenSha256: openAiCodexRelayProofTokenSha256("HERMES_OK_DOCKEREXEC"),
					observedAt: new Date(Date.now() + 5_000).toISOString(),
				}),
			)}\n`,
		);
		const dockerBin = writeExecutable(
			tempDir,
			`#!/bin/sh
printf '%s\\n' "$*" >> "${callsPath}"
if [ "$1" = "inspect" ]; then
  printf '%s\\n' '{"Id":"container-id","Image":"sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7","Config":{"Image":"nousresearch/hermes-agent@sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7","Hostname":"tc-hermes-contained"},"NetworkSettings":{"Networks":{"telclaude-hermes-private":{"IPAddress":"${CLI_HEADLESS_TEST_CONTAINED_IP}"}}}}'
  exit 0
fi
case "$*" in
*"socket.gethostbyname"*)
  printf '%s\\n' '{"observedPeerAddress":"${CLI_HEADLESS_TEST_CONTAINED_IP}","relayResolvedAddress":"${CLI_HEADLESS_TEST_RELAY_IP}"}'
  exit 0
  ;;
*"json.load(sys.stdin)"*)
  cat >/dev/null
  exit 0
  ;;
*"relay-proof/latest"*)
  cat "${proofPath}"
  exit 0
  ;;
esac
printf '%s\\n' 'HERMES_OK_DOCKEREXEC'
`,
		);

		try {
			const result = await runHermesCommandWithEnv(
				[
					"hermes",
					"probe",
					"execution.cli_headless",
					"--allow-run",
					"--json",
					"--docker-bin",
					dockerBin,
					"--docker-exec-container",
					"tc-hermes-contained",
					"--hermes-bin",
					"/opt/hermes/hermes",
					"--hermes-home",
					"/home/hermes/.hermes",
					"--cwd",
					"/tmp",
					"--prompt",
					"Reply with exactly HERMES_OK_DOCKEREXEC",
					"--out",
					evidencePath,
				],
				cliRelayEnv({ HERMES_INFERENCE_MODEL: "gpt-5.5" }),
			);
			const report = JSON.parse(result.stdout) as {
				status: string;
				summary: string;
				stdoutPreview: string;
			};

			expect(result.exitCode).toBe(1);
			expect(report.status).toBe("fail");
			expect(report.stdoutPreview).toContain("HERMES_OK_DOCKEREXEC");
			expect(report.summary).toBe(
				"Hermes CLI oneshot probe lacks relay-backed model proof: relay proof observedAt is outside the probe window",
			);
			expect(JSON.stringify(report)).not.toContain("relay-scoped-proxy-token");
			expect(fs.readFileSync(callsPath, "utf8")).not.toContain("relay-scoped-proxy-token");
			expect(readJson(evidencePath)).toMatchObject({
				status: "fail",
				summary:
					"Hermes CLI oneshot probe lacks relay-backed model proof: relay proof observedAt is outside the probe window",
			});
		} finally {
			restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY", originalRelayPrivateKey);
			restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", originalRelayPublicKey);
		}
	}, 20_000);

	it("passes cli-headless docker exec evidence with a signed relay proof", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cli-docker-exec-"));
		const evidencePath = path.join(tempDir, "evidence.json");
		const proofPath = path.join(tempDir, "relay-proof.json");
		const callsPath = path.join(tempDir, "docker-calls.txt");
		const originalRelayPrivateKey = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
		const originalRelayPublicKey = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = cliHeadlessRelaySigningKeys.privateKey;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = cliHeadlessRelaySigningKeys.publicKey;
		const proofObservedAt = new Date(Date.now() + 12_000).toISOString();
		fs.writeFileSync(
			proofPath,
			`${JSON.stringify(
				cliHeadlessRelayProof({
					requestId: "codex-proof-docker-exec",
					model: "gpt-5.5",
					proofTokenSha256: openAiCodexRelayProofTokenSha256("HERMES_OK_DOCKEREXEC"),
					observedAt: proofObservedAt,
				}),
			)}\n`,
		);
		const dockerBin = writeExecutable(
			tempDir,
			`#!/bin/sh
printf '%s\\n' "$*" >> "${callsPath}"
if [ "$1" = "inspect" ]; then
  printf '%s\\n' '{"Id":"container-id","Image":"sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7","Config":{"Image":"nousresearch/hermes-agent@sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7","Hostname":"tc-hermes-contained"},"NetworkSettings":{"Networks":{"telclaude-hermes-private":{"IPAddress":"${CLI_HEADLESS_TEST_CONTAINED_IP}"}}}}'
  exit 0
fi
if [ "$1" = "exec" ] && [ "$3" = "test" ]; then
  exit 0
fi
case "$*" in
*"socket.gethostbyname"*)
  printf '%s\\n' '{"observedPeerAddress":"${CLI_HEADLESS_TEST_CONTAINED_IP}","relayResolvedAddress":"${CLI_HEADLESS_TEST_RELAY_IP}"}'
  exit 0
  ;;
esac
if [ "$1" = "exec" ] && [ "$2" = "-i" ] && [ "$4" = "python" ]; then
  cat >/dev/null
  exit 0
fi
case "$*" in
*"Hermes home is missing before docker exec launch"*)
  exit 0
  ;;
*"shutil.rmtree(home, ignore_errors=True)"*)
  exit 0
  ;;
*"relay-proof/latest"*)
  sleep 2
  cat "${proofPath}"
  exit 0
  ;;
*"/opt/hermes/hermes"*)
  sleep 16
  printf '%s\\n' 'HERMES_OK_DOCKEREXEC'
  exit 0
  ;;
esac
printf '%s\\n' "unexpected docker args: $*" >&2
exit 99
`,
		);

		try {
			const result = await runHermesCommandWithEnv(
				[
					"hermes",
					"probe",
					"execution.cli_headless",
					"--allow-run",
					"--json",
					"--docker-bin",
					dockerBin,
					"--docker-exec-container",
					"tc-hermes-contained",
					"--hermes-bin",
					"/opt/hermes/hermes",
					"--hermes-home",
					"/home/hermes/.hermes",
					"--cwd",
					"/tmp",
					"--prompt",
					"Reply with exactly HERMES_OK_DOCKEREXEC",
					"--out",
					evidencePath,
				],
				cliRelayEnv({ HERMES_INFERENCE_MODEL: "gpt-5.5" }),
			);
			const report = JSON.parse(result.stdout) as {
				status: string;
				summary: string;
				runtime: Record<string, unknown>;
				relayProof: Record<string, unknown>;
				stdoutPreview: string;
			};

			expect(result.exitCode, result.stdout).toBe(0);
			expect(report.status).toBe("pass");
			expect(report.summary).toBe("Hermes CLI oneshot probe completed successfully");
			expect(report.stdoutPreview).toContain("HERMES_OK_DOCKEREXEC");
			expect(report.runtime).toMatchObject({
				kind: "contained-docker",
				containerName: "tc-hermes-contained",
				networkName: "telclaude-hermes-private",
				relayResolvedAddress: CLI_HEADLESS_TEST_RELAY_IP,
				containerIpAddress: CLI_HEADLESS_TEST_CONTAINED_IP,
				observedPeerAddress: CLI_HEADLESS_TEST_CONTAINED_IP,
				provenanceSource: "docker-inspect-container-dns-and-relay-peer",
			});
			expect(report.relayProof).toMatchObject({
				source: "telclaude-openai-codex-proxy",
				path: "/backend-api/codex/responses",
				observedPeerAddress: CLI_HEADLESS_TEST_CONTAINED_IP,
				upstreamStatus: 200,
				model: "gpt-5.5",
			});
			expect(JSON.stringify(report)).not.toContain("relay-scoped-proxy-token");
			const dockerCalls = fs.readFileSync(callsPath, "utf8");
			expect(dockerCalls).not.toContain("relay-scoped-proxy-token");
			expect(dockerCalls).toContain(
				"HERMES_BUNDLED_SKILLS=/home/hermes/.telclaude-curated-bundled-skills",
			);
			expect(dockerCalls).toContain("HERMES_HOME=/home/hermes/.telclaude-docker-exec/");
			expect(dockerCalls).not.toContain("HERMES_HOME=/home/hermes/.hermes");
			expect(readJson(evidencePath)).toMatchObject({
				status: "pass",
				runtime: report.runtime,
				relayProof: report.relayProof,
			});
		} finally {
			restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY", originalRelayPrivateKey);
			restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", originalRelayPublicKey);
		}
	}, 20_000);

	it("does not execute or write api-server containment evidence without --allow-run", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-api-server-probe-"));
		const evidencePath = path.join(tempDir, "evidence.json");
		const markerPath = path.join(tempDir, "ran");
		const dockerBin = writeExecutable(
			tempDir,
			`#!/bin/sh
touch "${markerPath}"
echo should-not-run
`,
		);

		const result = await runHermesCommand([
			"hermes",
			"probe",
			"execution.api_server_containment",
			"--json",
			"--docker-bin",
			dockerBin,
			"--cwd",
			tempDir,
			"--out",
			evidencePath,
		]);
		const report = JSON.parse(result.stdout) as {
			status: string;
			ran: boolean;
			invocation: { envKeys: string[]; ephemeralAuth: { classification: string } };
		};

		expect(result.exitCode).toBe(2);
		expect(report).toMatchObject({ status: "pending", ran: false });
		expect(report.invocation.envKeys).toContain("API_SERVER_KEY");
		expect(report.invocation.ephemeralAuth.classification).toBe("ephemeral_api_auth");
		expect(fs.existsSync(markerPath)).toBe(false);
		expect(fs.existsSync(evidencePath)).toBe(false);
	});

	it("runs skills.allowlist through the CLI handler with docker-exec profile proof", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-skills-allowlist-"));
		const evidencePath = path.join(tempDir, "skills-allowlist.json");
		const callsPath = path.join(tempDir, "docker-calls.txt");
		const dockerBin = writeExecutable(
			tempDir,
			`#!/bin/sh
printf '%s\\n' "$*" >> "${callsPath}"
if [ "$1" = "network" ] && [ "$2" = "inspect" ]; then
  printf '%s\\n' '{"Internal":true,"Containers":{"contained":{"Name":"tc-hermes-contained"},"relay":{"Name":"tc-hermes-relay"}}}'
  exit 0
fi
if [ "$1" = "exec" ]; then
  shift
  while [ "$1" = "-e" ]; do
    shift 2
  done
  container="$1"
  shift
  if [ "$container" = "tc-hermes-contained" ] && [ "$1" = "node" ]; then
    prop="$5"
    case "$prop" in
      pretooluse_hook_registered|allowlisted_skill_invocation_allowed|nonallowlisted_skill_invocation_denied|social_missing_allowlist_denied|social_empty_allowlist_denied)
        printf '%s\\n' '{"level":30,"msg":"structured runtime log before proof JSON"}'
        printf '%s\\n' '{malformed runtime log before proof JSON}'
        printf '%s\\n' '{"passed":false,"detail":"stale structured runtime proof before final proof"}'
        printf '%s\\n' '{"passed":true,"detail":"docker exec PreToolUse proof","enforcementLayer":"pretooluse"}'
        printf '%s\\n' 'node warning emitted after proof JSON'
        exit 0
        ;;
    esac
  fi
  prop="$4"
  case "$prop" in
    allowlist_manifest_present|allowlisted_skill_present|nonallowlisted_skill_absent|runtime_skills_match_allowlist|skill_creation_nudge_disabled)
      printf '%s\\n' '{"passed":true,"detail":"docker exec profile proof"}'
      exit 0
      ;;
  esac
fi
printf '%s\\n' "unexpected docker args: $*" >&2
exit 99
`,
		);

		const result = await runHermesCommand([
			"hermes",
			"probe",
			"skills.allowlist",
			"--allow-run",
			"--json",
			"--docker-bin",
			dockerBin,
			"--container-name",
			"tc-hermes-contained",
			"--network",
			"telclaude-hermes-private",
			"--relay-container",
			"tc-hermes-relay",
			"--out",
			evidencePath,
		]);
		const report = JSON.parse(result.stdout) as {
			status: string;
			origin: Record<string, unknown>;
			checks: Array<{ name: string; status: string; observationLayer?: string }>;
		};

		expect(result.exitCode, result.stdout).toBe(0);
		expect(report.status).toBe("pass");
		expect(report.origin).toMatchObject({
			kind: "contained-runtime",
			containerName: "tc-hermes-contained",
			topologyInternal: true,
			relayContainerPresent: true,
		});
		expect(report.checks).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					name: "nonallowlisted_skill_absent",
					status: "pass",
					observationLayer: "docker_exec",
				}),
				expect.objectContaining({
					name: "runtime_skills_match_allowlist",
					status: "pass",
					observationLayer: "docker_exec",
				}),
				expect.objectContaining({
					name: "skill_creation_nudge_disabled",
					status: "pass",
					observationLayer: "docker_exec",
				}),
				expect.objectContaining({
					name: "nonallowlisted_skill_invocation_denied",
					status: "pass",
					observationLayer: "docker_exec",
					enforcementLayer: "pretooluse",
				}),
				expect.objectContaining({
					name: "social_missing_allowlist_denied",
					status: "pass",
					observationLayer: "docker_exec",
					enforcementLayer: "pretooluse",
				}),
			]),
		);
		expect(readJson(evidencePath)).toMatchObject({ status: "pass", ran: true });
		expect(fs.readFileSync(callsPath, "utf8")).toContain(
			"network inspect telclaude-hermes-private",
		);
		expect(fs.readFileSync(callsPath, "utf8")).toContain(
			"exec -e HERMES_HOME=/home/hermes/.hermes tc-hermes-contained python -c",
		);
		expect(fs.readFileSync(callsPath, "utf8")).toContain(
			"exec -e HERMES_HOME=/home/hermes/.hermes -e CLAUDE_CONFIG_DIR=/home/hermes/.hermes -e TELCLAUDE_CLAUDE_HOME=/home/hermes/.hermes tc-hermes-contained node",
		);
		// Bind the proof to the REAL registered-hook invocation, not merely that "node"
		// ran: assert the docker-exec command carries the module invocation, loads
		// probeSkillAllowlistPreToolUse, and passes each scenario's exact
		// property/allowlistedSkill/nonAllowlistedSkill/decision/omit args. These fail
		// if production stops importing the registered helper or sends the wrong
		// skill/allowlist/decision, instead of passing on self-consistent JSON.
		const dockerCalls = fs.readFileSync(callsPath, "utf8");
		expect(dockerCalls).toContain("node --input-type=module -e");
		expect(dockerCalls).toContain("probeSkillAllowlistPreToolUse");
		// argv order after the inline script: property allowlistedSkill nonAllowlistedSkill
		// expectedDecision omit(true|false) allowedSkillsJson
		expect(dockerCalls).toContain(
			"nonallowlisted_skill_invocation_denied plan test-driven-development deny false",
		);
		expect(dockerCalls).toContain("allowlisted_skill_invocation_allowed plan godmode allow false");
		expect(dockerCalls).toContain("social_missing_allowlist_denied plan godmode deny true");
		expect(dockerCalls).toContain("social_empty_allowlist_denied plan godmode deny false []");
	});

	it("wires relay catalog evidence into the skills.allowlist CLI live run", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-skills-catalog-cli-"));
		const catalogRoot = path.join(tempDir, "catalog");
		const skillSource = path.join(tempDir, "catalog-proof");
		const catalogMount = "/opt/data/telclaude-hermes-skill-catalog";
		const evidencePath = path.join(tempDir, "skills-allowlist.json");
		const callsPath = path.join(tempDir, "docker-calls.txt");
		fs.mkdirSync(skillSource, { recursive: true });
		fs.writeFileSync(
			path.join(skillSource, "SKILL.md"),
			`---
name: catalog-proof
description: Proves the relay catalog is observed from the contained runtime.
---

# Catalog Proof

Use this only as a harmless test skill.
`,
			"utf8",
		);
		const installed = installSkillFromDir(skillSource, {
			catalogRoot,
			origin: "test://catalog-proof",
			now: new Date("2026-01-02T03:04:05.000Z"),
		});
		const dockerBin = writeExecutable(
			tempDir,
			`#!/bin/sh
printf '%s\\n' "$*" >> "${callsPath}"
if [ "$1" = "network" ] && [ "$2" = "inspect" ]; then
  printf '%s\\n' '{"Internal":true,"Containers":{"contained":{"Name":"tc-hermes-contained"},"relay":{"Name":"tc-hermes-relay"}}}'
  exit 0
fi
if [ "$1" = "exec" ]; then
  shift
  while [ "$1" = "-e" ]; do
    shift 2
  done
  container="$1"
  shift
  if [ "$container" = "tc-hermes-contained" ] && [ "$1" = "node" ]; then
    if [ "$5" = "${catalogMount}" ]; then
      printf '%s\\n' '[{"name":"${installed.name}","sha256":"${installed.sha256}","hasScriptsDir":false,"hasSymlink":false,"hasExecutable":false}]'
      exit 0
    fi
    prop="$5"
    case "$prop" in
      pretooluse_hook_registered|allowlisted_skill_invocation_allowed|nonallowlisted_skill_invocation_denied|social_missing_allowlist_denied|social_empty_allowlist_denied)
        printf '%s\\n' '{"passed":true,"detail":"docker exec PreToolUse proof","enforcementLayer":"pretooluse"}'
        exit 0
        ;;
    esac
  fi
  prop="$4"
  case "$prop" in
    allowlist_manifest_present|allowlisted_skill_present|nonallowlisted_skill_absent|runtime_skills_match_allowlist|skill_creation_nudge_disabled)
      printf '%s\\n' '{"passed":true,"detail":"docker exec profile proof"}'
      exit 0
      ;;
  esac
fi
printf '%s\\n' "unexpected docker args: $*" >&2
exit 99
`,
		);

		const result = await withHermesCommandTestEnv(
			{
				TELCLAUDE_HERMES_SKILL_CATALOG_DIR: catalogRoot,
				TELCLAUDE_HERMES_SKILL_CATALOG_MOUNT: catalogMount,
			},
			() =>
				runHermesCommand([
					"hermes",
					"probe",
					"skills.allowlist",
					"--allow-run",
					"--json",
					"--docker-bin",
					dockerBin,
					"--container-name",
					"tc-hermes-contained",
					"--network",
					"telclaude-hermes-private",
					"--relay-container",
					"tc-hermes-relay",
					"--out",
					evidencePath,
				]),
		);
		const report = JSON.parse(result.stdout) as {
			status: string;
			catalog?: {
				mountPath: string;
				manifestSkillCount: number;
				manifestSha256: string;
				checks: Array<{ name: string; status: string; observationLayer: string }>;
			};
		};

		expect(result.exitCode, result.stdout).toBe(0);
		expect(report.status).toBe("pass");
		expect(report.catalog).toMatchObject({
			mountPath: catalogMount,
			manifestSkillCount: 1,
		});
		expect(report.catalog?.manifestSha256).toMatch(/^[a-f0-9]{64}$/);
		expect(report.catalog?.checks).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					name: "catalog_manifest_match",
					status: "pass",
					observationLayer: "docker_exec",
				}),
				expect.objectContaining({
					name: "catalog_no_scripts",
					status: "pass",
					observationLayer: "docker_exec",
				}),
			]),
		);
		expect(readJson(evidencePath)).toMatchObject({
			status: "pass",
			catalog: { mountPath: catalogMount, manifestSkillCount: 1 },
		});
		const dockerCalls = fs.readFileSync(callsPath, "utf8");
		expect(dockerCalls).toContain(`exec tc-hermes-contained node --input-type=module -e`);
		expect(dockerCalls).toContain(catalogMount);
	});

	it("wires social relay catalog evidence from the social runtime container", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-skills-social-catalog-cli-"));
		const catalogRoot = path.join(tempDir, "catalog");
		const socialCatalogRoot = path.join(tempDir, "social-catalog");
		const privateSkillSource = path.join(tempDir, "private-proof");
		const socialSkillSource = path.join(tempDir, "social-proof");
		const privateMount = "/opt/data/telclaude-hermes-skill-catalog";
		const socialMount = "/opt/data/telclaude-hermes-social-skill-catalog";
		const evidencePath = path.join(tempDir, "skills-allowlist.json");
		const callsPath = path.join(tempDir, "docker-calls.txt");
		for (const [dir, name] of [
			[privateSkillSource, "private-proof"],
			[socialSkillSource, "social-proof"],
		] as const) {
			fs.mkdirSync(dir, { recursive: true });
			fs.writeFileSync(
				path.join(dir, "SKILL.md"),
				`---\nname: ${name}\ndescription: Catalog proof fixture.\n---\n\n# ${name}\n`,
				"utf8",
			);
		}
		const privateInstalled = installSkillFromDir(privateSkillSource, {
			catalogRoot,
			origin: "test://private-proof",
			now: new Date("2026-01-02T03:04:05.000Z"),
		});
		const socialInstalled = installSkillFromDir(socialSkillSource, {
			catalogRoot: socialCatalogRoot,
			origin: "test://social-proof",
			now: new Date("2026-01-02T03:04:05.000Z"),
		});
		const dockerBin = writeExecutable(
			tempDir,
			`#!/bin/sh
printf '%s\\n' "$*" >> "${callsPath}"
if [ "$1" = "network" ] && [ "$2" = "inspect" ]; then
  printf '%s\\n' '{"Internal":true,"Containers":{"contained":{"Name":"tc-hermes-contained"},"relay":{"Name":"tc-hermes-relay"}}}'
  exit 0
fi
if [ "$1" = "exec" ]; then
  shift
  while [ "$1" = "-e" ]; do
    shift 2
  done
  container="$1"
  shift
  if [ "$1" = "node" ]; then
    if [ "$container" = "tc-hermes-contained" ] && [ "$5" = "${privateMount}" ]; then
      printf '%s\\n' '[{"name":"${privateInstalled.name}","sha256":"${privateInstalled.sha256}","hasScriptsDir":false,"hasSymlink":false,"hasExecutable":false}]'
      exit 0
    fi
    if [ "$container" = "tc-hermes-social" ] && [ "$5" = "${socialMount}" ]; then
      printf '%s\\n' '[{"name":"${socialInstalled.name}","sha256":"${socialInstalled.sha256}","hasScriptsDir":false,"hasSymlink":false,"hasExecutable":false}]'
      exit 0
    fi
    prop="$5"
    case "$prop" in
      pretooluse_hook_registered|allowlisted_skill_invocation_allowed|nonallowlisted_skill_invocation_denied|social_missing_allowlist_denied|social_empty_allowlist_denied)
        printf '%s\\n' '{"passed":true,"detail":"docker exec PreToolUse proof","enforcementLayer":"pretooluse"}'
        exit 0
        ;;
    esac
  fi
  prop="$4"
  case "$prop" in
    allowlist_manifest_present|allowlisted_skill_present|nonallowlisted_skill_absent|runtime_skills_match_allowlist|skill_creation_nudge_disabled)
      printf '%s\\n' '{"passed":true,"detail":"docker exec profile proof"}'
      exit 0
      ;;
  esac
fi
printf '%s\\n' "unexpected docker args: $*" >&2
exit 99
`,
		);

		const result = await withHermesCommandTestEnv(
			{
				TELCLAUDE_HERMES_SKILL_CATALOG_DIR: catalogRoot,
				TELCLAUDE_HERMES_SKILL_CATALOG_MOUNT: privateMount,
				TELCLAUDE_HERMES_SOCIAL_SKILL_CATALOG_DIR: socialCatalogRoot,
				TELCLAUDE_HERMES_SOCIAL_SKILL_CATALOG_MOUNT: socialMount,
			},
			() =>
				runHermesCommand([
					"hermes",
					"probe",
					"skills.allowlist",
					"--allow-run",
					"--json",
					"--docker-bin",
					dockerBin,
					"--container-name",
					"tc-hermes-contained",
					"--social-container-name",
					"tc-hermes-social",
					"--network",
					"telclaude-hermes-private",
					"--relay-container",
					"tc-hermes-relay",
					"--out",
					evidencePath,
				]),
		);
		const report = JSON.parse(result.stdout) as {
			status: string;
			catalog?: { mountPath: string; manifestSkillCount: number };
			socialCatalog?: { mountPath: string; manifestSkillCount: number };
		};

		expect(result.exitCode, result.stdout).toBe(0);
		expect(report.status).toBe("pass");
		expect(report.catalog).toMatchObject({ mountPath: privateMount, manifestSkillCount: 1 });
		expect(report.socialCatalog).toMatchObject({
			mountPath: socialMount,
			manifestSkillCount: 1,
		});
		expect(readJson(evidencePath)).toMatchObject({
			status: "pass",
			catalog: { mountPath: privateMount, manifestSkillCount: 1 },
			socialCatalog: { mountPath: socialMount, manifestSkillCount: 1 },
		});
		const dockerCalls = fs.readFileSync(callsPath, "utf8");
		expect(dockerCalls).toContain(`exec tc-hermes-contained node --input-type=module -e`);
		expect(dockerCalls).toContain(`exec tc-hermes-social node --input-type=module -e`);
		expect(dockerCalls).toContain(privateMount);
		expect(dockerCalls).toContain(socialMount);
	});

	it("fails skills.allowlist when the contained module lacks probeSkillAllowlistPreToolUse", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-skills-allowlist-neg-"));
		const evidencePath = path.join(tempDir, "skills-allowlist.json");
		// A contained runtime whose docker-exec node step cannot load the registered hook
		// helper (module missing the export) must fail closed, not pass on a self-consistent
		// JSON shape. The node step reports the load failure as passed:false.
		const dockerBin = writeExecutable(
			tempDir,
			`#!/bin/sh
if [ "$1" = "network" ] && [ "$2" = "inspect" ]; then
  printf '%s\\n' '{"Internal":true,"Containers":{"contained":{"Name":"tc-hermes-contained"},"relay":{"Name":"tc-hermes-relay"}}}'
  exit 0
fi
if [ "$1" = "exec" ]; then
  shift
  while [ "$1" = "-e" ]; do shift 2; done
  container="$1"
  shift
  if [ "$container" = "tc-hermes-contained" ] && [ "$1" = "node" ]; then
    # Profile checks pass; only the registered-hook (node) step cannot load the
    # helper export, so the probe must fail closed specifically on enforcement.
    printf '%s\\n' '{"passed":false,"detail":"probeSkillAllowlistPreToolUse not found in module","enforcementLayer":"pretooluse"}'
    exit 0
  fi
  if [ "$container" = "tc-hermes-contained" ] && [ "$1" = "python" ]; then
    printf '%s\\n' '{"passed":true,"detail":"docker exec profile proof"}'
    exit 0
  fi
fi
printf '%s\\n' "unexpected docker args: $*" >&2
exit 99
`,
		);
		const result = await runHermesCommand([
			"hermes",
			"probe",
			"skills.allowlist",
			"--allow-run",
			"--json",
			"--docker-bin",
			dockerBin,
			"--container-name",
			"tc-hermes-contained",
			"--network",
			"telclaude-hermes-private",
			"--relay-container",
			"tc-hermes-relay",
			"--out",
			evidencePath,
		]);
		const report = JSON.parse(result.stdout) as { status: string };
		expect(result.exitCode).not.toBe(0);
		expect(report.status).toBe("fail");
	});

	it("writes a passing cli-headless artifact only with runtime and relay proof", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cli-probe-"));
		const evidencePath = path.join(tempDir, "evidence.json");
		const argvPath = path.join(tempDir, "argv.txt");
		const originalRelayPublicKey = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = cliHeadlessRelaySigningKeys.publicKey;
		const hermesBin = writeExecutable(
			tempDir,
			`#!/bin/sh
printf '%s\\n' "$@" > "${argvPath}"
observed_at=$(node -e 'process.stdout.write(new Date().toISOString())')
cat > "$HERMES_HOME/runtime-evidence.json" <<'JSON'
{
  "kind": "contained-docker",
  "containerName": "tc-hermes-contained",
  "networkName": "telclaude-hermes-private",
  "containerId": "tc-hermes-contained-container-id",
  "image": "nousresearch/hermes-agent@sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7",
  "imageDigest": "sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7",
  "hostname": "tc-hermes-contained",
  "relayHost": "telclaude",
  "relayResolvedAddress": "${CLI_HEADLESS_TEST_RELAY_IP}",
  "containerIpAddress": "${CLI_HEADLESS_TEST_CONTAINED_IP}",
  "observedPeerAddress": "${CLI_HEADLESS_TEST_CONTAINED_IP}",
  "provenanceSource": "docker-inspect-container-dns-and-relay-peer"
}
JSON
node - "$HERMES_HOME/relay-proof.json" "$observed_at" <<'NODE'
const crypto = require("node:crypto");
const fs = require("node:fs");
const outputPath = process.argv[2];
const observedAt = process.argv[3];
const privateKey = ${JSON.stringify(cliHeadlessRelaySigningKeys.privateKey)};
const proof = {
  schemaVersion: "telclaude.hermes.cli-headless-relay-proof.v1",
  source: "telclaude-openai-codex-proxy",
  requestId: "codex-proof-1",
  method: "POST",
  path: "/backend-api/codex/responses",
  observedPeerAddress: "${CLI_HEADLESS_TEST_CONTAINED_IP}",
  upstreamStatus: 200,
  model: "gpt-5.3-codex",
  requestBodySha256: "sha256:${"a".repeat(64)}",
  proofTokenSha256: "${openAiCodexRelayProofTokenSha256("TELCLAUDE_HERMES_CLI_OK")}",
  observedAt,
};
const signedPayload = JSON.stringify(proof);
const sha256Hex = (value) => crypto.createHash("sha256").update(value).digest("hex");
const unsigned = {
  version: "v1",
  scope: "operator",
  timestamp: Date.now().toString(),
  nonce: crypto.randomBytes(16).toString("hex"),
  method: "POST",
  path: "/backend-api/codex/responses",
  requestBodySha256: sha256Hex(signedPayload),
  responseBodySha256: sha256Hex(signedPayload),
};
const signaturePayload = Buffer.from([
  "v1",
  "relay-response",
  unsigned.scope,
  unsigned.timestamp,
  unsigned.nonce,
  unsigned.method,
  unsigned.path,
  unsigned.requestBodySha256,
  unsigned.responseBodySha256,
].join("\\n"));
const signature = crypto.sign(null, signaturePayload, {
  key: Buffer.from(privateKey, "base64"),
  format: "der",
  type: "pkcs8",
}).toString("base64");
fs.writeFileSync(outputPath, JSON.stringify({ ...proof, signature: { ...unsigned, signature } }, null, 2) + "\\n");
NODE
node -e 'process.stdout.write("x".repeat(450) + "\\n")'
echo "TELCLAUDE_HERMES_CLI_OK"
exit 0
`,
		);

		try {
			const result = await runHermesCommandWithEnv(
				[
					"hermes",
					"probe",
					"execution.cli_headless",
					"--allow-run",
					"--json",
					"--hermes-bin",
					hermesBin,
					"--hermes-home",
					path.join(tempDir, "home"),
					"--cwd",
					tempDir,
					"--out",
					evidencePath,
				],
				cliRelayEnv(),
			);
			const report = JSON.parse(result.stdout) as { status: string; exitCode: number };
			const artifact = readJson(evidencePath) as {
				status: string;
				exitCode: number;
				stdoutPreview: string;
				provenance: { stdoutSha256: string };
			};

			expect(result.exitCode).toBe(0);
			expect(report).toMatchObject({ status: "pass", exitCode: 0 });
			expect(artifact).toMatchObject({ status: "pass", exitCode: 0 });
			expect(artifact.stdoutPreview.length).toBeGreaterThan(400);
			expect(artifact.stdoutPreview).toContain("TELCLAUDE_HERMES_CLI_OK");
			expect(artifact.stdoutPreview.endsWith("...")).toBe(false);
			expect(artifact.provenance.stdoutSha256).toBe(computeTextDigest(artifact.stdoutPreview));
			expect(artifact).toMatchObject({
				invocation: { args: ["chat", "-q", "Reply with exactly TELCLAUDE_HERMES_CLI_OK"] },
			});
			expect(fs.readFileSync(argvPath, "utf8").trim().split("\n")).toEqual([
				"chat",
				"-q",
				"Reply with exactly TELCLAUDE_HERMES_CLI_OK",
			]);
		} finally {
			restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", originalRelayPublicKey);
		}
	});

	it("validates imported cli-headless reports without writing canonical evidence", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cli-promote-"));
		const sourcePath = path.join(tempDir, "execution-cli-headless-source.json");
		writeJson(sourcePath, cliHeadlessEvidence());

		const result = await runHermesCommand([
			"hermes",
			"probe",
			"execution.cli_headless",
			"--json",
			"--from-report",
			sourcePath,
		]);
		const report = JSON.parse(result.stdout) as { status: string; modelProvider?: unknown };

		expect(result.exitCode, result.stdout).toBe(0);
		expect(report).toMatchObject({ status: "pass" });
		expect(report.modelProvider).toBeDefined();
	});

	it("validates imported cli-headless reports with the archived relay key lock", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cli-promote-lock-"));
		const sourcePath = path.join(tempDir, "execution-cli-headless-source.json");
		const sourceKeyPath = path.join(tempDir, "rollback-relay-public-key-source.json");
		const lockPath = path.join(tempDir, "rollback-relay-public-key.lock.json");
		const relayPublicKeySha256 = computeTextDigest(cliHeadlessRelaySigningKeys.publicKey);
		const originalRelayPublicKey = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		const originalLockPath = process.env[HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK_ENV];
		writeJson(sourcePath, cliHeadlessEvidence());
		writeJson(sourceKeyPath, {
			schemaVersion: "telclaude.hermes.rollback-relay-public-key-source.v1",
			keys: [
				{
					scope: "operator",
					envKey: HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV,
					value: cliHeadlessRelaySigningKeys.publicKey,
					sha256: relayPublicKeySha256,
				},
			],
		});
		writeJson(lockPath, {
			schemaVersion: "telclaude.hermes.rollback-relay-public-key-lock.v1",
			keys: [
				{
					scope: "operator",
					envKey: HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV,
					value: cliHeadlessRelaySigningKeys.publicKey,
					sha256: relayPublicKeySha256,
					source: sourceKeyPath,
					sourceSha256: computeFileDigest(sourceKeyPath),
				},
			],
		});

		try {
			delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
			process.env[HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK_ENV] = lockPath;

			const result = await runHermesCommand([
				"hermes",
				"probe",
				"execution.cli_headless",
				"--json",
				"--from-report",
				sourcePath,
			]);
			const report = JSON.parse(result.stdout) as { status: string; summary: string };

			expect(result.exitCode, result.stdout).toBe(0);
			expect(report).toMatchObject({
				status: "pass",
				summary: "Hermes CLI oneshot probe completed successfully",
			});
		} finally {
			restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", originalRelayPublicKey);
			restoreEnv(HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK_ENV, originalLockPath);
		}
	});

	it("refuses imported cli-headless reports with mismatched output provenance", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cli-promote-digest-"));
		const sourcePath = path.join(tempDir, "execution-cli-headless-source.json");
		const evidence = cliHeadlessEvidence();
		writeJson(sourcePath, {
			...evidence,
			provenance: {
				...evidence.provenance,
				stdoutSha256: `sha256:${"1".repeat(64)}`,
			},
		});

		const result = await runHermesCommand([
			"hermes",
			"probe",
			"execution.cli_headless",
			"--json",
			"--from-report",
			sourcePath,
		]);
		const report = JSON.parse(result.stdout) as { status: string; summary: string };

		expect(result.exitCode).toBe(1);
		expect(report.status).toBe("fail");
		expect(report.summary).toContain(
			"cli-headless probe report provenance stdoutSha256 does not match stdoutPreview",
		);
	});

	it("refuses to write imported cli-headless reports to evidence paths", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cli-promote-"));
		const sourcePath = path.join(tempDir, "execution-cli-headless-source.json");
		const outPath = path.join(tempDir, "execution-cli-headless.json");
		writeJson(sourcePath, cliHeadlessEvidence());

		const result = await runHermesCommand([
			"hermes",
			"probe",
			"execution.cli_headless",
			"--json",
			"--from-report",
			sourcePath,
			"--out",
			outPath,
		]);
		const report = JSON.parse(result.stdout) as { status: string; summary: string };

		expect(result.exitCode).toBe(1);
		expect(report.status).toBe("fail");
		expect(report.summary).toContain("Imported cli-headless reports cannot write evidence");
		expect(fs.existsSync(outPath)).toBe(false);
	});

	it("refuses to promote failed cli-headless reports", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cli-promote-fail-"));
		const sourcePath = path.join(tempDir, "execution-cli-headless-source.json");
		const outPath = path.join(tempDir, "execution-cli-headless.json");
		writeJson(
			sourcePath,
			cliHeadlessEvidence({
				status: "fail",
				summary: "Hermes CLI oneshot probe reported runtime failure: model API call failed",
				stdoutPreview: "API call failed after 3 retries: HTTP 429: Error\n",
			}),
		);

		const result = await runHermesCommand([
			"hermes",
			"probe",
			"execution.cli_headless",
			"--json",
			"--from-report",
			sourcePath,
			"--out",
			outPath,
		]);
		const report = JSON.parse(result.stdout) as { status: string; summary: string };

		expect(result.exitCode).toBe(1);
		expect(report.status).toBe("fail");
		expect(report.summary).toContain("cli-headless probe report status is fail");
		expect(fs.existsSync(outPath)).toBe(false);
	});

	it("writes a failing cli-headless artifact from a nonzero child exit", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cli-probe-"));
		const evidencePath = path.join(tempDir, "evidence.json");
		const hermesBin = writeExecutable(
			tempDir,
			`#!/bin/sh
echo "probe failed" >&2
exit 7
`,
		);

		const result = await runHermesCommandWithEnv(
			[
				"hermes",
				"probe",
				"execution.cli_headless",
				"--allow-run",
				"--json",
				"--hermes-bin",
				hermesBin,
				"--hermes-home",
				path.join(tempDir, "home"),
				"--cwd",
				tempDir,
				"--out",
				evidencePath,
			],
			cliRelayEnv(),
		);
		const artifact = readJson(evidencePath) as {
			status: string;
			exitCode: number;
			stderrPreview: string;
		};

		expect(result.exitCode).toBe(1);
		expect(artifact).toMatchObject({
			status: "fail",
			exitCode: 7,
			stderrPreview: "probe failed\n",
		});
	});

	it("writes a failing cli-headless artifact from a spawn error", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cli-probe-"));
		const evidencePath = path.join(tempDir, "evidence.json");

		const result = await runHermesCommandWithEnv(
			[
				"hermes",
				"probe",
				"execution.cli_headless",
				"--allow-run",
				"--json",
				"--hermes-bin",
				path.join(tempDir, "missing-hermes"),
				"--hermes-home",
				path.join(tempDir, "home"),
				"--cwd",
				tempDir,
				"--out",
				evidencePath,
			],
			cliRelayEnv(),
		);
		const artifact = readJson(evidencePath) as {
			status: string;
			exitCode: number;
			stderrPreview: string;
		};

		expect(result.exitCode).toBe(1);
		expect(artifact.status).toBe("fail");
		expect(artifact.exitCode).toBe(127);
		expect(artifact.stderrPreview).toContain("failed to launch Hermes probe");
	});

	it("writes a failing cli-headless artifact from a timed-out child", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cli-probe-"));
		const evidencePath = path.join(tempDir, "evidence.json");
		const hermesBin = writeExecutable(
			tempDir,
			`#!/bin/sh
sleep 5
`,
		);

		const result = await runHermesCommandWithEnv(
			[
				"hermes",
				"probe",
				"execution.cli_headless",
				"--allow-run",
				"--json",
				"--hermes-bin",
				hermesBin,
				"--hermes-home",
				path.join(tempDir, "home"),
				"--cwd",
				tempDir,
				"--timeout-ms",
				"20",
				"--out",
				evidencePath,
			],
			cliRelayEnv(),
		);
		const artifact = readJson(evidencePath) as {
			status: string;
			exitCode: number;
			stderrPreview: string;
		};

		expect(result.exitCode).toBe(1);
		expect(artifact.status).toBe("fail");
		expect(artifact.exitCode).toBe(124);
		expect(artifact.stderrPreview).toContain("Hermes probe timed out after 20ms");
	});

	it("does not connect or write served-MCP evidence without --allow-run", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-served-mcp-probe-"));
		const evidencePath = path.join(tempDir, "served-mcp-containment.json");
		const server = await startProbeServer();
		try {
			const result = await runHermesCommand([
				"hermes",
				"probe",
				"execution.served_mcp_containment",
				"--json",
				"--mcp-url",
				server.url,
				"--out",
				evidencePath,
			]);
			const report = JSON.parse(result.stdout) as { status: string; ran: boolean };

			expect(result.exitCode).toBe(2);
			expect(report).toMatchObject({ status: "pending", ran: false });
			expect(server.requests.count).toBe(0);
			expect(fs.existsSync(evidencePath)).toBe(false);
		} finally {
			await server.close();
		}
	});

	it("runs served_mcp.memory private and off-domain sentinel calls from distinct docker origins", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-served-mcp-memory-"));
		const evidencePath = path.join(tempDir, "served-mcp-memory.json");
		const callsPath = path.join(tempDir, "docker-calls.txt");
		const dockerBin = writeExecutable(
			tempDir,
			`#!/bin/sh
printf '%s\\n' "$*" >> "${callsPath}"
if [ "$1" != "exec" ]; then
  printf '%s\\n' "unexpected docker command: $*" >&2
  exit 99
fi
if [ "$2" = "-i" ]; then
  container="$3"
else
  container="$2"
fi
request="$(cat)"
CONTAINER_NAME="$container" REQUEST_JSON="$request" node <<'NODE'
const container = process.env.CONTAINER_NAME;
const request = JSON.parse(process.env.REQUEST_JSON || "{}");
const payload = JSON.parse(String(request.body || "{}"));
const headers = request.headers || {};
const auth = headers.authorization || headers.Authorization || "";
const tool = payload.params?.name;
const args = payload.params?.arguments || {};

function emit(body, peer) {
  console.log(JSON.stringify({
    status: 200,
    body: JSON.stringify(body),
    headers: peer ? {"x-telclaude-live-mcp-observed-peer-address": peer} : {}
  }));
}

function rpcError(message) {
  emit({error: {code: -32602, message}});
}

function hasClientSourceAuthority(value) {
  return ["source", "memorySource", "namespace", "domain", "peerAddress"].some((key) =>
    Object.prototype.hasOwnProperty.call(value, key)
  ) || Boolean(value.filters?.source);
}

if (container === "tc-hermes-contained") {
  if (auth !== "Bearer private") rpcError("private auth header missing");
  else if (payload.method === "initialize") emit({
    result: {
      ok: true,
      telclaudeProbeAuthority: {
        domain: "private",
        memorySource: "telegram:default",
        profileId: "default",
        endpointId: "tc-hermes-private",
        networkNamespace: "telclaude-hermes-private"
      }
    }
  }, "${CLI_HEADLESS_TEST_CONTAINED_IP}");
  else if (tool === "tc_memory_write") {
    const content = String(args.content || "");
    if (content.includes("off-domain sentinel")) rpcError("private container must not seed social sentinel");
    else if (hasClientSourceAuthority(args)) rpcError("client source authority rejected");
    else if (content.includes("AKIA") || /ignore all previous/i.test(content)) rpcError("memory entry rejected");
    else emit({result: {id: args.id}});
  } else if (tool === "tc_memory_search") {
    const query = String(args.query || "");
    if (hasClientSourceAuthority(args)) rpcError("client source authority rejected");
    else if (query.includes("social-sentinel")) emit({result: {entries: []}});
    else emit({result: {entries: [{id: "probe.memory.positive", content: "clean"}]}});
  } else {
    emit({result: {}});
  }
} else if (container === "tc-hermes-social-sentinel") {
  if (auth !== "Bearer social") rpcError("social auth header missing");
  else if (payload.method === "initialize") emit({
    result: {
      ok: true,
      telclaudeProbeAuthority: {
        domain: "social",
        memorySource: "social",
        profileId: "social",
        endpointId: "tc-hermes-social",
        networkNamespace: "telclaude-hermes-private"
      }
    }
  }, "${CLI_HEADLESS_WRONG_CONTAINED_IP}");
  else if (tool === "tc_memory_write" && String(args.content || "").includes("off-domain sentinel")) {
    emit({result: {id: args.id}}, "${CLI_HEADLESS_WRONG_CONTAINED_IP}");
  } else if (tool === "tc_memory_search" && String(args.query || "").includes("social-sentinel")) {
    emit({result: {entries: [{id: "probe.memory.social-sentinel", content: "social sentinel"}]}}, "${CLI_HEADLESS_WRONG_CONTAINED_IP}");
  } else {
    rpcError("social container only seeds and verifies the off-domain sentinel");
  }
} else {
  console.error("unexpected container: " + container);
  process.exit(99);
}
NODE
`,
		);

		const result = await runHermesCommandWithEnv(
			[
				"hermes",
				"probe",
				"served_mcp.memory",
				"--allow-run",
				"--json",
				"--docker-bin",
				dockerBin,
				"--mcp-url",
				"http://telclaude:8793/mcp",
				"--container-name",
				"tc-hermes-contained",
				"--expected-peer-address",
				CLI_HEADLESS_TEST_CONTAINED_IP,
				"--mcp-off-domain-container",
				"tc-hermes-social-sentinel",
				"--mcp-off-domain-peer-address",
				CLI_HEADLESS_WRONG_CONTAINED_IP,
				"--out",
				evidencePath,
			],
			{
				TELCLAUDE_HERMES_SERVED_MCP_AUTH: "Authorization: Bearer private",
				TELCLAUDE_HERMES_SERVED_MCP_OFF_DOMAIN_PEER_AUTH: "Authorization: Bearer social",
			},
		);
		const report = JSON.parse(result.stdout) as {
			status: string;
			checks: Array<{
				name: string;
				status: string;
				observedResultCount?: number;
				privateObservedResultCount?: number;
				offDomainObservedResultCount?: number;
				offDomainObservedEntryHashes?: string[];
				sentinelSeedObservedPeerAddress?: string;
				sentinelSeedExpectedPeerAddress?: string;
				sentinelSeedAuthorityDomain?: string;
				sentinelSeedMemorySource?: string;
			}>;
		};
		const calls = fs.readFileSync(callsPath, "utf8");

		expect(result.exitCode, result.stdout).toBe(0);
		expect(report.status).toBe("pass");
		expect(report.checks.find((check) => check.name === "cross_source_read_denied")).toMatchObject({
			status: "pass",
			observedResultCount: 0,
			privateObservedResultCount: 0,
			offDomainObservedResultCount: 1,
			sentinelSeedObservedPeerAddress: CLI_HEADLESS_WRONG_CONTAINED_IP,
			sentinelSeedExpectedPeerAddress: CLI_HEADLESS_WRONG_CONTAINED_IP,
			sentinelSeedAuthorityDomain: "social",
			sentinelSeedMemorySource: "social",
		});
		expect(
			report.checks.find((check) => check.name === "cross_source_read_denied")
				?.offDomainObservedEntryHashes?.[0],
		).toMatch(/^sha256:[a-f0-9]{64}$/);
		expect(calls).toContain("exec -i tc-hermes-contained node --input-type=module -e");
		expect(calls).toContain("exec -i tc-hermes-social-sentinel node --input-type=module -e");
		expect(readJson(evidencePath)).toMatchObject({ status: "pass", ran: true });
	});

	it("requests live-MCP probe tokens from the relay admin socket", async () => {
		const admin = await startLiveMcpAdminSocket(liveMcpProbeTokenResponse());
		try {
			const result = await runHermesCommand([
				"hermes",
				"live-mcp",
				"probe-tokens",
				"--socket",
				admin.socketPath,
				"--json",
				"--ttl-ms",
				"60000",
			]);
			const response = JSON.parse(result.stdout) as {
				type: string;
				env: Record<string, string>;
				tokens?: unknown;
			};

			expect(result.exitCode).toBeUndefined();
			expect(response.type).toBe("probe_tokens");
			expect(response.env.TELCLAUDE_HERMES_SERVED_MCP_AUTH).toBe(
				"Authorization: Bearer tc_mcp_conn_allowed",
			);
			expect(response.env.TELCLAUDE_HERMES_SERVED_MCP_OFF_DOMAIN_PEER_AUTH).toBe(
				"Authorization: Bearer tc_mcp_conn_off_domain_peer",
			);
			expect(response.tokens).toBeUndefined();
			expect(admin.requests[0]).toMatchObject({
				ttlMs: 60000,
				privateConnection: {
					sessionKey: "probe:private",
					profileId: "default",
					endpointId: "tc-hermes-private",
					networkNamespace: "telclaude-hermes-private",
				},
				wrongConnection: {
					sessionKey: "probe:wrong",
					profileId: "social",
					endpointId: "tc-hermes-wrong",
					networkNamespace: "telclaude-hermes-private",
				},
				offDomainConnection: {
					sessionKey: "probe:social",
					profileId: "social",
					endpointId: "tc-hermes-social",
					networkNamespace: "telclaude-hermes-private",
				},
				privateAuthority: {
					actorId: "operator:probe",
					memorySource: "telegram:default",
					providerScopes: ["bank"],
					outboundChannels: ["whatsapp"],
				},
				offDomainAuthority: {
					actorId: "social:probe",
					domain: "social",
					memorySource: "social",
					writableNamespace: "social:probe",
					providerScopes: [],
					outboundChannels: [],
				},
			});
		} finally {
			await admin.close();
		}
	});

	it("prints shell exports for live-MCP probe tokens by default", async () => {
		const admin = await startLiveMcpAdminSocket(liveMcpProbeTokenResponse());
		try {
			const result = await runHermesCommand([
				"hermes",
				"live-mcp",
				"probe-tokens",
				"--socket",
				admin.socketPath,
			]);

			expect(result.exitCode).toBeUndefined();
			expect(result.stdout).toContain(
				"export TELCLAUDE_HERMES_SERVED_MCP_AUTH='Authorization: Bearer tc_mcp_conn_allowed'",
			);
			expect(result.stdout).toContain(
				"export TELCLAUDE_HERMES_SERVED_MCP_OFF_DOMAIN_PEER_AUTH='Authorization: Bearer tc_mcp_conn_off_domain_peer'",
			);
			expect(result.stdout).toContain(
				"export TELCLAUDE_HERMES_SERVED_MCP_FORGED_AUTH='Authorization: Bearer tc_mcp_conn_forged'",
			);
			expect(result.stdout).toContain(
				"export TELCLAUDE_HERMES_SERVED_MCP_WRONG_CONNECTION_AUTH='Authorization: Bearer tc_mcp_conn_wrong'",
			);
		} finally {
			await admin.close();
		}
	});

});
