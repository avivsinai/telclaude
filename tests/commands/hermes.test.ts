import crypto from "node:crypto";
import fs from "node:fs";
import http, { type IncomingMessage, type ServerResponse } from "node:http";
import net, { type AddressInfo, type Socket } from "node:net";
import os from "node:os";
import path from "node:path";
import { Command } from "commander";
import { describe, expect, it, vi } from "vitest";
import { shutdownTokenClient } from "../../src/agent/token-client.js";
import { registerHermesCommand } from "../../src/commands/hermes.js";
import type { TelclaudeConfig } from "../../src/config/config.js";
import { REQUIRED_APPROVAL_FALLBACK_FIXTURE_IDS } from "../../src/hermes/approval-continuation.js";
import {
	buildCompatibilityLockfileDraft,
	buildCutoverInputBundleFromArtifacts,
	buildCutoverProofBundle,
	buildCutoverScopeManifestFromInventory,
	buildGuardrailManifest,
	buildGuardrailMountPlan,
	buildHermesDoctorReport,
	buildHermesGenerateDryRun,
	buildHermesQueueSnapshot,
	type CompatibilityLockfile,
	type CutoverInputBundle,
	computeHermesArtifactDigest,
	evaluateCutoverCheck,
	evaluateGuardrailMutation,
	type FeatureProbeMatrix,
	GuardrailManifestSchema,
	GuardrailMountPlanSchema,
	HERMES_ROLLBACK_CONTROL_SURFACE,
	HERMES_ROLLBACK_OBSERVATION_SURFACE,
	HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV,
	NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION,
	PRIVATE_TELEGRAM_FIXTURE_DIGEST_PATHS,
	PRIVATE_TELEGRAM_FIXTURE_REQUIREMENTS,
	parseHermesPin,
	REQUIRED_CUTOVER_NETWORK_PROBE_IDS,
	validateCompatibilityLockfile,
	validateFeatureProbeMatrix,
	writeHermesProfileGenerationProof,
} from "../../src/hermes/foundation.js";
import {
	buildHermesInventorySnapshot,
	type HermesPendingQueueSummary,
	type HermesQueueSnapshot,
} from "../../src/hermes/inventory.js";
import { startTelclaudeLiveMcpAdminServer } from "../../src/hermes/mcp/live-admin.js";
import type { TelclaudeLiveMcpProbeTokenBundle } from "../../src/hermes/mcp/live-probe-tokens.js";
import { REQUIRED_PRO_REVIEW_FILES } from "../../src/hermes/pro-review.js";
import {
	SERVED_MCP_CONTAINMENT_SCHEMA_VERSION,
	SERVED_MCP_REQUIRED_PROPERTY_NAMES,
} from "../../src/hermes/served-mcp-containment.js";
import { buildInternalResponseProof, generateKeyPair } from "../../src/internal-auth.js";

const hermesPin = { version: "0.15.1" };
const requiredNetworkProbeIds = [...REQUIRED_CUTOVER_NETWORK_PROBE_IDS];
type CutoverBundleWithoutProof = Omit<CutoverInputBundle, "cutoverProofBundle">;

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

const emptyQueues: HermesQueueSnapshot = {
	approvals: { pending: 0, expired: 0 },
	planApprovals: { pending: 0, expired: 0 },
	cards: { active: 0, expired: 0, byStatus: {} },
	backgroundJobs: { active: 0, byStatus: {} },
	pairing: { pendingRequests: 0, activePairs: 0, activeLockouts: 0 },
	allowlist: { active: 0, total: 0 },
	curator: { open: 0, byStatus: {} },
	social: { activeItems: 0 },
	webhooks: { enabled: 0, total: 0 },
	memory: { entries: 0, episodes: 0 },
};

const emptyPendingQueues: HermesPendingQueueSummary = {
	approvals: 0,
	planApprovals: 0,
	cards: 0,
	backgroundJobs: 0,
	socialItems: 0,
	curatorItems: 0,
	pairingPendingRequests: 0,
	pairingActiveLockouts: 0,
};

function pendingQueues(
	overrides: Partial<HermesPendingQueueSummary> = {},
): HermesPendingQueueSummary {
	return { ...emptyPendingQueues, ...overrides };
}

async function runHermesCommand(args: string[]): Promise<{ exitCode: unknown; stdout: string }> {
	const output: string[] = [];
	const logSpy = vi.spyOn(console, "log").mockImplementation((...values: unknown[]) => {
		output.push(values.map(String).join(" "));
	});
	const program = new Command();
	registerHermesCommand(program);
	process.exitCode = undefined;
	try {
		await program.parseAsync(["node", "telclaude", ...args]);
		return { exitCode: process.exitCode, stdout: output.join("\n") };
	} finally {
		process.exitCode = undefined;
		logSpy.mockRestore();
	}
}

async function runHermesCommandWithEnv(
	args: string[],
	env: Record<string, string>,
): Promise<{ exitCode: unknown; stdout: string }> {
	const original = Object.fromEntries(
		Object.keys(env).map((key) => [key, process.env[key] as string | undefined]),
	);
	for (const [key, value] of Object.entries(env)) {
		process.env[key] = value;
	}
	try {
		return await runHermesCommand(args);
	} finally {
		for (const [key, value] of Object.entries(original)) {
			if (value === undefined) {
				delete process.env[key];
			} else {
				process.env[key] = value;
			}
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
	return JSON.parse(fs.readFileSync(filePath, "utf8")) as unknown;
}

function writeJson(filePath: string, value: unknown): void {
	fs.mkdirSync(path.dirname(filePath), { recursive: true });
	fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function hermesRuntimeState() {
	return {
		ok: true,
		effectiveMode: "hermes",
		effectiveValue: "1",
		rolloutAllowed: true,
		rolloutEnvValue: "1",
		controlMode: "hermes",
		controlSource: "runtime-config",
		fallbackPath: "telclaude.private-runtime.legacy",
	};
}

function legacyRuntimeState() {
	return {
		ok: true,
		effectiveMode: "legacy",
		effectiveValue: "0",
		rolloutAllowed: true,
		rolloutEnvValue: "1",
		controlMode: "legacy",
		controlSource: "runtime-config",
		fallbackPath: "telclaude.private-runtime.legacy",
	};
}

function signedRuntimeStatePayload(
	requestPath: string,
	requestBody: string,
	state: ReturnType<typeof hermesRuntimeState> | ReturnType<typeof legacyRuntimeState>,
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

function minimalInventoryConfig(options: { webhooksEnabled?: boolean } = {}): TelclaudeConfig {
	return {
		security: { profile: "simple", permissions: { defaultTier: "READ_ONLY", users: {} } },
		telegram: { allowedChats: [], heartbeatSeconds: 60 },
		profiles: [],
		providers: [],
		socialServices: [],
		cron: { enabled: true, pollIntervalSeconds: 15, timeoutSeconds: 900 },
		dashboard: { enabled: false, port: 3005 },
		webhooks: { enabled: options.webhooksEnabled === true, port: 8788 },
	} as unknown as TelclaudeConfig;
}

function emptyCronOverview() {
	return {
		enabled: true,
		pollIntervalSeconds: 15,
		timeoutSeconds: 900,
		summary: { totalJobs: 0, enabledJobs: 0, runningJobs: 0, nextRunAtMs: null },
		coverage: { allSocial: false, socialServiceIds: [], hasPrivateHeartbeat: false },
		jobs: [],
	};
}

function writeFirewallSentinel(tempDir: string): string {
	const sentinelPath = path.join(tempDir, "firewall-active");
	fs.writeFileSync(sentinelPath, "active\n", "utf8");
	return sentinelPath;
}

function writePassingNetworkProbeBundle() {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-network-"));
	return {
		schemaVersion: 1 as const,
		probes: requiredNetworkProbeIds.map((id) => {
			const evidencePath = path.join(tempDir, `${id.replace(/^network\./, "")}.json`);
			writeJson(evidencePath, passingNetworkProbeEvidence(id, evidencePath));
			return {
				id,
				status: "pass" as const,
				evidence_path: evidencePath,
			};
		}),
	};
}

function writeNoForkProof(overrides: Record<string, unknown> = {}) {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-nofork-"));
	const evidencePath =
		typeof overrides.evidence_path === "string"
			? overrides.evidence_path
			: path.join(tempDir, "no-fork.json");
	const proof = {
		schemaVersion: 1,
		hermesCheckoutClean: true,
		evidence_path: evidencePath,
		checkoutPath: "/home/user/MyProjects/hermes-agent-v2026.5.29",
		expectedRef: "v2026.5.29",
		expectedVersion: "0.15.1",
		head: "a".repeat(40),
		expectedRefCommit: "a".repeat(40),
		exactTags: ["v2026.5.29"],
		statusPorcelain: "",
		diffExitCode: 0,
		cachedDiffExitCode: 0,
		checks: [
			{
				name: "checkout.present",
				status: "pass",
				detail: "Hermes checkout found at pinned tag",
			},
			{
				name: "checkout.head",
				status: "pass",
				detail: "HEAD is pinned commit",
			},
			{
				name: "checkout.expectedRef",
				status: "pass",
				detail: "v2026.5.29 resolves to pinned commit",
			},
			{
				name: "checkout.pinned",
				status: "pass",
				detail: "HEAD matches pinned Hermes ref v2026.5.29",
			},
			{
				name: "checkout.statusClean",
				status: "pass",
				detail: "git status porcelain is clean",
			},
			{
				name: "checkout.diffClean",
				status: "pass",
				detail: "git diff --quiet is clean",
			},
			{
				name: "checkout.indexClean",
				status: "pass",
				detail: "git diff --cached --quiet is clean",
			},
		],
		...overrides,
	};
	writeJson(evidencePath, proof);
	return proof;
}

function writeRollbackRehearsal(overrides: Record<string, unknown> = {}) {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-rollback-"));
	const evidencePath =
		typeof overrides.evidence_path === "string"
			? overrides.evidence_path
			: path.join(tempDir, "rollback-rehearsal.json");
	const relayKeys = generateKeyPair();
	process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
	process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;
	const relayPublicKey = {
		scope: "operator",
		envKey: HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV,
		value: relayKeys.publicKey,
		sha256: `sha256:${crypto.createHash("sha256").update(relayKeys.publicKey).digest("hex")}`,
		source: "test-fixture",
	};
	const rehearsal = {
		schemaVersion: 1,
		passed: true,
		evidence_path: evidencePath,
		allowedToRun: true,
		observedBeforeValue: "1",
		observedAfterValue: "0",
		observedFallbackPath: "telclaude.private-runtime.legacy",
		observedAt: "2026-05-30T00:00:00.000Z",
		controlSurface: HERMES_ROLLBACK_CONTROL_SURFACE,
		observationSurface: HERMES_ROLLBACK_OBSERVATION_SURFACE,
		observedBeforeSource: "relay-effective-mode",
		observedAfterSource: "relay-effective-mode",
		observedAfterControlSource: "runtime-config",
		relayPublicKey,
		signedRelayTranscripts: {
			before: signedRelayTranscript(
				"/v1/hermes.private-runtime.status",
				"{}",
				hermesRuntimeState(),
			),
			afterControl: signedRelayTranscript(
				"/v1/hermes.private-runtime.mode",
				JSON.stringify({ mode: "legacy" }),
				legacyRuntimeState(),
			),
			after: signedRelayTranscript("/v1/hermes.private-runtime.status", "{}", legacyRuntimeState()),
		},
		checks: [
			{
				name: "rollback.allowed",
				status: "pass",
				detail: "operator allowed a real rollback rehearsal",
			},
			{
				name: "rollback.relayProofs",
				status: "pass",
				detail: "relay signed every rollback observation",
			},
			{
				name: "rollback.flagBefore",
				status: "pass",
				detail: "TELCLAUDE_HERMES_PRIVATE_RUNTIME was observed enabled before rollback",
			},
			{
				name: "rollback.flagAfter",
				status: "pass",
				detail: "TELCLAUDE_HERMES_PRIVATE_RUNTIME was observed disabled after rollback",
			},
			{
				name: "rollback.fallbackPath",
				status: "pass",
				detail: "pre-Hermes fallback path observed",
			},
			{
				name: "rollback.controlSurface",
				status: "pass",
				detail: "relay durable runtime config accepted legacy mode",
			},
			{
				name: "rollback.observedSources",
				status: "pass",
				detail: "rollback observations came from relay effective-mode status",
			},
		],
		...overrides,
	};
	writeJson(evidencePath, rehearsal);
	return rehearsal;
}

function signedRelayTranscript(
	requestPath: string,
	requestBody: string,
	state: ReturnType<typeof hermesRuntimeState> | ReturnType<typeof legacyRuntimeState>,
) {
	const responseBody = JSON.stringify(state);
	return {
		request: { method: "POST", path: requestPath, body: requestBody },
		responseBody,
		proof: buildInternalResponseProof("POST", requestPath, requestBody, responseBody, {
			scope: "operator",
		}),
	};
}

function writeFixtureResults() {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-fixtures-"));
	const reportPath = path.join(tempDir, "private-telegram-vitest.json");
	writeJson(reportPath, privateTelegramVitestReport());
	const reportDigest = `sha256:${crypto
		.createHash("sha256")
		.update(fs.readFileSync(reportPath))
		.digest("hex")}`;
	const invocation = privateTelegramFixtureInvocation(reportPath, reportDigest);
	const fixtures = PRIVATE_TELEGRAM_FIXTURE_REQUIREMENTS.map((requirement) => {
		const evidencePath = path.join(tempDir, `${requirement.id}.json`);
		writeJson(evidencePath, {
			schemaVersion: "telclaude.hermes.fixture-evidence.v1",
			id: requirement.id,
			status: "pass",
			ran: true,
			evidence_path: evidencePath,
			observedAt: "2026-05-30T00:00:00.000Z",
			provenance: {
				runner: "vitest-json",
				source: "machine-observed-test-report",
			},
			testReport: {
				path: reportPath,
				sha256: reportDigest,
				requiredTests: requirement.requiredTests,
				requiredAssertions: requirement.requiredAssertions,
			},
			invocation,
			checks: requirement.requiredTests.map((testName) => ({
				name: testName,
				status: "pass",
				detail: "required fixture assertion passed in machine-observed Vitest report",
			})),
		});
		return { id: requirement.id, status: "pass" as const, evidence_path: evidencePath };
	});
	return { schemaVersion: 1 as const, results: fixtures };
}

function privateTelegramFixtureInvocation(reportPath: string, reportDigest: string) {
	return {
		command: [
			"pnpm",
			"exec",
			"vitest",
			"run",
			"tests/integration/telegram-control-plane.replay.test.ts",
			"tests/telegram/command-gating.test.ts",
			"--reporter=json",
			`--outputFile=${reportPath}`,
		],
		cwd: process.cwd(),
		exitCode: 0,
		startedAt: "2026-05-30T00:00:00.000Z",
		endedAt: "2026-05-30T00:00:01.000Z",
		reportPath,
		reportSha256: reportDigest,
		sourceDigests: Object.fromEntries(
			PRIVATE_TELEGRAM_FIXTURE_DIGEST_PATHS.map((sourcePath) => [
				sourcePath,
				`sha256:${crypto
					.createHash("sha256")
					.update(fs.readFileSync(path.resolve(sourcePath)))
					.digest("hex")}`,
			]),
		),
	};
}

function privateTelegramVitestReport() {
	return {
		success: true,
		numFailedTests: 0,
		numFailedTestSuites: 0,
		testResults: [
			{
				name: "tests/integration/telegram-control-plane.replay.test.ts",
				status: "passed",
				assertionResults: PRIVATE_TELEGRAM_FIXTURE_REQUIREMENTS[0].requiredTests.map(
					(testName) => ({
						fullName: testName,
						status: "passed",
					}),
				),
			},
			{
				name: "tests/telegram/command-gating.test.ts",
				status: "passed",
				assertionResults: PRIVATE_TELEGRAM_FIXTURE_REQUIREMENTS[1].requiredTests.map(
					(testName) => ({
						fullName: testName,
						status: "passed",
					}),
				),
			},
		],
	};
}

function passingNetworkProbeEvidence(id: string, evidencePath: string) {
	return {
		schemaVersion: NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION,
		id,
		posture: "contained-internal",
		status: "pass",
		ran: true,
		summary:
			id === "network.relay-control-allowed"
				? `${id} observed expected relay reachability`
				: `${id} observed only expected denials`,
		generatedAt: "2026-05-30T00:00:00.000Z",
		evidence_path: evidencePath,
		attempts: [passingFirewallSentinelAttempt(), passingNetworkProbeAttempt(id)],
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
			observedPeerAddress: "172.30.92.11",
			observedPeerSource: "server-peer-echo",
			expectedPeerAddress: "172.30.92.11",
			expectedPeerSource: "configured-contained-ip",
			detail: "model relay peer origin was observed by the relay endpoint",
		},
		observation: {
			relayUrl: "http://telclaude:8790/v1/models",
			directModelUrl: "https://api.anthropic.com/v1/models",
			profileDir: "/home/hermes/.hermes",
			scannedProfileFiles: ["/home/hermes/.hermes/config.yaml"],
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

function passingNetworkProbeAttempt(id: string) {
	switch (id) {
		case "network.relay-control-allowed":
			return {
				name: "relay-control",
				kind: "http",
				target: "http://127.0.0.1/relay-control",
				expectation: "allow",
				status: "pass",
				observed: "reachable",
				detail: "allowed control reached relay with HTTP status 204",
				durationMs: 1,
				httpStatus: 204,
			};
		case "network.direct-vault-denied":
			return {
				name: "vault-socket",
				kind: "unix_socket",
				target: "/run/vault/vault.sock",
				expectation: "deny",
				status: "pass",
				observed: "absent",
				detail: "vault socket path is absent from the probe environment",
			};
		case "network.dns-exfil-denied":
			return {
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
			};
		case "network.direct-provider-denied":
			return passingHttpDenialAttempt("provider", "https://provider.internal/probe");
		case "network.direct-model-provider-denied":
			return passingHttpDenialAttempt(
				"model-provider",
				"https://chatgpt.com/backend-api/codex/models?client_version=1.0.0",
			);
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

function makeCutoverProofBundle(bundle: CutoverBundleWithoutProof) {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-proof-bundle-"));
	const paths = writeCutoverProofSourceArtifacts(tempDir, bundle);
	return buildCutoverProofBundle({
		hermes: bundle.lockfile.hermes,
		wrapperVersion: bundle.lockfile.wrapperPackageVersion,
		now: new Date("2026-05-31T00:00:00.000Z"),
		artifacts: {
			inventory: proofArtifact(paths.inventory, "pnpm dev hermes inventory --json", [
				"inputs.inventory",
			]),
			scopeManifest: proofArtifact(paths.scopeManifest, "pnpm dev hermes cutover-scope --json", [
				"inputs.scopeManifest",
				"workflow.scope",
			]),
			decisionLog: proofArtifact(paths.decisionLog, "pnpm dev hermes decision-log --json", [
				"inputs.decisionLog",
				"decisions.resolved",
			]),
			compatibilityLockfile: proofArtifact(
				paths.compatibilityLockfile,
				"pnpm dev hermes compat-lock --dry-run --json",
				["inputs.lockfile", "lockfile.consistent"],
			),
			featureProbeMatrix: proofArtifact(paths.featureProbeMatrix, "pnpm dev hermes probes --json", [
				"inputs.featureProbeMatrix",
				"featureProbes.pass",
			]),
			fixtureResults: proofArtifact(paths.fixtureResults, "pnpm dev hermes fixtures --json", [
				"inputs.fixtureResults",
				"fixtures.pass",
			]),
			noForkProof: proofArtifact(
				paths.noForkProof,
				"pnpm dev hermes prove --upstream-clean --p0 --json",
				["inputs.noForkProof", "nofork.clean"],
			),
			networkProbeBundle: proofArtifact(
				paths.networkProbeBundle,
				"pnpm dev hermes network-probes --json",
				["inputs.networkProbes", "networkProbes.pass"],
			),
			queueSnapshot: proofArtifact(paths.queueSnapshot, "pnpm dev hermes queue-snapshot --json", [
				"inputs.queueSnapshot",
				"queues.owned",
			]),
			rollbackEvidence: proofArtifact(
				paths.rollbackEvidence,
				"pnpm dev hermes rollback-rehearsal --json",
				["inputs.rollbackRehearsal", "rollback.rehearsed"],
			),
		},
	});
}

function writeCutoverProofSourceArtifacts(tempDir: string, bundle: CutoverBundleWithoutProof) {
	const paths = {
		inventory: path.join(tempDir, "inventory.json"),
		scopeManifest: path.join(tempDir, "scope.json"),
		decisionLog: path.join(tempDir, "decisions.json"),
		compatibilityLockfile: path.join(tempDir, "lockfile.json"),
		featureProbeMatrix: path.join(tempDir, "feature-probes.json"),
		fixtureResults: path.join(tempDir, "fixtures.json"),
		noForkProof: path.join(tempDir, "nofork.json"),
		networkProbeBundle: path.join(tempDir, "network-probes.json"),
		queueSnapshot: path.join(tempDir, "queue.json"),
		rollbackEvidence: path.join(tempDir, "rollback.json"),
	};
	writeJson(paths.inventory, bundle.inventory);
	writeJson(paths.scopeManifest, bundle.scopeManifest);
	writeJson(paths.decisionLog, bundle.decisionLog);
	writeJson(paths.compatibilityLockfile, bundle.lockfile);
	writeJson(paths.featureProbeMatrix, bundle.featureProbeMatrix);
	writeJson(paths.fixtureResults, bundle.fixtureResults);
	writeJson(paths.noForkProof, bundle.noForkProof);
	writeJson(paths.networkProbeBundle, bundle.networkProbes);
	writeJson(paths.queueSnapshot, bundle.queueSnapshot);
	writeJson(paths.rollbackEvidence, bundle.rollbackRehearsal);
	return paths;
}

function proofArtifact(artifactPath: string, sourceCommand: string, gateIds: string[]) {
	return { artifactPath, sourceCommand, gateIds, checkIds: gateIds };
}

function safeCutoverBundle(overrides: Partial<CutoverInputBundle> = {}): CutoverInputBundle {
	const noForkProof = writeNoForkProof();
	const lockfile = { ...compatLockfile, noForkProofEvidencePath: noForkProof.evidence_path };
	const base: CutoverBundleWithoutProof = {
		schemaVersion: 1,
		inventory: {
			generatedAt: "2026-05-29T00:00:00Z",
			status: "complete",
			summary: {
				pendingQueues: pendingQueues(),
			},
			workflows: [
				{
					workflow_id: "private.telegram.basic",
					owner: "operator",
					trust_domain: "private",
					active: true,
				},
			],
		},
		scopeManifest: {
			schemaVersion: 1,
			workflows: [
				{
					workflow_id: "private.telegram.basic",
					owner: "operator",
					trust_domain: "private",
					current_behavior: "Telclaude handles a private Telegram chat through the relay.",
					hermes_target_behavior: "Hermes runs behind the Telclaude edge with relay-owned secrets.",
					cutover_class: "P0",
					cutover_requirement: "Pinned Hermes wrapper parity fixture must pass.",
					status: "included",
					rollback_owner: "operator",
					fixture_ids: ["fixture.private.telegram.basic"],
					negative_fixture_ids: ["fixture.private.telegram.basic.deny"],
					required_surface_ids: ["edge.whatsapp.plugin-adapter"],
					unresolved_decision_ids: [],
				},
			],
		},
		decisionLog: { schemaVersion: 1, decisions: [] },
		lockfile,
		featureProbeMatrix,
		featureProbeEvidence: {
			schemaVersion: 1,
			results: featureProbeMatrix.probes.map((probe) => ({
				surface_id: probe.surface_id,
				status: "pass" as const,
				evidence_path: probe.evidence_path,
				detail: "test fixture observed feature probe pass",
			})),
		},
		fixtureResults: writeFixtureResults(),
		noForkProof,
		networkProbes: writePassingNetworkProbeBundle(),
		queueSnapshot: { unownedActiveCount: 0 },
		rollbackRehearsal: writeRollbackRehearsal(),
	};
	const { cutoverProofBundle, ...bundleOverrides } = overrides;
	const merged: CutoverBundleWithoutProof = { ...base, ...bundleOverrides };
	const hasProfileProofOverride = Object.hasOwn(overrides, "profileGenerationProof");
	const profileGenerationProof = hasProfileProofOverride
		? merged.profileGenerationProof
		: writeHermesProfileGenerationProof({
				pin: merged.lockfile.hermes,
				outDir: fs.mkdtempSync(path.join(os.tmpdir(), "hermes-profile-fixture-")),
				lockfile: merged.lockfile,
				evidencePath: path.join(
					fs.mkdtempSync(path.join(os.tmpdir(), "hermes-profile-proof-")),
					"profile-generation-proof.json",
				),
				now: "2026-05-29T00:00:00Z",
			});
	const hasDecisionOverride = Object.hasOwn(overrides, "decisionLog");
	const withoutProof: CutoverBundleWithoutProof = {
		...merged,
		profileGenerationProof,
		decisionLog: hasDecisionOverride
			? merged.decisionLog
			: {
					schemaVersion: 1,
					decisions: [
						{
							id: "D-profile-generation",
							status: "accepted",
							owner: "operator",
							deadline_phase: "Phase 1",
							accepted_answer:
								"Generated Hermes profiles are produced by the checked profile generator.",
							evidence_path: profileGenerationProof?.evidence_path,
							affected_workflows: ["private.telegram.basic"],
							cutover_impact: "Profile generation proof is required before private cutover.",
						},
					],
				},
	};
	return {
		...withoutProof,
		cutoverProofBundle: cutoverProofBundle ?? makeCutoverProofBundle(withoutProof),
	};
}

function cliHeadlessProbe(evidencePath: string, status: "pass" | "fail" | "skip" = "pass") {
	return {
		surface_id: "execution.cli_headless",
		hermes_pin: hermesPin,
		documented_seam: "Hermes top-level -z/--oneshot mode",
		probe_command: "pnpm dev hermes probe execution.cli_headless --allow-run",
		expected_result: "Wrapper launches pinned Hermes and receives a final response",
		negative_probe: "Credential-shaped launch material is denied before spawn",
		evidence_path: evidencePath,
		lockfile_key: "featureProbes.execution.cliHeadless",
		security_scope: "headless-availability-only" as const,
		approval_equivalent: false,
		failure_outcome: "disable" as const,
		status,
	};
}

function cliHeadlessCutoverBundle(
	evidencePath: string,
	matrixStatus: "pass" | "fail" | "skip" = "pass",
) {
	const probe = cliHeadlessProbe(evidencePath, matrixStatus);
	const featureProbeMatrix = {
		schemaVersion: 1 as const,
		probes: [probe],
	};
	const base = safeCutoverBundle();
	return safeCutoverBundle({
		inventory: {
			generatedAt: "2026-05-29T00:00:00Z",
			workflows: [
				{
					workflow_id: "private.telegram.basic",
					owner: "operator",
					trust_domain: "private",
					active: true,
				},
			],
			status: "complete",
			summary: {
				pendingQueues: pendingQueues(),
			},
		},
		scopeManifest: {
			schemaVersion: 1,
			workflows: [
				{
					...base.scopeManifest.workflows[0],
					required_surface_ids: ["execution.cli_headless"],
				},
			],
		},
		featureProbeMatrix,
		noForkProof: base.noForkProof,
		lockfile: {
			...compatLockfile,
			featureProbeMatrixDigest: computeHermesArtifactDigest(featureProbeMatrix),
			featureProbes: [
				{
					surface_id: "execution.cli_headless",
					status: "pass",
					evidence_path: evidencePath,
				},
			],
			adapterApiSignatures: {
				"execution.cli_headless": `sha256:${"c".repeat(64)}`,
			},
			noForkProofEvidencePath: base.noForkProof.evidence_path,
		},
	});
}

function approvalContinuationProbe(
	evidencePath: string,
	status: "pass" | "fail" | "skip" = "pass",
	surfaceId = "execution.approval_continuation",
) {
	return {
		surface_id: surfaceId,
		hermes_pin: hermesPin,
		documented_seam: "Hermes MCP approval fallback through Telclaude MCP bridge",
		probe_command: "pnpm dev hermes probe execution.approval_continuation --allow-run",
		expected_result:
			"Prepare/approve/execute fallback traverses registry, bridge, ledger, verifier, and JTI",
		negative_probe: "Wrong actor, stale request, replay, and mutated binding are denied",
		evidence_path: evidencePath,
		lockfile_key:
			surfaceId === "approval.continuation"
				? "featureProbes.approval.continuation"
				: "featureProbes.execution.approvalContinuation",
		security_scope: "approval-continuation" as const,
		approval_equivalent: true,
		failure_outcome: "disable" as const,
		status,
	};
}

function approvalContinuationCutoverBundle(
	evidencePath: string,
	matrixStatus: "pass" | "fail" | "skip" = "pass",
	surfaceId = "execution.approval_continuation",
) {
	const probe = approvalContinuationProbe(evidencePath, matrixStatus, surfaceId);
	const featureProbeMatrix = {
		schemaVersion: 1 as const,
		probes: [probe],
	};
	const base = safeCutoverBundle();
	return safeCutoverBundle({
		inventory: {
			generatedAt: "2026-05-29T00:00:00Z",
			workflows: [
				{
					workflow_id: "private.telegram.basic",
					owner: "operator",
					trust_domain: "private",
					active: true,
				},
			],
			status: "complete",
			summary: {
				pendingQueues: pendingQueues(),
			},
		},
		scopeManifest: {
			schemaVersion: 1,
			workflows: [
				{
					...base.scopeManifest.workflows[0],
					required_surface_ids: [surfaceId],
				},
			],
		},
		featureProbeMatrix,
		noForkProof: base.noForkProof,
		lockfile: {
			...compatLockfile,
			featureProbeMatrixDigest: computeHermesArtifactDigest(featureProbeMatrix),
			featureProbes: [
				{
					surface_id: surfaceId,
					status: "pass",
					evidence_path: evidencePath,
				},
			],
			adapterApiSignatures: {
				[surfaceId]: `sha256:${"d".repeat(64)}`,
			},
			noForkProofEvidencePath: base.noForkProof.evidence_path,
		},
	});
}

function sideEffectLedgerProbe(evidencePath: string, status: "pass" | "fail" | "skip" = "pass") {
	return {
		surface_id: "sideeffect.ledger",
		hermes_pin: hermesPin,
		documented_seam:
			"Telclaude MCP side-effect ledger owns provider/outbound prepared refs and execution authorization",
		probe_command: "pnpm dev hermes probe sideeffect.ledger --allow-run",
		expected_result:
			"Prepared provider/outbound refs authorize one matching execution and deny mutation/replay/revocation/expiry mismatches",
		negative_probe:
			"Execute without ledger, kind mismatch, authority mismatch, expired/revoked/executed refs, params mutation, and replay fail closed",
		evidence_path: evidencePath,
		lockfile_key: "featureProbes.sideeffect.ledger",
		security_scope: "side-effect-ledger" as const,
		approval_equivalent: true,
		failure_outcome: "disable" as const,
		status,
	};
}

function sideEffectLedgerCutoverBundle(
	evidencePath: string,
	matrixStatus: "pass" | "fail" | "skip" = "pass",
) {
	const probe = sideEffectLedgerProbe(evidencePath, matrixStatus);
	const featureProbeMatrix = {
		schemaVersion: 1 as const,
		probes: [probe],
	};
	const base = safeCutoverBundle();
	return safeCutoverBundle({
		inventory: {
			generatedAt: "2026-05-29T00:00:00Z",
			workflows: [
				{
					workflow_id: "private.telegram.basic",
					owner: "operator",
					trust_domain: "private",
					active: true,
				},
			],
			status: "complete",
			summary: {
				pendingQueues: pendingQueues(),
			},
		},
		scopeManifest: {
			schemaVersion: 1,
			workflows: [
				{
					...base.scopeManifest.workflows[0],
					required_surface_ids: ["sideeffect.ledger"],
				},
			],
		},
		featureProbeMatrix,
		noForkProof: base.noForkProof,
		lockfile: {
			...compatLockfile,
			featureProbeMatrixDigest: computeHermesArtifactDigest(featureProbeMatrix),
			featureProbes: [
				{
					surface_id: "sideeffect.ledger",
					status: "pass",
					evidence_path: evidencePath,
				},
			],
			adapterApiSignatures: {
				"sideeffect.ledger": `sha256:${"9".repeat(64)}`,
			},
			noForkProofEvidencePath: base.noForkProof.evidence_path,
		},
	});
}

function providerApprovalBindingProbe(
	evidencePath: string,
	status: "pass" | "fail" | "skip" = "pass",
) {
	return {
		surface_id: "providers.approval-binding",
		hermes_pin: hermesPin,
		documented_seam:
			"Telclaude provider writes bind approval tokens to immutable prepared provider refs",
		probe_command: "pnpm dev hermes probe providers.approval-binding --allow-run",
		expected_result:
			"Provider write execution succeeds only with a valid one-time approval token matching the prepared action",
		negative_probe:
			"Missing token, wrong actor, wrong service/action, params mutation, expiry, revocation, duplicate JTI, and replay fail closed",
		evidence_path: evidencePath,
		lockfile_key: "featureProbes.providers.approvalBinding",
		security_scope: "provider-approval-binding" as const,
		approval_equivalent: true,
		failure_outcome: "disable" as const,
		status,
	};
}

function providerApprovalBindingCutoverBundle(
	evidencePath: string,
	matrixStatus: "pass" | "fail" | "skip" = "pass",
) {
	const probe = providerApprovalBindingProbe(evidencePath, matrixStatus);
	const featureProbeMatrix = {
		schemaVersion: 1 as const,
		probes: [probe],
	};
	const base = safeCutoverBundle();
	return safeCutoverBundle({
		inventory: {
			generatedAt: "2026-05-29T00:00:00Z",
			workflows: [
				{
					workflow_id: "providers.bank",
					owner: "provider:bank",
					trust_domain: "provider",
					active: true,
				},
			],
			status: "complete",
			summary: {
				pendingQueues: pendingQueues(),
			},
		},
		scopeManifest: {
			schemaVersion: 1,
			workflows: [
				{
					...base.scopeManifest.workflows[0],
					workflow_id: "providers.bank",
					owner: "provider:bank",
					trust_domain: "provider",
					required_surface_ids: ["providers.approval-binding"],
				},
			],
		},
		featureProbeMatrix,
		noForkProof: base.noForkProof,
		decisionLog: {
			schemaVersion: 1,
			decisions: [
				{
					id: "D-profile-generation",
					status: "accepted",
					owner: "operator",
					deadline_phase: "Phase 1",
					accepted_answer:
						"Generated Hermes profiles are produced by the checked profile generator.",
					affected_workflows: [],
					cutover_impact: "Profile generation proof is required before provider cutover.",
				},
			],
		},
		lockfile: {
			...compatLockfile,
			featureProbeMatrixDigest: computeHermesArtifactDigest(featureProbeMatrix),
			featureProbes: [
				{
					surface_id: "providers.approval-binding",
					status: "pass",
					evidence_path: evidencePath,
				},
			],
			adapterApiSignatures: {
				"providers.approval-binding": `sha256:${"8".repeat(64)}`,
			},
			noForkProofEvidencePath: base.noForkProof.evidence_path,
		},
	});
}

function servedMcpContainmentProbe(
	evidencePath: string,
	status: "pass" | "fail" | "skip" = "pass",
) {
	return {
		surface_id: "execution.served_mcp_containment",
		hermes_pin: hermesPin,
		documented_seam: "Telclaude-served Hermes MCP relay-only HTTP endpoint",
		probe_command: "pnpm dev hermes probe execution.served_mcp_containment --allow-run",
		expected_result:
			"HTTP JSON-RPC client proves positive tools-only control and specific adversarial denials",
		negative_probe:
			"Forged handle, wrong connection, cross-domain memory, out-of-scope provider/outbound, sampling, malformed, unauthenticated, batch, prototype-key, and execute-without-ledger calls fail closed",
		evidence_path: evidencePath,
		lockfile_key: "featureProbes.execution.servedMcpContainment",
		security_scope: "served-mcp-containment" as const,
		approval_equivalent: true,
		failure_outcome: "disable" as const,
		status,
	};
}

function apiServerContainmentProbe(
	evidencePath: string,
	status: "pass" | "fail" | "skip" = "pass",
) {
	return {
		surface_id: "execution.api_server_containment",
		hermes_pin: hermesPin,
		documented_seam: "Pinned Hermes API server behind Telclaude relay control",
		probe_command: "pnpm dev hermes probe execution.api_server_containment --allow-run",
		expected_result:
			"Contained Hermes API server starts with ephemeral auth and proves relay-only network containment",
		negative_probe:
			"Direct provider, vault, model-provider, private DNS, firewall, route, and runtime tamper attempts fail closed",
		evidence_path: evidencePath,
		lockfile_key: "featureProbes.execution.apiServerContainment",
		security_scope: "api-server-containment" as const,
		approval_equivalent: false,
		failure_outcome: "disable" as const,
		status,
	};
}

function apiServerContainmentCutoverBundle(
	evidencePath: string,
	matrixStatus: "pass" | "fail" | "skip" = "pass",
) {
	const probe = apiServerContainmentProbe(evidencePath, matrixStatus);
	const featureProbeMatrix = {
		schemaVersion: 1 as const,
		probes: [probe],
	};
	const base = safeCutoverBundle();
	return safeCutoverBundle({
		inventory: {
			generatedAt: "2026-05-29T00:00:00Z",
			workflows: [
				{
					workflow_id: "private.telegram.basic",
					owner: "operator",
					trust_domain: "private",
					active: true,
				},
			],
			status: "complete",
			summary: {
				pendingQueues: pendingQueues(),
			},
		},
		scopeManifest: {
			schemaVersion: 1,
			workflows: [
				{
					...base.scopeManifest.workflows[0],
					required_surface_ids: ["execution.api_server_containment"],
				},
			],
		},
		featureProbeMatrix,
		noForkProof: base.noForkProof,
		lockfile: {
			...compatLockfile,
			featureProbeMatrixDigest: computeHermesArtifactDigest(featureProbeMatrix),
			featureProbes: [
				{
					surface_id: "execution.api_server_containment",
					status: "pass",
					evidence_path: evidencePath,
				},
			],
			adapterApiSignatures: {
				"execution.api_server_containment": `sha256:${"e".repeat(64)}`,
			},
			noForkProofEvidencePath: base.noForkProof.evidence_path,
		},
	});
}

function servedMcpContainmentCutoverBundle(
	evidencePath: string,
	matrixStatus: "pass" | "fail" | "skip" = "pass",
) {
	const probe = servedMcpContainmentProbe(evidencePath, matrixStatus);
	const featureProbeMatrix = {
		schemaVersion: 1 as const,
		probes: [probe],
	};
	const base = safeCutoverBundle();
	return safeCutoverBundle({
		inventory: {
			generatedAt: "2026-05-29T00:00:00Z",
			workflows: [
				{
					workflow_id: "private.telegram.basic",
					owner: "operator",
					trust_domain: "private",
					active: true,
				},
			],
			status: "complete",
			summary: {
				pendingQueues: pendingQueues(),
			},
		},
		scopeManifest: {
			schemaVersion: 1,
			workflows: [
				{
					...base.scopeManifest.workflows[0],
					required_surface_ids: ["execution.served_mcp_containment"],
				},
			],
		},
		featureProbeMatrix,
		noForkProof: base.noForkProof,
		lockfile: {
			...compatLockfile,
			featureProbeMatrixDigest: computeHermesArtifactDigest(featureProbeMatrix),
			featureProbes: [
				{
					surface_id: "execution.served_mcp_containment",
					status: "pass",
					evidence_path: evidencePath,
				},
			],
			adapterApiSignatures: {
				"execution.served_mcp_containment": `sha256:${"f".repeat(64)}`,
			},
			noForkProofEvidencePath: base.noForkProof.evidence_path,
		},
	});
}

function servedMcpProviderToolsProbe(
	evidencePath: string,
	status: "pass" | "fail" | "skip" = "pass",
) {
	return {
		surface_id: "served_mcp.provider-tools",
		hermes_pin: hermesPin,
		documented_seam:
			"Telclaude-served Hermes MCP exposes provider tools only behind relay-owned authority and side-effect ledger execution gates",
		probe_command: "pnpm dev hermes probe served_mcp.provider-tools --allow-run",
		expected_result:
			"Provider tools are exposed only on the tc_ tool surface and require relay-stamped authority plus prepared side-effect ledger refs",
		negative_probe:
			"Client-supplied authority, forged handles, sampling/resources/prompts, out-of-scope providers, and execute-without-ledger fail closed",
		evidence_path: evidencePath,
		lockfile_key: "featureProbes.served_mcp.providerTools",
		security_scope: "served-mcp-provider-tools" as const,
		approval_equivalent: true,
		failure_outcome: "disable" as const,
		status,
	};
}

function servedMcpProviderToolsCutoverBundle(
	evidencePath: string,
	matrixStatus: "pass" | "fail" | "skip" = "pass",
) {
	const probe = servedMcpProviderToolsProbe(evidencePath, matrixStatus);
	const featureProbeMatrix = {
		schemaVersion: 1 as const,
		probes: [probe],
	};
	const base = safeCutoverBundle();
	return safeCutoverBundle({
		inventory: {
			generatedAt: "2026-05-29T00:00:00Z",
			workflows: [
				{
					workflow_id: "providers.bank",
					owner: "provider:bank",
					trust_domain: "provider",
					active: true,
				},
			],
			status: "complete",
			summary: {
				pendingQueues: pendingQueues(),
			},
		},
		scopeManifest: {
			schemaVersion: 1,
			workflows: [
				{
					...base.scopeManifest.workflows[0],
					workflow_id: "providers.bank",
					owner: "provider:bank",
					trust_domain: "provider",
					required_surface_ids: ["served_mcp.provider-tools"],
				},
			],
		},
		featureProbeMatrix,
		noForkProof: base.noForkProof,
		decisionLog: {
			schemaVersion: 1,
			decisions: [
				{
					id: "D-profile-generation",
					status: "accepted",
					owner: "operator",
					deadline_phase: "Phase 1",
					accepted_answer:
						"Generated Hermes profiles are produced by the checked profile generator.",
					affected_workflows: [],
					cutover_impact:
						"Profile generation proof is required before served-MCP provider cutover.",
				},
			],
		},
		lockfile: {
			...compatLockfile,
			featureProbeMatrixDigest: computeHermesArtifactDigest(featureProbeMatrix),
			featureProbes: [
				{
					surface_id: "served_mcp.provider-tools",
					status: "pass",
					evidence_path: evidencePath,
				},
			],
			adapterApiSignatures: {
				"served_mcp.provider-tools": `sha256:${"7".repeat(64)}`,
			},
			noForkProofEvidencePath: base.noForkProof.evidence_path,
		},
	});
}

function writeCutoverBundleArtifacts(tempDir: string, bundle: CutoverInputBundle) {
	const paths = {
		inventory: path.join(tempDir, "inventory.json"),
		scope: path.join(tempDir, "scope.json"),
		decisions: path.join(tempDir, "decisions.json"),
		proofBundle: path.join(tempDir, "proof-bundle.json"),
		featureProbes: path.join(tempDir, "feature-probes.json"),
		lockfile: path.join(tempDir, "lockfile.json"),
		fixtures: path.join(tempDir, "fixtures.json"),
		queueSnapshot: path.join(tempDir, "queue.json"),
		networkProbes: path.join(tempDir, "network-probes.json"),
		nofork: path.join(tempDir, "nofork.json"),
		profileProof: path.join(tempDir, "profile-generation-proof.json"),
		rollback: path.join(tempDir, "rollback.json"),
	};
	writeJson(paths.inventory, bundle.inventory);
	writeJson(paths.scope, bundle.scopeManifest);
	writeJson(paths.decisions, bundle.decisionLog);
	writeJson(paths.proofBundle, bundle.cutoverProofBundle);
	writeJson(paths.featureProbes, bundle.featureProbeMatrix);
	writeJson(paths.lockfile, bundle.lockfile);
	writeJson(paths.fixtures, bundle.fixtureResults);
	writeJson(paths.queueSnapshot, bundle.queueSnapshot);
	writeJson(paths.networkProbes, bundle.networkProbes);
	writeJson(paths.nofork, bundle.noForkProof);
	if (bundle.profileGenerationProof) {
		writeJson(paths.profileProof, bundle.profileGenerationProof);
	}
	writeJson(paths.rollback, bundle.rollbackRehearsal);
	return paths;
}

function writeProfileProofForBundle(tempDir: string, bundle: CutoverInputBundle) {
	return writeHermesProfileGenerationProof({
		pin: bundle.lockfile.hermes,
		outDir: path.join(tempDir, "profile"),
		lockfile: bundle.lockfile,
		evidencePath: path.join(tempDir, "profile-generation-proof.json"),
		now: "2026-05-29T00:00:00Z",
	});
}

async function runCutoverCheckWithBundle(bundle: CutoverInputBundle) {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-"));
	const paths = writeCutoverBundleArtifacts(tempDir, bundle);
	return runHermesCommand([
		"hermes",
		"cutover-check",
		"--strict",
		"--dry-run",
		"--json",
		"--inventory",
		paths.inventory,
		"--scope",
		paths.scope,
		"--decisions",
		paths.decisions,
		"--proof-bundle",
		paths.proofBundle,
		"--feature-probes",
		paths.featureProbes,
		"--lockfile",
		paths.lockfile,
		"--fixtures",
		paths.fixtures,
		"--queue-snapshot",
		paths.queueSnapshot,
		"--network-probes",
		paths.networkProbes,
		"--nofork",
		paths.nofork,
		"--profile-proof",
		paths.profileProof,
		"--rollback",
		paths.rollback,
	]);
}

type CliHeadlessEvidenceFixture = Record<string, unknown> & {
	invocation: Record<string, unknown>;
	provenance?: Record<string, unknown>;
	runtime?: Record<string, unknown>;
};

function cliHeadlessEvidence(overrides: Record<string, unknown> = {}): CliHeadlessEvidenceFixture {
	const invocation = {
		command: "/usr/local/bin/hermes",
		args: ["-z", "telclaude probe ok"],
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
		networkName: "telclaude-hermes-relay",
		containerId: "tc-hermes-contained-container-id",
		image:
			"nousresearch/hermes-agent@sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7",
		imageDigest: "sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7",
		hostname: "tc-hermes-contained",
		relayHost: "telclaude",
		relayResolvedAddress: "172.29.92.10",
		containerIpAddress: "172.29.92.11",
		observedPeerAddress: "172.29.92.11",
		provenanceSource: "docker-inspect-container-dns-and-relay-peer",
	};
	const relayProof = {
		schemaVersion: "telclaude.hermes.cli-headless-relay-proof.v1",
		source: "telclaude-openai-codex-proxy",
		requestId: "codex-proof-1",
		method: "POST",
		path: "/backend-api/codex/responses",
		observedPeerAddress: "172.29.92.11",
		upstreamStatus: 200,
		model: "gpt-5.3-codex",
		requestBodySha256: `sha256:${"a".repeat(64)}`,
		observedAt: "2026-05-30T00:00:00.500Z",
	};
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
			tokenScoping: "static-shared",
			auxiliaryAuthSource: "manual:telclaude-relay",
			auxiliaryBaseUrl: "http://telclaude:8790/v1/openai-codex-proxy",
			auxiliaryBaseUrlHost: "telclaude",
			refreshTokenPolicy: "non-refreshable-placeholder",
		},
		provenance: {
			runner: "telclaude-hermes-cli-probe",
			source: "live-allow-run",
			startedAt: "2026-05-30T00:00:00.000Z",
			endedAt: "2026-05-30T00:00:01.000Z",
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

function cliHeadlessReadinessFailureEvidence(): Record<string, unknown> {
	return {
		schemaVersion: "telclaude.hermes.probe-result.v1",
		probeId: "execution.cli_headless",
		status: "fail",
		ran: false,
		summary: "Hermes CLI probe launch failed readiness checks",
		invocation: {
			command: "scripts/hermes-contained-cli-probe.sh",
			args: ["-z", "Reply with exactly HERMES_OK_GPT55_RELAY"],
			cwd: "/repo",
			envKeys: [
				"HERMES_CODEX_BASE_URL",
				"HERMES_HOME",
				"HERMES_INFERENCE_MODEL",
				"HERMES_INFERENCE_PROVIDER",
				"NO_COLOR",
			],
		},
		readiness: {
			status: "fail",
			gates: [
				{
					name: "auth.relayToken",
					status: "fail",
					detail: "TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN is missing",
				},
			],
		},
		findings: [],
	};
}

function proReviewCanary(overrides: Record<string, unknown> = {}) {
	return {
		schemaVersion: "telclaude.hermes.pro-review-native-canary.v1",
		status: "pass",
		transport: "chrome-extension-native",
		recipe: "chatgpt",
		modelSelectionStatus: "selected",
		modelUsed: "Extended Pro",
		live: true,
		runId: "canary_test",
		conversationId: "conv_test",
		conversationUrl: "https://chatgpt.com/c/conv_test",
		extensionInstanceId: "ext_test",
		extensionVersion: "0.5.19",
		promptClass: "non-private transport canary",
		expectedResponse: "OK",
		response: "OK",
		warnings: [],
		observedAt: "2026-05-31T17:00:00.000Z",
		reverifiedAt: "2026-05-31T17:04:51Z",
		dryCanary: {
			command: "YOETZ_AGENT=1 yoetz browser extension canary --chatgpt --format json",
			exitCode: 0,
			status: "ok",
			transport: "chrome-extension-native",
			live: false,
		},
		liveCanary: {
			command:
				"YOETZ_AGENT=1 yoetz browser extension canary --chatgpt --live --extension-instance-id ext_test --format json",
			exitCode: 0,
			status: "ok",
			transport: "chrome-extension-native",
			live: true,
			modelUsed: "Extended Pro",
			response: "OK",
		},
		nativeStatus: {
			command: "YOETZ_AGENT=1 yoetz browser extension status --chatgpt --format json",
			exitCode: 0,
			status: "connected",
			detail: "native host socket is reachable and extension hello was observed",
			extensionId: "njdakhppfigmloihiikbjmheejfndbfa",
			extensionInstanceId: "ext_test",
			extensionVersion: "0.5.19",
			nativeHostName: "com.yoetz.chatgpt_native",
			protocolVersion: 1,
			socketReachable: true,
			transport: "chrome-extension-native",
		},
		checks: [
			{
				name: "native.status",
				status: "pass",
				detail: "host command reported Yoetz ChatGPT native extension connected",
			},
			{
				name: "native.liveCanary",
				status: "pass",
				detail: "live canary completed through chrome-extension-native",
			},
			{
				name: "model.extendedPro",
				status: "pass",
				detail: "ChatGPT UI selected Extended Pro",
			},
			{
				name: "fallback.disabled",
				status: "pass",
				detail: "no fallback was used",
			},
		],
		...overrides,
	};
}

function proReviewRequest(
	canaryPath: string,
	overrides: Record<string, unknown> = {},
	selectedFiles: readonly string[] = [...REQUIRED_PRO_REVIEW_FILES],
) {
	const prompt = "Review the attached Hermes wrapper files.";
	const selectedFileContentsSha256 = computeSelectedFileContentsDigest(selectedFiles);
	const transportEvidenceSha256 = computeFileDigest(canaryPath);
	const request = {
		schemaVersion: "telclaude.hermes.pro-review-request.v1",
		status: "pending_operator_disclosure_approval",
		reviewer: "ChatGPT Pro Extended via Yoetz native extension",
		transport: "chrome-extension-native",
		model: "Extended Pro",
		fallbackAllowed: false,
		transportEvidence: canaryPath,
		prompt,
		privateWorkspaceDisclosure: {
			required: true,
			approved: false,
			approvalReason: "The payload includes private repo code.",
			approvalBindingRequired: true,
			approvalId: null,
			operator: null,
			approvedAt: null,
			payloadSha256: null,
		},
		payloadBinding: {
			digestAlgorithm: "sha256",
			canonicalJsonFields: [
				"reviewer",
				"transport",
				"model",
				"fallbackAllowed",
				"transportEvidence",
				"blockedFallbacks",
				"prompt",
				"selectedFiles",
				"selectedFileContentsSha256",
				"transportEvidenceSha256",
			],
			payloadSha256: computeTextDigest(
				JSON.stringify({
					reviewer: "ChatGPT Pro Extended via Yoetz native extension",
					transport: "chrome-extension-native",
					model: "Extended Pro",
					fallbackAllowed: false,
					transportEvidence: canaryPath,
					blockedFallbacks: [
						"cdp",
						"api-key",
						"manual-browser",
						"claude-substitution",
						"amq-substitution",
					],
					prompt,
					selectedFiles,
					selectedFileContentsSha256,
					transportEvidenceSha256,
				}),
			),
			promptSha256: computeTextDigest(prompt),
			selectedFilesSha256: computeTextDigest(JSON.stringify(selectedFiles)),
			selectedFileContentsSha256,
			transportEvidenceSha256,
			notes: "A future approval is valid only for this exact payload.",
		},
		selectedFiles,
		blockedFallbacks: [
			"cdp",
			"api-key",
			"manual-browser",
			"claude-substitution",
			"amq-substitution",
		],
		...overrides,
	};
	return request;
}

function writeRequiredProReviewWorkspace(root: string): void {
	for (const file of REQUIRED_PRO_REVIEW_FILES) {
		const resolved = path.join(root, file);
		fs.mkdirSync(path.dirname(resolved), { recursive: true });
		if (file === "artifacts/hermes/probes/execution-cli-headless.json") {
			writeJson(resolved, cliHeadlessEvidence());
		} else if (file === "artifacts/hermes/pro-review-native-canary.json") {
			writeJson(resolved, proReviewCanary());
		} else {
			fs.writeFileSync(resolved, `test fixture for ${file}\n`, "utf8");
		}
	}
}

async function withCwd<T>(cwd: string, callback: () => Promise<T>): Promise<T> {
	const previous = process.cwd();
	process.chdir(cwd);
	try {
		return await callback();
	} finally {
		process.chdir(previous);
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

function computeSelectedFileContentsDigest(selectedFiles: readonly string[]): string {
	return computeTextDigest(
		JSON.stringify(
			selectedFiles.map((file) => {
				const resolved = path.resolve(file);
				if (!fs.existsSync(resolved)) return { file, missing: true };
				return {
					file,
					sha256: crypto.createHash("sha256").update(fs.readFileSync(resolved)).digest("hex"),
				};
			}),
		),
	);
}

function computeFileDigest(file: string): string {
	const resolved = path.resolve(file);
	if (!fs.existsSync(resolved)) return computeTextDigest(JSON.stringify({ file, missing: true }));
	return `sha256:${crypto.createHash("sha256").update(fs.readFileSync(resolved)).digest("hex")}`;
}

function apiServerContainmentEvidence(overrides: Record<string, unknown> = {}) {
	return {
		schemaVersion: "telclaude.hermes.api-server-containment.v1",
		probeId: "execution.api_server_containment",
		status: "pass",
		ran: true,
		summary: "Hermes API-server containment probe passed",
		gates: [
			{
				name: "lifecycle.started",
				status: "pass",
				detail: "container started",
			},
			{
				name: "lifecycle.stopped",
				status: "pass",
				detail: "probe container was explicitly stopped",
			},
			{
				name: "readiness.health",
				status: "pass",
				detail: "GET /health returned ok",
			},
			{
				name: "readiness.capabilities",
				status: "pass",
				detail:
					"capabilities advertise runs, approvals, stop, bearer auth, and server-side tool execution",
			},
			{
				name: "network.topology",
				status: "pass",
				detail: "Docker internal network contains only the contained Hermes server and relay",
			},
			{
				name: "network.relay_only",
				status: "pass",
				detail:
					"relay control reachable and direct provider, vault, model provider, and private DNS denied",
			},
			{
				name: "network.tamper_resistant",
				status: "pass",
				detail: "non-root runtime could not bypass containment",
			},
		],
		findings: [],
		...overrides,
	};
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
			observedPeerAddress: "172.29.92.11",
			observedPeerSource: "server-peer-echo",
			expectedPeerAddress: "172.29.92.11",
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
				networkNamespace: "telclaude-hermes-relay",
			},
			wrongConnection: {
				profileId: "social",
				endpointId: "tc-hermes-wrong",
				networkNamespace: "telclaude-hermes-relay",
			},
		},
	};
}

describe("Hermes wrapper foundation", () => {
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

	it("uses the compatibility lockfile Hermes pin for generate dry-run", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-generate-lockfile-pin-"));
		writeJson(path.join(tempDir, "docs/hermes/hermes-compat.lock.json"), compatLockfile);

		await withCwd(tempDir, async () => {
			const result = await runHermesCommand([
				"hermes",
				"generate",
				"--dry-run",
				"--out",
				path.join(tempDir, "profile"),
				"--json",
			]);
			const report = JSON.parse(result.stdout) as { pin: unknown; outputs: unknown[] };

			expect(result.exitCode, result.stdout).toBe(0);
			expect(report.pin).toEqual(hermesPin);
			expect(report.outputs.length).toBeGreaterThan(0);
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

	it("generates a dry-run profile manifest without raw secret values", () => {
		const manifest = buildHermesGenerateDryRun({
			pin: hermesPin,
			outDir: "/tmp/tc-hermes",
		});

		expect(manifest.outputs.some((output) => output.classification === "secret")).toBe(false);
		expect(manifest.outputs.map((output) => output.path)).toEqual([
			"config.yaml",
			".env.EXAMPLE",
			"secret-manifest.json",
			"SOUL.md",
			"guardrails/ownership.json",
			"guardrails/mount-plan.json",
			"plugins.json",
			"plugins/model-providers/README.md",
			"mcp.json",
			"toolsets.json",
			"terminal-backend.json",
			"gateway-platforms.json",
			"cron/export.json",
			"memory-provider.json",
			"skills-manifest.json",
			"promoted-skills/README.md",
			"quarantine/agent-authored/README.md",
			"provenance-manifest.json",
			"audit-cutover-manifest.json",
			"docs/hermes/hermes-compat.lock.json",
		]);
		expect(JSON.stringify(manifest)).not.toContain("sk-");
		expect(manifest.secretManifest.map((secret) => secret.owner)).toEqual([
			"telclaude-vault",
			"telclaude-vault",
			"telclaude-edge",
		]);
	});

	it("builds generated-profile guardrails and an unapplied OS mount plan", () => {
		const manifest = buildGuardrailManifest({
			profileId: "tc-private-default",
			now: "2026-05-29T00:00:00Z",
		});
		const mountPlan = buildGuardrailMountPlan({
			profileRoot: "/profiles/tc-private-default",
			manifest,
		});

		expect(() => GuardrailManifestSchema.parse(manifest)).not.toThrow();
		expect(() => GuardrailMountPlanSchema.parse(mountPlan)).not.toThrow();
		expect(manifest.productionMutationPolicy).toBe("deny-and-quarantine");
		expect(manifest.readOnlyRoots).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ path: "config.yaml", mutability: "read-only" }),
				expect.objectContaining({ path: "mcp.json", mutability: "read-only" }),
				expect.objectContaining({ path: "plugins/model-providers", mutability: "read-only" }),
				expect.objectContaining({ path: "promoted-skills", mutability: "read-only" }),
			]),
		);
		expect(mountPlan.status).toBe("generated-not-enforced");
		expect(mountPlan.readOnlyBindMounts).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					source: "/profiles/tc-private-default/config.yaml",
					target: "config.yaml",
					mode: "ro",
				}),
				expect.objectContaining({
					source: "/profiles/tc-private-default/plugins/model-providers",
					target: "plugins/model-providers",
					mode: "ro",
				}),
			]),
		);
		expect(mountPlan.writableBindMounts).toEqual([
			expect.objectContaining({
				source: "/profiles/tc-private-default/quarantine/agent-authored",
				target: "quarantine/agent-authored",
				mode: "rw",
				reviewRequired: true,
			}),
		]);
		expect(evaluateGuardrailMutation(manifest, "plugins/model-providers/malicious.py")).toEqual(
			expect.objectContaining({
				allowed: false,
				outcome: "denied-and-copied-to-quarantine",
				quarantinePath: "quarantine/agent-authored/plugins__model-providers__malicious.py",
			}),
		);
		expect(evaluateGuardrailMutation(manifest, "quarantine/agent-authored/draft.patch")).toEqual(
			expect.objectContaining({
				allowed: true,
				outcome: "allowed-quarantine-write",
			}),
		);
	});

	it("writes a profile-generation proof tied to the compatibility lockfile", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-profile-generation-"));
		const proofPath = path.join(tempDir, "profile-generation-proof.json");
		const lockfilePath = path.join(tempDir, "lockfile.json");
		writeJson(lockfilePath, compatLockfile);

		const result = await runHermesCommand([
			"hermes",
			"generate",
			"--write",
			"--json",
			"--pin",
			"0.15.1",
			"--out",
			path.join(tempDir, "profile"),
			"--lockfile",
			lockfilePath,
			"--proof-out",
			proofPath,
		]);
		const proof = readJson(proofPath) as NonNullable<CutoverInputBundle["profileGenerationProof"]>;

		expect(result.exitCode, result.stdout).toBe(0);
		expect(proof.status).toBe("pass");
		expect(proof.lockfileDigest).toBe(computeHermesArtifactDigest(compatLockfile));
		expect(proof.outputs.map((output) => output.path)).toContain("gateway-platforms.json");
		expect(result.stdout).toContain("profile-generation-proof.json");
	});

	it("assembles cutover input from separate canonical artifacts", () => {
		const source = safeCutoverBundle();
		const inventory = {
			...source.inventory,
			status: "complete" as const,
			summary: {
				pendingQueues: pendingQueues(),
			},
		};
		const proofSource = safeCutoverBundle({ inventory, queueSnapshot: { unownedActiveCount: 0 } });
		const assembled = buildCutoverInputBundleFromArtifacts({
			inventory: proofSource.inventory,
			scopeManifest: proofSource.scopeManifest,
			decisionLog: proofSource.decisionLog,
			cutoverProofBundle: proofSource.cutoverProofBundle,
			lockfile: proofSource.lockfile,
			featureProbeMatrix: proofSource.featureProbeMatrix,
			featureProbeEvidence: proofSource.featureProbeEvidence,
			fixtureResults: proofSource.fixtureResults,
			noForkProof: proofSource.noForkProof,
			profileGenerationProof: proofSource.profileGenerationProof,
			networkProbes: proofSource.networkProbes,
			rollbackRehearsal: proofSource.rollbackRehearsal,
		});

		expect(evaluateCutoverCheck(assembled).exitCode).toBe(0);
		expect(assembled.queueSnapshot).toEqual({ unownedActiveCount: 0 });
	});

	it("builds queue ownership snapshots from complete inventory evidence", () => {
		const source = safeCutoverBundle();
		const inventory = {
			...source.inventory,
			status: "complete" as const,
			summary: {
				pendingQueues: pendingQueues({
					approvals: 2,
					backgroundJobs: 1,
				}),
			},
		};

		expect(buildHermesQueueSnapshot({ inventory })).toEqual({ unownedActiveCount: 3 });
	});

	it("writes queue-snapshot artifacts from an inventory snapshot", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-queue-snapshot-"));
		const source = safeCutoverBundle();
		const inventoryPath = path.join(tempDir, "inventory.json");
		const outPath = path.join(tempDir, "queue-snapshot.json");
		writeJson(inventoryPath, {
			...source.inventory,
			status: "complete",
			summary: {
				pendingQueues: pendingQueues({
					approvals: 1,
					backgroundJobs: 2,
				}),
			},
		});

		const result = await runHermesCommand([
			"hermes",
			"queue-snapshot",
			"--json",
			"--inventory",
			inventoryPath,
			"--out",
			outPath,
		]);
		const snapshot = JSON.parse(result.stdout) as { unownedActiveCount: number };

		expect(result.exitCode, result.stdout).toBe(1);
		expect(snapshot).toEqual({ unownedActiveCount: 3 });
		expect(readJson(outPath)).toEqual(snapshot);
	});

	it("cutover-check consumes explicit queue snapshot artifacts", async () => {
		const source = safeCutoverBundle();
		const inventory = {
			...source.inventory,
			status: "complete" as const,
			summary: {
				pendingQueues: pendingQueues(),
			},
		};
		const bundle = safeCutoverBundle({
			inventory,
			queueSnapshot: { unownedActiveCount: 2 },
		});

		const result = await runCutoverCheckWithBundle(bundle);
		const report = JSON.parse(result.stdout) as {
			status: string;
			gates: Array<{ name: string; status: string }>;
		};

		expect(result.exitCode, result.stdout).toBe(1);
		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "proofBundle.queueSnapshot")).toMatchObject({
			status: "pass",
		});
		expect(report.gates.find((gate) => gate.name === "queues.owned")).toMatchObject({
			status: "fail",
		});
	});

	it("fails cutover when explicit queue snapshots underreport inventory queues", () => {
		const source = safeCutoverBundle();
		const inventory = {
			...source.inventory,
			status: "complete" as const,
			summary: {
				pendingQueues: pendingQueues({
					approvals: 1,
					backgroundJobs: 2,
				}),
			},
		};

		const report = evaluateCutoverCheck(
			safeCutoverBundle({
				inventory,
				queueSnapshot: { unownedActiveCount: 0 },
			}),
		);

		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "queues.owned")).toEqual(
			expect.objectContaining({
				status: "fail",
				detail: expect.stringContaining(
					"queue snapshot does not match inventory pendingQueues: expected 3, got 0",
				),
			}),
		);
	});

	it("builds a byte-bound proof bundle from canonical artifact files", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-proof-command-"));
		const bundle = safeCutoverBundle();
		const paths = writeCutoverBundleArtifacts(tempDir, bundle);
		const outPath = path.join(tempDir, "command-proof-bundle.json");

		const result = await runHermesCommand([
			"hermes",
			"proof-bundle",
			"--json",
			"--inventory",
			paths.inventory,
			"--scope-manifest",
			paths.scope,
			"--decision-log",
			paths.decisions,
			"--compatibility-lockfile",
			paths.lockfile,
			"--feature-probe-matrix",
			paths.featureProbes,
			"--fixture-results",
			paths.fixtures,
			"--nofork-proof-file",
			paths.nofork,
			"--network-probe-bundle",
			paths.networkProbes,
			"--queue-snapshot",
			paths.queueSnapshot,
			"--rollback-evidence",
			paths.rollback,
			"--out",
			outPath,
		]);
		const proof = readJson(outPath) as CutoverInputBundle["cutoverProofBundle"];

		expect(result.exitCode, result.stdout).toBe(0);
		expect(proof.schemaVersion).toBe("telclaude.hermes.cutover-proof-bundle.v1");
		expect(proof.artifacts.fixtureResults.sha256).toBe(
			`sha256:${crypto.createHash("sha256").update(fs.readFileSync(paths.fixtures)).digest("hex")}`,
		);
		expect(proof.artifacts.fixtureResults.checkIds).toEqual([
			"inputs.fixtureResults",
			"fixtures.pass",
		]);
		expect(JSON.parse(result.stdout)).toEqual(proof);
	});

	it("fails cutover-check when proof bundle hashes do not bind the supplied artifacts", () => {
		const bundle = safeCutoverBundle();
		const cutoverProofBundle = structuredClone(bundle.cutoverProofBundle);
		cutoverProofBundle.artifacts.fixtureResults.sha256 = `sha256:${"0".repeat(64)}`;

		const report = evaluateCutoverCheck({ ...bundle, cutoverProofBundle });

		expect(report.status).toBe("input_error");
		expect(report.exitCode).toBe(2);
		expect(report.gates.find((gate) => gate.name === "proofBundle.fixtureResults.valid")).toEqual(
			expect.objectContaining({
				status: "fail",
			}),
		);
	});

	it("fails cutover-check when proof bundle artifact timestamps do not match on-disk evidence", () => {
		const bundle = safeCutoverBundle();
		const cutoverProofBundle = structuredClone(bundle.cutoverProofBundle);
		cutoverProofBundle.artifacts.inventory.generatedAt = "2026-05-31T00:00:00.000Z";

		const report = evaluateCutoverCheck({ ...bundle, cutoverProofBundle });

		expect(report.status).toBe("input_error");
		expect(report.exitCode).toBe(2);
		expect(report.gates.find((gate) => gate.name === "proofBundle.inventory.valid")).toEqual(
			expect.objectContaining({
				status: "fail",
				detail: expect.stringContaining("artifact generatedAt does not match on-disk evidence"),
			}),
		);
	});

	it("fails live cutover-check when the proof bundle timestamp is stale or future-dated", () => {
		const stale = evaluateCutoverCheck(safeCutoverBundle(), {
			liveCutover: true,
			now: new Date("2026-06-07T00:00:00.001Z"),
		});
		const future = evaluateCutoverCheck(safeCutoverBundle(), {
			liveCutover: true,
			now: new Date("2026-05-30T00:00:00.000Z"),
		});

		for (const report of [stale, future]) {
			expect(report.status).toBe("input_error");
			expect(report.exitCode).toBe(2);
			expect(report.gates.find((gate) => gate.name === "proofBundle.generatedAt.live")).toEqual(
				expect.objectContaining({
					status: "fail",
					detail: "proof bundle generatedAt is stale or future-dated for live cutover",
				}),
			);
		}
	});

	it("anchors artifact recency to the proof bundle timestamp during live cutover", () => {
		const report = evaluateCutoverCheck(safeCutoverBundle(), {
			liveCutover: true,
			now: new Date("2026-06-06T23:59:59.000Z"),
		});

		expect(report.status).toBe("safe");
		expect(report.exitCode).toBe(0);
	});

	it("marks proof bundle artifacts failed when raw evidence bytes contain secrets", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-proof-leak-"));
		const bundle = safeCutoverBundle();
		const paths = writeCutoverProofSourceArtifacts(tempDir, bundle);
		writeJson(paths.fixtureResults, {
			...bundle.fixtureResults,
			diagnostic: "OPENAI_API_KEY=sk-test-this-must-not-enter-proof-artifacts",
		});

		const proof = buildCutoverProofBundle({
			hermes: bundle.lockfile.hermes,
			wrapperVersion: bundle.lockfile.wrapperPackageVersion,
			now: new Date("2026-05-31T00:00:00.000Z"),
			artifacts: {
				inventory: proofArtifact(paths.inventory, "pnpm dev hermes inventory --json", [
					"inputs.inventory",
				]),
				scopeManifest: proofArtifact(paths.scopeManifest, "pnpm dev hermes cutover-scope --json", [
					"inputs.scopeManifest",
					"workflow.scope",
				]),
				decisionLog: proofArtifact(paths.decisionLog, "pnpm dev hermes decision-log --json", [
					"inputs.decisionLog",
					"decisions.resolved",
				]),
				compatibilityLockfile: proofArtifact(
					paths.compatibilityLockfile,
					"pnpm dev hermes compat-lock --dry-run --json",
					["inputs.lockfile", "lockfile.consistent"],
				),
				featureProbeMatrix: proofArtifact(
					paths.featureProbeMatrix,
					"pnpm dev hermes probes --json",
					["inputs.featureProbeMatrix", "featureProbes.pass"],
				),
				fixtureResults: proofArtifact(paths.fixtureResults, "pnpm dev hermes fixtures --json", [
					"inputs.fixtureResults",
					"fixtures.pass",
				]),
				noForkProof: proofArtifact(
					paths.noForkProof,
					"pnpm dev hermes prove --upstream-clean --p0 --json",
					["inputs.noForkProof", "nofork.clean"],
				),
				networkProbeBundle: proofArtifact(
					paths.networkProbeBundle,
					"pnpm dev hermes network-probes --json",
					["inputs.networkProbes", "networkProbes.pass"],
				),
				queueSnapshot: proofArtifact(paths.queueSnapshot, "pnpm dev hermes queue-snapshot --json", [
					"inputs.queueSnapshot",
					"queues.owned",
				]),
				rollbackEvidence: proofArtifact(
					paths.rollbackEvidence,
					"pnpm dev hermes rollback-rehearsal --json",
					["inputs.rollbackRehearsal", "rollback.rehearsed"],
				),
			},
		});

		expect(proof.artifacts.fixtureResults.status).toBe("fail");
		expect(proof.artifacts.fixtureResults.leakScan.status).toBe("fail");
	});

	it("fails closed when canonical artifact assembly lacks complete queue evidence", () => {
		const source = safeCutoverBundle();
		const {
			status: _status,
			summary: _summary,
			...inventoryWithoutQueueEvidence
		} = source.inventory;
		expect(() =>
			buildCutoverInputBundleFromArtifacts({
				inventory: inventoryWithoutQueueEvidence,
				scopeManifest: source.scopeManifest,
				decisionLog: source.decisionLog,
				cutoverProofBundle: source.cutoverProofBundle,
				lockfile: source.lockfile,
				featureProbeMatrix: source.featureProbeMatrix,
				fixtureResults: source.fixtureResults,
				noForkProof: source.noForkProof,
				networkProbes: source.networkProbes,
				rollbackRehearsal: source.rollbackRehearsal,
			}),
		).toThrow("inventory queue evidence is missing or incomplete");

		expect(() =>
			buildCutoverInputBundleFromArtifacts({
				inventory: {
					...source.inventory,
					status: "partial",
					summary: {
						pendingQueues: pendingQueues(),
					},
				},
				scopeManifest: source.scopeManifest,
				decisionLog: source.decisionLog,
				cutoverProofBundle: source.cutoverProofBundle,
				lockfile: source.lockfile,
				featureProbeMatrix: source.featureProbeMatrix,
				fixtureResults: source.fixtureResults,
				noForkProof: source.noForkProof,
				networkProbes: source.networkProbes,
				rollbackRehearsal: source.rollbackRehearsal,
			}),
		).toThrow("inventory queue evidence is missing or incomplete");
	});

	it("derives nonzero queue ownership failures from complete inventory evidence", () => {
		const source = safeCutoverBundle();
		const inventory = {
			...source.inventory,
			status: "complete" as const,
			summary: {
				pendingQueues: pendingQueues({
					approvals: 1,
					backgroundJobs: 2,
				}),
			},
		};
		const proofSource = safeCutoverBundle({ inventory, queueSnapshot: { unownedActiveCount: 3 } });
		const assembled = buildCutoverInputBundleFromArtifacts({
			inventory: proofSource.inventory,
			scopeManifest: proofSource.scopeManifest,
			decisionLog: proofSource.decisionLog,
			cutoverProofBundle: proofSource.cutoverProofBundle,
			lockfile: proofSource.lockfile,
			featureProbeMatrix: proofSource.featureProbeMatrix,
			featureProbeEvidence: proofSource.featureProbeEvidence,
			fixtureResults: proofSource.fixtureResults,
			noForkProof: proofSource.noForkProof,
			profileGenerationProof: proofSource.profileGenerationProof,
			networkProbes: proofSource.networkProbes,
			rollbackRehearsal: proofSource.rollbackRehearsal,
		});

		const report = evaluateCutoverCheck(assembled);
		expect(assembled.queueSnapshot).toEqual({ unownedActiveCount: 3 });
		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "queues.owned")?.status).toBe("fail");
	});

	it("blocks cutover on active pairing queues but not enabled webhooks", () => {
		const source = safeCutoverBundle();
		const pairingInventory = {
			...source.inventory,
			status: "complete" as const,
			summary: {
				pendingQueues: pendingQueues({
					pairingPendingRequests: 1,
					pairingActiveLockouts: 2,
				}),
			},
		};
		const pairingProofSource = safeCutoverBundle({
			inventory: pairingInventory,
			queueSnapshot: { unownedActiveCount: 3 },
		});
		const withPairingQueues = buildCutoverInputBundleFromArtifacts({
			inventory: pairingProofSource.inventory,
			scopeManifest: pairingProofSource.scopeManifest,
			decisionLog: pairingProofSource.decisionLog,
			cutoverProofBundle: pairingProofSource.cutoverProofBundle,
			lockfile: pairingProofSource.lockfile,
			featureProbeMatrix: pairingProofSource.featureProbeMatrix,
			featureProbeEvidence: pairingProofSource.featureProbeEvidence,
			fixtureResults: pairingProofSource.fixtureResults,
			noForkProof: pairingProofSource.noForkProof,
			profileGenerationProof: pairingProofSource.profileGenerationProof,
			networkProbes: pairingProofSource.networkProbes,
			rollbackRehearsal: pairingProofSource.rollbackRehearsal,
		});

		expect(withPairingQueues.queueSnapshot).toEqual({ unownedActiveCount: 3 });
		expect(
			evaluateCutoverCheck(withPairingQueues).gates.find((gate) => gate.name === "queues.owned"),
		).toMatchObject({ status: "fail" });

		const inventoryWithEnabledWebhook = buildHermesInventorySnapshot({
			generatedAt: new Date("2026-05-29T00:00:00.000Z"),
			redactionSalt: "test-only-redaction-salt",
			source: {
				configPath: "/tmp/telclaude.json",
				runtimeConfigPath: "/tmp/telclaude.runtime.json",
				privateConfigPresent: true,
				dataDir: "/tmp/telclaude-data",
			},
			config: minimalInventoryConfig({ webhooksEnabled: true }),
			sessions: [],
			cron: emptyCronOverview(),
			queues: {
				...emptyQueues,
				webhooks: { enabled: 1, total: 1 },
			},
			socialActivity: [],
		});
		const webhookInventory = {
			...inventoryWithEnabledWebhook,
			workflows: [...source.inventory.workflows, ...inventoryWithEnabledWebhook.workflows],
		};
		const webhookScopeManifest = {
			...source.scopeManifest,
			workflows: [
				...source.scopeManifest.workflows,
				{
					workflow_id: "webhooks.signed-inbound",
					owner: "system:webhooks",
					trust_domain: "system",
					current_behavior: "Telclaude signed webhook receiver is enabled.",
					hermes_target_behavior: "Webhook delivery stays edge-owned during cutover.",
					cutover_class: "P1",
					cutover_requirement: "Webhook delivery parity is warning-only for queue ownership.",
					status: "excluded",
					fixture_ids: [],
					negative_fixture_ids: [],
					required_surface_ids: [],
					unresolved_decision_ids: [],
				},
			],
		};
		const webhookProofSource = safeCutoverBundle({
			inventory: webhookInventory,
			scopeManifest: webhookScopeManifest,
			queueSnapshot: { unownedActiveCount: 0 },
		});
		const webhookOnlyBundle = buildCutoverInputBundleFromArtifacts({
			inventory: webhookProofSource.inventory,
			scopeManifest: webhookProofSource.scopeManifest,
			decisionLog: webhookProofSource.decisionLog,
			cutoverProofBundle: webhookProofSource.cutoverProofBundle,
			lockfile: webhookProofSource.lockfile,
			featureProbeMatrix: webhookProofSource.featureProbeMatrix,
			featureProbeEvidence: webhookProofSource.featureProbeEvidence,
			fixtureResults: webhookProofSource.fixtureResults,
			noForkProof: webhookProofSource.noForkProof,
			profileGenerationProof: webhookProofSource.profileGenerationProof,
			networkProbes: webhookProofSource.networkProbes,
			rollbackRehearsal: webhookProofSource.rollbackRehearsal,
		});

		expect(inventoryWithEnabledWebhook.summary.pendingQueues).toMatchObject(pendingQueues());
		expect(inventoryWithEnabledWebhook.risks).toContain("enabled webhooks require cutover review");
		expect(webhookOnlyBundle.queueSnapshot).toEqual({ unownedActiveCount: 0 });
		expect(evaluateCutoverCheck(webhookOnlyBundle).status).toBe("safe");
	});

	it("marks inventory partial when live queue collection fails", () => {
		const source = safeCutoverBundle();
		const inventory = buildHermesInventorySnapshot({
			generatedAt: new Date("2026-05-29T00:00:00.000Z"),
			redactionSalt: "test-only-redaction-salt",
			source: {
				configPath: "/tmp/telclaude.json",
				runtimeConfigPath: "/tmp/telclaude.runtime.json",
				privateConfigPresent: true,
				dataDir: "/tmp/telclaude-data",
			},
			config: minimalInventoryConfig(),
			sessions: [],
			cron: emptyCronOverview(),
			queues: emptyQueues,
			socialActivity: [],
			collectorErrors: [{ collector: "queues", error: "database is locked" }],
		});

		expect(inventory.status).toBe("partial");
		expect(inventory.summary.pendingQueues).toMatchObject(pendingQueues());
		expect(() =>
			buildCutoverInputBundleFromArtifacts({
				inventory,
				scopeManifest: source.scopeManifest,
				decisionLog: source.decisionLog,
				cutoverProofBundle: source.cutoverProofBundle,
				lockfile: source.lockfile,
				featureProbeMatrix: source.featureProbeMatrix,
				fixtureResults: source.fixtureResults,
				noForkProof: source.noForkProof,
				networkProbes: source.networkProbes,
				rollbackRehearsal: source.rollbackRehearsal,
			}),
		).toThrow("inventory queue evidence is missing or incomplete");
	});

	it("generates a fail-closed cutover scope skeleton from inventory workflows", () => {
		const manifest = buildCutoverScopeManifestFromInventory({
			workflows: [
				{
					workflow_id: "private.telegram.basic",
					owner: "operator",
					trust_domain: "private",
					active: true,
					current_surface: "Telclaude Telegram relay",
					hermes_target: "Hermes private runtime behind Telclaude edge",
					p_class: "P0",
				},
				{
					workflow_id: "social.xtwitter.proactive",
					owner: "operator",
					trust_domain: "social",
					active: false,
				},
			],
		});

		expect(manifest).toMatchObject({
			schemaVersion: 1,
			workflows: [
				{
					workflow_id: "private.telegram.basic",
					status: "excluded",
					unresolved_decision_ids: ["D-first-cutover-workflow-set"],
				},
				{
					workflow_id: "social.xtwitter.proactive",
					status: "disabled",
					unresolved_decision_ids: [],
				},
			],
		});
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

	it("returns cutover exit code 0 only when all strict evidence gates pass", () => {
		expect(evaluateCutoverCheck(safeCutoverBundle()).exitCode).toBe(0);

		const failed = evaluateCutoverCheck(
			safeCutoverBundle({
				noForkProof: writeNoForkProof({
					hermesCheckoutClean: false,
					checks: [
						{
							name: "checkout.pinned",
							status: "fail",
							detail: "HEAD does not match v2026.5.29",
						},
					],
				}),
			}),
		);
		expect(failed.status).toBe("fail");
		expect(failed.exitCode).toBe(1);
		expect(failed.gates.find((gate) => gate.name === "nofork.clean")?.status).toBe("fail");
	});

	it("fails strict cutover when no-fork proof evidence is missing", () => {
		const missingEvidence = path.join(
			fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-nofork-missing-")),
			"missing-no-fork.json",
		);
		const failed = evaluateCutoverCheck(
			safeCutoverBundle({
				noForkProof: {
					schemaVersion: 1,
					hermesCheckoutClean: true,
					evidence_path: missingEvidence,
				},
			}),
		);

		expect(failed.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "nofork.clean")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("missing no-fork proof evidence"),
		});
	});

	it("fails strict cutover when no-fork proof evidence omits required checks", () => {
		const proof = writeNoForkProof({
			checks: [
				{
					name: "checkout.present",
					status: "pass",
					detail: "Hermes checkout found at pinned tag",
				},
			],
		});

		const failed = evaluateCutoverCheck(safeCutoverBundle({ noForkProof: proof }));

		expect(failed.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "nofork.clean")?.detail).toContain(
			"missing no-fork evidence check checkout.expectedRef",
		);
	});

	it("fails strict cutover when no-fork proof fields contradict passing checks", () => {
		const proof = writeNoForkProof({
			expectedRefCommit: "b".repeat(40),
		});

		const failed = evaluateCutoverCheck(safeCutoverBundle({ noForkProof: proof }));

		expect(failed.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "nofork.clean")?.detail).toContain(
			"no-fork evidence HEAD does not match expectedRefCommit",
		);
	});

	it("fails strict cutover when no-fork proof fields are placeholders", () => {
		const proof = writeNoForkProof({
			expectedRef: "TODO",
			head: "pending",
			expectedRefCommit: "pending",
			exactTags: ["TODO"],
		});

		const failed = evaluateCutoverCheck(safeCutoverBundle({ noForkProof: proof }));

		expect(failed.status).toBe("fail");
		const detail = failed.gates.find((gate) => gate.name === "nofork.clean")?.detail ?? "";
		expect(detail).toContain("no-fork evidence.expectedRef is placeholder");
		expect(detail).toContain("no-fork evidence head is placeholder or invalid");
	});

	it("fails strict cutover when rollback rehearsal evidence is missing", () => {
		const missingEvidence = path.join(
			fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-rollback-missing-")),
			"missing-rollback.json",
		);
		const failed = evaluateCutoverCheck(
			safeCutoverBundle({
				rollbackRehearsal: {
					schemaVersion: 1,
					passed: true,
					evidence_path: missingEvidence,
				},
			}),
		);

		expect(failed.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "rollback.rehearsed")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("missing rollback rehearsal evidence"),
		});
	});

	it("fails strict cutover when rollback rehearsal proof omits required checks", () => {
		const rehearsal = writeRollbackRehearsal({
			checks: [
				{
					name: "rollback.allowed",
					status: "pass",
					detail: "operator allowed a real rollback rehearsal",
				},
			],
		});

		const failed = evaluateCutoverCheck(safeCutoverBundle({ rollbackRehearsal: rehearsal }));

		expect(failed.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "rollback.rehearsed")?.detail).toContain(
			"missing rollback rehearsal evidence check rollback.flagBefore",
		);
	});

	it("fails strict cutover when rollback transcript proof is tampered", () => {
		const base = safeCutoverBundle();
		const rehearsal = base.rollbackRehearsal;
		const transcripts = rehearsal.signedRelayTranscripts;
		if (!transcripts) throw new Error("missing signed relay transcripts");
		const tampered = {
			...rehearsal,
			signedRelayTranscripts: {
				...transcripts,
				before: {
					...transcripts.before,
					responseBody: JSON.stringify(legacyRuntimeState()),
				},
			},
		};
		writeJson(rehearsal.evidence_path, tampered);

		const failed = evaluateCutoverCheck(safeCutoverBundle({ rollbackRehearsal: tampered }));

		expect(failed.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "rollback.rehearsed")?.detail).toContain(
			"rollback before relay transcript proof invalid: response body digest mismatch",
		);
	});

	it("accepts archived rollback transcript proofs outside the live RPC skew window", () => {
		vi.useFakeTimers();
		try {
			vi.setSystemTime(new Date("2000-01-01T00:00:00.000Z"));
			const rehearsal = writeRollbackRehearsal();
			vi.useRealTimers();

			const report = evaluateCutoverCheck(safeCutoverBundle({ rollbackRehearsal: rehearsal }));

			expect(report.status).toBe("safe");
			expect(report.gates.find((gate) => gate.name === "rollback.rehearsed")).toMatchObject({
				status: "pass",
			});
		} finally {
			vi.useRealTimers();
		}
	});

	it("accepts archived rollback transcript proofs with embedded relay public-key provenance", () => {
		const originalRelayPublicKey = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		const rehearsal = writeRollbackRehearsal();
		delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		try {
			const report = evaluateCutoverCheck(safeCutoverBundle({ rollbackRehearsal: rehearsal }));

			expect(report.gates.find((gate) => gate.name === "rollback.rehearsed")).toMatchObject({
				status: "pass",
			});
		} finally {
			restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", originalRelayPublicKey);
		}
	});

	it("rejects archived rollback transcript proofs when embedded relay public key is wrong", () => {
		const rehearsal = writeRollbackRehearsal();
		const wrongKey = generateKeyPair().publicKey;
		const tampered = {
			...rehearsal,
			relayPublicKey: {
				...rehearsal.relayPublicKey,
				value: wrongKey,
				sha256: `sha256:${crypto.createHash("sha256").update(wrongKey).digest("hex")}`,
			},
		};
		writeJson(rehearsal.evidence_path, tampered);

		const failed = evaluateCutoverCheck(safeCutoverBundle({ rollbackRehearsal: tampered }));

		expect(failed.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "rollback.rehearsed")?.detail).toContain(
			"rollback before relay transcript proof invalid: signature verification failed",
		);
	});

	it("fails strict cutover when evidence bundles are empty", () => {
		const failed = evaluateCutoverCheck(
			safeCutoverBundle({
				featureProbeMatrix: { schemaVersion: 1, probes: [] },
				fixtureResults: { schemaVersion: 1, results: [] },
				networkProbes: { schemaVersion: 1, probes: [] },
			}),
		);

		expect(failed.status).toBe("fail");
		expect(failed.exitCode).toBe(1);
		expect(failed.gates.find((gate) => gate.name === "featureProbes.pass")?.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "fixtures.pass")?.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "networkProbes.pass")?.status).toBe("fail");
	});

	it("fails strict cutover when a required feature probe has no passing status", () => {
		const [probe] = featureProbeMatrix.probes;
		const { status: _status, ...probeWithoutStatus } = probe;
		const failed = evaluateCutoverCheck(
			safeCutoverBundle({
				featureProbeMatrix: {
					schemaVersion: 1,
					probes: [probeWithoutStatus],
				},
			}),
		);

		expect(failed.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "featureProbes.pass")?.detail).toContain(
			"status is missing",
		);
	});

	it("fails strict cutover when a passing feature probe has no observed evidence", () => {
		const failed = evaluateCutoverCheck(
			safeCutoverBundle({
				featureProbeEvidence: undefined,
			}),
		);

		expect(failed.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "featureProbes.pass")?.detail).toContain(
			"feature probe edge.whatsapp.plugin-adapter requires observed evidence",
		);
	});

	it("passes the feature-probe gate from complete cli-headless evidence read by cutover-check", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-cli-"));
		const evidencePath = path.join(tempDir, "execution-cli-headless.json");
		writeJson(evidencePath, cliHeadlessEvidence());

		const result = await runCutoverCheckWithBundle(cliHeadlessCutoverBundle(evidencePath));
		const report = JSON.parse(result.stdout) as {
			status: string;
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode, result.stdout).toBe(0);
		expect(report.status).toBe("safe");
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "pass",
		});
	});

	it("does not let cli-headless evidence satisfy unrelated feature probes", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-cli-"));
		const evidencePath = path.join(tempDir, "execution-cli-headless.json");
		writeJson(evidencePath, cliHeadlessEvidence());
		const skippedOtherProbe = { ...featureProbeMatrix.probes[0], status: "skip" as const };
		const mixedMatrix = {
			schemaVersion: 1 as const,
			probes: [cliHeadlessProbe(evidencePath), skippedOtherProbe],
		};
		const base = cliHeadlessCutoverBundle(evidencePath);
		const lockfile = {
			...base.lockfile,
			featureProbeMatrixDigest: computeHermesArtifactDigest(mixedMatrix),
			featureProbes: [
				...base.lockfile.featureProbes,
				{
					surface_id: skippedOtherProbe.surface_id,
					status: "pass" as const,
					evidence_path: skippedOtherProbe.evidence_path,
				},
			],
		};

		const result = await runCutoverCheckWithBundle(
			safeCutoverBundle({
				inventory: base.inventory,
				scopeManifest: base.scopeManifest,
				featureProbeMatrix: mixedMatrix,
				lockfile,
				noForkProof: base.noForkProof,
			}),
		);
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};
		const featureGate = report.gates.find((gate) => gate.name === "featureProbes.pass");

		expect(result.exitCode, result.stdout).toBe(1);
		expect(featureGate).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("feature probe edge.whatsapp.plugin-adapter status is skip"),
		});
		expect(featureGate?.detail).not.toContain(
			"feature probe execution.cli_headless status is skip",
		);
	});

	it("does not let model-relay pass from matrix and lockfile status alone", () => {
		const modelRelayProbe = {
			surface_id: "model.relay",
			hermes_pin: hermesPin,
			documented_seam: "Hermes model provider configuration is relay-owned",
			probe_command: "pnpm dev hermes probe model.relay --allow-run",
			expected_result: "Model traffic reaches only the Telclaude relay",
			negative_probe: "Direct model provider egress and writable profile overrides fail",
			evidence_path: "artifacts/hermes/probes/model-relay.json",
			lockfile_key: "featureProbes.model.relay",
			security_scope: "model-relay" as const,
			approval_equivalent: false,
			failure_outcome: "disable" as const,
			status: "pass" as const,
		};
		const featureProbeMatrix = {
			schemaVersion: 1 as const,
			probes: [modelRelayProbe],
		};
		const base = safeCutoverBundle();
		const report = evaluateCutoverCheck(
			safeCutoverBundle({
				scopeManifest: {
					schemaVersion: 1,
					workflows: [
						{
							...base.scopeManifest.workflows[0],
							required_surface_ids: ["model.relay"],
						},
					],
				},
				featureProbeMatrix,
				lockfile: {
					...base.lockfile,
					featureProbeMatrixDigest: computeHermesArtifactDigest(featureProbeMatrix),
					featureProbes: [
						{
							surface_id: "model.relay",
							status: "pass",
							evidence_path: "artifacts/hermes/probes/model-relay.json",
						},
					],
				},
			}),
		);

		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")?.detail).toContain(
			"feature probe model.relay requires observed evidence",
		);
	});

	it("does not let full-parity edge probes pass from matrix and lockfile status alone", () => {
		const edgeProbe = {
			surface_id: "edge.whatsapp",
			hermes_pin: hermesPin,
			documented_seam: "Telclaude edge adapter contract mediates WhatsApp ingress and egress",
			probe_command: "pnpm dev hermes parity --whatsapp --edge-adapter",
			expected_result: "WhatsApp ingress is sanitized and outbound delivery uses prepared refs",
			negative_probe: "raw WhatsApp credentials and direct native bridge access are absent",
			evidence_path: "artifacts/hermes/probes/edge-whatsapp.json",
			lockfile_key: "featureProbes.edge.whatsapp",
			security_scope: "edge-adapter" as const,
			approval_equivalent: true,
			failure_outcome: "disable" as const,
			status: "pass" as const,
		};
		const featureProbeMatrix = {
			schemaVersion: 1 as const,
			probes: [edgeProbe],
		};
		const base = safeCutoverBundle();
		const report = evaluateCutoverCheck(
			safeCutoverBundle({
				scopeManifest: {
					schemaVersion: 1,
					workflows: [
						{
							...base.scopeManifest.workflows[0],
							required_surface_ids: ["edge.whatsapp"],
						},
					],
				},
				featureProbeMatrix,
				lockfile: {
					...base.lockfile,
					featureProbeMatrixDigest: computeHermesArtifactDigest(featureProbeMatrix),
					featureProbes: [
						{
							surface_id: "edge.whatsapp",
							status: "pass",
							evidence_path: "artifacts/hermes/probes/edge-whatsapp.json",
						},
					],
				},
			}),
		);

		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")?.detail).toContain(
			"feature probe edge.whatsapp requires observed evidence",
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
			source: "telclaude-edge-contract-unit",
		});
		expect(artifact.controls).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ name: "credentials.raw-denied", status: "pass" }),
				expect.objectContaining({ name: "whatsapp.direct-bridge-denied", status: "pass" }),
			]),
		);
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

	it("passes the served-MCP provider-tools cutover gate with derived containment evidence", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-served-mcp-provider-cutover-"));
		const sourcePath = path.join(tempDir, "execution-served-mcp-containment.json");
		const evidencePath = path.join(tempDir, "served-mcp-provider-tools.json");
		writeJson(sourcePath, servedMcpContainmentEvidence());
		const probeResult = await runHermesCommand([
			"hermes",
			"probe",
			"served_mcp.provider-tools",
			"--from-report",
			sourcePath,
			"--json",
			"--out",
			evidencePath,
		]);

		expect(probeResult.exitCode, probeResult.stdout).toBe(0);
		const result = await runCutoverCheckWithBundle(
			servedMcpProviderToolsCutoverBundle(evidencePath),
		);
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode, result.stdout).toBe(0);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "pass",
		});
	});

	it("fails served-MCP provider-tools cutover when execute-without-ledger denial is absent", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-served-mcp-provider-fail-"));
		const sourcePath = path.join(tempDir, "execution-served-mcp-containment.json");
		const evidencePath = path.join(tempDir, "served-mcp-provider-tools.json");
		const sourceEvidence = servedMcpContainmentEvidence();
		sourceEvidence.properties.provider_execute_without_ledger_denied = false;
		sourceEvidence.checks = sourceEvidence.checks.map((check) =>
			check.name === "provider_execute_without_ledger_denied"
				? { ...check, status: "fail", detail: "provider execute without ledger was allowed" }
				: check,
		);
		writeJson(sourcePath, sourceEvidence);
		const probeResult = await runHermesCommand([
			"hermes",
			"probe",
			"served_mcp.provider-tools",
			"--from-report",
			sourcePath,
			"--json",
			"--out",
			evidencePath,
		]);

		expect(probeResult.exitCode, probeResult.stdout).toBe(1);
		const result = await runCutoverCheckWithBundle(
			servedMcpProviderToolsCutoverBundle(evidencePath),
		);
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode, result.stdout).toBe(1);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")?.detail).toContain(
			"served-mcp.provider-tools.execute-without-ledger-denied",
		);
	});

	it("fails the feature-probe gate when cli-headless evidence is missing", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-cli-"));
		const evidencePath = path.join(tempDir, "missing-execution-cli-headless.json");

		const result = await runCutoverCheckWithBundle(cliHeadlessCutoverBundle(evidencePath));
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode, result.stdout).toBe(1);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("missing feature probe evidence execution.cli_headless"),
		});
	});

	it.each([
		{
			name: "pending",
			evidence: cliHeadlessEvidence({ status: "pending", ran: false }),
			detail: "status is pending",
		},
		{
			name: "status fail",
			evidence: cliHeadlessEvidence({ status: "fail", exitCode: 7 }),
			detail: "status is fail",
		},
		{
			name: "ran false",
			evidence: cliHeadlessEvidence({ ran: false }),
			detail: "ran is false",
		},
		{
			name: "wrong schema",
			evidence: cliHeadlessEvidence({ schemaVersion: "telclaude.hermes.probe-report.v1" }),
			detail: "schemaVersion",
		},
		{
			name: "wrong probe id",
			evidence: cliHeadlessEvidence({ probeId: "execution.approval_continuation" }),
			detail: "probeId",
		},
		{
			name: "nonzero exit",
			evidence: cliHeadlessEvidence({ exitCode: 7 }),
			detail: "exitCode is 7",
		},
		{
			name: "non-empty findings",
			evidence: cliHeadlessEvidence({
				findings: [
					{
						location: "env.OPENAI_API_KEY",
						reason: "forbidden credential environment key",
					},
				],
			}),
			detail: "findings are not empty",
		},
		{
			name: "missing live-run provenance",
			evidence: cliHeadlessEvidence({ provenance: undefined }),
			detail: "provenance is missing",
		},
		{
			name: "missing contained runtime evidence",
			evidence: cliHeadlessEvidence({ runtime: undefined }),
			detail: "runtime evidence is missing",
		},
		{
			name: "loopback contained runtime peer",
			evidence: cliHeadlessEvidence({
				runtime: {
					...cliHeadlessEvidence().runtime,
					observedPeerAddress: "127.0.0.1",
				},
			}),
			detail: "runtime observedPeerAddress is loopback",
		},
		{
			name: "public contained runtime relay address",
			evidence: cliHeadlessEvidence({
				runtime: {
					...cliHeadlessEvidence().runtime,
					relayResolvedAddress: "8.8.8.8",
				},
			}),
			detail: "runtime relayResolvedAddress is not a private container-network IP",
		},
		{
			name: "host-gateway private relay address",
			evidence: cliHeadlessEvidence({
				runtime: {
					...cliHeadlessEvidence().runtime,
					relayResolvedAddress: "192.168.5.2",
				},
			}),
			detail: "runtime relayResolvedAddress is 192.168.5.2, expected 172.29.92.10",
		},
		{
			name: "editable runtime provenance",
			evidence: cliHeadlessEvidence({
				provenance: {
					runtimeSha256: `sha256:${"0".repeat(64)}`,
				},
			}),
			detail: "provenance runtimeSha256 does not match runtime",
		},
		{
			name: "missing relay proof",
			evidence: cliHeadlessEvidence({ relayProof: undefined }),
			detail: "relay proof is missing",
		},
		{
			name: "mismatched relay proof provenance",
			evidence: cliHeadlessEvidence({
				provenance: {
					relayProofSha256: `sha256:${"0".repeat(64)}`,
				},
			}),
			detail: "provenance relayProofSha256 does not match relayProof",
		},
		{
			name: "relay proof from wrong peer",
			evidence: cliHeadlessEvidence({
				relayProof: {
					...(cliHeadlessEvidence().relayProof as Record<string, unknown>),
					observedPeerAddress: "172.29.92.12",
				},
			}),
			detail: "relay proof observedPeerAddress does not match runtime observedPeerAddress",
		},
		{
			name: "mismatched invocation provenance",
			evidence: cliHeadlessEvidence({
				provenance: {
					runner: "telclaude-hermes-cli-probe",
					source: "live-allow-run",
					startedAt: "2026-05-30T00:00:00.000Z",
					endedAt: "2026-05-30T00:00:01.000Z",
					expectedProofToken: "telclaude probe ok",
					proofTokenObserved: true,
					invocationSha256: `sha256:${"0".repeat(64)}`,
					stdoutSha256: `sha256:${"1".repeat(64)}`,
					stderrSha256: `sha256:${"2".repeat(64)}`,
				},
			}),
			detail: "provenance invocationSha256 does not match invocation",
		},
		{
			name: "mismatched stdout provenance",
			evidence: cliHeadlessEvidence({
				provenance: {
					runner: "telclaude-hermes-cli-probe",
					source: "live-allow-run",
					startedAt: "2026-05-30T00:00:00.000Z",
					endedAt: "2026-05-30T00:00:01.000Z",
					expectedProofToken: "telclaude probe ok",
					proofTokenObserved: true,
					invocationSha256: computeHermesArtifactDigest(cliHeadlessEvidence().invocation),
					stdoutSha256: `sha256:${"1".repeat(64)}`,
					stderrSha256: computeTextDigest(""),
				},
			}),
			detail: "provenance stdoutSha256 does not match stdoutPreview",
		},
		{
			name: "truncated stdout preview",
			evidence: cliHeadlessEvidence({
				stdoutPreview: "telclaude probe ok...",
				provenance: {
					runner: "telclaude-hermes-cli-probe",
					source: "live-allow-run",
					startedAt: "2026-05-30T00:00:00.000Z",
					endedAt: "2026-05-30T00:00:01.000Z",
					expectedProofToken: "telclaude probe ok",
					proofTokenObserved: true,
					invocationSha256: computeHermesArtifactDigest(cliHeadlessEvidence().invocation),
					stdoutSha256: computeTextDigest("telclaude probe ok..."),
					stderrSha256: computeTextDigest(""),
				},
			}),
			detail: "stdoutPreview is truncated",
		},
		{
			name: "forbidden env key",
			evidence: cliHeadlessEvidence({
				invocation: {
					command: "/usr/local/bin/hermes",
					args: ["-z", "telclaude probe ok"],
					cwd: "/repo",
					envKeys: ["HERMES_HOME", "OPENAI_API_KEY"],
				},
			}),
			detail: "forbidden credential envKeys: OPENAI_API_KEY",
		},
		{
			name: "missing relay model provider",
			evidence: cliHeadlessEvidence({ modelProvider: undefined }),
			detail: "modelProvider is missing",
		},
		{
			name: "missing relay token scoping metadata",
			evidence: cliHeadlessEvidence({
				modelProvider: {
					provider: "openai-codex",
					baseUrl: "http://telclaude:8790/v1/openai-codex-proxy",
					baseUrlHost: "telclaude",
					model: "gpt-5.3-codex",
					modelSource: "env:HERMES_INFERENCE_MODEL",
					authLocation: "hermes-auth-store:openai-codex",
					authScope: "relay-openai-codex-subscription-proxy",
				},
			}),
			detail: "invalid feature probe evidence execution.cli_headless",
		},
		{
			name: "direct model provider base url",
			evidence: cliHeadlessEvidence({
				modelProvider: {
					provider: "openai-codex",
					baseUrl: "https://chatgpt.com/backend-api/codex",
					baseUrlHost: "chatgpt.com",
					model: "gpt-5.3-codex",
					modelSource: "env:HERMES_INFERENCE_MODEL",
					authLocation: "hermes-auth-store:openai-codex",
					authScope: "relay-openai-codex-subscription-proxy",
					tokenScoping: "static-shared",
				},
			}),
			detail: "modelProvider.baseUrl is not a relay OpenAI Codex proxy URL",
		},
		{
			name: "relay-shaped base url on non-Telclaude host",
			evidence: cliHeadlessEvidence({
				modelProvider: {
					provider: "openai-codex",
					baseUrl: "http://evil.internal:8790/v1/openai-codex-proxy",
					baseUrlHost: "evil.internal",
					model: "gpt-5.3-codex",
					modelSource: "env:HERMES_INFERENCE_MODEL",
					authLocation: "hermes-auth-store:openai-codex",
					authScope: "relay-openai-codex-subscription-proxy",
					tokenScoping: "static-shared",
				},
			}),
			detail: "modelProvider.baseUrl is not a relay OpenAI Codex proxy URL",
		},
		{
			name: "missing relay model env keys",
			evidence: cliHeadlessEvidence({
				invocation: {
					command: "/usr/local/bin/hermes",
					args: ["-z", "telclaude probe ok"],
					cwd: "/repo",
					envKeys: ["HERMES_HOME", "NO_COLOR"],
				},
			}),
			detail: "HERMES_INFERENCE_PROVIDER envKey is missing",
		},
		{
			name: "missing inherited Hermes model env key",
			evidence: cliHeadlessEvidence({
				invocation: {
					command: "/usr/local/bin/hermes",
					args: ["-z", "telclaude probe ok"],
					cwd: "/repo",
					envKeys: [
						"HERMES_CODEX_BASE_URL",
						"HERMES_HOME",
						"HERMES_INFERENCE_PROVIDER",
						"NO_COLOR",
					],
				},
			}),
			detail: "HERMES_INFERENCE_MODEL envKey is missing",
		},
		{
			name: "missing model metadata value",
			evidence: cliHeadlessEvidence({
				modelProvider: {
					provider: "openai-codex",
					baseUrl: "http://telclaude:8790/v1/openai-codex-proxy",
					baseUrlHost: "telclaude",
					model: "",
					modelSource: "env:HERMES_INFERENCE_MODEL",
					authLocation: "hermes-auth-store:openai-codex",
					authScope: "relay-openai-codex-subscription-proxy",
					tokenScoping: "static-shared",
				},
			}),
			detail: "modelProvider.model is missing",
		},
		{
			name: "missing model source metadata",
			evidence: cliHeadlessEvidence({
				modelProvider: {
					provider: "openai-codex",
					baseUrl: "http://telclaude:8790/v1/openai-codex-proxy",
					baseUrlHost: "telclaude",
					model: "gpt-5.3-codex",
					modelSource: "missing",
					authLocation: "hermes-auth-store:openai-codex",
					authScope: "relay-openai-codex-subscription-proxy",
					tokenScoping: "static-shared",
				},
			}),
			detail: "modelProvider.modelSource is not env:HERMES_INFERENCE_MODEL",
		},
		{
			name: "partial handwritten pass",
			evidence: {
				schemaVersion: "telclaude.hermes.probe-result.v1",
				probeId: "execution.cli_headless",
				status: "pass",
			},
			detail: "ran",
		},
	])("fails the feature-probe gate from invalid cli-headless evidence: $name", async ({
		evidence,
		detail,
	}) => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-cli-"));
		const evidencePath = path.join(tempDir, "execution-cli-headless.json");
		writeJson(evidencePath, evidence);

		const result = await runCutoverCheckWithBundle(cliHeadlessCutoverBundle(evidencePath));
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode, result.stdout).toBe(1);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining(detail),
		});
	});

	it("fails strict cutover when active inventory workflows are not scoped", () => {
		const failed = evaluateCutoverCheck(
			safeCutoverBundle({
				inventory: {
					generatedAt: "2026-05-29T00:00:00Z",
					workflows: [
						{
							workflow_id: "private.telegram.basic",
							owner: "operator",
							trust_domain: "private",
							active: true,
						},
						{
							workflow_id: "provider.bank.read",
							owner: "operator",
							trust_domain: "provider-read",
							active: true,
						},
					],
				},
			}),
		);

		expect(failed.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "workflow.scope")?.detail).toContain(
			"provider.bank.read",
		);
	});

	it("does not require explicitly excluded active workflows to satisfy included-workflow gates", () => {
		const bundle = safeCutoverBundle();
		const report = evaluateCutoverCheck(
			safeCutoverBundle({
				inventory: {
					...bundle.inventory,
					workflows: [
						...bundle.inventory.workflows,
						{
							workflow_id: "provider.bank.read",
							owner: "operator",
							trust_domain: "provider-read",
							active: true,
						},
					],
				},
				scopeManifest: {
					schemaVersion: 1,
					workflows: [
						...bundle.scopeManifest.workflows,
						{
							workflow_id: "provider.bank.read",
							owner: "operator",
							trust_domain: "provider-read",
							current_behavior: "Telclaude provider reads route through the relay.",
							hermes_target_behavior: "Excluded until provider envelope parity is proven.",
							cutover_class: "P0",
							cutover_requirement: "Provider envelope parity required before inclusion.",
							status: "excluded",
							fixture_ids: [],
							negative_fixture_ids: [],
							required_surface_ids: [],
							unresolved_decision_ids: [],
						},
					],
				},
			}),
		);

		expect(report.status).toBe("safe");
		expect(report.gates.find((gate) => gate.name === "workflow.scope")?.status).toBe("pass");
	});

	it("accepts rich Hermes inventory workflow metadata in cutover input", () => {
		const bundle = safeCutoverBundle();
		const richBundle = safeCutoverBundle({
			inventory: {
				...bundle.inventory,
				workflows: [
					{
						...bundle.inventory.workflows[0],
						current_surface: "Telclaude Telegram relay",
						hermes_target: "Hermes private profile behind Telclaude edge",
						status: "inventory_only",
						p_class: "P0",
						source_refs: ["config.telegram.allowedChats"],
						queue_refs: [],
						fixture_ids: [],
						unresolved_decision_ids: [],
						risk_notes: [],
					},
				],
			},
		});

		expect(evaluateCutoverCheck(richBundle).exitCode).toBe(0);
	});

	it("fails strict cutover when unresolved decisions affect included workflows", () => {
		const failed = evaluateCutoverCheck(
			safeCutoverBundle({
				profileGenerationProof: undefined,
				decisionLog: {
					schemaVersion: 1,
					decisions: [
						{
							id: "D-private-execution",
							status: "unresolved",
							owner: "operator",
							deadline_phase: "Phase 1",
							affected_workflows: ["private.telegram.basic"],
							cutover_impact:
								"Private Telegram workflow cannot cut over until execution seam is chosen.",
						},
					],
				},
			}),
		);

		expect(failed.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "decisions.resolved")?.detail).toContain(
			"D-private-execution",
		);
	});

	it("fails strict cutover when unresolved decisions have no workflow scope", () => {
		const failed = evaluateCutoverCheck(
			safeCutoverBundle({
				decisionLog: {
					schemaVersion: 1,
					decisions: [
						{
							id: "D-model-relay-seam",
							status: "unresolved",
							owner: "operator",
							deadline_phase: "Phase 1",
							affected_workflows: [],
							cutover_impact: "Model relay seam cannot be treated as resolved by omission.",
						},
					],
				},
			}),
		);

		expect(failed.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "decisions.resolved")?.detail).toContain(
			"D-model-relay-seam",
		);
	});

	it("fails strict cutover when an accepted profile-generation decision has no proof", () => {
		const failed = evaluateCutoverCheck(
			safeCutoverBundle({
				profileGenerationProof: undefined,
				decisionLog: {
					schemaVersion: 1,
					decisions: [
						{
							id: "D-profile-generation",
							status: "accepted",
							owner: "operator",
							deadline_phase: "Phase 1",
							accepted_answer:
								"Generated Hermes profiles are produced by the checked profile generator.",
							affected_workflows: ["private.telegram.basic"],
							cutover_impact: "Profile generation proof is required before private cutover.",
						},
					],
				},
			}),
		);

		expect(failed.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "profileGeneration.proven")?.detail).toContain(
			"has no profile-generation proof",
		);
	});

	it("fails strict cutover when included workflows omit the profile-generation decision", () => {
		const failed = evaluateCutoverCheck(
			safeCutoverBundle({
				decisionLog: { schemaVersion: 1, decisions: [] },
			}),
		);

		expect(failed.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "profileGeneration.proven")?.detail).toContain(
			"missing required decision D-profile-generation",
		);
	});

	it("passes the profile-generation gate with schema-valid generated profile evidence", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-profile-cutover-"));
		const base = safeCutoverBundle();
		const proof = writeProfileProofForBundle(tempDir, base);
		const report = evaluateCutoverCheck(
			safeCutoverBundle({
				lockfile: base.lockfile,
				noForkProof: base.noForkProof,
				profileGenerationProof: proof,
				decisionLog: {
					schemaVersion: 1,
					decisions: [
						{
							id: "D-profile-generation",
							status: "accepted",
							owner: "operator",
							deadline_phase: "Phase 1",
							accepted_answer:
								"Generated Hermes profiles are produced by the checked profile generator.",
							evidence_path: proof.evidence_path,
							affected_workflows: ["private.telegram.basic"],
							cutover_impact: "Profile generation proof is required before private cutover.",
						},
					],
				},
			}),
		);

		expect(report.exitCode).toBe(0);
		expect(report.gates.find((gate) => gate.name === "profileGeneration.proven")?.status).toBe(
			"pass",
		);
	});

	it("fails the profile-generation gate when output hashes are self-consistent but content is not canonical", () => {
		const base = safeCutoverBundle();
		const proof = structuredClone(base.profileGenerationProof) as NonNullable<
			CutoverInputBundle["profileGenerationProof"]
		>;
		const configPath = path.join(proof.outDir, "config.yaml");
		const tamperedConfig = fs
			.readFileSync(configPath, "utf8")
			.replace(
				"http://telclaude:8790/v1/openai-codex-proxy",
				"https://chatgpt.com/backend-api/codex",
			);
		fs.writeFileSync(configPath, tamperedConfig, "utf8");
		const tamperedDigest = `sha256:${crypto
			.createHash("sha256")
			.update(tamperedConfig)
			.digest("hex")}`;
		proof.outputs = proof.outputs.map((output) =>
			output.path === "config.yaml" ? { ...output, sha256: tamperedDigest } : output,
		);
		proof.directoryInventory = proof.directoryInventory.map((entry) =>
			entry.path === "config.yaml" ? { ...entry, sha256: tamperedDigest } : entry,
		);
		proof.treeDigest = computeHermesArtifactDigest(proof.directoryInventory);
		proof.manifestDigest = computeHermesArtifactDigest({
			outputs: [...proof.outputs].sort((left, right) => left.path.localeCompare(right.path)),
			secretManifest: [...proof.secretManifest].sort((left, right) =>
				left.id.localeCompare(right.id),
			),
			treeDigest: proof.treeDigest,
		});
		writeJson(proof.evidence_path, proof);

		const report = evaluateCutoverCheck({ ...base, profileGenerationProof: proof });

		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "profileGeneration.proven")?.detail).toContain(
			"profile output config.yaml does not match canonical generator output",
		);
	});

	it("fails the profile-generation gate when stale files remain in the profile directory", () => {
		const base = safeCutoverBundle();
		const proof = base.profileGenerationProof as NonNullable<
			CutoverInputBundle["profileGenerationProof"]
		>;
		writeJson(path.join(proof.outDir, ".codex", "auth.json"), { token: "placeholder-only" });

		const report = evaluateCutoverCheck(base);

		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "profileGeneration.proven")?.detail).toContain(
			"profile-generation proof directoryInventory does not match output tree",
		);
	});

	it("fails the profile-generation gate when generated output contains Hermes source replacement paths", () => {
		const base = safeCutoverBundle();
		const proof = base.profileGenerationProof as NonNullable<
			CutoverInputBundle["profileGenerationProof"]
		>;
		writeJson(path.join(proof.outDir, "providers", "__init__.py"), {
			note: "runtime source replacement",
		});

		const report = evaluateCutoverCheck(base);

		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "profileGeneration.proven")?.detail).toContain(
			"profile-generation output contains Hermes source replacement artifacts: providers/__init__.py",
		);
	});

	it("fails strict cutover when feature probes are not tied to the lockfile pin", () => {
		const [probe] = featureProbeMatrix.probes;
		const failed = evaluateCutoverCheck(
			safeCutoverBundle({
				featureProbeMatrix: {
					schemaVersion: 1,
					probes: [{ ...probe, hermes_pin: { version: "0.15.0" } }],
				},
			}),
		);

		expect(failed.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "lockfile.consistent")?.detail).toContain(
			"not tied to the lockfile Hermes pin",
		);
	});

	it("fails strict cutover when the lockfile digest or probe status is stale", () => {
		const staleDigest = evaluateCutoverCheck(
			safeCutoverBundle({
				lockfile: {
					...compatLockfile,
					featureProbeMatrixDigest: "sha256:stale",
				},
			}),
		);
		expect(staleDigest.status).toBe("fail");
		expect(staleDigest.gates.find((gate) => gate.name === "lockfile.consistent")?.detail).toContain(
			"digest does not match",
		);

		const failedProbe = evaluateCutoverCheck(
			safeCutoverBundle({
				lockfile: {
					...compatLockfile,
					featureProbes: [{ ...compatLockfile.featureProbes[0], status: "fail" }],
				},
			}),
		);
		expect(failedProbe.status).toBe("fail");
		expect(failedProbe.gates.find((gate) => gate.name === "lockfile.consistent")?.detail).toContain(
			"status is fail",
		);
	});

	it("fails strict cutover when lockfile proof fields are placeholders", () => {
		const failed = evaluateCutoverCheck(
			safeCutoverBundle({
				lockfile: {
					...compatLockfile,
					adapterApiSignatures: { "edge.whatsapp": "sha256:pending" },
					paritySuiteDigests: { p0: "sha256:pending" },
					sourceDriftSignals: { sourceCommit: "pending", docsCommit: "pending" },
				},
			}),
		);

		expect(failed.status).toBe("fail");
		const detail = failed.gates.find((gate) => gate.name === "lockfile.consistent")?.detail ?? "";
		expect(detail).toContain("adapterApiSignatures.edge.whatsapp");
		expect(detail).toContain("paritySuiteDigests.p0");
		expect(detail).toContain("sourceDriftSignals.sourceCommit");
	});

	it("fails strict cutover when fixture evidence is missing", () => {
		const missingDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-fixture-missing-"));
		const failed = evaluateCutoverCheck(
			safeCutoverBundle({
				fixtureResults: {
					schemaVersion: 1,
					results: [
						{
							id: "fixture.private.telegram.basic",
							status: "pass",
							evidence_path: path.join(missingDir, "missing.json"),
						},
						{
							id: "fixture.private.telegram.basic.deny",
							status: "pass",
							evidence_path: path.join(missingDir, "missing-deny.json"),
						},
					],
				},
			}),
		);

		expect(failed.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "fixtures.pass")?.detail).toContain(
			"missing fixture evidence",
		);
	});

	it("fails strict cutover for imported private Telegram fixture reports", () => {
		const fixtureResults = writeFixtureResults();
		for (const fixture of fixtureResults.results) {
			const evidence = readJson(fixture.evidence_path) as Record<string, unknown>;
			delete evidence.invocation;
			evidence.provenance = { runner: "vitest-json", source: "imported-test-report" };
			writeJson(fixture.evidence_path, evidence);
		}

		const failed = evaluateCutoverCheck(safeCutoverBundle({ fixtureResults }));

		expect(failed.status).toBe("fail");
		const detail = failed.gates.find((gate) => gate.name === "fixtures.pass")?.detail ?? "";
		expect(detail).toContain("provenance source is not machine-observed-test-report");
		expect(detail).toContain("missing Vitest invocation transcript");
	});

	it("fails strict cutover when the Vitest report failed even if required assertions passed", () => {
		const fixtureResults = writeFixtureResults();
		const evidence = readJson(fixtureResults.results[0].evidence_path) as {
			testReport: { path: string };
		};
		const report = privateTelegramVitestReport();
		report.success = false;
		report.numFailedTestSuites = 1;
		writeJson(evidence.testReport.path, report);

		const failed = evaluateCutoverCheck(safeCutoverBundle({ fixtureResults }));

		expect(failed.status).toBe("fail");
		const detail = failed.gates.find((gate) => gate.name === "fixtures.pass")?.detail ?? "";
		expect(detail).toContain("test report success is not true");
		expect(detail).toContain("numFailedTestSuites is 1");
	});

	it("fails strict cutover when required fixture assertions appear in the wrong test file", () => {
		const fixtureResults = writeFixtureResults();
		const evidence = readJson(fixtureResults.results[0].evidence_path) as {
			testReport: { path: string };
		};
		const report = privateTelegramVitestReport();
		report.testResults[0].name = "tests/integration/forged-control-plane.test.ts";
		writeJson(evidence.testReport.path, report);

		const failed = evaluateCutoverCheck(safeCutoverBundle({ fixtureResults }));

		expect(failed.status).toBe("fail");
		const detail = failed.gates.find((gate) => gate.name === "fixtures.pass")?.detail ?? "";
		expect(detail).toContain("unexpected suite");
		expect(detail).toContain(
			"is missing from tests/integration/telegram-control-plane.replay.test.ts",
		);
	});

	it("fails strict cutover when fixture invocation source digests are stale", () => {
		const fixtureResults = writeFixtureResults();
		const evidencePath = fixtureResults.results[0].evidence_path;
		const evidence = readJson(evidencePath) as {
			invocation: { sourceDigests: Record<string, string> };
		};
		evidence.invocation.sourceDigests["src/telegram/command-gating.ts"] =
			`sha256:${"0".repeat(64)}`;
		writeJson(evidencePath, evidence);

		const failed = evaluateCutoverCheck(safeCutoverBundle({ fixtureResults }));

		expect(failed.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "fixtures.pass")?.detail).toContain(
			"source digest changed for src/telegram/command-gating.ts",
		);
	});

	it("returns cutover exit code 2 for malformed checker inputs", () => {
		const report = evaluateCutoverCheck({ schemaVersion: 1 });
		expect(report.status).toBe("input_error");
		expect(report.exitCode).toBe(2);
	});

	it("does not apply wall-clock proof-bundle recency to archival dry-run checks", () => {
		const report = evaluateCutoverCheck(safeCutoverBundle(), {
			strict: true,
			dryRun: true,
			liveCutover: false,
			now: new Date("2026-07-01T00:00:00.000Z"),
		});

		expect(report.exitCode).toBe(0);
		expect(report.gates.map((gate) => gate.name)).not.toContain("proofBundle.generatedAt.live");
	});

	it("fails live cutover checks when the proof bundle is stale by wall clock", () => {
		const report = evaluateCutoverCheck(safeCutoverBundle(), {
			strict: true,
			dryRun: false,
			liveCutover: true,
			now: new Date("2026-07-01T00:00:00.000Z"),
		});

		expect(report.status).toBe("input_error");
		expect(report.exitCode).toBe(2);
		expect(report.gates.find((gate) => gate.name === "proofBundle.generatedAt.live")).toMatchObject(
			{
				status: "fail",
			},
		);
	});

	it("registers the top-level hermes command group", () => {
		const program = new Command();
		registerHermesCommand(program);
		expect(program.commands.map((command) => command.name())).toContain("hermes");
	});

	it("registers the approval-continuation probe command", () => {
		const program = new Command();
		registerHermesCommand(program);
		const hermesCommand = program.commands.find((command) => command.name() === "hermes");
		expect(hermesCommand?.commands.map((command) => command.name())).toContain("probe");
	});

	it("registers the network-probes command", () => {
		const program = new Command();
		registerHermesCommand(program);
		const hermesCommand = program.commands.find((command) => command.name() === "hermes");
		expect(hermesCommand?.commands.map((command) => command.name())).toContain("network-probes");
		expect(hermesCommand?.commands.map((command) => command.name())).toContain("queue-snapshot");
		expect(hermesCommand?.commands.map((command) => command.name())).toContain(
			"rollback-rehearsal",
		);
	});

	it("registers the fixtures command", () => {
		const program = new Command();
		registerHermesCommand(program);
		const hermesCommand = program.commands.find((command) => command.name() === "hermes");
		expect(hermesCommand?.commands.map((command) => command.name())).toContain("fixtures");
	});

	it("registers the pro-review-check command", () => {
		const program = new Command();
		registerHermesCommand(program);
		const hermesCommand = program.commands.find((command) => command.name() === "hermes");
		expect(hermesCommand?.commands.map((command) => command.name())).toContain("pro-review-check");
		expect(hermesCommand?.commands.map((command) => command.name())).toContain("pro-review-send");
	});

	it("validates pending ChatGPT Pro native-extension review evidence without sending a bundle", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-"));
		writeRequiredProReviewWorkspace(tempDir);
		await withCwd(tempDir, async () => {
			const requestPath = "docs/hermes/pro-review-request.json";
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			writeJson(canaryPath, proReviewCanary());
			writeJson(requestPath, proReviewRequest(canaryPath));

			const result = await runHermesCommand([
				"hermes",
				"pro-review-check",
				"--json",
				"--request",
				requestPath,
				"--canary",
				canaryPath,
			]);
			const report = JSON.parse(result.stdout) as {
				status: string;
				gates: Array<{ name: string; status: string; detail: string }>;
			};

			expect(result.exitCode, result.stdout).toBe(2);
			expect(report.status).toBe("pending");
			expect(report.gates.some((gate) => gate.status === "fail")).toBe(false);
			expect(report.gates.find((gate) => gate.name === "disclosure.approved")).toMatchObject({
				status: "pending",
			});
		});
	});

	it("fails Pro review readiness when exact private disclosure approval is required but absent", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-"));
		writeRequiredProReviewWorkspace(tempDir);
		const requestPath = path.join(tempDir, "docs/hermes/pro-review-request.json");
		const canaryPath = path.join(tempDir, "artifacts/hermes/pro-review-native-canary.json");
		await withCwd(tempDir, async () => {
			writeJson(canaryPath, proReviewCanary());
			writeJson(requestPath, proReviewRequest(canaryPath));

			const result = await runHermesCommand([
				"hermes",
				"pro-review-check",
				"--json",
				"--require-approval",
				"--request",
				requestPath,
				"--canary",
				canaryPath,
			]);
			const report = JSON.parse(result.stdout) as {
				status: string;
				gates: Array<{ name: string; status: string; detail: string }>;
			};

			expect(result.exitCode).toBe(1);
			expect(report.status).toBe("fail");
			expect(report.gates.find((gate) => gate.name === "disclosure.approved")).toMatchObject({
				status: "fail",
				detail: "private workspace disclosure is not approved",
			});
		});
	});

	it("allows Pro review readiness to carry explicitly red cli_headless evidence", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-red-"));
		writeRequiredProReviewWorkspace(tempDir);
		await withCwd(tempDir, async () => {
			const requestPath = "docs/hermes/pro-review-request.json";
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			writeJson(canaryPath, proReviewCanary());
			writeJson(
				"artifacts/hermes/probes/execution-cli-headless.json",
				cliHeadlessReadinessFailureEvidence(),
			);
			writeJson(requestPath, proReviewRequest(canaryPath));

			const result = await runHermesCommand([
				"hermes",
				"pro-review-check",
				"--json",
				"--request",
				requestPath,
				"--canary",
				canaryPath,
			]);
			const report = JSON.parse(result.stdout) as {
				status: string;
				gates: Array<{ name: string; status: string; detail: string }>;
			};

			expect(result.exitCode).toBe(2);
			expect(report.status).toBe("pending");
			expect(
				report.gates.find((gate) => gate.name === "request.cliHeadlessEvidence"),
			).toMatchObject({
				status: "pass",
				detail: expect.stringContaining("explicitly red"),
			});
			expect(report.gates.find((gate) => gate.name === "disclosure.approved")).toMatchObject({
				status: "pending",
			});
		});
	});

	it("refuses Pro review send unless native evidence and exact private disclosure approval pass", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-send-"));
		writeRequiredProReviewWorkspace(tempDir);
		await withCwd(tempDir, async () => {
			const requestPath = "docs/hermes/pro-review-request.json";
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			writeJson(canaryPath, proReviewCanary());
			writeJson(requestPath, proReviewRequest(canaryPath));

			const result = await runHermesCommand([
				"hermes",
				"pro-review-send",
				"--json",
				"--request",
				requestPath,
				"--canary",
				canaryPath,
			]);
			const report = JSON.parse(result.stdout) as {
				send: { status: string; reason: string; yoetzCommand: string[] };
				report: { gates: Array<{ name: string; status: string }> };
			};

			expect(result.exitCode).toBe(1);
			expect(report.send).toMatchObject({
				status: "refused",
				reason: "pro-review-check did not pass with approval required",
			});
			expect(report.send.yoetzCommand).toEqual(
				expect.arrayContaining(["--transport", "chrome-extension-native"]),
			);
			expect(report.report.gates.find((gate) => gate.name === "disclosure.approved")).toMatchObject(
				{
					status: "fail",
				},
			);
		});
	});

	it("fails Pro review evidence when a required selected file is missing", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-required-"));
		writeRequiredProReviewWorkspace(tempDir);
		await withCwd(tempDir, async () => {
			const requestPath = "docs/hermes/pro-review-request.json";
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			const selectedFiles = REQUIRED_PRO_REVIEW_FILES.filter(
				(file) => file !== "docs/hermes/decisions.json",
			);
			writeJson(canaryPath, proReviewCanary());
			writeJson(requestPath, proReviewRequest(canaryPath, {}, selectedFiles));

			const result = await runHermesCommand([
				"hermes",
				"pro-review-check",
				"--json",
				"--request",
				requestPath,
				"--canary",
				canaryPath,
			]);
			const report = JSON.parse(result.stdout) as {
				gates: Array<{ name: string; status: string; detail: string }>;
			};

			expect(result.exitCode).toBe(1);
			expect(report.gates.find((gate) => gate.name === "request.requiredFiles")).toMatchObject({
				status: "fail",
				detail: expect.stringContaining("docs/hermes/decisions.json"),
			});
		});
	});

	it("fails Pro review evidence when the selected payload digest is stale", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-"));
		const requestPath = path.join(tempDir, "pro-review-request.json");
		const canaryPath = path.join(tempDir, "pro-review-native-canary.json");
		writeJson(canaryPath, proReviewCanary());
		writeJson(
			requestPath,
			proReviewRequest(canaryPath, {
				payloadBinding: {
					...(proReviewRequest(canaryPath).payloadBinding as Record<string, unknown>),
					payloadSha256: `sha256:${"0".repeat(64)}`,
				},
			}),
		);

		const result = await runHermesCommand([
			"hermes",
			"pro-review-check",
			"--json",
			"--request",
			requestPath,
			"--canary",
			canaryPath,
		]);
		const report = JSON.parse(result.stdout) as {
			status: string;
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode, result.stdout).toBe(1);
		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "request.payloadBinding")).toMatchObject({
			status: "fail",
			detail: "payloadSha256 does not match review content, selected files, and native evidence",
		});
	});

	it("fails Pro review evidence when selected file contents changed after payload binding", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-"));
		const selectedPath = path.join(tempDir, "selected.txt");
		const requestPath = path.join(tempDir, "pro-review-request.json");
		const canaryPath = path.join(tempDir, "pro-review-native-canary.json");
		fs.writeFileSync(selectedPath, "before\n");
		writeJson(canaryPath, proReviewCanary());
		writeJson(requestPath, proReviewRequest(canaryPath, {}, [selectedPath]));
		fs.writeFileSync(selectedPath, "after\n");

		const result = await runHermesCommand([
			"hermes",
			"pro-review-check",
			"--json",
			"--request",
			requestPath,
			"--canary",
			canaryPath,
		]);
		const report = JSON.parse(result.stdout) as {
			status: string;
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode, result.stdout).toBe(1);
		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "request.payloadBinding")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("selectedFileContentsSha256 does not match"),
		});
	});

	it("fails approved Pro review metadata when approval is not bound to the payload digest", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-"));
		const requestPath = path.join(tempDir, "pro-review-request.json");
		const canaryPath = path.join(tempDir, "pro-review-native-canary.json");
		const baseRequest = proReviewRequest(canaryPath);
		writeJson(canaryPath, proReviewCanary());
		writeJson(
			requestPath,
			proReviewRequest(canaryPath, {
				status: "approved",
				privateWorkspaceDisclosure: {
					...(baseRequest.privateWorkspaceDisclosure as Record<string, unknown>),
					approved: true,
					approvalId: "approval-1",
					operator: "aviv",
					approvedAt: "2026-05-31T17:10:00Z",
					payloadSha256: `sha256:${"1".repeat(64)}`,
				},
			}),
		);

		const result = await runHermesCommand([
			"hermes",
			"pro-review-check",
			"--json",
			"--require-approval",
			"--request",
			requestPath,
			"--canary",
			canaryPath,
		]);
		const report = JSON.parse(result.stdout) as {
			status: string;
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode).toBe(1);
		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "disclosure.approved")).toMatchObject({
			status: "fail",
			detail: "approval payloadSha256 does not match payloadBinding.payloadSha256",
		});
	});

	it("fails Pro review evidence when the native canary omits no-fallback proof", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-"));
		const requestPath = path.join(tempDir, "pro-review-request.json");
		const canaryPath = path.join(tempDir, "pro-review-native-canary.json");
		writeJson(
			canaryPath,
			proReviewCanary({
				checks: (proReviewCanary().checks as Array<{ name: string }>).filter(
					(check) => check.name !== "fallback.disabled",
				),
			}),
		);
		writeJson(requestPath, proReviewRequest(canaryPath));

		const result = await runHermesCommand([
			"hermes",
			"pro-review-check",
			"--json",
			"--request",
			requestPath,
			"--canary",
			canaryPath,
		]);
		const report = JSON.parse(result.stdout) as {
			status: string;
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode).toBe(1);
		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "nativeCanary.requiredChecks")).toMatchObject({
			status: "fail",
			detail: "fallback.disabled check is missing or not pass",
		});
	});

	it("fails Pro review evidence when the native live canary is not extension-instance bound", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-"));
		const requestPath = path.join(tempDir, "pro-review-request.json");
		const canaryPath = path.join(tempDir, "pro-review-native-canary.json");
		writeJson(
			canaryPath,
			proReviewCanary({
				liveCanary: {
					...(proReviewCanary().liveCanary as Record<string, unknown>),
					command: "YOETZ_AGENT=1 yoetz browser extension canary --chatgpt --live --format json",
				},
			}),
		);
		writeJson(requestPath, proReviewRequest(canaryPath));

		const result = await runHermesCommand([
			"hermes",
			"pro-review-check",
			"--json",
			"--request",
			requestPath,
			"--canary",
			canaryPath,
		]);
		const report = JSON.parse(result.stdout) as {
			status: string;
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode).toBe(1);
		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "nativeCanary.requiredChecks")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("live canary command does not bind an extension instance"),
		});
	});

	it("writes private Telegram fixture results from a machine-observed Vitest report", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-fixtures-"));
		const testReportPath = path.join(tempDir, "private-telegram-vitest.json");
		const outPath = path.join(tempDir, "fixture-results.json");
		const evidenceDir = path.join(tempDir, "evidence");

		const result = await runHermesCommand([
			"hermes",
			"fixtures",
			"--write",
			"--json",
			"--report-out",
			testReportPath,
			"--out",
			outPath,
			"--evidence-dir",
			evidenceDir,
			"--observed-at",
			"2026-05-31T00:00:00.000Z",
		]);
		const report = JSON.parse(result.stdout) as {
			status: string;
			results: Array<{ id: string; status: string; evidence_path: string }>;
		};
		const bundle = readJson(outPath) as CutoverInputBundle["fixtureResults"];

		expect(result.exitCode).toBe(0);
		expect(report.status).toBe("pass");
		expect(bundle.results.map((fixture) => fixture.status)).toEqual(["pass", "pass"]);
		for (const fixture of bundle.results) {
			expect(fs.existsSync(fixture.evidence_path)).toBe(true);
			expect(readJson(fixture.evidence_path)).toMatchObject({
				id: fixture.id,
				status: "pass",
				provenance: { runner: "vitest-json", source: "machine-observed-test-report" },
				invocation: { exitCode: 0, reportPath: testReportPath },
			});
		}
		expect(
			evaluateCutoverCheck(safeCutoverBundle({ fixtureResults: bundle })).gates.find(
				(gate) => gate.name === "fixtures.pass",
			),
		).toMatchObject({ status: "pass" });
	});

	it("refuses to write imported private Telegram fixture reports", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-fixtures-imported-"));
		const testReportPath = path.join(tempDir, "private-telegram-vitest.json");
		const outPath = path.join(tempDir, "fixture-results.json");
		const evidenceDir = path.join(tempDir, "evidence");
		writeJson(testReportPath, privateTelegramVitestReport());

		const result = await runHermesCommand([
			"hermes",
			"fixtures",
			"--write",
			"--json",
			"--test-report",
			testReportPath,
			"--out",
			outPath,
			"--evidence-dir",
			evidenceDir,
		]);
		const report = JSON.parse(result.stdout) as { status: string; detail?: string };

		expect(result.exitCode).toBe(1);
		expect(report.status).toBe("input_error");
		expect(report.detail).toContain("Imported private Telegram fixture reports cannot be written");
		expect(fs.existsSync(outPath)).toBe(false);
		expect(fs.existsSync(evidenceDir)).toBe(false);
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

	it("evaluates P0 cutover gates when prove is run with --p0", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-prove-p0-"));
		const base = safeCutoverBundle();
		const paths = writeCutoverBundleArtifacts(
			tempDir,
			safeCutoverBundle({
				inventory: {
					...base.inventory,
					status: "complete",
					summary: {
						pendingQueues: pendingQueues(),
					},
				},
			}),
		);

		const result = await runHermesCommand([
			"hermes",
			"prove",
			"--upstream-clean",
			"--p0",
			"--json",
			"--checkout",
			tempDir,
			"--out",
			paths.nofork,
			"--inventory",
			paths.inventory,
			"--scope",
			paths.scope,
			"--decisions",
			paths.decisions,
			"--proof-bundle",
			paths.proofBundle,
			"--feature-probes",
			paths.featureProbes,
			"--lockfile",
			paths.lockfile,
			"--fixtures",
			paths.fixtures,
			"--network-probes",
			paths.networkProbes,
			"--profile-proof",
			paths.profileProof,
			"--rollback",
			paths.rollback,
		]);
		const report = JSON.parse(result.stdout) as {
			noForkProof: { hermesCheckoutClean: boolean };
			p0: { status: string; gates: Array<{ name: string; status: string }> };
		};

		expect(result.exitCode, result.stdout).toBe(1);
		expect(report.noForkProof.hermesCheckoutClean).toBe(false);
		expect(report.p0.status).toBe("fail");
		expect(report.p0.gates.find((gate) => gate.name === "profileGeneration.proven")).toMatchObject({
			status: "pass",
		});
		expect(report.p0.gates.find((gate) => gate.name === "nofork.clean")).toMatchObject({
			status: "fail",
		});
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

	it("writes passing network-probe artifacts from observed denials and a reachable relay control", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-probe-"));
		const relay = await startProbeServer();
		try {
			const outPath = path.join(tempDir, "network-probes.json");
			const evidenceDir = path.join(tempDir, "evidence");
			const deniedProviderUrl = await closedProbeUrl();
			const deniedModelUrl = await closedProbeUrl();
			const deniedDnsUrl = await closedProbeUrl();

			const result = await runHermesCommand([
				"hermes",
				"network-probes",
				"--allow-run",
				"--json",
				"--relay-url",
				relay.url,
				"--provider-url",
				deniedProviderUrl,
				"--model-url",
				deniedModelUrl,
				"--dns-url",
				deniedDnsUrl,
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
					?.attempts.find((attempt) => attempt.name === "provider"),
			).toMatchObject({ observed: "denied", errorCode: "ECONNREFUSED" });
			expect(
				report.evidence
					.find((probe) => probe.id === "network.relay-control-allowed")
					?.attempts.find((attempt) => attempt.name === "relay-control"),
			).toMatchObject({ observed: "reachable" });
		} finally {
			await relay.close();
		}
	});

	it("writes contained-internal network-probe artifacts without a firewall sentinel", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-probe-"));
		const relay = await startProbeServer();
		try {
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
				await closedProbeUrl(),
				"--model-url",
				await closedProbeUrl(),
				"--dns-url",
				await closedProbeUrl(),
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
			return passingNetworkProbeEvidence(id, evidencePath);
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
			});
		}
		expect(promoted.evidence.map((probe) => probe.evidence_path)).toEqual(
			bundle.probes.map((probe) => probe.evidence_path),
		);
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

	it("does not write rollback rehearsal evidence without --allow-run", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-rollback-cli-"));
		const outPath = path.join(tempDir, "rollback.json");

		const result = await runHermesCommand([
			"hermes",
			"rollback-rehearsal",
			"--json",
			"--out",
			outPath,
		]);
		const report = JSON.parse(result.stdout) as { allowedToRun: boolean; written: boolean };

		expect(result.exitCode).toBe(2);
		expect(report.allowedToRun).toBe(false);
		expect(report.written).toBe(false);
		expect(fs.existsSync(outPath)).toBe(false);
	});

	it("writes rollback rehearsal evidence by driving the relay capability surface", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-rollback-cli-"));
		const outPath = path.join(tempDir, "rollback.json");
		const originalUrl = process.env.TELCLAUDE_CAPABILITIES_URL;
		const originalOperatorPrivate = process.env.OPERATOR_RPC_AGENT_PRIVATE_KEY;
		const originalOperatorPublic = process.env.OPERATOR_RPC_AGENT_PUBLIC_KEY;
		const originalOperatorRelayPrivate = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
		const originalOperatorRelayPublic = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		const keys = generateKeyPair();
		const relayKeys = generateKeyPair();
		let statusCalls = 0;
		shutdownTokenClient();
		const relay = await startProbeServer((req, res) => {
			const requestPath = req.url?.split("?")[0] ?? "";
			res.setHeader("Content-Type", "application/json");
			if (requestPath === "/v1/hermes.private-runtime.status") {
				statusCalls += 1;
				res.end(
					signedRuntimeStatePayload(
						requestPath,
						"{}",
						statusCalls === 1 ? hermesRuntimeState() : legacyRuntimeState(),
					),
				);
				return;
			}
			if (requestPath === "/v1/hermes.private-runtime.mode") {
				res.end(
					signedRuntimeStatePayload(
						requestPath,
						JSON.stringify({ mode: "legacy" }),
						legacyRuntimeState(),
					),
				);
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
			const result = await runHermesCommand([
				"hermes",
				"rollback-rehearsal",
				"--allow-run",
				"--json",
				"--out",
				outPath,
				"--evidence-path",
				"artifacts/hermes/rollback-rehearsal.json",
			]);
			const report = JSON.parse(result.stdout) as {
				passed: boolean;
				written: boolean;
				evidence_path: string;
				observedBeforeValue: string;
				observedAfterValue: string;
				controlSurface: string;
			};
			const evidence = readJson(outPath) as {
				passed: boolean;
				evidence_path: string;
				observedAfterControlSource: string;
			};

			expect(result.exitCode, result.stdout).toBe(0);
			expect(report).toMatchObject({
				passed: true,
				written: true,
				evidence_path: "artifacts/hermes/rollback-rehearsal.json",
				observedBeforeValue: "1",
				observedAfterValue: "0",
			});
			expect(evidence).toMatchObject({
				passed: true,
				evidence_path: "artifacts/hermes/rollback-rehearsal.json",
				observedAfterControlSource: "runtime-config",
			});
			expect(statusCalls).toBe(2);
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

	it("rejects forged rollback evidence from an unsigned fake capability surface", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-rollback-cli-"));
		const outPath = path.join(tempDir, "rollback.json");
		const originalUrl = process.env.TELCLAUDE_CAPABILITIES_URL;
		const originalOperatorPrivate = process.env.OPERATOR_RPC_AGENT_PRIVATE_KEY;
		const originalOperatorPublic = process.env.OPERATOR_RPC_AGENT_PUBLIC_KEY;
		const originalOperatorRelayPublic = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		const keys = generateKeyPair();
		const relayKeys = generateKeyPair();
		let statusCalls = 0;
		shutdownTokenClient();
		const relay = await startProbeServer((req, res) => {
			const requestPath = req.url?.split("?")[0] ?? "";
			res.setHeader("Content-Type", "application/json");
			if (requestPath === "/v1/hermes.private-runtime.status") {
				statusCalls += 1;
				res.end(JSON.stringify(statusCalls === 1 ? hermesRuntimeState() : legacyRuntimeState()));
				return;
			}
			if (requestPath === "/v1/hermes.private-runtime.mode") {
				res.end(JSON.stringify(legacyRuntimeState()));
				return;
			}
			res.statusCode = 404;
			res.end(JSON.stringify({ error: `not found: ${requestPath}` }));
		});
		process.env.OPERATOR_RPC_AGENT_PRIVATE_KEY = keys.privateKey;
		process.env.OPERATOR_RPC_AGENT_PUBLIC_KEY = keys.publicKey;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;
		process.env.TELCLAUDE_CAPABILITIES_URL = new URL(relay.url).origin;
		try {
			const result = await runHermesCommand([
				"hermes",
				"rollback-rehearsal",
				"--allow-run",
				"--json",
				"--out",
				outPath,
			]);
			const report = JSON.parse(result.stdout) as { passed: boolean; written: boolean };

			expect(result.exitCode).toBe(2);
			expect(report.passed).toBe(false);
			expect(report.written).toBe(false);
			expect(fs.existsSync(outPath)).toBe(false);
		} finally {
			await relay.close();
			shutdownTokenClient();
			restoreEnv("TELCLAUDE_CAPABILITIES_URL", originalUrl);
			restoreEnv("OPERATOR_RPC_AGENT_PRIVATE_KEY", originalOperatorPrivate);
			restoreEnv("OPERATOR_RPC_AGENT_PUBLIC_KEY", originalOperatorPublic);
			restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", originalOperatorRelayPublic);
		}
	});

	it("sets and observes private-runtime durable mode through relay operator RPC", async () => {
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
			if (requestPath === "/v1/hermes.private-runtime.mode") {
				res.end(
					signedRuntimeStatePayload(
						requestPath,
						JSON.stringify({ mode: "hermes" }),
						hermesRuntimeState(),
					),
				);
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
			const setResult = await runHermesCommand([
				"hermes",
				"private-runtime",
				"set",
				"hermes",
				"--json",
			]);
			const statusResult = await runHermesCommand([
				"hermes",
				"private-runtime",
				"status",
				"--json",
			]);

			expect(setResult.exitCode, setResult.stdout).toBe(0);
			expect(JSON.parse(setResult.stdout)).toMatchObject({
				effectiveMode: "hermes",
				controlSource: "runtime-config",
			});
			expect(statusResult.exitCode, statusResult.stdout).toBe(0);
			expect(JSON.parse(statusResult.stdout)).toMatchObject({ effectiveValue: "1" });
			expect(requests).toEqual([
				"/v1/hermes.private-runtime.mode",
				"/v1/hermes.private-runtime.status",
			]);
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

	it("fails cutover when the required relay-control network probe is missing", () => {
		const failed = evaluateCutoverCheck(
			safeCutoverBundle({
				networkProbes: {
					schemaVersion: 1,
					probes: requiredNetworkProbeIds
						.filter((id) => id !== "network.relay-control-allowed")
						.map((id) => ({
							id,
							status: "pass",
							evidence_path: `artifacts/hermes/${id}.json`,
						})),
				},
			}),
		);

		expect(failed.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "networkProbes.pass")?.detail).toContain(
			"missing network probe network.relay-control-allowed",
		);
	});

	it("does not run or write approval-continuation evidence without --allow-run", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-approval-probe-"));
		const evidencePath = path.join(tempDir, "approval-continuation.json");

		const result = await runHermesCommand([
			"hermes",
			"probe",
			"execution.approval_continuation",
			"--json",
			"--evidence",
			evidencePath,
		]);
		const report = JSON.parse(result.stdout) as { status: string; ran: boolean };

		expect(result.exitCode).toBe(2);
		expect(report).toMatchObject({ status: "pending", ran: false });
		expect(fs.existsSync(evidencePath)).toBe(false);
	});

	it("writes passing approval-continuation evidence only after an allowed live run", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-approval-probe-"));
		const evidencePath = path.join(tempDir, "approval-continuation.json");

		const result = await runHermesCommand([
			"hermes",
			"probe",
			"execution.approval_continuation",
			"--allow-run",
			"--pin",
			"0.15.1",
			"--json",
			"--evidence",
			evidencePath,
		]);
		const report = JSON.parse(result.stdout) as {
			status: string;
			ran: boolean;
			evidencePath: string;
		};
		const evidence = readJson(evidencePath) as {
			native: Record<string, unknown>;
			fallback: { fixtures: Array<{ status: string; evidence_path: string }> };
		};
		const serializedEvidence = JSON.stringify(evidence);

		expect(result.exitCode).toBe(0);
		expect(report).toMatchObject({ status: "pass", ran: true, evidencePath });
		expect(evidence.native).toMatchObject({
			wrong_actor_denied: true,
			stale_request_denied: true,
			replay_denied: true,
			mutated_decision_denied: true,
		});
		expect(evidence.fallback.fixtures.map((fixture) => fixture.status)).toEqual([
			"pass",
			"pass",
			"pass",
			"pass",
		]);
		for (const fixture of evidence.fallback.fixtures) {
			expect(fs.existsSync(fixture.evidence_path)).toBe(true);
		}
		expect(serializedEvidence).not.toContain("v1.");
		expect(serializedEvidence).not.toContain("approvalToken");
		expect(serializedEvidence).not.toContain("signature");
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
		const report = JSON.parse(result.stdout) as { status: string; ran: boolean };

		expect(result.exitCode).toBe(2);
		expect(report).toMatchObject({ status: "pending", ran: false });
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

	it("does not pass cli-headless docker exec evidence without relay proof", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cli-docker-exec-"));
		const evidencePath = path.join(tempDir, "evidence.json");
		const callsPath = path.join(tempDir, "docker-calls.txt");
		const dockerBin = writeExecutable(
			tempDir,
			`#!/bin/sh
printf '%s\\n' "$*" >> "${callsPath}"
if [ "$1" = "inspect" ]; then
  printf '%s\\n' '{"Id":"container-id","Image":"sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7","Config":{"Image":"nousresearch/hermes-agent@sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7","Hostname":"tc-hermes-contained"},"NetworkSettings":{"Networks":{"telclaude-hermes-relay":{"IPAddress":"172.29.92.11"}}}}'
  exit 0
fi
if [ "$1" = "exec" ] && [ "$3" = "python" ]; then
  printf '%s\\n' '{"observedPeerAddress":"172.29.92.11","relayResolvedAddress":"172.29.92.10"}'
  exit 0
fi
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
			stdoutPreview: string;
		};

		expect(result.exitCode, result.stdout).toBe(1);
		expect(report.status).toBe("fail");
		expect(report.summary).toBe(
			"Hermes CLI oneshot probe lacks relay-backed model proof: relay proof is missing",
		);
		expect(report.stdoutPreview).toContain("HERMES_OK_DOCKEREXEC");
		expect(report.runtime).toMatchObject({
			kind: "contained-docker",
			containerName: "tc-hermes-contained",
			networkName: "telclaude-hermes-relay",
			relayResolvedAddress: "172.29.92.10",
			containerIpAddress: "172.29.92.11",
			observedPeerAddress: "172.29.92.11",
			provenanceSource: "docker-inspect-container-dns-and-relay-peer",
		});
		expect(JSON.stringify(report)).not.toContain("relay-scoped-proxy-token");
		expect(fs.readFileSync(callsPath, "utf8")).not.toContain("relay-scoped-proxy-token");
		expect(readJson(evidencePath)).toMatchObject({ status: "fail", runtime: report.runtime });
	});

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

	it("writes a passing cli-headless artifact only with runtime and relay proof", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cli-probe-"));
		const evidencePath = path.join(tempDir, "evidence.json");
		const hermesBin = writeExecutable(
			tempDir,
			`#!/bin/sh
observed_at=$(node -e 'process.stdout.write(new Date().toISOString())')
cat > "$HERMES_HOME/runtime-evidence.json" <<'JSON'
{
  "kind": "contained-docker",
  "containerName": "tc-hermes-contained",
  "networkName": "telclaude-hermes-relay",
  "containerId": "tc-hermes-contained-container-id",
  "image": "nousresearch/hermes-agent@sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7",
  "imageDigest": "sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7",
  "hostname": "tc-hermes-contained",
  "relayHost": "telclaude",
  "relayResolvedAddress": "172.29.92.10",
  "containerIpAddress": "172.29.92.11",
  "observedPeerAddress": "172.29.92.11",
  "provenanceSource": "docker-inspect-container-dns-and-relay-peer"
}
JSON
cat > "$HERMES_HOME/relay-proof.json" <<JSON
{
  "schemaVersion": "telclaude.hermes.cli-headless-relay-proof.v1",
  "source": "telclaude-openai-codex-proxy",
  "requestId": "codex-proof-1",
  "method": "POST",
  "path": "/backend-api/codex/responses",
  "observedPeerAddress": "172.29.92.11",
  "upstreamStatus": 200,
  "model": "gpt-5.3-codex",
  "requestBodySha256": "sha256:${"a".repeat(64)}",
  "observedAt": "$observed_at"
}
JSON
echo "TELCLAUDE_HERMES_CLI_OK"
exit 0
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
		const report = JSON.parse(result.stdout) as { status: string; exitCode: number };
		const artifact = readJson(evidencePath) as { status: string; exitCode: number };

		expect(result.exitCode).toBe(0);
		expect(report).toMatchObject({ status: "pass", exitCode: 0 });
		expect(artifact).toMatchObject({ status: "pass", exitCode: 0 });
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

	it("passes the approval-continuation cutover gate from the existing evidence schema", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-approval-"));
		const evidencePath = path.join(tempDir, "execution-approval-continuation.json");
		const probeResult = await runHermesCommand([
			"hermes",
			"probe",
			"execution.approval_continuation",
			"--allow-run",
			"--pin",
			"0.15.1",
			"--json",
			"--evidence",
			evidencePath,
		]);
		expect(probeResult.exitCode).toBe(0);

		const result = await runCutoverCheckWithBundle(approvalContinuationCutoverBundle(evidencePath));
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode).toBe(0);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "pass",
		});
	});

	it("passes the workflow approval.continuation alias from the same observed evidence", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-approval-"));
		const evidencePath = path.join(tempDir, "execution-approval-continuation.json");
		const probeResult = await runHermesCommand([
			"hermes",
			"probe",
			"execution.approval_continuation",
			"--allow-run",
			"--pin",
			"0.15.1",
			"--json",
			"--evidence",
			evidencePath,
		]);
		expect(probeResult.exitCode).toBe(0);

		const result = await runCutoverCheckWithBundle(
			approvalContinuationCutoverBundle(evidencePath, "pass", "approval.continuation"),
		);
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode).toBe(0);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "pass",
		});
	});

	it("passes the side-effect ledger cutover gate from complete observed evidence", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-sideeffect-"));
		const evidencePath = path.join(tempDir, "sideeffect-ledger.json");
		const probeResult = await runHermesCommand([
			"hermes",
			"probe",
			"sideeffect.ledger",
			"--allow-run",
			"--json",
			"--out",
			evidencePath,
		]);
		expect(probeResult.exitCode).toBe(0);

		const result = await runCutoverCheckWithBundle(sideEffectLedgerCutoverBundle(evidencePath));
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode).toBe(0);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "pass",
		});
	});

	it("fails the side-effect ledger cutover gate when replay denial is unproven", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-sideeffect-"));
		const evidencePath = path.join(tempDir, "sideeffect-ledger.json");
		const probeResult = await runHermesCommand([
			"hermes",
			"probe",
			"sideeffect.ledger",
			"--allow-run",
			"--json",
			"--out",
			evidencePath,
		]);
		expect(probeResult.exitCode).toBe(0);
		const evidence = readJson(evidencePath) as { checks: Array<{ name: string }> };
		writeJson(evidencePath, {
			...evidence,
			checks: evidence.checks.filter((check) => check.name !== "ledger.replay-denied"),
		});

		const result = await runCutoverCheckWithBundle(sideEffectLedgerCutoverBundle(evidencePath));
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode).toBe(1);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("check ledger.replay-denied is missing"),
		});
	});

	it("passes the provider approval-binding cutover gate from complete observed evidence", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-provider-approval-"));
		const evidencePath = path.join(tempDir, "providers-approval-binding.json");
		const probeResult = await runHermesCommand([
			"hermes",
			"probe",
			"providers.approval-binding",
			"--allow-run",
			"--json",
			"--out",
			evidencePath,
		]);
		expect(probeResult.exitCode).toBe(0);

		const result = await runCutoverCheckWithBundle(
			providerApprovalBindingCutoverBundle(evidencePath),
		);
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode, result.stdout).toBe(0);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "pass",
		});
	});

	it("fails the provider approval-binding cutover gate when duplicate JTI denial is unproven", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-provider-approval-"));
		const evidencePath = path.join(tempDir, "providers-approval-binding.json");
		const probeResult = await runHermesCommand([
			"hermes",
			"probe",
			"providers.approval-binding",
			"--allow-run",
			"--json",
			"--out",
			evidencePath,
		]);
		expect(probeResult.exitCode).toBe(0);
		const evidence = readJson(evidencePath) as { checks: Array<{ name: string }> };
		writeJson(evidencePath, {
			...evidence,
			checks: evidence.checks.filter(
				(check) => check.name !== "provider.approval-binding.duplicate-jti-denied",
			),
		});

		const result = await runCutoverCheckWithBundle(
			providerApprovalBindingCutoverBundle(evidencePath),
		);
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode, result.stdout).toBe(1);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining(
				"check provider.approval-binding.duplicate-jti-denied is missing",
			),
		});
	});

	it("fails the approval-continuation cutover gate when evidence is missing", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-approval-"));
		const evidencePath = path.join(tempDir, "missing-approval-continuation.json");

		const result = await runCutoverCheckWithBundle(approvalContinuationCutoverBundle(evidencePath));
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode).toBe(1);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining(
				"feature probe execution.approval_continuation evidence failed",
			),
		});
	});

	it("fails the approval-continuation cutover gate when evidence has the wrong schema", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-approval-"));
		const evidencePath = path.join(tempDir, "bad-approval-continuation.json");
		writeJson(evidencePath, {
			schemaVersion: 1,
			hermes: hermesPin,
			native: {
				events_wait: false,
				permissions_list_open: false,
				permissions_respond: false,
				responds_to_blocked_run: false,
			},
		});

		const result = await runCutoverCheckWithBundle(approvalContinuationCutoverBundle(evidencePath));
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode).toBe(1);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("wrong actor denial is unproven"),
		});
	});

	it("fails the approval-continuation cutover gate when positive fixtures pass but replay defense is unproven", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-approval-"));
		const evidencePath = path.join(tempDir, "bad-replay-approval-continuation.json");
		writeJson(evidencePath, {
			schemaVersion: 1,
			hermes: hermesPin,
			native: {
				events_wait: false,
				permissions_list_open: false,
				permissions_respond: false,
				responds_to_blocked_run: false,
				wrong_actor_denied: true,
				stale_request_denied: true,
				replay_denied: false,
				mutated_decision_denied: true,
			},
			fallback: {
				strategy: "cross_turn_prepare_approve_execute",
				fixtures: REQUIRED_APPROVAL_FALLBACK_FIXTURE_IDS.map((id) => ({
					id,
					status: "pass",
					evidence_path: `artifacts/hermes/approval/${id}.json`,
				})),
			},
		});

		const result = await runCutoverCheckWithBundle(approvalContinuationCutoverBundle(evidencePath));
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode).toBe(1);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("approval replay denial is unproven"),
		});
	});

	it("passes the API-server containment cutover gate from complete observed evidence", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-api-server-"));
		const evidencePath = path.join(tempDir, "execution-api-server-containment.json");
		writeJson(evidencePath, apiServerContainmentEvidence());

		const result = await runCutoverCheckWithBundle(apiServerContainmentCutoverBundle(evidencePath));
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode).toBe(0);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "pass",
		});
	});

	it("fails the API-server containment cutover gate when evidence is missing", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-api-server-"));
		const evidencePath = path.join(tempDir, "missing-api-server-containment.json");

		const result = await runCutoverCheckWithBundle(apiServerContainmentCutoverBundle(evidencePath));
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode).toBe(1);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining(
				"missing feature probe evidence execution.api_server_containment",
			),
		});
	});

	it("fails the API-server containment cutover gate when a required gate is not passing", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-api-server-"));
		const evidencePath = path.join(tempDir, "bad-api-server-containment.json");
		const evidence = apiServerContainmentEvidence({
			gates: apiServerContainmentEvidence().gates.map((gate) =>
				gate.name === "network.relay_only"
					? { ...gate, status: "fail", detail: "direct model provider was reachable" }
					: gate,
			),
		});
		writeJson(evidencePath, evidence);

		const result = await runCutoverCheckWithBundle(apiServerContainmentCutoverBundle(evidencePath));
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode).toBe(1);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("gate network.relay_only is fail"),
		});
	});

	it("fails the API-server containment cutover gate when the report did not run", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-api-server-"));
		const evidencePath = path.join(tempDir, "pending-api-server-containment.json");
		writeJson(
			evidencePath,
			apiServerContainmentEvidence({
				status: "pending",
				ran: false,
			}),
		);

		const result = await runCutoverCheckWithBundle(apiServerContainmentCutoverBundle(evidencePath));
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode).toBe(1);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("status is pending; ran is false"),
		});
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

	it("passes the served-MCP cutover gate from complete observed evidence", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-served-mcp-"));
		const evidencePath = path.join(tempDir, "execution-served-mcp-containment.json");
		writeJson(evidencePath, servedMcpContainmentEvidence());

		const result = await runCutoverCheckWithBundle(servedMcpContainmentCutoverBundle(evidencePath));
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode).toBe(0);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "pass",
		});
	});

	it("fails the served-MCP cutover gate when contained-peer origin is only operator-typed", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-served-mcp-"));
		const evidencePath = path.join(tempDir, "operator-typed-served-mcp.json");
		writeJson(
			evidencePath,
			servedMcpContainmentEvidence({
				origin: {
					kind: "contained-peer",
					containerName: "tc-hermes-contained",
					observedPeerAddress: "172.29.92.11",
					expectedPeerAddress: "172.29.92.11",
					detail: "operator declared contained peer origin",
				},
			}),
		);

		const result = await runCutoverCheckWithBundle(servedMcpContainmentCutoverBundle(evidencePath));
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode).toBe(1);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("server-observed contained peer IP"),
		});
	});

	it("fails the served-MCP cutover gate when evidence is relay-self smoke only", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-served-mcp-"));
		const evidencePath = path.join(tempDir, "relay-self-served-mcp.json");
		writeJson(
			evidencePath,
			servedMcpContainmentEvidence({
				origin: {
					kind: "relay-self-smoke",
					containerName: "telclaude",
					observedPeerAddress: "172.29.92.10",
					observedPeerSource: "server-peer-echo",
					expectedPeerAddress: "172.29.92.11",
					expectedPeerSource: "configured-contained-ip",
					detail: "probe peer origin matched relay namespace",
				},
			}),
		);

		const result = await runCutoverCheckWithBundle(servedMcpContainmentCutoverBundle(evidencePath));
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode).toBe(1);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("smoke"),
		});
	});

	it("fails the served-MCP cutover gate when negative controls are missing", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-served-mcp-"));
		const evidencePath = path.join(tempDir, "missing-served-mcp-negative.json");
		writeJson(
			evidencePath,
			servedMcpContainmentEvidence({
				negativeControls: {},
			}),
		);

		const result = await runCutoverCheckWithBundle(servedMcpContainmentCutoverBundle(evidencePath));
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode).toBe(1);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("negative control offDomainPeerDenied is missing"),
		});
	});

	it.each(
		SERVED_MCP_REQUIRED_PROPERTY_NAMES,
	)("fails the served-MCP cutover gate when property %s is missing", async (property) => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-served-mcp-"));
		const evidencePath = path.join(tempDir, `missing-${property}.json`);
		const evidence = servedMcpContainmentEvidence() as {
			properties: Record<string, boolean | undefined>;
		};
		delete evidence.properties[property];
		writeJson(evidencePath, evidence);

		const result = await runCutoverCheckWithBundle(servedMcpContainmentCutoverBundle(evidencePath));
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode).toBe(1);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining(`served-MCP property ${property} is missing`),
		});
	});

	it.each(
		SERVED_MCP_REQUIRED_PROPERTY_NAMES,
	)("fails the served-MCP cutover gate when property %s is false", async (property) => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-served-mcp-"));
		const evidencePath = path.join(tempDir, `false-${property}.json`);
		const evidence = servedMcpContainmentEvidence() as {
			properties: Record<string, boolean | undefined>;
		};
		evidence.properties[property] = false;
		writeJson(evidencePath, evidence);

		const result = await runCutoverCheckWithBundle(servedMcpContainmentCutoverBundle(evidencePath));
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode).toBe(1);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining(`served-MCP property ${property} is false`),
		});
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
					networkNamespace: "telclaude-hermes-relay",
				},
				wrongConnection: {
					sessionKey: "probe:wrong",
					profileId: "social",
					endpointId: "tc-hermes-wrong",
					networkNamespace: "telclaude-hermes-relay",
				},
				privateAuthority: {
					actorId: "operator:probe",
					memorySource: "telegram:default",
					providerScopes: ["bank"],
					outboundChannels: ["whatsapp"],
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

	it("builds a real sanitized inventory snapshot with deterministic workflows", () => {
		const inventory = buildHermesInventorySnapshot({
			generatedAt: new Date("2026-05-29T00:00:00.000Z"),
			redactionSalt: "test-only-redaction-salt",
			source: {
				configPath: "/tmp/telclaude.json",
				runtimeConfigPath: "/tmp/telclaude.runtime.json",
				privateConfigPresent: true,
				dataDir: "/tmp/telclaude-data",
			},
			config: {
				security: {
					profile: "strict",
					permissions: { defaultTier: "READ_ONLY", users: {} },
					network: {
						privateEndpoints: [{ label: "provider", host: "provider.local", ports: [3000] }],
					},
				},
				telegram: {
					botToken: "12345:RAW_TELEGRAM_TOKEN",
					allowedChats: ["RAW_CHAT_ID_SHOULD_NOT_LEAK"],
					webhook: { secretToken: "RAW_WEBHOOK_SECRET" },
					heartbeatSeconds: 60,
					heartbeat: { enabled: true },
				},
				profiles: [
					{
						id: "family",
						label: "Family",
						allowedSkills: ["memory"],
						soulPath: "docs/soul.md",
					},
				],
				providers: [
					{
						id: "clalit",
						baseUrl: "http://clalit.internal:3000/api?token=RAW_PROVIDER_QUERY_SECRET",
						services: ["appointments"],
						description: "Health provider",
					},
					{
						id: "broken",
						baseUrl: "://RAW_MALFORMED_BASE_URL_SECRET",
						services: ["debug"],
					},
				],
				socialServices: [
					{
						id: "x",
						type: "xtwitter",
						enabled: true,
						apiKey: "RAW_SOCIAL_API_KEY",
						handle: "operator",
						displayName: "Operator",
						agentUrl: "http://agent.internal/private",
						heartbeatEnabled: true,
						heartbeatIntervalHours: 4,
						enableSkills: true,
						allowedSkills: ["social-posting"],
						agentSkillsAllowed: ["voice"],
						notifyOnHeartbeat: "activity",
					},
				],
				cron: { enabled: true, pollIntervalSeconds: 15, timeoutSeconds: 900 },
				dashboard: { enabled: true, port: 8787 },
				webhooks: { enabled: true, port: 8788 },
			} as unknown as TelclaudeConfig,
			sessions: [
				{
					key: "RAW_SESSION_KEY_SHOULD_NOT_LEAK",
					kind: "direct",
					sessionId: "RAW_SDK_SESSION_ID_SHOULD_NOT_LEAK",
					updatedAt: Date.parse("2026-05-29T00:00:00.000Z"),
					ageMs: 0,
					systemSent: true,
				},
			],
			cron: {
				enabled: true,
				pollIntervalSeconds: 15,
				timeoutSeconds: 900,
				summary: { totalJobs: 1, enabledJobs: 1, runningJobs: 0, nextRunAtMs: null },
				coverage: { allSocial: false, socialServiceIds: ["x"], hasPrivateHeartbeat: false },
				jobs: [
					{
						id: "daily-brief",
						name: "Daily brief",
						enabled: true,
						running: false,
						ownerId: "RAW_OWNER_ID_SHOULD_NOT_LEAK",
						deliveryTarget: { kind: "home" },
						schedule: { kind: "cron", expr: "0 8 * * *" },
						action: {
							kind: "agent-prompt",
							prompt: "RAW_CRON_PROMPT_SHOULD_NOT_LEAK",
							allowedSkills: ["daily-brief"],
							preprocess: { command: "RAW_PREPROCESS_COMMAND_SHOULD_NOT_LEAK" },
						},
						nextRunAtMs: null,
						lastRunAtMs: null,
						lastStatus: null,
						lastError: null,
						createdAtMs: 0,
						updatedAtMs: 0,
					},
				],
			},
			queues: {
				...emptyQueues,
				approvals: { pending: 1, expired: 0 },
				backgroundJobs: { active: 1, byStatus: { queued: 1 } },
				social: { activeItems: 1 },
			},
			socialActivity: [{ serviceId: "x", type: "drafted", count: 2 }],
		});

		expect(inventory.status).toBe("complete");
		expect(inventory.summary.workflows).toBeGreaterThan(0);
		expect(inventory.workflows.map((workflow) => workflow.workflow_id)).toEqual(
			[...inventory.workflows.map((workflow) => workflow.workflow_id)].sort(),
		);
		expect(inventory.config.telegram.botTokenPresent).toBe(true);
		expect(inventory.actors.find((actor) => actor.kind === "telegram-chat")?.id).toMatch(
			/^telegram-chat:/,
		);
		expect(
			inventory.workflows.find((workflow) =>
				workflow.source_refs.includes("config.telegram.allowedChats"),
			)?.owner,
		).toMatch(/^telegram-chat:/);
		expect(inventory.sessions.rows[0].keyRef).toMatch(/^session-key:/);
		expect(inventory.sessions.rows[0].sessionRef).toMatch(/^session:/);
		expect(inventory.cron.jobs[0].ownerRef).toMatch(/^owner:/);
		expect(inventory.cron.jobs[0].action).toMatchObject({
			kind: "agent-prompt",
			promptPresent: true,
			allowedSkillCount: 1,
			preprocessPresent: true,
		});
		expect(
			inventory.providers.find((provider) => provider.id === "broken")?.endpoint,
		).toMatchObject({
			scheme: null,
			host: null,
			parseError: "unparseable baseUrl",
		});

		const serialized = JSON.stringify(inventory);
		for (const secret of [
			"RAW_TELEGRAM_TOKEN",
			"RAW_CHAT_ID_SHOULD_NOT_LEAK",
			"RAW_SESSION_KEY_SHOULD_NOT_LEAK",
			"RAW_OWNER_ID_SHOULD_NOT_LEAK",
			"RAW_WEBHOOK_SECRET",
			"RAW_PROVIDER_QUERY_SECRET",
			"RAW_MALFORMED_BASE_URL_SECRET",
			"RAW_SOCIAL_API_KEY",
			"RAW_SDK_SESSION_ID_SHOULD_NOT_LEAK",
			"RAW_CRON_PROMPT_SHOULD_NOT_LEAK",
			"RAW_PREPROCESS_COMMAND_SHOULD_NOT_LEAK",
			"/api?token=",
			"/private",
		]) {
			expect(serialized).not.toContain(secret);
		}
	});
});
