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
	buildCutoverScopeManifestFromInventory,
	buildHermesDoctorReport,
	buildHermesGenerateDryRun,
	type CompatibilityLockfile,
	type CutoverInputBundle,
	computeHermesArtifactDigest,
	evaluateCutoverCheck,
	type FeatureProbeMatrix,
	HERMES_ROLLBACK_CONTROL_SURFACE,
	HERMES_ROLLBACK_OBSERVATION_SURFACE,
	NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION,
	parseHermesPin,
	REQUIRED_CUTOVER_NETWORK_PROBE_IDS,
	validateCompatibilityLockfile,
	validateFeatureProbeMatrix,
} from "../../src/hermes/foundation.js";
import {
	buildHermesInventorySnapshot,
	type HermesPendingQueueSummary,
	type HermesQueueSnapshot,
} from "../../src/hermes/inventory.js";
import { startTelclaudeLiveMcpAdminServer } from "../../src/hermes/mcp/live-admin.js";
import type { TelclaudeLiveMcpProbeTokenBundle } from "../../src/hermes/mcp/live-probe-tokens.js";
import {
	SERVED_MCP_CONTAINMENT_SCHEMA_VERSION,
	SERVED_MCP_REQUIRED_PROPERTY_NAMES,
} from "../../src/hermes/served-mcp-containment.js";
import { buildInternalResponseProof, generateKeyPair } from "../../src/internal-auth.js";

const hermesPin = { version: "0.15.1" };
const requiredNetworkProbeIds = [...REQUIRED_CUTOVER_NETWORK_PROBE_IDS];

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
	const fixtures = ["fixture.private.telegram.basic", "fixture.private.telegram.basic.deny"].map(
		(id) => {
			const evidencePath = path.join(tempDir, `${id}.json`);
			writeJson(evidencePath, {
				schemaVersion: "telclaude.hermes.fixture-evidence.v1",
				id,
				status: "pass",
				ran: true,
				evidence_path: evidencePath,
				observedAt: "2026-05-30T00:00:00.000Z",
				provenance: {
					runner: "vitest",
					source: "unit-fixture",
				},
			});
			return { id, status: "pass" as const, evidence_path: evidencePath };
		},
	);
	return { schemaVersion: 1 as const, results: fixtures };
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
			return passingHttpDenialAttempt("model-provider", "https://api.anthropic.com/v1/models");
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

function safeCutoverBundle(overrides: Partial<CutoverInputBundle> = {}): CutoverInputBundle {
	const noForkProof = writeNoForkProof();
	return {
		schemaVersion: 1,
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
		lockfile: { ...compatLockfile, noForkProofEvidencePath: noForkProof.evidence_path },
		featureProbeMatrix,
		fixtureResults: writeFixtureResults(),
		noForkProof,
		networkProbes: writePassingNetworkProbeBundle(),
		queueSnapshot: { unownedActiveCount: 0 },
		rollbackRehearsal: writeRollbackRehearsal(),
		...overrides,
	};
}

function cliHeadlessProbe(evidencePath: string, status: "pass" | "fail" | "skip" = "skip") {
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
	matrixStatus: "pass" | "fail" | "skip" = "skip",
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
	status: "pass" | "fail" | "skip" = "skip",
) {
	return {
		surface_id: "execution.approval_continuation",
		hermes_pin: hermesPin,
		documented_seam: "Hermes MCP approval fallback through Telclaude MCP bridge",
		probe_command: "pnpm dev hermes probe execution.approval_continuation --allow-run",
		expected_result:
			"Prepare/approve/execute fallback traverses registry, bridge, ledger, verifier, and JTI",
		negative_probe: "Wrong actor, stale request, replay, and mutated binding are denied",
		evidence_path: evidencePath,
		lockfile_key: "featureProbes.execution.approvalContinuation",
		security_scope: "approval-continuation" as const,
		approval_equivalent: true,
		failure_outcome: "disable" as const,
		status,
	};
}

function approvalContinuationCutoverBundle(
	evidencePath: string,
	matrixStatus: "pass" | "fail" | "skip" = "skip",
) {
	const probe = approvalContinuationProbe(evidencePath, matrixStatus);
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
					required_surface_ids: ["execution.approval_continuation"],
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
					surface_id: "execution.approval_continuation",
					status: "pass",
					evidence_path: evidencePath,
				},
			],
			adapterApiSignatures: {
				"execution.approval_continuation": `sha256:${"d".repeat(64)}`,
			},
			noForkProofEvidencePath: base.noForkProof.evidence_path,
		},
	});
}

function servedMcpContainmentProbe(
	evidencePath: string,
	status: "pass" | "fail" | "skip" = "skip",
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
	status: "pass" | "fail" | "skip" = "skip",
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
	matrixStatus: "pass" | "fail" | "skip" = "skip",
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
	matrixStatus: "pass" | "fail" | "skip" = "skip",
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

function writeCutoverBundleArtifacts(tempDir: string, bundle: CutoverInputBundle) {
	const paths = {
		inventory: path.join(tempDir, "inventory.json"),
		scope: path.join(tempDir, "scope.json"),
		decisions: path.join(tempDir, "decisions.json"),
		featureProbes: path.join(tempDir, "feature-probes.json"),
		lockfile: path.join(tempDir, "lockfile.json"),
		fixtures: path.join(tempDir, "fixtures.json"),
		networkProbes: path.join(tempDir, "network-probes.json"),
		nofork: path.join(tempDir, "nofork.json"),
		rollback: path.join(tempDir, "rollback.json"),
	};
	writeJson(paths.inventory, bundle.inventory);
	writeJson(paths.scope, bundle.scopeManifest);
	writeJson(paths.decisions, bundle.decisionLog);
	writeJson(paths.featureProbes, bundle.featureProbeMatrix);
	writeJson(paths.lockfile, bundle.lockfile);
	writeJson(paths.fixtures, bundle.fixtureResults);
	writeJson(paths.networkProbes, bundle.networkProbes);
	writeJson(paths.nofork, bundle.noForkProof);
	writeJson(paths.rollback, bundle.rollbackRehearsal);
	return paths;
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
		"--feature-probes",
		paths.featureProbes,
		"--lockfile",
		paths.lockfile,
		"--fixtures",
		paths.fixtures,
		"--network-probes",
		paths.networkProbes,
		"--nofork",
		paths.nofork,
		"--rollback",
		paths.rollback,
	]);
}

function cliHeadlessEvidence(overrides: Record<string, unknown> = {}) {
	return {
		schemaVersion: "telclaude.hermes.probe-result.v1",
		probeId: "execution.cli_headless",
		status: "pass",
		ran: true,
		exitCode: 0,
		summary: "Hermes CLI oneshot probe completed successfully",
		invocation: {
			command: "/usr/local/bin/hermes",
			args: ["-z", "telclaude probe ok"],
			cwd: "/repo",
			envKeys: [
				"ANTHROPIC_API_KEY",
				"ANTHROPIC_BASE_URL",
				"HERMES_HOME",
				"HERMES_INFERENCE_MODEL",
				"NO_COLOR",
			],
		},
		modelProvider: {
			baseUrl: "http://telclaude:8790/v1/anthropic-proxy",
			baseUrlHost: "telclaude",
			model: "claude-sonnet-4-6",
			modelSource: "env:HERMES_INFERENCE_MODEL",
			authEnvKey: "ANTHROPIC_API_KEY",
			authScope: "relay-anthropic-proxy",
			tokenScoping: "static-shared",
		},
		findings: [],
		...overrides,
	};
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
		expect(JSON.stringify(manifest)).not.toContain("sk-");
		expect(manifest.secretManifest.map((secret) => secret.owner)).toEqual([
			"telclaude-vault",
			"telclaude-vault",
			"telclaude-edge",
		]);
	});

	it("assembles cutover input from separate canonical artifacts", () => {
		const source = safeCutoverBundle();
		const assembled = buildCutoverInputBundleFromArtifacts({
			inventory: {
				...source.inventory,
				status: "complete",
				summary: {
					pendingQueues: pendingQueues(),
				},
			},
			scopeManifest: source.scopeManifest,
			decisionLog: source.decisionLog,
			lockfile: source.lockfile,
			featureProbeMatrix: source.featureProbeMatrix,
			fixtureResults: source.fixtureResults,
			noForkProof: source.noForkProof,
			networkProbes: source.networkProbes,
			rollbackRehearsal: source.rollbackRehearsal,
		});

		expect(evaluateCutoverCheck(assembled).exitCode).toBe(0);
		expect(assembled.queueSnapshot).toEqual({ unownedActiveCount: 0 });
	});

	it("fails closed when canonical artifact assembly lacks complete queue evidence", () => {
		const source = safeCutoverBundle();
		expect(() =>
			buildCutoverInputBundleFromArtifacts({
				inventory: source.inventory,
				scopeManifest: source.scopeManifest,
				decisionLog: source.decisionLog,
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
		const assembled = buildCutoverInputBundleFromArtifacts({
			inventory: {
				...source.inventory,
				status: "complete",
				summary: {
					pendingQueues: pendingQueues({
						approvals: 1,
						backgroundJobs: 2,
					}),
				},
			},
			scopeManifest: source.scopeManifest,
			decisionLog: source.decisionLog,
			lockfile: source.lockfile,
			featureProbeMatrix: source.featureProbeMatrix,
			fixtureResults: source.fixtureResults,
			noForkProof: source.noForkProof,
			networkProbes: source.networkProbes,
			rollbackRehearsal: source.rollbackRehearsal,
		});

		const report = evaluateCutoverCheck(assembled);
		expect(assembled.queueSnapshot).toEqual({ unownedActiveCount: 3 });
		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "queues.owned")?.status).toBe("fail");
	});

	it("blocks cutover on active pairing queues but not enabled webhooks", () => {
		const source = safeCutoverBundle();
		const withPairingQueues = buildCutoverInputBundleFromArtifacts({
			inventory: {
				...source.inventory,
				status: "complete",
				summary: {
					pendingQueues: pendingQueues({
						pairingPendingRequests: 1,
						pairingActiveLockouts: 2,
					}),
				},
			},
			scopeManifest: source.scopeManifest,
			decisionLog: source.decisionLog,
			lockfile: source.lockfile,
			featureProbeMatrix: source.featureProbeMatrix,
			fixtureResults: source.fixtureResults,
			noForkProof: source.noForkProof,
			networkProbes: source.networkProbes,
			rollbackRehearsal: source.rollbackRehearsal,
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
		const webhookOnlyBundle = buildCutoverInputBundleFromArtifacts({
			inventory: {
				...inventoryWithEnabledWebhook,
				workflows: [...source.inventory.workflows, ...inventoryWithEnabledWebhook.workflows],
			},
			scopeManifest: {
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
			},
			decisionLog: source.decisionLog,
			lockfile: source.lockfile,
			featureProbeMatrix: source.featureProbeMatrix,
			fixtureResults: source.fixtureResults,
			noForkProof: source.noForkProof,
			networkProbes: source.networkProbes,
			rollbackRehearsal: source.rollbackRehearsal,
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

		const failed = evaluateCutoverCheck({ ...base, rollbackRehearsal: tampered });

		expect(failed.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "rollback.rehearsed")?.detail).toContain(
			"rollback before relay transcript signature is invalid",
		);
	});

	it("accepts archived rollback transcript proofs outside the live RPC skew window", () => {
		const base = safeCutoverBundle();
		vi.useFakeTimers();
		try {
			vi.setSystemTime(new Date("2000-01-01T00:00:00.000Z"));
			const rehearsal = writeRollbackRehearsal();
			vi.useRealTimers();

			const report = evaluateCutoverCheck({ ...base, rollbackRehearsal: rehearsal });

			expect(report.status).toBe("safe");
			expect(report.gates.find((gate) => gate.name === "rollback.rehearsed")).toMatchObject({
				status: "pass",
			});
		} finally {
			vi.useRealTimers();
		}
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
		const failed = evaluateCutoverCheck(
			safeCutoverBundle({
				featureProbeMatrix: {
					schemaVersion: 1,
					probes: [{ ...probe, status: undefined }],
				},
			}),
		);

		expect(failed.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "featureProbes.pass")?.detail).toContain(
			"status is missing",
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

		expect(result.exitCode).toBe(0);
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

		const result = await runCutoverCheckWithBundle({
			...base,
			featureProbeMatrix: mixedMatrix,
			lockfile: {
				...base.lockfile,
				featureProbeMatrixDigest: computeHermesArtifactDigest(mixedMatrix),
				featureProbes: [
					...base.lockfile.featureProbes,
					{
						surface_id: skippedOtherProbe.surface_id,
						status: "pass",
						evidence_path: skippedOtherProbe.evidence_path,
					},
				],
			},
		});
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
			detail: "invalid feature probe evidence execution.cli_headless",
		},
		{
			name: "missing relay token scoping metadata",
			evidence: cliHeadlessEvidence({
				modelProvider: {
					baseUrl: "http://telclaude:8790/v1/anthropic-proxy",
					baseUrlHost: "telclaude",
					model: "claude-sonnet-4-6",
					modelSource: "env:HERMES_INFERENCE_MODEL",
					authEnvKey: "ANTHROPIC_API_KEY",
					authScope: "relay-anthropic-proxy",
				},
			}),
			detail: "invalid feature probe evidence execution.cli_headless",
		},
		{
			name: "direct model provider base url",
			evidence: cliHeadlessEvidence({
				modelProvider: {
					baseUrl: "https://api.anthropic.com/v1/anthropic-proxy",
					baseUrlHost: "api.anthropic.com",
					model: "claude-sonnet-4-6",
					modelSource: "env:HERMES_INFERENCE_MODEL",
					authEnvKey: "ANTHROPIC_API_KEY",
					authScope: "relay-anthropic-proxy",
					tokenScoping: "static-shared",
				},
			}),
			detail: "modelProvider.baseUrl is not a relay Anthropic proxy URL",
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
			detail: "ANTHROPIC_BASE_URL envKey is missing",
		},
		{
			name: "missing inherited Hermes model env key",
			evidence: cliHeadlessEvidence({
				invocation: {
					command: "/usr/local/bin/hermes",
					args: ["-z", "telclaude probe ok"],
					cwd: "/repo",
					envKeys: ["ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "HERMES_HOME", "NO_COLOR"],
				},
			}),
			detail: "HERMES_INFERENCE_MODEL envKey is missing",
		},
		{
			name: "missing model metadata value",
			evidence: cliHeadlessEvidence({
				modelProvider: {
					baseUrl: "http://telclaude:8790/v1/anthropic-proxy",
					baseUrlHost: "telclaude",
					model: "",
					modelSource: "env:HERMES_INFERENCE_MODEL",
					authEnvKey: "ANTHROPIC_API_KEY",
					authScope: "relay-anthropic-proxy",
					tokenScoping: "static-shared",
				},
			}),
			detail: "modelProvider.model is missing",
		},
		{
			name: "missing model source metadata",
			evidence: cliHeadlessEvidence({
				modelProvider: {
					baseUrl: "http://telclaude:8790/v1/anthropic-proxy",
					baseUrlHost: "telclaude",
					model: "claude-sonnet-4-6",
					modelSource: "missing",
					authEnvKey: "ANTHROPIC_API_KEY",
					authScope: "relay-anthropic-proxy",
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

		expect(result.exitCode).toBe(1);
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
					generatedAt: "2026-05-29T00:00:00Z",
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
		const richBundle: unknown = {
			...bundle,
			inventory: {
				generatedAt: "2026-05-29T00:00:00Z",
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
		};

		expect(evaluateCutoverCheck(richBundle).exitCode).toBe(0);
	});

	it("fails strict cutover when unresolved decisions affect included workflows", () => {
		const failed = evaluateCutoverCheck(
			safeCutoverBundle({
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

	it("returns cutover exit code 2 for malformed checker inputs", () => {
		const report = evaluateCutoverCheck({ schemaVersion: 1 });
		expect(report.status).toBe("input_error");
		expect(report.exitCode).toBe(2);
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
			"--feature-probes",
			paths.featureProbes,
			"--lockfile",
			paths.lockfile,
			"--fixtures",
			paths.fixtures,
			"--network-probes",
			paths.networkProbes,
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

		const result = await runHermesCommand([
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
		]);
		const report = JSON.parse(result.stdout) as { status: string; ran: boolean };

		expect(result.exitCode).toBe(2);
		expect(report).toMatchObject({ status: "pending", ran: false });
		expect(fs.existsSync(markerPath)).toBe(false);
		expect(fs.existsSync(evidencePath)).toBe(false);
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

	it("writes a passing cli-headless artifact only after observed child exit zero", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cli-probe-"));
		const evidencePath = path.join(tempDir, "evidence.json");
		const hermesBin = writeExecutable(
			tempDir,
			`#!/bin/sh
echo "TELCLAUDE_HERMES_CLI_OK"
exit 0
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
		const report = JSON.parse(result.stdout) as { status: string; exitCode: number };
		const artifact = readJson(evidencePath) as { status: string; exitCode: number };

		expect(result.exitCode).toBe(0);
		expect(report).toMatchObject({ status: "pass", exitCode: 0 });
		expect(artifact).toMatchObject({ status: "pass", exitCode: 0 });
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

		const result = await runHermesCommand([
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
		]);
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
			"--timeout-ms",
			"20",
			"--out",
			evidencePath,
		]);
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
