import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http, { type IncomingMessage, type ServerResponse } from "node:http";
import net, { type AddressInfo, type Socket } from "node:net";
import os from "node:os";
import path from "node:path";
import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { shutdownTokenClient } from "../../src/agent/token-client.js";
import { deriveNoForkP0Status, registerHermesCommand } from "../../src/commands/hermes.js";
import type { TelclaudeConfig } from "../../src/config/config.js";
import { REQUIRED_APPROVAL_FALLBACK_FIXTURE_IDS } from "../../src/hermes/approval-continuation.js";
import {
	type BrowserComputerBrokerSurfaceId,
	buildBrowserComputerBrokerFixtureEvidenceBundle,
	buildNetworkEgressBrokerProbeEvidenceFromReport,
	NETWORK_EGRESS_BROKER_RUN_REPORT_SCHEMA_VERSION,
	NETWORK_EGRESS_BROKER_RUN_REPORT_SOURCE,
	runTelclaudeBrowserComputerBrokerProbe,
} from "../../src/hermes/browser-computer-broker-probes.js";
import { signEdgeAdapterAttestation } from "../../src/hermes/edge-adapter-attestation.js";
import {
	EDGE_ADAPTER_CONTRACT_VERSION,
	EDGE_ADAPTER_OPERATION_NAMES,
	EdgeAdapterSchemaVersions,
} from "../../src/hermes/edge-adapter-contract.js";
import {
	buildEdgeAdapterFixtureEvidenceBundle,
	buildEdgeAdapterProbeEvidence,
	type EdgeAdapterFeatureSurfaceId,
} from "../../src/hermes/edge-adapter-probes.js";
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
	buildMissingDefaultCutoverFixtureResults,
	buildMissingDefaultCutoverNetworkProbes,
	buildMissingDefaultRollbackRehearsal,
	type CompatibilityLockfile,
	type CutoverInputBundle,
	computeHermesArtifactDigest,
	DEFAULT_COMPAT_LOCKFILE_PATH,
	DEFAULT_CUTOVER_PROOF_BUNDLE_PATH,
	DEFAULT_CUTOVER_SCOPE_PATH,
	DEFAULT_DECISION_LOG_PATH,
	DEFAULT_FEATURE_PROBE_MATRIX_PATH,
	DEFAULT_FIXTURE_RESULTS_PATH,
	DEFAULT_INVENTORY_PATH,
	DEFAULT_NETWORK_PROBES_PATH,
	DEFAULT_NO_FORK_PROOF_PATH,
	DEFAULT_PROFILE_GENERATION_PROOF_PATH,
	DEFAULT_QUEUE_SNAPSHOT_PATH,
	DEFAULT_ROLLBACK_REHEARSAL_PATH,
	evaluateCutoverCheck,
	evaluateGuardrailMutation,
	type FeatureProbeMatrix,
	GuardrailManifestSchema,
	GuardrailMountPlanSchema,
	HERMES_ROLLBACK_CONTROL_SURFACE,
	HERMES_ROLLBACK_OBSERVATION_SURFACE,
	HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV,
	HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK_ENV,
	HERMES_TRACKED_SEED_PATHS,
	NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION,
	PRIVATE_TELEGRAM_FIXTURE_DIGEST_PATHS,
	PRIVATE_TELEGRAM_FIXTURE_REQUIREMENTS,
	parseHermesPin,
	REQUIRED_CUTOVER_NETWORK_PROBE_IDS,
	validateCompatibilityLockfile,
	validateFeatureProbeMatrix,
	writeHermesJsonArtifact,
	writeHermesProfileGenerationProof,
} from "../../src/hermes/foundation.js";
import {
	buildHermesInventorySnapshot,
	type HermesPendingQueueSummary,
	type HermesQueueSnapshot,
} from "../../src/hermes/inventory.js";
import { startTelclaudeLiveMcpAdminServer } from "../../src/hermes/mcp/live-admin.js";
import type { TelclaudeLiveMcpProbeTokenBundle } from "../../src/hermes/mcp/live-probe-tokens.js";
import { runTelclaudeMcpSideEffectLedgerProbe } from "../../src/hermes/mcp/side-effect-ledger-probe.js";
import { DEFAULT_MODEL_RELAY_PROFILE_DIR } from "../../src/hermes/model-relay.js";
import { signNetworkProbeEvidenceAttestation } from "../../src/hermes/network-probe-attestation.js";
import {
	noForkProofChecksSha256,
	noForkProofEvidenceSha256,
	signNoForkRunnerAttestation,
} from "../../src/hermes/no-fork-attestation.js";
import { noForkSha256Digest } from "../../src/hermes/no-fork-proof.js";
import { signPrivateTelegramFixtureEvidenceAttestation } from "../../src/hermes/private-telegram-fixture-attestation.js";
import { buildProReviewShardPlan, REQUIRED_PRO_REVIEW_FILES } from "../../src/hermes/pro-review.js";
import { signProviderApprovalBindingAttestation } from "../../src/hermes/provider-approval-binding-attestation.js";
import { runTelclaudeProviderApprovalBindingProbe } from "../../src/hermes/provider-approval-binding-probe.js";
import {
	buildProviderDomainFixtureEvidenceBundle,
	DEFAULT_PROVIDER_DOMAIN_EVIDENCE_PATHS,
	type ProviderDomainSurfaceId as HermesProviderDomainSurfaceId,
	runTelclaudeProviderDomainProbe,
} from "../../src/hermes/provider-domain-probes.js";
import {
	buildGoogleProviderFixtureEvidenceBundle,
	DEFAULT_PROVIDER_GOOGLE_EVIDENCE_PATH,
	runTelclaudeGoogleProviderProbe,
} from "../../src/hermes/provider-google-probe.js";
import { runTelclaudeProviderReleasePolicyProbe } from "../../src/hermes/provider-release-policy-probe.js";
import {
	SERVED_MCP_CONTAINMENT_SCHEMA_VERSION,
	SERVED_MCP_REQUIRED_PROPERTY_NAMES,
} from "../../src/hermes/served-mcp-containment.js";
import { SERVED_MCP_MEMORY_REQUIRED_PROPERTY_NAMES } from "../../src/hermes/served-mcp-memory.js";
import { signServedMcpMemoryAttestation } from "../../src/hermes/served-mcp-memory-attestation.js";
import { buildServedMcpProviderToolsProbeEvidence } from "../../src/hermes/served-mcp-provider-tools-probe.js";
import { signSkillsAllowlistAttestation } from "../../src/hermes/skills-allowlist-attestation.js";
import {
	SKILLS_ALLOWLIST_REQUIRED_PROPERTY_NAMES,
	type SkillsAllowlistPropertyName,
} from "../../src/hermes/skills-allowlist-probe.js";
import {
	buildHermesWorkflowFixtureEvidenceBundle,
	runHermesWorkflowProbe,
} from "../../src/hermes/workflow-probes.js";
import { buildInternalResponseProof, generateKeyPair } from "../../src/internal-auth.js";
import { verifyOpenAiCodexPeerBoundProxyToken } from "../../src/relay/openai-codex-proxy.js";
import {
	type OpenAiCodexRelayProof,
	type OpenAiCodexRelayProofSignedFields,
	openAiCodexRelayProofTokenSha256,
	signOpenAiCodexRelayProof,
} from "../../src/relay/openai-codex-relay-proof.js";
import { redactSecrets } from "../../src/security/output-filter.js";

const hermesPin = { version: "0.15.1" };
const CLI_HEADLESS_TEST_RELAY_IP = "10.88.93.10";
const CLI_HEADLESS_TEST_CONTAINED_IP = "10.88.93.11";
const CLI_HEADLESS_WRONG_CONTAINED_IP = "10.88.93.12";
const ORIGINAL_HERMES_RUNTIME_IP_ENV = {
	TELCLAUDE_HERMES_RELAY_IP: process.env.TELCLAUDE_HERMES_RELAY_IP,
	TELCLAUDE_HERMES_CONTAINED_IP: process.env.TELCLAUDE_HERMES_CONTAINED_IP,
};
const requiredNetworkProbeIds = [...REQUIRED_CUTOVER_NETWORK_PROBE_IDS];
const cliHeadlessRelaySigningKeys = generateKeyPair();
type CutoverBundleWithoutProof = Omit<CutoverInputBundle, "cutoverProofBundle">;

const HERMES_COMMAND_TEST_ENV_KEYS = [
	"OPERATOR_RPC_AGENT_PRIVATE_KEY",
	"OPERATOR_RPC_AGENT_PUBLIC_KEY",
	"OPERATOR_RPC_RELAY_PRIVATE_KEY",
	"OPERATOR_RPC_RELAY_PUBLIC_KEY",
	"TELCLAUDE_CAPABILITIES_URL",
	HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV,
	HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK_ENV,
] as const;

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

function queueDetailsFromPending(pending: HermesPendingQueueSummary = pendingQueues()) {
	return {
		approvals: { pending: pending.approvals, expired: 0 },
		planApprovals: { pending: pending.planApprovals, expired: 0 },
		cards: { active: pending.cards, expired: 0, byStatus: {} },
		backgroundJobs: { active: pending.backgroundJobs, byStatus: {} },
		pairing: {
			pendingRequests: pending.pairingPendingRequests,
			activePairs: 0,
			activeLockouts: pending.pairingActiveLockouts,
		},
		allowlist: { active: 0, total: 0 },
		curator: { open: pending.curatorItems, byStatus: {} },
		social: { activeItems: pending.socialItems },
		webhooks: { enabled: 0, total: 0 },
		memory: { entries: 0, episodes: 0 },
	};
}

function queueSnapshotFromPending(
	pending: HermesPendingQueueSummary = pendingQueues(),
	generatedAt = "2026-05-29T00:00:00Z",
) {
	const unownedActiveCount = Object.values(pending).reduce<number>(
		(total, value) => total + value,
		0,
	);
	return {
		schemaVersion: "telclaude.hermes.queue-ownership-snapshot.v1",
		status: unownedActiveCount === 0 ? "pass" : "fail",
		generatedAt,
		unownedActiveCount,
		pendingQueues: pending,
		queues: queueDetailsFromPending(pending),
		source: {
			inventoryGeneratedAt: generatedAt,
			inventoryStatus: "complete",
		},
	};
}

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

async function runHermesCommandWithEnv(
	args: string[],
	env: Record<string, string>,
	options: HermesCommandTestOptions = {},
): Promise<{ exitCode: unknown; stdout: string }> {
	const original = Object.fromEntries(
		Object.keys(env).map((key) => [key, process.env[key] as string | undefined]),
	);
	for (const [key, value] of Object.entries(env)) {
		process.env[key] = value;
	}
	try {
		return await runHermesCommand(args, options);
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
	return JSON.parse(fs.readFileSync(resolveTestPath(filePath), "utf8")) as unknown;
}

function writeJson(filePath: string, value: unknown): void {
	const resolved = resolveTestPath(filePath);
	fs.mkdirSync(path.dirname(resolved), { recursive: true });
	fs.writeFileSync(resolved, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function writeProviderFixtureProbeInputs(cwd: string): Promise<void> {
	const observedAt = "2026-01-02T03:04:05.000Z";
	for (const surfaceId of Object.keys(
		DEFAULT_PROVIDER_DOMAIN_EVIDENCE_PATHS,
	) as HermesProviderDomainSurfaceId[]) {
		writeJson(
			path.join(cwd, DEFAULT_PROVIDER_DOMAIN_EVIDENCE_PATHS[surfaceId]),
			await runTelclaudeProviderDomainProbe({ surfaceId, allowRun: true, observedAt }),
		);
	}
	writeJson(
		path.join(cwd, DEFAULT_PROVIDER_GOOGLE_EVIDENCE_PATH),
		await runTelclaudeGoogleProviderProbe({ allowRun: true, observedAt }),
	);
}

function initPinnedHermesCheckout(checkoutPath: string): void {
	fs.mkdirSync(checkoutPath, { recursive: true });
	execFileSync("git", ["init", "-q"], { cwd: checkoutPath });
	execFileSync("git", ["config", "user.email", "hermes-wrapper-test@example.invalid"], {
		cwd: checkoutPath,
	});
	execFileSync("git", ["config", "user.name", "Hermes Wrapper Test"], { cwd: checkoutPath });
	fs.writeFileSync(path.join(checkoutPath, "README.md"), "Hermes upstream fixture\n", "utf8");
	execFileSync("git", ["add", "README.md"], { cwd: checkoutPath });
	execFileSync("git", ["commit", "-q", "-m", "fixture"], { cwd: checkoutPath });
	execFileSync("git", ["tag", "v2026.5.29"], { cwd: checkoutPath });
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
	const relayKeys = ensureOperatorRelayKeys();
	const proof = {
		schemaVersion: 1,
		hermesCheckoutClean: true,
		evidence_path: evidencePath,
		checkoutPath: path.join(os.tmpdir(), "hermes-agent-v2026.5.29"),
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
			{
				name: "runner.attestation",
				status: "pass",
				detail: "no-fork wrapper run attestation is signed",
			},
			{
				name: "runner.p0",
				status: "pass",
				detail: "P0 fixture/cutover command passed",
			},
			{
				name: "runner.noRuntimeSourceReplacement",
				status: "pass",
				detail: "runtime source replacement denial was observed",
			},
			{
				name: "runner.noMonkeypatch",
				status: "pass",
				detail: "monkeypatch denial was observed",
			},
			{
				name: "runner.postStatusClean",
				status: "pass",
				detail: "post-run git status porcelain is clean",
			},
			{
				name: "runner.postDiffClean",
				status: "pass",
				detail: "post-run git diff --quiet is clean",
			},
			{
				name: "runner.postIndexClean",
				status: "pass",
				detail: "post-run git diff --cached --quiet is clean",
			},
		],
		...overrides,
	};
	if (!Object.hasOwn(overrides, "runnerAttestation")) {
		Object.assign(proof, {
			runnerAttestation: signNoForkRunnerAttestation({
				schemaVersion: "telclaude.hermes.no-fork-runner-attestation.v1",
				source: "telclaude-no-fork-proof-runner",
				runner: "telclaude-hermes-no-fork-runner",
				startedAt: "2026-05-31T09:00:00.000Z",
				endedAt: "2026-05-31T09:01:00.000Z",
				checkoutPath: String(proof.checkoutPath),
				expectedRef: String(proof.expectedRef),
				expectedVersion: String(proof.expectedVersion),
				head: String(proof.head),
				expectedRefCommit: String(proof.expectedRefCommit),
				wrapperPackageSha256: noForkSha256Digest("wrapper-package"),
				profileGenerationSha256: noForkSha256Digest("profile-generation"),
				fixtureResultsSha256: noForkSha256Digest("fixture-results"),
				transcriptSha256: noForkSha256Digest("command-transcript"),
				checksSha256: noForkProofChecksSha256(proof.checks ?? []),
				evidenceSha256: noForkProofEvidenceSha256(proof),
				p0Command: ["pnpm", "dev", "hermes", "prove", "--upstream-clean", "--p0"],
				p0ExitCode: 0,
				p0Status: "pass",
				runtimeSourceReplacementDenied: true,
				monkeypatchDenied: true,
				postRunStatusPorcelain: String(proof.statusPorcelain),
				postRunDiffExitCode: Number(proof.diffExitCode),
				postRunCachedDiffExitCode: Number(proof.cachedDiffExitCode),
			}),
		});
	}
	process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
	process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;
	writeJson(evidencePath, proof);
	return proof;
}

function writeRollbackRehearsal(overrides: Record<string, unknown> = {}) {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-rollback-"));
	const evidencePath =
		typeof overrides.evidence_path === "string"
			? overrides.evidence_path
			: path.join(tempDir, "rollback-rehearsal.json");
	const relayKeys = ensureOperatorRelayKeys();
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
	ensureOperatorRelayKeys();
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-fixtures-"));
	const reportPath = path.join(tempDir, "private-telegram-vitest.json");
	writeJson(reportPath, privateTelegramVitestReport());
	const reportDigest = `sha256:${crypto
		.createHash("sha256")
		.update(fs.readFileSync(reportPath))
		.digest("hex")}`;
	const observedAt = freshHermesFixtureTimestamp();
	const invocation = privateTelegramFixtureInvocation(reportPath, reportDigest, observedAt);
	const fixtures = PRIVATE_TELEGRAM_FIXTURE_REQUIREMENTS.map((requirement) => {
		const evidencePath = path.join(tempDir, `${requirement.id}.json`);
		const checks = requirement.requiredTests.map((testName) => ({
			name: testName,
			status: "pass",
			detail: "required fixture assertion passed in machine-observed Vitest report",
		}));
		const evidence = {
			schemaVersion: "telclaude.hermes.fixture-evidence.v1",
			id: requirement.id,
			status: "pass",
			ran: true,
			evidence_path: evidencePath,
			observedAt,
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
			checks,
		};
		writeJson(evidencePath, {
			...evidence,
			privateTelegramRunnerAttestation: signPrivateTelegramFixtureEvidenceAttestation({
				fixtureId: requirement.id,
				status: evidence.status,
				observedAt: evidence.observedAt,
				provenanceRunner: evidence.provenance.runner,
				provenanceSource: evidence.provenance.source,
				testReportPath: evidence.testReport.path,
				testReportSha256: reportDigest as `sha256:${string}`,
				invocation,
				requiredTests: requirement.requiredTests,
				requiredAssertions: requirement.requiredAssertions,
				checks,
			}),
		});
		return { id: requirement.id, status: "pass" as const, evidence_path: evidencePath };
	});
	return { schemaVersion: 1 as const, results: fixtures };
}

function privateTelegramFixtureInvocation(
	reportPath: string,
	reportDigest: string,
	startedAt = freshHermesFixtureTimestamp(),
) {
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
		cwd: testCwd ?? process.cwd(),
		exitCode: 0,
		startedAt,
		endedAt: addMs(startedAt, 1000),
		reportPath,
		reportSha256: reportDigest,
		sourceDigests: Object.fromEntries(
			PRIVATE_TELEGRAM_FIXTURE_DIGEST_PATHS.map((sourcePath) => [
				sourcePath,
				`sha256:${crypto
					.createHash("sha256")
					.update(fs.readFileSync(resolveTestPath(sourcePath)))
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

function refreshCutoverProofBundle(bundle: CutoverInputBundle): CutoverInputBundle {
	const withoutProof = { ...bundle } as Partial<CutoverInputBundle>;
	const staleProof = withoutProof.cutoverProofBundle;
	if (!staleProof) throw new Error("missing cutover proof bundle");
	delete withoutProof.cutoverProofBundle;
	const cutover = withoutProof as CutoverBundleWithoutProof;
	return { ...cutover, cutoverProofBundle: makeCutoverProofBundle(cutover) };
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

function simpleFeatureProbe(
	surfaceId: string,
	evidencePath: string,
	lockfileKey = `featureProbes.${surfaceId}`,
): FeatureProbeMatrix["probes"][number] {
	return {
		surface_id: surfaceId,
		hermes_pin: hermesPin,
		documented_seam: `${surfaceId} test seam`,
		probe_command: `pnpm dev hermes probe ${surfaceId} --allow-run`,
		expected_result: `${surfaceId} passes`,
		negative_probe: `${surfaceId} negative controls fail closed`,
		evidence_path: evidencePath,
		lockfile_key: lockfileKey,
		approval_equivalent: false,
		failure_outcome: "disable",
		status: "pass",
	};
}

function writeIdentityMigrationProbeEvidence(evidencePath: string): void {
	ensureOperatorRelayKeys();
	const observedAt = freshHermesFixtureTimestamp();
	const controls = [
		"contract.actor-ref.validates",
		"contract.conversation-ref.validates",
		"identity.private-authorized-allowed",
		"identity.authorization-denied-enforced",
		"identity.unpaired-sender-denied",
		"identity.forged-actor-denied",
		"identity.revocation-enforced",
		"identity.session-id-not-authority",
		"identity.cross-channel-denied",
		"identity.wrong-thread-denied",
	].map((name) => ({
		name,
		status: "pass" as const,
		detail: `${name} passed in deterministic identity migration fixture`,
	}));
	const evidence = {
		schemaVersion: "telclaude.hermes.edge-adapter-probe.v1",
		probeId: "identity.migration",
		status: "pass" as const,
		ran: true,
		observedAt,
		source: "telclaude-edge-runtime-harness",
		summary: "Edge runtime harness passed for identity.migration",
		surface: {
			id: "identity.migration",
			channels: ["whatsapp", "email", "agentmail", "social"],
			trustDomains: ["private", "household", "public", "public-social"],
		},
		contract: {
			version: EDGE_ADAPTER_CONTRACT_VERSION,
			operations: [...EDGE_ADAPTER_OPERATION_NAMES],
			schemaVersions: Object.values(EdgeAdapterSchemaVersions),
		},
		custody: {
			credentialOwner: "telclaude-edge",
			hermesRawCredentialAccess: "denied",
			attachmentRawAccess: "denied",
			outboundExecutionOwner: "telclaude-edge",
		},
		controls,
		runtime: {
			source: "telclaude-edge-runtime-harness",
			operationTrace: [...EDGE_ADAPTER_OPERATION_NAMES],
			checks: controls,
			observations: {
				ingestedAttachments: 1,
				deniedAttempts: 10,
				ledgerEntries: 1,
				receiptRefs: 1,
			},
		},
	};
	writeJson(evidencePath, {
		...evidence,
		runnerAttestation: signEdgeAdapterAttestation(evidence),
	});
}

const PROVIDER_APPROVAL_BINDING_TEST_CHECKS = [
	"provider.approval-binding.prepare-hashes",
	"provider.approval-binding.content-hash",
	"provider.approval-binding.valid-token-executes",
	"provider.approval-binding.proxy-relay",
	"provider.approval-binding.hermes-approval-token-input-denied",
	"provider.approval-binding.invalid-token-denied",
	"provider.approval-binding.params-mutation-denied",
	"provider.approval-binding.wrong-actor-denied",
	"provider.approval-binding.service-action-mismatch-denied",
	"provider.approval-binding.wrong-account-denied",
	"provider.approval-binding.wrong-approval-request-denied",
	"provider.approval-binding.wrong-card-revision-denied",
	"provider.approval-binding.wrong-approver-denied",
	"provider.approval-binding.wysiwys-render-mismatch-denied",
	"provider.approval-binding.expired-ref-denied",
	"provider.approval-binding.revoked-ref-denied",
	"provider.approval-binding.approved-then-revoked-ref-denied",
	"provider.approval-binding.executed-ref-replay-denied",
	"provider.approval-binding.duplicate-jti-denied",
	"provider.approval-binding.google-sidecar-token-roundtrip",
	"provider.approval-binding.hermes-token-sidecar-rejected",
] as const;

function writeProviderApprovalBindingProbeEvidence(evidencePath: string): void {
	ensureOperatorRelayKeys();
	const evidence = {
		schemaVersion: "telclaude.hermes.provider-approval-binding-probe.v1",
		probeId: "providers.approval-binding",
		status: "pass" as const,
		ran: true,
		observedAt: freshHermesFixtureTimestamp(),
		source: "telclaude-provider-approval-binding-harness",
		summary: "Provider approval-binding probe passed",
		checks: PROVIDER_APPROVAL_BINDING_TEST_CHECKS.map((name) => ({
			name,
			status: "pass" as const,
			detail: `${name} passed in deterministic approval-binding fixture`,
		})),
		observations: {
			actionRef: "provider-approval-probe-1",
			paramsHash: `sha256:${"1".repeat(64)}`,
			bodyHash: `sha256:${"2".repeat(64)}`,
			contentHash: `sha256:${"3".repeat(64)}`,
			verifierCallCount: 12,
			providerProxyCallCount: 1,
			googleSidecarParamsHash: `sha256:${"4".repeat(64)}`,
			hermesTokenSidecarRejectCode: "invalid_grant",
		},
	};
	writeJson(evidencePath, {
		...evidence,
		runnerAttestation: signProviderApprovalBindingAttestation(evidence),
	});
}

function writeApprovalContinuationEvidence(evidencePath: string): void {
	const fixtureDir = path.dirname(evidencePath);
	writeJson(evidencePath, {
		schemaVersion: 1,
		hermes: hermesPin,
		native: {
			events_wait: true,
			permissions_list_open: true,
			permissions_respond: true,
			responds_to_blocked_run: true,
			wrong_actor_denied: true,
			stale_request_denied: true,
			replay_denied: true,
			mutated_decision_denied: true,
			evidence_path: evidencePath,
		},
		fallback: {
			strategy: "cross_turn_prepare_approve_execute",
			fixtures: REQUIRED_APPROVAL_FALLBACK_FIXTURE_IDS.map((id) => ({
				id,
				status: "pass",
				evidence_path: path.join(fixtureDir, `${id}.json`),
			})),
		},
	});
}

function writeSafeParityFixtures(
	root: string,
	privateFixtureResults: ReturnType<typeof writeFixtureResults>,
): ReturnType<typeof writeFixtureResults> {
	const identityProbePath = path.join(root, "artifacts/hermes/probes/identity-migration.json");
	writeIdentityMigrationProbeEvidence(identityProbePath);
	const observedAt = freshHermesFixtureTimestamp();
	const edgeFixtures = buildEdgeAdapterFixtureEvidenceBundle({
		evidenceDir: path.join(root, "artifacts/hermes/fixtures"),
		observedAt,
		probePaths: { "identity.migration": identityProbePath },
	});
	for (const evidence of edgeFixtures.evidence) {
		writeJson(evidence.evidence_path, evidence);
	}
	const identityFixture = edgeFixtures.results.find(
		(result) => result.id === "fixture.identity.migration.relink",
	);
	if (!identityFixture) throw new Error("identity migration relink fixture was not generated");
	return {
		schemaVersion: 1,
		results: [...privateFixtureResults.results, identityFixture],
	};
}

const DESCOPED_TEST_PARITY_ROWS = [
	"approvals-cards",
	"providers",
	"banking",
	"clalit-health",
	"government-identity",
	"google-provider",
	"memory",
	"skills",
	"social-public",
	"whatsapp",
	"household-whatsapp",
	"email",
	"household-email",
	"agentmail",
	"edge-adapters",
	"model-provider-relay",
	"cron",
	"long-lived-workflows",
	"chief-of-staff",
	"browser-web-computer",
	"web-browser-broker",
] as const;

type TestInventoryWorkflow = {
	readonly workflow_id: string;
	readonly owner: string;
	readonly trust_domain: string;
	readonly active: boolean;
};

function completeTestInventory(
	workflows: readonly TestInventoryWorkflow[],
	generatedAt = "2026-05-29T00:00:00Z",
) {
	const queueSummary = pendingQueues();
	return {
		generatedAt,
		status: "complete" as const,
		summary: {
			pendingQueues: queueSummary,
		},
		queues: queueDetailsFromPending(queueSummary),
		workflows: [...workflows],
	};
}

function moduleTestWorkflow(workflowId: string): TestInventoryWorkflow {
	return {
		workflow_id: workflowId,
		owner: "operator",
		trust_domain: "module-test",
		active: true,
	};
}

function privateChatWorkflow(): TestInventoryWorkflow {
	return {
		workflow_id: "private.telegram.basic",
		owner: "operator",
		trust_domain: "private",
		active: true,
	};
}

function providerWorkflow(workflowId: string, owner: string): TestInventoryWorkflow {
	return {
		workflow_id: workflowId,
		owner,
		trust_domain: "provider",
		active: true,
	};
}

function householdWorkflow(workflowId: string): TestInventoryWorkflow {
	return {
		workflow_id: workflowId,
		owner: "household:family",
		trust_domain: "household",
		active: true,
	};
}

function profileDecisionLogFor(workflowIds: readonly string[], impact = "test module cutover") {
	return {
		schemaVersion: 1 as const,
		decisions: [
			{
				id: "D-profile-generation",
				status: "accepted" as const,
				owner: "operator",
				deadline_phase: "Phase 1",
				accepted_answer: "Generated Hermes profiles are produced by the checked profile generator.",
				affected_workflows: [...workflowIds],
				cutover_impact: impact,
			},
		],
	};
}

function mergeFeatureProbeMatrix(
	base: FeatureProbeMatrix,
	probes: readonly FeatureProbeMatrix["probes"][number][],
): FeatureProbeMatrix {
	const bySurfaceId = new Map<string, FeatureProbeMatrix["probes"][number]>();
	for (const probe of base.probes) bySurfaceId.set(probe.surface_id, probe);
	for (const probe of probes) bySurfaceId.set(probe.surface_id, probe);
	return {
		schemaVersion: 1,
		probes: [...bySurfaceId.values()],
	};
}

function featureProbeEvidenceForMatrix(matrix: FeatureProbeMatrix) {
	return {
		schemaVersion: 1 as const,
		results: matrix.probes.map((probe) => ({
			surface_id: probe.surface_id,
			status: "pass" as const,
			evidence_path: probe.evidence_path,
			detail: "test fixture observed feature probe pass",
		})),
	};
}

function cutoverBundleWithAdditionalWorkflow(options: {
	readonly base: CutoverInputBundle;
	readonly inventoryWorkflow: TestInventoryWorkflow;
	readonly scopeWorkflow: CutoverInputBundle["scopeManifest"]["workflows"][number];
	readonly probes: readonly FeatureProbeMatrix["probes"][number][];
	readonly adapterApiSignatures?: Record<string, string>;
	readonly decisionImpact?: string;
}): Partial<CutoverInputBundle> {
	const featureProbeMatrix = mergeFeatureProbeMatrix(
		options.base.featureProbeMatrix,
		options.probes,
	);
	return {
		inventory: completeTestInventory([privateChatWorkflow(), options.inventoryWorkflow]),
		scopeManifest: {
			schemaVersion: 1,
			workflows: [options.base.scopeManifest.workflows[0], options.scopeWorkflow],
		},
		featureProbeMatrix,
		featureProbeEvidence: featureProbeEvidenceForMatrix(featureProbeMatrix),
		noForkProof: options.base.noForkProof,
		decisionLog: profileDecisionLogFor([], options.decisionImpact),
		lockfile: {
			...options.base.lockfile,
			featureProbeMatrixDigest: computeHermesArtifactDigest(featureProbeMatrix),
			featureProbes: featureProbeMatrix.probes.map((probe) => ({
				surface_id: probe.surface_id,
				status: probe.status ?? "fail",
				evidence_path: probe.evidence_path,
			})),
			adapterApiSignatures: {
				...options.base.lockfile.adapterApiSignatures,
				...(options.adapterApiSignatures ?? {}),
			},
			noForkProofEvidencePath: options.base.noForkProof.evidence_path,
		},
	};
}

function freshCutoverTimingOverrides(bundle: CutoverInputBundle) {
	const generatedAt = freshHermesFixtureTimestamp();
	const pendingQueues = bundle.inventory.summary.pendingQueues;
	const rollbackRehearsal = {
		...bundle.rollbackRehearsal,
		observedAt: generatedAt,
	};
	writeJson(rollbackRehearsal.evidence_path, rollbackRehearsal);
	return {
		inventory: {
			...bundle.inventory,
			generatedAt,
		},
		queueSnapshot: queueSnapshotFromPending(pendingQueues, generatedAt),
		rollbackRehearsal,
	};
}

const SKILLS_ALLOWLIST_PRETOOLUSE_TEST_PROPERTIES = new Set<SkillsAllowlistPropertyName>([
	"pretooluse_hook_registered",
	"allowlisted_skill_invocation_allowed",
	"nonallowlisted_skill_invocation_denied",
	"social_missing_allowlist_denied",
	"social_empty_allowlist_denied",
]);

function writeServedMcpMemoryFeatureEvidence(evidencePath: string): void {
	ensureOperatorRelayKeys();
	const properties = Object.fromEntries(
		SERVED_MCP_MEMORY_REQUIRED_PROPERTY_NAMES.map((name) => [name, true]),
	);
	const rpcDenials = new Set(["secret_write_rejected", "instruction_like_write_rejected"]);
	const evidence = {
		schemaVersion: "telclaude.hermes.served-mcp-memory.v1",
		probeId: "served_mcp.memory",
		status: "pass",
		ran: true,
		generatedAt: freshHermesFixtureTimestamp(),
		summary: "memory parity proven from contained peer",
		memorySource: "telegram:default",
		origin: {
			kind: "contained-peer",
			containerName: "tc-hermes-contained",
			observedPeerAddress: "172.30.92.11",
			observedPeerSource: "server-peer-echo",
			expectedPeerAddress: "172.30.92.11",
			expectedPeerSource: "configured-contained-ip",
			detail: "server-echoed contained peer",
		},
		properties,
		checks: SERVED_MCP_MEMORY_REQUIRED_PROPERTY_NAMES.map((name) => ({
			name,
			status: "pass",
			detail: `${name} proven`,
			...(name === "memory_source_resolved_server_side"
				? {
						clientSourceWriteRpcErrorCode: -32001,
						clientSourceWriteRpcErrorMessage:
							"MCP client cannot supply memory authority fields",
						clientSourceSearchRpcErrorCode: -32001,
						clientSourceSearchRpcErrorMessage:
							"MCP client cannot supply memory authority fields",
					}
				: {}),
			...(rpcDenials.has(name)
				? { rpcErrorCode: -32602, rpcErrorMessage: "memory entry rejected" }
				: {}),
			...(name === "cross_source_read_denied"
				? {
						observedResultCount: 0,
						sentinelSeeded: true,
						sentinelSeedObservedPeerAddress: "172.30.92.12",
						sentinelSeedObservedPeerSource: "server-peer-echo",
						sentinelSeedExpectedPeerAddress: "172.30.92.12",
						sentinelSeedExpectedPeerSource: "configured-off-domain-ip",
					}
				: {}),
		})),
	};
	writeJson(evidencePath, {
		...evidence,
		runnerAttestation: signServedMcpMemoryAttestation(evidence),
	});
}

function writeSkillsAllowlistFeatureEvidence(evidencePath: string): void {
	ensureOperatorRelayKeys();
	const properties = Object.fromEntries(
		SKILLS_ALLOWLIST_REQUIRED_PROPERTY_NAMES.map((name) => [name, true]),
	);
	const evidence = {
		schemaVersion: "telclaude.hermes.skills-allowlist.v1",
		probeId: "skills.allowlist",
		status: "pass",
		ran: true,
		generatedAt: freshHermesFixtureTimestamp(),
		summary: "skills allowlist profile proven in contained runtime",
		origin: {
			kind: "contained-runtime",
			containerName: "tc-hermes-contained",
			topologyInternal: true,
			relayContainerPresent: true,
			authoritativeBoundary: "docker_internal_network",
			detail: "docker internal-network topology proof",
		},
		properties,
		checks: SKILLS_ALLOWLIST_REQUIRED_PROPERTY_NAMES.map((name) => ({
			name,
			status: "pass",
			detail: `${name} proven`,
			...(name === "artifact_redacted" ? {} : { observationLayer: "docker_exec" }),
			...(SKILLS_ALLOWLIST_PRETOOLUSE_TEST_PROPERTIES.has(name)
				? { enforcementLayer: "pretooluse" }
				: {}),
		})),
	};
	writeJson(evidencePath, {
		...evidence,
		runnerAttestation: signSkillsAllowlistAttestation(evidence),
	});
}

function cutoverBundleWithMemoryAndSkillsFeatureProbes(): CutoverInputBundle {
	const base = safeCutoverBundle();
	const evidenceRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-memory-skills-"));
	const memoryEvidencePath = path.join(evidenceRoot, "served-mcp-memory.json");
	const skillsEvidencePath = path.join(evidenceRoot, "skills-allowlist.json");
	writeServedMcpMemoryFeatureEvidence(memoryEvidencePath);
	writeSkillsAllowlistFeatureEvidence(skillsEvidencePath);
	const featureProbeMatrix = mergeFeatureProbeMatrix(base.featureProbeMatrix, [
		simpleFeatureProbe("served_mcp.memory", memoryEvidencePath, "featureProbes.servedMcpMemory"),
		simpleFeatureProbe("skills.allowlist", skillsEvidencePath, "featureProbes.skillsAllowlist"),
	]);
	const lockfile = {
		...base.lockfile,
		featureProbeMatrixDigest: computeHermesArtifactDigest(featureProbeMatrix),
		featureProbes: featureProbeMatrix.probes.map((probe) => ({
			surface_id: probe.surface_id,
			status: probe.status,
			evidence_path: probe.evidence_path,
		})),
	};
	const profileGenerationProof = writeHermesProfileGenerationProof({
		pin: lockfile.hermes,
		outDir: path.join(evidenceRoot, "profile"),
		lockfile,
		evidencePath: path.join(evidenceRoot, "profile-generation-proof.json"),
		now: "2026-05-29T00:00:00Z",
	});
	const decisionLog = {
		...base.decisionLog,
		decisions: base.decisionLog.decisions.map((decision) =>
			decision.id === "D-profile-generation"
				? { ...decision, evidence_path: profileGenerationProof.evidence_path }
				: decision,
		),
	};
	return refreshCutoverProofBundle({
		...base,
		lockfile,
		decisionLog,
		featureProbeMatrix,
		featureProbeEvidence: featureProbeEvidenceForMatrix(featureProbeMatrix),
		profileGenerationProof,
	});
}

function safeCutoverBundle(overrides: Partial<CutoverInputBundle> = {}): CutoverInputBundle {
	const noForkProof = writeNoForkProof();
	const parityRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-parity-safe-"));
	const cliHeadlessEvidencePath = path.join(
		parityRoot,
		"artifacts/hermes/probes/execution-cli-headless.json",
	);
	writeJson(cliHeadlessEvidencePath, cliHeadlessEvidence());
	writeHeadlessEntrypointGreenEvidence(parityRoot);
	const headlessEntrypointEvidencePath = path.join(
		parityRoot,
		"artifacts/hermes/probes/execution-headless-entrypoint.json",
	);
	const providerApprovalEvidencePath = path.join(
		parityRoot,
		"artifacts/hermes/probes/providers-approval-binding.json",
	);
	writeProviderApprovalBindingProbeEvidence(providerApprovalEvidencePath);
	const approvalContinuationEvidencePath = path.join(
		parityRoot,
		"artifacts/hermes/probes/execution-approval-continuation.json",
	);
	writeApprovalContinuationEvidence(approvalContinuationEvidencePath);
	const identityProbeEvidencePath = path.join(
		parityRoot,
		"artifacts/hermes/probes/identity-migration.json",
	);
	writeIdentityMigrationProbeEvidence(identityProbeEvidencePath);
	const baseFeatureProbeMatrix: FeatureProbeMatrix = {
		schemaVersion: 1,
		probes: [
			cliHeadlessProbe(cliHeadlessEvidencePath),
			simpleFeatureProbe(
				"execution.headless_entrypoint",
				headlessEntrypointEvidencePath,
				"featureProbes.execution.headlessEntrypoint",
			),
			simpleFeatureProbe(
				"providers.approval-binding",
				providerApprovalEvidencePath,
				"featureProbes.providers.approvalBinding",
			),
			approvalContinuationProbe(approvalContinuationEvidencePath),
			simpleFeatureProbe(
				"identity.migration",
				identityProbeEvidencePath,
				"featureProbes.identity.migration",
			),
		],
	};
	const lockfile = {
		...compatLockfile,
		noForkProofEvidencePath: noForkProof.evidence_path,
		featureProbeMatrixDigest: computeHermesArtifactDigest(baseFeatureProbeMatrix),
		featureProbes: baseFeatureProbeMatrix.probes.map((probe) => ({
			surface_id: probe.surface_id,
			status: probe.status,
			evidence_path: probe.evidence_path,
		})),
	};
	const basePendingQueues = pendingQueues();
	const baseGeneratedAt = "2026-05-29T00:00:00Z";
	const baseFixtureResults = writeSafeParityFixtures(parityRoot, writeFixtureResults());
	const base: CutoverBundleWithoutProof = {
		schemaVersion: 1,
		inventory: {
			...completeTestInventory([privateChatWorkflow()], baseGeneratedAt),
			summary: {
				pendingQueues: basePendingQueues,
			},
			queues: queueDetailsFromPending(basePendingQueues),
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
					fixture_ids: ["fixture.private.telegram.basic", "fixture.identity.migration.relink"],
					negative_fixture_ids: ["fixture.private.telegram.basic.deny"],
					required_surface_ids: [
						"execution.cli_headless",
						"execution.approval_continuation",
						"providers.approval-binding",
						"identity.migration",
					],
					unresolved_decision_ids: [],
				},
			],
		},
		decisionLog: {
			schemaVersion: 1,
			decisions: DESCOPED_TEST_PARITY_ROWS.map((row) => ({
				id: `parity-descope:${row}`,
				status: "accepted" as const,
				owner: "operator",
				deadline_phase: "test",
				accepted_answer: `${row} intentionally descoped in the narrow cutover fixture`,
				affected_workflows: ["private.telegram.basic"],
				cutover_impact: "test fixture only",
			})),
		},
		lockfile,
		featureProbeMatrix: baseFeatureProbeMatrix,
		featureProbeEvidence: {
			schemaVersion: 1,
			results: baseFeatureProbeMatrix.probes.map((probe) => ({
				surface_id: probe.surface_id,
				status: "pass" as const,
				evidence_path: probe.evidence_path,
				detail: "test fixture observed feature probe pass",
			})),
		},
		fixtureResults: baseFixtureResults,
		noForkProof,
		networkProbes: writePassingNetworkProbeBundle(),
		queueSnapshot: queueSnapshotFromPending(basePendingQueues, baseGeneratedAt),
		rollbackRehearsal: writeRollbackRehearsal(),
	};
	const { cutoverProofBundle, ...bundleOverrides } = overrides;
	const merged: CutoverBundleWithoutProof = { ...base, ...bundleOverrides };
	if (typeof merged.rollbackRehearsal.relayPublicKey?.value === "string") {
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = merged.rollbackRehearsal.relayPublicKey.value;
	}
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
	const decisionLogWithParityDescopes = {
		schemaVersion: 1 as const,
		decisions: [
			...(hasDecisionOverride
				? []
				: DESCOPED_TEST_PARITY_ROWS.map((row) => ({
						id: `parity-descope:${row}`,
						status: "accepted" as const,
						owner: "operator",
						deadline_phase: "test",
						accepted_answer: `${row} intentionally descoped in the narrow cutover fixture`,
						affected_workflows: ["private.telegram.basic"],
						cutover_impact: "test fixture only",
					}))),
			...(hasDecisionOverride
				? merged.decisionLog.decisions
				: [
						{
							id: "D-profile-generation",
							status: "accepted" as const,
							owner: "operator",
							deadline_phase: "Phase 1",
							accepted_answer:
								"Generated Hermes profiles are produced by the checked profile generator.",
							evidence_path: profileGenerationProof?.evidence_path,
							affected_workflows: ["private.telegram.basic"],
							cutover_impact: "Profile generation proof is required before private cutover.",
						},
					]),
		],
	};
	const withoutProof: CutoverBundleWithoutProof = {
		...merged,
		profileGenerationProof,
		decisionLog: decisionLogWithParityDescopes,
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
		documented_seam: "Hermes chat -q headless mode",
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
		inventory: completeTestInventory([moduleTestWorkflow("execution.cli_headless.module")]),
		scopeManifest: {
			schemaVersion: 1,
			workflows: [
				{
					...base.scopeManifest.workflows[0],
					workflow_id: "execution.cli_headless.module",
					trust_domain: "module-test",
					required_surface_ids: ["execution.cli_headless"],
				},
			],
		},
		featureProbeMatrix,
		noForkProof: base.noForkProof,
		decisionLog: profileDecisionLogFor(["execution.cli_headless.module"]),
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

type RuntimeRequiredEdgeSurfaceId =
	| "edge.whatsapp"
	| "edge.email"
	| "edge.agentmail"
	| "edge.social"
	| "identity.migration"
	| "household.scopes"
	| "attachment.quarantine"
	| "outbound.policy"
	| "public.social.isolation";

function edgeAdapterProbe(
	surfaceId: RuntimeRequiredEdgeSurfaceId,
	evidencePath: string,
	status: "pass" | "fail" | "skip" = "pass",
) {
	return {
		surface_id: surfaceId,
		hermes_pin: hermesPin,
		documented_seam:
			"Telclaude edge runtime owns identity, household, attachment, and outbound policy enforcement",
		probe_command: `pnpm dev hermes probe ${surfaceId} --allow-run`,
		expected_result:
			"Runtime harness proves edge-owned identity, household scope, attachment ref, outbound binding, and replay enforcement",
		negative_probe:
			"Forged identities, session-id authority, weak household links, raw attachments, direct credentials, approval-token injection, mutation, and replay fail closed",
		evidence_path: evidencePath,
		lockfile_key: `featureProbes.${surfaceId}`,
		security_scope: "edge-adapter" as const,
		approval_equivalent: true,
		failure_outcome: "disable" as const,
		status,
	};
}

function edgeAdapterCutoverBundleFromEvidence(
	evidence: readonly Array<{ surfaceId: RuntimeRequiredEdgeSurfaceId; evidencePath: string }>,
	matrixStatus: "pass" | "fail" | "skip" = "pass",
) {
	const probes = evidence.map(({ surfaceId, evidencePath }) =>
		edgeAdapterProbe(surfaceId, evidencePath, matrixStatus),
	);
	const base = safeCutoverBundle();
	return safeCutoverBundle(
		cutoverBundleWithAdditionalWorkflow({
			base,
			inventoryWorkflow: moduleTestWorkflow("edge.runtime.module"),
			scopeWorkflow: {
				...base.scopeManifest.workflows[0],
				workflow_id: "edge.runtime.module",
				trust_domain: "module-test",
				required_surface_ids: evidence.map(({ surfaceId }) => surfaceId),
			},
			probes,
			adapterApiSignatures: Object.fromEntries(
				evidence.map(({ surfaceId }) => [surfaceId, `sha256:${"e".repeat(64)}`]),
			),
			decisionImpact: "Edge runtime module cutover proof extends the private P0 bundle.",
		}),
	);
}

function edgeAdapterCutoverBundle(
	surfaceId: RuntimeRequiredEdgeSurfaceId,
	evidencePath: string,
	matrixStatus: "pass" | "fail" | "skip" = "pass",
) {
	return edgeAdapterCutoverBundleFromEvidence([{ surfaceId, evidencePath }], matrixStatus);
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
	const base = safeCutoverBundle();
	return safeCutoverBundle(
		cutoverBundleWithAdditionalWorkflow({
			base,
			inventoryWorkflow: moduleTestWorkflow("approval.continuation.module"),
			scopeWorkflow: {
				...base.scopeManifest.workflows[0],
				workflow_id: "approval.continuation.module",
				trust_domain: "module-test",
				required_surface_ids: [surfaceId],
			},
			probes: [probe],
			adapterApiSignatures: {
				[surfaceId]: `sha256:${"d".repeat(64)}`,
			},
			decisionImpact: "Approval-continuation module cutover proof extends the private P0 bundle.",
		}),
	);
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
	const base = safeCutoverBundle();
	return safeCutoverBundle(
		cutoverBundleWithAdditionalWorkflow({
			base,
			inventoryWorkflow: moduleTestWorkflow("sideeffect.ledger.module"),
			scopeWorkflow: {
				...base.scopeManifest.workflows[0],
				workflow_id: "sideeffect.ledger.module",
				trust_domain: "module-test",
				required_surface_ids: ["sideeffect.ledger"],
			},
			probes: [probe],
			adapterApiSignatures: {
				"sideeffect.ledger": `sha256:${"9".repeat(64)}`,
			},
			decisionImpact: "Side-effect ledger module cutover proof extends the private P0 bundle.",
		}),
	);
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
	const base = safeCutoverBundle();
	return safeCutoverBundle(
		cutoverBundleWithAdditionalWorkflow({
			base,
			inventoryWorkflow: providerWorkflow("providers.bank", "provider:bank"),
			scopeWorkflow: {
				...base.scopeManifest.workflows[0],
				workflow_id: "providers.bank",
				owner: "provider:bank",
				trust_domain: "provider",
				required_surface_ids: ["providers.approval-binding"],
			},
			probes: [probe],
			adapterApiSignatures: {
				"providers.approval-binding": `sha256:${"8".repeat(64)}`,
			},
			decisionImpact: "Profile generation proof is required before provider cutover.",
		}),
	);
}

function providerReleasePolicyProbe(
	evidencePath: string,
	status: "pass" | "fail" | "skip" = "pass",
) {
	return {
		surface_id: "providers.release-policy",
		hermes_pin: hermesPin,
		documented_seam:
			"Telclaude provider release policy binds scoped actor, domain, recipient, and provider account release",
		probe_command: "pnpm dev hermes probe providers.release-policy --allow-run",
		expected_result:
			"Provider reads and prepared actions release only non-secret refs to bound actors and audit the decision",
		negative_probe:
			"Wrong actor, wrong recipient, missing strong link, urgent health misclassification, private memory, and unapproved sensitive release fail closed",
		evidence_path: evidencePath,
		lockfile_key: "featureProbes.providers.releasePolicy",
		approval_equivalent: true,
		failure_outcome: "disable" as const,
		status,
	};
}

function providerReleasePolicyCutoverBundle(
	evidencePath: string,
	matrixStatus: "pass" | "fail" | "skip" = "pass",
) {
	const probe = providerReleasePolicyProbe(evidencePath, matrixStatus);
	const base = safeCutoverBundle();
	return safeCutoverBundle(
		cutoverBundleWithAdditionalWorkflow({
			base,
			inventoryWorkflow: householdWorkflow("household.assistant"),
			scopeWorkflow: {
				...base.scopeManifest.workflows[0],
				workflow_id: "household.assistant",
				owner: "household:family",
				trust_domain: "household",
				required_surface_ids: ["providers.release-policy"],
			},
			probes: [probe],
			adapterApiSignatures: {
				"providers.release-policy": `sha256:${"5".repeat(64)}`,
			},
			decisionImpact: "Profile generation proof is required before provider cutover.",
		}),
	);
}

function googleProviderProbe(evidencePath: string, status: "pass" | "fail" | "skip" = "pass") {
	return {
		surface_id: "providers.google",
		hermes_pin: hermesPin,
		documented_seam:
			"Telclaude Google sidecar remains OAuth credential owner and Hermes uses provider proxy tools",
		probe_command: "pnpm dev hermes probe providers.google --allow-run",
		expected_result:
			"Gmail reads, draft writes, wrong-actor denial, replay denial, and raw OAuth absence pass",
		negative_probe:
			"Mismatched approval-token audience, wrong actor, replay, mutated write params, direct Google/provider/vault access, and raw OAuth exposure fail closed",
		evidence_path: evidencePath,
		lockfile_key: "featureProbes.providers.google",
		approval_equivalent: true,
		failure_outcome: "disable" as const,
		status,
	};
}

type ProviderDomainSurfaceId = "providers.bank" | "providers.clalit" | "providers.government";

const providerDomainDetails: Record<
	ProviderDomainSurfaceId,
	{
		readonly providerId: "bank" | "clalit" | "government";
		readonly owner: string;
		readonly expectedResult: string;
		readonly negativeProbe: string;
	}
> = {
	"providers.bank": {
		providerId: "bank",
		owner: "provider:bank",
		expectedResult:
			"Bank read, transfer prepare, approved transfer execute, scope denial, replay denial, and credential absence pass",
		negativeProbe:
			"Wrong actor, wrong provider scope, replay, direct bank/provider/vault access, and raw credential exposure fail closed",
	},
	"providers.clalit": {
		providerId: "clalit",
		owner: "provider:clalit",
		expectedResult:
			"Clalit read, booking prepare, approved execute, emergency escalation, scope denial, replay denial, and credential absence pass",
		negativeProbe:
			"Wrong actor, wrong provider scope, emergency mishandling, replay, direct provider/vault access, and raw credential exposure fail closed",
	},
	"providers.government": {
		providerId: "government",
		owner: "provider:government",
		expectedResult:
			"Government status read, form prepare, approved submission, scope denial, replay denial, and credential absence pass",
		negativeProbe:
			"Wrong actor, wrong provider scope, replay, direct government/provider/vault access, and raw credential exposure fail closed",
	},
};

function providerDomainProbe(
	surfaceId: ProviderDomainSurfaceId,
	evidencePath: string,
	status: "pass" | "fail" | "skip" = "pass",
) {
	const details = providerDomainDetails[surfaceId];
	return {
		surface_id: surfaceId,
		hermes_pin: hermesPin,
		documented_seam: `Telclaude ${details.providerId} provider sidecar remains credential owner and Hermes uses MCP/provider proxy tools`,
		probe_command: `pnpm dev hermes probe ${surfaceId} --allow-run`,
		expected_result: details.expectedResult,
		negative_probe: details.negativeProbe,
		evidence_path: evidencePath,
		lockfile_key: `featureProbes.providers.${details.providerId}`,
		approval_equivalent: true,
		failure_outcome: "disable" as const,
		status,
	};
}

function providerDomainCutoverBundle(
	surfaceId: ProviderDomainSurfaceId,
	evidencePath: string,
	matrixStatus: "pass" | "fail" | "skip" = "pass",
) {
	const probe = providerDomainProbe(surfaceId, evidencePath, matrixStatus);
	const details = providerDomainDetails[surfaceId];
	const base = safeCutoverBundle();
	return safeCutoverBundle(
		cutoverBundleWithAdditionalWorkflow({
			base,
			inventoryWorkflow: providerWorkflow(surfaceId, details.owner),
			scopeWorkflow: {
				...base.scopeManifest.workflows[0],
				workflow_id: surfaceId,
				owner: details.owner,
				trust_domain: "provider",
				required_surface_ids: [surfaceId],
			},
			probes: [probe],
			adapterApiSignatures: {
				[surfaceId]: `sha256:${"7".repeat(64)}`,
			},
			decisionImpact: "Profile generation proof is required before provider cutover.",
		}),
	);
}

function googleProviderCutoverBundle(
	evidencePath: string,
	matrixStatus: "pass" | "fail" | "skip" = "pass",
) {
	const probe = googleProviderProbe(evidencePath, matrixStatus);
	const base = safeCutoverBundle();
	return safeCutoverBundle(
		cutoverBundleWithAdditionalWorkflow({
			base,
			inventoryWorkflow: providerWorkflow("providers.google", "provider:google"),
			scopeWorkflow: {
				...base.scopeManifest.workflows[0],
				workflow_id: "providers.google",
				owner: "provider:google",
				trust_domain: "provider",
				required_surface_ids: ["providers.google"],
			},
			probes: [probe],
			adapterApiSignatures: {
				"providers.google": `sha256:${"6".repeat(64)}`,
			},
			decisionImpact: "Profile generation proof is required before provider cutover.",
		}),
	);
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
	const base = safeCutoverBundle();
	return safeCutoverBundle(
		cutoverBundleWithAdditionalWorkflow({
			base,
			inventoryWorkflow: moduleTestWorkflow("execution.api_server.module"),
			scopeWorkflow: {
				...base.scopeManifest.workflows[0],
				workflow_id: "execution.api_server.module",
				trust_domain: "module-test",
				required_surface_ids: ["execution.api_server_containment"],
			},
			probes: [probe],
			adapterApiSignatures: {
				"execution.api_server_containment": `sha256:${"e".repeat(64)}`,
			},
			decisionImpact: "API-server containment module cutover proof extends the private P0 bundle.",
		}),
	);
}

function servedMcpContainmentCutoverBundle(
	evidencePath: string,
	matrixStatus: "pass" | "fail" | "skip" = "pass",
) {
	const probe = servedMcpContainmentProbe(evidencePath, matrixStatus);
	const base = safeCutoverBundle();
	return safeCutoverBundle(
		cutoverBundleWithAdditionalWorkflow({
			base,
			inventoryWorkflow: moduleTestWorkflow("execution.served_mcp.module"),
			scopeWorkflow: {
				...base.scopeManifest.workflows[0],
				workflow_id: "execution.served_mcp.module",
				trust_domain: "module-test",
				required_surface_ids: ["execution.served_mcp_containment"],
			},
			probes: [probe],
			adapterApiSignatures: {
				"execution.served_mcp_containment": `sha256:${"f".repeat(64)}`,
			},
			decisionImpact: "Served-MCP containment module cutover proof extends the private P0 bundle.",
		}),
	);
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
	const base = safeCutoverBundle();
	return safeCutoverBundle(
		cutoverBundleWithAdditionalWorkflow({
			base,
			inventoryWorkflow: providerWorkflow("providers.bank", "provider:bank"),
			scopeWorkflow: {
				...base.scopeManifest.workflows[0],
				workflow_id: "providers.bank",
				owner: "provider:bank",
				trust_domain: "provider",
				required_surface_ids: ["served_mcp.provider-tools"],
			},
			probes: [probe],
			adapterApiSignatures: {
				"served_mcp.provider-tools": `sha256:${"7".repeat(64)}`,
			},
			decisionImpact: "Profile generation proof is required before served-MCP provider cutover.",
		}),
	);
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

async function runCutoverCheckWithBundle(
	bundle: CutoverInputBundle,
	options: { readonly scoped?: boolean } = {},
) {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-"));
	const paths = writeCutoverBundleArtifacts(tempDir, bundle);
	return runHermesCommand([
		"hermes",
		"cutover-check",
		"--strict",
		"--dry-run",
		"--json",
		...(options.scoped ? ["--scoped"] : []),
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

async function runScopedCutoverCheckWithBundle(bundle: CutoverInputBundle) {
	return runCutoverCheckWithBundle(bundle, { scoped: true });
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
		networkName: "telclaude-hermes-relay",
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

function cliHeadlessUnsignedRelayProofWithNullToken(): Record<string, unknown> {
	const { signature: _signature, ...unsigned } = cliHeadlessRelayProof();
	return {
		...unsigned,
		proofTokenSha256: null,
	};
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
			args: ["chat", "-q", "Reply with exactly HERMES_OK_GPT55_RELAY"],
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
	const reverifiedAt = new Date().toISOString();
	const observedAt = new Date(Date.now() - 60_000).toISOString();
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
		observedAt,
		reverifiedAt,
		dryCanary: {
			command:
				"YOETZ_AGENT=1 yoetz browser extension canary --chatgpt --extension-instance-id ext_test --format json",
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
			command:
				"YOETZ_AGENT=1 yoetz browser extension reconnect --chatgpt --extension-instance-id ext_test --format json",
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

function writeRecoverableYoetzNativeReadFailureBin(
	tempDir: string,
	stderrLine = "chrome-extension-native: failed to fill whole buffer",
): string {
	const binDir = path.join(tempDir, "bin");
	fs.mkdirSync(binDir, { recursive: true });
	const yoetzPath = path.join(binDir, "yoetz");
	fs.writeFileSync(
		yoetzPath,
		`#!/usr/bin/env node
const fs = require("fs");
const os = require("os");
const path = require("path");

const args = process.argv.slice(2);

function flagValue(flag) {
  const index = args.indexOf(flag);
  return index >= 0 ? args[index + 1] : undefined;
}

function varValue(name) {
  for (let index = 0; index < args.length - 1; index += 1) {
    if (args[index] !== "--var") continue;
    const value = args[index + 1];
    const prefix = name + "=";
    if (typeof value === "string" && value.startsWith(prefix)) return value.slice(prefix.length);
  }
  return undefined;
}

function metaPath(runId) {
  return path.join(os.tmpdir(), "hermes-pro-review-fake-yoetz-" + runId + ".json");
}

if (args[0] === "browser" && args[1] === "recipe") {
  const runId = varValue("run_id");
  if (!runId) {
    console.error("missing run_id");
    process.exit(2);
  }
  fs.writeFileSync(
    metaPath(runId),
    JSON.stringify({
      runId,
      payloadSha256: varValue("payload_sha256"),
      bundleSha256: varValue("bundle_sha256"),
      bundlePath: flagValue("--bundle")
    })
  );
  console.error(${JSON.stringify(stderrLine)});
  process.exit(1);
}

if (args[0] === "browser" && args[1] === "extension" && args[2] === "inspect") {
  const runId = flagValue("--run-id");
  if (!runId) {
    console.error("missing --run-id");
    process.exit(2);
  }
  const meta = JSON.parse(fs.readFileSync(metaPath(runId), "utf8"));
  process.stdout.write(JSON.stringify({
    status: "ok",
    transport: "chrome-extension-native",
    response: {
      run_id: runId,
      tabs: [
        {
          url: "https://chatgpt.com/c/fake",
          title: "ChatGPT",
          inspection: {
            ownership: { run_id: runId },
            window_name: "yoetz-chatgpt-native:" + runId + ":job_fake",
            extraction: {
              is_generating: false,
              text: [
                "payloadSha256: " + meta.payloadSha256,
                "Findings:",
                "- No P0/P1 findings in this recovered full-context fixture.",
                "Residual risk:",
                "- Fixture validates single-run native inspect recovery only."
              ].join("\\n")
            },
            model_selection: { current_model_label: "Extended Pro" }
          }
        }
      ]
    }
  }));
  process.exit(0);
}

console.error("unexpected yoetz args: " + args.join(" "));
process.exit(2);
`,
		"utf8",
	);
	fs.chmodSync(yoetzPath, 0o755);
	return binDir;
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

function legacyShardedProReviewRequest(
	canaryPath: string,
	selectedFiles: readonly string[] = [...REQUIRED_PRO_REVIEW_FILES],
	maxShardSourceBytes = 500,
): Record<string, unknown> {
	const prompt = "Review the attached Hermes wrapper files.";
	const blockedFallbacks = [
		"cdp",
		"api-key",
		"manual-browser",
		"claude-substitution",
		"amq-substitution",
	];
	const selectedFileContentsSha256 = computeSelectedFileContentsDigest(selectedFiles);
	const transportEvidenceSha256 = computeFileDigest(canaryPath);
	const shardPlan = buildProReviewShardPlan(selectedFiles, maxShardSourceBytes);
	const shardPlanSha256 = computeTextDigest(JSON.stringify(shardPlan));
	const payload = {
		reviewer: "ChatGPT Pro Extended via Yoetz native extension",
		transport: "chrome-extension-native",
		model: "Extended Pro",
		fallbackAllowed: false,
		transportEvidence: canaryPath,
		blockedFallbacks,
		prompt,
		selectedFiles,
		selectedFileContentsSha256,
		transportEvidenceSha256,
		reviewMode: "sharded",
		shardPlanSha256,
	};
	return proReviewRequest(
		canaryPath,
		{
			reviewMode: "sharded",
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
					"reviewMode",
					"shardPlanSha256",
				],
				payloadSha256: computeTextDigest(JSON.stringify(payload)),
				promptSha256: computeTextDigest(prompt),
				selectedFilesSha256: computeTextDigest(JSON.stringify(selectedFiles)),
				selectedFileContentsSha256,
				transportEvidenceSha256,
				shardPlanSha256,
				notes: "Legacy sharded fixture; production refresh must not generate this shape.",
			},
			shardPlan,
		},
		selectedFiles,
	);
}

async function writeRequiredProReviewWorkspace(
	root: string,
	options: { readonly semanticEvidence?: "red" | "green" } = {},
): Promise<void> {
	if (options.semanticEvidence === "green") {
		await writeGreenProReviewSemanticArtifacts(root);
	}
	for (const file of REQUIRED_PRO_REVIEW_FILES) {
		const resolved = path.join(root, file);
		if (fs.existsSync(resolved)) continue;
		fs.mkdirSync(path.dirname(resolved), { recursive: true });
		if (file === "artifacts/hermes/probes/execution-cli-headless.json") {
			writeJson(resolved, cliHeadlessEvidence());
		} else if (file === "artifacts/hermes/probes/execution-headless-entrypoint.json") {
			writeJson(resolved, headlessEntrypointReadinessFailureEvidence());
		} else if (file === "artifacts/hermes/probes/execution-headless-entrypoint.vitest.json") {
			writeJson(resolved, { numTotalTests: 0, numPassedTests: 0, testResults: [] });
		} else if (file === "artifacts/hermes/pro-review-native-canary.json") {
			writeJson(resolved, proReviewCanary());
		} else if (file === "artifacts/hermes/pro-review-current-cutover-check.json") {
			writeJson(resolved, currentCutoverCheckReport("safe"));
		} else if (isSignedProReviewProbeArtifact(file)) {
			writeJson(resolved, await signedProReviewProbeEvidence(file));
		} else if (file.startsWith("artifacts/hermes/") && file.endsWith(".json")) {
			writeJson(resolved, proReviewReadinessRedEvidence(file));
		} else {
			fs.writeFileSync(resolved, `test fixture for ${file}\n`, "utf8");
		}
	}
}

async function writeGreenProReviewSemanticArtifacts(root: string): Promise<void> {
	const observedAt = "2026-06-01T09:00:00.000Z";
	writeJson(
		rootArtifact(root, "artifacts/hermes/probes/execution-cli-headless.json"),
		cliHeadlessEvidence(),
	);
	writeHeadlessEntrypointGreenEvidence(root);
	writeJson(
		rootArtifact(root, "artifacts/hermes/probes/model-relay.json"),
		passingModelRelayEvidence(),
	);
	writeJson(
		rootArtifact(root, "artifacts/hermes/pro-review-native-canary.json"),
		proReviewCanary(),
	);
	for (const [relativePath, surfaceId] of Object.entries(PRO_REVIEW_EDGE_PROBE_ARTIFACTS)) {
		writeJson(
			rootArtifact(root, relativePath),
			await buildEdgeAdapterProbeEvidence({ surfaceId, allowRun: true, observedAt }),
		);
	}
	for (const [relativePath, surfaceId] of Object.entries(
		PRO_REVIEW_BROWSER_COMPUTER_PROBE_ARTIFACTS,
	)) {
		writeJson(
			rootArtifact(root, relativePath),
			greenBrowserComputerBrokerProbeEvidence(surfaceId, observedAt),
		);
	}
	for (const [relativePath, surfaceId] of Object.entries(
		PRO_REVIEW_PROVIDER_DOMAIN_PROBE_ARTIFACTS,
	)) {
		writeJson(
			rootArtifact(root, relativePath),
			await runTelclaudeProviderDomainProbe({ surfaceId, allowRun: true, observedAt }),
		);
	}
	writeJson(
		rootArtifact(root, "artifacts/hermes/probes/providers-google.json"),
		await runTelclaudeGoogleProviderProbe({ allowRun: true, observedAt }),
	);
	writeJson(
		rootArtifact(root, "artifacts/hermes/probes/providers-release-policy.json"),
		runTelclaudeProviderReleasePolicyProbe({ allowRun: true, observedAt }),
	);
	writeJson(
		rootArtifact(root, "artifacts/hermes/probes/sideeffect-ledger.json"),
		await runTelclaudeMcpSideEffectLedgerProbe({ allowRun: true, observedAt }),
	);
	writeJson(
		rootArtifact(root, "artifacts/hermes/probes/providers-approval-binding.json"),
		await runTelclaudeProviderApprovalBindingProbe({ allowRun: true, observedAt }),
	);
	writeJson(
		rootArtifact(root, "artifacts/hermes/probes/workflow-cron.json"),
		runHermesWorkflowProbe({ surfaceId: "workflow.cron", allowRun: true, observedAt }),
	);
	writeJson(
		rootArtifact(root, "artifacts/hermes/probes/workflow-longrun.json"),
		runHermesWorkflowProbe({ surfaceId: "workflow.longrun", allowRun: true, observedAt }),
	);
	for (const [relativePath, probeId] of Object.entries(PRO_REVIEW_NETWORK_PROBE_ARTIFACTS)) {
		writeJson(rootArtifact(root, relativePath), passingNetworkProbeEvidence(probeId, relativePath));
	}
	const servedMcpSourcePath = rootArtifact(
		root,
		"artifacts/hermes/probes/execution-served-mcp-containment.json",
	);
	const servedMcpSource = servedMcpContainmentEvidence();
	writeJson(servedMcpSourcePath, servedMcpSource);
	writeJson(
		rootArtifact(root, "artifacts/hermes/probes/served-mcp-provider-tools.json"),
		buildServedMcpProviderToolsProbeEvidence({
			sourceEvidencePath: servedMcpSourcePath,
			sourceEvidence: servedMcpSource,
			observedAt,
		}),
	);
	writeFixtureEvidenceBundle(
		root,
		buildEdgeAdapterFixtureEvidenceBundle({
			evidenceDir: rootArtifact(root, "artifacts/hermes/fixtures"),
			observedAt,
			probePaths: {
				...mapRecordValues(PRO_REVIEW_EDGE_PROBE_ARTIFACTS, (_surfaceId, relativePath) =>
					rootArtifact(root, relativePath),
				),
				"providers.release-policy": rootArtifact(
					root,
					"artifacts/hermes/probes/providers-release-policy.json",
				),
			},
		}),
	);
	writeFixtureEvidenceBundle(
		root,
		buildProviderDomainFixtureEvidenceBundle({
			evidenceDir: rootArtifact(root, "artifacts/hermes/fixtures"),
			observedAt,
			probePaths: mapRecordValues(
				PRO_REVIEW_PROVIDER_DOMAIN_PROBE_ARTIFACTS,
				(_surfaceId, relativePath) => rootArtifact(root, relativePath),
			),
			networkProbePath: rootArtifact(root, "artifacts/hermes/network/direct-provider-denied.json"),
		}),
	);
	writeFixtureEvidenceBundle(
		root,
		buildGoogleProviderFixtureEvidenceBundle({
			evidenceDir: rootArtifact(root, "artifacts/hermes/fixtures"),
			observedAt,
			probePath: rootArtifact(root, "artifacts/hermes/probes/providers-google.json"),
			networkProbePath: rootArtifact(root, "artifacts/hermes/network/direct-provider-denied.json"),
		}),
	);
	writeFixtureEvidenceBundle(
		root,
		buildBrowserComputerBrokerFixtureEvidenceBundle({
			evidenceDir: rootArtifact(root, "artifacts/hermes/fixtures"),
			observedAt,
			probePaths: mapRecordValues(
				PRO_REVIEW_BROWSER_COMPUTER_PROBE_ARTIFACTS,
				(_surfaceId, relativePath) => rootArtifact(root, relativePath),
			),
		}),
	);
	writeFixtureEvidenceBundle(
		root,
		buildHermesWorkflowFixtureEvidenceBundle({
			evidenceDir: rootArtifact(root, "artifacts/hermes/fixtures"),
			observedAt,
			probePaths: {
				"workflow.cron": rootArtifact(root, "artifacts/hermes/probes/workflow-cron.json"),
				"workflow.longrun": rootArtifact(root, "artifacts/hermes/probes/workflow-longrun.json"),
			},
		}),
	);
}

const HEADLESS_ENTRYPOINT_CHECKS = [
	"stream.delta_before_done",
	"stream.terminal_event",
	"session.initial",
	"session.resume",
	"session.new_clears_resume",
	"session.concurrent_isolation",
	"tool.result_returned",
	"approval.fallback_or_wait_resume",
	"cancellation.stop",
	"errors.deterministic",
	"redaction.secret_outputs",
] as const;
const HEADLESS_ENTRYPOINT_SOURCE_FILES = [
	"src/hermes/api-adapter.ts",
	"src/hermes/private-runtime.ts",
	"src/hermes/session-map.ts",
	"tests/hermes/api-adapter.test.ts",
	"tests/hermes/private-runtime.test.ts",
] as const;

function headlessEntrypointReadinessFailureEvidence(): Record<string, unknown> {
	return {
		schemaVersion: "telclaude.hermes.headless-entrypoint-proof.v1",
		probeId: "execution.headless_entrypoint",
		status: "fail",
		ran: false,
		generatedAt: "2026-06-01T09:00:00.000Z",
		summary: "headless entrypoint proof was not run in this fixture",
		checks: HEADLESS_ENTRYPOINT_CHECKS.map((name) => ({
			name,
			status: "fail",
			detail: "not run",
		})),
	};
}

function writeHeadlessEntrypointGreenEvidence(root: string): void {
	for (const sourcePath of HEADLESS_ENTRYPOINT_SOURCE_FILES) {
		const resolved = rootArtifact(root, sourcePath);
		if (!fs.existsSync(resolved)) {
			fs.mkdirSync(path.dirname(resolved), { recursive: true });
			fs.writeFileSync(resolved, `test fixture for ${sourcePath}\n`, "utf8");
		}
	}
	const reportPath = rootArtifact(
		root,
		"artifacts/hermes/probes/execution-headless-entrypoint.vitest.json",
	);
	writeJson(reportPath, { numTotalTests: 2, numPassedTests: 2, testResults: [] });
	writeJson(rootArtifact(root, "artifacts/hermes/probes/execution-headless-entrypoint.json"), {
		schemaVersion: "telclaude.hermes.headless-entrypoint-proof.v1",
		probeId: "execution.headless_entrypoint",
		status: "pass",
		ran: true,
		generatedAt: "2026-06-01T09:00:00.000Z",
		summary: "Hermes API adapter and private runtime semantic headless entrypoint checks passed",
		testReport: {
			runner: "vitest-json",
			command: [
				"pnpm",
				"exec",
				"vitest",
				"run",
				"tests/hermes/api-adapter.test.ts",
				"tests/hermes/private-runtime.test.ts",
				"--reporter=json",
			],
			cwd: root,
			exitCode: 0,
			reportPath,
			reportSha256: computeFileDigest(reportPath),
			sourceDigests: Object.fromEntries(
				HEADLESS_ENTRYPOINT_SOURCE_FILES.map((sourcePath) => {
					const resolvedSourcePath = rootArtifact(root, sourcePath);
					return [resolvedSourcePath, computeFileDigest(resolvedSourcePath)];
				}),
			),
		},
		checks: HEADLESS_ENTRYPOINT_CHECKS.map((name) => ({
			name,
			status: "pass",
			detail: `${name} passed in focused adapter/runtime tests`,
		})),
	});
}

function rootArtifact(root: string, relativePath: string): string {
	return path.join(root, relativePath);
}

function currentCutoverCheckReport(
	status: "safe" | "pass" | "fail" | "input_error",
	generatedAt = new Date().toISOString(),
	dryRun = status === "pass" || status === "fail",
): Record<string, unknown> {
	const ok = status === "safe" || status === "pass";
	return {
		generatedAt,
		status,
		exitCode: ok ? 0 : 1,
		mode: {
			strict: true,
			dryRun,
		},
		gates: [
			{
				name: "workflow.scope",
				status: ok ? "pass" : "fail",
				detail: ok ? "included workflows are scoped" : "no included workflows",
			},
		],
		workflowIds: ok ? ["workflow.private.telegram"] : [],
		evidencePaths: [],
		decisionIds: [],
		downgradeNotes: [],
		remediationOwners: [],
	};
}

function greenBrowserComputerBrokerProbeEvidence(
	surfaceId: BrowserComputerBrokerSurfaceId,
	observedAt: string,
): ReturnType<typeof runTelclaudeBrowserComputerBrokerProbe> {
	if (surfaceId === "network.egress-broker") {
		ensureOperatorRelaySigningKeys();
		return buildNetworkEgressBrokerProbeEvidenceFromReport(
			completeNetworkEgressBrokerRunReport(observedAt),
		);
	}
	return runTelclaudeBrowserComputerBrokerProbe({
		surfaceId,
		allowRun: true,
		observedAt,
	});
}

function completeNetworkEgressBrokerRunReport(observedAt: string): Record<string, unknown> {
	const deniedKinds = [
		"provider",
		"model",
		"vault",
		"metadata",
		"private-network",
		"smtp",
		"imap",
		"whatsapp-bridge",
		"dns-53",
		"doh",
		"dot",
		"connect-proxy",
		"websocket",
		"webrtc",
		"ip-literal",
		"dns-rebinding",
		"localhost-callback",
		"unquarantined-upload",
		"browser-provider-bypass",
		"computer-covert-egress",
	] as const;
	return {
		schemaVersion: NETWORK_EGRESS_BROKER_RUN_REPORT_SCHEMA_VERSION,
		surfaceId: "network.egress-broker",
		ran: true,
		observedAt,
		source: NETWORK_EGRESS_BROKER_RUN_REPORT_SOURCE,
		summary: "machine-observed egress broker denials passed",
		attempts: [
			{
				name: "public-research",
				kind: "public-research",
				target: "https://example.org/research/benign",
				expectation: "allow",
				status: "pass",
				observed: "reachable",
				detail: "allowed public research egress reached the broker",
				route: "telclaude-egress-broker",
				httpStatus: 200,
			},
			...deniedKinds.map((kind) => ({
				name: `${kind}-denied`,
				kind,
				target: `egress-test://${kind}`,
				expectation: "deny",
				status: "pass",
				observed: "denied",
				detail: `${kind} egress was denied by the contained runtime policy`,
				errorCode: "ENETUNREACH",
			})),
		],
	};
}

function writeFixtureEvidenceBundle(
	root: string,
	bundle: {
		readonly evidence: readonly Record<string, unknown>[];
	},
): void {
	for (const evidence of bundle.evidence) {
		const evidencePath = evidence.evidence_path;
		if (typeof evidencePath !== "string") throw new Error("fixture evidence_path is missing");
		const relativeEvidencePath = path.relative(root, evidencePath).split(path.sep).join("/");
		writeJson(evidencePath, { ...evidence, evidence_path: relativeEvidencePath });
	}
}

function proReviewReadinessRedEvidence(file: string): Record<string, unknown> {
	return {
		schemaVersion: "telclaude.hermes.pro-review-red-semantic-evidence.v1",
		id: path.basename(file, ".json"),
		probeId: path.basename(file, ".json"),
		status: "fail",
		ran: false,
		summary: `readiness-only red evidence for ${file}`,
	};
}

function mapRecordValues<T extends string, V extends string>(
	record: Record<string, V>,
	mapper: (value: V, key: string) => T,
): Partial<Record<V, T>> {
	return Object.fromEntries(
		Object.entries(record).map(([key, value]) => [value, mapper(value, key)]),
	) as Partial<Record<V, T>>;
}

function isSignedProReviewProbeArtifact(file: string): boolean {
	return (
		file in PRO_REVIEW_EDGE_PROBE_ARTIFACTS ||
		file === "artifacts/hermes/probes/sideeffect-ledger.json" ||
		file === "artifacts/hermes/probes/providers-approval-binding.json" ||
		file === "artifacts/hermes/probes/workflow-cron.json" ||
		file === "artifacts/hermes/probes/workflow-longrun.json"
	);
}

async function signedProReviewProbeEvidence(file: string): Promise<Record<string, unknown>> {
	ensureOperatorRelaySigningKeys();
	const observedAt = "2026-06-01T09:00:00.000Z";
	const edgeSurfaceId = PRO_REVIEW_EDGE_PROBE_ARTIFACTS[file];
	if (edgeSurfaceId) {
		return await buildEdgeAdapterProbeEvidence({
			surfaceId: edgeSurfaceId,
			allowRun: true,
			observedAt,
		});
	}
	if (file === "artifacts/hermes/probes/sideeffect-ledger.json") {
		return await runTelclaudeMcpSideEffectLedgerProbe({ allowRun: true, observedAt });
	}
	if (file === "artifacts/hermes/probes/providers-approval-binding.json") {
		return await runTelclaudeProviderApprovalBindingProbe({ allowRun: true, observedAt });
	}
	if (file === "artifacts/hermes/probes/workflow-cron.json") {
		return runHermesWorkflowProbe({ surfaceId: "workflow.cron", allowRun: true, observedAt });
	}
	if (file === "artifacts/hermes/probes/workflow-longrun.json") {
		return runHermesWorkflowProbe({ surfaceId: "workflow.longrun", allowRun: true, observedAt });
	}
	throw new Error(`unsupported signed Pro review probe artifact ${file}`);
}

function ensureOperatorRelaySigningKeys(): void {
	process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY ??= cliHeadlessRelaySigningKeys.privateKey;
	process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY ??= cliHeadlessRelaySigningKeys.publicKey;
}

const PRO_REVIEW_EDGE_PROBE_ARTIFACTS: Record<string, EdgeAdapterFeatureSurfaceId> = {
	"artifacts/hermes/probes/edge-whatsapp.json": "edge.whatsapp",
	"artifacts/hermes/probes/edge-email.json": "edge.email",
	"artifacts/hermes/probes/edge-agentmail.json": "edge.agentmail",
	"artifacts/hermes/probes/edge-social.json": "edge.social",
	"artifacts/hermes/probes/identity-migration.json": "identity.migration",
	"artifacts/hermes/probes/household-scopes.json": "household.scopes",
	"artifacts/hermes/probes/attachment-quarantine.json": "attachment.quarantine",
	"artifacts/hermes/probes/outbound-policy.json": "outbound.policy",
	"artifacts/hermes/probes/public-social-isolation.json": "public.social.isolation",
};

const PRO_REVIEW_BROWSER_COMPUTER_PROBE_ARTIFACTS: Record<string, BrowserComputerBrokerSurfaceId> =
	{
		"artifacts/hermes/probes/browser-profiles.json": "browser.profiles",
		"artifacts/hermes/probes/computer-broker.json": "computer.broker",
		"artifacts/hermes/probes/network-egress-broker.json": "network.egress-broker",
	};

const PRO_REVIEW_PROVIDER_DOMAIN_PROBE_ARTIFACTS: Record<string, HermesProviderDomainSurfaceId> = {
	"artifacts/hermes/probes/providers-bank.json": "providers.bank",
	"artifacts/hermes/probes/providers-clalit.json": "providers.clalit",
	"artifacts/hermes/probes/providers-government.json": "providers.government",
};

const PRO_REVIEW_NETWORK_PROBE_ARTIFACTS: Record<string, string> = {
	"artifacts/hermes/network/relay-control-allowed.json": "network.relay-control-allowed",
	"artifacts/hermes/network/direct-provider-denied.json": "network.direct-provider-denied",
	"artifacts/hermes/network/direct-vault-denied.json": "network.direct-vault-denied",
	"artifacts/hermes/network/direct-model-provider-denied.json":
		"network.direct-model-provider-denied",
	"artifacts/hermes/network/dns-exfil-denied.json": "network.dns-exfil-denied",
};

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

async function withActualCwd<T>(cwd: string, callback: () => Promise<T>): Promise<T> {
	const previousCwd = process.cwd();
	const previousTestCwd = testCwd;
	const realCwd = fs.realpathSync.native(cwd);
	process.chdir(realCwd);
	testCwd = realCwd;
	try {
		return await callback();
	} finally {
		testCwd = previousTestCwd;
		process.chdir(previousCwd);
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
				const resolved = resolveTestPath(file);
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
	const resolved = resolveTestPath(file);
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
	beforeEach(() => {
		snapshotHermesCommandTestEnv();
		process.exitCode = undefined;
		process.env.TELCLAUDE_HERMES_RELAY_IP = CLI_HEADLESS_TEST_RELAY_IP;
		process.env.TELCLAUDE_HERMES_CONTAINED_IP = CLI_HEADLESS_TEST_CONTAINED_IP;
	});

	afterEach(async () => {
		restoreEnv(
			"TELCLAUDE_HERMES_RELAY_IP",
			ORIGINAL_HERMES_RUNTIME_IP_ENV.TELCLAUDE_HERMES_RELAY_IP,
		);
		restoreEnv(
			"TELCLAUDE_HERMES_CONTAINED_IP",
			ORIGINAL_HERMES_RUNTIME_IP_ENV.TELCLAUDE_HERMES_CONTAINED_IP,
		);
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

	it("writes fail-closed profile-generation proof seeds", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-profile-red-seed-"));
		execFileSync("git", ["init"], { cwd: tempDir, stdio: "ignore" });
		await withCwd(tempDir, async () => {
			const proofPath = path.join(tempDir, "docs/hermes/profile-generation-proof.json");

			const result = await runHermesCommand([
				"hermes",
				"generate",
				"--red-seed",
				"--pin",
				"0.15.1",
				"--proof-out",
				proofPath,
				"--write-tracked-seed",
				"--json",
			]);
			const proof = readJson(proofPath) as {
				status: string;
				checks: Array<{ name: string; status: string }>;
			};

			expect(result.exitCode, result.stdout).toBe(1);
			expect(proof.status).toBe("fail");
			expect(proof.checks).toEqual([
				expect.objectContaining({ name: "profile.redSeed", status: "fail" }),
			]);
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

	it("refuses to write the tracked profile-generation proof seed by default", async () => {
		const trackedProofPath = path.resolve("docs/hermes/profile-generation-proof.json");
		const before = fs.readFileSync(trackedProofPath, "utf8");
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-generate-seed-guard-"));
		const profileDir = path.join(tempDir, "profile");

		const result = await runHermesCommand([
			"hermes",
			"generate",
			"--write",
			"--out",
			profileDir,
			"--json",
		]);

		expect(result.exitCode).toBe(1);
		expect(fs.readFileSync(trackedProofPath, "utf8")).toBe(before);
		expect(fs.existsSync(profileDir)).toBe(false);
	});

	it("writes profile-generation proof evidence to an explicit temp output", async () => {
		const trackedProofPath = path.resolve("docs/hermes/profile-generation-proof.json");
		const before = fs.readFileSync(trackedProofPath, "utf8");
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-generate-temp-proof-"));
		const profileDir = path.join(tempDir, "profile");
		const proofOut = path.join(tempDir, "profile-generation-proof.json");

		const result = await runHermesCommand([
			"hermes",
			"generate",
			"--write",
			"--out",
			profileDir,
			"--proof-out",
			proofOut,
			"--json",
		]);
		const report = readJson(proofOut) as { status: string; evidence_path: string };

		expect(result.exitCode, result.stdout).toBe(0);
		expect(report.status).toBe("pass");
		expect(report.evidence_path).toBe(proofOut);
		expect(fs.existsSync(path.join(profileDir, "docs/hermes/hermes-compat.lock.json"))).toBe(true);
		expect(
			readJson(path.join(profileDir, "profiles/tc-private-default/secret-manifest.json")),
		).toMatchObject({
			rawCredentialPolicy: "relay-owned-only",
			relayTokenBinding: "run-peer-bound",
		});
		expect(fs.readFileSync(trackedProofPath, "utf8")).toBe(before);
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

	it("generates a dry-run profile manifest without raw secret values", () => {
		const manifest = buildHermesGenerateDryRun({
			pin: hermesPin,
			outDir: "/tmp/tc-hermes",
		});

		expect(manifest.outputs.some((output) => output.classification === "secret")).toBe(false);
		const outputPaths = manifest.outputs.map((output) => output.path);
		expect(outputPaths).toEqual(
			expect.arrayContaining([
				"profile-roster.json",
				"profiles/tc-private-default/config.yaml",
				"profiles/tc-public/gateway-platforms.json",
				"profiles/tc-household/memory-provider.json",
				"profiles/tc-control/profile-manifest.json",
				"docs/hermes/hermes-compat.lock.json",
			]),
		);
		expect(outputPaths).not.toContain("config.yaml");
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
		expect(proof.outputs.map((output) => output.path)).toContain(
			"profiles/tc-public/gateway-platforms.json",
		);
		expect(result.stdout).toContain("profile-generation-proof.json");
	});

	it("assembles cutover input from separate canonical artifacts", () => {
		const source = safeCutoverBundle();
		const queueSummary = pendingQueues();
		const inventory = {
			...source.inventory,
			status: "complete" as const,
			summary: {
				pendingQueues: queueSummary,
			},
			queues: queueDetailsFromPending(queueSummary),
		};
		const queueSnapshot = queueSnapshotFromPending(queueSummary);
		const proofSource = safeCutoverBundle({ inventory, queueSnapshot });
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
		expect(assembled.queueSnapshot).toEqual(queueSnapshot);
	});

	it("builds queue ownership snapshots from complete inventory evidence", () => {
		const source = safeCutoverBundle();
		const queueSummary = pendingQueues({
			approvals: 2,
			backgroundJobs: 1,
		});
		const inventory = {
			...source.inventory,
			status: "complete" as const,
			summary: {
				pendingQueues: queueSummary,
			},
			queues: queueDetailsFromPending(queueSummary),
		};

		expect(buildHermesQueueSnapshot({ inventory })).toEqual(queueSnapshotFromPending(queueSummary));
	});

	it("writes queue-snapshot artifacts from an inventory snapshot", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-queue-snapshot-"));
		const source = safeCutoverBundle();
		const inventoryPath = path.join(tempDir, "inventory.json");
		const outPath = path.join(tempDir, "queue-snapshot.json");
		const queueSummary = pendingQueues({
			approvals: 1,
			backgroundJobs: 2,
		});
		writeJson(inventoryPath, {
			...source.inventory,
			status: "complete",
			summary: {
				pendingQueues: queueSummary,
			},
			queues: queueDetailsFromPending(queueSummary),
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
		expect(snapshot).toEqual(queueSnapshotFromPending(queueSummary));
		expect(readJson(outPath)).toEqual(snapshot);
	});

	it("writes fail-closed decision-log drafts from inventory decisions", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-decision-log-"));
		const inventoryPath = path.join(tempDir, "inventory.json");
		const outPath = path.join(tempDir, "decisions.json");
		writeJson(inventoryPath, {
			schemaVersion: 1,
			workflows: [
				{
					workflow_id: "private.telegram.basic",
					unresolved_decision_ids: ["D-private-execution-contract"],
				},
			],
		});

		const result = await runHermesCommand([
			"hermes",
			"decision-log",
			"--json",
			"--inventory",
			inventoryPath,
			"--out",
			outPath,
		]);
		const decisionLog = JSON.parse(result.stdout) as {
			decisions: Array<{ id: string; status: string; affected_workflows: string[] }>;
		};

		expect(result.exitCode, result.stdout).toBe(1);
		expect(readJson(outPath)).toEqual(decisionLog);
		expect(decisionLog.decisions).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					id: "D-first-cutover-workflow-set",
					status: "unresolved",
					affected_workflows: ["private.telegram.basic"],
				}),
				expect.objectContaining({
					id: "D-private-execution-contract",
					status: "unresolved",
					affected_workflows: ["private.telegram.basic"],
				}),
			]),
		);
	});

	it("writes cutover-scope manifests from inventory snapshots", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-scope-"));
		const inventoryPath = path.join(tempDir, "inventory.json");
		const outPath = path.join(tempDir, "cutover-scope.json");
		writeJson(inventoryPath, {
			schemaVersion: 1,
			workflows: [
				{
					workflow_id: "private.telegram.basic",
					owner: "operator",
					trust_domain: "private",
					active: true,
				},
				{
					workflow_id: "social.xtwitter.proactive",
					owner: "operator",
					trust_domain: "social",
					active: false,
				},
			],
		});

		const result = await runHermesCommand([
			"hermes",
			"cutover-scope",
			"--json",
			"--inventory",
			inventoryPath,
			"--out",
			outPath,
		]);
		const manifest = JSON.parse(result.stdout) as {
			workflows: Array<{ workflow_id: string; status: string }>;
		};

		expect(result.exitCode, result.stdout).toBe(0);
		expect(readJson(outPath)).toEqual(manifest);
		expect(manifest.workflows).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					workflow_id: "private.telegram.basic",
					status: "excluded",
				}),
				expect.objectContaining({
					workflow_id: "social.xtwitter.proactive",
					status: "disabled",
				}),
			]),
		);
	});

	it("cutover-check consumes explicit queue snapshot artifacts", async () => {
		const source = safeCutoverBundle();
		const queueSummary = pendingQueues();
		const inventory = {
			...source.inventory,
			status: "complete" as const,
			summary: {
				pendingQueues: queueSummary,
			},
			queues: queueDetailsFromPending(queueSummary),
		};
		const bundle = safeCutoverBundle({
			inventory,
			queueSnapshot: queueSnapshotFromPending(pendingQueues({ approvals: 2 })),
		});

		const result = await runCutoverCheckWithBundle(bundle);
		const report = JSON.parse(result.stdout) as {
			generatedAt?: string;
			status: string;
			gates: Array<{ name: string; status: string }>;
		};

		expect(result.exitCode, result.stdout).toBe(1);
		expect(report.status).toBe("fail");
		expect(Number.isNaN(Date.parse(report.generatedAt ?? ""))).toBe(false);
		expect(report.gates.find((gate) => gate.name === "proofBundle.queueSnapshot")).toMatchObject({
			status: "pass",
		});
		expect(report.gates.find((gate) => gate.name === "queues.owned")).toMatchObject({
			status: "fail",
		});
	});

	it("cutover-check dry-run fails semantically when generated default cutover inputs are absent", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-red-defaults-"));
		const fixtureResults = buildMissingDefaultCutoverFixtureResults();
		const networkProbes = buildMissingDefaultCutoverNetworkProbes();
		const rollbackRehearsal = buildMissingDefaultRollbackRehearsal();
		const generatedAt = freshHermesFixtureTimestamp();
		const baseSource = safeCutoverBundle({
			fixtureResults,
			networkProbes,
			rollbackRehearsal,
		});
		const source = safeCutoverBundle({
			fixtureResults,
			networkProbes,
			rollbackRehearsal,
			inventory: {
				...baseSource.inventory,
				generatedAt,
			},
			queueSnapshot: queueSnapshotFromPending(pendingQueues(), generatedAt),
		});

		await withCwd(tempDir, async () => {
			writeJson(DEFAULT_INVENTORY_PATH, source.inventory);
			writeJson(DEFAULT_CUTOVER_SCOPE_PATH, source.scopeManifest);
			writeJson(DEFAULT_DECISION_LOG_PATH, source.decisionLog);
			writeJson(DEFAULT_COMPAT_LOCKFILE_PATH, source.lockfile);
			writeJson(DEFAULT_FEATURE_PROBE_MATRIX_PATH, source.featureProbeMatrix);
			writeJson(DEFAULT_FIXTURE_RESULTS_PATH, fixtureResults);
			writeJson(DEFAULT_NO_FORK_PROOF_PATH, source.noForkProof);
			writeJson(DEFAULT_NETWORK_PROBES_PATH, networkProbes);
			writeJson(DEFAULT_QUEUE_SNAPSHOT_PATH, source.queueSnapshot);
			if (source.profileGenerationProof) {
				writeJson(DEFAULT_PROFILE_GENERATION_PROOF_PATH, source.profileGenerationProof);
			}
			writeJson(DEFAULT_ROLLBACK_REHEARSAL_PATH, rollbackRehearsal);
			const proofBundle = buildCutoverProofBundle({
				hermes: source.lockfile.hermes,
				wrapperVersion: source.lockfile.wrapperPackageVersion,
				artifacts: {
					inventory: proofArtifact(DEFAULT_INVENTORY_PATH, "pnpm dev hermes inventory --json", [
						"inputs.inventory",
					]),
					scopeManifest: proofArtifact(
						DEFAULT_CUTOVER_SCOPE_PATH,
						"pnpm dev hermes cutover-scope --json",
						["inputs.scopeManifest", "workflow.scope"],
					),
					decisionLog: proofArtifact(
						DEFAULT_DECISION_LOG_PATH,
						"pnpm dev hermes decision-log --json",
						["inputs.decisionLog", "decisions.resolved"],
					),
					compatibilityLockfile: proofArtifact(
						DEFAULT_COMPAT_LOCKFILE_PATH,
						"pnpm dev hermes compat-lock --dry-run --json",
						["inputs.lockfile", "lockfile.consistent"],
					),
					featureProbeMatrix: proofArtifact(
						DEFAULT_FEATURE_PROBE_MATRIX_PATH,
						"pnpm dev hermes probes --json",
						["inputs.featureProbeMatrix", "featureProbes.pass"],
					),
					fixtureResults: proofArtifact(
						DEFAULT_FIXTURE_RESULTS_PATH,
						"pnpm dev hermes fixtures --json",
						["inputs.fixtureResults", "fixtures.pass"],
					),
					noForkProof: proofArtifact(
						DEFAULT_NO_FORK_PROOF_PATH,
						"pnpm dev hermes prove --upstream-clean --p0 --json",
						["inputs.noForkProof", "nofork.clean"],
					),
					networkProbeBundle: proofArtifact(
						DEFAULT_NETWORK_PROBES_PATH,
						"pnpm dev hermes network-probes --json",
						["inputs.networkProbes", "networkProbes.pass"],
					),
					queueSnapshot: proofArtifact(
						DEFAULT_QUEUE_SNAPSHOT_PATH,
						"pnpm dev hermes queue-snapshot --json",
						["inputs.queueSnapshot", "queues.owned"],
					),
					rollbackEvidence: proofArtifact(
						DEFAULT_ROLLBACK_REHEARSAL_PATH,
						"pnpm dev hermes rollback-rehearsal --json",
						["inputs.rollbackRehearsal", "rollback.rehearsed"],
					),
				},
			});
			writeJson(DEFAULT_CUTOVER_PROOF_BUNDLE_PATH, proofBundle);
			fs.rmSync(resolveTestPath(DEFAULT_FIXTURE_RESULTS_PATH));
			fs.rmSync(resolveTestPath(DEFAULT_NETWORK_PROBES_PATH));
			fs.rmSync(resolveTestPath(DEFAULT_ROLLBACK_REHEARSAL_PATH));

			const result = await runHermesCommand([
				"hermes",
				"cutover-check",
				"--strict",
				"--dry-run",
				"--json",
			]);
			const report = JSON.parse(result.stdout) as {
				status: string;
				gates: Array<{ name: string; status: string; detail: string }>;
			};

			expect(result.exitCode, result.stdout).toBe(1);
			expect(report.status).toBe("fail");
			for (const gateName of [
				"proofBundle.fixtureResults",
				"proofBundle.networkProbeBundle",
				"proofBundle.rollbackEvidence",
				"proofBundle.complete",
			]) {
				expect(report.gates.find((gate) => gate.name === gateName)).toMatchObject({
					status: "pass",
				});
			}
			for (const gateName of ["fixtures.pass", "networkProbes.pass", "rollback.rehearsed"]) {
				expect(report.gates.find((gate) => gate.name === gateName)).toMatchObject({
					status: "fail",
				});
			}
		});
	});

	it("fails cutover when explicit queue snapshots underreport inventory queues", () => {
		const source = safeCutoverBundle();
		const queueSummary = pendingQueues({
			approvals: 1,
			backgroundJobs: 2,
		});
		const inventory = {
			...source.inventory,
			status: "complete" as const,
			summary: {
				pendingQueues: queueSummary,
			},
			queues: queueDetailsFromPending(queueSummary),
		};

		const report = evaluateCutoverCheck(
			safeCutoverBundle({
				inventory,
				queueSnapshot: queueSnapshotFromPending(pendingQueues()),
			}),
		);

		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "queues.owned")).toEqual(
			expect.objectContaining({
				status: "fail",
				detail: expect.stringContaining(
					"queue snapshot unownedActiveCount does not match inventory pendingQueues: expected 3, got 0",
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

	it("marks proof bundle fixture artifacts failed when fixture results are red", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-proof-fixtures-red-"));
		const bundle = safeCutoverBundle();
		const paths = writeCutoverProofSourceArtifacts(tempDir, bundle);
		writeJson(paths.fixtureResults, {
			...bundle.fixtureResults,
			results: [
				{
					...bundle.fixtureResults.results[0],
					status: "fail",
				},
				...bundle.fixtureResults.results.slice(1),
			],
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
	});

	it("marks proof bundle feature-probe artifacts failed when matrix status is red", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-proof-feature-red-"));
		const bundle = safeCutoverBundle();
		const paths = writeCutoverProofSourceArtifacts(tempDir, bundle);
		writeJson(paths.featureProbeMatrix, {
			...bundle.featureProbeMatrix,
			probes: [
				{
					...bundle.featureProbeMatrix.probes[0],
					status: "fail",
				},
				...bundle.featureProbeMatrix.probes.slice(1),
			],
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

		expect(proof.artifacts.featureProbeMatrix.status).toBe("fail");
	});

	it("fails cutover-check when proof bundle artifact status forges green over red evidence", () => {
		const noForkProof = writeNoForkProof({
			hermesCheckoutClean: false,
			statusPorcelain: " M src/index.ts",
			diffExitCode: 1,
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
					status: "fail",
					detail: "git status porcelain is not clean",
				},
				{
					name: "checkout.diffClean",
					status: "fail",
					detail: "git diff --quiet reported changes",
				},
				{
					name: "checkout.indexClean",
					status: "pass",
					detail: "git diff --cached --quiet is clean",
				},
			],
		});
		const bundle = safeCutoverBundle({ noForkProof });
		const cutoverProofBundle = structuredClone(bundle.cutoverProofBundle);
		expect(cutoverProofBundle.artifacts.noForkProof.status).toBe("fail");

		cutoverProofBundle.artifacts.noForkProof.status = "pass";
		const report = evaluateCutoverCheck({ ...bundle, cutoverProofBundle });

		expect(report.status).toBe("input_error");
		expect(report.exitCode).toBe(2);
		expect(report.gates.find((gate) => gate.name === "proofBundle.noForkProof.valid")).toEqual(
			expect.objectContaining({
				status: "fail",
				detail: expect.stringContaining("artifact status does not match on-disk semantic evidence"),
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

	it("passes live cutover when proof bundle and signed attestations are current", () => {
		vi.useFakeTimers();
		try {
			const now = new Date("2026-06-01T12:00:00.000Z");
			vi.setSystemTime(now);
			const report = evaluateCutoverCheck(safeCutoverBundle(), {
				liveCutover: true,
				now,
			});

			expect(report.status).toBe("safe");
			expect(report.exitCode).toBe(0);
		} finally {
			vi.useRealTimers();
		}
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
		const queueSummary = pendingQueues({
			approvals: 1,
			backgroundJobs: 2,
		});
		const inventory = {
			...source.inventory,
			status: "complete" as const,
			summary: {
				pendingQueues: queueSummary,
			},
			queues: queueDetailsFromPending(queueSummary),
		};
		const queueSnapshot = queueSnapshotFromPending(queueSummary);
		const proofSource = safeCutoverBundle({ inventory, queueSnapshot });
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
		expect(assembled.queueSnapshot).toEqual(queueSnapshot);
		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "queues.owned")?.status).toBe("fail");
	});

	it("blocks cutover on active pairing queues but not enabled webhooks", () => {
		const source = safeCutoverBundle();
		const pairingQueueSummary = pendingQueues({
			pairingPendingRequests: 1,
			pairingActiveLockouts: 2,
		});
		const pairingInventory = {
			...source.inventory,
			status: "complete" as const,
			summary: {
				pendingQueues: pairingQueueSummary,
			},
			queues: queueDetailsFromPending(pairingQueueSummary),
		};
		const pairingQueueSnapshot = queueSnapshotFromPending(pairingQueueSummary);
		const pairingProofSource = safeCutoverBundle({
			inventory: pairingInventory,
			queueSnapshot: pairingQueueSnapshot,
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

		expect(withPairingQueues.queueSnapshot).toEqual(pairingQueueSnapshot);
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
			queueSnapshot: buildHermesQueueSnapshot({ inventory: webhookInventory }),
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
		expect(webhookOnlyBundle.queueSnapshot).toEqual(
			buildHermesQueueSnapshot({ inventory: webhookInventory }),
		);
		expect(evaluateCutoverCheck(webhookOnlyBundle).status).toBe("safe");
	}, 20_000);

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
		const report = evaluateCutoverCheck(safeCutoverBundle());
		expect(report.exitCode).toBe(0);
		expect(report.mode.completeParityCutover).toBe(true);
		expect(report.gates.find((gate) => gate.name === "parity.rosterCovered")).toMatchObject({
			status: "pass",
		});

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

	it("fails production cutover when a missing parity row is not descoped", () => {
		const base = safeCutoverBundle();
		const bundle = safeCutoverBundle({
			decisionLog: {
				...base.decisionLog,
				decisions: base.decisionLog.decisions.filter(
					(decision) => decision.id !== "parity-descope:skills",
				),
			},
		});
		const report = evaluateCutoverCheck(bundle);
		expect(report.mode.completeParityCutover).toBe(true);
		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "parity.rosterCovered")).toMatchObject({
			status: "fail",
		});
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

			const report = evaluateCutoverCheck(safeCutoverBundle({ rollbackRehearsal: rehearsal }), {
				liveCutover: false,
			});

			expect(report.status).toBe("safe");
			expect(report.gates.find((gate) => gate.name === "rollback.rehearsed")).toMatchObject({
				status: "pass",
			});
		} finally {
			vi.useRealTimers();
		}
	});

	it("rejects archived rollback transcript proofs without the trusted relay public-key env", () => {
		const originalRelayPublicKey = process.env[HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV];
		const originalRelayPublicKeyLock = process.env[HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK_ENV];
		const rehearsal = writeRollbackRehearsal();
		const bundleWithStaleProof = safeCutoverBundle({ rollbackRehearsal: rehearsal });
		try {
			delete process.env[HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV];
			process.env[HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK_ENV] = path.join(
				os.tmpdir(),
				`missing-rollback-relay-key-${crypto.randomUUID()}.json`,
			);
			const bundle = refreshCutoverProofBundle(bundleWithStaleProof);
			const report = evaluateCutoverCheck(bundle);

			expect(report.status).toBe("fail");
			expect(report.gates.find((gate) => gate.name === "rollback.rehearsed")).toMatchObject({
				status: "fail",
				detail: expect.stringContaining(
					`trusted operator relay public key env ${HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV} is missing for live validation`,
				),
			});
		} finally {
			restoreEnv(HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV, originalRelayPublicKey);
			restoreEnv(HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK_ENV, originalRelayPublicKeyLock);
		}
	});

	it("rejects rollback transcript proofs signed by an embedded attacker relay key", () => {
		const rehearsal = writeRollbackRehearsal();
		const trustedRelayPrivateKey = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
		const trustedRelayPublicKey = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		if (!trustedRelayPublicKey) throw new Error("missing trusted relay public key");
		const attackerKeys = generateKeyPair();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = attackerKeys.privateKey;
		try {
			const attackerRelayPublicKey = {
				...rehearsal.relayPublicKey,
				value: attackerKeys.publicKey,
				sha256: `sha256:${crypto
					.createHash("sha256")
					.update(attackerKeys.publicKey)
					.digest("hex")}`,
				source: "attacker-fixture",
			};
			const forged = {
				...rehearsal,
				relayPublicKey: attackerRelayPublicKey,
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
					after: signedRelayTranscript(
						"/v1/hermes.private-runtime.status",
						"{}",
						legacyRuntimeState(),
					),
				},
			};
			writeJson(rehearsal.evidence_path, forged);

			const bundleWithStaleProof = safeCutoverBundle({ rollbackRehearsal: forged });
			process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = trustedRelayPublicKey;
			const bundle = refreshCutoverProofBundle(bundleWithStaleProof);
			const failed = evaluateCutoverCheck(bundle);

			expect(failed.status).toBe("fail");
			expect(failed.gates.find((gate) => gate.name === "rollback.rehearsed")?.detail).toContain(
				"rollback rehearsal evidence relay public key does not match trusted relay public key",
			);
		} finally {
			restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY", trustedRelayPrivateKey);
			restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", trustedRelayPublicKey);
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

		const bundleWithStaleProof = safeCutoverBundle({ rollbackRehearsal: tampered });
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = rehearsal.relayPublicKey.value;
		const bundle = refreshCutoverProofBundle(bundleWithStaleProof);
		const failed = evaluateCutoverCheck(bundle);

		expect(failed.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "rollback.rehearsed")?.detail).toContain(
			"rollback rehearsal evidence relay public key does not match trusted relay public key",
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
			"feature probe providers.approval-binding requires observed evidence",
		);
	});

	it("does not duplicate first-class memory and skills feature evidence in cutover-check", async () => {
		const result = await runScopedCutoverCheckWithBundle(
			cutoverBundleWithMemoryAndSkillsFeatureProbes(),
		);
		const report = JSON.parse(result.stdout) as {
			status: string;
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode, result.stdout).toBe(0);
		expect(report.status).toBe("safe");
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "pass",
		});
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")?.detail).not.toContain(
			"duplicate feature probe evidence",
		);
	});

	it("fails strict cutover when feature evidence repeats the same surface", () => {
		const bundle = cutoverBundleWithMemoryAndSkillsFeatureProbes();
		const duplicateEvidence = bundle.featureProbeEvidence.results.find(
			(result) => result.surface_id === "served_mcp.memory",
		);
		expect(duplicateEvidence).toBeDefined();
		bundle.featureProbeEvidence.results.push({ ...duplicateEvidence! });

		const report = evaluateCutoverCheck(bundle);

		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("duplicate feature probe evidence served_mcp.memory"),
		});
	});

	it("does not pass the feature-probe gate from cli-headless availability evidence alone", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-cli-"));
		const evidencePath = path.join(tempDir, "execution-cli-headless.json");
		writeJson(evidencePath, cliHeadlessEvidence());
		const bundle = cliHeadlessCutoverBundle(evidencePath);

		const result = await runCutoverCheckWithBundle(bundle);
		const report = JSON.parse(result.stdout) as {
			status: string;
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode, result.stdout).toBe(1);
		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("missing feature probe execution.headless_entrypoint"),
		});
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

		const result = await runScopedCutoverCheckWithBundle(
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
	}, 20_000);

	it("does not let model-relay pass from matrix and lockfile status alone", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-model-relay-matrix-only-"));
		const evidencePath = path.join(tempDir, "model-relay.json");
		const modelRelayProbe = {
			surface_id: "model.relay",
			hermes_pin: hermesPin,
			documented_seam: "Hermes model provider configuration is relay-owned",
			probe_command: "pnpm dev hermes probe model.relay --allow-run",
			expected_result: "Model traffic reaches only the Telclaude relay",
			negative_probe: "Direct model provider egress and writable profile overrides fail",
			evidence_path: evidencePath,
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
							evidence_path: evidencePath,
						},
					],
				},
			}),
		);

		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")?.detail).toContain(
			"feature probe model.relay evidence failed",
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

	it("passes runtime-required edge cutover gates from runtime harness evidence", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-edge-runtime-"));
		const evidence: Array<{ surfaceId: RuntimeRequiredEdgeSurfaceId; evidencePath: string }> = [];
		for (const surface of [
			"edge.whatsapp",
			"edge.email",
			"edge.agentmail",
			"edge.social",
			"identity.migration",
			"household.scopes",
			"attachment.quarantine",
			"outbound.policy",
			"public.social.isolation",
		] as const) {
			const evidencePath = path.join(tempDir, `${surface}.json`);
			const probeResult = await runHermesCommand([
				"hermes",
				"probe",
				surface,
				"--allow-run",
				"--json",
				"--out",
				evidencePath,
			]);
			expect(probeResult.exitCode, probeResult.stdout).toBe(0);
			evidence.push({ surfaceId: surface, evidencePath });
		}

		const result = await runScopedCutoverCheckWithBundle(
			edgeAdapterCutoverBundleFromEvidence(evidence),
		);
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode, result.stdout).toBe(0);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "pass",
		});
	});

	it("fails runtime-required edge cutover gates when runtime evidence is stripped", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-edge-runtime-"));
		const evidencePath = path.join(tempDir, "attachment-quarantine.json");
		const probeResult = await runHermesCommand([
			"hermes",
			"probe",
			"attachment.quarantine",
			"--allow-run",
			"--json",
			"--out",
			evidencePath,
		]);
		expect(probeResult.exitCode, probeResult.stdout).toBe(0);
		const evidence = readJson(evidencePath) as Record<string, unknown>;
		writeJson(evidencePath, {
			...evidence,
			source: "telclaude-edge-contract-unit",
			runtime: undefined,
		});

		const result = await runScopedCutoverCheckWithBundle(
			edgeAdapterCutoverBundle("attachment.quarantine", evidencePath),
		);
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode, result.stdout).toBe(1);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")?.detail).toContain(
			"runtime harness evidence is missing",
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
		const result = await runScopedCutoverCheckWithBundle(
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
		const result = await runScopedCutoverCheckWithBundle(
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

		const result = await runScopedCutoverCheckWithBundle(cliHeadlessCutoverBundle(evidencePath));
		const report = JSON.parse(result.stdout) as {
			mode: { completeParityCutover: boolean };
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode, result.stdout).toBe(1);
		expect(report.mode.completeParityCutover).toBe(false);
		expect(report.gates.find((gate) => gate.name === "parity.rosterCovered")).toBeUndefined();
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
			detail: `runtime relayResolvedAddress is 192.168.5.2, expected ${CLI_HEADLESS_TEST_RELAY_IP}`,
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
			name: "unsigned relay proof with null proof token",
			evidence: cliHeadlessEvidence({
				relayProof: cliHeadlessUnsignedRelayProofWithNullToken(),
			}),
			detail: "relayProof.signature",
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
				relayProof: cliHeadlessRelayProof({
					observedPeerAddress: CLI_HEADLESS_WRONG_CONTAINED_IP,
				}),
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
					args: ["chat", "-q", "telclaude probe ok"],
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
					tokenScoping: "peer-bound",
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
					tokenScoping: "peer-bound",
				},
			}),
			detail: "modelProvider.baseUrl is not a relay OpenAI Codex proxy URL",
		},
		{
			name: "missing relay model env keys",
			evidence: cliHeadlessEvidence({
				invocation: {
					command: "/usr/local/bin/hermes",
					args: ["chat", "-q", "telclaude probe ok"],
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
					args: ["chat", "-q", "telclaude probe ok"],
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
					tokenScoping: "peer-bound",
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
					tokenScoping: "peer-bound",
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

		const result = await runScopedCutoverCheckWithBundle(cliHeadlessCutoverBundle(evidencePath));
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
				featureProbeMatrix: base.featureProbeMatrix,
				featureProbeEvidence: base.featureProbeEvidence,
				noForkProof: base.noForkProof,
				profileGenerationProof: proof,
				decisionLog: {
					schemaVersion: 1,
					decisions: base.decisionLog.decisions.map((decision) =>
						decision.id === "D-profile-generation"
							? { ...decision, evidence_path: proof.evidence_path }
							: decision,
					),
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
		const configPath = path.join(proof.outDir, "profiles", "tc-private-default", "config.yaml");
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
			"profile output profiles/tc-private-default/config.yaml does not match canonical generator output",
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
		expect(hermesCommand?.commands.map((command) => command.name())).toContain("probes");
		expect(hermesCommand?.commands.map((command) => command.name())).toContain("network-probes");
		expect(hermesCommand?.commands.map((command) => command.name())).toContain("queue-snapshot");
		expect(hermesCommand?.commands.map((command) => command.name())).toContain("decision-log");
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
		expect(hermesCommand?.commands.map((command) => command.name())).toContain(
			"pro-review-refresh",
		);
		expect(hermesCommand?.commands.map((command) => command.name())).toContain(
			"pro-review-approve",
		);
		expect(hermesCommand?.commands.map((command) => command.name())).toContain("pro-review-check");
		expect(hermesCommand?.commands.map((command) => command.name())).toContain("pro-review-send");
	});

	it("refreshes the Pro review request payload binding and resets disclosure approval", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-refresh-"));
		await writeRequiredProReviewWorkspace(tempDir);
		await withCwd(tempDir, async () => {
			const requestPath = path.join(tempDir, "pro-review-request.json");
			const canaryPath = path.join(tempDir, "artifacts/hermes/pro-review-native-canary.json");
			writeJson(canaryPath, proReviewCanary());
			const staleRequest = proReviewRequest(canaryPath, {
				status: "approved",
				privateWorkspaceDisclosure: {
					...(proReviewRequest(canaryPath).privateWorkspaceDisclosure as Record<string, unknown>),
					approved: true,
					approvalId: "old-approval",
					operator: "aviv",
					approvedAt: "2026-06-01T08:00:00.000Z",
					payloadSha256: (proReviewRequest(canaryPath).payloadBinding as Record<string, unknown>)
						.payloadSha256,
				},
				selectedFiles: ["src/hermes/pro-review.ts"],
				payloadBinding: {
					...(proReviewRequest(canaryPath).payloadBinding as Record<string, unknown>),
					payloadSha256: `sha256:${"0".repeat(64)}`,
					selectedFilesSha256: `sha256:${"1".repeat(64)}`,
					selectedFileContentsSha256: `sha256:${"2".repeat(64)}`,
				},
			});
			writeJson(requestPath, staleRequest);

			const refresh = await runHermesCommand([
				"hermes",
				"pro-review-refresh",
				"--write",
				"--json",
				"--request",
				requestPath,
				"--canary",
				canaryPath,
			]);
			const refreshed = JSON.parse(refresh.stdout) as {
				status: string;
				written: boolean;
				payloadSha256: string;
				request: {
					status: string;
					reviewMode?: string;
					privateWorkspaceDisclosure: { approved: boolean; approvalId: string | null };
					selectedFiles: string[];
					payloadBinding: {
						payloadSha256: string;
						selectedFileContentsSha256: string;
					};
				};
			};

			expect(refresh.exitCode, refresh.stdout).toBe(0);
			expect(refreshed).toMatchObject({
				status: "pass",
				written: true,
				request: {
					status: "pending_operator_disclosure_approval",
					privateWorkspaceDisclosure: { approved: false, approvalId: null },
				},
			});
			expect(refreshed.request.selectedFiles).toEqual(
				expect.arrayContaining([...REQUIRED_PRO_REVIEW_FILES]),
			);
			expect(refreshed.request.reviewMode).toBe("single");
			expect(refreshed.request).not.toHaveProperty("shardPlan");
			expect(refreshed.payloadSha256).not.toBe(`sha256:${"0".repeat(64)}`);
			expect(refreshed.request.payloadBinding.selectedFileContentsSha256).not.toBe(
				`sha256:${"2".repeat(64)}`,
			);

			const check = await runHermesCommand([
				"hermes",
				"pro-review-check",
				"--json",
				"--request",
				requestPath,
				"--canary",
				canaryPath,
			]);
			const report = JSON.parse(check.stdout) as {
				status: string;
				gates: Array<{ name: string; status: string }>;
			};

			expect(check.exitCode, check.stdout).toBe(2);
			expect(report.status).toBe("pending");
			expect(report.gates.find((gate) => gate.name === "request.payloadBinding")).toMatchObject({
				status: "pass",
			});
			expect(report.gates.some((gate) => gate.name.startsWith("request.semanticEvidence."))).toBe(
				true,
			);
			expect(report.gates.find((gate) => gate.name === "disclosure.approved")).toMatchObject({
				status: "pending",
			});
		});
	});

	it("refuses Pro review refresh sharding options", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-refresh-"));
		await writeRequiredProReviewWorkspace(tempDir);
		await withCwd(tempDir, async () => {
			const requestPath = path.join(tempDir, "pro-review-request.json");
			const canaryPath = path.join(tempDir, "artifacts/hermes/pro-review-native-canary.json");
			writeJson(canaryPath, proReviewCanary());
			writeJson(requestPath, proReviewRequest(canaryPath));

			const result = await runHermesCommand([
				"hermes",
				"pro-review-refresh",
				"--write",
				"--json",
				"--request",
				requestPath,
				"--canary",
				canaryPath,
				"--shard-max-source-bytes",
				"500",
			]);
			const report = JSON.parse(result.stdout) as {
				status: string;
				detail: string;
			};

			expect(result.exitCode, result.stdout).toBe(1);
			expect(report).toMatchObject({
				status: "input_error",
				detail: expect.stringContaining("one complete full-context native bundle"),
			});
			expect(readJson(requestPath)).not.toMatchObject({ reviewMode: "sharded" });
		});
	});

	it("includes custom native canary evidence in refreshed Pro review selected files", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-canary-"));
		await writeRequiredProReviewWorkspace(tempDir);
		await withCwd(tempDir, async () => {
			const requestPath = path.join(tempDir, "pro-review-request.json");
			const canaryPath = path.join(tempDir, "artifacts/hermes/custom-native-canary.json");
			writeJson(canaryPath, proReviewCanary({ runId: "canary_custom" }));
			writeJson(requestPath, proReviewRequest(canaryPath));

			const result = await runHermesCommand([
				"hermes",
				"pro-review-refresh",
				"--write",
				"--json",
				"--request",
				requestPath,
				"--canary",
				canaryPath,
			]);
			const refreshed = JSON.parse(result.stdout) as {
				request: { selectedFiles: string[]; transportEvidence: string };
			};

			expect(result.exitCode, result.stdout).toBe(0);
			expect(refreshed.request.transportEvidence).toBe(canaryPath);
			expect(refreshed.request.selectedFiles).toContain(canaryPath);
		});
	});

	it("refreshes the ignored default Pro review request without the seed-write flag", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-refresh-"));
		await withCwd(tempDir, async () => {
			const requestPath = "docs/hermes/pro-review-request.json";
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			fs.writeFileSync(
				resolveTestPath(".gitignore"),
				"docs/hermes/*.json\n!docs/hermes/feature-probes.json\n",
				"utf8",
			);
			execFileSync("git", ["init", "-q"], { cwd: tempDir });
			writeJson(canaryPath, proReviewCanary());

			const result = await runHermesCommand([
				"hermes",
				"pro-review-refresh",
				"--write",
				"--json",
				"--request",
				requestPath,
				"--canary",
				canaryPath,
				"--prompt",
				"Review the attached Hermes wrapper files.",
			]);
			const report = JSON.parse(result.stdout) as { status: string; requestPath: string };

			expect(result.exitCode).toBe(0);
			expect(report).toMatchObject({ status: "pass", requestPath: resolveTestPath(requestPath) });
			expect(fs.existsSync(resolveTestPath(requestPath))).toBe(true);
			expect(
				execFileSync("git", ["check-ignore", requestPath], {
					cwd: tempDir,
					encoding: "utf8",
				}).trim(),
			).toBe(requestPath);
		});
	});

	it("refuses to refresh a tracked Pro review request that binds dirty selected files", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-refresh-"));
		await writeRequiredProReviewWorkspace(tempDir);
		await withCwd(tempDir, async () => {
			execFileSync("git", ["init", "-q"], { cwd: tempDir });
			execFileSync("git", ["config", "user.email", "hermes-wrapper-test@example.invalid"], {
				cwd: tempDir,
			});
			execFileSync("git", ["config", "user.name", "Hermes Wrapper Test"], { cwd: tempDir });
			const requestPath = "docs/hermes/pro-review-request.json";
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			writeJson(canaryPath, proReviewCanary());
			writeJson(requestPath, proReviewRequest(canaryPath));
			execFileSync("git", ["add", "."], { cwd: tempDir });
			execFileSync("git", ["commit", "-q", "-m", "fixture"], { cwd: tempDir });
			fs.appendFileSync(
				resolveTestPath("src/hermes/pro-review.ts"),
				"dirty selected file\n",
				"utf8",
			);

			const result = await runHermesCommand([
				"hermes",
				"pro-review-refresh",
				"--write",
				"--write-tracked-seed",
				"--json",
				"--request",
				requestPath,
				"--canary",
				canaryPath,
			]);
			const report = JSON.parse(result.stdout) as { status: string; detail: string };

			expect(result.exitCode).toBe(1);
			expect(report).toMatchObject({ status: "input_error" });
			expect(report.detail).toContain(
				"Refusing to write tracked Pro review request while selected tracked file(s) are dirty",
			);
			expect(report.detail).toContain("src/hermes/pro-review.ts");
		});
	});

	it("validates pending ChatGPT Pro native-extension review evidence without sending a bundle", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-"));
		await writeRequiredProReviewWorkspace(tempDir);
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
		await writeRequiredProReviewWorkspace(tempDir);
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

	it("records digest-bound Pro review disclosure approval through the CLI", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-approve-"));
		await writeRequiredProReviewWorkspace(tempDir, { semanticEvidence: "green" });
		await withCwd(tempDir, async () => {
			const requestPath = "docs/hermes/pro-review-request.json";
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			writeJson(canaryPath, proReviewCanary());
			const request = proReviewRequest(canaryPath);
			const payloadSha256 = (request.payloadBinding as Record<string, string>).payloadSha256;
			writeJson(requestPath, request);

			const approval = await runHermesCommand([
				"hermes",
				"pro-review-approve",
				"--write",
				"--json",
				"--request",
				requestPath,
				"--approval-id",
				"aviv-ofc-drive-it",
				"--operator",
				"aviv",
				"--approved-at",
				"2026-06-03T13:36:35.321Z",
				"--payload-sha256",
				payloadSha256,
			]);
			const approvalReport = JSON.parse(approval.stdout) as {
				status: string;
				written: boolean;
				approval: {
					approved: boolean;
					approvalId: string;
					operator: string;
					approvedAt: string;
					payloadSha256: string;
				};
			};

			expect(approval.exitCode, approval.stdout).toBe(0);
			expect(approvalReport).toMatchObject({
				status: "pass",
				written: true,
				approval: {
					approved: true,
					approvalId: "aviv-ofc-drive-it",
					operator: "aviv",
					approvedAt: "2026-06-03T13:36:35.321Z",
					payloadSha256,
				},
			});

			const saved = readJson(requestPath) as {
				status: string;
				privateWorkspaceDisclosure: {
					approved: boolean;
					approvalId: string;
					operator: string;
					approvedAt: string;
					payloadSha256: string;
				};
			};
			expect(saved).toMatchObject({
				status: "approved",
				privateWorkspaceDisclosure: {
					approved: true,
					approvalId: "aviv-ofc-drive-it",
					operator: "aviv",
					approvedAt: "2026-06-03T13:36:35.321Z",
					payloadSha256,
				},
			});
		});
	});

	it("refuses Pro review disclosure approval for a stale payload digest", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-approve-"));
		await writeRequiredProReviewWorkspace(tempDir);
		await withCwd(tempDir, async () => {
			const requestPath = "docs/hermes/pro-review-request.json";
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			writeJson(canaryPath, proReviewCanary());
			writeJson(requestPath, proReviewRequest(canaryPath));

			const result = await runHermesCommand([
				"hermes",
				"pro-review-approve",
				"--write",
				"--json",
				"--request",
				requestPath,
				"--approval-id",
				"stale-approval",
				"--operator",
				"aviv",
				"--payload-sha256",
				`sha256:${"0".repeat(64)}`,
			]);
			const report = JSON.parse(result.stdout) as { status: string; detail: string };
			const saved = readJson(requestPath) as {
				privateWorkspaceDisclosure: { approved: boolean };
			};

			expect(result.exitCode).toBe(1);
			expect(report).toMatchObject({ status: "input_error" });
			expect(report.detail).toContain("does not match request payload");
			expect(saved.privateWorkspaceDisclosure.approved).toBe(false);
		});
	});

	it("allows Pro review readiness to carry explicitly red cli_headless evidence", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-red-"));
		await writeRequiredProReviewWorkspace(tempDir);
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
		await writeRequiredProReviewWorkspace(tempDir);
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
				send: { status: string; reason: string; note: string; yoetzCommand?: string[] };
				report: { gates: Array<{ name: string; status: string }> };
			};

			expect(result.exitCode).toBe(1);
			expect(report.send).toMatchObject({
				status: "refused",
				reason: "pro-review-check did not pass with approval required",
			});
			expect(report.send.note).toContain("no Yoetz command is constructed");
			expect(report.send.yoetzCommand).toBeUndefined();
			expect(report.report.gates.find((gate) => gate.name === "disclosure.approved")).toMatchObject(
				{
					status: "fail",
				},
			);
		});
	});

	it("refuses approved Pro review send when selected evidence is explicitly red", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-send-red-"));
		await writeRequiredProReviewWorkspace(tempDir);
		await withCwd(tempDir, async () => {
			const requestPath = "docs/hermes/pro-review-request.json";
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			const bundlePath = "artifacts/hermes/prepared-pro-review.md";
			writeJson(canaryPath, proReviewCanary());
			writeJson(
				"artifacts/hermes/probes/execution-cli-headless.json",
				cliHeadlessReadinessFailureEvidence(),
			);
			const baseRequest = proReviewRequest(canaryPath);
			writeJson(
				requestPath,
				proReviewRequest(canaryPath, {
					status: "approved",
					privateWorkspaceDisclosure: {
						...(baseRequest.privateWorkspaceDisclosure as Record<string, unknown>),
						approved: true,
						approvalId: "approval-1",
						operator: "aviv",
						approvedAt: new Date().toISOString(),
						payloadSha256: (baseRequest.payloadBinding as Record<string, unknown>).payloadSha256,
					},
				}),
			);

			const result = await runHermesCommand([
				"hermes",
				"pro-review-send",
				"--json",
				"--request",
				requestPath,
				"--canary",
				canaryPath,
				"--bundle-out",
				bundlePath,
			]);
			const report = JSON.parse(result.stdout) as {
				send: { status: string; reason: string; yoetzCommand?: string[] };
				report: { gates: Array<{ name: string; status: string; detail: string }> };
			};

			expect(result.exitCode).toBe(1);
			expect(report.send.status).toBe("refused");
			expect(report.send.reason).toBe("pro-review-check did not pass with approval required");
			expect(report.send.yoetzCommand).toBeUndefined();
			expect(
				report.report.gates.find((gate) => gate.name === "request.cliHeadlessEvidence"),
			).toMatchObject({
				status: "fail",
				detail: expect.stringContaining("explicitly red and cannot be sent"),
			});
			expect(fs.existsSync(path.join(tempDir, bundlePath))).toBe(false);
		});
	});

	it("refuses Pro review send without constructing a native command when canary evidence is invalid", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-send-"));
		await writeRequiredProReviewWorkspace(tempDir);
		await withCwd(tempDir, async () => {
			const requestPath = "docs/hermes/pro-review-request.json";
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			writeJson(canaryPath, { schemaVersion: "wrong" });
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
				send: { status: string; reason: string; yoetzCommand?: string[]; canaryError?: string };
				report: { gates: Array<{ name: string; status: string }> };
			};

			expect(result.exitCode).toBe(1);
			expect(report.send.status).toBe("refused");
			expect(report.send.reason).toBe("pro-review-check did not pass with approval required");
			expect(report.send.yoetzCommand).toBeUndefined();
			expect(report.send.canaryError).toBeUndefined();
			expect(report.report.gates.find((gate) => gate.name === "nativeCanary.schema")).toMatchObject(
				{
					status: "fail",
				},
			);
		});
	});

	it("refuses Pro review send when selected files change after approval gate validation", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-send-race-"));
		await writeRequiredProReviewWorkspace(tempDir, { semanticEvidence: "green" });
		await withCwd(tempDir, async () => {
			const requestPath = path.join(tempDir, "docs/hermes/pro-review-request.json");
			const canaryPath = path.join(tempDir, "artifacts/hermes/pro-review-native-canary.json");
			const bundlePath = "artifacts/hermes/prepared-pro-review.md";
			const racedFilePath = path.join(tempDir, "CLAUDE.md");
			writeJson(canaryPath, proReviewCanary());
			writeJson(requestPath, proReviewRequest(canaryPath));
			const refresh = await runHermesCommand([
				"hermes",
				"pro-review-refresh",
				"--write",
				"--json",
				"--request",
				requestPath,
				"--canary",
				canaryPath,
			]);
			expect(refresh.exitCode, refresh.stdout).toBe(0);
			const refreshed = JSON.parse(refresh.stdout) as { payloadSha256: string };
			const approval = await runHermesCommand([
				"hermes",
				"pro-review-approve",
				"--write",
				"--json",
				"--request",
				requestPath,
				"--approval-id",
				"approval-1",
				"--operator",
				"aviv",
				"--approved-at",
				"2026-05-31T17:10:00Z",
				"--payload-sha256",
				refreshed.payloadSha256,
			]);
			expect(approval.exitCode, approval.stdout).toBe(0);

			const originalReadFileSync = fs.readFileSync.bind(fs);
			let requestReadCount = 0;
			const readSpy = vi.spyOn(fs, "readFileSync").mockImplementation(((
				file: fs.PathOrFileDescriptor,
				options?: Parameters<typeof fs.readFileSync>[1],
			) => {
				const result = originalReadFileSync(file, options);
				if (
					typeof file !== "number" &&
					path.resolve(String(file)) === requestPath &&
					++requestReadCount === 2
				) {
					fs.writeFileSync(racedFilePath, "tampered after approval gate\n", "utf8");
				}
				return result;
			}) as typeof fs.readFileSync);
			try {
				const result = await runHermesCommand([
					"hermes",
					"pro-review-send",
					"--json",
					"--request",
					requestPath,
					"--canary",
					canaryPath,
					"--bundle-out",
					bundlePath,
				]);
				const report = JSON.parse(result.stdout) as {
					send: {
						status: string;
						reason: string;
						detail: string;
						yoetzCommand?: string[];
					};
					report: { status: string; payloadSha256: string };
				};

				expect(result.exitCode, result.stdout).toBe(1);
				expect(report.report.status).toBe("pass");
				expect(report.report.payloadSha256).toBe(refreshed.payloadSha256);
				expect(report.send.status).toBe("refused");
				expect(report.send.reason).toBe(
					"approved Pro review payload changed before bundle construction",
				);
				expect(report.send.detail).toContain("no longer matches bundle snapshot payload");
				expect(report.send.yoetzCommand).toBeUndefined();
				expect(fs.existsSync(path.join(tempDir, bundlePath))).toBe(false);
			} finally {
				readSpy.mockRestore();
			}
		});
	});

	it("refuses executed Pro review sends with caller-controlled bundle output paths", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-send-path-"));
		await writeRequiredProReviewWorkspace(tempDir, { semanticEvidence: "green" });
		await withCwd(tempDir, async () => {
			const requestPath = path.join(tempDir, "docs/hermes/pro-review-request.json");
			const canaryPath = path.join(tempDir, "artifacts/hermes/pro-review-native-canary.json");
			const bundlePath = "artifacts/hermes/caller-controlled-pro-review.md";
			writeJson(canaryPath, proReviewCanary());
			writeJson(requestPath, proReviewRequest(canaryPath));
			const refresh = await runHermesCommand([
				"hermes",
				"pro-review-refresh",
				"--write",
				"--json",
				"--request",
				requestPath,
				"--canary",
				canaryPath,
			]);
			expect(refresh.exitCode, refresh.stdout).toBe(0);
			const refreshed = JSON.parse(refresh.stdout) as { payloadSha256: string };
			const approval = await runHermesCommand([
				"hermes",
				"pro-review-approve",
				"--write",
				"--json",
				"--request",
				requestPath,
				"--approval-id",
				"approval-1",
				"--operator",
				"aviv",
				"--approved-at",
				"2026-05-31T17:10:00Z",
				"--payload-sha256",
				refreshed.payloadSha256,
			]);
			expect(approval.exitCode, approval.stdout).toBe(0);

			const result = await runHermesCommand([
				"hermes",
				"pro-review-send",
				"--json",
				"--execute",
				"--request",
				requestPath,
				"--canary",
				canaryPath,
				"--bundle-out",
				bundlePath,
			]);
			const report = JSON.parse(result.stdout) as {
				send: { status: string; reason: string; yoetzCommand?: string[] };
			};

			expect(result.exitCode, result.stdout).toBe(1);
			expect(report.send.status).toBe("refused");
			expect(report.send.reason).toContain("--bundle-out is disabled with --execute");
			expect(report.send.yoetzCommand).toBeUndefined();
			expect(fs.existsSync(path.join(tempDir, bundlePath))).toBe(false);
		});
	});

	it("prepares Pro review send only through the canary-bound native extension instance", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-send-"));
		await writeRequiredProReviewWorkspace(tempDir, { semanticEvidence: "green" });
		await withCwd(tempDir, async () => {
			const requestPath = path.join(tempDir, "docs/hermes/pro-review-request.json");
			const canaryPath = path.join(tempDir, "artifacts/hermes/pro-review-native-canary.json");
			const bundlePath = "artifacts/hermes/prepared-pro-review.md";
			writeJson(canaryPath, proReviewCanary());
			writeJson(requestPath, proReviewRequest(canaryPath));
			const refresh = await runHermesCommand([
				"hermes",
				"pro-review-refresh",
				"--write",
				"--json",
				"--request",
				requestPath,
				"--canary",
				canaryPath,
			]);
			expect(refresh.exitCode, refresh.stdout).toBe(0);
			const refreshed = JSON.parse(refresh.stdout) as { payloadSha256: string };
			const approval = await runHermesCommand([
				"hermes",
				"pro-review-approve",
				"--write",
				"--json",
				"--request",
				requestPath,
				"--approval-id",
				"approval-1",
				"--operator",
				"aviv",
				"--approved-at",
				"2026-05-31T17:10:00Z",
				"--payload-sha256",
				refreshed.payloadSha256,
			]);
			expect(approval.exitCode, approval.stdout).toBe(0);

			const result = await runHermesCommand([
				"hermes",
				"pro-review-send",
				"--json",
				"--request",
				requestPath,
				"--canary",
				canaryPath,
				"--bundle-out",
				bundlePath,
				"--conversation",
				"https://chatgpt.com/c/retry-conversation",
				"--wait-timeout-ms",
				"120000",
			]);
			const report = JSON.parse(result.stdout) as {
				send: {
					status: string;
					bundlePath: string;
					payloadSha256: string;
					bundleSha256: string;
					runId: string;
					conversation?: string;
					inspectCommand: string[];
					yoetzCommand: string[];
				};
			};

			expect(result.exitCode, result.stdout).toBe(0);
			expect(report.send.status).toBe("ready");
			expect(report.send.payloadSha256).toBe(refreshed.payloadSha256);
			expect(report.send.bundleSha256).toBe(
				`sha256:${crypto
					.createHash("sha256")
					.update(fs.readFileSync(path.join(tempDir, bundlePath)))
					.digest("hex")}`,
			);
			expect(report.send.yoetzCommand).toEqual(
				expect.arrayContaining([
					"--transport",
					"chrome-extension-native",
					"--var",
					"extension_instance_id=ext_test",
					"--var",
					`payload_sha256=${report.send.payloadSha256}`,
					"--var",
					`bundle_sha256=${report.send.bundleSha256}`,
					"--var",
					`run_id=${report.send.runId}`,
					"--var",
					"wait_timeout_ms=120000",
				]),
			);
			expect(report.send.runId).toMatch(/^hermes_\d{14}_[a-f0-9]{8}$/);
			expect(report.send.conversation).toBe("https://chatgpt.com/c/retry-conversation");
			expect(report.send.inspectCommand).toEqual([
				"yoetz",
				"browser",
				"extension",
				"inspect",
				"--chatgpt",
				"--run-id",
				report.send.runId,
				"--extension-instance-id",
				"ext_test",
				"--format",
				"json",
			]);
			expect(report.send.yoetzCommand).not.toContain("--allow-cdp-fallback");
			expect(report.send.yoetzCommand).not.toContain("--cdp");
			expect(report.send.yoetzCommand).toEqual(
				expect.arrayContaining(["--var", "conversation=https://chatgpt.com/c/retry-conversation"]),
			);
			expect(fs.statSync(path.join(tempDir, bundlePath)).mode & 0o777).toBe(0o600);
		});
	});

	it("recovers single Pro review sends from completed native inspect output", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-send-recover-"));
		await writeRequiredProReviewWorkspace(tempDir, { semanticEvidence: "green" });
		await withCwd(tempDir, async () => {
			const requestPath = path.join(tempDir, "docs/hermes/pro-review-request.json");
			const canaryPath = path.join(tempDir, "artifacts/hermes/pro-review-native-canary.json");
			writeJson(canaryPath, proReviewCanary());
			writeJson(requestPath, proReviewRequest(canaryPath));
			const refresh = await runHermesCommand([
				"hermes",
				"pro-review-refresh",
				"--write",
				"--json",
				"--request",
				requestPath,
				"--canary",
				canaryPath,
			]);
			expect(refresh.exitCode, refresh.stdout).toBe(0);
			const refreshed = JSON.parse(refresh.stdout) as { payloadSha256: string };
			const approval = await runHermesCommand([
				"hermes",
				"pro-review-approve",
				"--write",
				"--json",
				"--request",
				requestPath,
				"--approval-id",
				"approval-1",
				"--operator",
				"aviv",
				"--approved-at",
				"2026-05-31T17:10:00Z",
				"--payload-sha256",
				refreshed.payloadSha256,
			]);
			expect(approval.exitCode, approval.stdout).toBe(0);
			const fakeYoetzBin = writeRecoverableYoetzNativeReadFailureBin(
				tempDir,
				"chrome-extension-native: ChatGPT wait_response phase failed after browser side effects; automatic transport fallback is disabled: ChatGPT response did not reach stable completion before timeout",
			);

			const result = await runHermesCommandWithEnv(
				[
					"hermes",
					"pro-review-send",
					"--json",
					"--execute",
					"--request",
					requestPath,
					"--canary",
					canaryPath,
				],
				{ PATH: `${fakeYoetzBin}${path.delimiter}${process.env.PATH ?? ""}` },
			);
			const report = JSON.parse(result.stdout) as {
				send: {
					status: string;
					bundlePath: string;
					exitCode: number;
					payloadSha256: string;
					validation: { status: string; detail: string };
					inspect: { exitCode: number; validation: { status: string } };
				};
			};

			expect(result.exitCode, result.stdout).toBe(0);
			expect(report.send.status).toBe("sent");
			expect(report.send.bundlePath).toContain("telclaude-hermes-pro-review-send-");
			expect(fs.statSync(report.send.bundlePath).mode & 0o777).toBe(0o400);
			expect(report.send.exitCode).toBe(1);
			expect(report.send.payloadSha256).toBe(refreshed.payloadSha256);
			expect(report.send.validation).toMatchObject({
				status: "pass",
				detail: expect.stringContaining("recovered a completed Extended Pro response"),
			});
			expect(report.send.inspect).toMatchObject({
				exitCode: 0,
				validation: { status: "pass" },
			});
		});
	});

	it("refuses stale sharded Pro review requests without preparing shard artifacts", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-sharded-"));
		await writeRequiredProReviewWorkspace(tempDir, { semanticEvidence: "green" });
		await withCwd(tempDir, async () => {
			const requestPath = path.join(tempDir, "docs/hermes/pro-review-request.json");
			const canaryPath = path.join(tempDir, "artifacts/hermes/pro-review-native-canary.json");
			const bundlePath = "artifacts/hermes/prepared-pro-review.md";
			writeJson(canaryPath, proReviewCanary());
			writeJson(requestPath, proReviewRequest(canaryPath));
			const shardedRequest = legacyShardedProReviewRequest(canaryPath);
			writeJson(requestPath, shardedRequest);
			const approval = await runHermesCommand([
				"hermes",
				"pro-review-approve",
				"--write",
				"--json",
				"--request",
				requestPath,
				"--approval-id",
				"approval-1",
				"--operator",
				"aviv",
				"--approved-at",
				"2026-05-31T17:10:00Z",
				"--payload-sha256",
				shardedRequest.payloadBinding.payloadSha256,
			]);
			expect(approval.exitCode, approval.stdout).toBe(0);

			const result = await runHermesCommand([
				"hermes",
				"pro-review-send",
				"--json",
				"--request",
				requestPath,
				"--canary",
				canaryPath,
				"--bundle-out",
				bundlePath,
				"--wait-timeout-ms",
				"120000",
			]);
			const report = JSON.parse(result.stdout) as {
				report: {
					payloadSha256: string;
					gates: Array<{ name: string; status: string; detail: string }>;
				};
				send: {
					status: string;
					reason: string;
				};
			};

			expect(result.exitCode, result.stdout).toBe(1);
			expect(report.send.status).toBe("refused");
			expect(report.send.reason).toContain("pro-review-check did not pass");
			expect(report.report.payloadSha256).toBe(shardedRequest.payloadBinding.payloadSha256);
			expect(report.report.gates.find((gate) => gate.name === "request.shardPlan")).toMatchObject({
				status: "fail",
				detail: expect.stringContaining("one complete full-context native bundle"),
			});
			expect(fs.existsSync(path.join(tempDir, bundlePath))).toBe(false);
			const artifactNames = fs.readdirSync(path.join(tempDir, "artifacts/hermes"));
			expect(artifactNames.filter((name) => name.includes(".shard-"))).toEqual([]);
		});
	});

	it("fails Pro review evidence when a required selected file is missing", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-required-"));
		await writeRequiredProReviewWorkspace(tempDir);
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
		const originalPrivateKey = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
		const originalPublicKey = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		const relayKeys = generateKeyPair();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;

		try {
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
				const evidence = readJson(fixture.evidence_path);
				expect(evidence).toMatchObject({
					id: fixture.id,
					status: "pass",
					provenance: { runner: "vitest-json", source: "machine-observed-test-report" },
					invocation: { exitCode: 0, reportPath: testReportPath },
					privateTelegramRunnerAttestation: {
						fixtureId: fixture.id,
						status: "pass",
						provenanceRunner: "vitest-json",
						provenanceSource: "machine-observed-test-report",
						testReportPath,
						testReportSha256: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
						invocationReportPath: testReportPath,
						invocationReportSha256: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
						invocationSha256: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
						requiredTestsSha256: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
						requiredAssertionsSha256: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
						checksSha256: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
						evidenceSha256: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
						signature: expect.objectContaining({
							scope: "operator",
							signature: expect.any(String),
						}),
					},
				});
			}
			const fixturesGate = evaluateCutoverCheck(
				safeCutoverBundle({ fixtureResults: writeSafeParityFixtures(tempDir, bundle) }),
			).gates.find((gate) => gate.name === "fixtures.pass");
			expect(fixturesGate, JSON.stringify(fixturesGate)).toMatchObject({ status: "pass" });
		} finally {
			restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY", originalPrivateKey);
			restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", originalPublicKey);
		}
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

	it("refuses to run writable private Telegram fixtures without the operator relay signing key", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-fixtures-unsigned-"));
		const testReportPath = path.join(tempDir, "private-telegram-vitest.json");
		const outPath = path.join(tempDir, "fixture-results.json");
		const evidenceDir = path.join(tempDir, "evidence");
		const originalPrivateKey = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;

		try {
			delete process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
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
			]);
			const report = JSON.parse(result.stdout) as { status: string; detail?: string };

			expect(result.exitCode).toBe(1);
			expect(report.status).toBe("input_error");
			expect(report.detail).toBe(
				"Missing relay response signing key for operator. Set OPERATOR_RPC_RELAY_PRIVATE_KEY.",
			);
			expect(fs.existsSync(testReportPath)).toBe(false);
			expect(fs.existsSync(outPath)).toBe(false);
			expect(fs.existsSync(evidenceDir)).toBe(false);
		} finally {
			restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY", originalPrivateKey);
		}
	});

	it("refuses to run writable private Telegram fixtures without the operator relay verification key", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-fixtures-unverified-"));
		const testReportPath = path.join(tempDir, "private-telegram-vitest.json");
		const outPath = path.join(tempDir, "fixture-results.json");
		const evidenceDir = path.join(tempDir, "evidence");
		const originalPrivateKey = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
		const originalPublicKey = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		const relayKeys = generateKeyPair();

		try {
			process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
			delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
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
			]);
			const report = JSON.parse(result.stdout) as { status: string; detail?: string };

			expect(result.exitCode).toBe(1);
			expect(report.status).toBe("input_error");
			expect(report.detail).toBe(
				"Missing relay response verification key for operator. Set OPERATOR_RPC_RELAY_PUBLIC_KEY.",
			);
			expect(fs.existsSync(testReportPath)).toBe(false);
			expect(fs.existsSync(outPath)).toBe(false);
			expect(fs.existsSync(evidenceDir)).toBe(false);
		} finally {
			restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY", originalPrivateKey);
			restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", originalPublicKey);
		}
	});

	it("refuses to run writable private Telegram fixtures with mismatched operator relay signing keys", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-fixtures-bad-keypair-"));
		const testReportPath = path.join(tempDir, "private-telegram-vitest.json");
		const outPath = path.join(tempDir, "fixture-results.json");
		const evidenceDir = path.join(tempDir, "evidence");
		const originalPrivateKey = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
		const originalPublicKey = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		const privateKeys = generateKeyPair();
		const publicKeys = generateKeyPair();

		try {
			process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = privateKeys.privateKey;
			process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = publicKeys.publicKey;
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
			]);
			const report = JSON.parse(result.stdout) as { status: string; detail?: string };

			expect(result.exitCode).toBe(1);
			expect(report.status).toBe("input_error");
			expect(report.detail).toContain("Operator relay signing keys failed round-trip verification");
			expect(report.detail).toContain("signature verification failed");
			expect(fs.existsSync(testReportPath)).toBe(false);
			expect(fs.existsSync(outPath)).toBe(false);
			expect(fs.existsSync(evidenceDir)).toBe(false);
		} finally {
			restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY", originalPrivateKey);
			restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", originalPublicKey);
		}
	});

	it("can preserve existing fixtures while skipping private Telegram without signing keys", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-fixtures-skip-private-"));
		const outPath = path.join(tempDir, "fixture-results.json");
		const evidenceDir = path.join(tempDir, "evidence");
		const reportOut = path.join(tempDir, "private-telegram-vitest.json");
		const originalPrivateKey = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
		const originalPublicKey = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		writeJson(outPath, {
			schemaVersion: 1,
			results: [
				{
					id: "fixture.private.telegram.basic",
					status: "pass",
					evidence_path: "artifacts/hermes/fixtures/fixture.private.telegram.basic.json",
				},
			],
		});

		try {
			delete process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
			delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
			const result = await runHermesCommand([
				"hermes",
				"fixtures",
				"--write",
				"--json",
				"--merge-existing",
				"--skip-private-telegram",
				"--report-out",
				reportOut,
				"--out",
				outPath,
				"--evidence-dir",
				evidenceDir,
			]);
			const report = JSON.parse(result.stdout) as {
				status: string;
				results: Array<{ id: string; status: string; evidence_path: string }>;
			};
			const written = readJson(outPath) as { results: Array<{ id: string; status: string }> };

			expect(result.exitCode, result.stdout).toBe(0);
			expect(report.status).toBe("pass");
			expect(report.results).toEqual(written.results);
			expect(report.results).toEqual([
				expect.objectContaining({ id: "fixture.private.telegram.basic", status: "pass" }),
			]);
			expect(fs.existsSync(reportOut)).toBe(false);
			expect(fs.existsSync(evidenceDir)).toBe(false);
		} finally {
			restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY", originalPrivateKey);
			restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", originalPublicKey);
		}
	});

	it("refuses skip-private fixture writes without an existing output bundle", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-fixtures-skip-private-missing-"));
		const outPath = path.join(tempDir, "fixture-results.json");
		const evidenceDir = path.join(tempDir, "evidence");
		const originalPrivateKey = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
		const originalPublicKey = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;

		try {
			delete process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
			delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
			const result = await runHermesCommand([
				"hermes",
				"fixtures",
				"--write",
				"--json",
				"--merge-existing",
				"--skip-private-telegram",
				"--out",
				outPath,
				"--evidence-dir",
				evidenceDir,
			]);
			const report = JSON.parse(result.stdout) as { status: string; detail?: string };

			expect(result.exitCode).toBe(1);
			expect(report).toMatchObject({
				status: "input_error",
				detail: "--skip-private-telegram writes require an existing --out fixture results bundle.",
			});
			expect(fs.existsSync(outPath)).toBe(false);
			expect(fs.existsSync(evidenceDir)).toBe(false);
		} finally {
			restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY", originalPrivateKey);
			restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", originalPublicKey);
		}
	});

	it("refreshes provider fixtures independently of private Telegram fixture execution", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-fixtures-provider-only-"));
		const outPath = path.join(tempDir, "fixture-results.json");
		const reportOut = path.join(tempDir, "private-telegram-vitest.json");
		const originalPrivateKey = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
		const originalPublicKey = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		writeJson(outPath, {
			schemaVersion: 1,
			results: [
				{
					id: "fixture.private.telegram.basic",
					status: "pass",
					evidence_path: "artifacts/hermes/fixtures/fixture.private.telegram.basic.json",
				},
			],
		});
		await writeProviderFixtureProbeInputs(tempDir);

		try {
			delete process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
			delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
			await withActualCwd(tempDir, async () => {
				const result = await runHermesCommand([
					"hermes",
					"fixtures",
					"--json",
					"--merge-existing",
					"--only-provider-domain",
					"--report-out",
					reportOut,
					"--out",
					outPath,
					"--evidence-dir",
					path.join(tempDir, "evidence"),
				]);
				const report = JSON.parse(result.stdout) as {
					status: string;
					results: Array<{ id: string; status: string; evidence_path: string }>;
				};

				expect(result.exitCode).toBe(1);
				expect(report.status).toBe("fail");
				expect(report.results).toEqual(
					expect.arrayContaining([
						expect.objectContaining({ id: "fixture.private.telegram.basic", status: "pass" }),
						expect.objectContaining({ id: "fixture.providers.bank.read", status: "pass" }),
						expect.objectContaining({
							id: "fixture.providers.bank.direct-provider-deny",
							status: "fail",
						}),
						expect.objectContaining({
							id: "fixture.providers.google.direct-provider-deny",
							status: "fail",
						}),
					]),
				);
				expect(result.stdout).not.toContain("Missing relay response signing key");
				expect(fs.existsSync(reportOut)).toBe(false);
			});
		} finally {
			restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY", originalPrivateKey);
			restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", originalPublicKey);
		}
	});

	it("binds provider direct-deny fixtures to an explicit network probe artifact", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-fixtures-provider-network-"));
		const outPath = path.join(tempDir, "fixture-results.json");
		const reportOut = path.join(tempDir, "private-telegram-vitest.json");
		const evidenceDir = path.join(tempDir, "evidence");
		const networkProbePath = path.join(tempDir, "network", "direct-provider-denied.json");
		const originalPrivateKey = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
		const originalPublicKey = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		ensureOperatorRelayKeys();
		writeJson(outPath, {
			schemaVersion: 1,
			results: [
				{
					id: "fixture.private.telegram.basic",
					status: "pass",
					evidence_path: "artifacts/hermes/fixtures/fixture.private.telegram.basic.json",
				},
			],
		});
		await writeProviderFixtureProbeInputs(tempDir);
		writeJson(
			networkProbePath,
			passingNetworkProbeEvidence("network.direct-provider-denied", networkProbePath),
		);

		try {
			await withActualCwd(tempDir, async () => {
				const result = await runHermesCommand([
					"hermes",
					"fixtures",
					"--write",
					"--json",
					"--merge-existing",
					"--only-provider-domain",
					"--provider-network-probe",
					networkProbePath,
					"--report-out",
					reportOut,
					"--out",
					outPath,
					"--evidence-dir",
					evidenceDir,
				]);
				const report = JSON.parse(result.stdout) as {
					status: string;
					results: Array<{ id: string; status: string; evidence_path: string }>;
				};

				expect(result.exitCode, result.stdout).toBe(0);
				expect(report.status).toBe("pass");
				expect(report.results).toEqual(
					expect.arrayContaining([
						expect.objectContaining({
							id: "fixture.providers.bank.direct-provider-deny",
							status: "pass",
						}),
						expect.objectContaining({
							id: "fixture.providers.google.direct-provider-deny",
							status: "pass",
						}),
					]),
				);
				for (const fixtureId of [
					"fixture.providers.bank.direct-provider-deny",
					"fixture.providers.google.direct-provider-deny",
				]) {
					const fixture = report.results.find((candidate) => candidate.id === fixtureId);
					if (!fixture) throw new Error(`missing ${fixtureId}`);
					const evidence = readJson(fixture.evidence_path) as {
						networkDeny?: { probePath?: string };
					};
					expect(evidence.networkDeny?.probePath).toBe(networkProbePath);
				}
				expect(fs.existsSync(reportOut)).toBe(false);
			});
		} finally {
			restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY", originalPrivateKey);
			restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", originalPublicKey);
		}
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

	it("does not write unsigned no-fork proof evidence when prove --p0 input validation fails", async () => {
		ensureOperatorRelayKeys();
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-prove-p0-input-"));
		const evidencePath = path.join(tempDir, "no-fork.json");

		const result = await runHermesCommand([
			"hermes",
			"prove",
			"--upstream-clean",
			"--p0",
			"--json",
			"--checkout",
			tempDir,
			"--out",
			evidencePath,
			"--feature-probes",
			path.join(tempDir, "missing-feature-probes.json"),
		]);
		const report = JSON.parse(result.stdout) as {
			p0: { status: string; gates: Array<{ name: string; status: string; detail: string }> };
			noForkProof: { evidence_path: string; runnerAttestation?: unknown };
		};

		expect(result.exitCode).toBe(2);
		expect(report.p0.status).toBe("input_error");
		expect(report.p0.gates[0]).toMatchObject({ name: "inputs.readable", status: "fail" });
		expect(report.noForkProof.evidence_path).toBe(evidencePath);
		expect(report.noForkProof.runnerAttestation).toBeUndefined();
		expect(fs.existsSync(evidencePath)).toBe(false);
	});

	it("refuses prove --p0 without operator relay signing keys before reading P0 inputs", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-prove-p0-no-key-"));
		const evidencePath = path.join(tempDir, "no-fork.json");
		const originalPrivateKey = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
		const originalPublicKey = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;

		try {
			delete process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
			delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
			const result = await runHermesCommand([
				"hermes",
				"prove",
				"--upstream-clean",
				"--p0",
				"--json",
				"--checkout",
				tempDir,
				"--out",
				evidencePath,
				"--feature-probes",
				path.join(tempDir, "missing-feature-probes.json"),
			]);
			const report = JSON.parse(result.stdout) as {
				p0: { status: string; gates: Array<{ name: string; status: string; detail: string }> };
				noForkProof: { evidence_path: string; runnerAttestation?: unknown };
			};

			expect(result.exitCode).toBe(2);
			expect(report.p0).toMatchObject({ status: "input_error" });
			expect(report.p0.gates[0]).toMatchObject({
				name: "inputs.operatorRelaySigning",
				status: "fail",
				detail:
					"Missing relay response signing key for operator. Set OPERATOR_RPC_RELAY_PRIVATE_KEY.",
			});
			expect(report.noForkProof.evidence_path).toBe(evidencePath);
			expect(report.noForkProof.runnerAttestation).toBeUndefined();
			expect(fs.existsSync(evidencePath)).toBe(false);
		} finally {
			restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY", originalPrivateKey);
			restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", originalPublicKey);
		}
	});

	it("does not classify a dirty checkout no-fork failure as a P0 bootstrap failure", () => {
		const status = deriveNoForkP0Status({
			gates: [
				{
					name: "nofork.clean",
					status: "fail",
					detail:
						"no-fork proof summary hermesCheckoutClean is false; no-fork evidence hermesCheckoutClean is false",
				},
			],
		} as ReturnType<typeof evaluateCutoverCheck>);

		expect(status).toBe("fail");
	});

	it("classifies no-fork runner attestation summary failures as P0 bootstrap failures", () => {
		const status = deriveNoForkP0Status({
			gates: [
				{
					name: "nofork.clean",
					status: "fail",
					detail:
						"no-fork proof summary hermesCheckoutClean is false; no-fork evidence hermesCheckoutClean is false; no-fork evidence runnerAttestation is missing; no-fork evidence required check runner.attestation is fail: no-fork wrapper run attestation is missing; no-fork evidence required check runner.p0 is fail: P0 fixture/cutover command did not pass",
				},
			],
		} as ReturnType<typeof evaluateCutoverCheck>);

		expect(status).toBe("pass");
	});

	it("does not classify signed no-fork runner invariant failures as P0 bootstrap", () => {
		const status = deriveNoForkP0Status({
			gates: [
				{
					name: "nofork.clean",
					status: "fail",
					detail:
						"no-fork proof summary hermesCheckoutClean is false; no-fork evidence hermesCheckoutClean is false; no-fork evidence required check runner.noMonkeypatch is fail: monkeypatch denial was not observed; no-fork evidence check runner.noMonkeypatch is fail: monkeypatch denial was not observed",
				},
			],
		} as ReturnType<typeof evaluateCutoverCheck>);

		expect(status).toBe("fail");
	});

	it("evaluates P0 cutover gates when prove is run with --p0", async () => {
		ensureOperatorRelayKeys();
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-prove-p0-"));
		const base = safeCutoverBundle();
		const paths = writeCutoverBundleArtifacts(
			tempDir,
			safeCutoverBundle({
				...freshCutoverTimingOverrides(base),
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

	it("writes signed runner attestation when prove --p0 runs from a pinned clean checkout", async () => {
		ensureOperatorRelayKeys();
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-prove-p0-clean-"));
		const checkoutPathRaw = path.join(tempDir, "upstream");
		initPinnedHermesCheckout(checkoutPathRaw);
		const checkoutPath = fs.realpathSync(checkoutPathRaw);
		const noForkPath = path.join(tempDir, "nofork.json");
		const noForkProof = writeNoForkProof({ evidence_path: noForkPath });
		const base = safeCutoverBundle();
		const lockfile = {
			...base.lockfile,
			noForkProofEvidencePath: noForkProof.evidence_path,
		};
		const paths = writeCutoverBundleArtifacts(
			tempDir,
			safeCutoverBundle({
				lockfile,
				featureProbeMatrix: base.featureProbeMatrix,
				featureProbeEvidence: base.featureProbeEvidence,
				noForkProof,
				...freshCutoverTimingOverrides(base),
			}),
		);

		const result = await runHermesCommand([
			"hermes",
			"prove",
			"--upstream-clean",
			"--p0",
			"--json",
			"--checkout",
			checkoutPath,
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
			noForkProof: {
				hermesCheckoutClean: boolean;
				runnerAttestation?: {
					checkoutPath: string;
					p0Command: string[];
					p0ExitCode: number;
					p0Status: string;
					signature?: { path: string };
				};
			};
			p0: { status: string; gates: Array<{ name: string; status: string }> };
		};
		const artifact = readJson(paths.nofork) as typeof report.noForkProof;

		expect(result.exitCode, result.stdout).toBe(0);
		expect(report.noForkProof.hermesCheckoutClean).toBe(true);
		expect(report.noForkProof.runnerAttestation).toMatchObject({
			checkoutPath,
			p0ExitCode: 0,
			p0Status: "pass",
			signature: { path: "/v1/hermes.no-fork.runner-attestation" },
		});
		expect(report.noForkProof.runnerAttestation?.p0Command).toContain("--p0");
		expect(artifact.runnerAttestation).toMatchObject(report.noForkProof.runnerAttestation ?? {});
		expect(report.p0.status).toBe("safe");
		expect(report.p0.gates.find((gate) => gate.name === "nofork.clean")).toMatchObject({
			status: "pass",
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

	it("refuses rollback rehearsal without operator relay verification key before relay I/O", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-rollback-no-key-"));
		const outPath = path.join(tempDir, "rollback.json");
		const originalUrl = process.env.TELCLAUDE_CAPABILITIES_URL;
		const originalOperatorPrivate = process.env.OPERATOR_RPC_AGENT_PRIVATE_KEY;
		const originalOperatorPublic = process.env.OPERATOR_RPC_AGENT_PUBLIC_KEY;
		const originalOperatorRelayPublic = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		const keys = generateKeyPair();
		let requestCount = 0;
		shutdownTokenClient();
		const relay = await startProbeServer((_req, res) => {
			requestCount += 1;
			res.setHeader("Content-Type", "application/json");
			res.end(JSON.stringify(legacyRuntimeState()));
		});
		process.env.OPERATOR_RPC_AGENT_PRIVATE_KEY = keys.privateKey;
		process.env.OPERATOR_RPC_AGENT_PUBLIC_KEY = keys.publicKey;
		process.env.TELCLAUDE_CAPABILITIES_URL = new URL(relay.url).origin;

		try {
			delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
			const result = await runHermesCommand([
				"hermes",
				"rollback-rehearsal",
				"--allow-run",
				"--json",
				"--out",
				outPath,
			]);
			const report = JSON.parse(result.stdout) as {
				passed: boolean;
				written: boolean;
				checks: Array<{ name: string; status: string; detail: string }>;
			};

			expect(result.exitCode).toBe(1);
			expect(report).toMatchObject({ passed: false, written: false });
			expect(report.checks[0]).toMatchObject({
				name: "rollback.controlSurface",
				status: "fail",
				detail:
					"Missing relay response verification key for operator. Set OPERATOR_RPC_RELAY_PUBLIC_KEY.",
			});
			expect(requestCount).toBe(0);
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

	it("writes rollback rehearsal evidence by driving the relay capability surface", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-rollback-cli-"));
		const outPath = path.join(tempDir, "rollback.json");
		const originalUrl = process.env.TELCLAUDE_CAPABILITIES_URL;
		const originalOperatorPrivate = process.env.OPERATOR_RPC_AGENT_PRIVATE_KEY;
		const originalOperatorPublic = process.env.OPERATOR_RPC_AGENT_PUBLIC_KEY;
		const originalOperatorRelayPrivate = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
		const originalOperatorRelayPublic = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		const originalOperatorRelayPublicKeyLock =
			process.env[HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK_ENV];
		const keys = generateKeyPair();
		const relayKeys = generateKeyPair();
		const relayPublicKeySha256 = computeTextDigest(relayKeys.publicKey);
		const relayPublicKeySourcePath = path.join(tempDir, "rollback-relay-public-key-source.json");
		const relayPublicKeyLockPath = path.join(tempDir, "rollback-relay-public-key.lock.json");
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
		writeJson(relayPublicKeySourcePath, {
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
		writeJson(relayPublicKeyLockPath, {
			schemaVersion: "telclaude.hermes.rollback-relay-public-key-lock.v1",
			keys: [
				{
					scope: "operator",
					envKey: HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV,
					value: relayKeys.publicKey,
					sha256: relayPublicKeySha256,
					source: relayPublicKeySourcePath,
					sourceSha256: computeFileDigest(relayPublicKeySourcePath),
				},
			],
		});
		process.env[HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK_ENV] = relayPublicKeyLockPath;
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
				relayPublicKey: { source: string };
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
				relayPublicKey: {
					source: relayPublicKeySourcePath,
				},
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
			restoreEnv(HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK_ENV, originalOperatorRelayPublicKeyLock);
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
  printf '%s\\n' '{"Id":"container-id","Image":"sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7","Config":{"Image":"nousresearch/hermes-agent@sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7","Hostname":"tc-hermes-contained"},"NetworkSettings":{"Networks":{"telclaude-hermes-relay":{"IPAddress":"${CLI_HEADLESS_TEST_CONTAINED_IP}"}}}}'
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
		expect(dockerCalls).toContain("os.chown(home, 0, runtime_gid)");
		expect(dockerCalls).toContain("os.chmod(home, 0o1770)");
		expect(dockerCalls).toContain("runtime_dirs = ('sessions', 'logs', 'cron'");
		expect(dockerCalls).toContain("harden_runtime_dirs()");
		expect(dockerCalls).toContain("os.chown(runtime_path, runtime_uid, runtime_gid)");
		expect(dockerCalls).toContain("os.chmod(runtime_path, 0o700)");
		expect(dockerCalls).toContain("Hermes home is missing before docker exec launch");
		expect(dockerCalls).toContain("auth.lock");
		expect(dockerCalls).toContain("os.unlink(lock_path)");
		expect(dockerCalls).toContain("os.chown(path, 0, runtime_gid)");
		expect(dockerCalls).toContain("os.chmod(path, 0o440)");
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
  printf '%s\\n' '{"Id":"container-id","Image":"sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7","Config":{"Image":"nousresearch/hermes-agent@sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7","Hostname":"tc-hermes-contained"},"NetworkSettings":{"Networks":{"telclaude-hermes-relay":{"IPAddress":"${CLI_HEADLESS_TEST_CONTAINED_IP}"}}}}'
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
  printf '%s\\n' '{"Id":"container-id","Image":"sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7","Config":{"Image":"nousresearch/hermes-agent@sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7","Hostname":"tc-hermes-contained"},"NetworkSettings":{"Networks":{"telclaude-hermes-relay":{"IPAddress":"${CLI_HEADLESS_TEST_CONTAINED_IP}"}}}}'
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
  printf '%s\\n' '{"Id":"container-id","Image":"sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7","Config":{"Image":"nousresearch/hermes-agent@sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7","Hostname":"tc-hermes-contained"},"NetworkSettings":{"Networks":{"telclaude-hermes-relay":{"IPAddress":"${CLI_HEADLESS_TEST_CONTAINED_IP}"}}}}'
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
				networkName: "telclaude-hermes-relay",
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
if [ "$1" = "exec" ] && [ "$2" = "tc-hermes-contained" ]; then
  if [ "$3" = "node" ]; then
    prop="$7"
    case "$prop" in
      pretooluse_hook_registered|allowlisted_skill_invocation_allowed|nonallowlisted_skill_invocation_denied|social_missing_allowlist_denied|social_empty_allowlist_denied)
        printf '%s\\n' '{"passed":true,"detail":"docker exec PreToolUse proof","enforcementLayer":"pretooluse"}'
        exit 0
        ;;
    esac
  fi
  prop="$6"
  case "$prop" in
    allowlist_manifest_present|allowlisted_skill_present|nonallowlisted_skill_absent|runtime_skills_match_allowlist)
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
			"telclaude-hermes-relay",
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
		expect(fs.readFileSync(callsPath, "utf8")).toContain("network inspect telclaude-hermes-relay");
		expect(fs.readFileSync(callsPath, "utf8")).toContain("exec tc-hermes-contained python -c");
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
  "networkName": "telclaude-hermes-relay",
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

		const result = await runScopedCutoverCheckWithBundle(
			approvalContinuationCutoverBundle(evidencePath),
		);
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

		const result = await runScopedCutoverCheckWithBundle(
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

		const result = await runScopedCutoverCheckWithBundle(
			sideEffectLedgerCutoverBundle(evidencePath),
		);
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

		const result = await runScopedCutoverCheckWithBundle(
			sideEffectLedgerCutoverBundle(evidencePath),
		);
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

		const result = await runScopedCutoverCheckWithBundle(
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

		const result = await runScopedCutoverCheckWithBundle(
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

	it("passes the provider release-policy cutover gate from complete observed evidence", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-provider-release-"));
		const evidencePath = path.join(tempDir, "providers-release-policy.json");
		const probeResult = await runHermesCommand([
			"hermes",
			"probe",
			"providers.release-policy",
			"--allow-run",
			"--json",
			"--out",
			evidencePath,
		]);
		expect(probeResult.exitCode).toBe(0);

		const result = await runScopedCutoverCheckWithBundle(
			providerReleasePolicyCutoverBundle(evidencePath),
		);
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode, result.stdout).toBe(0);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "pass",
		});
	});

	it("fails the provider release-policy cutover gate when urgent health denial is unproven", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-provider-release-"));
		const evidencePath = path.join(tempDir, "providers-release-policy.json");
		const probeResult = await runHermesCommand([
			"hermes",
			"probe",
			"providers.release-policy",
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
				(check) => check.name !== "provider.release.urgent-health-misclassification-denied",
			),
		});

		const result = await runScopedCutoverCheckWithBundle(
			providerReleasePolicyCutoverBundle(evidencePath),
		);
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode, result.stdout).toBe(1);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining(
				"check provider.release.urgent-health-misclassification-denied is missing",
			),
		});
	});

	it("passes the Google provider cutover gate from complete observed evidence", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-provider-google-"));
		const evidencePath = path.join(tempDir, "providers-google.json");
		const probeResult = await runHermesCommand([
			"hermes",
			"probe",
			"providers.google",
			"--allow-run",
			"--json",
			"--out",
			evidencePath,
		]);
		expect(probeResult.exitCode).toBe(0);

		const result = await runScopedCutoverCheckWithBundle(googleProviderCutoverBundle(evidencePath));
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode, result.stdout).toBe(0);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "pass",
		});
	});

	it("fails the Google provider cutover gate when wrong-actor denial is unproven", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-provider-google-"));
		const evidencePath = path.join(tempDir, "providers-google.json");
		const probeResult = await runHermesCommand([
			"hermes",
			"probe",
			"providers.google",
			"--allow-run",
			"--json",
			"--out",
			evidencePath,
		]);
		expect(probeResult.exitCode).toBe(0);
		const evidence = readJson(evidencePath) as { checks: Array<{ name: string }> };
		writeJson(evidencePath, {
			...evidence,
			checks: evidence.checks.filter((check) => check.name !== "google.wrong-actor-denied"),
		});

		const result = await runScopedCutoverCheckWithBundle(googleProviderCutoverBundle(evidencePath));
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode, result.stdout).toBe(1);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("check google.wrong-actor-denied is missing"),
		});
	});

	it.each([
		["providers.bank", "bank"],
		["providers.clalit", "clalit"],
		["providers.government", "government"],
	] as const)("passes the %s provider-domain cutover gate from complete observed evidence", async (surfaceId, providerId) => {
		const tempDir = fs.mkdtempSync(
			path.join(os.tmpdir(), `hermes-cutover-provider-${providerId}-`),
		);
		const evidencePath = path.join(tempDir, `${surfaceId.replace(".", "-")}.json`);
		const probeResult = await runHermesCommand([
			"hermes",
			"probe",
			surfaceId,
			"--allow-run",
			"--json",
			"--out",
			evidencePath,
		]);
		expect(probeResult.exitCode).toBe(0);

		const result = await runScopedCutoverCheckWithBundle(
			providerDomainCutoverBundle(surfaceId, evidencePath),
		);
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode, result.stdout).toBe(0);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "pass",
		});
	});

	it("fails the bank provider-domain cutover gate when provider scope denial is unproven", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-provider-bank-"));
		const evidencePath = path.join(tempDir, "providers-bank.json");
		const probeResult = await runHermesCommand([
			"hermes",
			"probe",
			"providers.bank",
			"--allow-run",
			"--json",
			"--out",
			evidencePath,
		]);
		expect(probeResult.exitCode).toBe(0);
		const evidence = readJson(evidencePath) as { checks: Array<{ name: string }> };
		writeJson(evidencePath, {
			...evidence,
			checks: evidence.checks.filter((check) => check.name !== "bank.wrong-provider-scope-denied"),
		});

		const result = await runScopedCutoverCheckWithBundle(
			providerDomainCutoverBundle("providers.bank", evidencePath),
		);
		const report = JSON.parse(result.stdout) as {
			gates: Array<{ name: string; status: string; detail: string }>;
		};

		expect(result.exitCode, result.stdout).toBe(1);
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("check bank.wrong-provider-scope-denied is missing"),
		});
	});

	it("fails the approval-continuation cutover gate when evidence is missing", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-approval-"));
		const evidencePath = path.join(tempDir, "missing-approval-continuation.json");

		const result = await runScopedCutoverCheckWithBundle(
			approvalContinuationCutoverBundle(evidencePath),
		);
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

		const result = await runScopedCutoverCheckWithBundle(
			approvalContinuationCutoverBundle(evidencePath),
		);
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

		const result = await runScopedCutoverCheckWithBundle(
			approvalContinuationCutoverBundle(evidencePath),
		);
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

		const result = await runScopedCutoverCheckWithBundle(
			apiServerContainmentCutoverBundle(evidencePath),
		);
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

		const result = await runScopedCutoverCheckWithBundle(
			apiServerContainmentCutoverBundle(evidencePath),
		);
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

		const result = await runScopedCutoverCheckWithBundle(
			apiServerContainmentCutoverBundle(evidencePath),
		);
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

		const result = await runScopedCutoverCheckWithBundle(
			apiServerContainmentCutoverBundle(evidencePath),
		);
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
  else if (payload.method === "initialize") emit({result: {ok: true}}, "${CLI_HEADLESS_TEST_CONTAINED_IP}");
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
} else if (container === "telclaude-agent-social") {
  if (auth !== "Bearer social") rpcError("social auth header missing");
  else if (payload.method === "initialize") emit({result: {ok: true}}, "${CLI_HEADLESS_WRONG_CONTAINED_IP}");
  else if (tool === "tc_memory_write" && String(args.content || "").includes("off-domain sentinel")) {
    emit({result: {id: args.id}}, "${CLI_HEADLESS_WRONG_CONTAINED_IP}");
  } else {
    rpcError("social container only seeds the off-domain sentinel");
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
				"telclaude-agent-social",
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
				sentinelSeedObservedPeerAddress?: string;
				sentinelSeedExpectedPeerAddress?: string;
			}>;
		};
		const calls = fs.readFileSync(callsPath, "utf8");

		expect(result.exitCode, result.stdout).toBe(0);
		expect(report.status).toBe("pass");
		expect(report.checks.find((check) => check.name === "cross_source_read_denied")).toMatchObject({
			status: "pass",
			sentinelSeedObservedPeerAddress: CLI_HEADLESS_WRONG_CONTAINED_IP,
			sentinelSeedExpectedPeerAddress: CLI_HEADLESS_WRONG_CONTAINED_IP,
		});
		expect(calls).toContain("exec -i tc-hermes-contained python -c");
		expect(calls).toContain("exec -i telclaude-agent-social python -c");
		expect(readJson(evidencePath)).toMatchObject({ status: "pass", ran: true });
	});

	it("passes the served-MCP cutover gate from complete observed evidence", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cutover-served-mcp-"));
		const evidencePath = path.join(tempDir, "execution-served-mcp-containment.json");
		writeJson(evidencePath, servedMcpContainmentEvidence());

		const result = await runScopedCutoverCheckWithBundle(
			servedMcpContainmentCutoverBundle(evidencePath),
		);
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
					observedPeerAddress: CLI_HEADLESS_TEST_CONTAINED_IP,
					expectedPeerAddress: CLI_HEADLESS_TEST_CONTAINED_IP,
					detail: "operator declared contained peer origin",
				},
			}),
		);

		const result = await runScopedCutoverCheckWithBundle(
			servedMcpContainmentCutoverBundle(evidencePath),
		);
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
					observedPeerAddress: CLI_HEADLESS_TEST_RELAY_IP,
					observedPeerSource: "server-peer-echo",
					expectedPeerAddress: CLI_HEADLESS_TEST_CONTAINED_IP,
					expectedPeerSource: "configured-contained-ip",
					detail: "probe peer origin matched relay namespace",
				},
			}),
		);

		const result = await runScopedCutoverCheckWithBundle(
			servedMcpContainmentCutoverBundle(evidencePath),
		);
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

		const result = await runScopedCutoverCheckWithBundle(
			servedMcpContainmentCutoverBundle(evidencePath),
		);
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

		const result = await runScopedCutoverCheckWithBundle(
			servedMcpContainmentCutoverBundle(evidencePath),
		);
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

		const result = await runScopedCutoverCheckWithBundle(
			servedMcpContainmentCutoverBundle(evidencePath),
		);
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
		expect(inventory.sessions.rows[0].keyRef).toMatch(/^session-ref:/);
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
		expect(redactSecrets(serialized)).toBe(serialized);
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
