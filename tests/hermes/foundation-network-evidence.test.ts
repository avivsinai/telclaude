import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
	buildEdgeAdapterProbeEvidence,
	EDGE_ADAPTER_CONTRACT_PROBE_SOURCE,
} from "../../src/hermes/edge-adapter-probes.js";
import {
	buildCutoverProofBundle,
	type CompatibilityLockfile,
	type CutoverInputBundle,
	collectFeatureProbeEvidence,
	computeHermesArtifactDigest,
	evaluateCutoverCheck,
	type FeatureProbeMatrix,
	HERMES_ROLLBACK_CONTROL_SURFACE,
	HERMES_ROLLBACK_OBSERVATION_SURFACE,
	HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV,
	NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION,
	PRIVATE_TELEGRAM_FIXTURE_DIGEST_PATHS,
	PRIVATE_TELEGRAM_FIXTURE_REQUIREMENTS,
	type ProbeBundle,
	REQUIRED_CUTOVER_NETWORK_PROBE_IDS,
	writeHermesProfileGenerationProof,
} from "../../src/hermes/foundation.js";
import { signNetworkProbeEvidenceAttestation } from "../../src/hermes/network-probe-attestation.js";
import { signNoForkRunnerAttestation } from "../../src/hermes/no-fork-attestation.js";
import { noForkSha256Digest } from "../../src/hermes/no-fork-proof.js";
import { signPrivateTelegramFixtureEvidenceAttestation } from "../../src/hermes/private-telegram-fixture-attestation.js";
import { buildInternalResponseProof, generateKeyPair } from "../../src/internal-auth.js";
import {
	type OpenAiCodexRelayProof,
	type OpenAiCodexRelayProofSignedFields,
	openAiCodexRelayProofTokenSha256,
	signOpenAiCodexRelayProof,
} from "../../src/relay/openai-codex-relay-proof.js";

const hermesPin = { version: "0.15.1" };
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
	adapterApiSignatures: { "edge.whatsapp": `sha256:${"a".repeat(64)}` },
	capabilities: {
		plugins: ["platform-adapter"],
		mcp: ["stdio"],
		modelProviders: ["custom-provider"],
		memoryProviders: ["custom-memory"],
	},
	requiredUpgradeTests: ["pnpm dev hermes prove --upstream-clean --p0"],
	generatedProfileSchemaVersion: "1",
	wrapperPackageVersion: "0.7.1",
	paritySuiteDigests: { p0: `sha256:${"b".repeat(64)}` },
	noForkProofEvidencePath: "artifacts/hermes/no-fork.json",
	sourceDriftSignals: { sourceCommit: "abcdef1", docsCommit: "1234567" },
};

function writeJson(filePath: string, value: unknown): void {
	fs.mkdirSync(path.dirname(filePath), { recursive: true });
	fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function readJson<T extends Record<string, unknown> = Record<string, unknown>>(
	filePath: string,
): T {
	return JSON.parse(fs.readFileSync(filePath, "utf8")) as T;
}

function writeProfileProof(lockfile: CompatibilityLockfile) {
	return writeHermesProfileGenerationProof({
		pin: lockfile.hermes,
		outDir: fs.mkdtempSync(path.join(os.tmpdir(), "hermes-profile-fixture-")),
		lockfile,
		evidencePath: path.join(
			fs.mkdtempSync(path.join(os.tmpdir(), "hermes-profile-proof-")),
			"profile-generation-proof.json",
		),
		now: "2026-05-30T00:00:00Z",
	});
}

function profileDecision(evidencePath: string) {
	return {
		id: "D-profile-generation",
		status: "accepted" as const,
		owner: "operator",
		deadline_phase: "Phase 1",
		accepted_answer: "Generated Hermes profiles are produced by the checked profile generator.",
		evidence_path: evidencePath,
		affected_workflows: ["private.telegram.basic"],
		cutover_impact: "Profile generation proof is required before private cutover.",
	};
}

function networkEvidence(
	id: string,
	evidencePath: string,
	overrides: Record<string, unknown> = {},
) {
	ensureOperatorRelayKeys();
	const evidence = {
		schemaVersion: NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION,
		id,
		status: "pass",
		ran: true,
		summary: `${id} observed expected network isolation`,
		generatedAt: "2026-05-30T00:00:00.000Z",
		evidence_path: evidencePath,
		attempts: [firewallSentinelAttempt(), networkPolicyAttempt(id)],
		...overrides,
	};
	return {
		...evidence,
		attestation: signNetworkProbeEvidenceAttestation(evidence),
	};
}

function containedInternalNetworkEvidence(
	id: string,
	evidencePath: string,
	overrides: Record<string, unknown> = {},
) {
	return networkEvidence(id, evidencePath, {
		posture: "contained-internal",
		attempts: containedInternalAttempts(id),
		...overrides,
	});
}

function firewallSentinelAttempt() {
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

function containedInternalAttempts(id: string) {
	if (id === "network.relay-control-allowed") {
		return [
			{
				name: "relay-control",
				kind: "http",
				target: "http://telclaude:8790/health",
				expectation: "allow",
				status: "pass",
				observed: "reachable",
				detail: "allowed control reached relay with HTTP status 200",
				durationMs: 1,
				httpStatus: 200,
			},
		];
	}
	if (id === "network.direct-vault-denied") {
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
	}
	if (id === "network.dns-exfil-denied") {
		return [
			{
				name: "dns-exfil-1",
				kind: "dns_guard",
				target: "http://169.254.169.254/latest/meta-data/",
				expectation: "deny",
				status: "pass",
				observed: "denied",
				detail: "target was actively denied with ENETUNREACH",
				durationMs: 1,
				errorName: "TypeError",
				errorCode: "ENETUNREACH",
				resolvedAddresses: [
					{
						address: "169.254.169.254",
						blocked: true,
						nonOverridable: true,
					},
				],
			},
		];
	}
	if (id === "network.direct-provider-denied") {
		return ["bank", "clalit", "government", "google"].map((provider) => ({
			name: `provider:${provider}`,
			kind: "http",
			target: `https://${provider}.provider.internal/probe`,
			expectation: "deny",
			status: "pass",
			observed: "denied",
			detail: "target was actively denied with ENETUNREACH",
			durationMs: 1,
			errorName: "TypeError",
			errorCode: "ENETUNREACH",
		}));
	}
	return [
		{
			name: "contained-egress",
			kind: "http",
			target: "https://chatgpt.com/backend-api/codex/models?client_version=1.0.0",
			expectation: "deny",
			status: "pass",
			observed: "denied",
			detail: "target was actively denied with ENETUNREACH",
			durationMs: 1,
			errorName: "TypeError",
			errorCode: "ENETUNREACH",
		},
	];
}

function networkPolicyAttempt(id: string) {
	if (id === "network.dns-exfil-denied") {
		return {
			name: "dns-exfil-guard",
			kind: "dns_guard",
			target: "http://169.254.169.254/latest/meta-data/",
			expectation: "deny",
			status: "pass",
			observed: "denied",
			detail: "DNS guard denied the forbidden target before egress",
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
	}
	return {
		name: "policy-check",
		kind: "http",
		target: "http://relay/probe",
		expectation: id === "network.relay-control-allowed" ? "allow" : "deny",
		status: "pass",
		observed: "expected",
		detail: "observed expected network policy result",
		durationMs: 1,
		httpStatus: 204,
	};
}

function writeNetworkBundle(
	tempDir: string,
	ids: string[] = [...REQUIRED_CUTOVER_NETWORK_PROBE_IDS],
	evidenceFactory: (
		id: string,
		evidencePath: string,
		overrides?: Record<string, unknown>,
	) => Record<string, unknown> = networkEvidence,
) {
	const probes = ids.map((id) => {
		const evidencePath = path.join(tempDir, `${id.replace(/^network\./, "")}.json`);
		writeJson(evidencePath, evidenceFactory(id, evidencePath));
		return { id, status: "pass" as const, evidence_path: evidencePath };
	});
	return { schemaVersion: 1 as const, probes };
}

function writeNoForkProof() {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-nofork-"));
	const evidencePath = path.join(tempDir, "no-fork.json");
	const relayKeys = ensureOperatorRelayKeys();
	process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
	process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;
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
		runnerAttestation: signNoForkRunnerAttestation({
			schemaVersion: "telclaude.hermes.no-fork-runner-attestation.v1",
			source: "telclaude-no-fork-proof-runner",
			runner: "telclaude-hermes-no-fork-runner",
			startedAt: "2026-05-31T09:00:00.000Z",
			endedAt: "2026-05-31T09:01:00.000Z",
			checkoutPath: "/home/user/MyProjects/hermes-agent-v2026.5.29",
			expectedRef: "v2026.5.29",
			expectedVersion: "0.15.1",
			head: "a".repeat(40),
			expectedRefCommit: "a".repeat(40),
			wrapperPackageSha256: noForkSha256Digest("wrapper-package"),
			profileGenerationSha256: noForkSha256Digest("profile-generation"),
			fixtureResultsSha256: noForkSha256Digest("fixture-results"),
			transcriptSha256: noForkSha256Digest("command-transcript"),
			p0Command: ["pnpm", "dev", "hermes", "prove", "--upstream-clean", "--p0"],
			p0ExitCode: 0,
			p0Status: "pass",
			runtimeSourceReplacementDenied: true,
			monkeypatchDenied: true,
			postRunStatusPorcelain: "",
			postRunDiffExitCode: 0,
			postRunCachedDiffExitCode: 0,
		}),
		checks: [
			{
				name: "checkout.present",
				status: "pass",
				detail: "Hermes checkout found at pinned tag",
			},
			{
				name: "checkout.head",
				status: "pass",
				detail: "HEAD is pinned",
			},
			{
				name: "checkout.expectedRef",
				status: "pass",
				detail: "expected ref resolved",
			},
			{
				name: "checkout.pinned",
				status: "pass",
				detail: "HEAD matches pinned Hermes ref",
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
	};
	writeJson(evidencePath, proof);
	return proof;
}

function writeRollbackRehearsal() {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-rollback-"));
	const evidencePath = path.join(tempDir, "rollback-rehearsal.json");
	const relayKeys =
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY && process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY
			? {
					privateKey: process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY,
					publicKey: process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY,
				}
			: generateKeyPair();
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
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-fixtures-"));
	const reportPath = path.join(tempDir, "private-telegram-vitest.json");
	writeJson(reportPath, privateTelegramVitestReport());
	const reportDigest = `sha256:${crypto
		.createHash("sha256")
		.update(fs.readFileSync(reportPath))
		.digest("hex")}` as `sha256:${string}`;
	const invocation = privateTelegramFixtureInvocation(reportPath, reportDigest);
	ensureOperatorRelayKeys();
	const results = PRIVATE_TELEGRAM_FIXTURE_REQUIREMENTS.map((requirement) => {
		const evidencePath = path.join(tempDir, `${requirement.id}.json`);
		const evidence = {
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
		};
		writeJson(evidencePath, {
			...evidence,
			privateTelegramRunnerAttestation: signPrivateTelegramFixtureEvidenceAttestation({
				fixtureId: evidence.id,
				status: evidence.status,
				observedAt: evidence.observedAt,
				provenanceRunner: evidence.provenance.runner,
				provenanceSource: evidence.provenance.source,
				testReportPath: evidence.testReport.path,
				testReportSha256: evidence.testReport.sha256,
				invocation: evidence.invocation,
				requiredTests: evidence.testReport.requiredTests,
				requiredAssertions: evidence.testReport.requiredAssertions,
				checks: evidence.checks,
			}),
		});
		return { id: requirement.id, status: "pass" as const, evidence_path: evidencePath };
	});
	return { schemaVersion: 1 as const, results };
}

function privateTelegramFixtureInvocation(reportPath: string, reportDigest: `sha256:${string}`) {
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
					(testName) => ({ fullName: testName, status: "passed" }),
				),
			},
			{
				name: "tests/telegram/command-gating.test.ts",
				status: "passed",
				assertionResults: PRIVATE_TELEGRAM_FIXTURE_REQUIREMENTS[1].requiredTests.map(
					(testName) => ({ fullName: testName, status: "passed" }),
				),
			},
		],
	};
}

function modelRelayEvidence(overrides: Record<string, unknown> = {}) {
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
				name: "modelRelay.origin",
				status: "pass",
				detail:
					"model-relay evidence originated from tc-hermes-contained at the expected peer address",
			},
			{
				name: "relay.reachable",
				status: "pass",
				detail: "model relay endpoint reached with HTTP status 204",
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
			observedPeerAddress: "172.29.92.11",
			observedPeerSource: "server-peer-echo",
			expectedPeerAddress: "172.29.92.11",
			expectedPeerSource: "configured-contained-ip",
			detail: "model relay peer origin was observed by the relay endpoint",
		},
		observation: {
			relayUrl: "http://telclaude:8790/v1/models",
			directModelUrl: "https://chatgpt.com/backend-api/codex/models?client_version=1.0.0",
			profileDir: "/home/hermes/.hermes",
			scannedProfileFiles: ["/home/hermes/.hermes/config.yaml"],
		},
		...overrides,
	};
}

function makeCutoverProofBundle(bundle: CutoverBundleWithoutProof) {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-proof-bundle-"));
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

function cutoverBundle(networkProbes: ProbeBundle): CutoverInputBundle {
	const noForkProof = writeNoForkProof();
	const lockfile = { ...compatLockfile, noForkProofEvidencePath: noForkProof.evidence_path };
	const profileGenerationProof = writeProfileProof(lockfile);
	const withoutProof: CutoverBundleWithoutProof = {
		schemaVersion: 1,
		inventory: {
			generatedAt: "2026-05-30T00:00:00Z",
			status: "complete",
			summary: {
				pendingQueues: {
					approvals: 0,
					planApprovals: 0,
					cards: 0,
					backgroundJobs: 0,
					socialItems: 0,
					curatorItems: 0,
					pairingPendingRequests: 0,
					pairingActiveLockouts: 0,
				},
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
		decisionLog: {
			schemaVersion: 1,
			decisions: [profileDecision(profileGenerationProof.evidence_path)],
		},
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
		profileGenerationProof,
		networkProbes,
		queueSnapshot: { unownedActiveCount: 0 },
		rollbackRehearsal: writeRollbackRehearsal(),
	};
	return {
		...withoutProof,
		cutoverProofBundle: makeCutoverProofBundle(withoutProof),
	};
}

function refreshCutoverProofBundle(bundle: CutoverInputBundle): CutoverInputBundle {
	const { cutoverProofBundle: _cutoverProofBundle, ...withoutProof } = bundle;
	return {
		...withoutProof,
		cutoverProofBundle: makeCutoverProofBundle(withoutProof),
	};
}

function cutoverBundleWithNoForkProof(
	noForkProof: ReturnType<typeof writeNoForkProof>,
): CutoverInputBundle {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-nofork-cutover-"));
	const base = cutoverBundle(
		writeNetworkBundle(tempDir, undefined, containedInternalNetworkEvidence),
	);
	const { cutoverProofBundle: _cutoverProofBundle, ...baseWithoutProof } = base;
	const lockfile = { ...base.lockfile, noForkProofEvidencePath: noForkProof.evidence_path };
	const profileGenerationProof = writeProfileProof(lockfile);
	const withoutProof: CutoverBundleWithoutProof = {
		...baseWithoutProof,
		lockfile,
		noForkProof,
		profileGenerationProof,
		decisionLog: {
			schemaVersion: 1,
			decisions: [profileDecision(profileGenerationProof.evidence_path)],
		},
	};
	return {
		...withoutProof,
		cutoverProofBundle: makeCutoverProofBundle(withoutProof),
	};
}

function modelRelayCutoverBundle(evidencePath: string): CutoverInputBundle {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-model-relay-cutover-"));
	const matrix = {
		schemaVersion: 1 as const,
		probes: [
			{
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
			},
		],
	};
	const base = cutoverBundle(
		writeNetworkBundle(tempDir, undefined, containedInternalNetworkEvidence),
	);
	const lockfile = {
		...base.lockfile,
		featureProbeMatrixDigest: computeHermesArtifactDigest(matrix),
		featureProbes: [
			{
				surface_id: "model.relay",
				status: "pass" as const,
				evidence_path: evidencePath,
			},
		],
		adapterApiSignatures: { "model.relay": `sha256:${"c".repeat(64)}` },
	};
	const profileGenerationProof = writeProfileProof(lockfile);
	const { cutoverProofBundle: _cutoverProofBundle, ...baseWithoutProof } = base;
	const withoutProof: CutoverBundleWithoutProof = {
		...baseWithoutProof,
		scopeManifest: {
			schemaVersion: 1,
			workflows: [
				{
					...base.scopeManifest.workflows[0],
					required_surface_ids: ["model.relay"],
				},
			],
		},
		featureProbeMatrix: matrix,
		featureProbeEvidence: collectFeatureProbeEvidence(matrix),
		lockfile,
		profileGenerationProof,
		decisionLog: {
			schemaVersion: 1,
			decisions: [profileDecision(profileGenerationProof.evidence_path)],
		},
	};
	return {
		...withoutProof,
		cutoverProofBundle: makeCutoverProofBundle(withoutProof),
	};
}

function edgeAdapterCutoverBundle(evidencePath: string): CutoverInputBundle {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-edge-cutover-"));
	const matrix = {
		schemaVersion: 1 as const,
		probes: [
			{
				surface_id: "edge.whatsapp",
				hermes_pin: hermesPin,
				documented_seam: "Telclaude edge adapter contract mediates WhatsApp ingress and egress",
				probe_command: "pnpm dev hermes probe edge.whatsapp --allow-run",
				expected_result: "WhatsApp ingress is sanitized and outbound delivery uses prepared refs",
				negative_probe: "raw WhatsApp credentials and direct native bridge access are absent",
				evidence_path: evidencePath,
				lockfile_key: "featureProbes.edge.whatsapp",
				security_scope: "edge-adapter" as const,
				approval_equivalent: true,
				failure_outcome: "disable" as const,
				status: "pass" as const,
			},
		],
	};
	const base = cutoverBundle(
		writeNetworkBundle(tempDir, undefined, containedInternalNetworkEvidence),
	);
	const lockfile = {
		...base.lockfile,
		featureProbeMatrixDigest: computeHermesArtifactDigest(matrix),
		featureProbes: [
			{
				surface_id: "edge.whatsapp",
				status: "pass" as const,
				evidence_path: evidencePath,
			},
		],
		adapterApiSignatures: { "edge.whatsapp": `sha256:${"c".repeat(64)}` },
	};
	const profileGenerationProof = writeProfileProof(lockfile);
	const { cutoverProofBundle: _cutoverProofBundle, ...baseWithoutProof } = base;
	const withoutProof: CutoverBundleWithoutProof = {
		...baseWithoutProof,
		scopeManifest: {
			schemaVersion: 1,
			workflows: [
				{
					...base.scopeManifest.workflows[0],
					required_surface_ids: ["edge.whatsapp"],
				},
			],
		},
		featureProbeMatrix: matrix,
		featureProbeEvidence: collectFeatureProbeEvidence(matrix),
		lockfile,
		profileGenerationProof,
		decisionLog: {
			schemaVersion: 1,
			decisions: [profileDecision(profileGenerationProof.evidence_path)],
		},
	};
	return {
		...withoutProof,
		cutoverProofBundle: makeCutoverProofBundle(withoutProof),
	};
}

function cliHeadlessCutoverBundle(
	evidencePath: string,
	beforeCollectFeatureEvidence?: () => void,
): CutoverInputBundle {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cli-headless-cutover-"));
	const matrix = {
		schemaVersion: 1 as const,
		probes: [
			{
				surface_id: "execution.cli_headless",
				hermes_pin: hermesPin,
				documented_seam: "Hermes CLI headless runs through the Telclaude model relay",
				probe_command: "pnpm dev hermes probe execution.cli_headless --allow-run",
				expected_result: "Hermes CLI returns a proof token through relay-owned Codex",
				negative_probe: "Direct model credentials and unsigned relay proofs fail",
				evidence_path: evidencePath,
				lockfile_key: "featureProbes.execution.cli_headless",
				security_scope: "headless-availability-only" as const,
				approval_equivalent: false,
				failure_outcome: "disable" as const,
				status: "pass" as const,
			},
		],
	};
	const base = cutoverBundle(
		writeNetworkBundle(tempDir, undefined, containedInternalNetworkEvidence),
	);
	const lockfile = {
		...base.lockfile,
		featureProbeMatrixDigest: computeHermesArtifactDigest(matrix),
		featureProbes: [
			{
				surface_id: "execution.cli_headless",
				status: "pass" as const,
				evidence_path: evidencePath,
			},
		],
		adapterApiSignatures: { "execution.cli_headless": `sha256:${"c".repeat(64)}` },
	};
	const profileGenerationProof = writeProfileProof(lockfile);
	const { cutoverProofBundle: _cutoverProofBundle, ...baseWithoutProof } = base;
	beforeCollectFeatureEvidence?.();
	const withoutProof: CutoverBundleWithoutProof = {
		...baseWithoutProof,
		scopeManifest: {
			schemaVersion: 1,
			workflows: [
				{
					...base.scopeManifest.workflows[0],
					required_surface_ids: ["execution.cli_headless"],
				},
			],
		},
		featureProbeMatrix: matrix,
		featureProbeEvidence: collectFeatureProbeEvidence(matrix),
		lockfile,
		profileGenerationProof,
		decisionLog: {
			schemaVersion: 1,
			decisions: [profileDecision(profileGenerationProof.evidence_path)],
		},
	};
	return {
		...withoutProof,
		cutoverProofBundle: makeCutoverProofBundle(withoutProof),
	};
}

function writeCliHeadlessEvidence(evidencePath: string, relayProof: OpenAiCodexRelayProof): void {
	const invocation = {
		command: "/usr/local/bin/hermes",
		args: ["-z", "Reply with exactly HERMES_OK_SIGNED_GATE"],
		cwd: process.cwd(),
		envKeys: [
			"HERMES_CODEX_BASE_URL",
			"HERMES_HOME",
			"HERMES_INFERENCE_MODEL",
			"HERMES_INFERENCE_PROVIDER",
			"NO_COLOR",
		],
	};
	const runtime = {
		kind: "contained-docker",
		containerName: "tc-hermes-contained",
		networkName: "telclaude-hermes-relay",
		containerId: "b6d8f6c9a1d4",
		image:
			"nousresearch/hermes-agent@sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7",
		imageDigest: "sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7",
		hostname: "b6d8f6c9a1d4",
		relayHost: "telclaude",
		relayResolvedAddress: "172.29.92.10",
		containerIpAddress: "172.29.92.11",
		observedPeerAddress: "172.29.92.11",
		provenanceSource: "docker-inspect-container-dns-and-relay-peer",
	};
	const stdoutPreview = "HERMES_OK_SIGNED_GATE\n";
	const stderrPreview = "";
	writeJson(evidencePath, {
		schemaVersion: "telclaude.hermes.probe-result.v1",
		probeId: "execution.cli_headless",
		status: "pass",
		ran: true,
		summary: "Hermes CLI oneshot probe completed successfully",
		exitCode: 0,
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
			startedAt: "2026-05-31T09:00:00.000Z",
			endedAt: "2026-05-31T09:01:00.000Z",
			expectedProofToken: "HERMES_OK_SIGNED_GATE",
			proofTokenObserved: true,
			invocationSha256: computeHermesArtifactDigest(invocation),
			stdoutSha256: textDigest(stdoutPreview),
			stderrSha256: textDigest(stderrPreview),
			runtimeSha256: computeHermesArtifactDigest(runtime),
			relayProofSha256: computeHermesArtifactDigest(relayProof),
		},
		stdoutPreview,
		stderrPreview,
		runtime,
		relayProof,
		findings: [],
	});
}

function cliHeadlessRelayProof(
	overrides: Partial<OpenAiCodexRelayProofSignedFields> = {},
): OpenAiCodexRelayProof {
	return signOpenAiCodexRelayProof({
		schemaVersion: "telclaude.hermes.cli-headless-relay-proof.v1",
		source: "telclaude-openai-codex-proxy",
		requestId: "codex-proof-1",
		method: "POST",
		path: "/backend-api/codex/responses",
		observedPeerAddress: "172.29.92.11",
		upstreamStatus: 200,
		model: "gpt-5.3-codex",
		requestBodySha256: `sha256:${"a".repeat(64)}`,
		proofTokenSha256: openAiCodexRelayProofTokenSha256("HERMES_OK_SIGNED_GATE"),
		observedAt: "2026-05-31T09:00:30.000Z",
		...overrides,
	});
}

function textDigest(value: string): string {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function cutoverBundleWithGenericFixture(fixtureId: string): CutoverInputBundle {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-fixture-catalog-"));
	const evidencePath = path.join(tempDir, `${fixtureId}.json`);
	writeJson(evidencePath, {
		schemaVersion: "telclaude.hermes.fixture-evidence.v1",
		id: fixtureId,
		status: "pass",
		ran: true,
		evidence_path: evidencePath,
		observedAt: "2026-05-31T09:00:00.000Z",
		provenance: {
			runner: "self-reported-json",
			source: "hand-authored",
		},
		checks: [
			{
				name: "self-reported-pass",
				status: "pass",
				detail: "hand-authored fixture evidence claimed pass",
			},
		],
	});
	const base = cutoverBundle(
		writeNetworkBundle(tempDir, undefined, containedInternalNetworkEvidence),
	);
	const { cutoverProofBundle: _cutoverProofBundle, ...baseWithoutProof } = base;
	const withoutProof: CutoverBundleWithoutProof = {
		...baseWithoutProof,
		scopeManifest: {
			schemaVersion: 1,
			workflows: [
				{
					...base.scopeManifest.workflows[0],
					fixture_ids: [fixtureId],
					negative_fixture_ids: [],
				},
			],
		},
		fixtureResults: {
			schemaVersion: 1,
			results: [{ id: fixtureId, status: "pass", evidence_path: evidencePath }],
		},
	};
	return {
		...withoutProof,
		cutoverProofBundle: makeCutoverProofBundle(withoutProof),
	};
}

function networkGateDetail(networkProbes: ProbeBundle): string {
	const report = evaluateCutoverCheck(cutoverBundle(networkProbes));
	return report.gates.find((gate) => gate.name === "networkProbes.pass")?.detail ?? "";
}

describe("Hermes cutover edge-adapter evidence validation", () => {
	it("refuses schema-only edge contract-unit evidence as cutover enforcement", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-edge-cutover-"));
		const evidencePath = path.join(tempDir, "edge-whatsapp.json");
		const relayKeys = generateKeyPair();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;
		const evidence = buildEdgeAdapterProbeEvidence({
			surfaceId: "edge.whatsapp",
			observedAt: "2026-05-31T09:00:00.000Z",
			allowRun: true,
		});
		writeJson(evidencePath, {
			...evidence,
			source: EDGE_ADAPTER_CONTRACT_PROBE_SOURCE,
			runtime: undefined,
		});

		const report = evaluateCutoverCheck(edgeAdapterCutoverBundle(evidencePath));

		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")?.detail).toContain(
			"schema-only edge contract-unit evidence",
		);
	});

	it("fails edge feature evidence when a required denial is missing", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-edge-cutover-"));
		const evidencePath = path.join(tempDir, "edge-whatsapp.json");
		const relayKeys = generateKeyPair();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;
		const evidence = buildEdgeAdapterProbeEvidence({
			surfaceId: "edge.whatsapp",
			observedAt: "2026-05-31T09:00:00.000Z",
			allowRun: true,
		});
		writeJson(evidencePath, {
			...evidence,
			controls: evidence.controls.filter((control) => control.name !== "credentials.raw-denied"),
		});

		const report = evaluateCutoverCheck(edgeAdapterCutoverBundle(evidencePath));

		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")?.detail).toContain(
			"control credentials.raw-denied is missing",
		);
	});
});

describe("Hermes cutover fixture evidence catalog validation", () => {
	it("fails unknown fixtures instead of accepting generic pass evidence", () => {
		const report = evaluateCutoverCheck(
			cutoverBundleWithGenericFixture("fixture.unregistered.self-reported"),
		);

		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "fixtures.pass")?.detail).toContain(
			"not registered in the fixture validator catalog",
		);
	});

	it("runs registered non-private fixtures through their specific validator", () => {
		const report = evaluateCutoverCheck(
			cutoverBundleWithGenericFixture("fixture.public.email.basic"),
		);

		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "fixtures.pass")?.detail).toContain(
			"invalid edge fixture evidence",
		);
	});

	it("requires private Telegram fixture evidence to carry a signed runner attestation", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-private-fixture-"));
		const bundle = cutoverBundle(
			writeNetworkBundle(tempDir, undefined, containedInternalNetworkEvidence),
		);
		const fixture = bundle.fixtureResults.results[0];
		const evidence = readJson<{ privateTelegramRunnerAttestation?: unknown }>(
			fixture.evidence_path,
		);
		delete evidence.privateTelegramRunnerAttestation;
		writeJson(fixture.evidence_path, evidence);

		const report = evaluateCutoverCheck(refreshCutoverProofBundle(bundle));

		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "fixtures.pass")?.detail).toContain(
			"privateTelegramRunnerAttestation is missing",
		);
	});

	it("rejects private Telegram fixture evidence mutated after runner attestation", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-private-fixture-"));
		const bundle = cutoverBundle(
			writeNetworkBundle(tempDir, undefined, containedInternalNetworkEvidence),
		);
		const fixture = bundle.fixtureResults.results[0];
		const evidence = readJson<{ checks: Array<{ detail: string }> }>(fixture.evidence_path);
		evidence.checks[0].detail = "tampered after signing";
		writeJson(fixture.evidence_path, evidence);

		const report = evaluateCutoverCheck(refreshCutoverProofBundle(bundle));

		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "fixtures.pass")?.detail).toContain(
			"privateTelegramRunnerAttestation checksSha256 mismatch",
		);
	});

	it("rejects private Telegram fixture evidence signed by an untrusted runner key", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-private-fixture-"));
		const trustedKeys = generateKeyPair();
		const attackerKeys = generateKeyPair();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = attackerKeys.privateKey;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = attackerKeys.publicKey;
		const fixtureResults = writeFixtureResults();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = trustedKeys.privateKey;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = trustedKeys.publicKey;
		const base = cutoverBundle(
			writeNetworkBundle(tempDir, undefined, containedInternalNetworkEvidence),
		);
		const { cutoverProofBundle: _cutoverProofBundle, ...baseWithoutProof } = base;
		const withoutProof: CutoverBundleWithoutProof = {
			...baseWithoutProof,
			fixtureResults,
		};
		const bundle = {
			...withoutProof,
			cutoverProofBundle: makeCutoverProofBundle(withoutProof),
		};

		const report = evaluateCutoverCheck(bundle);

		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "fixtures.pass")?.detail).toContain(
			"privateTelegramRunnerAttestation signature is invalid: signature verification failed",
		);
	});
});

describe("Hermes cutover cli-headless relay proof validation", () => {
	it("accepts cli-headless evidence only with a trusted signed relay proof", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cli-headless-cutover-"));
		const relayKeys = generateKeyPair();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;
		const evidencePath = path.join(tempDir, "execution-cli-headless.json");
		writeCliHeadlessEvidence(evidencePath, cliHeadlessRelayProof());
		const bundle = cliHeadlessCutoverBundle(evidencePath);
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;

		const report = evaluateCutoverCheck(bundle);

		expect(report.status).toBe("safe");
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "pass",
		});
	});

	it("rejects cli-headless evidence when a signed relay proof field is tampered", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cli-headless-cutover-"));
		const relayKeys = generateKeyPair();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;
		const evidencePath = path.join(tempDir, "execution-cli-headless.json");
		const signedProof = cliHeadlessRelayProof();
		writeCliHeadlessEvidence(evidencePath, { ...signedProof, model: "gpt-5.5" });
		const bundle = cliHeadlessCutoverBundle(evidencePath);
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;

		const report = evaluateCutoverCheck(bundle);

		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")?.detail).toContain(
			"relay proof signature is invalid",
		);
	});

	it("rejects cli-headless evidence when the signed relay proof is for a different proof token", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cli-headless-cutover-"));
		const relayKeys = generateKeyPair();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;
		const evidencePath = path.join(tempDir, "execution-cli-headless.json");
		writeCliHeadlessEvidence(
			evidencePath,
			cliHeadlessRelayProof({
				proofTokenSha256: openAiCodexRelayProofTokenSha256("HERMES_OK_DIFFERENT_GATE"),
			}),
		);
		const bundle = cliHeadlessCutoverBundle(evidencePath);
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;

		const report = evaluateCutoverCheck(bundle);

		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")?.detail).toContain(
			"relay proof proofTokenSha256 does not match expected proof token",
		);
	});

	it("rejects cli-headless evidence signed by an untrusted relay key", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cli-headless-cutover-"));
		const trustedKeys = generateKeyPair();
		const attackerKeys = generateKeyPair();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = attackerKeys.privateKey;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = attackerKeys.publicKey;
		const forgedProof = cliHeadlessRelayProof();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = trustedKeys.privateKey;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = trustedKeys.publicKey;
		const evidencePath = path.join(tempDir, "execution-cli-headless.json");
		writeCliHeadlessEvidence(evidencePath, forgedProof);
		const bundle = cliHeadlessCutoverBundle(evidencePath);
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = trustedKeys.publicKey;

		const report = evaluateCutoverCheck(bundle);

		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")?.detail).toContain(
			"relay proof signature is invalid: signature verification failed",
		);
	});

	it("fails closed when the trusted operator relay public key is missing", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-cli-headless-cutover-"));
		const relayKeys = generateKeyPair();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
		delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		const evidencePath = path.join(tempDir, "execution-cli-headless.json");
		writeCliHeadlessEvidence(evidencePath, cliHeadlessRelayProof());
		const bundle = cliHeadlessCutoverBundle(evidencePath, () => {
			delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		});

		const report = evaluateCutoverCheck(bundle);

		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")?.detail).toContain(
			"relay proof signature is invalid: missing relay public key env OPERATOR_RPC_RELAY_PUBLIC_KEY",
		);
	});
});

describe("Hermes cutover network evidence validation", () => {
	it("fails no-fork cutover proof without a signed wrapper-run attestation", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-nofork-attestation-"));
		const bundle = cutoverBundle(
			writeNetworkBundle(tempDir, undefined, containedInternalNetworkEvidence),
		);
		const noForkProof = { ...bundle.noForkProof };
		delete (noForkProof as Record<string, unknown>).runnerAttestation;
		writeJson(noForkProof.evidence_path, noForkProof);

		const report = evaluateCutoverCheck(cutoverBundleWithNoForkProof(noForkProof));

		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "nofork.clean")?.detail).toContain(
			"no-fork evidence runnerAttestation is missing",
		);
	});

	it("fails no-fork cutover proof when the wrapper-run attestation was tampered", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-nofork-attestation-"));
		const bundle = cutoverBundle(
			writeNetworkBundle(tempDir, undefined, containedInternalNetworkEvidence),
		);
		const runnerAttestation = bundle.noForkProof.runnerAttestation;
		if (!runnerAttestation) throw new Error("test no-fork proof lacks runnerAttestation");
		const noForkProof = {
			...bundle.noForkProof,
			runnerAttestation: {
				...runnerAttestation,
				p0Status: "fail",
			},
		};
		writeJson(noForkProof.evidence_path, noForkProof);

		const report = evaluateCutoverCheck(cutoverBundleWithNoForkProof(noForkProof));

		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "nofork.clean")?.detail).toContain(
			"no-fork runner attestation signature is invalid",
		);
	});

	it("passes only after reopening every required and extra network evidence file", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-cutover-"));
		const networkProbes = writeNetworkBundle(
			tempDir,
			[...REQUIRED_CUTOVER_NETWORK_PROBE_IDS, "network.extra-provider-denied"],
			containedInternalNetworkEvidence,
		);

		const report = evaluateCutoverCheck(cutoverBundle(networkProbes));

		expect(report.exitCode).toBe(0);
		expect(report.status).toBe("safe");
		expect(report.gates.find((gate) => gate.name === "networkProbes.pass")).toMatchObject({
			status: "pass",
		});
	});

	it("fails when required network evidence lacks a passing firewall sentinel", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-cutover-"));
		const networkProbes = writeNetworkBundle(tempDir);
		const probe = networkProbes.probes[0];
		writeJson(
			probe.evidence_path,
			networkEvidence(probe.id, probe.evidence_path, {
				attempts: [networkPolicyAttempt(probe.id)],
			}),
		);

		expect(networkGateDetail(networkProbes)).toContain(
			"network probe evidence network.relay-control-allowed firewall_sentinel attempt is missing or not pass",
		);
	});

	it("accepts contained-internal network evidence without a firewall sentinel", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-cutover-"));
		const networkProbes = writeNetworkBundle(tempDir, undefined, containedInternalNetworkEvidence);

		const report = evaluateCutoverCheck(cutoverBundle(networkProbes));

		expect(report.exitCode).toBe(0);
		expect(report.status).toBe("safe");
		expect(report.gates.find((gate) => gate.name === "networkProbes.pass")).toMatchObject({
			status: "pass",
		});
	});

	it("fails signed contained-internal provider denial evidence that only proves a generic provider", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-cutover-"));
		const networkProbes = writeNetworkBundle(tempDir, undefined, containedInternalNetworkEvidence);
		const probe = networkProbes.probes.find(
			(candidate) => candidate.id === "network.direct-provider-denied",
		);
		if (!probe) throw new Error("missing direct-provider probe");
		writeJson(
			probe.evidence_path,
			containedInternalNetworkEvidence(probe.id, probe.evidence_path, {
				attempts: [
					{
						name: "provider",
						kind: "http",
						target: "https://provider.internal/probe",
						expectation: "deny",
						status: "pass",
						observed: "denied",
						detail: "target was actively denied with ENETUNREACH",
						durationMs: 1,
						errorName: "TypeError",
						errorCode: "ENETUNREACH",
					},
				],
			}),
		);

		expect(networkGateDetail(networkProbes)).toContain(
			"network probe evidence network.direct-provider-denied provider:bank contained-internal denial proof is missing or not pass",
		);
	});

	it("fails Hermes cutover network evidence that selects the agent-iptables posture", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-cutover-"));
		const networkProbes = writeNetworkBundle(tempDir, undefined, (id, evidencePath) =>
			networkEvidence(id, evidencePath, { posture: "agent-iptables" }),
		);

		expect(networkGateDetail(networkProbes)).toContain(
			"network probe evidence network.relay-control-allowed posture is agent-iptables; expected contained-internal",
		);
	});

	it("fails Hermes cutover network evidence that omits the pinned posture", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-cutover-"));
		const networkProbes = writeNetworkBundle(tempDir);

		expect(networkGateDetail(networkProbes)).toContain(
			"network probe evidence network.relay-control-allowed posture is missing; expected contained-internal",
		);
	});

	it("fails contained-internal evidence without connection-layer denial proof", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-cutover-"));
		const networkProbes = writeNetworkBundle(tempDir, undefined, containedInternalNetworkEvidence);
		const probe = networkProbes.probes.find(
			(candidate) => candidate.id === "network.direct-model-provider-denied",
		);
		if (!probe) throw new Error("missing direct-model probe");
		writeJson(
			probe.evidence_path,
			containedInternalNetworkEvidence(probe.id, probe.evidence_path, {
				attempts: [
					{
						name: "model-provider",
						kind: "http",
						target: "https://chatgpt.com/backend-api/codex/models?client_version=1.0.0",
						expectation: "deny",
						status: "pass",
						observed: "policy_denied",
						detail: "target was denied by an in-process policy hook",
						httpStatus: 403,
					},
				],
			}),
		);

		expect(networkGateDetail(networkProbes)).toContain(
			"network probe evidence network.direct-model-provider-denied contained-internal denial proof is missing or not pass",
		);
	});

	it("fails passing network evidence without a runner attestation", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-cutover-"));
		const networkProbes = writeNetworkBundle(tempDir, undefined, containedInternalNetworkEvidence);
		const probe = networkProbes.probes[0];
		const evidence = containedInternalNetworkEvidence(probe.id, probe.evidence_path);
		delete evidence.attestation;
		writeJson(probe.evidence_path, evidence);

		expect(networkGateDetail(networkProbes)).toContain(
			"network probe evidence network.relay-control-allowed attestation is missing",
		);
	});

	it("fails passing network evidence mutated after runner attestation", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-cutover-"));
		const networkProbes = writeNetworkBundle(tempDir, undefined, containedInternalNetworkEvidence);
		const probe = networkProbes.probes.find(
			(candidate) => candidate.id === "network.direct-model-provider-denied",
		);
		if (!probe) throw new Error("missing direct-model probe");
		const evidence = containedInternalNetworkEvidence(probe.id, probe.evidence_path);
		evidence.attempts = [
			{
				...evidence.attempts[0],
				detail: "mutated denial detail after the attestation was signed",
			},
		];
		writeJson(probe.evidence_path, evidence);

		expect(networkGateDetail(networkProbes)).toContain(
			"network probe evidence network.direct-model-provider-denied attestation evidenceSha256 mismatch",
		);
	});

	it("fails dns-exfil evidence when dns_guard has no non-overridable resolved address", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-cutover-"));
		const networkProbes = writeNetworkBundle(tempDir);
		const probe = networkProbes.probes.find(
			(candidate) => candidate.id === "network.dns-exfil-denied",
		);
		if (!probe) throw new Error("missing dns-exfil probe");
		writeJson(
			probe.evidence_path,
			networkEvidence(probe.id, probe.evidence_path, {
				attempts: [
					firewallSentinelAttempt(),
					{
						name: "dns-exfil-guard",
						kind: "dns_guard",
						target: "http://169.254.169.254/latest/meta-data/",
						expectation: "deny",
						status: "pass",
						observed: "denied",
						detail: "DNS guard blocked the target but remains overridable",
						resolvedAddresses: [
							{
								address: "169.254.169.254",
								blocked: true,
								nonOverridable: false,
							},
						],
					},
				],
			}),
		);

		expect(networkGateDetail(networkProbes)).toContain(
			"network probe evidence network.dns-exfil-denied dns_guard lacks nonOverridable resolved address",
		);
	});

	it("fails when a passing bundle references missing per-probe evidence", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-cutover-"));
		const networkProbes = writeNetworkBundle(tempDir);
		networkProbes.probes[0] = {
			...networkProbes.probes[0],
			evidence_path: path.join(tempDir, "missing-relay-control.json"),
		};

		const detail = networkGateDetail(networkProbes);

		expect(detail).toContain("missing network probe evidence network.relay-control-allowed");
	});

	it.each([
		{
			name: "malformed JSON",
			write: (evidencePath: string, _id: string) => {
				fs.writeFileSync(evidencePath, "{not-json", "utf8");
			},
			detail: "unreadable network probe evidence network.relay-control-allowed",
		},
		{
			name: "wrong schema",
			write: (evidencePath: string, id: string) => {
				writeJson(evidencePath, networkEvidence(id, evidencePath, { schemaVersion: "wrong" }));
			},
			detail: "schemaVersion",
		},
		{
			name: "not ran",
			write: (evidencePath: string, id: string) => {
				writeJson(evidencePath, networkEvidence(id, evidencePath, { ran: false }));
			},
			detail: "ran is false",
		},
		{
			name: "non-pass status",
			write: (evidencePath: string, id: string) => {
				writeJson(evidencePath, networkEvidence(id, evidencePath, { status: "fail" }));
			},
			detail: "status is fail",
		},
		{
			name: "partial handwritten pass",
			write: (evidencePath: string, id: string) => {
				writeJson(evidencePath, {
					schemaVersion: NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION,
					id,
					status: "pass",
				});
			},
			detail: "ran",
		},
		{
			name: "empty attempts",
			write: (evidencePath: string, id: string) => {
				writeJson(evidencePath, networkEvidence(id, evidencePath, { attempts: [] }));
			},
			detail: "attempts are empty",
		},
		{
			name: "wrong evidence id",
			write: (evidencePath: string, _id: string) => {
				writeJson(evidencePath, networkEvidence("network.other", evidencePath));
			},
			detail: "id is network.other",
		},
		{
			name: "wrong evidence path",
			write: (evidencePath: string, id: string) => {
				writeJson(
					evidencePath,
					networkEvidence(id, path.join(path.dirname(evidencePath), "other.json")),
				);
			},
			detail: "evidence_path is",
		},
	])("fails when bundle pass is backed by $name evidence", ({ write, detail }) => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-cutover-"));
		const networkProbes = writeNetworkBundle(tempDir);
		const probe = networkProbes.probes[0];
		write(probe.evidence_path, probe.id);

		expect(networkGateDetail(networkProbes)).toContain(detail);
	});

	it("fails and redacts deterministic details from failed per-probe attempts", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-cutover-"));
		const networkProbes = writeNetworkBundle(tempDir, [
			...REQUIRED_CUTOVER_NETWORK_PROBE_IDS,
			"network.extra-provider-denied",
		]);
		const extraProbe = networkProbes.probes.at(-1);
		if (!extraProbe) throw new Error("missing extra probe fixture");
		writeJson(
			extraProbe.evidence_path,
			networkEvidence(extraProbe.id, extraProbe.evidence_path, {
				attempts: [
					{
						name: "extra-denial",
						kind: "http",
						target: "https://chatgpt.com/backend-api/codex/models?client_version=1.0.0",
						expectation: "deny",
						status: "fail",
						observed: "reachable",
						detail: "provider accepted credential sk-ant-1234567890abcdef",
						durationMs: 2,
						httpStatus: 200,
					},
				],
			}),
		);

		const firstDetail = networkGateDetail(networkProbes);
		const secondDetail = networkGateDetail(networkProbes);

		expect(firstDetail).toBe(secondDetail);
		expect(firstDetail).toContain(
			"network.extra-provider-denied attempt extra-denial status is fail",
		);
		expect(firstDetail).toContain("[REDACTED:anthropic_api_key]");
		expect(firstDetail).not.toContain("sk-ant-1234567890abcdef");
	});
});

describe("Hermes cutover model-relay evidence validation", () => {
	it("passes the model-relay feature probe only after reopening the observed evidence file", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-model-relay-cutover-"));
		const evidencePath = path.join(tempDir, "model-relay.json");
		writeJson(evidencePath, modelRelayEvidence());

		const report = evaluateCutoverCheck(modelRelayCutoverBundle(evidencePath));

		expect(report.status).toBe("safe");
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")).toMatchObject({
			status: "pass",
		});
	});

	it("fails when model-relay evidence omits a required live gate", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-model-relay-cutover-"));
		const evidencePath = path.join(tempDir, "model-relay.json");
		writeJson(
			evidencePath,
			modelRelayEvidence({
				gates: modelRelayEvidence().gates.filter((gate) => gate.name !== "directModel.denied"),
			}),
		);

		const report = evaluateCutoverCheck(modelRelayCutoverBundle(evidencePath));

		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")?.detail).toContain(
			"gate directModel.denied is missing",
		);
	});

	it("fails when model-relay evidence used a fake direct-model URL", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-model-relay-cutover-"));
		const evidencePath = path.join(tempDir, "model-relay.json");
		writeJson(
			evidencePath,
			modelRelayEvidence({
				observation: {
					relayUrl: "http://telclaude:8790/v1/models",
					directModelUrl: "http://127.0.0.1:9/v1/models",
					profileDir: "/home/hermes/.hermes",
					scannedProfileFiles: ["/home/hermes/.hermes/config.yaml"],
				},
			}),
		);

		const report = evaluateCutoverCheck(modelRelayCutoverBundle(evidencePath));

		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")?.detail).toContain(
			"observation.directModelUrl is not a recognized direct model-provider URL",
		);
	});

	it("fails when model-relay evidence omits contained-origin proof", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-model-relay-cutover-"));
		const evidencePath = path.join(tempDir, "model-relay.json");
		writeJson(
			evidencePath,
			modelRelayEvidence({
				gates: modelRelayEvidence().gates.filter((gate) => gate.name !== "modelRelay.origin"),
				origin: {
					kind: "unknown",
					detail: "model relay response did not include a server-observed peer header",
				},
			}),
		);

		const report = evaluateCutoverCheck(modelRelayCutoverBundle(evidencePath));

		expect(report.status).toBe("fail");
		const detail = report.gates.find((gate) => gate.name === "featureProbes.pass")?.detail;
		expect(detail).toContain("gate modelRelay.origin is missing");
		expect(detail).toContain("origin is not a server-observed tc-hermes-contained peer");
	});

	it("fails when model-relay evidence selects the agent-iptables posture", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-model-relay-cutover-"));
		const evidencePath = path.join(tempDir, "model-relay.json");
		writeJson(
			evidencePath,
			modelRelayEvidence({
				posture: "agent-iptables",
				gates: [
					...modelRelayEvidence().gates,
					{
						name: "firewall.sentinel",
						status: "pass",
						detail: "firewall sentinel is present",
					},
				],
			}),
		);

		const report = evaluateCutoverCheck(modelRelayCutoverBundle(evidencePath));

		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")?.detail).toContain(
			"posture is agent-iptables; expected contained-internal",
		);
	});

	it("fails when model-relay evidence omits the pinned posture", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-model-relay-cutover-"));
		const evidencePath = path.join(tempDir, "model-relay.json");
		const evidence = modelRelayEvidence();
		delete (evidence as Record<string, unknown>).posture;
		writeJson(evidencePath, evidence);

		const report = evaluateCutoverCheck(modelRelayCutoverBundle(evidencePath));

		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "featureProbes.pass")?.detail).toContain(
			"posture is missing; expected contained-internal",
		);
	});
});
