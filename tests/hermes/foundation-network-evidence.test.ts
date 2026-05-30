import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
	type CompatibilityLockfile,
	type CutoverInputBundle,
	collectFeatureProbeEvidence,
	computeHermesArtifactDigest,
	evaluateCutoverCheck,
	type FeatureProbeMatrix,
	HERMES_ROLLBACK_CONTROL_SURFACE,
	HERMES_ROLLBACK_OBSERVATION_SURFACE,
	NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION,
	type ProbeBundle,
	REQUIRED_CUTOVER_NETWORK_PROBE_IDS,
} from "../../src/hermes/foundation.js";
import { buildInternalResponseProof, generateKeyPair } from "../../src/internal-auth.js";

const hermesPin = { version: "0.15.1" };

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

function networkEvidence(
	id: string,
	evidencePath: string,
	overrides: Record<string, unknown> = {},
) {
	return {
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
) {
	const probes = ids.map((id) => {
		const evidencePath = path.join(tempDir, `${id.replace(/^network\./, "")}.json`);
		writeJson(evidencePath, networkEvidence(id, evidencePath));
		return { id, status: "pass" as const, evidence_path: evidencePath };
	});
	return { schemaVersion: 1 as const, probes };
}

function writeNoForkProof() {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-nofork-"));
	const evidencePath = path.join(tempDir, "no-fork.json");
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
		],
	};
	writeJson(evidencePath, proof);
	return proof;
}

function writeRollbackRehearsal() {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-rollback-"));
	const evidencePath = path.join(tempDir, "rollback-rehearsal.json");
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
	};
	writeJson(evidencePath, rehearsal);
	return rehearsal;
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
	const results = ["fixture.private.telegram.basic", "fixture.private.telegram.basic.deny"].map(
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
	return { schemaVersion: 1 as const, results };
}

function modelRelayEvidence(overrides: Record<string, unknown> = {}) {
	return {
		schemaVersion: "telclaude.hermes.model-relay.v1",
		probeId: "model.relay",
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
				name: "firewall.sentinel",
				status: "pass",
				detail: "firewall sentinel is present",
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
			directModelUrl: "https://api.anthropic.com/v1/models",
			profileDir: "/home/hermes/.hermes",
			scannedProfileFiles: ["/home/hermes/.hermes/config.yaml"],
		},
		...overrides,
	};
}

function cutoverBundle(networkProbes: ProbeBundle): CutoverInputBundle {
	const noForkProof = writeNoForkProof();
	return {
		schemaVersion: 1,
		inventory: {
			generatedAt: "2026-05-30T00:00:00Z",
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
		networkProbes,
		queueSnapshot: { unownedActiveCount: 0 },
		rollbackRehearsal: writeRollbackRehearsal(),
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
	const base = cutoverBundle(writeNetworkBundle(tempDir));
	return {
		...base,
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
		lockfile: {
			...base.lockfile,
			featureProbeMatrixDigest: computeHermesArtifactDigest(matrix),
			featureProbes: [
				{
					surface_id: "model.relay",
					status: "pass",
					evidence_path: evidencePath,
				},
			],
			adapterApiSignatures: { "model.relay": `sha256:${"c".repeat(64)}` },
		},
	};
}

function networkGateDetail(networkProbes: ProbeBundle): string {
	const report = evaluateCutoverCheck(cutoverBundle(networkProbes));
	return report.gates.find((gate) => gate.name === "networkProbes.pass")?.detail ?? "";
}

describe("Hermes cutover network evidence validation", () => {
	it("passes only after reopening every required and extra network evidence file", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-cutover-"));
		const networkProbes = writeNetworkBundle(tempDir, [
			...REQUIRED_CUTOVER_NETWORK_PROBE_IDS,
			"network.extra-provider-denied",
		]);

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
						target: "https://api.anthropic.com/v1/models",
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

	it("fails when model-relay evidence omits firewall or contained-origin proof", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-model-relay-cutover-"));
		const evidencePath = path.join(tempDir, "model-relay.json");
		writeJson(
			evidencePath,
			modelRelayEvidence({
				gates: modelRelayEvidence().gates.filter(
					(gate) => gate.name !== "firewall.sentinel" && gate.name !== "modelRelay.origin",
				),
				origin: {
					kind: "unknown",
					detail: "model relay response did not include a server-observed peer header",
				},
			}),
		);

		const report = evaluateCutoverCheck(modelRelayCutoverBundle(evidencePath));

		expect(report.status).toBe("fail");
		const detail = report.gates.find((gate) => gate.name === "featureProbes.pass")?.detail;
		expect(detail).toContain("gate firewall.sentinel is missing");
		expect(detail).toContain("gate modelRelay.origin is missing");
		expect(detail).toContain("origin is not a server-observed tc-hermes-contained peer");
	});
});
