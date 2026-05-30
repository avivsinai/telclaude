import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
	type CompatibilityLockfile,
	type CutoverInputBundle,
	computeHermesArtifactDigest,
	evaluateCutoverCheck,
	type FeatureProbeMatrix,
	NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION,
	type ProbeBundle,
	REQUIRED_CUTOVER_NETWORK_PROBE_IDS,
} from "../../src/hermes/foundation.js";

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
	adapterApiSignatures: { "edge.whatsapp": "sha256:adapter-signature" },
	capabilities: {
		plugins: ["platform-adapter"],
		mcp: ["stdio"],
		modelProviders: ["custom-provider"],
		memoryProviders: ["custom-memory"],
	},
	requiredUpgradeTests: ["pnpm dev hermes prove --upstream-clean --p0"],
	generatedProfileSchemaVersion: "1",
	wrapperPackageVersion: "0.7.1",
	paritySuiteDigests: { p0: "sha256:p0" },
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

function cutoverBundle(networkProbes: ProbeBundle): CutoverInputBundle {
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
		lockfile: compatLockfile,
		featureProbeMatrix,
		fixtureResults: {
			schemaVersion: 1,
			results: [
				{
					id: "fixture.private.telegram.basic",
					status: "pass",
					evidence_path: "artifacts/hermes/private-telegram.json",
				},
				{
					id: "fixture.private.telegram.basic.deny",
					status: "pass",
					evidence_path: "artifacts/hermes/private-telegram-deny.json",
				},
			],
		},
		noForkProof: {
			schemaVersion: 1,
			hermesCheckoutClean: true,
			evidence_path: "artifacts/hermes/no-fork.json",
		},
		networkProbes,
		queueSnapshot: { unownedActiveCount: 0 },
		rollbackRehearsal: {
			schemaVersion: 1,
			passed: true,
			evidence_path: "artifacts/hermes/rollback.json",
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
		const probe = networkProbes.probes.find((candidate) => candidate.id === "network.dns-exfil-denied");
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
