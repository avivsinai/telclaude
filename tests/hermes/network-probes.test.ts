import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
	NETWORK_PROBE_ATTESTATION_PATH,
	NETWORK_PROBE_ATTESTATION_RUNNER,
	NETWORK_PROBE_ATTESTATION_SOURCE,
	NETWORK_PROBE_RUNNER_RELAY_PRIVATE_KEY_ENV,
	NETWORK_PROBE_RUNNER_RELAY_PUBLIC_KEY_ENV,
	networkProbeAttestationFieldsForEvidence,
	networkProbeAttestationSignatureFailure,
	networkProbeEvidenceSha256,
	signNetworkProbeEvidenceAttestation,
} from "../../src/hermes/network-probe-attestation.js";
import {
	DEFAULT_FIREWALL_SENTINEL_PATH,
	type NetworkProbeRunnerReport,
	readHermesNetworkProbeRunReport,
	runHermesNetworkProbes,
} from "../../src/hermes/network-probes.js";
import { buildInternalResponseProof, generateKeyPair } from "../../src/internal-auth.js";

describe("Hermes network probes", () => {
	it("uses provider URL prefixes as provider-specific direct-deny attempt names", async () => {
		const restoreKeys = installNetworkProbeRunnerKeys();
		const policyDenied = await policyDeniedProbeUrl();
		const relay = await openProbeUrl();
		const fetchSpy = spyOnDeterministicDnsDenialFetch();
		try {
			const report = await runHermesNetworkProbes({
				allowRun: true,
				posture: "contained-internal",
				relayUrl: relay.url,
				providerUrls: requiredProviderUrls(policyDenied.url),
				vaultSocketPath: path.join(os.tmpdir(), "missing-hermes-vault.sock"),
				modelProviderUrl: policyDenied.url,
				dnsExfilUrls: [DETERMINISTIC_DNS_DENIAL_URL],
				firewallSentinelPath: path.join(os.tmpdir(), "missing-hermes-firewall-sentinel"),
				timeoutMs: 100,
				now: new Date("2026-06-01T09:10:00.000Z"),
			});
			const directProviderEvidence = report.evidence.find(
				(probe) => probe.id === "network.direct-provider-denied",
			);
			expect(directProviderEvidence?.attempts.map((attempt) => attempt.name)).toEqual([
				"provider:bank",
				"provider:clalit",
				"provider:government",
				"provider:google",
			]);
			expect(directProviderEvidence?.attempts.every((attempt) => attempt.status === "pass")).toBe(
				true,
			);
			expect(report.evidence.every((probe) => probe.attestation?.probeId === probe.id)).toBe(true);
			expect(
				report.evidence.every(
					(probe) =>
						probe.attestation &&
						networkProbeAttestationSignatureFailure(probe.attestation, {
							allowStale: true,
						}) === null,
				),
			).toBe(true);
			const reportPath = path.join(
				fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-report-")),
				"report.json",
			);
			const importableReport = resignReportEvidence(report, (probe) =>
				probe.id === "network.dns-exfil-denied"
					? {
							...probe,
							attempts: [metadataDnsGuardAttempt()],
						}
					: probe,
			);
			writeJson(reportPath, importableReport);
			expect(readHermesNetworkProbeRunReport(reportPath)).toMatchObject({ status: "pass" });

			const unsignedReport = cloneReport(importableReport);
			delete unsignedReport.evidence[0].attestation;
			writeJson(reportPath, unsignedReport);
			expect(() => readHermesNetworkProbeRunReport(reportPath)).toThrow(
				"network probe evidence network.relay-control-allowed attestation is missing",
			);

			const configurationOnlyReport = resignReportEvidence(importableReport, (probe) => ({
				...probe,
				attempts: [
					{
						name: `${probe.id}.configured`,
						kind: "configuration",
						target: probe.id,
						expectation: "configured",
						status: "pass",
						observed: "configured",
						detail: "schema-only configured proof",
					},
				],
			}));
			writeJson(reportPath, configurationOnlyReport);
			expect(() => readHermesNetworkProbeRunReport(reportPath)).toThrow(
				"network probe evidence network.relay-control-allowed contained-internal denial proof is missing or not pass",
			);

			const genericProviderReport = resignReportEvidence(importableReport, (probe) =>
				probe.id === "network.direct-provider-denied"
					? {
							...probe,
							attempts: [{ ...policyProviderDenialAttempt("generic"), name: "provider" }],
						}
					: probe,
			);
			writeJson(reportPath, genericProviderReport);
			expect(() => readHermesNetworkProbeRunReport(reportPath)).toThrow(
				"network probe evidence network.direct-provider-denied provider:bank contained-internal denial proof is missing or not pass",
			);

			const genericProviderSpecificReport = resignReportEvidence(importableReport, (probe) =>
				probe.id === "network.direct-provider-denied"
					? {
							...probe,
							attempts: requiredProviderNames().map((provider) =>
								provider === "bank"
									? genericProviderSpecificDenialAttempt(provider)
									: policyProviderDenialAttempt(provider),
							),
						}
					: probe,
			);
			writeJson(reportPath, genericProviderSpecificReport);
			expect(() => readHermesNetworkProbeRunReport(reportPath)).toThrow(
				"network probe evidence network.direct-provider-denied direct network denial lacks firewall_sentinel attribution",
			);

			const dnsGuardProviderReport = resignReportEvidence(importableReport, (probe) =>
				probe.id === "network.direct-provider-denied"
					? {
							...probe,
							attempts: requiredProviderNames().map((provider) =>
								provider === "bank"
									? dnsGuardProviderDenialAttempt(provider)
									: policyProviderDenialAttempt(provider),
							),
						}
					: probe,
			);
			writeJson(reportPath, dnsGuardProviderReport);
			expect(() => readHermesNetworkProbeRunReport(reportPath)).toThrow(
				"network probe evidence network.direct-provider-denied provider:bank contained-internal denial proof is missing or not pass",
			);

			const modelDnsGuardReport = resignReportEvidence(importableReport, (probe) =>
				probe.id === "network.direct-model-provider-denied"
					? {
							...probe,
							attempts: [metadataDnsGuardAttempt()],
						}
					: probe,
			);
			writeJson(reportPath, modelDnsGuardReport);
			expect(() => readHermesNetworkProbeRunReport(reportPath)).toThrow(
				"network probe evidence network.direct-model-provider-denied contained-internal denial proof is missing or not pass",
			);

			const vaultDnsGuardReport = resignReportEvidence(importableReport, (probe) =>
				probe.id === "network.direct-vault-denied"
					? {
							...probe,
							attempts: [metadataDnsGuardAttempt()],
						}
					: probe,
			);
			writeJson(reportPath, vaultDnsGuardReport);
			expect(() => readHermesNetworkProbeRunReport(reportPath)).toThrow(
				"network probe evidence network.direct-vault-denied contained-internal denial proof is missing or not pass",
			);

			const vaultGenericHttpReport = resignReportEvidence(importableReport, (probe) =>
				probe.id === "network.direct-vault-denied"
					? {
							...probe,
							attempts: [genericProviderDenialAttempt()],
						}
					: probe,
			);
			writeJson(reportPath, vaultGenericHttpReport);
			expect(() => readHermesNetworkProbeRunReport(reportPath)).toThrow(
				"network probe evidence network.direct-vault-denied direct network denial lacks firewall_sentinel attribution",
			);

			const mixedVaultUnattributedDirectReport = resignReportEvidence(importableReport, (probe) =>
				probe.id === "network.direct-vault-denied"
					? {
							...probe,
							attempts: [
								vaultSocketAbsentAttempt(),
								{
									...genericProviderDenialAttempt(),
									name: "vault-url",
									target: "https://vault.internal/probe",
								},
							],
						}
					: probe,
			);
			writeJson(reportPath, mixedVaultUnattributedDirectReport);
			expect(() => readHermesNetworkProbeRunReport(reportPath)).toThrow(
				"network probe evidence network.direct-vault-denied direct network denial lacks firewall_sentinel attribution",
			);

			const sentinelAttributedDirectDenialReport = resignReportEvidence(
				importableReport,
				(probe) => {
					if (probe.id === "network.direct-provider-denied") {
						return {
							...probe,
							attempts: [
								passingFirewallSentinelAttempt(),
								...requiredProviderNames().map((provider) =>
									genericProviderSpecificDenialAttempt(provider),
								),
							],
						};
					}
					if (probe.id === "network.direct-model-provider-denied") {
						return {
							...probe,
							attempts: [
								passingFirewallSentinelAttempt(),
								{
									...genericProviderDenialAttempt(),
									name: "model-provider",
									target: "https://chatgpt.com/backend-api/codex/models?client_version=1.0.0",
								},
							],
						};
					}
					if (probe.id === "network.direct-vault-denied") {
						return {
							...probe,
							attempts: [
								passingFirewallSentinelAttempt(),
								{
									...genericProviderDenialAttempt(),
									name: "vault-url",
									target: "https://vault.internal/probe",
								},
							],
						};
					}
					return probe;
				},
			);
			writeJson(reportPath, sentinelAttributedDirectDenialReport);
			const unsignedSentinelAttributedDirectDenialReport = cloneReport(
				sentinelAttributedDirectDenialReport,
			);
			for (const probe of unsignedSentinelAttributedDirectDenialReport.evidence) {
				delete probe.attestation;
			}
			writeJson(reportPath, unsignedSentinelAttributedDirectDenialReport);
			expect(() =>
				readHermesNetworkProbeRunReport(reportPath, { requireAttestation: false }),
			).toThrow(
				"network probe evidence network.direct-provider-denied direct network denial requires signed runner attestation",
			);

			const agentIptablesPosture = "agent-iptables" as const;
			const nonContainedSentinelAttributedReport = resignReportEvidence(
				sentinelAttributedDirectDenialReport,
				(probe) => ({ ...probe, posture: agentIptablesPosture }),
			);
			nonContainedSentinelAttributedReport.posture = agentIptablesPosture;
			writeJson(reportPath, nonContainedSentinelAttributedReport);
			expect(() => readHermesNetworkProbeRunReport(reportPath)).toThrow(
				"network probe evidence network.direct-provider-denied direct network denial requires contained-internal posture",
			);

			const nonContainedMixedVaultReport = resignReportEvidence(importableReport, (probe) => ({
				...probe,
				posture: "agent-iptables",
				attempts:
					probe.id === "network.direct-vault-denied"
						? [
								vaultSocketAbsentAttempt(),
								passingFirewallSentinelAttempt(),
								{
									...genericProviderDenialAttempt(),
									name: "vault-url",
									target: "https://vault.internal/probe",
								},
							]
						: probe.attempts,
			}));
			nonContainedMixedVaultReport.posture = "agent-iptables";
			writeJson(reportPath, nonContainedMixedVaultReport);
			expect(() => readHermesNetworkProbeRunReport(reportPath)).toThrow(
				"network probe evidence network.direct-vault-denied direct network denial requires contained-internal posture",
			);

			const overridableDnsGuardReport = resignReportEvidence(importableReport, (probe) =>
				probe.id === "network.dns-exfil-denied"
					? {
							...probe,
							attempts: [overridableDnsGuardAttempt()],
						}
					: probe,
			);
			writeJson(reportPath, overridableDnsGuardReport);
			expect(() => readHermesNetworkProbeRunReport(reportPath)).toThrow(
				"network probe evidence network.dns-exfil-denied contained-internal denial proof is missing or not pass",
			);

			const tamperedReport = cloneReport(importableReport);
			tamperedReport.evidence[1].attempts[0].detail = "mutated after signing";
			writeJson(reportPath, tamperedReport);
			expect(() => readHermesNetworkProbeRunReport(reportPath)).toThrow(
				"network probe evidence network.direct-provider-denied attestation attemptsSha256 mismatch",
			);

			const wrongAttestationSchemaReport = cloneReport(importableReport);
			if (!wrongAttestationSchemaReport.evidence[0].attestation) {
				throw new Error("missing attestation in test fixture");
			}
			wrongAttestationSchemaReport.evidence[0].attestation.schemaVersion = "wrong" as never;
			writeJson(reportPath, wrongAttestationSchemaReport);
			expect(() => readHermesNetworkProbeRunReport(reportPath)).toThrow(
				"network probe evidence network.relay-control-allowed attestation schemaVersion is invalid",
			);

			const restoreOperatorKeys = installOperatorRelayKeys();
			try {
				const legacyOperatorScopeReport = cloneReport(importableReport);
				legacyOperatorScopeReport.evidence = legacyOperatorScopeReport.evidence.map((probe) => ({
					...probe,
					attestation: legacyOperatorScopeNetworkProbeAttestation(probe) as never,
				}));
				writeJson(reportPath, legacyOperatorScopeReport);
				expect(() => readHermesNetworkProbeRunReport(reportPath)).toThrow(
					"network probe evidence network.relay-control-allowed attestation schemaVersion is invalid",
				);

				const operatorScopeReport = cloneReport(importableReport);
				operatorScopeReport.evidence = operatorScopeReport.evidence.map((probe) => ({
					...probe,
					attestation: operatorScopeNetworkProbeAttestation(probe) as never,
				}));
				writeJson(reportPath, operatorScopeReport);
				expect(() => readHermesNetworkProbeRunReport(reportPath)).toThrow(
					"network probe evidence network.relay-control-allowed attestation signature is invalid: scope mismatch",
				);
			} finally {
				restoreOperatorKeys();
			}

			const badSignatureReport = cloneReport(importableReport);
			if (!badSignatureReport.evidence[0].attestation) {
				throw new Error("missing attestation in test fixture");
			}
			badSignatureReport.evidence[0].attestation.signature.signature = "bad-signature";
			writeJson(reportPath, badSignatureReport);
			expect(() => readHermesNetworkProbeRunReport(reportPath)).toThrow(
				"network probe evidence network.relay-control-allowed attestation signature is invalid",
			);
		} finally {
			fetchSpy.mockRestore();
			restoreKeys();
			await policyDenied.close();
			await relay.close();
		}
	});

	it("does not count direct network errors as denial proof outside contained-internal", async () => {
		const restoreKeys = installNetworkProbeRunnerKeys();
		const relay = await openProbeUrl();
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-non-contained-"));
		const providerTarget = "http://192.0.2.10/probe";
		const modelTarget = "http://192.0.2.20/probe";
		const vaultTarget = "http://192.0.2.30/probe";
		const fetchSpy = spyOnNetworkProbeFetch({
			networkErrorTargets: [providerTarget, modelTarget, vaultTarget],
		});
		try {
			const firewallSentinelPath = path.join(tempDir, "firewall-active");
			fs.writeFileSync(firewallSentinelPath, "active\n", "utf8");
			const report = await runHermesNetworkProbes({
				allowRun: true,
				posture: "agent-iptables",
				relayUrl: relay.url,
				providerUrls: requiredProviderUrls(providerTarget),
				vaultUrl: vaultTarget,
				vaultSocketPath: path.join(tempDir, "missing-hermes-vault.sock"),
				modelProviderUrl: modelTarget,
				dnsExfilUrls: [DETERMINISTIC_DNS_DENIAL_URL],
				firewallSentinelPath,
				timeoutMs: 100,
				now: new Date("2026-06-01T09:10:00.000Z"),
			});
			const directProvider = report.evidence.find(
				(probe) => probe.id === "network.direct-provider-denied",
			);
			const directModel = report.evidence.find(
				(probe) => probe.id === "network.direct-model-provider-denied",
			);
			const directVault = report.evidence.find(
				(probe) => probe.id === "network.direct-vault-denied",
			);

			expect(report.status).toBe("fail");
			expect(
				directProvider?.attempts.find((attempt) => attempt.name === "provider:bank"),
			).toMatchObject({ status: "fail", observed: "inconclusive_error", errorCode: "ENETUNREACH" });
			expect(
				directModel?.attempts.find((attempt) => attempt.name === "model-provider"),
			).toMatchObject({ status: "fail", observed: "inconclusive_error", errorCode: "ENETUNREACH" });
			expect(directVault?.attempts.find((attempt) => attempt.name === "vault-url")).toMatchObject({
				status: "fail",
				observed: "inconclusive_error",
				errorCode: "ENETUNREACH",
			});
		} finally {
			fetchSpy.mockRestore();
			restoreKeys();
			await relay.close();
		}
	});

	it("does not attribute contained-internal direct network denials to a caller-selected sentinel path", async () => {
		const restoreKeys = installNetworkProbeRunnerKeys();
		const relay = await openProbeUrl();
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-network-custom-sentinel-"));
		const providerTarget = "http://192.0.2.10/probe";
		const fetchSpy = spyOnNetworkProbeFetch({
			networkErrorTargets: [providerTarget],
		});
		const realExistsSync = fs.existsSync;
		const existsSpy = vi.spyOn(fs, "existsSync").mockImplementation((candidate) => {
			if (candidate === DEFAULT_FIREWALL_SENTINEL_PATH) return false;
			return realExistsSync(candidate);
		});
		try {
			const callerSelectedSentinel = path.join(tempDir, "firewall-active");
			fs.writeFileSync(callerSelectedSentinel, "active\n", "utf8");
			const report = await runHermesNetworkProbes({
				allowRun: true,
				posture: "contained-internal",
				relayUrl: relay.url,
				providerUrls: requiredProviderUrls(providerTarget),
				vaultSocketPath: path.join(tempDir, "missing-hermes-vault.sock"),
				modelProviderUrl: "http://127.0.0.1/model",
				dnsExfilUrls: [DETERMINISTIC_DNS_DENIAL_URL],
				firewallSentinelPath: callerSelectedSentinel,
				timeoutMs: 100,
				now: new Date("2026-06-01T09:10:00.000Z"),
			});
			const directProvider = report.evidence.find(
				(probe) => probe.id === "network.direct-provider-denied",
			);

			expect(report.status).toBe("fail");
			expect(
				directProvider?.attempts.find((attempt) => attempt.name === "firewall-sentinel"),
			).toMatchObject({
				target: DEFAULT_FIREWALL_SENTINEL_PATH,
				status: "fail",
				observed: "missing",
			});
		} finally {
			existsSpy.mockRestore();
			fetchSpy.mockRestore();
			restoreKeys();
			await relay.close();
		}
	});

	it("fails contained-internal provider denial evidence without provider-specific targets", async () => {
		const restoreKeys = installNetworkProbeRunnerKeys();
		const policyDenied = await policyDeniedProbeUrl();
		const relay = await openProbeUrl();
		const fetchSpy = spyOnDeterministicDnsDenialFetch();
		try {
			const report = await runHermesNetworkProbes({
				allowRun: true,
				posture: "contained-internal",
				relayUrl: relay.url,
				providerUrls: [`bank=${policyDenied.url}`, policyDenied.url],
				vaultSocketPath: path.join(os.tmpdir(), "missing-hermes-vault.sock"),
				modelProviderUrl: policyDenied.url,
				dnsExfilUrls: [DETERMINISTIC_DNS_DENIAL_URL],
				firewallSentinelPath: path.join(os.tmpdir(), "missing-hermes-firewall-sentinel"),
				timeoutMs: 100,
				now: new Date("2026-06-01T09:10:00.000Z"),
			});
			const directProviderEvidence = report.evidence.find(
				(probe) => probe.id === "network.direct-provider-denied",
			);

			expect(report.status).toBe("fail");
			expect(directProviderEvidence).toMatchObject({ status: "fail" });
			expect(directProviderEvidence?.attempts).toEqual(
				expect.arrayContaining([
					expect.objectContaining({
						name: "provider:2.named",
						status: "fail",
						detail: expect.stringContaining("must name each provider"),
					}),
					expect.objectContaining({
						name: "provider:clalit.configured",
						status: "fail",
						detail: expect.stringContaining("missing provider:clalit"),
					}),
					expect.objectContaining({
						name: "provider:government.configured",
						status: "fail",
						detail: expect.stringContaining("missing provider:government"),
					}),
					expect.objectContaining({
						name: "provider:google.configured",
						status: "fail",
						detail: expect.stringContaining("missing provider:google"),
					}),
				]),
			);
		} finally {
			fetchSpy.mockRestore();
			restoreKeys();
			await policyDenied.close();
			await relay.close();
		}
	});
});

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

function spyOnNetworkProbeFetch(options: {
	readonly networkErrorTargets?: readonly string[];
}): ReturnType<typeof vi.spyOn> {
	const realFetch = globalThis.fetch;
	const networkErrorTargets = new Set(options.networkErrorTargets ?? []);
	return vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
		const target = fetchTarget(input);
		if (target === DETERMINISTIC_DNS_DENIAL_URL) {
			return Promise.reject(
				new TypeError("fetch failed", { cause: deterministicDnsDenialFetchCause() }),
			);
		}
		if (networkErrorTargets.has(target)) {
			const cause = new Error(`connect ENETUNREACH ${target}`) as Error & { code: string };
			cause.code = "ENETUNREACH";
			return Promise.reject(new TypeError("fetch failed", { cause }));
		}
		return realFetch(input, init);
	});
}

function installNetworkProbeRunnerKeys(): () => void {
	const originalPrivateKey = process.env[NETWORK_PROBE_RUNNER_RELAY_PRIVATE_KEY_ENV];
	const originalPublicKey = process.env[NETWORK_PROBE_RUNNER_RELAY_PUBLIC_KEY_ENV];
	const relayKeys = generateKeyPair();
	process.env[NETWORK_PROBE_RUNNER_RELAY_PRIVATE_KEY_ENV] = relayKeys.privateKey;
	process.env[NETWORK_PROBE_RUNNER_RELAY_PUBLIC_KEY_ENV] = relayKeys.publicKey;
	return () => {
		if (originalPrivateKey === undefined) {
			delete process.env[NETWORK_PROBE_RUNNER_RELAY_PRIVATE_KEY_ENV];
		} else {
			process.env[NETWORK_PROBE_RUNNER_RELAY_PRIVATE_KEY_ENV] = originalPrivateKey;
		}
		if (originalPublicKey === undefined) {
			delete process.env[NETWORK_PROBE_RUNNER_RELAY_PUBLIC_KEY_ENV];
		} else {
			process.env[NETWORK_PROBE_RUNNER_RELAY_PUBLIC_KEY_ENV] = originalPublicKey;
		}
	};
}

function installOperatorRelayKeys(): () => void {
	const originalPrivateKey = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
	const originalPublicKey = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
	const relayKeys = generateKeyPair();
	process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
	process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;
	return () => {
		if (originalPrivateKey === undefined) {
			delete process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
		} else {
			process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = originalPrivateKey;
		}
		if (originalPublicKey === undefined) {
			delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		} else {
			process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = originalPublicKey;
		}
	};
}

function operatorScopeNetworkProbeAttestation(
	evidence: NetworkProbeRunnerReport["evidence"][number],
) {
	const fields = networkProbeAttestationFieldsForEvidence(evidence);
	const payload = networkProbeAttestationSignedPayloadForTest(fields);
	return {
		...fields,
		signature: buildInternalResponseProof(
			"POST",
			NETWORK_PROBE_ATTESTATION_PATH,
			payload,
			payload,
			{
				scope: "operator",
			},
		),
	};
}

function legacyOperatorScopeNetworkProbeAttestation(
	evidence: NetworkProbeRunnerReport["evidence"][number],
) {
	const fields = {
		schemaVersion: "telclaude.hermes.network-probe-attestation.v1",
		source: NETWORK_PROBE_ATTESTATION_SOURCE,
		runner: NETWORK_PROBE_ATTESTATION_RUNNER,
		probeEvidenceSchemaVersion: evidence.schemaVersion,
		probeId: evidence.id,
		posture: evidence.posture ?? "agent-iptables",
		status: evidence.status,
		ran: evidence.ran,
		generatedAt: evidence.generatedAt,
		attemptsSha256: sha256Digest(JSON.stringify(evidence.attempts)),
		evidenceSha256: networkProbeEvidenceSha256(evidence),
	};
	const payload = networkProbeAttestationSignedPayloadForTest(fields);
	return {
		...fields,
		signature: buildInternalResponseProof(
			"POST",
			"/v1/hermes.network-probe.attestation",
			payload,
			payload,
			{ scope: "operator" },
		),
	};
}

function networkProbeAttestationSignedPayloadForTest(attestation: {
	readonly schemaVersion: string;
	readonly source: string;
	readonly runner: string;
	readonly probeEvidenceSchemaVersion: string;
	readonly probeId: string;
	readonly posture: string;
	readonly status: string;
	readonly ran: boolean;
	readonly generatedAt: string;
	readonly attemptsSha256: `sha256:${string}`;
	readonly evidenceSha256: `sha256:${string}`;
}): string {
	return JSON.stringify({
		schemaVersion: attestation.schemaVersion,
		source: attestation.source,
		runner: attestation.runner,
		probeEvidenceSchemaVersion: attestation.probeEvidenceSchemaVersion,
		probeId: attestation.probeId,
		posture: attestation.posture,
		status: attestation.status,
		ran: attestation.ran,
		generatedAt: attestation.generatedAt,
		attemptsSha256: attestation.attemptsSha256,
		evidenceSha256: attestation.evidenceSha256,
	});
}

function sha256Digest(value: string): `sha256:${string}` {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function metadataDnsGuardAttempt() {
	return {
		name: "dns-exfil-1",
		kind: "dns_guard" as const,
		target: "http://169.254.169.254/latest/meta-data/",
		expectation: "deny" as const,
		status: "pass" as const,
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
	};
}

function overridableDnsGuardAttempt() {
	return {
		...metadataDnsGuardAttempt(),
		target: "http://10.0.0.1/",
		resolvedAddresses: [
			{
				address: "10.0.0.1",
				blocked: true,
				nonOverridable: false,
			},
		],
	};
}

function genericProviderDenialAttempt() {
	return {
		name: "provider",
		kind: "http" as const,
		target: "https://provider.internal/probe",
		expectation: "deny" as const,
		status: "pass" as const,
		observed: "denied",
		detail: "target was actively denied with ENETUNREACH",
		durationMs: 1,
		errorName: "TypeError",
		errorCode: "ENETUNREACH",
	};
}

function genericProviderSpecificDenialAttempt(provider: string) {
	return {
		...genericProviderDenialAttempt(),
		name: `provider:${provider}`,
	};
}

function vaultSocketAbsentAttempt() {
	return {
		name: "vault-socket",
		kind: "unix_socket" as const,
		target: "/run/vault/vault.sock",
		expectation: "deny" as const,
		status: "pass" as const,
		observed: "absent",
		detail: "vault socket path is absent from the probe environment",
	};
}

function passingFirewallSentinelAttempt() {
	return {
		name: "firewall-sentinel",
		kind: "firewall_sentinel" as const,
		target: "/run/telclaude/firewall-active",
		expectation: "present" as const,
		status: "pass" as const,
		observed: "present",
		detail: "firewall sentinel is present",
	};
}

function policyProviderDenialAttempt(provider: string) {
	return {
		name: `provider:${provider}`,
		kind: "http" as const,
		target: `https://${provider}.provider.internal/probe`,
		expectation: "deny" as const,
		status: "pass" as const,
		observed: "policy_denied",
		detail: "target was denied by the Telclaude network policy proxy",
		durationMs: 1,
		httpStatus: 403,
	};
}

function dnsGuardProviderDenialAttempt(provider: string) {
	return {
		name: `provider:${provider}`,
		kind: "dns_guard" as const,
		target: `https://${provider}.provider.internal/probe`,
		expectation: "deny" as const,
		status: "pass" as const,
		observed: "denied",
		detail: "DNS guard should not satisfy provider direct HTTP denial",
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
	};
}

function cloneReport(report: NetworkProbeRunnerReport): NetworkProbeRunnerReport {
	return JSON.parse(JSON.stringify(report)) as NetworkProbeRunnerReport;
}

function resignReportEvidence(
	report: NetworkProbeRunnerReport,
	mutate: (
		probe: NetworkProbeRunnerReport["evidence"][number],
	) => NetworkProbeRunnerReport["evidence"][number],
): NetworkProbeRunnerReport {
	const updated = cloneReport(report);
	updated.evidence = updated.evidence.map((probe) => {
		const mutated = mutate(probe);
		delete mutated.attestation;
		return {
			...mutated,
			attestation: signNetworkProbeEvidenceAttestation(mutated),
		};
	});
	updated.bundle = {
		schemaVersion: 1,
		probes: updated.evidence.map((probe) => ({
			id: probe.id,
			status: probe.status === "pass" ? "pass" : "fail",
			evidence_path: probe.evidence_path,
		})),
	};
	return updated;
}

function writeJson(filePath: string, value: unknown): void {
	fs.mkdirSync(path.dirname(filePath), { recursive: true });
	fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function openProbeUrl(): Promise<{ url: string; close: () => Promise<void> }> {
	const server = http.createServer((_request, response) => {
		response.statusCode = 204;
		response.end();
	});
	await new Promise<void>((resolve, reject) => {
		server.once("error", reject);
		server.listen(0, "127.0.0.1", resolve);
	});
	const address = server.address();
	if (!address || typeof address === "string") {
		throw new Error("expected TCP server address");
	}
	return {
		url: `http://127.0.0.1:${address.port}/health`,
		close: () =>
			new Promise((resolve, reject) => {
				server.close((error) => (error ? reject(error) : resolve()));
			}),
	};
}

async function policyDeniedProbeUrl(): Promise<{ url: string; close: () => Promise<void> }> {
	const server = http.createServer((_request, response) => {
		response.statusCode = 403;
		response.setHeader("x-telclaude-network-policy", "denied");
		response.end("denied");
	});
	await new Promise<void>((resolve, reject) => {
		server.once("error", reject);
		server.listen(0, "127.0.0.1", resolve);
	});
	const address = server.address();
	if (!address || typeof address === "string") {
		throw new Error("expected TCP server address");
	}
	return {
		url: `http://127.0.0.1:${address.port}/probe`,
		close: () =>
			new Promise((resolve, reject) => {
				server.close((error) => (error ? reject(error) : resolve()));
			}),
	};
}

function requiredProviderUrls(url: string): string[] {
	return requiredProviderNames().map((name) => `${name}=${url}`);
}

function requiredProviderNames(): string[] {
	return ["bank", "clalit", "government", "google"];
}
