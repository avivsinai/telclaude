import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
	networkProbeAttestationSignatureFailure,
	signNetworkProbeEvidenceAttestation,
} from "../../src/hermes/network-probe-attestation.js";
import {
	type NetworkProbeRunnerReport,
	readHermesNetworkProbeRunReport,
	runHermesNetworkProbes,
} from "../../src/hermes/network-probes.js";
import { generateKeyPair } from "../../src/internal-auth.js";

describe("Hermes network probes", () => {
	it("uses provider URL prefixes as provider-specific direct-deny attempt names", async () => {
		const restoreKeys = installOperatorRelayKeys();
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
							attempts: [genericProviderDenialAttempt()],
						}
					: probe,
			);
			writeJson(reportPath, genericProviderReport);
			expect(() => readHermesNetworkProbeRunReport(reportPath)).toThrow(
				"network probe evidence network.direct-provider-denied contained-internal denial proof is missing or not pass",
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
				"network probe evidence network.direct-provider-denied provider:bank contained-internal denial proof is missing or not pass",
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
				"network probe evidence network.direct-vault-denied contained-internal denial proof is missing or not pass",
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

	it("fails contained-internal provider denial evidence without provider-specific targets", async () => {
		const restoreKeys = installOperatorRelayKeys();
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
