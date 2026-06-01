import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
	networkProbeAttestationSignatureFailure,
	signNetworkProbeEvidenceAttestation,
} from "../../src/hermes/network-probe-attestation.js";
import {
	type NetworkProbeRunnerReport,
	networkProbeEvidenceFailure,
	readHermesNetworkProbeRunReport,
	runHermesNetworkProbes,
} from "../../src/hermes/network-probes.js";
import { generateKeyPair } from "../../src/internal-auth.js";

describe("Hermes network probes", () => {
	it("uses provider URL prefixes as provider-specific direct-deny attempt names", async () => {
		const restoreKeys = installOperatorRelayKeys();
		const deniedProviderUrl = await closedProbeUrl();
		const relay = await openProbeUrl();
		try {
			const report = await runHermesNetworkProbes({
				allowRun: true,
				posture: "contained-internal",
				relayUrl: relay.url,
				providerUrls: [`bank=${deniedProviderUrl}`, `clalit=${deniedProviderUrl}`],
				vaultSocketPath: path.join(os.tmpdir(), "missing-hermes-vault.sock"),
				modelProviderUrl: await closedProbeUrl(),
				dnsExfilUrls: [await closedProbeUrl()],
				firewallSentinelPath: path.join(os.tmpdir(), "missing-hermes-firewall-sentinel"),
				timeoutMs: 100,
				now: new Date("2026-06-01T09:10:00.000Z"),
			});
			const directProviderEvidence = report.evidence.find(
				(probe) => probe.id === "network.direct-provider-denied",
			);
			if (!directProviderEvidence) {
				throw new Error("missing direct-provider network evidence");
			}

			expect(directProviderEvidence.attempts.map((attempt) => attempt.name)).toEqual([
				"provider:bank",
				"provider:clalit",
			]);
			expect(directProviderEvidence.attempts.every((attempt) => attempt.status === "pass")).toBe(
				true,
			);
			expect(
				networkProbeEvidenceFailure(directProviderEvidence, {
					expectedId: "network.direct-provider-denied",
					requiredAttemptNames: ["provider:bank"],
				}),
			).toBeNull();
			expect(
				networkProbeEvidenceFailure(directProviderEvidence, {
					expectedId: "network.direct-provider-denied",
					requiredAttemptNames: ["provider:google"],
				}),
			).toContain("attempt provider:google is missing");
			const unsignedDirectProviderEvidence = cloneReport({
				...report,
				evidence: [directProviderEvidence],
			}).evidence[0];
			delete unsignedDirectProviderEvidence.attestation;
			expect(
				networkProbeEvidenceFailure(unsignedDirectProviderEvidence, {
					expectedId: "network.direct-provider-denied",
					requiredAttemptNames: ["provider:bank"],
				}),
			).toContain("attestation is missing");
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
			restoreKeys();
			await relay.close();
		}
	});
});

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

async function closedProbeUrl(): Promise<string> {
	const server = net.createServer();
	await new Promise<void>((resolve, reject) => {
		server.once("error", reject);
		server.listen(0, "127.0.0.1", resolve);
	});
	const address = server.address();
	if (!address || typeof address === "string") {
		throw new Error("expected TCP server address");
	}
	await new Promise<void>((resolve, reject) => {
		server.close((error) => (error ? reject(error) : resolve()));
	});
	return `http://127.0.0.1:${address.port}/probe`;
}
