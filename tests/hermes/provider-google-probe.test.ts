import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION } from "../../src/hermes/network-probe-schema.js";
import {
	buildGoogleProviderFixtureEvidenceBundle,
	googleProviderFixtureEvidenceFailure,
	googleProviderProbeEvidenceFailure,
	runTelclaudeGoogleProviderProbe,
} from "../../src/hermes/provider-google-probe.js";

describe("Hermes Google provider probe", () => {
	it("passes only after exercising Google read, prepare, approved execute, actor, replay, and credential checks", async () => {
		const evidence = await runTelclaudeGoogleProviderProbe({
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(evidence.status).toBe("pass");
		expect(evidence.observations.providerProxyCallCount).toBe(2);
		expect(evidence.observations.approvalVerifierCallCount).toBeGreaterThanOrEqual(1);
		expect(evidence.observations.sidecarVerifierCallCount).toBeGreaterThanOrEqual(2);
		expect(evidence.observations.sidecarReplayCode).toBe("approval_replayed");
		expect(evidence.observations.ledgerReplayCode).toBe("effect_already_executed");
		expect(evidence.observations.rawOAuthObserved).toBe(false);
		expect(googleProviderProbeEvidenceFailure(evidence)).toBeNull();
	});

	it("rejects evidence missing wrong-actor denial", async () => {
		const evidence = await runTelclaudeGoogleProviderProbe({
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(
			googleProviderProbeEvidenceFailure({
				...evidence,
				checks: evidence.checks.filter((check) => check.name !== "google.wrong-actor-denied"),
			}),
		).toContain("check google.wrong-actor-denied is missing");
	});

	it("rejects pass-looking evidence without the Google provider proxy calls", async () => {
		const evidence = await runTelclaudeGoogleProviderProbe({
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(
			googleProviderProbeEvidenceFailure({
				...evidence,
				observations: {
					...evidence.observations,
					providerProxyCallCount: 1,
				},
			}),
		).toContain("providerProxyCallCount is 1");
	});

	it("rejects evidence produced without --allow-run", async () => {
		const evidence = await runTelclaudeGoogleProviderProbe({
			allowRun: false,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(evidence.status).toBe("fail");
		expect(googleProviderProbeEvidenceFailure(evidence)).toContain("harness did not run");
	});

	it("builds Google provider fixture evidence bound to the probe artifact", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "google-provider-fixtures-"));
		const probePath = await writeGoogleProviderProbeArtifact(tempDir);
		const networkProbePath = writeGoogleProviderNetworkProbeArtifact(tempDir, ["provider:google"]);
		const bundle = buildGoogleProviderFixtureEvidenceBundle({
			evidenceDir: path.join(tempDir, "fixtures"),
			probePath,
			networkProbePath,
			observedAt: "2026-06-01T09:10:00.000Z",
		});

		expect(bundle.results).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ id: "fixture.providers.google.read", status: "pass" }),
				expect.objectContaining({
					id: "fixture.providers.google.approved-write",
					status: "pass",
				}),
				expect.objectContaining({ id: "fixture.providers.google.replay-deny", status: "pass" }),
				expect.objectContaining({
					id: "fixture.providers.google.direct-provider-deny",
					status: "pass",
				}),
			]),
		);
		const readEvidence = bundle.evidence.find(
			(evidence) => evidence.id === "fixture.providers.google.read",
		);
		expect(
			googleProviderFixtureEvidenceFailure("fixture.providers.google.read", readEvidence),
		).toBeNull();
		const directEvidence = bundle.evidence.find(
			(evidence) => evidence.id === "fixture.providers.google.direct-provider-deny",
		);
		expect(
			googleProviderFixtureEvidenceFailure(
				"fixture.providers.google.direct-provider-deny",
				directEvidence,
			),
		).toBeNull();
	});

	it("keeps Google direct-provider-deny red without provider-specific network evidence", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "google-provider-fixtures-"));
		const probePath = await writeGoogleProviderProbeArtifact(tempDir);
		const networkProbePath = writeGoogleProviderNetworkProbeArtifact(tempDir, ["provider"]);
		const bundle = buildGoogleProviderFixtureEvidenceBundle({
			evidenceDir: path.join(tempDir, "fixtures"),
			probePath,
			networkProbePath,
			observedAt: "2026-06-01T09:10:00.000Z",
		});
		const directEvidence = bundle.evidence.find(
			(evidence) => evidence.id === "fixture.providers.google.direct-provider-deny",
		);

		expect(bundle.results).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					id: "fixture.providers.google.direct-provider-deny",
					status: "fail",
				}),
			]),
		);
		expect(
			googleProviderFixtureEvidenceFailure(
				"fixture.providers.google.direct-provider-deny",
				directEvidence,
			),
		).toContain("networkDeny attempt provider:google is missing");
	});

	it("rejects Google fixture evidence when the bound probe artifact changes", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "google-provider-fixtures-"));
		const probePath = await writeGoogleProviderProbeArtifact(tempDir);
		const bundle = buildGoogleProviderFixtureEvidenceBundle({
			evidenceDir: path.join(tempDir, "fixtures"),
			probePath,
			observedAt: "2026-06-01T09:10:00.000Z",
		});
		const readEvidence = bundle.evidence.find(
			(evidence) => evidence.id === "fixture.providers.google.read",
		);

		fs.writeFileSync(probePath, JSON.stringify({ changed: true }), "utf8");

		expect(
			googleProviderFixtureEvidenceFailure("fixture.providers.google.read", readEvidence),
		).toContain("probeSha256 does not match");
	});
});

async function writeGoogleProviderProbeArtifact(tempDir: string): Promise<string> {
	const probePath = path.join(tempDir, "providers-google.json");
	const evidence = await runTelclaudeGoogleProviderProbe({
		allowRun: true,
		observedAt: "2026-06-01T09:00:00.000Z",
	});
	fs.writeFileSync(probePath, JSON.stringify(evidence, null, 2), "utf8");
	return probePath;
}

function writeGoogleProviderNetworkProbeArtifact(
	tempDir: string,
	attemptNames: readonly string[],
): string {
	const probePath = path.join(tempDir, "direct-provider-denied.json");
	fs.writeFileSync(
		probePath,
		JSON.stringify(
			{
				schemaVersion: NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION,
				id: "network.direct-provider-denied",
				posture: "contained-internal",
				status: "pass",
				ran: true,
				summary: "direct provider endpoints were denied in the Hermes runtime namespace",
				generatedAt: "2026-06-01T09:10:00.000Z",
				evidence_path: probePath,
				attempts: attemptNames.map((name) => ({
					name,
					kind: "http",
					target: `http://${name.replace(/[^a-z0-9-]/gi, "-")}.invalid/v1/health`,
					expectation: "deny",
					status: "pass",
					observed: "denied",
					detail: `${name} was denied`,
					errorCode: "ENETUNREACH",
				})),
			},
			null,
			2,
		),
		"utf8",
	);
	return probePath;
}
