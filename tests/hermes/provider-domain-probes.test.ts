import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { signNetworkProbeEvidenceAttestation } from "../../src/hermes/network-probe-attestation.js";
import { NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION } from "../../src/hermes/network-probe-schema.js";
import {
	buildProviderDomainFixtureEvidenceBundle,
	PROVIDER_DOMAIN_SURFACE_IDS,
	type ProviderDomainSurfaceId,
	providerDomainFixtureEvidenceFailure,
	providerDomainProbeEvidenceFailure,
	runTelclaudeProviderDomainProbe,
} from "../../src/hermes/provider-domain-probes.js";
import { generateKeyPair } from "../../src/internal-auth.js";

let restoreOperatorRelayKeys: (() => void) | undefined;

describe("Hermes provider-domain probes", () => {
	beforeEach(() => {
		restoreOperatorRelayKeys = installOperatorRelayKeys();
	});

	afterEach(() => {
		restoreOperatorRelayKeys?.();
		restoreOperatorRelayKeys = undefined;
	});

	it.each(
		PROVIDER_DOMAIN_SURFACE_IDS,
	)("passes %s only after read, prepare, approved execute, scope, replay, and credential checks", async (surfaceId: ProviderDomainSurfaceId) => {
		const evidence = await runTelclaudeProviderDomainProbe({
			surfaceId,
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(evidence.status).toBe("pass");
		expect(evidence.observations.providerProxyCallCount).toBe(2);
		expect(evidence.observations.approvalVerifierCallCount).toBeGreaterThanOrEqual(1);
		expect(evidence.observations.sidecarTokenIssuerCallCount).toBe(1);
		expect(evidence.observations.wrongActorCode).toBe("effect_authority_mismatch");
		expect(evidence.observations.wrongProviderScopeCode).toBe("effect_authority_mismatch");
		expect(evidence.observations.ledgerReplayCode).toBe("effect_already_executed");
		expect(evidence.observations.rawCredentialObserved).toBe(false);
		expect(evidence.checks).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					name: `${evidence.observations.providerId}.catalog-registered`,
					status: "pass",
				}),
			]),
		);
		expect(providerDomainProbeEvidenceFailure(surfaceId, evidence)).toBeNull();
	});

	it("proves Clalit emergency-language escalation denial", async () => {
		const evidence = await runTelclaudeProviderDomainProbe({
			surfaceId: "providers.clalit",
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(evidence.observations.emergencyEscalationCode).toContain(
			"urgent_health_escalation_required",
		);
		expect(evidence.checks).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					name: "clalit.emergency-escalation-denied",
					status: "pass",
				}),
			]),
		);
	});

	it("rejects evidence missing wrong-provider-scope denial", async () => {
		const evidence = await runTelclaudeProviderDomainProbe({
			surfaceId: "providers.bank",
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(
			providerDomainProbeEvidenceFailure("providers.bank", {
				...evidence,
				checks: evidence.checks.filter(
					(check) => check.name !== "bank.wrong-provider-scope-denied",
				),
			}),
		).toContain("check bank.wrong-provider-scope-denied is missing");
	});

	it("rejects provider-domain evidence missing catalog registration proof", async () => {
		const evidence = await runTelclaudeProviderDomainProbe({
			surfaceId: "providers.bank",
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(
			providerDomainProbeEvidenceFailure("providers.bank", {
				...evidence,
				checks: evidence.checks.filter((check) => check.name !== "bank.catalog-registered"),
			}),
		).toContain("check bank.catalog-registered is missing");
	});

	it("rejects pass-looking evidence with raw provider credential material", async () => {
		const evidence = await runTelclaudeProviderDomainProbe({
			surfaceId: "providers.government",
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(
			providerDomainProbeEvidenceFailure("providers.government", {
				...evidence,
				observations: {
					...evidence.observations,
					rawCredentialObserved: true,
				},
			}),
		).toContain("raw provider credential material was observed");
	});

	it("rejects evidence produced without --allow-run", async () => {
		const evidence = await runTelclaudeProviderDomainProbe({
			surfaceId: "providers.clalit",
			allowRun: false,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(evidence.status).toBe("fail");
		expect(providerDomainProbeEvidenceFailure("providers.clalit", evidence)).toContain(
			"harness did not run",
		);
	});

	it("builds provider fixture evidence bound to provider-domain probe artifacts", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "provider-domain-fixtures-"));
		const probePaths = await writeProviderDomainProbeArtifacts(tempDir);
		const networkProbePath = writeDirectProviderNetworkProbeArtifact(tempDir, [
			"provider:bank",
			"provider:clalit",
			"provider:government",
			"provider:google",
		]);
		const bundle = buildProviderDomainFixtureEvidenceBundle({
			evidenceDir: path.join(tempDir, "fixtures"),
			probePaths,
			networkProbePath,
			observedAt: "2026-06-01T09:10:00.000Z",
		});

		expect(bundle.results).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ id: "fixture.providers.bank.read", status: "pass" }),
				expect.objectContaining({
					id: "fixture.providers.bank.direct-provider-deny",
					status: "pass",
				}),
				expect.objectContaining({
					id: "fixture.providers.clalit.emergency-escalate",
					status: "pass",
				}),
				expect.objectContaining({
					id: "fixture.providers.clalit.direct-provider-deny",
					status: "pass",
				}),
				expect.objectContaining({
					id: "fixture.providers.government.approved-submit",
					status: "pass",
				}),
				expect.objectContaining({
					id: "fixture.providers.government.direct-provider-deny",
					status: "pass",
				}),
			]),
		);
		const bankReadEvidence = bundle.evidence.find(
			(evidence) => evidence.id === "fixture.providers.bank.read",
		);
		expect(
			providerDomainFixtureEvidenceFailure("fixture.providers.bank.read", bankReadEvidence),
		).toBeNull();
		const bankDirectEvidence = bundle.evidence.find(
			(evidence) => evidence.id === "fixture.providers.bank.direct-provider-deny",
		);
		expect(
			providerDomainFixtureEvidenceFailure(
				"fixture.providers.bank.direct-provider-deny",
				bankDirectEvidence,
			),
		).toBeNull();
	});

	it("keeps direct-provider-deny fixtures red without provider-specific network attempts", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "provider-domain-fixtures-"));
		const probePaths = await writeProviderDomainProbeArtifacts(tempDir);
		const networkProbePath = writeDirectProviderNetworkProbeArtifact(tempDir, ["provider"]);
		const bundle = buildProviderDomainFixtureEvidenceBundle({
			evidenceDir: path.join(tempDir, "fixtures"),
			probePaths,
			networkProbePath,
			observedAt: "2026-06-01T09:10:00.000Z",
		});
		const bankDirectEvidence = bundle.evidence.find(
			(evidence) => evidence.id === "fixture.providers.bank.direct-provider-deny",
		);

		expect(bundle.results).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					id: "fixture.providers.bank.direct-provider-deny",
					status: "fail",
				}),
			]),
		);
		expect(
			providerDomainFixtureEvidenceFailure(
				"fixture.providers.bank.direct-provider-deny",
				bankDirectEvidence,
			),
		).toContain("provider:bank");
	});

	it("rejects direct-provider-deny fixtures backed by unsigned network evidence", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "provider-domain-fixtures-"));
		const probePaths = await writeProviderDomainProbeArtifacts(tempDir);
		const networkProbePath = writeDirectProviderNetworkProbeArtifact(
			tempDir,
			["provider:bank", "provider:clalit", "provider:government", "provider:google"],
			{ sign: false },
		);
		const bundle = buildProviderDomainFixtureEvidenceBundle({
			evidenceDir: path.join(tempDir, "fixtures"),
			probePaths,
			networkProbePath,
			observedAt: "2026-06-01T09:10:00.000Z",
		});
		const bankDirectEvidence = bundle.evidence.find(
			(evidence) => evidence.id === "fixture.providers.bank.direct-provider-deny",
		);

		expect(bundle.results).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					id: "fixture.providers.bank.direct-provider-deny",
					status: "fail",
				}),
			]),
		);
		expect(
			providerDomainFixtureEvidenceFailure(
				"fixture.providers.bank.direct-provider-deny",
				bankDirectEvidence,
			),
		).toContain("attestation is missing");
	});

	it("rejects provider fixture evidence when the bound probe artifact changes", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "provider-domain-fixtures-"));
		const probePaths = await writeProviderDomainProbeArtifacts(tempDir);
		const bundle = buildProviderDomainFixtureEvidenceBundle({
			evidenceDir: path.join(tempDir, "fixtures"),
			probePaths,
			observedAt: "2026-06-01T09:10:00.000Z",
		});
		const bankReadEvidence = bundle.evidence.find(
			(evidence) => evidence.id === "fixture.providers.bank.read",
		);

		fs.writeFileSync(probePaths["providers.bank"], JSON.stringify({ changed: true }), "utf8");

		expect(
			providerDomainFixtureEvidenceFailure("fixture.providers.bank.read", bankReadEvidence),
		).toContain("probeSha256 does not match");
	});
});

async function writeProviderDomainProbeArtifacts(
	tempDir: string,
): Promise<Record<ProviderDomainSurfaceId, string>> {
	const probePaths = {
		"providers.bank": path.join(tempDir, "providers-bank.json"),
		"providers.clalit": path.join(tempDir, "providers-clalit.json"),
		"providers.government": path.join(tempDir, "providers-government.json"),
	} satisfies Record<ProviderDomainSurfaceId, string>;
	for (const surfaceId of PROVIDER_DOMAIN_SURFACE_IDS) {
		const evidence = await runTelclaudeProviderDomainProbe({
			surfaceId,
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});
		fs.writeFileSync(probePaths[surfaceId], JSON.stringify(evidence, null, 2), "utf8");
	}
	return probePaths;
}

function writeDirectProviderNetworkProbeArtifact(
	tempDir: string,
	attemptNames: readonly string[],
	options: { readonly sign?: boolean } = {},
): string {
	const probePath = path.join(tempDir, "direct-provider-denied.json");
	const evidence = {
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
	};
	fs.writeFileSync(
		probePath,
		JSON.stringify(
			options.sign === false
				? evidence
				: {
						...evidence,
						attestation: signNetworkProbeEvidenceAttestation(evidence),
					},
			null,
			2,
		),
		"utf8",
	);
	return probePath;
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
