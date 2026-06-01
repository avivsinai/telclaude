import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	buildEdgeAdapterFixtureEvidenceBundle,
	buildEdgeAdapterProbeEvidence,
	EDGE_ADAPTER_FEATURE_SURFACE_IDS,
	edgeAdapterFixtureEvidenceFailure,
	edgeAdapterProbeEvidenceFailure,
} from "../../src/hermes/edge-adapter-probes.js";
import { runTelclaudeProviderReleasePolicyProbe } from "../../src/hermes/provider-release-policy-probe.js";
import { generateKeyPair } from "../../src/internal-auth.js";

const observedAt = "2026-05-31T09:00:00.000Z";
const ORIGINAL_ENV = {
	OPERATOR_RPC_RELAY_PRIVATE_KEY: process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY,
	OPERATOR_RPC_RELAY_PUBLIC_KEY: process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY,
};

describe("Hermes edge adapter probe evidence", () => {
	beforeEach(() => {
		const relayKeys = generateKeyPair();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;
	});

	afterEach(() => {
		restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY");
		restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY");
	});

	it.each(EDGE_ADAPTER_FEATURE_SURFACE_IDS)("accepts generated evidence for %s", (surfaceId) => {
		const evidence = buildEdgeAdapterProbeEvidence({
			surfaceId,
			observedAt,
			allowRun: true,
		});

		expect(evidence.status).toBe("pass");
		expect(evidence.runnerAttestation).toMatchObject({
			source: "telclaude-edge-runtime-probe-runner",
			runner: "telclaude-edge-runtime-probe",
			probeId: surfaceId,
			status: "pass",
			ran: true,
			evidenceSource: "telclaude-edge-runtime-harness",
			signature: expect.objectContaining({
				version: "v1",
				scope: "operator",
				path: "/v1/hermes.edge-adapter.attestation",
			}),
		});
		expect(edgeAdapterProbeEvidenceFailure(surfaceId, evidence)).toBeNull();
	});

	it("rejects pass-looking evidence that did not run", () => {
		const evidence = {
			...buildEdgeAdapterProbeEvidence({
				surfaceId: "edge.whatsapp",
				observedAt,
				allowRun: true,
			}),
			ran: false,
		};

		expect(edgeAdapterProbeEvidenceFailure("edge.whatsapp", evidence)).toContain(
			"harness did not run",
		);
	});

	it("rejects a wrong channel binding for a surface", () => {
		const evidence = {
			...buildEdgeAdapterProbeEvidence({
				surfaceId: "edge.whatsapp",
				observedAt,
				allowRun: true,
			}),
			surface: {
				id: "edge.whatsapp",
				channels: ["email"],
				trustDomains: ["public", "household"],
			},
		};

		expect(edgeAdapterProbeEvidenceFailure("edge.whatsapp", evidence)).toContain(
			"channels do not match whatsapp",
		);
	});

	it("rejects evidence missing a required negative credential control", () => {
		const evidence = buildEdgeAdapterProbeEvidence({
			surfaceId: "edge.whatsapp",
			observedAt,
			allowRun: true,
		});
		const withoutRawCredentialDenial = {
			...evidence,
			controls: evidence.controls.filter((control) => control.name !== "credentials.raw-denied"),
		};

		expect(edgeAdapterProbeEvidenceFailure("edge.whatsapp", withoutRawCredentialDenial)).toContain(
			"control credentials.raw-denied is missing",
		);
	});

	it("requires runtime harness evidence for attachment quarantine", () => {
		const evidence = buildEdgeAdapterProbeEvidence({
			surfaceId: "attachment.quarantine",
			observedAt,
			allowRun: true,
		});

		expect(evidence.source).toBe("telclaude-edge-runtime-harness");
		expect(evidence.runtime?.checks).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					name: "attachment.unknown-quarantine-denied",
					status: "pass",
				}),
				expect.objectContaining({ name: "attachment.raw-bytes-denied", status: "pass" }),
				expect.objectContaining({ name: "attachment.cross-domain-reuse-denied", status: "pass" }),
			]),
		);
		expect(evidence.runtime?.operationTrace).toEqual(
			expect.arrayContaining(["ingest", "prepareOutbound", "executeOutbound", "status", "ack"]),
		);
		expect(edgeAdapterProbeEvidenceFailure("attachment.quarantine", evidence)).toBeNull();
	});

	it("requires runtime harness evidence for outbound policy", () => {
		const evidence = buildEdgeAdapterProbeEvidence({
			surfaceId: "outbound.policy",
			observedAt,
			allowRun: true,
		});

		expect(evidence.source).toBe("telclaude-edge-runtime-harness");
		expect(evidence.runtime?.checks).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ name: "outbound.recipient-body-bound", status: "pass" }),
				expect.objectContaining({ name: "outbound.replay-denied", status: "pass" }),
			]),
		);
		expect(edgeAdapterProbeEvidenceFailure("outbound.policy", evidence)).toBeNull();
	});

	it("rejects pass-looking edge evidence without a signed runner attestation", () => {
		const evidence = buildEdgeAdapterProbeEvidence({
			surfaceId: "edge.whatsapp",
			observedAt,
			allowRun: true,
		});
		const { runnerAttestation: _attestation, ...unsignedEvidence } = evidence;

		expect(edgeAdapterProbeEvidenceFailure("edge.whatsapp", unsignedEvidence)).toContain(
			"runnerAttestation is missing",
		);
	});

	it("rejects mutated runtime observations after signing", () => {
		const evidence = buildEdgeAdapterProbeEvidence({
			surfaceId: "edge.whatsapp",
			observedAt,
			allowRun: true,
		});

		expect(
			edgeAdapterProbeEvidenceFailure("edge.whatsapp", {
				...evidence,
				runtime: {
					...evidence.runtime,
					observations: {
						...evidence.runtime?.observations,
						deniedAttempts: 0,
					},
				},
			}),
		).toContain("runnerAttestation runtimeSha256 mismatch");
	});

	it("rejects runner attestations signed by an untrusted relay key", () => {
		const trustedPublicKey = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		const attackerKeys = generateKeyPair();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = attackerKeys.privateKey;
		const forgedEvidence = buildEdgeAdapterProbeEvidence({
			surfaceId: "edge.whatsapp",
			observedAt,
			allowRun: true,
		});
		if (trustedPublicKey) process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = trustedPublicKey;

		expect(edgeAdapterProbeEvidenceFailure("edge.whatsapp", forgedEvidence)).toContain(
			"runnerAttestation signature is invalid: signature verification failed",
		);
	});

	it("requires runtime harness evidence for migrated identity", () => {
		const evidence = buildEdgeAdapterProbeEvidence({
			surfaceId: "identity.migration",
			observedAt,
			allowRun: true,
		});

		expect(evidence.source).toBe("telclaude-edge-runtime-harness");
		expect(evidence.runtime?.checks).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ name: "identity.forged-actor-denied", status: "pass" }),
				expect.objectContaining({ name: "identity.revocation-enforced", status: "pass" }),
				expect.objectContaining({ name: "identity.session-id-not-authority", status: "pass" }),
				expect.objectContaining({ name: "identity.cross-channel-denied", status: "pass" }),
			]),
		);
		expect(edgeAdapterProbeEvidenceFailure("identity.migration", evidence)).toBeNull();
	});

	it("requires runtime harness evidence for household scopes", () => {
		const evidence = buildEdgeAdapterProbeEvidence({
			surfaceId: "household.scopes",
			observedAt,
			allowRun: true,
		});

		expect(evidence.source).toBe("telclaude-edge-runtime-harness");
		expect(evidence.runtime?.checks).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ name: "household.scoped-benign-allowed", status: "pass" }),
				expect.objectContaining({ name: "household.strong-link-required", status: "pass" }),
				expect.objectContaining({
					name: "household.number-only-provider-denied",
					status: "pass",
				}),
				expect.objectContaining({ name: "household.private-memory-denied", status: "pass" }),
				expect.objectContaining({ name: "household.cross-recipient-denied", status: "pass" }),
			]),
		);
		expect(edgeAdapterProbeEvidenceFailure("household.scopes", evidence)).toBeNull();
	});

	it.each([
		["edge.whatsapp", "whatsapp.direct-bridge-denied"],
		["edge.email", "email.direct-mailbox-denied"],
		["edge.agentmail", "agentmail.direct-key-denied"],
		["edge.social", "social.unapproved-posting-denied"],
	] as const)("requires runtime harness evidence for %s", (surfaceId, expectedControl) => {
		const evidence = buildEdgeAdapterProbeEvidence({
			surfaceId,
			observedAt,
			allowRun: true,
		});

		expect(evidence.source).toBe("telclaude-edge-runtime-harness");
		expect(evidence.runtime?.checks).toEqual(
			expect.arrayContaining([expect.objectContaining({ name: expectedControl, status: "pass" })]),
		);
		expect(edgeAdapterProbeEvidenceFailure(surfaceId, evidence)).toBeNull();
	});

	it("requires runtime harness evidence for public-social isolation", () => {
		const evidence = buildEdgeAdapterProbeEvidence({
			surfaceId: "public.social.isolation",
			observedAt,
			allowRun: true,
		});

		expect(evidence.source).toBe("telclaude-edge-runtime-harness");
		expect(evidence.runtime?.checks).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ name: "public-social.separate-profile", status: "pass" }),
				expect.objectContaining({
					name: "public-social.private-workspace-denied",
					status: "pass",
				}),
				expect.objectContaining({ name: "public-social.provider-scope-denied", status: "pass" }),
			]),
		);
		expect(edgeAdapterProbeEvidenceFailure("public.social.isolation", evidence)).toBeNull();
	});

	it.each([
		"edge.whatsapp",
		"edge.email",
		"edge.agentmail",
		"edge.social",
		"identity.migration",
		"household.scopes",
		"attachment.quarantine",
		"outbound.policy",
		"public.social.isolation",
	] as const)("rejects contract-only evidence for runtime-required edge surface %s", (surfaceId) => {
		const evidence = buildEdgeAdapterProbeEvidence({
			surfaceId,
			observedAt,
			allowRun: true,
		});
		const contractOnly = {
			...evidence,
			source: "telclaude-edge-contract-unit",
			runtime: undefined,
		};

		expect(edgeAdapterProbeEvidenceFailure(surfaceId, contractOnly)).toContain(
			"runtime harness evidence is missing",
		);
	});

	it("rejects unpinned operation sets", () => {
		const evidence = {
			...buildEdgeAdapterProbeEvidence({
				surfaceId: "edge.email",
				observedAt,
				allowRun: true,
			}),
			contract: {
				version: "telclaude.hermes.edge-adapter-contract.v1",
				operations: ["ingest", "prepareOutbound", "executeOutbound", "status"],
				schemaVersions: ["telclaude.hermes.edge.actor-ref.v1"],
			},
		};

		expect(edgeAdapterProbeEvidenceFailure("edge.email", evidence)).toContain(
			"contract.operations",
		);
	});

	it("does not let one edge surface satisfy another", () => {
		const evidence = buildEdgeAdapterProbeEvidence({
			surfaceId: "edge.email",
			observedAt,
			allowRun: true,
		});

		expect(edgeAdapterProbeEvidenceFailure("edge.whatsapp", evidence)).toContain(
			"probe surface mismatch",
		);
	});

	it("builds public and household fixture evidence from current edge probe artifacts", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-edge-fixtures-"));
		const probePaths = writeEdgeFixtureProbeArtifacts(tempDir);
		const bundle = buildEdgeAdapterFixtureEvidenceBundle({
			evidenceDir: path.join(tempDir, "fixtures"),
			observedAt,
			probePaths,
		});

		expect(bundle.results).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ id: "fixture.public.whatsapp.basic", status: "pass" }),
				expect.objectContaining({
					id: "fixture.household.provider.strong-link-read",
					status: "pass",
				}),
				expect.objectContaining({ id: "fixture.public.social.private-leak-deny", status: "pass" }),
			]),
		);
		for (const evidence of bundle.evidence) {
			for (const artifact of evidence.edge.probeArtifacts) {
				fs.mkdirSync(path.dirname(artifact.evidencePath), { recursive: true });
			}
			expect(edgeAdapterFixtureEvidenceFailure(evidence.id, evidence)).toBeNull();
		}
	});

	it("rejects edge fixture evidence when a bound probe artifact changes", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-edge-fixture-tamper-"));
		const probePaths = writeEdgeFixtureProbeArtifacts(tempDir);
		const bundle = buildEdgeAdapterFixtureEvidenceBundle({
			evidenceDir: path.join(tempDir, "fixtures"),
			observedAt,
			probePaths,
		});
		const whatsappFixture = bundle.evidence.find(
			(item) => item.id === "fixture.public.whatsapp.basic",
		);
		expect(whatsappFixture).toBeDefined();

		fs.writeFileSync(probePaths["edge.whatsapp"], JSON.stringify({ changed: true }), "utf8");

		expect(
			edgeAdapterFixtureEvidenceFailure("fixture.public.whatsapp.basic", whatsappFixture),
		).toContain("sha256 changed");
	});
});

function writeEdgeFixtureProbeArtifacts(tempDir: string) {
	const probePaths = Object.fromEntries(
		EDGE_ADAPTER_FEATURE_SURFACE_IDS.map((surfaceId) => {
			const evidence = buildEdgeAdapterProbeEvidence({
				surfaceId,
				observedAt,
				allowRun: true,
			});
			const file = path.join(tempDir, "probes", `${surfaceId.replaceAll(".", "-")}.json`);
			fs.mkdirSync(path.dirname(file), { recursive: true });
			fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`, "utf8");
			return [surfaceId, file];
		}),
	) as Record<(typeof EDGE_ADAPTER_FEATURE_SURFACE_IDS)[number], string> & {
		"providers.release-policy": string;
	};
	const releasePolicyFile = path.join(tempDir, "probes", "providers-release-policy.json");
	fs.writeFileSync(
		releasePolicyFile,
		`${JSON.stringify(
			runTelclaudeProviderReleasePolicyProbe({ allowRun: true, observedAt }),
			null,
			2,
		)}\n`,
		"utf8",
	);
	probePaths["providers.release-policy"] = releasePolicyFile;
	return probePaths;
}

function restoreEnv(key: keyof typeof ORIGINAL_ENV): void {
	const value = ORIGINAL_ENV[key];
	if (value === undefined) {
		delete process.env[key];
	} else {
		process.env[key] = value;
	}
}
