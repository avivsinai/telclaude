import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildCutoverProofBundle } from "../../src/hermes/foundation.js";

describe("cutover proof bundle", () => {
	it("keeps live-surface seed artifacts red in the proof bundle", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-proof-red-seeds-"));
		const paths = {
			inventory: writeJson(tempDir, "inventory.json", { schemaVersion: 1 }),
			scopeManifest: writeJson(tempDir, "scope.json", { schemaVersion: 1 }),
			decisionLog: writeJson(tempDir, "decisions.json", { schemaVersion: 1 }),
			compatibilityLockfile: writeJson(tempDir, "lockfile.json", { schemaVersion: 1 }),
			featureProbeMatrix: writeJson(tempDir, "feature-probes.json", {
				schemaVersion: 1,
				probes: [featureProbe("pass")],
			}),
			fixtureResults: writeJson(tempDir, "fixtures.json", {
				schemaVersion: 1,
				results: [fixtureResult("fail")],
			}),
			noForkProof: writeJson(tempDir, "no-fork-proof.json", {
				schemaVersion: 1,
				hermesCheckoutClean: false,
				evidence_path: "artifacts/hermes/no-fork.json",
			}),
			networkProbeBundle: writeJson(tempDir, "network-probes.json", {
				schemaVersion: 1,
				probes: [
					networkProbe("network.relay-control-allowed"),
					networkProbe("network.direct-provider-denied"),
					networkProbe("network.direct-vault-denied"),
					networkProbe("network.direct-model-provider-denied"),
					networkProbe("network.dns-exfil-denied"),
				],
			}),
			queueSnapshot: writeJson(tempDir, "queue.json", { unownedActiveCount: 0 }),
			rollbackEvidence: writeJson(tempDir, "rollback.json", {
				schemaVersion: 1,
				passed: false,
				evidence_path: "artifacts/hermes/rollback-rehearsal.json",
			}),
		};

		const proofBundle = buildCutoverProofBundle({
			hermes: { version: "0.15.1" },
			wrapperVersion: "0.7.1",
			now: new Date("2026-06-01T00:00:00.000Z"),
			artifacts: {
				inventory: proofArtifact(paths.inventory, ["inputs.inventory"]),
				scopeManifest: proofArtifact(paths.scopeManifest, ["inputs.scopeManifest"]),
				decisionLog: proofArtifact(paths.decisionLog, ["inputs.decisionLog"]),
				compatibilityLockfile: proofArtifact(paths.compatibilityLockfile, ["inputs.lockfile"]),
				featureProbeMatrix: proofArtifact(paths.featureProbeMatrix, ["inputs.featureProbeMatrix"]),
				fixtureResults: proofArtifact(paths.fixtureResults, ["inputs.fixtureResults"]),
				noForkProof: proofArtifact(paths.noForkProof, ["inputs.noForkProof", "nofork.clean"]),
				networkProbeBundle: proofArtifact(paths.networkProbeBundle, [
					"inputs.networkProbes",
					"networkProbes.pass",
				]),
				queueSnapshot: proofArtifact(paths.queueSnapshot, ["inputs.queueSnapshot"]),
				rollbackEvidence: proofArtifact(paths.rollbackEvidence, [
					"inputs.rollbackRehearsal",
					"rollback.rehearsed",
				]),
			},
		});

		expect(proofBundle.artifacts.noForkProof.status).toBe("fail");
		expect(proofBundle.artifacts.networkProbeBundle.status).toBe("fail");
		expect(proofBundle.artifacts.rollbackEvidence.status).toBe("fail");
		expect(proofBundle.artifacts.featureProbeMatrix.status).toBe("pass");
		expect(proofBundle.artifacts.fixtureResults.status).toBe("fail");
	});

	it("marks feature-probe artifacts failed when any probe is red", () => {
		const proofBundle = buildProofBundleForFeatureAndFixtureStatus("fail", "fail");

		expect(proofBundle.artifacts.featureProbeMatrix.status).toBe("fail");
	});

	it("marks fixture artifacts failed when any fixture is red", () => {
		const proofBundle = buildProofBundleForFeatureAndFixtureStatus("pass", "fail");

		expect(proofBundle.artifacts.featureProbeMatrix.status).toBe("pass");
		expect(proofBundle.artifacts.fixtureResults.status).toBe("fail");
	});
});

function buildProofBundleForFeatureAndFixtureStatus(
	featureStatus: "pass" | "fail",
	fixtureStatus: "pass" | "fail",
): ReturnType<typeof buildCutoverProofBundle> {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-proof-status-"));
	const paths = {
		inventory: writeJson(tempDir, "inventory.json", { schemaVersion: 1 }),
		scopeManifest: writeJson(tempDir, "scope.json", { schemaVersion: 1 }),
		decisionLog: writeJson(tempDir, "decisions.json", { schemaVersion: 1 }),
		compatibilityLockfile: writeJson(tempDir, "lockfile.json", { schemaVersion: 1 }),
		featureProbeMatrix: writeJson(tempDir, "feature-probes.json", {
			schemaVersion: 1,
			probes: [featureProbe(featureStatus)],
		}),
		fixtureResults: writeJson(tempDir, "fixtures.json", {
			schemaVersion: 1,
			results: [fixtureResult(fixtureStatus)],
		}),
		noForkProof: writeJson(tempDir, "no-fork-proof.json", {
			schemaVersion: 1,
			hermesCheckoutClean: true,
			evidence_path: "artifacts/hermes/no-fork.json",
			checks: [],
		}),
		networkProbeBundle: writeJson(tempDir, "network-probes.json", {
			schemaVersion: 1,
			probes: REQUIRED_NETWORK_PROBES.map((id) => networkProbe(id, "pass")),
		}),
		queueSnapshot: writeJson(tempDir, "queue.json", { unownedActiveCount: 0 }),
		rollbackEvidence: writeJson(tempDir, "rollback.json", {
			schemaVersion: 1,
			passed: true,
			evidence_path: "artifacts/hermes/rollback-rehearsal.json",
		}),
	};

	return buildCutoverProofBundle({
		hermes: { version: "0.15.1" },
		wrapperVersion: "0.7.1",
		now: new Date("2026-06-01T00:00:00.000Z"),
		artifacts: {
			inventory: proofArtifact(paths.inventory, ["inputs.inventory"]),
			scopeManifest: proofArtifact(paths.scopeManifest, ["inputs.scopeManifest"]),
			decisionLog: proofArtifact(paths.decisionLog, ["inputs.decisionLog"]),
			compatibilityLockfile: proofArtifact(paths.compatibilityLockfile, ["inputs.lockfile"]),
			featureProbeMatrix: proofArtifact(paths.featureProbeMatrix, ["inputs.featureProbeMatrix"]),
			fixtureResults: proofArtifact(paths.fixtureResults, ["inputs.fixtureResults"]),
			noForkProof: proofArtifact(paths.noForkProof, ["inputs.noForkProof"]),
			networkProbeBundle: proofArtifact(paths.networkProbeBundle, ["inputs.networkProbes"]),
			queueSnapshot: proofArtifact(paths.queueSnapshot, ["inputs.queueSnapshot"]),
			rollbackEvidence: proofArtifact(paths.rollbackEvidence, ["inputs.rollbackRehearsal"]),
		},
	});
}

function writeJson(tempDir: string, filename: string, value: unknown): string {
	const filePath = path.join(tempDir, filename);
	fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
	return filePath;
}

const REQUIRED_NETWORK_PROBES = [
	"network.relay-control-allowed",
	"network.direct-provider-denied",
	"network.direct-vault-denied",
	"network.direct-model-provider-denied",
	"network.dns-exfil-denied",
];

function featureProbe(status: "pass" | "fail"): Record<string, unknown> {
	return {
		surface_id: "edge.whatsapp",
		hermes_pin: { version: "0.15.1" },
		documented_seam: "adapter contract",
		probe_command: "pnpm dev hermes probes --json",
		expected_result: "provider fixture result is recorded",
		negative_probe: "direct provider access is denied",
		evidence_path: "artifacts/hermes/probes/edge-whatsapp.json",
		lockfile_key: "edge.whatsapp",
		failure_outcome: "disable",
		status,
	};
}

function fixtureResult(status: "pass" | "fail"): Record<string, unknown> {
	return {
		id: "fixture.public.whatsapp.basic",
		status,
		evidence_path: "artifacts/hermes/fixtures/public-whatsapp-basic.json",
	};
}

function networkProbe(id: string, status: "pass" | "fail" = "fail"): Record<string, unknown> {
	return {
		id,
		status,
		evidence_path: `artifacts/hermes/network/${id}.json`,
	};
}

function proofArtifact(artifactPath: string, gateIds: string[]) {
	return {
		artifactPath,
		sourceCommand: `test command for ${path.basename(artifactPath)}`,
		gateIds,
		checkIds: gateIds,
	};
}
