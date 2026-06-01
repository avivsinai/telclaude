import { describe, expect, it } from "vitest";
import {
	buildEdgeAdapterProbeEvidence,
	EDGE_ADAPTER_FEATURE_SURFACE_IDS,
	edgeAdapterProbeEvidenceFailure,
} from "../../src/hermes/edge-adapter-probes.js";

const observedAt = "2026-05-31T09:00:00.000Z";

describe("Hermes edge adapter probe evidence", () => {
	it.each(EDGE_ADAPTER_FEATURE_SURFACE_IDS)("accepts generated evidence for %s", (surfaceId) => {
		const evidence = buildEdgeAdapterProbeEvidence({
			surfaceId,
			observedAt,
			allowRun: true,
		});

		expect(evidence.status).toBe("pass");
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
});
