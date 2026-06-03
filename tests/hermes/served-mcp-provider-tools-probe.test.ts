import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { SERVED_MCP_REQUIRED_PROPERTY_NAMES } from "../../src/hermes/served-mcp-containment.js";
import {
	buildServedMcpProviderToolsProbeEvidence,
	servedMcpProviderToolsProbeEvidenceFailure,
} from "../../src/hermes/served-mcp-provider-tools-probe.js";

describe("served-MCP provider-tools probe", () => {
	it("passes only from served-MCP containment evidence with provider-tool controls", () => {
		const sourceEvidence = servedMcpContainmentEvidence();
		const sourceEvidencePath = writeServedMcpSourceEvidence(sourceEvidence);
		const evidence = buildServedMcpProviderToolsProbeEvidence({
			sourceEvidencePath,
			sourceEvidence,
			observedAt: "2026-05-31T09:00:00.000Z",
		});

		expect(evidence.status).toBe("pass");
		expect(evidence.observations.originKind).toBe("contained-peer");
		expect(evidence.observations.providerTools).toEqual([
			"tc_provider_read",
			"tc_provider_prepare_write",
			"tc_provider_execute_write",
		]);
		expect(servedMcpProviderToolsProbeEvidenceFailure(evidence)).toBeNull();
	});

	it("rejects source evidence without provider execute ledger denial", () => {
		const sourceEvidence = servedMcpContainmentEvidence({
			properties: {
				...servedMcpContainmentEvidence().properties,
				provider_execute_without_ledger_denied: false,
			},
		});
		const sourceEvidencePath = writeServedMcpSourceEvidence(sourceEvidence);
		const evidence = buildServedMcpProviderToolsProbeEvidence({
			sourceEvidencePath,
			sourceEvidence,
			observedAt: "2026-05-31T09:00:00.000Z",
		});

		expect(evidence.status).toBe("fail");
		expect(servedMcpProviderToolsProbeEvidenceFailure(evidence)).toContain(
			"check served-mcp.provider-tools.execute-without-ledger-denied is fail",
		);
	});

	it("rejects relay-self smoke origin for provider tools", () => {
		const sourceEvidence = servedMcpContainmentEvidence({
			origin: {
				kind: "relay-self-smoke",
				containerName: "telclaude",
				observedPeerAddress: "127.0.0.1",
				observedPeerSource: "server-peer-echo",
				detail: "relay self smoke",
			},
		});
		const sourceEvidencePath = writeServedMcpSourceEvidence(sourceEvidence);
		const evidence = buildServedMcpProviderToolsProbeEvidence({
			sourceEvidencePath,
			sourceEvidence,
			observedAt: "2026-05-31T09:00:00.000Z",
		});

		expect(evidence.status).toBe("fail");
		expect(servedMcpProviderToolsProbeEvidenceFailure(evidence)).toContain(
			"originKind is relay-self-smoke",
		);
	});

	it("rejects provider-tools evidence when the source containment artifact changes", () => {
		const sourceEvidence = servedMcpContainmentEvidence();
		const sourceEvidencePath = writeServedMcpSourceEvidence(sourceEvidence);
		const evidence = buildServedMcpProviderToolsProbeEvidence({
			sourceEvidencePath,
			sourceEvidence,
			observedAt: "2026-05-31T09:00:00.000Z",
		});

		fs.writeFileSync(
			sourceEvidencePath,
			`${JSON.stringify(
				servedMcpContainmentEvidence({
					properties: {
						...servedMcpContainmentEvidence().properties,
						out_of_scope_provider_denied: false,
					},
				}),
				null,
				2,
			)}\n`,
			"utf8",
		);

		expect(servedMcpProviderToolsProbeEvidenceFailure(evidence)).toContain(
			"source served-MCP containment artifact sha256 changed",
		);
	});

	it("rejects provider-tools evidence when the source containment artifact is missing", () => {
		const sourceEvidence = servedMcpContainmentEvidence();
		const sourceEvidencePath = writeServedMcpSourceEvidence(sourceEvidence);
		const evidence = buildServedMcpProviderToolsProbeEvidence({
			sourceEvidencePath,
			sourceEvidence,
			observedAt: "2026-05-31T09:00:00.000Z",
		});

		fs.unlinkSync(sourceEvidencePath);

		expect(servedMcpProviderToolsProbeEvidenceFailure(evidence)).toContain(
			"source served-MCP containment artifact is missing",
		);
	});

	it("rejects provider-tools evidence when the source containment artifact is invalid JSON", () => {
		const sourceEvidence = servedMcpContainmentEvidence();
		const sourceEvidencePath = writeServedMcpSourceEvidence(sourceEvidence);
		const evidence = buildServedMcpProviderToolsProbeEvidence({
			sourceEvidencePath,
			sourceEvidence,
			observedAt: "2026-05-31T09:00:00.000Z",
		});

		fs.writeFileSync(sourceEvidencePath, "{not-json", "utf8");

		expect(servedMcpProviderToolsProbeEvidenceFailure(evidence)).toContain(
			"source served-MCP containment artifact is unreadable",
		);
	});
});

function writeServedMcpSourceEvidence(sourceEvidence: unknown): string {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "served-mcp-source-"));
	const sourceEvidencePath = path.join(tempDir, "execution-served-mcp-containment.json");
	fs.writeFileSync(sourceEvidencePath, `${JSON.stringify(sourceEvidence, null, 2)}\n`, "utf8");
	return sourceEvidencePath;
}

function servedMcpContainmentEvidence(overrides: Record<string, unknown> = {}) {
	const properties = Object.fromEntries(
		SERVED_MCP_REQUIRED_PROPERTY_NAMES.map((property) => [property, true]),
	);
	return {
		schemaVersion: "telclaude.hermes.served-mcp-containment.v1",
		probeId: "execution.served_mcp_containment",
		status: "pass",
		ran: true,
		generatedAt: "2026-05-31T09:00:00.000Z",
		summary: "Served MCP containment probe passed",
		endpoint: {
			transport: "http",
			target: "redacted-http-mcp-endpoint",
		},
		placement: {
			loadBearing: false,
			detail: "relay-internal served MCP endpoint",
		},
		origin: {
			kind: "contained-peer",
			containerName: "tc-hermes-contained",
			observedPeerAddress: "192.0.2.11",
			observedPeerSource: "server-peer-echo",
			expectedPeerAddress: "192.0.2.11",
			expectedPeerSource: "configured-contained-ip",
			detail: "probe peer origin was observed by live MCP server",
		},
		negativeControls: {
			forgedAuthorityDenied: true,
			wrongConnectionDenied: true,
			offDomainPeerDenied: true,
		},
		properties,
		checks: SERVED_MCP_REQUIRED_PROPERTY_NAMES.map((name) => ({
			name,
			status: "pass",
			detail: `${name} passed`,
		})),
		...overrides,
	};
}
