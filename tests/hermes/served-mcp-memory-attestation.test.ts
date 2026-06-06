import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	evaluateServedMcpMemoryEvidence,
	SERVED_MCP_MEMORY_REQUIRED_PROPERTY_NAMES,
	type ServedMcpMemoryEvidence,
} from "../../src/hermes/served-mcp-memory.js";
import { signServedMcpMemoryAttestation } from "../../src/hermes/served-mcp-memory-attestation.js";
import { generateKeyPair } from "../../src/internal-auth.js";

// These tests prove Pro P1#2: under a live cutover the evaluator only grants
// productionEnable when the evidence carries a valid Ed25519 attestation signed by
// the operator relay key — a hand-edited / unsigned / attacker-signed artifact fails.

const savedRelay = {
	private: process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY,
	public: process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY,
};
let relayPublicKey = "";

beforeEach(() => {
	const keys = generateKeyPair();
	process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = keys.privateKey;
	process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = keys.publicKey;
	relayPublicKey = keys.publicKey;
});
afterEach(() => {
	if (savedRelay.private === undefined) delete process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
	else process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = savedRelay.private;
	if (savedRelay.public === undefined) delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
	else process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = savedRelay.public;
});

function unsignedEvidence(): ServedMcpMemoryEvidence {
	const properties = Object.fromEntries(
		SERVED_MCP_MEMORY_REQUIRED_PROPERTY_NAMES.map((name) => [name, true]),
	) as ServedMcpMemoryEvidence["properties"];
	const rpcDenial = new Set(["secret_write_rejected", "instruction_like_write_rejected"]);
	return {
		schemaVersion: "telclaude.hermes.served-mcp-memory.v1",
		probeId: "served_mcp.memory",
		status: "pass",
		ran: true,
		generatedAt: new Date().toISOString(),
		summary: "memory parity proven from contained peer",
		memorySource: "telegram:default",
		origin: {
			kind: "contained-peer",
			containerName: "tc-hermes-contained",
			observedPeerAddress: "172.30.92.11",
			observedPeerSource: "server-peer-echo",
			expectedPeerAddress: "172.30.92.11",
			expectedPeerSource: "configured-contained-ip",
			detail: "server-echoed contained peer",
		},
		properties,
		checks: SERVED_MCP_MEMORY_REQUIRED_PROPERTY_NAMES.map((name) => ({
			name,
			status: "pass" as const,
			detail: `${name} proven`,
			...(name === "memory_source_resolved_server_side"
				? {
						clientSourceWriteRpcErrorCode: -32001,
						clientSourceWriteRpcErrorMessage:
							"MCP client cannot supply memory authority fields",
						clientSourceSearchRpcErrorCode: -32001,
						clientSourceSearchRpcErrorMessage:
							"MCP client cannot supply memory authority fields",
					}
				: {}),
			...(rpcDenial.has(name)
				? { rpcErrorCode: -32602, rpcErrorMessage: "memory entry rejected" }
				: {}),
			...(name === "cross_source_read_denied"
				? {
						observedResultCount: 0,
						sentinelSeeded: true,
						sentinelSeedObservedPeerAddress: "172.30.92.12",
						sentinelSeedObservedPeerSource: "server-peer-echo",
						sentinelSeedExpectedPeerAddress: "172.30.92.12",
						sentinelSeedExpectedPeerSource: "configured-off-domain-ip",
						sentinelSeedAuthorityDomain: "social",
						sentinelSeedMemorySource: "social",
					}
				: {}),
		})),
	};
}

function signedEvidence(): ServedMcpMemoryEvidence {
	const evidence = unsignedEvidence();
	return { ...evidence, runnerAttestation: signServedMcpMemoryAttestation(evidence) };
}

const liveOptions = () => ({ allowStaleAttestations: false, now: new Date(), relayPublicKey });

describe("served-MCP memory attestation gate (live cutover)", () => {
	it("grants productionEnable for valid signed evidence", () => {
		const report = evaluateServedMcpMemoryEvidence(signedEvidence(), liveOptions());
		expect(report.status).toBe("pass");
		expect(report.productionEnable).toBe(true);
		expect(report.gates.find((gate) => gate.name === "memory.attestation")).toBeUndefined();
	});

	it("rejects unsigned evidence (runnerAttestation missing)", () => {
		const report = evaluateServedMcpMemoryEvidence(unsignedEvidence(), liveOptions());
		expect(report.productionEnable).toBe(false);
		expect(report.gates.find((gate) => gate.name === "memory.attestation")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("runnerAttestation is missing"),
		});
	});

	it("rejects a hand-edited body whose signed digest no longer matches", () => {
		const signed = signedEvidence();
		// Tamper a field bound only through evidenceSha256 (summary) after signing.
		const tampered = { ...signed, summary: "attacker-substituted summary" };
		const report = evaluateServedMcpMemoryEvidence(tampered, liveOptions());
		expect(report.productionEnable).toBe(false);
		expect(report.gates.find((gate) => gate.name === "memory.attestation")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("evidenceSha256 mismatch"),
		});
	});

	it("rejects an attestation signed by a non-relay (attacker) key", () => {
		const signed = signedEvidence();
		const attacker = generateKeyPair();
		const report = evaluateServedMcpMemoryEvidence(signed, {
			...liveOptions(),
			relayPublicKey: attacker.publicKey,
		});
		expect(report.productionEnable).toBe(false);
		expect(report.gates.find((gate) => gate.name === "memory.attestation")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("signature is invalid"),
		});
	});

	it("does not require an attestation when stale attestations are allowed (non-live)", () => {
		const report = evaluateServedMcpMemoryEvidence(unsignedEvidence(), {
			allowStaleAttestations: true,
			now: new Date(),
		});
		expect(report.gates.find((gate) => gate.name === "memory.attestation")).toBeUndefined();
	});

	it("requires an attestation when strict archival validation asks for one", () => {
		const report = evaluateServedMcpMemoryEvidence(unsignedEvidence(), {
			allowStaleAttestations: true,
			requireRunnerAttestation: true,
			now: new Date(),
		});
		expect(report.productionEnable).toBe(false);
		expect(report.gates.find((gate) => gate.name === "memory.attestation")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("runnerAttestation is missing"),
		});
	});
});
