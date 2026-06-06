import { describe, expect, it } from "vitest";
import {
	evaluateServedMcpMemoryEvidence,
	SERVED_MCP_MEMORY_REQUIRED_PROPERTY_NAMES,
	type ServedMcpMemoryEvidence,
} from "../../src/hermes/served-mcp-memory.js";

function validEvidence(): ServedMcpMemoryEvidence {
	const properties = Object.fromEntries(
		SERVED_MCP_MEMORY_REQUIRED_PROPERTY_NAMES.map((name) => [name, true]),
	) as ServedMcpMemoryEvidence["properties"];
	const rpcDenial = new Set(["secret_write_rejected", "instruction_like_write_rejected"]);
	const checks = SERVED_MCP_MEMORY_REQUIRED_PROPERTY_NAMES.map((name) => ({
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
				}
			: {}),
	}));
	return {
		schemaVersion: "telclaude.hermes.served-mcp-memory.v1",
		probeId: "served_mcp.memory",
		status: "pass",
		ran: true,
		generatedAt: "2026-06-05T20:00:00.000Z",
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
		checks,
	};
}

describe("evaluateServedMcpMemoryEvidence", () => {
	it("passes for complete, check-backed, contained-peer-origin evidence", () => {
		const report = evaluateServedMcpMemoryEvidence(validEvidence());
		expect(report.status).toBe("pass");
		expect(report.productionEnable).toBe(true);
		expect(report.gates.every((g) => g.status === "pass")).toBe(true);
	});

	it("input_errors when evidence is missing", () => {
		const report = evaluateServedMcpMemoryEvidence(undefined);
		expect(report.status).toBe("input_error");
		expect(report.gates[0]?.name).toBe("memory.evidence");
	});

	it("input_errors on a schema-invalid artifact", () => {
		const report = evaluateServedMcpMemoryEvidence({ schemaVersion: "wrong" });
		expect(report.status).toBe("input_error");
	});

	it("fails origin for relay-self-smoke evidence", () => {
		const ev = validEvidence();
		const report = evaluateServedMcpMemoryEvidence({
			...ev,
			origin: { ...ev.origin, kind: "relay-self-smoke" },
		});
		expect(report.status).toBe("fail");
		expect(report.gates.find((g) => g.name === "memory.origin")?.status).toBe("fail");
	});

	it("fails origin when observed and expected peer addresses differ", () => {
		const ev = validEvidence();
		const report = evaluateServedMcpMemoryEvidence({
			...ev,
			origin: { ...ev.origin, observedPeerAddress: "172.30.92.99" },
		});
		expect(report.gates.find((g) => g.name === "memory.origin")?.status).toBe("fail");
	});

	it("fails when the private/public air-gap (cross_source_read_denied) is not proven", () => {
		const ev = validEvidence();
		const report = evaluateServedMcpMemoryEvidence({
			...ev,
			properties: { ...ev.properties, cross_source_read_denied: false },
		});
		expect(report.status).toBe("fail");
		expect(report.gates.find((g) => g.name === "memory.cross_source_read_denied")?.status).toBe(
			"fail",
		);
	});

	it("rejects a self-reported property bit with no passing backing check", () => {
		const ev = validEvidence();
		// keep the bit true but drop its backing check
		const report = evaluateServedMcpMemoryEvidence({
			...ev,
			checks: ev.checks.filter((c) => c.name !== "secret_write_rejected"),
		});
		const gate = report.gates.find((g) => g.name === "memory.secret_write_rejected");
		expect(gate?.status).toBe("fail");
		expect(gate?.detail).toContain("lacks a passing backing check");
	});

	it("rejects a property whose backing check failed", () => {
		const ev = validEvidence();
		const report = evaluateServedMcpMemoryEvidence({
			...ev,
			checks: ev.checks.map((c) =>
				c.name === "episodic_recall_sanitized" ? { ...c, status: "fail" as const } : c,
			),
		});
		expect(report.gates.find((g) => g.name === "memory.episodic_recall_sanitized")?.status).toBe(
			"fail",
		);
	});

	it("fails the source gate for social, bare/legacy, or malformed memorySource", () => {
		const ev = validEvidence();
		for (const bad of ["social", "telegram", "telegram:Bad_Profile"]) {
			const report = evaluateServedMcpMemoryEvidence({ ...ev, memorySource: bad });
			expect(report.status).toBe("fail");
			expect(report.gates.find((g) => g.name === "memory.source")?.status).toBe("fail");
		}
	});

	it("passes the source gate for a valid telegram:<profile> source", () => {
		const report = evaluateServedMcpMemoryEvidence({
			...validEvidence(),
			memorySource: "telegram:ops",
		});
		expect(report.gates.find((g) => g.name === "memory.source")?.status).toBe("pass");
		expect(report.status).toBe("pass");
	});

	it("requires an empty-result proof for cross-source denial (server-scoped, not an RPC error)", () => {
		const ev = validEvidence();
		// drop observedResultCount from cross_source_read_denied's check
		const report = evaluateServedMcpMemoryEvidence({
			...ev,
			checks: ev.checks.map((c) =>
				c.name === "cross_source_read_denied"
					? { name: c.name, status: c.status, detail: c.detail }
					: c,
			),
		});
		expect(report.status).toBe("fail");
		const gate = report.gates.find((g) => g.name === "memory.cross_source_read_denied");
		expect(gate?.status).toBe("fail");
		expect(gate?.detail).toContain("off-domain sentinel");
	});

	it("requires write and search denial proof for client-supplied memory source", () => {
		const ev = validEvidence();
		const report = evaluateServedMcpMemoryEvidence({
			...ev,
			checks: ev.checks.map((c) =>
				c.name === "memory_source_resolved_server_side"
					? { name: c.name, status: c.status, detail: c.detail }
					: c,
			),
		});
		expect(report.status).toBe("fail");
		const gate = report.gates.find(
			(g) => g.name === "memory.memory_source_resolved_server_side",
		);
		expect(gate?.status).toBe("fail");
		expect(gate?.detail).toContain("client-supplied source authority");
	});

	it("requires proof that the off-domain sentinel was seeded", () => {
		const ev = validEvidence();
		const report = evaluateServedMcpMemoryEvidence({
			...ev,
			checks: ev.checks.map((c) =>
				c.name === "cross_source_read_denied"
					? { name: c.name, status: c.status, detail: c.detail, observedResultCount: 0 }
					: c,
			),
		});
		expect(report.gates.find((g) => g.name === "memory.cross_source_read_denied")?.status).toBe(
			"fail",
		);
	});

	it("requires the sentinel seed peer to differ from the private contained peer", () => {
		const ev = validEvidence();
		const report = evaluateServedMcpMemoryEvidence({
			...ev,
			checks: ev.checks.map((c) =>
				c.name === "cross_source_read_denied"
					? {
							...c,
							sentinelSeedObservedPeerAddress: "172.30.92.11",
							sentinelSeedExpectedPeerAddress: "172.30.92.11",
						}
					: c,
			),
		});
		expect(report.gates.find((g) => g.name === "memory.cross_source_read_denied")?.status).toBe(
			"fail",
		);
	});

	it("fails cross-source denial when the search returned rows (not actually denied)", () => {
		const ev = validEvidence();
		const report = evaluateServedMcpMemoryEvidence({
			...ev,
			checks: ev.checks.map((c) =>
				c.name === "cross_source_read_denied" ? { ...c, observedResultCount: 3 } : c,
			),
		});
		expect(report.gates.find((g) => g.name === "memory.cross_source_read_denied")?.status).toBe(
			"fail",
		);
	});

	it("requires rpcErrorCode evidence for write-rejection denials", () => {
		const ev = validEvidence();
		const report = evaluateServedMcpMemoryEvidence({
			...ev,
			checks: ev.checks.map((c) =>
				c.name === "secret_write_rejected"
					? { name: c.name, status: c.status, detail: c.detail }
					: c,
			),
		});
		expect(report.gates.find((g) => g.name === "memory.secret_write_rejected")?.status).toBe(
			"fail",
		);
	});

	it("forces artifact_redacted to fail when evidence bytes contain a secret (not self-attested)", () => {
		// bit true + passing backing check, but a credential-shaped token is embedded
		// in a free-text field — the evaluator must scan bytes and fail closed.
		const report = evaluateServedMcpMemoryEvidence({
			...validEvidence(),
			summary: "leak AKIAIOSFODNN7EXAMPLE embedded in summary",
		});
		expect(report.status).toBe("fail");
		expect(report.gates.find((g) => g.name === "memory.artifact_redacted")?.status).toBe("fail");
	});

	it("fails when status is pending or ran is false", () => {
		expect(evaluateServedMcpMemoryEvidence({ ...validEvidence(), status: "pending" }).status).toBe(
			"fail",
		);
		expect(evaluateServedMcpMemoryEvidence({ ...validEvidence(), ran: false }).status).toBe("fail");
	});

	it("rejects stale generatedAt when strict validation disallows stale attestations", () => {
		const report = evaluateServedMcpMemoryEvidence(validEvidence(), {
			allowStaleAttestations: false,
			now: new Date("2026-06-20T00:00:00.000Z"),
		});
		expect(report.gates.find((g) => g.name === "memory.freshness")?.status).toBe("fail");
	});
});
