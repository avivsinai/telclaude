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
	const checks = SERVED_MCP_MEMORY_REQUIRED_PROPERTY_NAMES.map((name) => ({
		name,
		status: "pass" as const,
		detail: `${name} proven`,
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
});
