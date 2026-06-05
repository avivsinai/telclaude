import { describe, expect, it } from "vitest";
import {
	evaluateServedMcpMemoryEvidence,
	runServedMcpMemoryProbe,
} from "../../src/hermes/served-mcp-memory.js";

function fakeResponse(body: unknown, peerHeader?: string): Response {
	return {
		status: 200,
		text: async () => JSON.stringify(body),
		headers: {
			get: (name: string) =>
				name === "x-telclaude-live-mcp-observed-peer-address" ? (peerHeader ?? null) : null,
		},
	} as unknown as Response;
}

// Simulates the served-MCP bridge: server-stamps the source, rejects
// secret/instruction writes with an RPC error, and returns an empty result for a
// cross-source (social-sentinel) search.
function bridgeFetcher(): typeof fetch {
	return (async (_url: unknown, init?: { body?: unknown }) => {
		const payload = JSON.parse(String(init?.body ?? "{}")) as {
			method?: string;
			params?: { name?: string; arguments?: Record<string, unknown> };
		};
		if (payload.method === "initialize") {
			return fakeResponse({ result: { ok: true } }, "172.30.92.11");
		}
		const tool = payload.params?.name;
		const args = payload.params?.arguments ?? {};
		if (tool === "tc_memory_write") {
			const content = String(args.content ?? "");
			if (content.includes("AKIA") || /ignore all previous/i.test(content)) {
				return fakeResponse({ error: { code: -32602, message: "memory entry rejected" } });
			}
			return fakeResponse({ result: { id: args.id } });
		}
		if (tool === "tc_memory_search") {
			const query = String(args.query ?? "");
			if (query.includes("social-sentinel")) return fakeResponse({ result: { entries: [] } });
			return fakeResponse({
				result: { entries: [{ id: "probe.memory.positive", content: "clean" }] },
			});
		}
		return fakeResponse({ result: {} });
	}) as unknown as typeof fetch;
}

describe("runServedMcpMemoryProbe", () => {
	it("produces evidence that the evaluator accepts (round-trip)", async () => {
		const evidence = await runServedMcpMemoryProbe({
			allowRun: true,
			endpoint: { url: "http://tc-hermes-contained/mcp" },
			fetchImpl: bridgeFetcher(),
			now: new Date("2026-06-05T20:00:00.000Z"),
		});
		expect(evidence.ran).toBe(true);
		expect(evidence.status).toBe("pass");
		// The producer's output must satisfy the hardened evaluator contract — this
		// fails if any derived field (origin, result count, denial code, source) is wrong.
		const report = evaluateServedMcpMemoryEvidence(evidence);
		expect(report.status).toBe("pass");
		expect(report.productionEnable).toBe(true);
	});

	it("derives the denial controls with real evidence shapes", async () => {
		const evidence = await runServedMcpMemoryProbe({
			allowRun: true,
			endpoint: { url: "http://tc-hermes-contained/mcp" },
			fetchImpl: bridgeFetcher(),
			now: new Date("2026-06-05T20:00:00.000Z"),
		});
		const cross = evidence.checks.find((c) => c.name === "cross_source_read_denied");
		expect(cross?.observedResultCount).toBe(0);
		const secret = evidence.checks.find((c) => c.name === "secret_write_rejected");
		expect(typeof secret?.rpcErrorCode).toBe("number");
		expect(typeof secret?.rpcErrorMessage).toBe("string");
	});

	it("returns a fail-closed pending artifact without --allow-run", async () => {
		const evidence = await runServedMcpMemoryProbe({ allowRun: false });
		expect(evidence.ran).toBe(false);
		expect(evidence.status).toBe("pending");
		expect(evaluateServedMcpMemoryEvidence(evidence).status).toBe("fail");
	});
});
