import crypto from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	evaluateServedMcpHouseholdMemoryEvidence,
	runServedMcpHouseholdMemoryProbe,
	SERVED_MCP_HOUSEHOLD_MEMORY_REQUIRED_PROPERTIES,
	type ServedMcpHouseholdMemoryEvidence,
} from "../../src/hermes/served-mcp-household-memory.js";
import { signServedMcpMemoryAttestation } from "../../src/hermes/served-mcp-memory-attestation.js";
import { generateKeyPair } from "../../src/internal-auth.js";

const savedRelayKeys = {
	private: process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY,
	public: process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY,
};
const CREDENTIAL_SHAPED_NONCE = Buffer.from("aa123456782bcccccccccccccccccccc", "hex");

const EXPECTED_REQUIRED_PROPERTIES = [
	"parent_a_authority_observed",
	"parent_b_authority_observed",
	"parent_a_write_recall",
	"parent_b_write_recall",
	"parent_a_sibling_read_denied",
	"parent_b_sibling_read_denied",
	"client_source_denied",
	"secret_write_rejected",
	"instruction_like_write_rejected",
	"artifact_redacted",
] as const;

beforeEach(() => {
	const relayKeys = generateKeyPair();
	process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
	process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;
});

afterEach(() => {
	vi.restoreAllMocks();
	if (savedRelayKeys.private === undefined) delete process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
	else process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = savedRelayKeys.private;
	if (savedRelayKeys.public === undefined) delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
	else process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = savedRelayKeys.public;
});

describe("served-MCP household memory sibling probe", () => {
	it("pins the required property catalog independently of the evaluator", () => {
		expect(SERVED_MCP_HOUSEHOLD_MEMORY_REQUIRED_PROPERTIES).toEqual(EXPECTED_REQUIRED_PROPERTIES);
	});

	it("does not scan relay-signed crypto metadata as evidence content", async () => {
		vi.spyOn(crypto, "randomBytes").mockReturnValue(CREDENTIAL_SHAPED_NONCE);
		const evidence = await passingEvidence();

		const report = evaluateServedMcpHouseholdMemoryEvidence(evidence);
		expect(report.status).toBe("pass");
		expect(report.productionEnable).toBe(true);
		expect(report.gates).toContainEqual(
			expect.objectContaining({ name: "household-memory.artifact_redacted", status: "pass" }),
		);
	});

	it("proves two-way own recall and sibling isolation without weakening the private probe", async () => {
		const evidence = await runServedMcpHouseholdMemoryProbe({
			allowRun: true,
			parentAEndpoint: {
				url: "http://tc-hermes-contained/mcp",
				headers: { Authorization: "Bearer parent-a" },
			},
			parentBEndpoint: {
				url: "http://tc-hermes-contained/mcp",
				headers: { Authorization: "Bearer parent-b" },
			},
			parentAMemorySource: "household:parent-a",
			parentBMemorySource: "household:parent-b",
			expectedPeerAddress: "172.30.92.11",
			fetchImpl: householdBridgeFetcher(),
			now: new Date("2026-07-17T09:00:00.000Z"),
		});

		expect(evidence).toMatchObject({
			probeId: "served_mcp.household_memory",
			status: "pass",
			ran: true,
			memorySource: "household:parent-a",
			siblingMemorySource: "household:parent-b",
			properties: {
				parent_a_write_recall: true,
				parent_b_write_recall: true,
				parent_a_sibling_read_denied: true,
				parent_b_sibling_read_denied: true,
			},
		});
		expect(evaluateServedMcpHouseholdMemoryEvidence(evidence)).toMatchObject({
			status: "pass",
			productionEnable: true,
		});
	});

	it("fails if the sibling source is tampered after the signed run", async () => {
		const evidence = await runServedMcpHouseholdMemoryProbe({
			allowRun: true,
			parentAEndpoint: { url: "http://mcp", headers: { Authorization: "Bearer parent-a" } },
			parentBEndpoint: { url: "http://mcp", headers: { Authorization: "Bearer parent-b" } },
			parentAMemorySource: "household:parent-a",
			parentBMemorySource: "household:parent-b",
			expectedPeerAddress: "172.30.92.11",
			fetchImpl: householdBridgeFetcher(),
			now: new Date("2026-07-17T09:00:00.000Z"),
		});

		const tampered = { ...evidence, siblingMemorySource: "household:parent-c" };
		expect(evaluateServedMcpHouseholdMemoryEvidence(tampered)).toMatchObject({
			status: "fail",
			productionEnable: false,
		});
	});

	it.each(
		EXPECTED_REQUIRED_PROPERTIES.flatMap((property) => [
			[property, "missing" as const],
			[property, "false" as const],
		]),
	)("fails when required property %s is %s", async (property, mutation) => {
		const evidence = await passingEvidence();
		const properties = { ...evidence.properties };
		if (mutation === "missing") delete properties[property];
		else properties[property] = false;
		const report = evaluateServedMcpHouseholdMemoryEvidence(
			resignEvidence({ ...evidence, properties }),
		);

		expect(report).toMatchObject({ status: "fail", productionEnable: false });
		expect(report.gates).toContainEqual(
			expect.objectContaining({
				name: `household-memory.${property}`,
				status: "fail",
			}),
		);
	});

	it.each([
		"parentA",
		"parentB",
	] as const)("fails when %s was observed from a different peer", async (parent) => {
		const evidence = await passingEvidence();
		const origin = {
			...evidence.origin,
			[parent]: { ...evidence.origin[parent], observedPeerAddress: "172.30.92.99" },
		};
		const report = evaluateServedMcpHouseholdMemoryEvidence(
			resignEvidence({ ...evidence, origin }),
		);

		expect(report).toMatchObject({ status: "fail", productionEnable: false });
		expect(report.gates).toContainEqual(
			expect.objectContaining({ name: "household-memory.origin", status: "fail" }),
		);
	});

	it.each([
		"parentA",
		"parentB",
	] as const)("fails when %s is observed under a non-household domain", async (parent) => {
		const evidence = await passingEvidence();
		const origin = {
			...evidence.origin,
			[parent]: { ...evidence.origin[parent], domain: "private" },
		};
		const report = evaluateServedMcpHouseholdMemoryEvidence(
			resignEvidence({ ...evidence, origin }),
		);

		expect(report).toMatchObject({ status: "fail", productionEnable: false });
		expect(report.gates).toContainEqual(
			expect.objectContaining({ name: "household-memory.origin", status: "fail" }),
		);
	});

	it("fails when the two bindings claim the same memory source", async () => {
		const evidence = await passingEvidence();
		const origin = {
			...evidence.origin,
			parentB: { ...evidence.origin.parentB, memorySource: evidence.memorySource },
		};
		const report = evaluateServedMcpHouseholdMemoryEvidence(
			resignEvidence({
				...evidence,
				siblingMemorySource: evidence.memorySource,
				origin,
			}),
		);

		expect(report).toMatchObject({ status: "fail", productionEnable: false });
		expect(report.gates).toContainEqual(
			expect.objectContaining({ name: "household-memory.sources", status: "fail" }),
		);
	});

	it("fails when the sibling source is outside the household family", async () => {
		const evidence = await passingEvidence();
		const origin = {
			...evidence.origin,
			parentB: { ...evidence.origin.parentB, memorySource: "telegram:parent-b" },
		};
		const report = evaluateServedMcpHouseholdMemoryEvidence(
			resignEvidence({
				...evidence,
				siblingMemorySource: "telegram:parent-b",
				origin,
			}),
		);

		expect(report).toMatchObject({ status: "fail", productionEnable: false });
		expect(report.gates).toContainEqual(
			expect.objectContaining({ name: "household-memory.sources", status: "fail" }),
		);
	});

	it("fails stale evidence independently of its valid signature", async () => {
		const evidence = await passingEvidence(new Date("2026-01-01T00:00:00.000Z"));
		const report = evaluateServedMcpHouseholdMemoryEvidence(evidence, {
			allowStaleAttestations: false,
			now: new Date("2026-07-17T10:00:00.000Z"),
		});

		expect(report).toMatchObject({ status: "fail", productionEnable: false });
		expect(report.gates).toContainEqual(
			expect.objectContaining({ name: "household-memory.freshness", status: "fail" }),
		);
	});
});

async function passingEvidence(
	now = new Date("2026-07-17T09:00:00.000Z"),
): Promise<ServedMcpHouseholdMemoryEvidence> {
	return runServedMcpHouseholdMemoryProbe({
		allowRun: true,
		parentAEndpoint: { url: "http://mcp", headers: { Authorization: "Bearer parent-a" } },
		parentBEndpoint: { url: "http://mcp", headers: { Authorization: "Bearer parent-b" } },
		parentAMemorySource: "household:parent-a",
		parentBMemorySource: "household:parent-b",
		expectedPeerAddress: "172.30.92.11",
		fetchImpl: householdBridgeFetcher(),
		now,
	});
}

function resignEvidence(
	evidence: ServedMcpHouseholdMemoryEvidence,
): ServedMcpHouseholdMemoryEvidence {
	const { runnerAttestation: _oldAttestation, ...unsigned } = evidence;
	return { ...unsigned, runnerAttestation: signServedMcpMemoryAttestation(unsigned) };
}

function householdBridgeFetcher(): typeof fetch {
	const stores = new Map<string, Map<string, { id: string; content: string }>>([
		["parent-a", new Map()],
		["parent-b", new Map()],
	]);
	return (async (_url: unknown, init?: RequestInit) => {
		const authorization = new Headers(init?.headers).get("Authorization") ?? "";
		const bindingId = authorization.endsWith("parent-a") ? "parent-a" : "parent-b";
		const store = stores.get(bindingId);
		if (!store) throw new Error("unknown household probe binding");
		const payload = JSON.parse(String(init?.body ?? "{}")) as {
			method?: string;
			params?: { name?: string; arguments?: Record<string, unknown> };
		};
		if (payload.method === "initialize") {
			return fakeResponse({
				result: {
					ok: true,
					telclaudeProbeAuthority: {
						domain: "household",
						memorySource: `household:${bindingId}`,
						profileId: bindingId,
						endpointId: "tc-hermes-private",
						networkNamespace: "telclaude_internal",
					},
				},
			});
		}
		const args = payload.params?.arguments ?? {};
		if (containsClientMemoryAuthority(args)) {
			return fakeResponse({
				error: { code: -32001, message: "MCP client cannot supply memory authority fields" },
			});
		}
		if (payload.params?.name === "tc_memory_write") {
			const content = String(args.content ?? "");
			if (content.includes("AKIA") || /ignore all previous/i.test(content)) {
				return fakeResponse({ error: { code: -32602, message: "memory entry rejected" } });
			}
			const id = String(args.id ?? "");
			store.set(id, { id, content });
			return fakeResponse({ result: { accepted: 1 } });
		}
		if (payload.params?.name === "tc_memory_search") {
			const query = String(args.query ?? "");
			return fakeResponse({
				result: { entries: [...store.values()].filter((entry) => entry.content.includes(query)) },
			});
		}
		return fakeResponse({ result: {} });
	}) as typeof fetch;
}

const CLIENT_AUTHORITY_KEYS = new Set([
	"actorId",
	"domain",
	"memorySource",
	"namespace",
	"source",
	"sources",
	"subjectUserId",
	"writableNamespace",
]);

function containsClientMemoryAuthority(value: unknown): boolean {
	if (Array.isArray(value)) return value.some(containsClientMemoryAuthority);
	if (!value || typeof value !== "object") return false;
	return Object.entries(value as Record<string, unknown>).some(
		([key, child]) => CLIENT_AUTHORITY_KEYS.has(key) || containsClientMemoryAuthority(child),
	);
}

function fakeResponse(body: unknown): Response {
	return {
		status: 200,
		text: async () => JSON.stringify(body),
		headers: {
			get: (name: string) =>
				name === "x-telclaude-live-mcp-observed-peer-address" ? "172.30.92.11" : null,
		},
	} as unknown as Response;
}
