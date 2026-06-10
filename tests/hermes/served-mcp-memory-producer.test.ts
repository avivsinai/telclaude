import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	evaluateServedMcpMemoryEvidence,
	runServedMcpMemoryProbe,
} from "../../src/hermes/served-mcp-memory.js";
import { generateKeyPair } from "../../src/internal-auth.js";

// The producer signs evidence with the operator relay key; provide a deterministic
// keypair so signServedMcpMemoryAttestation can sign and the evaluator can verify.
const savedRelayKeys = {
	private: process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY,
	public: process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY,
};
beforeEach(() => {
	const relayKeys = generateKeyPair();
	process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
	process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;
});
afterEach(() => {
	if (savedRelayKeys.private === undefined) delete process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
	else process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = savedRelayKeys.private;
	if (savedRelayKeys.public === undefined) delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
	else process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = savedRelayKeys.public;
});

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

const CLIENT_MEMORY_AUTHORITY_KEYS = new Set([
	"authority",
	"authorityHandle",
	"connection",
	"sessionKey",
	"actorId",
	"profileId",
	"domain",
	"memorySource",
	"source",
	"sources",
	"sourceFamilies",
	"trust",
	"writableNamespace",
	"providerAuthority",
	"endpointId",
	"networkNamespace",
	"turnConversationRef",
	"turnId",
	"inboundTurnId",
	"inboundTurnRef",
	"namespace",
	"peerAddress",
]);

function containsClientMemoryAuthority(value: unknown): boolean {
	if (Array.isArray(value)) return value.some(containsClientMemoryAuthority);
	if (typeof value !== "object" || value === null) return false;
	return Object.entries(value as Record<string, unknown>).some(
		([key, child]) => CLIENT_MEMORY_AUTHORITY_KEYS.has(key) || containsClientMemoryAuthority(child),
	);
}

// Simulates the served-MCP bridge: server-stamps the source, rejects
// secret/instruction writes with an RPC error, and returns an empty result for a
// cross-source (social-sentinel) search.
function bridgeFetcher(): typeof fetch {
	return (async (url: unknown, init?: { body?: unknown }) => {
		const payload = JSON.parse(String(init?.body ?? "{}")) as {
			method?: string;
			params?: { name?: string; arguments?: Record<string, unknown> };
		};
		if (payload.method === "initialize") {
			const social = String(url).includes("tc-hermes-social-sentinel");
			const peerAddress = social ? "172.30.92.12" : "172.30.92.11";
			return fakeResponse(
				{
					result: {
						ok: true,
						telclaudeProbeAuthority: social
							? {
									domain: "social",
									memorySource: "social",
									profileId: "social",
									endpointId: "tc-hermes-social",
									networkNamespace: "telclaude_internal",
								}
							: {
									domain: "private",
									memorySource: "telegram:default",
									profileId: "default",
									endpointId: "tc-hermes-private",
									networkNamespace: "telclaude_internal",
								},
					},
				},
				peerAddress,
			);
		}
		const tool = payload.params?.name;
		const args = payload.params?.arguments ?? {};
		if (
			(tool === "tc_memory_write" || tool === "tc_memory_search") &&
			containsClientMemoryAuthority(args)
		) {
			return fakeResponse({
				error: { code: -32001, message: "MCP client cannot supply memory authority fields" },
			});
		}
		if (tool === "tc_memory_write") {
			const content = String(args.content ?? "");
			if (content.includes("AKIA") || /ignore all previous/i.test(content)) {
				return fakeResponse({ error: { code: -32602, message: "memory entry rejected" } });
			}
			return fakeResponse({ result: { id: args.id } });
		}
		if (tool === "tc_memory_search") {
			const query = String(args.query ?? "");
			if (query.includes("social-sentinel")) {
				const social = String(url).includes("tc-hermes-social-sentinel");
				return fakeResponse({
					result: {
						entries: social
							? [{ id: "probe.memory.social-sentinel", content: "social sentinel" }]
							: [],
					},
				});
			}
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
			expectedPeerAddress: "172.30.92.11",
			expectedSocialSentinelPeerAddress: "172.30.92.12",
			socialSentinelEndpoint: { url: "http://tc-hermes-social-sentinel/mcp" },
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
			expectedPeerAddress: "172.30.92.11",
			expectedSocialSentinelPeerAddress: "172.30.92.12",
			socialSentinelEndpoint: { url: "http://tc-hermes-social-sentinel/mcp" },
			fetchImpl: bridgeFetcher(),
			now: new Date("2026-06-05T20:00:00.000Z"),
		});
		const cross = evidence.checks.find((c) => c.name === "cross_source_read_denied");
		expect(cross?.observedResultCount).toBe(0);
		expect(cross?.privateObservedResultCount).toBe(0);
		expect(cross?.offDomainObservedResultCount).toBeGreaterThan(0);
		expect(cross?.offDomainObservedEntryHashes?.[0]).toMatch(/^sha256:[a-f0-9]{64}$/);
		expect(cross?.sentinelSeeded).toBe(true);
		expect(cross).toMatchObject({
			sentinelSeedObservedPeerAddress: "172.30.92.12",
			sentinelSeedObservedPeerSource: "server-peer-echo",
			sentinelSeedExpectedPeerAddress: "172.30.92.12",
			sentinelSeedExpectedPeerSource: "configured-off-domain-ip",
			sentinelSeedAuthorityDomain: "social",
			sentinelSeedMemorySource: "social",
		});
		const secret = evidence.checks.find((c) => c.name === "secret_write_rejected");
		expect(typeof secret?.rpcErrorCode).toBe("number");
		expect(typeof secret?.rpcErrorMessage).toBe("string");
		const source = evidence.checks.find((c) => c.name === "memory_source_resolved_server_side");
		expect(source).toMatchObject({
			clientSourceWriteRpcErrorCode: -32001,
			clientSourceSearchRpcErrorCode: -32001,
		});
	});

	it("does not self-anchor origin to the observed peer echo", async () => {
		const evidence = await runServedMcpMemoryProbe({
			allowRun: true,
			endpoint: { url: "http://tc-hermes-contained/mcp" },
			expectedPeerAddress: "172.30.92.99",
			expectedSocialSentinelPeerAddress: "172.30.92.12",
			socialSentinelEndpoint: { url: "http://tc-hermes-social-sentinel/mcp" },
			fetchImpl: bridgeFetcher(),
			now: new Date("2026-06-05T20:00:00.000Z"),
		});
		expect(evidence.origin).toMatchObject({
			observedPeerAddress: "172.30.92.11",
			expectedPeerAddress: "172.30.92.99",
		});
		expect(evidence.status).toBe("fail");
		expect(evaluateServedMcpMemoryEvidence(evidence).status).toBe("fail");
	});

	it("fails cross-source denial if the sentinel was not seeded", async () => {
		const evidence = await runServedMcpMemoryProbe({
			allowRun: true,
			endpoint: { url: "http://tc-hermes-contained/mcp" },
			expectedPeerAddress: "172.30.92.11",
			fetchImpl: bridgeFetcher(),
			now: new Date("2026-06-05T20:00:00.000Z"),
		});
		expect(evidence.checks.find((c) => c.name === "cross_source_read_denied")).toMatchObject({
			status: "fail",
			sentinelSeeded: false,
		});
		expect(evidence.status).toBe("fail");
		expect(evaluateServedMcpMemoryEvidence(evidence).status).toBe("fail");
	});

	it("fails cross-source denial on malformed private search even after seeding", async () => {
		const malformedCrossSearch = (async (url: unknown, init?: { body?: unknown }) => {
			const payload = JSON.parse(String(init?.body ?? "{}")) as {
				params?: { name?: string; arguments?: Record<string, unknown> };
			};
			if (
				String(url).includes("tc-hermes-contained") &&
				payload.params?.name === "tc_memory_search" &&
				String(payload.params.arguments?.query ?? "").includes("social-sentinel")
			) {
				return fakeResponse({ result: { malformed: true } });
			}
			return bridgeFetcher()(url as RequestInfo | URL, init as RequestInit);
		}) as unknown as typeof fetch;
		const evidence = await runServedMcpMemoryProbe({
			allowRun: true,
			endpoint: { url: "http://tc-hermes-contained/mcp" },
			expectedPeerAddress: "172.30.92.11",
			expectedSocialSentinelPeerAddress: "172.30.92.12",
			socialSentinelEndpoint: { url: "http://tc-hermes-social-sentinel/mcp" },
			fetchImpl: malformedCrossSearch,
			now: new Date("2026-06-05T20:00:00.000Z"),
		});
		expect(evidence.checks.find((c) => c.name === "cross_source_read_denied")).toMatchObject({
			status: "fail",
			sentinelSeeded: true,
		});
		expect(evaluateServedMcpMemoryEvidence(evidence).status).toBe("fail");
	});

	it("fails cross-source denial if the off-domain sentinel is not searchable", async () => {
		const droppedOffDomainSentinel = (async (url: unknown, init?: { body?: unknown }) => {
			const payload = JSON.parse(String(init?.body ?? "{}")) as {
				params?: { name?: string; arguments?: Record<string, unknown> };
			};
			if (
				String(url).includes("tc-hermes-social-sentinel") &&
				payload.params?.name === "tc_memory_search" &&
				String(payload.params.arguments?.query ?? "").includes("social-sentinel")
			) {
				return fakeResponse({ result: { entries: [] } });
			}
			return bridgeFetcher()(url as RequestInfo | URL, init as RequestInit);
		}) as unknown as typeof fetch;
		const evidence = await runServedMcpMemoryProbe({
			allowRun: true,
			endpoint: { url: "http://tc-hermes-contained/mcp" },
			expectedPeerAddress: "172.30.92.11",
			expectedSocialSentinelPeerAddress: "172.30.92.12",
			socialSentinelEndpoint: { url: "http://tc-hermes-social-sentinel/mcp" },
			fetchImpl: droppedOffDomainSentinel,
			now: new Date("2026-06-05T20:00:00.000Z"),
		});
		expect(evidence.checks.find((c) => c.name === "cross_source_read_denied")).toMatchObject({
			status: "fail",
			sentinelSeeded: true,
			offDomainObservedResultCount: 0,
			observedResultCount: 0,
		});
		expect(evaluateServedMcpMemoryEvidence(evidence).status).toBe("fail");
	});

	it("returns a fail-closed pending artifact without --allow-run", async () => {
		const evidence = await runServedMcpMemoryProbe({ allowRun: false });
		expect(evidence.ran).toBe(false);
		expect(evidence.status).toBe("pending");
		expect(evaluateServedMcpMemoryEvidence(evidence).status).toBe("fail");
	});

	it("uses the off-domain fetcher for sentinel seed traffic", async () => {
		const privateUrls: string[] = [];
		const socialUrls: string[] = [];
		const privateFetcher = (async (url: unknown, init?: RequestInit) => {
			privateUrls.push(String(url));
			if (String(url).includes("tc-hermes-social-sentinel")) {
				return fakeResponse({ error: { code: -32001, message: "wrong origin" } });
			}
			return bridgeFetcher()(url as RequestInfo | URL, init);
		}) as unknown as typeof fetch;
		const socialFetcher = (async (url: unknown, init?: RequestInit) => {
			socialUrls.push(String(url));
			if (!String(url).includes("tc-hermes-social-sentinel")) {
				return fakeResponse({ error: { code: -32001, message: "wrong origin" } });
			}
			return bridgeFetcher()(url as RequestInfo | URL, init);
		}) as unknown as typeof fetch;

		const evidence = await runServedMcpMemoryProbe({
			allowRun: true,
			endpoint: { url: "http://tc-hermes-contained/mcp" },
			expectedPeerAddress: "172.30.92.11",
			expectedSocialSentinelPeerAddress: "172.30.92.12",
			socialSentinelEndpoint: { url: "http://tc-hermes-social-sentinel/mcp" },
			fetchImpl: privateFetcher,
			socialSentinelFetchImpl: socialFetcher,
			now: new Date("2026-06-05T20:00:00.000Z"),
		});

		expect(evidence.status).toBe("pass");
		expect(privateUrls.length).toBeGreaterThan(0);
		expect(privateUrls.every((url) => url.includes("tc-hermes-contained"))).toBe(true);
		expect(socialUrls.length).toBeGreaterThan(0);
		expect(socialUrls.every((url) => url.includes("tc-hermes-social-sentinel"))).toBe(true);
	});
});
