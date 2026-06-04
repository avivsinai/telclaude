import fs from "node:fs";
import type http from "node:http";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	EdgeAdapterSchemaVersions,
	type PreparedOutbound,
} from "../../src/hermes/edge-adapter-contract.js";
import { edgePreparedPayloadHash } from "../../src/hermes/edge-adapter-runtime.js";
import {
	createTelclaudeMcpSideEffectApprovalVerifier,
	generateTelclaudeMcpSideEffectApprovalToken,
	TelclaudeMcpSideEffectJtiStore,
} from "../../src/hermes/mcp/approval-token.js";
import {
	createTelclaudeMcpAuthorityRegistry,
	type TelclaudeMcpAuthorityConnection,
} from "../../src/hermes/mcp/authority-registry.js";
import {
	TELCLAUDE_MCP_TOOL_NAMES,
	type TelclaudeMcpAuthority,
} from "../../src/hermes/mcp/bridge.js";
import {
	createTelclaudeLiveMcpNodeHttpServer,
	createTelclaudeLiveMcpRelayHttpServer,
	TELCLAUDE_LIVE_MCP_DEPENDENCY_SURFACE,
	TELCLAUDE_LIVE_MCP_OBSERVED_PEER_HEADER,
	TELCLAUDE_LIVE_MCP_PLACEMENT_SIDE_HEADER,
	TELCLAUDE_LIVE_MCP_TRANSPORT,
	type TelclaudeLiveMcpJsonRpcResponse,
	type TelclaudeLiveMcpRelayClients,
} from "../../src/hermes/mcp/live-server.js";
import {
	createTelclaudeMcpSideEffectLedger,
	getTelclaudeMcpSideEffectApprovalBinding,
	type TelclaudeMcpOutboundSideEffectPrepareInput,
	type TelclaudeMcpProviderSideEffectPrepareInput,
	type TelclaudeMcpSideEffectLedger,
} from "../../src/hermes/mcp/side-effect-ledger.js";
import type { RelayConversation } from "../../src/hermes/relay-conversation-store.js";
import type { OutboundDeliveryDispatcher } from "../../src/relay/outbound-delivery-dispatcher.js";

describe("Telclaude live MCP relay-side server", () => {
	const cleanup: Array<() => void | Promise<void>> = [];

	afterEach(async () => {
		for (const clean of cleanup.splice(0).reverse()) {
			await clean();
		}
	});

	it("declares relay-side HTTP placement and exposes only the tc_ MCP protocol surface", async () => {
		const harness = createHarness(cleanup);

		expect(harness.server.transport).toBe(TELCLAUDE_LIVE_MCP_TRANSPORT);
		expect(harness.server.placement).toEqual({
			side: "relay",
			runsInHermesContainer: false,
			transport: "http",
			networkExposure: "relay_internal_only",
			bindHost: "telclaude",
			networkName: "telclaude-hermes-relay",
		});
		expect(harness.server.dependencySurface).toEqual(TELCLAUDE_LIVE_MCP_DEPENDENCY_SURFACE);

		const initialize = resultOf<{ capabilities: Record<string, unknown> }>(
			await harness.server.handleJsonRpc({
				jsonrpc: "2.0",
				id: "init",
				method: "initialize",
				params: { protocolVersion: "2024-11-05" },
			}),
		);
		expect(initialize.capabilities).toEqual({ tools: { listChanged: false } });

		const tools = resultOf<{ tools: Array<{ name: string }> }>(
			await harness.server.handleJsonRpc({
				jsonrpc: "2.0",
				id: "tools",
				method: "tools/list",
			}),
		);
		expect(tools.tools.map((tool) => tool.name)).toEqual([...TELCLAUDE_MCP_TOOL_NAMES]);

		await expectEmptySurface(harness.server.handleJsonRpc(rpc("resources/list")));
		await expectEmptySurface(harness.server.handleJsonRpc(rpc("prompts/list")));
		await expectEmptySurface(harness.server.handleJsonRpc(rpc("roots/list")));
		expect(
			await harness.server.handleJsonRpc(rpc("sampling/createMessage", undefined, "sample")),
		).toMatchObject({
			id: "sample",
			error: { code: -32001, message: "MCP sampling is disabled" },
		});
		expect(await harness.server.handleJsonRpc(rpc("unknown/method"))).toMatchObject({
			error: { code: -32601, message: "MCP method denied" },
		});
		expect(
			await harness.server.handleJsonRpc(
				toolCall("tc_nonexistent", { service: "bank" }),
				harness.privateContext,
			),
		).toMatchObject({
			error: { code: -32601, message: "MCP tool denied" },
		});
	});

	it("rejects malformed JSON-RPC envelopes before method dispatch", async () => {
		const harness = createHarness(cleanup);

		expect(
			await harness.server.handleJsonRpc({
				id: "missing-jsonrpc",
				method: "tools/list",
			}),
		).toMatchObject({
			id: "missing-jsonrpc",
			error: { code: -32600, message: "MCP JSON-RPC version must be 2.0" },
		});
		expect(
			await harness.server.handleJsonRpc({
				jsonrpc: "1.0",
				id: "wrong-jsonrpc",
				method: "tools/list",
			}),
		).toMatchObject({
			id: "wrong-jsonrpc",
			error: { code: -32600, message: "MCP JSON-RPC version must be 2.0" },
		});
		expect(
			await harness.server.handleJsonRpc({
				jsonrpc: "2.0",
				id: { nested: true },
				method: "tools/list",
			}),
		).toMatchObject({
			error: { code: -32600, message: "MCP JSON-RPC id is invalid" },
		});
		expect(await harness.server.handleJsonRpc([])).toMatchObject({
			error: { code: -32600, message: "MCP JSON-RPC batch requests are not supported" },
		});

		for (const method of ["constructor", "toString", "hasOwnProperty", "__proto__"]) {
			expect(
				await harness.server.handleJsonRpc(rpc(method, undefined, `method-${method}`)),
			).toMatchObject({
				id: `method-${method}`,
				error: { code: -32601, message: "MCP method denied" },
			});
		}

		expect(
			resultOf<{ tools: Array<{ name: string }> }>(
				await harness.server.handleJsonRpc(rpc("tools/list")),
			),
		).toEqual({
			tools: expect.arrayContaining([expect.objectContaining({ name: "tc_provider_read" })]),
		});
	});

	it("serves JSON-RPC over HTTP with relay-derived connection context and fails closed", async () => {
		const harness = createHarness(cleanup);
		const nodeServer = createTelclaudeLiveMcpNodeHttpServer(harness.server, {
			resolveConnection: () => harness.privateContext,
		});
		const { baseUrl, close } = await listen(nodeServer);
		cleanup.push(close);

		const response = await fetch(`${baseUrl}/mcp`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				jsonrpc: "2.0",
				id: "http-tools",
				method: "tools/list",
			}),
		});
		expect(response.status).toBe(200);
		expect(response.headers.get(TELCLAUDE_LIVE_MCP_OBSERVED_PEER_HEADER)).toBe("127.0.0.1");
		expect(response.headers.get(TELCLAUDE_LIVE_MCP_PLACEMENT_SIDE_HEADER)).toBe("relay");
		expect(await response.json()).toMatchObject({
			jsonrpc: "2.0",
			id: "http-tools",
			result: {
				tools: expect.arrayContaining([expect.objectContaining({ name: "tc_provider_read" })]),
			},
		});

		const malformed = await fetch(`${baseUrl}/mcp`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: "{not-json",
		});
		expect(malformed.status).toBe(400);
		expect(await malformed.json()).toMatchObject({
			error: { code: -32700, message: "MCP JSON parse error" },
		});

		const unauthenticated = await createTelclaudeLiveMcpNodeHttpServer(harness.server, {
			resolveConnection: () => null,
		});
		const unauth = await listen(unauthenticated);
		cleanup.push(unauth.close);
		const denied = await fetch(`${unauth.baseUrl}/mcp`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				jsonrpc: "2.0",
				id: "unauth-tools",
				method: "tools/list",
			}),
		});
		expect(denied.status).toBe(403);
		expect(denied.headers.get(TELCLAUDE_LIVE_MCP_OBSERVED_PEER_HEADER)).toBeNull();
		expect(await denied.json()).toMatchObject({
			id: "unauth-tools",
			error: { code: -32001, message: "MCP connection is not authorized" },
		});
	});

	it("resolves authority from relay transport identity and ignores message-supplied handles", async () => {
		const harness = createHarness(cleanup);
		const allowed = resultOf(
			await harness.server.handleJsonRpc(
				toolCall("tc_provider_read", {
					service: "bank",
					action: "balances.list",
					params: { account: "primary" },
					authorityHandle: harness.socialContext.authorityHandle,
					connection: harness.socialContext.connection,
					sessionKey: "telegram:social",
					actorId: "attacker",
					profileId: "social",
					domain: "social",
				}),
				harness.privateContext,
			),
		);

		expect(allowed).toEqual({ balances: [] });
		expect(harness.calls.providerRead).toEqual([
			expect.objectContaining({
				actorId: "operator",
				profileId: "ops",
				domain: "private",
				memorySource: "telegram:ops",
				service: "bank",
			}),
		]);

		expect(
			await harness.server.handleJsonRpc(
				toolCall("tc_provider_read", { service: "bank", action: "balances.list" }),
				{ ...harness.privateContext, authorityHandle: "tc_mcp_forged" },
			),
		).toMatchObject({
			error: { code: -32001, message: "MCP authority is not registered" },
		});
		expect(
			await harness.server.handleJsonRpc(
				toolCall("tc_provider_read", { service: "bank", action: "balances.list" }),
				{
					authorityHandle: harness.privateContext.authorityHandle,
					connection: harness.socialContext.connection,
				},
			),
		).toMatchObject({
			error: { code: -32001, message: "MCP authority connection mismatch" },
		});
	});

	it("denies cross-domain memory, out-of-scope provider, and legacy outbound attempts", async () => {
		const harness = createHarness(cleanup);

		expect(
			await harness.server.handleJsonRpc(
				toolCall("tc_memory_search", {
					query: "family",
					filters: { source: "social", profileId: "social" },
				}),
				harness.privateContext,
			),
		).toMatchObject({
			error: { code: -32001, message: "MCP client cannot supply memory authority fields" },
		});
		expect(
			await harness.server.handleJsonRpc(
				toolCall("tc_provider_read", { service: "clalit", action: "appointments.list" }),
				harness.privateContext,
			),
		).toMatchObject({
			error: { code: -32001, message: "provider scope denied: clalit" },
		});
		expect(
			await harness.server.handleJsonRpc(
				toolCall("tc_outbound_prepare", {
					channel: "telegram",
					recipient: "family",
					content: "hello",
				}),
				harness.privateContext,
			),
		).toMatchObject({
			error: {
				code: -32001,
				message: expect.stringContaining("Unrecognized keys"),
			},
		});
		expect(harness.calls.memorySearch).toEqual([]);
		expect(harness.calls.providerRead).toEqual([]);
		expect(harness.calls.outboundPrepare).toEqual([]);
	});

	it("rejects prototype-pollution keys in tool arguments before bridge dispatch", async () => {
		const harness = createHarness(cleanup);

		const forbiddenArgs = [
			JSON.parse(
				'{"service":"bank","action":"balances.list","params":{},"__proto__":{"polluted":true}}',
			),
			{ service: "bank", action: "balances.list", params: {}, constructor: { polluted: true } },
			{ service: "bank", action: "balances.list", params: {}, prototype: { polluted: true } },
			JSON.parse(
				'{"service":"bank","action":"balances.list","params":{"nested":{"__proto__":{"polluted":true}}}}',
			),
			{
				service: "bank",
				action: "balances.list",
				params: { nested: { constructor: { polluted: true } } },
			},
			{
				service: "bank",
				action: "balances.list",
				params: { nested: { prototype: { polluted: true } } },
			},
		];

		for (const args of forbiddenArgs) {
			expect(
				await harness.server.handleJsonRpc(
					toolCall("tc_provider_read", args),
					harness.privateContext,
				),
			).toMatchObject({
				error: {
					code: -32602,
					message: "MCP tools/call arguments contain forbidden prototype key",
				},
			});
		}

		expect(({} as Record<string, unknown>).polluted).toBeUndefined();
		expect(harness.calls.providerRead).toEqual([]);
		expect(
			resultOf(
				await harness.server.handleJsonRpc(
					toolCall("tc_provider_read", { service: "bank", action: "balances.list", params: {} }),
					harness.privateContext,
				),
			),
		).toEqual({ balances: [] });
	});

	it("executes provider side effects only through the ledger and preserves JTI on denials", async () => {
		const harness = createHarness(cleanup);
		const prepared = harness.ledger.prepare(providerPrepareInput());
		const token = await tokenFor(harness, prepared);
		harness.storeProviderApproval(prepared.ref, token);

		expect(
			await harness.server.handleJsonRpc(
				toolCall("tc_provider_execute_write", {
					actionRef: prepared.ref,
					approvalToken: token,
				}),
				harness.privateContext,
			),
		).toMatchObject({ error: { code: -32001 } });
		expect(harness.vault.verifyCalls).toHaveLength(0);
		expect(harness.calls.providerExecute).toEqual([]);
		expect(harness.ledger.get(prepared.ref)).toEqual(
			expect.objectContaining({ ref: prepared.ref, status: "prepared" }),
		);

		expect(
			resultOf(
				await harness.server.handleJsonRpc(
					toolCall("tc_provider_execute_write", {
						actionRef: "missing-ref",
					}),
					harness.privateContext,
				),
			),
		).toEqual({
			ok: false,
			code: "effect_not_found",
			reason: "side effect was not prepared",
			retryable: false,
		});
		expect(harness.vault.verifyCalls).toHaveLength(0);

		const wrongAuthority = harness.ledger.prepare(
			providerPrepareInput({ actorId: "other-actor", approvalRequestId: "approval-wrong-actor" }),
		);
		harness.storeProviderApproval(
			wrongAuthority.ref,
			await tokenFor(harness, wrongAuthority, "jti-wrong-authority"),
		);
		expect(
			resultOf(
				await harness.server.handleJsonRpc(
					toolCall("tc_provider_execute_write", {
						actionRef: wrongAuthority.ref,
					}),
					harness.privateContext,
				),
			),
		).toEqual({
			ok: false,
			code: "effect_authority_mismatch",
			reason: "side effect authority mismatch",
			retryable: false,
		});
		expect(harness.vault.verifyCalls).toHaveLength(0);

		const badSignatureRecord = harness.ledger.prepare(
			providerPrepareInput({ approvalRequestId: "approval-invalid-token" }),
		);
		const validAfterBad = await tokenFor(harness, badSignatureRecord, "jti-invalid-then-valid");
		const badToken = validAfterBad.replace(/\.[^.]+$/, ".bad-signature");
		harness.storeProviderApproval(badSignatureRecord.ref, badToken);

		expect(
			resultOf(
				await harness.server.handleJsonRpc(
					toolCall("tc_provider_execute_write", {
						actionRef: badSignatureRecord.ref,
					}),
					harness.privateContext,
				),
			),
		).toEqual({
			ok: false,
			code: "approval_required",
			reason: "Invalid token signature",
			retryable: true,
			record: expect.objectContaining({ ref: badSignatureRecord.ref, status: "prepared" }),
		});
		harness.storeProviderApproval(badSignatureRecord.ref, validAfterBad);
		expect(
			resultOf(
				await harness.server.handleJsonRpc(
					toolCall("tc_provider_execute_write", {
						actionRef: badSignatureRecord.ref,
					}),
					harness.privateContext,
				),
			),
		).toEqual({
			ok: true,
			record: expect.objectContaining({
				ref: badSignatureRecord.ref,
				status: "executed",
				approvalId: "jti-invalid-then-valid",
			}),
		});

		expect(
			resultOf(
				await harness.server.handleJsonRpc(
					toolCall("tc_provider_execute_write", {
						actionRef: prepared.ref,
					}),
					harness.privateContext,
				),
			),
		).toEqual({
			ok: true,
			record: expect.objectContaining({
				ref: prepared.ref,
				status: "executed",
				approvalId: "jti-live-provider",
			}),
		});

		const replayRecord = harness.ledger.prepare(
			providerPrepareInput({ approvalRequestId: "approval-replay" }),
		);
		harness.storeProviderApproval(
			replayRecord.ref,
			await tokenFor(harness, replayRecord, "jti-live-provider"),
		);
		expect(
			resultOf(
				await harness.server.handleJsonRpc(
					toolCall("tc_provider_execute_write", {
						actionRef: replayRecord.ref,
					}),
					harness.privateContext,
				),
			),
		).toEqual({
			ok: false,
			code: "approval_replayed",
			reason: "Approval token already used",
			retryable: true,
			record: expect.objectContaining({ ref: replayRecord.ref, status: "prepared" }),
		});
		harness.storeProviderApproval(
			replayRecord.ref,
			await tokenFor(harness, replayRecord, "jti-live-provider-retry"),
		);
		expect(
			resultOf(
				await harness.server.handleJsonRpc(
					toolCall("tc_provider_execute_write", {
						actionRef: replayRecord.ref,
					}),
					harness.privateContext,
				),
			),
		).toEqual({
			ok: true,
			record: expect.objectContaining({
				ref: replayRecord.ref,
				status: "executed",
				approvalId: "jti-live-provider-retry",
			}),
		});
		expect(harness.calls.providerExecute).toEqual([
			expect.objectContaining({
				providerId: "bank",
				path: "/v1/fetch",
				method: "POST",
				userId: "operator",
				approvalToken: "sidecar:bank:bank:transfer.execute:approval-invalid-token",
				approvalMode: "preapproved-ledger",
			}),
			expect.objectContaining({
				providerId: "bank",
				path: "/v1/fetch",
				method: "POST",
				userId: "operator",
				approvalToken: "sidecar:bank:bank:transfer.execute:approval-live-provider",
				approvalMode: "preapproved-ledger",
			}),
			expect.objectContaining({
				providerId: "bank",
				path: "/v1/fetch",
				method: "POST",
				userId: "operator",
				approvalToken: "sidecar:bank:bank:transfer.execute:approval-replay",
				approvalMode: "preapproved-ledger",
			}),
		]);
	});

	it("executes outbound side effects through server-side approval resolution only", async () => {
		const harness = createHarness(cleanup);
		const outbound = harness.ledger.prepare(outboundPrepareInput());
		const token = await tokenFor(harness, outbound, "jti-live-outbound");
		harness.storeProviderApproval(outbound.ref, token);

		await expect(
			harness.server
				.handleJsonRpc(
					toolCall("tc_outbound_execute", {
						outboundRef: outbound.ref,
						approvalToken: "model-supplied-token",
					}),
					harness.privateContext,
				)
				.then(resultOf),
		).rejects.toThrow("Unrecognized key");

		expect(
			resultOf(
				await harness.server.handleJsonRpc(
					toolCall("tc_outbound_execute", {
						outboundRef: outbound.ref,
					}),
					harness.privateContext,
				),
			),
		).toEqual({
			ok: true,
			record: expect.objectContaining({
				ref: outbound.ref,
				status: "executed",
				approvalId: "jti-live-outbound",
			}),
		});
		expect(harness.ledger.get(outbound.ref)).toEqual(
			expect.objectContaining({ ref: outbound.ref, status: "executed" }),
		);
		expect(harness.calls.outboundDelivery).toEqual([
			expect.objectContaining({
				outboundRef: outbound.edgePreparedRef,
				channel: "whatsapp",
				resolvedDestination: outbound.resolvedDestination,
				finalRenderedBody: outbound.renderedBody,
				sideEffectLedgerRef: outbound.ref,
			}),
		]);
	});

	it("fails WhatsApp outbound execution closed when no delivery dispatcher is configured", async () => {
		const harness = createHarness(cleanup, { outboundDeliveryDispatcher: undefined });
		const outbound = harness.ledger.prepare(outboundPrepareInput());
		const token = await tokenFor(harness, outbound, "jti-live-outbound-no-dispatcher");
		harness.storeProviderApproval(outbound.ref, token);

		expect(
			resultOf(
				await harness.server.handleJsonRpc(
					toolCall("tc_outbound_execute", {
						outboundRef: outbound.ref,
					}),
					harness.privateContext,
				),
			),
		).toEqual({
			ok: false,
			code: "outbound_delivery_dispatcher_missing",
			reason: "outbound delivery dispatcher is not configured for WhatsApp",
			retryable: false,
			record: expect.objectContaining({ ref: outbound.ref, status: "prepared" }),
		});
		expect(harness.calls.outboundDelivery).toEqual([]);
		expect(harness.ledger.get(outbound.ref)).toEqual(
			expect.objectContaining({ ref: outbound.ref, status: "prepared" }),
		);
	});
});

function createHarness(
	cleanup: Array<() => void | Promise<void>>,
	options: { outboundDeliveryDispatcher?: OutboundDeliveryDispatcher } = {},
) {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-live-mcp-"));
	const jtiStore = new TelclaudeMcpSideEffectJtiStore(tempDir);
	cleanup.push(() => {
		jtiStore.close();
		fs.rmSync(tempDir, { recursive: true, force: true });
	});
	const vault = new MockVaultClient();
	const registry = createTelclaudeMcpAuthorityRegistry();
	const privateConnection = connection("ops", "endpoint-private", "netns-private");
	const socialConnection = connection("social", "endpoint-social", "netns-social");
	const privateGrant = registry.register({
		connection: privateConnection,
		authority: authority(),
		nowMs: 100_000,
	});
	const socialGrant = registry.register({
		connection: socialConnection,
		authority: authority({
			actorId: "social-agent",
			profileId: "social",
			domain: "social",
			memorySource: "social",
			writableNamespace: "social:public",
			providerScopes: [],
			outboundChannels: [],
			endpointId: "endpoint-social",
			networkNamespace: "netns-social",
		}),
		nowMs: 100_000,
	});
	const ledger = createTelclaudeMcpSideEffectLedger({
		nowMs: () => 120_000,
		makeRef: makeRef(),
		defaultTtlMs: 60_000,
		verifyApproval: createTelclaudeMcpSideEffectApprovalVerifier({
			vaultClient: vault,
			jtiStore,
			nowSeconds: () => 120,
		}),
	});
	const providerApprovals = new Map<string, string>();
	const calls = {
		providerRead: [] as unknown[],
		providerExecute: [] as unknown[],
		memorySearch: [] as unknown[],
		outboundPrepare: [] as unknown[],
		outboundDelivery: [] as PreparedOutbound[],
	};
	const hasOutboundDispatcher = Object.hasOwn(options, "outboundDeliveryDispatcher");
	const outboundDeliveryDispatcher = hasOutboundDispatcher
		? options.outboundDeliveryDispatcher
		: sentOutboundDeliveryDispatcher(calls.outboundDelivery);
	const relayClients: TelclaudeLiveMcpRelayClients = {
		providerRead: async (request) => {
			calls.providerRead.push(request);
			return { balances: [] };
		},
		providerPrepareWrite: async () => ({ actionRef: "prepared-by-relay" }),
		memorySearch: async (request) => {
			calls.memorySearch.push(request);
			return { entries: [] };
		},
		memoryWrite: async () => ({ accepted: 1 }),
		attachmentGet: async () => ({ bytes: 0 }),
		outboundPrepare: async (request) => {
			calls.outboundPrepare.push(request);
			return { outboundRef: "prepared-outbound" };
		},
		auditNote: async () => ({ stored: true }),
	};

	return {
		vault,
		ledger,
		calls,
		privateContext: {
			authorityHandle: privateGrant.handle,
			connection: privateConnection,
		},
		socialContext: {
			authorityHandle: socialGrant.handle,
			connection: socialConnection,
		},
		server: createTelclaudeLiveMcpRelayHttpServer({
			registry,
			ledger,
			relayClients,
			providerProxy: async (request) => {
				calls.providerExecute.push(request);
				return { status: "ok", data: { executed: true } };
			},
			providerApprovalTokenIssuer: ({ providerId, service, action, approvalNonce }) =>
				`sidecar:${providerId}:${service}:${action}:${approvalNonce}`,
			sideEffectApprovalTokenResolver: ({ actionRef }) => {
				const approvalToken = providerApprovals.get(actionRef);
				if (!approvalToken) {
					return {
						ok: false,
						code: "approval_token_unavailable",
						reason: "server-side approval token is unavailable",
						retryable: true,
					};
				}
				return {
					ok: true,
					approvalToken,
					finalize: () => {
						providerApprovals.delete(actionRef);
					},
				};
			},
			resolveAuthorizedOutboundConversation: (conversationRef) =>
				fixtureConversation({
					token: conversationRef,
					conversationId: conversationRef,
				}),
			...(outboundDeliveryDispatcher ? { outboundDeliveryDispatcher } : {}),
			bindHost: "telclaude",
			networkName: "telclaude-hermes-relay",
			nowMs: () => 120_000,
		}),
		storeProviderApproval(actionRef: string, approvalToken: string) {
			providerApprovals.set(actionRef, approvalToken);
		},
	};
}

function sentOutboundDeliveryDispatcher(calls: PreparedOutbound[]): OutboundDeliveryDispatcher {
	return async (prepared) => {
		calls.push(prepared);
		return {
			schemaVersion: EdgeAdapterSchemaVersions.deliveryReceipt,
			outboundRef: prepared.outboundRef,
			platformMessageId: "wa-live-msg-1",
			deliveryStatus: "sent",
			timestamps: {
				observedAt: "2026-06-04T00:00:00.000Z",
				sentAt: "2026-06-04T00:00:00.000Z",
			},
			retry: {
				attempt: 1,
				maxAttempts: prepared.retryPolicy.maxAttempts,
				idempotencyKey: prepared.idempotencyKey,
			},
		};
	};
}

function toolCall(name: string, args: Record<string, unknown>) {
	return {
		jsonrpc: "2.0",
		id: `call-${name}`,
		method: "tools/call",
		params: { name, arguments: args },
	};
}

function rpc(method: string, params?: unknown, id = `rpc-${method}`) {
	return {
		jsonrpc: "2.0",
		id,
		method,
		...(params !== undefined ? { params } : {}),
	};
}

async function expectEmptySurface(responsePromise: Promise<TelclaudeLiveMcpJsonRpcResponse>) {
	const result = resultOf<Record<string, unknown>>(await responsePromise);
	expect(Object.values(result)).toEqual([[]]);
}

function resultOf<T = unknown>(response: TelclaudeLiveMcpJsonRpcResponse): T {
	if ("error" in response) {
		throw new Error(response.error.message);
	}
	return response.result as T;
}

function connection(
	profileId: string,
	endpointId: string,
	networkNamespace: string,
): TelclaudeMcpAuthorityConnection {
	return {
		sessionKey: `telegram:${profileId}`,
		profileId,
		endpointId,
		networkNamespace,
	};
}

function authority(overrides: Partial<TelclaudeMcpAuthority> = {}): TelclaudeMcpAuthority {
	return {
		actorId: "operator",
		profileId: "ops",
		domain: "private",
		memorySource: "telegram:ops",
		writableNamespace: "private:ops",
		providerScopes: ["bank"],
		outboundChannels: ["whatsapp"],
		endpointId: "endpoint-private",
		networkNamespace: "netns-private",
		...overrides,
	};
}

function providerPrepareInput(
	overrides: Partial<Omit<TelclaudeMcpProviderSideEffectPrepareInput, "kind">> = {},
): TelclaudeMcpProviderSideEffectPrepareInput {
	return {
		kind: "provider",
		actorId: "operator",
		approverActorId: "operator:provider-approver",
		profileId: "ops",
		domain: "private",
		providerId: "bank",
		service: "bank",
		action: "transfer.execute",
		params: { amount: 100, currency: "ILS" },
		providerAccountRef: "bank:primary",
		approvalRequestId: "approval-live-provider",
		approvalRevision: 1,
		wysiwysRender: "Transfer ILS 100 to saved recipient",
		idempotencyKey: "idem-live-provider",
		...overrides,
	};
}

function outboundPrepareInput(
	overrides: Partial<Omit<TelclaudeMcpOutboundSideEffectPrepareInput, "kind">> = {},
): TelclaudeMcpOutboundSideEffectPrepareInput {
	const channel = "whatsapp";
	const requestedBody = "I'll pick up dinner at 19:00.";
	const resolvedDestination = {
		kind: "address" as const,
		addressRef: "+15551234567",
		conversationId: "whatsapp:+15551234567",
	};
	const preparedMediaRefs = [
		{
			quarantineId: "attachment:menu",
			contentHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	];
	return {
		kind: "outbound",
		actorId: "operator",
		approverActorId: "operator:outbound-approver",
		profileId: "ops",
		domain: "private",
		channel,
		destination: "+15551234567",
		resolvedDestination,
		requestedBody,
		renderedBody: requestedBody,
		mediaRefs: ["attachment:menu"],
		preparedMediaRefs,
		conversationRef: "whatsapp:+15551234567",
		authorizationState: "authorized",
		edgePreparedRef: "edge-outbound-live-1",
		edgePreparedHash: edgePreparedPayloadHash({
			channel,
			resolvedDestination,
			body: requestedBody,
			mediaRefs: preparedMediaRefs,
		}),
		approvalRequestId: "approval-live-outbound",
		approvalRevision: 1,
		approvalMetadata: { category: "family-logistics" },
		idempotencyKey: "idem-live-outbound",
		...overrides,
	};
}

function fixtureConversation(overrides: Partial<RelayConversation> = {}): RelayConversation {
	return {
		token: "whatsapp:+15551234567",
		channel: "whatsapp",
		conversationId: "whatsapp:+15551234567",
		threadId: "thread-private",
		profileId: "ops",
		domain: "private",
		mcpDomain: "private",
		edgeDomain: "private",
		routingSession: {
			sessionId: "session-private",
			routeKey: "route-private",
		},
		authorizationState: "authorized",
		humanPairingProvenance: false,
		authorizationScopes: ["message:reply"],
		members: [
			{
				actorId: "operator",
				channel: "whatsapp",
				principalId: "+15551234567",
				principalHash: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
				role: "sender",
				identityAssurance: "strong_link",
				scopes: ["message:reply"],
				revoked: false,
			},
		],
		threadMessageIds: [],
		inboundCursor: null,
		auditIds: [],
		createdAtMs: 100_000,
		expiresAtMs: null,
		revokedAtMs: null,
		revokeReason: null,
		updatedAtMs: 100_000,
		...overrides,
	};
}

function makeRef(): () => string {
	let refCounter = 0;
	return () => `effect-live-${++refCounter}`;
}

async function tokenFor(
	harness: {
		readonly vault: MockVaultClient;
		readonly ledger: TelclaudeMcpSideEffectLedger;
	},
	record: NonNullable<ReturnType<TelclaudeMcpSideEffectLedger["get"]>>,
	jti = "jti-live-provider",
): Promise<string> {
	return generateTelclaudeMcpSideEffectApprovalToken(
		getTelclaudeMcpSideEffectApprovalBinding(record),
		harness.vault,
		{ nowSeconds: () => 100, jti },
	);
}

class MockVaultClient {
	readonly verifyCalls: Array<{ payload: string; signature: string; prefix: string }> = [];

	async signPayload(payload: string, prefix: string): Promise<{ type: string; signature: string }> {
		return { type: "sign-payload", signature: signatureFor(prefix, payload) };
	}

	async verifyPayload(
		payload: string,
		signature: string,
		prefix: string,
	): Promise<{ type: string; valid: boolean }> {
		this.verifyCalls.push({ payload, signature, prefix });
		return { type: "verify-payload", valid: signature === signatureFor(prefix, payload) };
	}
}

function signatureFor(prefix: string, payload: string): string {
	return Buffer.from(`${prefix}\n${payload}`, "utf8").toString("base64url");
}

async function listen(server: http.Server): Promise<{ baseUrl: string; close(): Promise<void> }> {
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const address = server.address();
	if (!address || typeof address === "string") {
		throw new Error("HTTP server did not expose an address");
	}
	return {
		baseUrl: `http://127.0.0.1:${address.port}`,
		close: () => new Promise<void>((resolve) => server.close(() => resolve())),
	};
}
