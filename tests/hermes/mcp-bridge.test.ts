import { describe, expect, it } from "vitest";
import {
	createTelclaudeMcpBridge,
	TELCLAUDE_MCP_SERVER_POLICY,
	type TelclaudeMcpAuthority,
	type TelclaudeMcpBridgeDependencies,
} from "../../src/hermes/mcp/bridge.js";

describe("Telclaude MCP bridge foundation", () => {
	it("declares a deny-by-default MCP server policy with explicit tools", () => {
		expect(TELCLAUDE_MCP_SERVER_POLICY).toEqual({
			tools: [
				"tc_provider_read",
				"tc_provider_prepare_write",
				"tc_provider_execute_write",
				"tc_memory_search",
				"tc_memory_write",
				"tc_attachment_get",
				"tc_outbound_prepare",
				"tc_outbound_execute",
				"tc_audit_note",
			],
			resources: [],
			prompts: [],
			roots: [],
			sampling: false,
			env: {},
			cwd: null,
			subprocess: false,
		});
	});

	it("derives memory search authority from the wrapper session", async () => {
		const calls: unknown[] = [];
		const bridge = createTelclaudeMcpBridge(baseAuthority(), {
			...baseDependencies(),
			memorySearch: async (request) => {
				calls.push(request);
				return { entries: [] };
			},
		});

		await expect(
			bridge.tc_memory_search({
				query: "family",
				limit: 20,
			}),
		).resolves.toEqual({ entries: [] });

		expect(calls).toEqual([
			{
				actorId: "operator",
				profileId: "ops",
				domain: "private",
				memorySource: "telegram:ops",
				writableNamespace: "private:ops",
				endpointId: "endpoint-private",
				networkNamespace: "netns-private",
				query: "family",
				filters: undefined,
				limit: 20,
			},
		]);
	});

	it("rejects client-supplied memory authority before search or write dependencies run", async () => {
		const calls: unknown[] = [];
		const bridge = createTelclaudeMcpBridge(baseAuthority(), {
			...baseDependencies(),
			memorySearch: async (request) => {
				calls.push(request);
				return { entries: [] };
			},
			memoryWrite: async (request) => {
				calls.push(request);
				return { accepted: 1 };
			},
		});

		await expect(
			bridge.tc_memory_search({
				query: "family",
				filters: { source: "social", namespace: "social", peerAddress: "172.30.0.9" },
			}),
		).rejects.toThrow("MCP client cannot supply memory authority fields");
		await expect(
			bridge.tc_memory_write({
				id: "spoof",
				category: "profile",
				content: "try to choose source",
				source: "social",
				memorySource: "social",
				domain: "social",
			}),
		).rejects.toThrow("MCP clients may not supply MCP authority field");

		expect(calls).toEqual([]);
	});

	it("overwrites memory write authority and rejects authoritative provenance", async () => {
		const calls: unknown[] = [];
		const bridge = createTelclaudeMcpBridge(baseAuthority(), {
			...baseDependencies(),
			memoryWrite: async (request) => {
				calls.push(request);
				return { accepted: 1 };
			},
		});

		await expect(
			bridge.tc_memory_write({
				id: "family-pref",
				category: "profile",
				content: "Family prefers WhatsApp for logistics",
				metadata: { note: "operator approved" },
				provenance: { note: "metadata-only" },
			}),
		).resolves.toEqual({ accepted: 1 });

		expect(calls).toEqual([
			{
				actorId: "operator",
				profileId: "ops",
				domain: "private",
				memorySource: "telegram:ops",
				writableNamespace: "private:ops",
				endpointId: "endpoint-private",
				networkNamespace: "netns-private",
				id: "family-pref",
				category: "profile",
				content: "Family prefers WhatsApp for logistics",
				metadata: { note: "operator approved" },
				trust: "trusted",
			},
		]);

		await expect(
			bridge.tc_memory_write({
				id: "spoof",
				category: "profile",
				content: "try to choose source",
				provenance: { source: "social" },
			}),
		).rejects.toThrow("MCP client cannot supply memory authority fields");
	});

	it("reuses memory validation for secret-like writes", async () => {
		const bridge = createTelclaudeMcpBridge(baseAuthority(), baseDependencies());

		await expect(
			bridge.tc_memory_write({
				id: "bad",
				category: "profile",
				content: "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi",
			}),
		).rejects.toThrow("potential secret detected");
	});

	it("defaults specialist memory writes to untrusted", async () => {
		const calls: unknown[] = [];
		const bridge = createTelclaudeMcpBridge(baseAuthority({ domain: "specialist" }), {
			...baseDependencies(),
			memoryWrite: async (request) => {
				calls.push(request);
				return { accepted: 1 };
			},
		});

		await expect(
			bridge.tc_memory_write({
				id: "research-note",
				category: "meta",
				content: "External research result to review before promotion",
			}),
		).resolves.toEqual({ accepted: 1 });

		expect(calls).toEqual([
			expect.objectContaining({
				domain: "specialist",
				trust: "untrusted",
			}),
		]);
	});

	it("enforces provider scopes and rejects model-supplied identity", async () => {
		const calls: unknown[] = [];
		const bridge = createTelclaudeMcpBridge(baseAuthority({ providerScopes: ["clalit"] }), {
			...baseDependencies(),
			providerRead: async (request) => {
				calls.push(request);
				return { appointments: [] };
			},
		});

		await expect(
			bridge.tc_provider_read({
				service: "clalit",
				action: "appointments.list",
				params: { subjectUserId: "spoofed-family-member" },
			}),
		).resolves.toEqual({ appointments: [] });

		expect(calls).toEqual([
			{
				actorId: "operator",
				profileId: "ops",
				domain: "private",
				memorySource: "telegram:ops",
				writableNamespace: "private:ops",
				endpointId: "endpoint-private",
				networkNamespace: "netns-private",
				providerId: "clalit",
				service: "clalit",
				action: "appointments.list",
				params: { subjectUserId: "spoofed-family-member" },
			},
		]);

		await expect(
			bridge.tc_provider_read({
				service: "clalit",
				action: "appointments.list",
				params: { subjectUserId: "spoofed-family-member" },
				actorId: "other",
				profileId: "other",
				domain: "public",
			}),
		).rejects.toThrow("MCP clients may not supply MCP authority field");

		await expect(
			bridge.tc_provider_read({ service: "bank", action: "balances.list", params: {} }),
		).rejects.toThrow("provider scope denied: bank");
	});

	it("keeps provider and outbound execute immutable", async () => {
		const calls: unknown[] = [];
		const bridge = createTelclaudeMcpBridge(baseAuthority({ outboundChannels: ["whatsapp"] }), {
			...baseDependencies(),
			providerExecuteWrite: async (request) => {
				calls.push(request);
				return { status: "queued" };
			},
			outboundExecute: async (request) => {
				calls.push(request);
				return { status: "sent" };
			},
		});

		await expect(
			bridge.tc_provider_execute_write({
				actionRef: "act_123",
			}),
		).resolves.toEqual({ status: "queued" });
		await expect(
			bridge.tc_outbound_execute({
				outboundRef: "out_123",
			}),
		).resolves.toEqual({ status: "sent" });

		expect(calls).toEqual([
			expect.objectContaining({ actionRef: "act_123" }),
			expect.objectContaining({ outboundRef: "out_123" }),
		]);
		expect(calls[0]).not.toHaveProperty("approvalToken");
		expect(calls[1]).not.toHaveProperty("approvalToken");
		await expect(
			bridge.tc_provider_execute_write({
				actionRef: "act_123",
				approvalToken: "signed-token",
			}),
		).rejects.toThrow();
		await expect(
			bridge.tc_provider_execute_write({
				actionRef: "act_123",
				params: { amount: 100 },
			}),
		).rejects.toThrow();
		await expect(
			bridge.tc_outbound_execute({
				outboundRef: "out_123",
				approvalToken: "signed-token",
			}),
		).rejects.toThrow();
	});

	it("stamps relay-owned turn refs and rejects model-supplied turn fields", async () => {
		const calls: unknown[] = [];
		const turnConversationRef = `turn_${"a".repeat(32)}`;
		const bridge = createTelclaudeMcpBridge(
			baseAuthority({
				outboundChannels: ["whatsapp"],
				turnConversationRef,
			}),
			{
				...baseDependencies(),
				outboundPrepare: async (request) => {
					calls.push(request);
					return { outboundRef: "out_turn" };
				},
				outboundExecute: async (request) => {
					calls.push(request);
					return { status: "sent" };
				},
			},
		);

		await expect(
			bridge.tc_outbound_prepare({
				conversationToken: `conv_${"a".repeat(32)}`,
				body: "hello from original turn",
			}),
		).resolves.toEqual({ outboundRef: "out_turn" });
		await expect(bridge.tc_outbound_execute({ outboundRef: "out_turn" })).resolves.toEqual({
			status: "sent",
		});

		expect(calls).toEqual([
			expect.objectContaining({ turnConversationRef }),
			expect.objectContaining({ turnConversationRef }),
		]);

		await expect(
			bridge.tc_outbound_prepare({
				conversationToken: `conv_${"a".repeat(32)}`,
				body: "try to choose turn",
				turnConversationRef: `turn_${"b".repeat(32)}`,
			}),
		).rejects.toThrow("MCP clients may not supply relay turn authority");
		await expect(
			bridge.tc_outbound_execute({
				outboundRef: "out_turn",
				turnId: "model-turn",
			}),
		).rejects.toThrow("MCP clients may not supply relay turn authority");
	});

	it("requires relay conversation tokens for outbound prepare and stamps attachment/audit calls", async () => {
		const calls: unknown[] = [];
		const bridge = createTelclaudeMcpBridge(baseAuthority({ outboundChannels: ["whatsapp"] }), {
			...baseDependencies(),
			attachmentGet: async (request) => {
				calls.push(request);
				return { bytes: 0 };
			},
			outboundPrepare: async (request) => {
				calls.push(request);
				return { outboundRef: "out_123" };
			},
			auditNote: async (request) => {
				calls.push(request);
				return { stored: true };
			},
		});

		await expect(bridge.tc_attachment_get({ ref: "att_123" })).resolves.toEqual({ bytes: 0 });
		await expect(
			bridge.tc_outbound_prepare({
				conversationToken: `conv_${"a".repeat(32)}`,
				replyIntent: {
					kind: "actor",
					actorId: "actor:recipient",
				},
				body: "hello",
				mediaRefs: ["att_123"],
			}),
		).resolves.toEqual({ outboundRef: "out_123" });
		await expect(
			bridge.tc_audit_note({ kind: "mcp.test", payload: { ok: true } }),
		).resolves.toEqual({ stored: true });

		expect(calls).toEqual([
			expect.objectContaining({ ref: "att_123", actorId: "operator" }),
			expect.objectContaining({
				conversationToken: `conv_${"a".repeat(32)}`,
				replyIntent: {
					kind: "actor",
					actorId: "actor:recipient",
				},
				body: "hello",
				outboundChannels: ["whatsapp"],
			}),
			expect.objectContaining({ kind: "mcp.test", payload: { ok: true } }),
		]);
		expect(calls[1]).not.toHaveProperty("channel");
		expect(calls[1]).not.toHaveProperty("recipient");
		expect(calls[1]).not.toHaveProperty("conversationRef");
		expect(calls[1]).not.toHaveProperty("approvalToken");
	});

	it("rejects old or caller-shaped outbound prepare authority", async () => {
		const bridge = createTelclaudeMcpBridge(baseAuthority({ outboundChannels: ["whatsapp"] }), {
			...baseDependencies(),
			outboundPrepare: async () => {
				throw new Error("outboundPrepare should not be called");
			},
		});

		await expect(
			bridge.tc_outbound_prepare({
				channel: "whatsapp",
				recipient: "+15551234567",
				content: "hello",
			}),
		).rejects.toThrow();
		await expect(
			bridge.tc_outbound_prepare({
				conversationToken: `conv_${"a".repeat(32)}`,
				body: "hello",
				recipient: "+15551234567",
			}),
		).rejects.toThrow();
		await expect(
			bridge.tc_outbound_prepare({
				conversationToken: `conv_${"a".repeat(32)}`,
				body: "hello",
				conversationRef: { channel: "whatsapp" },
			}),
		).rejects.toThrow();
		await expect(
			bridge.tc_outbound_prepare({
				conversationToken: "not-a-token",
				body: "hello",
			}),
		).rejects.toThrow("invalid conversation token");
		await expect(
			bridge.tc_outbound_prepare({
				conversationToken: `conv_${"a".repeat(32)}`,
				content: "old content key",
			}),
		).rejects.toThrow();
	});
});

function baseAuthority(overrides: Partial<TelclaudeMcpAuthority> = {}): TelclaudeMcpAuthority {
	return {
		actorId: "operator",
		profileId: "ops",
		domain: "private",
		memorySource: "telegram:ops",
		writableNamespace: "private:ops",
		providerScopes: [],
		outboundChannels: [],
		endpointId: "endpoint-private",
		networkNamespace: "netns-private",
		...overrides,
	};
}

function baseDependencies(): TelclaudeMcpBridgeDependencies {
	return {
		providerRead: async () => ({ ok: true }),
		providerPrepareWrite: async () => ({ actionRef: "act_123" }),
		providerExecuteWrite: async () => ({ ok: true }),
		memorySearch: async () => ({ entries: [] }),
		memoryWrite: async () => ({ accepted: 1 }),
		attachmentGet: async () => ({ bytes: 0 }),
		outboundPrepare: async () => ({ outboundRef: "out_123" }),
		outboundExecute: async () => ({ ok: true }),
		auditNote: async () => ({ stored: true }),
	};
}
