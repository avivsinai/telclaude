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
				source: "social",
				actorId: "attacker",
				profileId: "other",
				domain: "public",
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
		).rejects.toThrow("memory provenance cannot set authoritative field: source");
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

	it("enforces provider scopes and ignores model-supplied identity", async () => {
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
				actorId: "other",
				profileId: "other",
				domain: "public",
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
				service: "clalit",
				action: "appointments.list",
				params: { subjectUserId: "spoofed-family-member" },
			},
		]);

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
				approvalToken: "signed-token",
			}),
		).resolves.toEqual({ status: "queued" });
		await expect(
			bridge.tc_outbound_execute({
				outboundRef: "out_123",
				approvalToken: "signed-token",
			}),
		).resolves.toEqual({ status: "sent" });

		expect(calls).toEqual([
			expect.objectContaining({ actionRef: "act_123", approvalToken: "signed-token" }),
			expect.objectContaining({ outboundRef: "out_123", approvalToken: "signed-token" }),
		]);
		await expect(
			bridge.tc_provider_execute_write({
				actionRef: "act_123",
				approvalToken: "signed-token",
				params: { amount: 100 },
			}),
		).rejects.toThrow();
		await expect(
			bridge.tc_outbound_execute({
				outboundRef: "out_123",
				approvalToken: "signed-token",
				content: "mutated",
			}),
		).rejects.toThrow();
	});

	it("applies outbound channel scope and stamps attachment/audit calls", async () => {
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
				channel: "whatsapp",
				recipient: "+15551234567",
				content: "hello",
				mediaRefs: ["att_123"],
			}),
		).resolves.toEqual({ outboundRef: "out_123" });
		await expect(
			bridge.tc_audit_note({ kind: "mcp.test", payload: { ok: true } }),
		).resolves.toEqual({ stored: true });

		expect(calls).toEqual([
			expect.objectContaining({ ref: "att_123", actorId: "operator" }),
			expect.objectContaining({ channel: "whatsapp", recipient: "+15551234567" }),
			expect.objectContaining({ kind: "mcp.test", payload: { ok: true } }),
		]);
		await expect(
			bridge.tc_outbound_prepare({
				channel: "email",
				recipient: "a@example.com",
				content: "hello",
			}),
		).rejects.toThrow("outbound channel denied: email");
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
