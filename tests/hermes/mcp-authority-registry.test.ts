import { describe, expect, it } from "vitest";
import {
	createTelclaudeMcpAuthorityRegistry,
	createTelclaudeMcpBridgeForRegisteredConnection,
	type TelclaudeMcpAuthorityConnection,
} from "../../src/hermes/mcp/authority-registry.js";
import type {
	TelclaudeMcpAuthority,
	TelclaudeMcpBridgeDependencies,
} from "../../src/hermes/mcp/bridge.js";
import { telegramMemorySource } from "../../src/memory/source.js";

describe("Telclaude MCP authority registry", () => {
	it("registers opaque authority handles and resolves only with the minted connection binding", async () => {
		const registry = createTelclaudeMcpAuthorityRegistry();
		const connection = baseConnection();
		const authority = baseAuthority({ turnConversationRef: `turn_${"a".repeat(32)}` });

		const grant = registry.register({ connection, authority, nowMs: 1_000, ttlMs: 10_000 });

		expect(grant.handle).toMatch(/^tc_mcp_[A-Za-z0-9_-]+$/);
		expect(grant.handle).not.toContain(authority.actorId);
		expect(grant.handle).not.toContain(authority.profileId);
		expect(grant.handle).not.toContain(authority.domain);
		expect(grant.handle).not.toContain(authority.turnConversationRef ?? "");

		const resolved = registry.resolve({ handle: grant.handle, connection, nowMs: 2_000 });
		expect(resolved).toMatchObject({
			ok: true,
			issuedAtMs: 1_000,
			expiresAtMs: 11_000,
			authority,
		});
		if (!resolved.ok) throw new Error("expected authority resolution");
		(resolved.authority.providerScopes as string[]).push("mutated");
		expect(registry.resolve({ handle: grant.handle, connection, nowMs: 2_001 })).toMatchObject({
			ok: true,
			authority,
		});
	});

	it("rejects non relay-minted turn authority refs", () => {
		const registry = createTelclaudeMcpAuthorityRegistry();

		expect(() =>
			registry.register({
				connection: baseConnection(),
				authority: baseAuthority({ turnConversationRef: "model-supplied-turn" }),
			}),
		).toThrow("MCP authority turnConversationRef must be a relay turn ref");
	});

	it.each([
		["endpoint", { endpointId: "endpoint-other" }],
		["network namespace", { networkNamespace: "netns-other" }],
		["session", { sessionKey: "tg:456" }],
		["profile", { profileId: "social" }],
	])("denies %s binding drift", (_label, override) => {
		const registry = createTelclaudeMcpAuthorityRegistry();
		const connection = baseConnection();
		const grant = registry.register({
			connection,
			authority: baseAuthority(),
			nowMs: 1_000,
			ttlMs: 10_000,
		});

		expect(
			registry.resolve({
				handle: grant.handle,
				connection: { ...connection, ...override },
				nowMs: 2_000,
			}),
		).toEqual({
			ok: false,
			code: "mcp_authority_connection_mismatch",
			reason: "MCP authority connection mismatch",
			retryable: false,
		});
	});

	it("denies unknown, expired, and revoked handles without a fallback authority", () => {
		const registry = createTelclaudeMcpAuthorityRegistry();
		const connection = baseConnection();
		const grant = registry.register({
			connection,
			authority: baseAuthority(),
			nowMs: 1_000,
			ttlMs: 1_000,
		});

		expect(registry.resolve({ handle: "tc_mcp_unknown", connection, nowMs: 1_000 })).toEqual({
			ok: false,
			code: "mcp_authority_unknown",
			reason: "MCP authority is not registered",
			retryable: false,
		});
		expect(registry.resolve({ handle: grant.handle, connection, nowMs: 2_000 })).toEqual({
			ok: false,
			code: "mcp_authority_expired",
			reason: "MCP authority expired",
			retryable: false,
		});

		const revoked = registry.register({
			connection,
			authority: baseAuthority(),
			nowMs: 3_000,
			ttlMs: 1_000,
		});
		expect(registry.revoke(revoked.handle, "done", 3_500)).toBe(true);
		expect(registry.resolve({ handle: revoked.handle, connection, nowMs: 3_501 })).toEqual({
			ok: false,
			code: "mcp_authority_revoked",
			reason: "MCP authority was revoked",
			retryable: false,
		});

		expect(
			createTelclaudeMcpBridgeForRegisteredConnection({
				registry,
				handle: "tc_mcp_unknown",
				connection,
				dependencies: baseDependencies(),
				nowMs: 3_501,
			}),
		).toEqual({
			ok: false,
			code: "mcp_authority_unknown",
			reason: "MCP authority is not registered",
			retryable: false,
		});
	});

	it("prevents connection A from resolving connection B's authority or scopes", async () => {
		const registry = createTelclaudeMcpAuthorityRegistry();
		const connectionA = baseConnection();
		const connectionB = baseConnection({
			sessionKey: "tg:999",
			endpointId: "endpoint-social",
			networkNamespace: "netns-social",
			profileId: "social",
		});
		const grantA = registry.register({
			connection: connectionA,
			authority: baseAuthority({ providerScopes: ["google"] }),
			nowMs: 1_000,
			ttlMs: 10_000,
		});
		const grantB = registry.register({
			connection: connectionB,
			authority: baseAuthority({
				actorId: "social-agent",
				profileId: "social",
				domain: "social",
				memorySource: "social",
				writableNamespace: "social:social",
				providerScopes: ["bank"],
				endpointId: "endpoint-social",
				networkNamespace: "netns-social",
			}),
			nowMs: 1_000,
			ttlMs: 10_000,
		});

		expect(
			createTelclaudeMcpBridgeForRegisteredConnection({
				registry,
				handle: grantB.handle,
				connection: connectionA,
				dependencies: baseDependencies(),
				nowMs: 2_000,
			}),
		).toMatchObject({ ok: false, code: "mcp_authority_connection_mismatch" });

		const calls: unknown[] = [];
		const bridgeResult = createTelclaudeMcpBridgeForRegisteredConnection({
			registry,
			handle: grantA.handle,
			connection: connectionA,
			dependencies: {
				...baseDependencies(),
				providerRead: async (request) => {
					calls.push(request);
					return { ok: true };
				},
			},
			nowMs: 2_000,
		});
		if (!bridgeResult.ok) throw new Error("expected bridge");

		await expect(
			bridgeResult.bridge.tc_provider_read({
				service: "bank",
				action: "balances.list",
				actorId: "social-agent",
				profileId: "social",
				domain: "social",
			}),
		).rejects.toThrow("MCP clients may not supply MCP authority field: actorId");
		await expect(
			bridgeResult.bridge.tc_provider_read({
				service: "bank",
				action: "balances.list",
			}),
		).rejects.toThrow("provider scope denied: bank");
		await expect(
			bridgeResult.bridge.tc_provider_read({
				service: "calendar",
				action: "events.list",
			}),
		).resolves.toEqual({ ok: true });
		expect(calls).toEqual([
			expect.objectContaining({
				actorId: "operator",
				profileId: "ops",
				domain: "private",
				memorySource: "telegram:ops",
				service: "calendar",
			}),
		]);
	});

	it("enforces private/social memory boundaries at registration", () => {
		const registry = createTelclaudeMcpAuthorityRegistry();

		expect(() =>
			registry.register({
				connection: baseConnection(),
				authority: baseAuthority({ memorySource: "social" }),
			}),
		).toThrow("private MCP authority must use telegram profile memory source");
		expect(() =>
			registry.register({
				connection: baseConnection(),
				authority: baseAuthority({ memorySource: telegramMemorySource("default") }),
			}),
		).toThrow("private MCP authority memory source must be telegram:ops");
		expect(() =>
			registry.register({
				connection: baseConnection({ profileId: "social" }),
				authority: baseAuthority({
					profileId: "social",
					domain: "social",
					memorySource: telegramMemorySource("social"),
				}),
			}),
		).toThrow("social MCP authority must use social memory source");
	});

	it("revokes all authorities for a completed connection", () => {
		const registry = createTelclaudeMcpAuthorityRegistry();
		const connection = baseConnection();
		const first = registry.register({ connection, authority: baseAuthority(), nowMs: 1_000 });
		const second = registry.register({ connection, authority: baseAuthority(), nowMs: 1_001 });

		expect(registry.revokeConnection(connection, "transport closed", 2_000)).toBe(2);
		expect(registry.resolve({ handle: first.handle, connection, nowMs: 2_001 })).toMatchObject({
			ok: false,
			code: "mcp_authority_revoked",
		});
		expect(registry.resolve({ handle: second.handle, connection, nowMs: 2_001 })).toMatchObject({
			ok: false,
			code: "mcp_authority_revoked",
		});
	});
});

function baseConnection(
	overrides: Partial<TelclaudeMcpAuthorityConnection> = {},
): TelclaudeMcpAuthorityConnection {
	return {
		sessionKey: "tg:123",
		profileId: "ops",
		endpointId: "endpoint-private",
		networkNamespace: "netns-private",
		...overrides,
	};
}

function baseAuthority(overrides: Partial<TelclaudeMcpAuthority> = {}): TelclaudeMcpAuthority {
	return {
		actorId: "operator",
		profileId: "ops",
		domain: "private",
		memorySource: telegramMemorySource("ops"),
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
