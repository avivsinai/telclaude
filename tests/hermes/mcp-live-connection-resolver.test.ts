import type http from "node:http";
import { describe, expect, it } from "vitest";
import {
	createTelclaudeMcpAuthorityRegistry,
	type TelclaudeMcpAuthorityConnection,
} from "../../src/hermes/mcp/authority-registry.js";
import type { TelclaudeMcpAuthority } from "../../src/hermes/mcp/bridge.js";
import {
	createTelclaudeLiveMcpConnectionResolver,
	TELCLAUDE_LIVE_MCP_CONNECTION_TOKEN_PREFIX,
} from "../../src/hermes/mcp/live-connection-resolver.js";

describe("Telclaude live MCP connection resolver", () => {
	it("resolves authority only from a relay-issued transport token", () => {
		const registry = createTelclaudeMcpAuthorityRegistry();
		const resolver = createTelclaudeLiveMcpConnectionResolver({
			registry,
			nowMs: () => 2_000,
			allowedPeerAddresses: ["10.0.0.2"],
		});
		const privateConnection = connection();
		const privateGrant = registry.register({
			connection: privateConnection,
			authority: authority(),
			nowMs: 1_000,
		});
		const socialConnection = connection({
			sessionKey: "telegram:social",
			profileId: "social",
			endpointId: "endpoint-social",
			networkNamespace: "netns-social",
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
			nowMs: 1_000,
		});
		const transportGrant = resolver.issue({
			authorityHandle: privateGrant.handle,
			connection: privateConnection,
			nowMs: 1_000,
			peerAddress: "10.0.0.2",
		});

		expect(transportGrant.token).toMatch(
			new RegExp(`^${TELCLAUDE_LIVE_MCP_CONNECTION_TOKEN_PREFIX}`),
		);
		expect(
			resolver.resolveConnection(
				request({
					authorization: `Bearer ${transportGrant.token}`,
					"x-telclaude-mcp-authority": socialGrant.handle,
					"x-telclaude-mcp-session-key": socialConnection.sessionKey,
					"x-telclaude-mcp-profile": socialConnection.profileId,
				}),
			),
		).toEqual({
			authorityHandle: privateGrant.handle,
			connection: privateConnection,
		});
	});

	it("fails closed for missing tokens, malformed tokens, wrong peers, expiry, and revocation", () => {
		let nowMs = 1_000;
		const registry = createTelclaudeMcpAuthorityRegistry();
		const resolver = createTelclaudeLiveMcpConnectionResolver({
			registry,
			nowMs: () => nowMs,
			allowedPeerAddresses: ["10.0.0.2"],
		});
		const authorityConnection = connection();
		const authorityGrant = registry.register({
			connection: authorityConnection,
			authority: authority(),
			nowMs,
			ttlMs: 10_000,
		});
		const transportGrant = resolver.issue({
			authorityHandle: authorityGrant.handle,
			connection: authorityConnection,
			nowMs,
			ttlMs: 1_000,
			peerAddress: "10.0.0.2",
		});

		expect(resolver.resolveConnection(request({}))).toBeNull();
		expect(resolver.resolveConnection(request({ authorization: "Bearer wrong" }))).toBeNull();
		expect(
			resolver.resolveConnection(
				request({ authorization: `Bearer ${transportGrant.token}` }, "10.0.0.3"),
			),
		).toBeNull();

		nowMs = 2_000;
		expect(
			resolver.resolveConnection(request({ authorization: `Bearer ${transportGrant.token}` })),
		).toBeNull();
		expect(resolver.cleanupExpired(nowMs)).toBe(1);

		const revokedGrant = resolver.issue({
			authorityHandle: authorityGrant.handle,
			connection: authorityConnection,
			nowMs,
			ttlMs: 10_000,
			peerAddress: "10.0.0.2",
		});
		expect(resolver.revoke(revokedGrant.token, "transport closed", 2_001)).toBe(true);
		expect(
			resolver.resolveConnection(request({ authorization: `Bearer ${revokedGrant.token}` })),
		).toBeNull();
		expect(
			registry.resolve({
				handle: authorityGrant.handle,
				connection: authorityConnection,
				nowMs: 2_002,
			}),
		).toMatchObject({
			ok: false,
			code: "mcp_authority_revoked",
		});
	});

	it("requires either a peer-bound token or an explicit resolver peer allowlist", () => {
		const registry = createTelclaudeMcpAuthorityRegistry();
		const unscopedResolver = createTelclaudeLiveMcpConnectionResolver({
			registry,
			nowMs: () => 2_000,
		});
		const authorityConnection = connection();
		const authorityGrant = registry.register({
			connection: authorityConnection,
			authority: authority(),
			nowMs: 1_000,
		});
		const unbound = unscopedResolver.issue({
			authorityHandle: authorityGrant.handle,
			connection: authorityConnection,
			nowMs: 1_000,
		});
		const peerBound = unscopedResolver.issue({
			authorityHandle: authorityGrant.handle,
			connection: authorityConnection,
			nowMs: 1_000,
			peerAddress: "10.0.0.2",
		});

		expect(
			unscopedResolver.resolveConnection(
				request({ authorization: `Bearer ${unbound.token}` }, "10.0.0.2"),
			),
		).toBeNull();
		expect(
			unscopedResolver.resolveConnection(
				request({ authorization: `Bearer ${peerBound.token}` }, "10.0.0.2"),
			),
		).toEqual({
			authorityHandle: authorityGrant.handle,
			connection: authorityConnection,
		});
		expect(
			unscopedResolver.resolveConnection(
				request({ authorization: `Bearer ${peerBound.token}` }, "10.0.0.3"),
			),
		).toBeNull();

		const allowlistedResolver = createTelclaudeLiveMcpConnectionResolver({
			registry,
			nowMs: () => 2_000,
			allowedPeerAddresses: ["10.0.0.2"],
		});
		const allowlistedUnbound = allowlistedResolver.issue({
			authorityHandle: authorityGrant.handle,
			connection: authorityConnection,
			nowMs: 1_000,
		});

		expect(
			allowlistedResolver.resolveConnection(
				request({ authorization: `Bearer ${allowlistedUnbound.token}` }, "10.0.0.2"),
			),
		).toEqual({
			authorityHandle: authorityGrant.handle,
			connection: authorityConnection,
		});
		expect(
			allowlistedResolver.resolveConnection(
				request({ authorization: `Bearer ${allowlistedUnbound.token}` }, "::ffff:10.0.0.2"),
			),
		).toEqual({
			authorityHandle: authorityGrant.handle,
			connection: authorityConnection,
		});
		expect(
			allowlistedResolver.resolveConnection(
				request({ authorization: `Bearer ${allowlistedUnbound.token}` }, "10.0.0.3"),
			),
		).toBeNull();
		expect(
			allowlistedResolver.resolveConnection(
				request({ authorization: `Bearer ${allowlistedUnbound.token}` }, undefined),
			),
		).toBeNull();
	});

	it("rejects production peer-bound token issuance outside the configured peer ceiling", () => {
		const registry = createTelclaudeMcpAuthorityRegistry();
		const resolver = createTelclaudeLiveMcpConnectionResolver({
			registry,
			nowMs: () => 2_000,
			allowedPeerAddresses: ["10.0.0.2"],
		});
		const authorityConnection = connection();
		const authorityGrant = registry.register({
			connection: authorityConnection,
			authority: authority(),
			nowMs: 1_000,
		});

		expect(() =>
			resolver.issue({
				authorityHandle: authorityGrant.handle,
				connection: authorityConnection,
				nowMs: 1_000,
				peerAddress: "10.0.0.3",
			}),
		).toThrow("peerAddress is not in allowedPeerAddresses");
		expect(() =>
			resolver.issue({
				authorityHandle: authorityGrant.handle,
				connection: authorityConnection,
				nowMs: 1_000,
				peerAddress: "tc-hermes-contained",
			}),
		).toThrow("peerAddress must be an IP address");
	});

	it("revokes all transport tokens and authority for a connection", () => {
		const registry = createTelclaudeMcpAuthorityRegistry();
		const resolver = createTelclaudeLiveMcpConnectionResolver({ registry, nowMs: () => 2_000 });
		const authorityConnection = connection();
		const otherConnection = connection({
			sessionKey: "telegram:other",
			endpointId: "endpoint-other",
			networkNamespace: "netns-other",
		});
		const authorityGrant = registry.register({
			connection: authorityConnection,
			authority: authority(),
			nowMs: 1_000,
		});
		const otherGrant = registry.register({
			connection: otherConnection,
			authority: authority({
				endpointId: "endpoint-other",
				networkNamespace: "netns-other",
			}),
			nowMs: 1_000,
		});
		const first = resolver.issue({
			authorityHandle: authorityGrant.handle,
			connection: authorityConnection,
			peerAddress: "10.0.0.2",
		});
		const second = resolver.issue({
			authorityHandle: authorityGrant.handle,
			connection: authorityConnection,
			peerAddress: "10.0.0.2",
		});
		const other = resolver.issue({
			authorityHandle: otherGrant.handle,
			connection: otherConnection,
			peerAddress: "10.0.0.2",
		});

		expect(resolver.revokeConnection(authorityConnection, "session closed", 2_500)).toBe(2);
		expect(
			resolver.resolveConnection(request({ authorization: `Bearer ${first.token}` })),
		).toBeNull();
		expect(
			resolver.resolveConnection(request({ authorization: `Bearer ${second.token}` })),
		).toBeNull();
		expect(resolver.resolveConnection(request({ authorization: `Bearer ${other.token}` }))).toEqual(
			{
				authorityHandle: otherGrant.handle,
				connection: otherConnection,
			},
		);
	});
});

function request(
	headers: Record<string, string> = {},
	remoteAddress?: string,
): http.IncomingMessage {
	const resolvedRemoteAddress = arguments.length < 2 ? "10.0.0.2" : remoteAddress;
	return {
		headers,
		socket: { remoteAddress: resolvedRemoteAddress },
	} as http.IncomingMessage;
}

function connection(
	overrides: Partial<TelclaudeMcpAuthorityConnection> = {},
): TelclaudeMcpAuthorityConnection {
	return {
		sessionKey: "telegram:ops",
		profileId: "ops",
		endpointId: "endpoint-private",
		networkNamespace: "netns-private",
		...overrides,
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
