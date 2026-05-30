import type http from "node:http";
import { describe, expect, it } from "vitest";
import {
	createTelclaudeMcpAuthorityRegistry,
	type TelclaudeMcpAuthorityConnection,
} from "../../src/hermes/mcp/authority-registry.js";
import type { TelclaudeMcpAuthority } from "../../src/hermes/mcp/bridge.js";
import { createTelclaudeLiveMcpConnectionResolver } from "../../src/hermes/mcp/live-connection-resolver.js";
import { createTelclaudeLiveMcpProbeTokenBundle } from "../../src/hermes/mcp/live-probe-tokens.js";

describe("Telclaude live MCP probe tokens", () => {
	it("issues bearer tokens against the shared resolver without exposing token material in metadata", () => {
		const registry = createTelclaudeMcpAuthorityRegistry();
		const resolver = createTelclaudeLiveMcpConnectionResolver({
			registry,
			nowMs: () => 2_000,
			allowedPeerAddresses: ["10.0.0.2"],
		});
		const privateConnection = connection();
		const wrongConnection = connection({
			sessionKey: "telegram:social",
			profileId: "social",
			endpointId: "endpoint-social",
			networkNamespace: "netns-social",
		});
		const bundle = createTelclaudeLiveMcpProbeTokenBundle({
			registry,
			resolver,
			privateConnection,
			wrongConnection,
			privateAuthority: authority(),
			nowMs: 1_000,
			ttlMs: 10_000,
			peerAddress: "10.0.0.2",
			randomBytes: () => Buffer.alloc(32, 7),
		});

		expect(bundle.allowed.token).toMatch(/^tc_mcp_conn_/);
		expect(bundle.wrongConnection.token).toMatch(/^tc_mcp_conn_/);
		expect(bundle.forged.token).toMatch(/^tc_mcp_conn_/);
		expect(
			new Set([bundle.allowed.token, bundle.wrongConnection.token, bundle.forged.token]).size,
		).toBe(3);

		expect(
			resolver.resolveConnection(
				request({ authorization: bundle.allowed.authorizationHeader }, "10.0.0.2"),
			),
		).toEqual({
			authorityHandle: expect.stringMatching(/^tc_mcp_/),
			connection: privateConnection,
		});
		expect(
			resolver.resolveConnection(
				request({ authorization: bundle.allowed.authorizationHeader }, "10.0.0.3"),
			),
		).toBeNull();
		expect(
			resolver.resolveConnection(
				request({ authorization: bundle.wrongConnection.authorizationHeader }, "10.0.0.2"),
			),
		).toBeNull();
		expect(
			resolver.resolveConnection(
				request({ authorization: bundle.forged.authorizationHeader }, "10.0.0.2"),
			),
		).toBeNull();

		const metadata = JSON.stringify(bundle.metadata);
		for (const secret of [bundle.allowed, bundle.wrongConnection, bundle.forged]) {
			expect(metadata).not.toContain(secret.token);
			expect(metadata).not.toContain(secret.authorizationHeader);
		}
		expect(bundle.metadata.tokenMaterial).toBe("omitted");
		expect(bundle.metadata.peerBound).toBe(true);
	});

	it("keeps expiry and revocation behavior delegated to the shared resolver", () => {
		let nowMs = 1_000;
		const registry = createTelclaudeMcpAuthorityRegistry();
		const resolver = createTelclaudeLiveMcpConnectionResolver({
			registry,
			nowMs: () => nowMs,
			allowedPeerAddresses: ["10.0.0.2"],
		});
		const bundle = createTelclaudeLiveMcpProbeTokenBundle({
			registry,
			resolver,
			privateConnection: connection(),
			wrongConnection: connection({
				sessionKey: "telegram:social",
				profileId: "social",
				endpointId: "endpoint-social",
				networkNamespace: "netns-social",
			}),
			privateAuthority: authority(),
			nowMs,
			ttlMs: 1_000,
			peerAddress: "10.0.0.2",
		});

		expect(
			resolver.resolveConnection(
				request({ authorization: bundle.allowed.authorizationHeader }, "10.0.0.2"),
			),
		).not.toBeNull();

		nowMs = 2_000;
		expect(
			resolver.resolveConnection(
				request({ authorization: bundle.allowed.authorizationHeader }, "10.0.0.2"),
			),
		).toBeNull();
		expect(resolver.cleanupExpired(nowMs)).toBe(2);

		const revocationRegistry = createTelclaudeMcpAuthorityRegistry();
		const revocationResolver = createTelclaudeLiveMcpConnectionResolver({
			registry: revocationRegistry,
			nowMs: () => 3_000,
		});
		const revocationBundle = createTelclaudeLiveMcpProbeTokenBundle({
			registry: revocationRegistry,
			resolver: revocationResolver,
			privateConnection: connection(),
			wrongConnection: connection({
				sessionKey: "telegram:social",
				profileId: "social",
				endpointId: "endpoint-social",
				networkNamespace: "netns-social",
			}),
			privateAuthority: authority(),
			nowMs: 3_000,
			ttlMs: 10_000,
			peerAddress: "10.0.0.2",
		});

		expect(
			revocationResolver.resolveConnection(
				request({ authorization: revocationBundle.allowed.authorizationHeader }, "10.0.0.2"),
			),
		).not.toBeNull();
		expect(revocationResolver.revoke(revocationBundle.allowed.token, "probe closed", 3_100)).toBe(
			true,
		);
		expect(
			revocationResolver.resolveConnection(
				request({ authorization: revocationBundle.allowed.authorizationHeader }),
			),
		).toBeNull();
		expect(revocationResolver.revoke(revocationBundle.forged.token, "unknown", 3_100)).toBe(false);
	});
});

function request(
	headers: Record<string, string> = {},
	remoteAddress = "10.0.0.2",
): http.IncomingMessage {
	return {
		headers,
		socket: { remoteAddress },
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
