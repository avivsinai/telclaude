import http from "node:http";
import { describe, expect, it } from "vitest";
import {
	assertPlacementMatchesBindHost,
	assertRelayInternalBindHost,
	assertRelayInternalBoundAddress,
	listenTelclaudeLiveMcpRelayHttpServer,
} from "../../src/hermes/mcp/live-listen.js";
import {
	TELCLAUDE_LIVE_MCP_DEPENDENCY_SURFACE,
	TELCLAUDE_LIVE_MCP_TRANSPORT,
	type TelclaudeLiveMcpRelayHttpServer,
} from "../../src/hermes/mcp/live-server.js";

describe("Telclaude live MCP listen helper", () => {
	it("refuses unspecified, public, ambiguous, or dotted public-looking bind hosts", () => {
		for (const host of [
			"0.0.0.0",
			"::",
			"[::]",
			"8.8.8.8",
			"192.0.2.10",
			"198.51.100.10",
			"203.0.113.10",
			"2001:4860:4860::8888",
			"localhost",
			"example.com",
		]) {
			expect(() => assertRelayInternalBindHost(host)).toThrow();
		}

		for (const host of [
			"127.0.0.1",
			"10.0.0.12",
			"172.18.0.4",
			"192.168.1.10",
			"100.64.0.9",
			"telclaude",
		]) {
			expect(() => assertRelayInternalBindHost(host)).not.toThrow();
		}
	});

	it("rejects placement metadata that does not match the requested bind", () => {
		expect(() =>
			assertPlacementMatchesBindHost(placement({ bindHost: "telclaude" }), "127.0.0.1"),
		).toThrow("does not match placement bindHost");
		expect(() =>
			assertPlacementMatchesBindHost(
				{ ...placement({ bindHost: "127.0.0.1" }), networkExposure: "public" as never },
				"127.0.0.1",
			),
		).toThrow("placement must be relay-internal");
	});

	it("rejects actual public or mismatched IP bind evidence", () => {
		expect(() => assertRelayInternalBoundAddress("127.0.0.1", "8.8.8.8")).toThrow(
			"actual bind address must be loopback or private/internal",
		);
		expect(() => assertRelayInternalBoundAddress("127.0.0.1", "127.0.0.2")).toThrow(
			"does not match requested host",
		);
		expect(() => assertRelayInternalBoundAddress("telclaude", "172.18.0.4")).not.toThrow();
	});

	it("listens only on an explicit relay-internal bind and returns probe endpoint metadata", async () => {
		const liveServer = server("127.0.0.1");
		const nodeServer = http.createServer((_request, response) => {
			response.writeHead(200).end("ok");
		});

		const endpoint = await listenTelclaudeLiveMcpRelayHttpServer(liveServer, nodeServer, {
			port: 0,
			path: "/mcp",
		});
		try {
			expect(endpoint.host).toBe("127.0.0.1");
			expect(endpoint.actualAddress).toBe("127.0.0.1");
			expect(endpoint.networkName).toBe("telclaude-hermes-private");
			expect(endpoint.url).toBe(`http://127.0.0.1:${endpoint.port}/mcp`);
			const response = await fetch(endpoint.url);
			expect(response.status).toBe(200);
		} finally {
			await endpoint.close();
		}
	});
});

function server(bindHost: string): TelclaudeLiveMcpRelayHttpServer {
	return {
		transport: TELCLAUDE_LIVE_MCP_TRANSPORT,
		placement: placement({ bindHost }),
		dependencySurface: TELCLAUDE_LIVE_MCP_DEPENDENCY_SURFACE,
		async handleJsonRpc() {
			return { jsonrpc: "2.0", result: {} };
		},
	};
}

function placement(overrides: Partial<TelclaudeLiveMcpRelayHttpServer["placement"]> = {}) {
	return {
		side: "relay" as const,
		runsInHermesContainer: false as const,
		transport: "http" as const,
		networkExposure: "relay_internal_only" as const,
		bindHost: "telclaude",
		networkName: "telclaude-hermes-private",
		...overrides,
	};
}
