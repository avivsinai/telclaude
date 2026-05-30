import { describe, expect, it } from "vitest";
import type { TelclaudeMcpAuthorityConnection } from "../../src/hermes/mcp/authority-registry.js";
import { createTelclaudeMcpAuthorityRegistry } from "../../src/hermes/mcp/authority-registry.js";
import type { TelclaudeMcpAuthority } from "../../src/hermes/mcp/bridge.js";
import {
	createFailClosedTelclaudeLiveMcpRelayClients,
	readTelclaudeLiveMcpRuntimeConfig,
	startTelclaudeLiveMcpRuntime,
	type TelclaudeLiveMcpRuntimeConfig,
} from "../../src/hermes/mcp/live-runtime.js";

describe("Telclaude live MCP runtime", () => {
	it("is a flag-off no-op", async () => {
		const runtime = await startTelclaudeLiveMcpRuntime({
			config: config({ enabled: false }),
		});

		expect(runtime.enabled).toBe(false);
		expect(runtime.endpoint).toBeNull();
		expect(() =>
			runtime.issueProbeTokenBundle({
				privateConnection: connection(),
				wrongConnection: connection({
					sessionKey: "telegram:social",
					profileId: "social",
					endpointId: "endpoint-social",
					networkNamespace: "netns-social",
				}),
				privateAuthority: authority(),
			}),
		).toThrow("disabled");
		await expect(runtime.stop()).resolves.toBeUndefined();
	});

	it("starts on a relay-internal bind with one shared registry/resolver for HTTP and probe tokens", async () => {
		const registry = createTelclaudeMcpAuthorityRegistry();
		const runtime = await startTelclaudeLiveMcpRuntime({
			config: config(),
			registry,
			nowMs: () => 2_000,
			admin: {
				start(context) {
					expect(context.endpoint.url).toBe(runtimeUrl(context.endpoint.port));
					return { stop: () => undefined };
				},
			},
		});
		try {
			expect(runtime.enabled).toBe(true);
			expect(runtime.registry).toBe(registry);
			expect(runtime.endpoint?.actualAddress).toBe("127.0.0.1");

			const tokenBundle = runtime.issueProbeTokenBundle({
				privateConnection: connection(),
				wrongConnection: connection({
					sessionKey: "telegram:social",
					profileId: "social",
					endpointId: "endpoint-social",
					networkNamespace: "netns-social",
				}),
				privateAuthority: authority(),
				nowMs: 1_000,
				ttlMs: 60_000,
				peerAddress: "127.0.0.1",
			});
			const initialized = await postRpc(
				runtime.endpoint?.url,
				tokenBundle.allowed.authorizationHeader,
				{
					jsonrpc: "2.0",
					id: "initialize",
					method: "initialize",
				},
			);

			expect(initialized.httpStatus).toBe(200);
			expect(initialized.body).toMatchObject({
				jsonrpc: "2.0",
				id: "initialize",
				result: {
					capabilities: { tools: { listChanged: false } },
				},
			});

			const wrong = await postRpc(
				runtime.endpoint?.url,
				tokenBundle.wrongConnection.authorizationHeader,
				{
					jsonrpc: "2.0",
					id: "wrong",
					method: "tools/list",
				},
			);
			const forged = await postRpc(runtime.endpoint?.url, tokenBundle.forged.authorizationHeader, {
				jsonrpc: "2.0",
				id: "forged",
				method: "tools/list",
			});
			expect(wrong).toMatchObject({
				httpStatus: 403,
				body: { error: { code: -32001, message: expect.stringContaining("not authorized") } },
			});
			expect(forged).toMatchObject({
				httpStatus: 403,
				body: { error: { code: -32001, message: expect.stringContaining("not authorized") } },
			});
		} finally {
			await runtime.stop();
		}

		expect(() =>
			registry.resolve({ handle: "tc_mcp_missing", connection: connection(), nowMs: 3_000 }),
		).not.toThrow();
		expect(() =>
			runtime.issueProbeTokenBundle({
				privateConnection: connection(),
				wrongConnection: connection({
					sessionKey: "telegram:social",
					profileId: "social",
					endpointId: "endpoint-social",
					networkNamespace: "netns-social",
				}),
				privateAuthority: authority(),
			}),
		).toThrow("stopped");
	});

	it("fails closed when relay-client adapters have not been wired yet", async () => {
		const runtime = await startTelclaudeLiveMcpRuntime({
			config: config(),
			nowMs: () => 2_000,
			relayClients: createFailClosedTelclaudeLiveMcpRelayClients("B2 adapter not wired"),
		});
		try {
			const tokenBundle = runtime.issueProbeTokenBundle({
				privateConnection: connection(),
				wrongConnection: connection({
					sessionKey: "telegram:social",
					profileId: "social",
					endpointId: "endpoint-social",
					networkNamespace: "netns-social",
				}),
				privateAuthority: authority(),
				nowMs: 1_000,
				ttlMs: 60_000,
				peerAddress: "127.0.0.1",
			});
			const result = await postRpc(runtime.endpoint?.url, tokenBundle.allowed.authorizationHeader, {
				jsonrpc: "2.0",
				id: "read",
				method: "tools/call",
				params: {
					name: "tc_provider_read",
					arguments: {
						service: "bank",
						action: "balances.list",
						params: {},
					},
				},
			});

			expect(result).toMatchObject({
				httpStatus: 200,
				body: {
					error: {
						code: -32001,
						message: expect.stringContaining("B2 adapter not wired"),
					},
				},
			});
		} finally {
			await runtime.stop();
		}
	});

	it("keeps the live-listen relay-internal bind guard load-bearing", async () => {
		await expect(
			startTelclaudeLiveMcpRuntime({
				config: config({ host: "0.0.0.0" }),
			}),
		).rejects.toThrow("must not bind an unspecified interface");

		await expect(
			startTelclaudeLiveMcpRuntime({
				config: config({ host: "localhost" }),
			}),
		).rejects.toThrow("must be explicit");
	});

	it("parses environment defaults and overrides without enabling by default", () => {
		const disabledConfig = {
			enabled: false,
			host: "127.0.0.1",
			port: 8793,
			path: "/mcp",
			networkName: "telclaude-hermes-relay",
			allowedPeerAddresses: undefined,
		};

		expect(readTelclaudeLiveMcpRuntimeConfig({})).toEqual(disabledConfig);
		expect(
			readTelclaudeLiveMcpRuntimeConfig({
				TELCLAUDE_HERMES_LIVE_MCP_ENABLED: "0",
				TELCLAUDE_HERMES_LIVE_MCP_PORT: "not-a-port",
			}),
		).toEqual(disabledConfig);
		expect(
			readTelclaudeLiveMcpRuntimeConfig({
				TELCLAUDE_HERMES_LIVE_MCP_ENABLED: "1",
				TELCLAUDE_HERMES_LIVE_MCP_HOST: "10.0.0.4",
				TELCLAUDE_HERMES_LIVE_MCP_PORT: "8794",
				TELCLAUDE_HERMES_LIVE_MCP_PATH: "mcp",
				TELCLAUDE_HERMES_LIVE_MCP_NETWORK: "tc-net",
				TELCLAUDE_HERMES_LIVE_MCP_ALLOWED_PEERS: "10.0.0.5, 10.0.0.6",
			}),
		).toEqual({
			enabled: true,
			host: "10.0.0.4",
			port: 8794,
			path: "/mcp",
			networkName: "tc-net",
			allowedPeerAddresses: ["10.0.0.5", "10.0.0.6"],
		});
		expect(() =>
			readTelclaudeLiveMcpRuntimeConfig({
				TELCLAUDE_HERMES_LIVE_MCP_ENABLED: "1",
				TELCLAUDE_HERMES_LIVE_MCP_PORT: "8793abc",
			}),
		).toThrow("Invalid TELCLAUDE_HERMES_LIVE_MCP_PORT");
		expect(() =>
			readTelclaudeLiveMcpRuntimeConfig({
				TELCLAUDE_HERMES_LIVE_MCP_ENABLED: "1",
				TELCLAUDE_HERMES_LIVE_MCP_HOST: "10.0.0.4",
			}),
		).toThrow("TELCLAUDE_HERMES_LIVE_MCP_ALLOWED_PEERS is required");
		expect(() =>
			readTelclaudeLiveMcpRuntimeConfig({
				TELCLAUDE_HERMES_LIVE_MCP_ENABLED: "1",
				TELCLAUDE_HERMES_LIVE_MCP_HOST: "10.0.0.4",
				TELCLAUDE_HERMES_LIVE_MCP_ALLOWED_PEERS: "tc-hermes-contained",
			}),
		).toThrow("TELCLAUDE_HERMES_LIVE_MCP_ALLOWED_PEERS must contain IP addresses");
		expect(
			readTelclaudeLiveMcpRuntimeConfig({
				TELCLAUDE_HERMES_LIVE_MCP_ENABLED: "1",
			}).allowedPeerAddresses,
		).toBeUndefined();
	});
});

function config(
	overrides: Partial<TelclaudeLiveMcpRuntimeConfig> = {},
): TelclaudeLiveMcpRuntimeConfig {
	return {
		enabled: true,
		host: "127.0.0.1",
		port: 0,
		path: "/mcp",
		networkName: "telclaude-hermes-relay",
		...overrides,
	};
}

function runtimeUrl(port: number): string {
	return `http://127.0.0.1:${port}/mcp`;
}

async function postRpc(
	url: string | undefined,
	authorizationHeader: string,
	body: Record<string, unknown>,
): Promise<{ httpStatus: number; body: unknown }> {
	if (!url) throw new Error("runtime endpoint URL missing");
	const response = await fetch(url, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			Authorization: authorizationHeader,
		},
		body: JSON.stringify(body),
	});
	return {
		httpStatus: response.status,
		body: (await response.json()) as unknown,
	};
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
