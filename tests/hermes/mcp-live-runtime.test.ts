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
		).rejects.toThrow("TELCLAUDE_HERMES_LIVE_MCP_HOST must not bind");

		await expect(
			startTelclaudeLiveMcpRuntime({
				config: config({ host: "localhost" }),
			}),
		).rejects.toThrow("TELCLAUDE_HERMES_LIVE_MCP_HOST must be explicit");

		await expect(
			startTelclaudeLiveMcpRuntime({
				config: config({ host: "10.0.0.4", allowedPeerAddresses: undefined }),
			}),
		).rejects.toThrow("TELCLAUDE_HERMES_LIVE_MCP_ALLOWED_PEERS is required");
	});

	it("parses environment defaults and overrides without enabling by default", () => {
		const disabledConfig = {
			enabled: false,
			host: "127.0.0.1",
			port: 8793,
			path: "/mcp",
			networkName: "telclaude-hermes-relay",
			allowedPeerAddresses: undefined,
			runtimeTransportToken: undefined,
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
				TELCLAUDE_HERMES_MCP_RELAY_TOKEN: "tc-live-mcp-runtime-token",
			}),
		).toEqual({
			enabled: true,
			host: "10.0.0.4",
			port: 8794,
			path: "/mcp",
			networkName: "tc-net",
			allowedPeerAddresses: ["10.0.0.5", "10.0.0.6"],
			runtimeTransportToken: "tc-live-mcp-runtime-token",
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
				TELCLAUDE_HERMES_MCP_RELAY_TOKEN: "tc-live-mcp-runtime-token",
			}),
		).toThrow("TELCLAUDE_HERMES_LIVE_MCP_ALLOWED_PEERS is required");
		for (const host of ["0.0.0.0", "::", "[::]"]) {
			expect(() =>
				readTelclaudeLiveMcpRuntimeConfig({
					TELCLAUDE_HERMES_LIVE_MCP_ENABLED: "1",
					TELCLAUDE_HERMES_LIVE_MCP_HOST: host,
					TELCLAUDE_HERMES_LIVE_MCP_ALLOWED_PEERS: "10.0.0.5",
					TELCLAUDE_HERMES_MCP_RELAY_TOKEN: "tc-live-mcp-runtime-token",
				}),
			).toThrow("TELCLAUDE_HERMES_LIVE_MCP_HOST must not bind");
		}
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
				TELCLAUDE_HERMES_MCP_RELAY_TOKEN: "tc-live-mcp-runtime-token",
			}).allowedPeerAddresses,
		).toBeUndefined();
		expect(() =>
			readTelclaudeLiveMcpRuntimeConfig({
				TELCLAUDE_HERMES_LIVE_MCP_ENABLED: "1",
			}),
		).toThrow("TELCLAUDE_HERMES_MCP_RELAY_TOKEN is required");
	});

	it("maps the contained transport bearer to exactly one active runtime authority", async () => {
		const runtime = await startTelclaudeLiveMcpRuntime({
			config: config({ runtimeTransportToken: "tc-contained-mcp-transport-token" }),
			nowMs: () => 2_000,
		});
		try {
			if (!runtime.registry) throw new Error("runtime registry missing");
			const startupDiscovery = await postRpc(
				runtime.endpoint?.url,
				"Bearer tc-contained-mcp-transport-token",
				{
					jsonrpc: "2.0",
					id: "startup-tools",
					method: "tools/list",
				},
			);
			expect(startupDiscovery.httpStatus).toBe(200);
			expect(startupDiscovery.body).toMatchObject({
				result: {
					tools: expect.arrayContaining([expect.objectContaining({ name: "tc_provider_read" })]),
				},
			});

			const idleToolCall = await postRpc(
				runtime.endpoint?.url,
				"Bearer tc-contained-mcp-transport-token",
				providerReadCall("idle-call"),
			);
			expect(idleToolCall).toMatchObject({
				httpStatus: 200,
				body: { error: { code: -32001, message: "MCP runtime authority is not active" } },
			});

			const grant = runtime.registry.register({
				connection: connection(),
				authority: authority(),
				nowMs: 1_000,
				ttlMs: 60_000,
			});
			const activation = runtime.activateRuntimeAuthority({
				authorityHandle: grant.handle,
				connection: connection(),
				nowMs: 1_000,
				ttlMs: 60_000,
			});

			const listed = await postRpc(
				runtime.endpoint?.url,
				"Bearer tc-contained-mcp-transport-token",
				{
					jsonrpc: "2.0",
					id: "tools",
					method: "tools/list",
				},
			);
			expect(listed).toMatchObject({
				httpStatus: 200,
				body: {
					result: {
						tools: expect.arrayContaining([
							expect.objectContaining({
								name: "tc_provider_read",
								inputSchema: expect.objectContaining({
									type: "object",
									required: ["service", "action"],
								}),
							}),
						]),
					},
				},
			});
			const activeToolCall = await postRpc(
				runtime.endpoint?.url,
				"Bearer tc-contained-mcp-transport-token",
				providerReadCall("active-call"),
			);
			expect(activeToolCall).toMatchObject({
				httpStatus: 200,
				body: {
					error: {
						code: -32001,
						message: expect.stringContaining("live MCP relay client adapter is not configured"),
					},
				},
			});

			const secondGrant = runtime.registry.register({
				connection: connection({ sessionKey: "telegram:ops-2" }),
				authority: authority(),
				nowMs: 1_000,
				ttlMs: 60_000,
			});
			const secondActivation = runtime.activateRuntimeAuthority({
				authorityHandle: secondGrant.handle,
				connection: connection({ sessionKey: "telegram:ops-2" }),
				nowMs: 1_000,
				ttlMs: 60_000,
			});
			const ambiguous = await postRpc(
				runtime.endpoint?.url,
				"Bearer tc-contained-mcp-transport-token",
				{
					jsonrpc: "2.0",
					id: "ambiguous",
					method: "tools/list",
				},
			);
			expect(ambiguous).toMatchObject({
				httpStatus: 200,
				body: {
					result: {
						tools: expect.arrayContaining([expect.objectContaining({ name: "tc_provider_read" })]),
					},
				},
			});
			const ambiguousToolCall = await postRpc(
				runtime.endpoint?.url,
				"Bearer tc-contained-mcp-transport-token",
				providerReadCall("ambiguous-call"),
			);
			expect(ambiguousToolCall).toMatchObject({
				httpStatus: 200,
				body: { error: { code: -32001, message: "MCP runtime authority is not active" } },
			});

			expect(runtime.revokeRuntimeAuthority(secondActivation.id, "test complete", 1_500)).toBe(
				true,
			);
			const unambiguous = await postRpc(
				runtime.endpoint?.url,
				"Bearer tc-contained-mcp-transport-token",
				{
					jsonrpc: "2.0",
					id: "unambiguous",
					method: "tools/list",
				},
			);
			expect(unambiguous.httpStatus).toBe(200);
			expect(runtime.revokeRuntimeAuthority(activation.id, "test complete", 1_500)).toBe(true);
		} finally {
			await runtime.stop();
		}
	});

	it("keeps startup discovery alive when an activation outlives its registry grant", async () => {
		const runtime = await startTelclaudeLiveMcpRuntime({
			config: config({ runtimeTransportToken: "tc-contained-mcp-transport-token" }),
			nowMs: () => 2_000,
		});
		try {
			if (!runtime.registry) throw new Error("runtime registry missing");
			const grant = runtime.registry.register({
				connection: connection(),
				authority: authority(),
				nowMs: 1_000,
				ttlMs: 60_000,
			});
			runtime.activateRuntimeAuthority({
				authorityHandle: grant.handle,
				connection: connection(),
				nowMs: 1_000,
				ttlMs: 90_000,
			});
			expect(runtime.registry.revoke(grant.handle, "test registry grant expired", 1_500)).toBe(
				true,
			);

			const initialize = await postRpc(
				runtime.endpoint?.url,
				"Bearer tc-contained-mcp-transport-token",
				{
					jsonrpc: "2.0",
					id: "initialize",
					method: "initialize",
				},
			);
			expect(initialize).toMatchObject({
				httpStatus: 200,
				body: {
					result: {
						serverInfo: { name: "telclaude-live-mcp-relay" },
					},
				},
			});

			const listed = await postRpc(runtime.endpoint?.url, "Bearer tc-contained-mcp-transport-token", {
				jsonrpc: "2.0",
				id: "tools",
				method: "tools/list",
			});
			expect(listed).toMatchObject({
				httpStatus: 200,
				body: {
					result: {
						tools: expect.arrayContaining([expect.objectContaining({ name: "tc_provider_read" })]),
					},
				},
			});

			const call = await postRpc(
				runtime.endpoint?.url,
				"Bearer tc-contained-mcp-transport-token",
				providerReadCall("revoked-grant-call"),
			);
			expect(call).toMatchObject({
				httpStatus: 200,
				body: { error: { code: -32001, message: "MCP runtime authority is not active" } },
			});
		} finally {
			await runtime.stop();
		}
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
		runtimeTransportToken: "tc-live-mcp-runtime-token",
		...overrides,
	};
}

function providerReadCall(id: string): Record<string, unknown> {
	return {
		jsonrpc: "2.0",
		id,
		method: "tools/call",
		params: {
			name: "tc_provider_read",
			arguments: {
				service: "bank",
				action: "balances.list",
				params: {},
			},
		},
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
