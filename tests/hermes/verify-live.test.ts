import { describe, expect, it } from "vitest";
import { TELCLAUDE_MCP_TOOL_NAMES } from "../../src/hermes/mcp/policy.js";
import type {
	HermesRuntimeAdapter,
	HermesRuntimeEvent,
	HermesRuntimeRequest,
} from "../../src/hermes/private-runtime.js";
import {
	buildHermesVerifyLiveCanaryPrompt,
	buildHermesVerifyLiveReport,
	HERMES_VERIFY_LIVE_SENTINEL,
	type HermesVerifyLiveCanaryWindowClient,
	type HermesVerifyLiveRpcTransport,
	runHermesVerifyLiveMcpChecks,
	runHermesVerifyLiveTurnChecks,
} from "../../src/hermes/verify-live.js";

function fakeCanaryWindow(overrides: Partial<HermesVerifyLiveCanaryWindowClient> = {}): {
	client: HermesVerifyLiveCanaryWindowClient;
	calls: { opened: number; closed: number };
} {
	const calls = { opened: 0, closed: 0 };
	const client: HermesVerifyLiveCanaryWindowClient = {
		open:
			overrides.open ??
			(async () => {
				calls.opened += 1;
				return {
					activationId: "tc_mcp_active_test",
					authorityHandle: "tc_mcp_handle_test",
					expiresAtMs: 9_999_999,
				};
			}),
		close:
			overrides.close ??
			(async () => {
				calls.closed += 1;
				return {};
			}),
	};
	return { client, calls };
}

const ENDPOINT = "http://192.0.2.10:8793/mcp";

function fullTool(name: string): Record<string, unknown> {
	return {
		name,
		description: `Telclaude relay tool ${name}`,
		inputSchema: { type: "object", properties: { input: { type: "string" } } },
	};
}

function mcpTransport(handlers: {
	initialize?: () => { status: number; body: unknown };
	toolsList?: () => { status: number; body: unknown };
	toolsCall?: (params: { name: string; arguments: Record<string, unknown> }) => {
		status: number;
		body: unknown;
	};
}): HermesVerifyLiveRpcTransport {
	return async (request) => {
		const payload = request.payload as { method: string; id: string; params: unknown };
		if (payload.method === "initialize") {
			return (
				handlers.initialize?.() ?? {
					status: 200,
					body: { result: { serverInfo: { name: "telclaude-live-mcp-relay" } } },
				}
			);
		}
		if (payload.method === "tools/list") {
			return (
				handlers.toolsList?.() ?? {
					status: 200,
					body: { result: { tools: TELCLAUDE_MCP_TOOL_NAMES.map(fullTool) } },
				}
			);
		}
		if (payload.method === "tools/call") {
			const params = payload.params as { name: string; arguments: Record<string, unknown> };
			return (
				handlers.toolsCall?.(params) ?? {
					status: 200,
					body: { error: { code: -32001, message: "capability scope denied: web.fetch" } },
				}
			);
		}
		return { status: 404, body: { error: { message: "unexpected method" } } };
	};
}

function statuses(checks: readonly { id: string; status: string }[]): Record<string, string> {
	return Object.fromEntries(checks.map((check) => [check.id, check.status]));
}

describe("runHermesVerifyLiveMcpChecks", () => {
	it("passes when the full surface is advertised and the scope-less canary is denied", async () => {
		const toolCalls: { name: string; arguments: Record<string, unknown> }[] = [];
		const checks = await runHermesVerifyLiveMcpChecks({
			endpointUrl: ENDPOINT,
			transport: mcpTransport({
				toolsCall: (params) => {
					toolCalls.push(params);
					return {
						status: 200,
						body: { error: { code: -32001, message: "capability scope denied: web.fetch" } },
					};
				},
			}),
		});
		expect(statuses(checks)).toEqual({
			"mcp.initialize": "pass",
			"mcp.tools_list_exact": "pass",
			"mcp.tool_schemas": "pass",
			"mcp.capability_scope_fail_closed": "pass",
		});
		// The canary fetch target can never resolve, so even a broken gate
		// cannot produce real egress.
		expect(toolCalls).toEqual([
			{
				name: "tc_web_fetch",
				arguments: { url: "https://capability-scope-canary.invalid/", maxChars: 64 },
			},
		]);
	});

	it("opens and closes the canary window around the capability scope check", async () => {
		const { client, calls } = fakeCanaryWindow();
		const checks = await runHermesVerifyLiveMcpChecks({
			endpointUrl: ENDPOINT,
			transport: mcpTransport({}),
			canaryWindow: client,
		});
		expect(statuses(checks)["mcp.capability_scope_fail_closed"]).toBe("pass");
		expect(calls).toEqual({ opened: 1, closed: 1 });
	});

	it("fails the capability check when tc_web_fetch returns a result (gating regression)", async () => {
		const { client, calls } = fakeCanaryWindow();
		const checks = await runHermesVerifyLiveMcpChecks({
			endpointUrl: ENDPOINT,
			transport: mcpTransport({
				toolsCall: () => ({
					status: 200,
					body: { result: { content: [{ type: "text", text: "fetched" }] } },
				}),
			}),
			canaryWindow: client,
		});
		const check = checks.find((entry) => entry.id === "mcp.capability_scope_fail_closed");
		expect(check?.status).toBe("fail");
		expect(check?.detail).toContain("capability gating is broken");
		expect(calls.closed).toBe(1);
	});

	it("fails the capability check on a non-scope denial with actionable detail", async () => {
		const checks = await runHermesVerifyLiveMcpChecks({
			endpointUrl: ENDPOINT,
			transport: mcpTransport({
				toolsCall: () => ({
					status: 200,
					body: { error: { code: -32001, message: "MCP runtime authority is not active" } },
				}),
			}),
		});
		const check = checks.find((entry) => entry.id === "mcp.capability_scope_fail_closed");
		expect(check?.status).toBe("fail");
		expect(check?.detail).toContain("MCP runtime authority is not active");
		expect(check?.detail).toContain("canary activation window");
	});

	it("fails the capability check closed when the canary window open is refused", async () => {
		const { client } = fakeCanaryWindow({
			open: async () => {
				throw new Error("Hermes live MCP admin request failed (409): Busy.");
			},
		});
		const checks = await runHermesVerifyLiveMcpChecks({
			endpointUrl: ENDPOINT,
			transport: mcpTransport({}),
			canaryWindow: client,
		});
		const check = checks.find((entry) => entry.id === "mcp.capability_scope_fail_closed");
		expect(check?.status).toBe("fail");
		expect(check?.detail).toContain("409");
	});

	it("fails closed on a names-only tools/list (the live regression shape)", async () => {
		const checks = await runHermesVerifyLiveMcpChecks({
			endpointUrl: ENDPOINT,
			transport: mcpTransport({
				toolsList: () => ({
					status: 200,
					body: { result: { tools: TELCLAUDE_MCP_TOOL_NAMES.map((name) => ({ name })) } },
				}),
			}),
		});
		expect(statuses(checks)["mcp.tools_list_exact"]).toBe("pass");
		expect(statuses(checks)["mcp.tool_schemas"]).toBe("fail");
	});

	it("fails the exact-surface check when a provider tool is missing", async () => {
		const partial = TELCLAUDE_MCP_TOOL_NAMES.filter((name) => name !== "tc_provider_read");
		const checks = await runHermesVerifyLiveMcpChecks({
			endpointUrl: ENDPOINT,
			transport: mcpTransport({
				toolsList: () => ({ status: 200, body: { result: { tools: partial.map(fullTool) } } }),
			}),
		});
		expect(statuses(checks)["mcp.tools_list_exact"]).toBe("fail");
	});

	it("fails all MCP checks on an unauthorized connection", async () => {
		const denied = {
			status: 403,
			body: { error: { message: "MCP connection is not authorized" } },
		};
		const checks = await runHermesVerifyLiveMcpChecks({
			endpointUrl: ENDPOINT,
			transport: mcpTransport({ initialize: () => denied, toolsList: () => denied }),
		});
		expect(checks.every((check) => check.status === "fail")).toBe(true);
		expect(checks[0].detail).toContain("probe token");
	});

	it("fails closed on a transport error", async () => {
		const checks = await runHermesVerifyLiveMcpChecks({
			endpointUrl: ENDPOINT,
			transport: async () => {
				throw new Error("network unreachable");
			},
		});
		expect(checks.every((check) => check.status === "fail")).toBe(true);
	});
});

function fakeRuntime(
	events: (request: HermesRuntimeRequest) => HermesRuntimeEvent[],
): HermesRuntimeAdapter {
	return {
		async *run(request) {
			yield* events(request);
		},
	};
}

function successfulTurnEvents(toolNames: readonly string[]): HermesRuntimeEvent[] {
	return [
		{ type: "session", hermesSessionId: "hermes-session-1" },
		...toolNames.flatMap((toolName): HermesRuntimeEvent[] => [
			{ type: "tool_use", toolName, input: {} },
			{ type: "tool_result", toolName, output: { ok: true } },
		]),
		{ type: "text_delta", text: HERMES_VERIFY_LIVE_SENTINEL },
		{
			type: "done",
			response: HERMES_VERIFY_LIVE_SENTINEL,
			success: true,
			costUsd: 0,
			numTurns: 1,
			durationMs: 1234,
		},
	];
}

describe("runHermesVerifyLiveTurnChecks", () => {
	it("passes when the canary turn invokes the served MCP and acknowledges", async () => {
		const { client, calls } = fakeCanaryWindow();
		const checks = await runHermesVerifyLiveTurnChecks({
			runtime: fakeRuntime(() => successfulTurnEvents(["telclaudeRelay.tc_memory_search"])),
			timeoutMs: 5_000,
			canaryWindow: client,
		});
		expect(statuses(checks)).toEqual({
			"runtime.turn_completes": "pass",
			"runtime.mcp_tool_invoked": "pass",
			"runtime.canary_acknowledged": "pass",
			"runtime.provider_read": "skip",
		});
		expect(calls).toEqual({ opened: 1, closed: 1 });
	});

	it("fails all turn checks closed without a canary window client", async () => {
		const checks = await runHermesVerifyLiveTurnChecks({
			runtime: fakeRuntime(() => successfulTurnEvents(["tc_memory_search"])),
			timeoutMs: 5_000,
		});
		expect(statuses(checks)["runtime.turn_completes"]).toBe("fail");
		expect(statuses(checks)["runtime.mcp_tool_invoked"]).toBe("fail");
		expect(statuses(checks)["runtime.canary_acknowledged"]).toBe("fail");
		expect(checks[0].detail).toContain("canary activation window");
	});

	it("fails all turn checks closed when the window open is refused (busy)", async () => {
		const { client } = fakeCanaryWindow({
			open: async () => {
				throw new Error("Hermes live MCP admin request failed (409): Busy.");
			},
		});
		const checks = await runHermesVerifyLiveTurnChecks({
			runtime: fakeRuntime(() => successfulTurnEvents(["tc_memory_search"])),
			timeoutMs: 5_000,
			canaryWindow: client,
		});
		expect(checks.every((check) => check.status !== "pass")).toBe(true);
		expect(checks[0].detail).toContain("409");
	});

	it("closes the window even when the turn stream errors", async () => {
		const { client, calls } = fakeCanaryWindow();
		const checks = await runHermesVerifyLiveTurnChecks({
			runtime: {
				// biome-ignore lint/correctness/useYield: error-path generator never yields by design
				async *run() {
					throw new Error("stream exploded");
				},
			},
			timeoutMs: 5_000,
			canaryWindow: client,
		});
		expect(statuses(checks)["runtime.turn_completes"]).toBe("fail");
		expect(calls.closed).toBe(1);
	});

	it("fails the MCP-invocation check when the turn streams but never calls a tc_ tool", async () => {
		const { client } = fakeCanaryWindow();
		const checks = await runHermesVerifyLiveTurnChecks({
			runtime: fakeRuntime(() => [
				{ type: "session", hermesSessionId: "hermes-session-2" },
				{ type: "text_delta", text: "the provider tools are not available in my toolset" },
				{ type: "done", response: "no tools", success: true, durationMs: 10 },
			]),
			timeoutMs: 5_000,
			canaryWindow: client,
		});
		expect(statuses(checks)["runtime.turn_completes"]).toBe("pass");
		expect(statuses(checks)["runtime.mcp_tool_invoked"]).toBe("fail");
		expect(statuses(checks)["runtime.canary_acknowledged"]).toBe("fail");
	});

	it("fails turn completion on an unsuccessful done event", async () => {
		const { client } = fakeCanaryWindow();
		const checks = await runHermesVerifyLiveTurnChecks({
			runtime: fakeRuntime(() => [
				{ type: "done", success: false, error: "api server unreachable", durationMs: 5 },
			]),
			timeoutMs: 5_000,
			canaryWindow: client,
		});
		expect(statuses(checks)["runtime.turn_completes"]).toBe("fail");
	});

	it("requires tc_provider_read when a provider canary is configured", async () => {
		const canary = { providerId: "google", service: "calendar", action: "list_events" };
		const without = await runHermesVerifyLiveTurnChecks({
			runtime: fakeRuntime(() => successfulTurnEvents(["tc_memory_search"])),
			timeoutMs: 5_000,
			providerCanary: canary,
			canaryWindow: fakeCanaryWindow().client,
		});
		expect(statuses(without)["runtime.provider_read"]).toBe("fail");

		const openInputs: unknown[] = [];
		const { client } = fakeCanaryWindow({
			open: async (input) => {
				openInputs.push(input);
				return {
					activationId: "tc_mcp_active_test",
					authorityHandle: "tc_mcp_handle_test",
					expiresAtMs: 9_999_999,
				};
			},
		});
		const withProvider = await runHermesVerifyLiveTurnChecks({
			runtime: fakeRuntime(() => successfulTurnEvents(["tc_memory_search", "tc_provider_read"])),
			timeoutMs: 5_000,
			providerCanary: canary,
			canaryWindow: client,
		});
		expect(statuses(withProvider)["runtime.provider_read"]).toBe("pass");
		expect(openInputs[0]).toMatchObject({ providerScopes: ["google"] });
	});

	it("includes the provider step in the canary prompt only when configured", () => {
		expect(buildHermesVerifyLiveCanaryPrompt()).not.toContain("tc_provider_read");
		expect(
			buildHermesVerifyLiveCanaryPrompt({
				providerId: "google",
				service: "calendar",
				action: "list_events",
			}),
		).toContain("tc_provider_read");
	});
});

describe("buildHermesVerifyLiveReport", () => {
	it("fails the report when any check fails and ignores skips", () => {
		const failing = buildHermesVerifyLiveReport(
			[
				{ id: "a", status: "pass", detail: "ok" },
				{ id: "b", status: "fail", detail: "broken" },
			],
			1_000,
		);
		expect(failing.status).toBe("fail");

		const passing = buildHermesVerifyLiveReport(
			[
				{ id: "a", status: "pass", detail: "ok" },
				{ id: "b", status: "skip", detail: "not configured" },
			],
			1_000,
		);
		expect(passing.status).toBe("pass");
	});
});
