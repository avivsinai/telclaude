import { describe, expect, it } from "vitest";
import {
	startTelclaudeLiveMcpRuntime,
	TelclaudeLiveMcpCanaryWindowBusyError,
} from "../../src/hermes/mcp/live-runtime.js";

const STATIC_TOKEN = "tc-live-mcp-canary-test-token";

async function startRuntime() {
	return startTelclaudeLiveMcpRuntime({
		config: {
			enabled: true,
			host: "127.0.0.1",
			port: 0,
			path: "/mcp",
			networkName: "telclaude-hermes-private",
			allowedPeerAddresses: undefined,
			runtimeTransportToken: STATIC_TOKEN,
		},
	});
}

async function postRpc(
	url: string,
	body: Record<string, unknown>,
): Promise<{ httpStatus: number; body: unknown }> {
	const response = await fetch(url, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			authorization: `Bearer ${STATIC_TOKEN}`,
		},
		body: JSON.stringify(body),
	});
	return { httpStatus: response.status, body: await response.json() };
}

function memorySearchCall(id: string): Record<string, unknown> {
	return {
		jsonrpc: "2.0",
		id,
		method: "tools/call",
		params: { name: "tc_memory_search", arguments: { query: "verify-live-canary", limit: 1 } },
	};
}

describe("live MCP canary window", () => {
	it("activates exactly one canary authority that the static transport token resolves", async () => {
		const runtime = await startRuntime();
		try {
			const url = runtime.endpoint?.url;
			if (!url) throw new Error("runtime endpoint missing");

			// Before the window: discovery works, tools/call is denied at 200.
			const denied = await postRpc(url, memorySearchCall("pre-window"));
			expect(denied.httpStatus).toBe(200);
			expect(denied.body).toMatchObject({
				error: { message: "MCP runtime authority is not active" },
			});

			const window = runtime.openCanaryWindow({ ttlMs: 60_000 });
			expect(window.activationId).toMatch(/^tc_mcp_active_/);
			expect(window.authorityHandle).toMatch(/^tc_mcp_/);

			// During the window: the canary authority resolves; the call reaches
			// the bridge (fail-closed relay clients reject it, but that proves
			// authority resolution succeeded — the denial is past the auth gate).
			const during = await postRpc(url, memorySearchCall("in-window"));
			expect(during.httpStatus).toBe(200);
			const duringBody = during.body as { error?: { message?: string } };
			expect(duringBody.error?.message).not.toBe("MCP runtime authority is not active");
			expect(duringBody.error?.message).not.toBe("MCP connection is not authorized");

			const closed = runtime.closeCanaryWindow({
				activationId: window.activationId,
				authorityHandle: window.authorityHandle,
			});
			expect(closed).toEqual({ revokedActivation: true, revokedAuthority: true });

			// After close: back to denial, and discovery still works.
			const after = await postRpc(url, memorySearchCall("post-window"));
			expect(after.body).toMatchObject({
				error: { message: "MCP runtime authority is not active" },
			});
			const list = await postRpc(url, { jsonrpc: "2.0", id: "list", method: "tools/list" });
			expect(list.httpStatus).toBe(200);
		} finally {
			await runtime.stop();
		}
	});

	it("refuses to open while another runtime authority is active and is idempotent on close", async () => {
		const runtime = await startRuntime();
		try {
			const window = runtime.openCanaryWindow({ ttlMs: 60_000 });
			expect(() => runtime.openCanaryWindow({ ttlMs: 60_000 })).toThrow(
				TelclaudeLiveMcpCanaryWindowBusyError,
			);
			const closed = runtime.closeCanaryWindow({
				activationId: window.activationId,
				authorityHandle: window.authorityHandle,
			});
			expect(closed).toEqual({ revokedActivation: true, revokedAuthority: true });
			const again = runtime.closeCanaryWindow({
				activationId: window.activationId,
				authorityHandle: window.authorityHandle,
			});
			expect(again).toEqual({ revokedActivation: false, revokedAuthority: false });

			// After close, a fresh window opens fine.
			const second = runtime.openCanaryWindow({ ttlMs: 60_000 });
			runtime.closeCanaryWindow({
				activationId: second.activationId,
				authorityHandle: second.authorityHandle,
			});
		} finally {
			await runtime.stop();
		}
	});
});
