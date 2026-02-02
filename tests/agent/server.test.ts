import { once } from "node:events";
import type { AddressInfo } from "node:net";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const executePooledQueryImpl = vi.hoisted(() => vi.fn());

vi.mock("../../src/sdk/client.js", () => ({
	executePooledQuery: (...args: unknown[]) => executePooledQueryImpl(...args),
}));

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		debug: vi.fn(),
	}),
}));

import { startAgentServer } from "../../src/agent/server.js";
import { buildInternalAuthHeaders, generateMoltbookKeyPair } from "../../src/internal-auth.js";

const ORIGINAL_MOLTBOOK_SECRET = process.env.MOLTBOOK_RPC_SECRET;
const ORIGINAL_MOLTBOOK_PRIVATE_KEY = process.env.MOLTBOOK_RPC_PRIVATE_KEY;
const ORIGINAL_MOLTBOOK_PUBLIC_KEY = process.env.MOLTBOOK_RPC_PUBLIC_KEY;

describe("agent server moltbook userId normalization", () => {
	let server: ReturnType<typeof startAgentServer> | null = null;
	let baseUrl = "";

	beforeEach(async () => {
		// Generate Ed25519 key pair for moltbook asymmetric auth
		const { privateKey, publicKey } = generateMoltbookKeyPair();
		process.env.MOLTBOOK_RPC_PRIVATE_KEY = privateKey;
		process.env.MOLTBOOK_RPC_PUBLIC_KEY = publicKey;
		delete process.env.MOLTBOOK_RPC_SECRET; // Ensure no symmetric fallback

		server = startAgentServer({ port: 0, host: "127.0.0.1" });
		await once(server, "listening");
		const address = server.address() as AddressInfo;
		baseUrl = `http://127.0.0.1:${address.port}`;
	});

	afterEach(() => {
		if (server) {
			server.close();
			server = null;
		}
		executePooledQueryImpl.mockReset();
		if (ORIGINAL_MOLTBOOK_SECRET === undefined) {
			delete process.env.MOLTBOOK_RPC_SECRET;
		} else {
			process.env.MOLTBOOK_RPC_SECRET = ORIGINAL_MOLTBOOK_SECRET;
		}
		if (ORIGINAL_MOLTBOOK_PRIVATE_KEY === undefined) {
			delete process.env.MOLTBOOK_RPC_PRIVATE_KEY;
		} else {
			process.env.MOLTBOOK_RPC_PRIVATE_KEY = ORIGINAL_MOLTBOOK_PRIVATE_KEY;
		}
		if (ORIGINAL_MOLTBOOK_PUBLIC_KEY === undefined) {
			delete process.env.MOLTBOOK_RPC_PUBLIC_KEY;
		} else {
			process.env.MOLTBOOK_RPC_PUBLIC_KEY = ORIGINAL_MOLTBOOK_PUBLIC_KEY;
		}
	});

	it("forces moltbook prefix for moltbook scope userId", async () => {
		executePooledQueryImpl.mockReturnValueOnce(
			(async function* () {
				yield {
					type: "done",
					result: {
						response: "ok",
						success: true,
						error: undefined,
						costUsd: 0,
						numTurns: 0,
						durationMs: 1,
					},
				};
			})(),
		);

		const body = JSON.stringify({
			prompt: "hi",
			tier: "READ_ONLY",
			poolKey: "pool-1",
			userId: "user-1",
		});
		const headers = buildInternalAuthHeaders("POST", "/v1/query", body, { scope: "moltbook" });

		const res = await fetch(`${baseUrl}/v1/query`, {
			method: "POST",
			headers: { "Content-Type": "application/json", ...headers },
			body,
		});
		await res.text();

		expect(executePooledQueryImpl).toHaveBeenCalledTimes(1);
		const [, options] = executePooledQueryImpl.mock.calls[0] as [string, { userId?: string }];
		expect(options.userId).toBe("moltbook:user-1");
	});
});
