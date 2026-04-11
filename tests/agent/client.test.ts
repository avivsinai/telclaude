import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const buildInternalAuthHeadersImpl = vi.hoisted(() => vi.fn(() => ({ "x-test-auth": "ok" })));
const retryAsyncImpl = vi.hoisted(
	() =>
		vi.fn(async <T>(fn: () => Promise<T>) => {
			return await fn();
		}),
);
const withTimeoutImpl = vi.hoisted(
	() =>
		vi.fn(async <T>(promise: Promise<T>) => {
			return await promise;
		}),
);
const issueTokenImpl = vi.hoisted(() => vi.fn(async () => ({ token: "session-token" })));
const isTokenManagerActiveImpl = vi.hoisted(() => vi.fn(() => true));

vi.mock("../../src/infra/network-errors.js", () => ({
	isTransientNetworkError: () => false,
}));

vi.mock("../../src/infra/retry.js", () => ({
	retryAsync: (...args: Parameters<typeof retryAsyncImpl>) => retryAsyncImpl(...args),
}));

vi.mock("../../src/infra/timeout.js", () => ({
	withTimeout: (...args: Parameters<typeof withTimeoutImpl>) => withTimeoutImpl(...args),
}));

vi.mock("../../src/internal-auth.js", () => ({
	buildInternalAuthHeaders: (...args: Parameters<typeof buildInternalAuthHeadersImpl>) =>
		buildInternalAuthHeadersImpl(...args),
}));

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		debug: vi.fn(),
	}),
}));

vi.mock("../../src/relay/token-manager.js", () => ({
	issueToken: (...args: Parameters<typeof issueTokenImpl>) => issueTokenImpl(...args),
	isTokenManagerActive: (...args: Parameters<typeof isTokenManagerActiveImpl>) =>
		isTokenManagerActiveImpl(...args),
}));

import { executeRemoteQuery } from "../../src/agent/client.js";

function buildStreamingResponse() {
	const encoder = new TextEncoder();
	const doneChunk = {
		type: "done",
		result: {
			response: "ok",
			success: true,
			error: undefined,
			costUsd: 0,
			numTurns: 1,
			durationMs: 1,
		},
	};
	return new Response(
		new ReadableStream({
			start(controller) {
				controller.enqueue(encoder.encode(`${JSON.stringify(doneChunk)}\n`));
				controller.close();
			},
		}),
		{ status: 200 },
	);
}

describe("executeRemoteQuery credential forwarding", () => {
	const originalFetch = globalThis.fetch;
	let capturedBody: Record<string, unknown> | undefined;

	beforeEach(() => {
		capturedBody = undefined;
		globalThis.fetch = vi.fn(async (_input, init) => {
			capturedBody = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
			return buildStreamingResponse();
		}) as typeof fetch;
	});

	afterEach(() => {
		globalThis.fetch = originalFetch;
		vi.clearAllMocks();
	});

	it("does not serialize exposed credentials", async () => {
		const chunks = [];
		for await (const chunk of executeRemoteQuery("hi", {
			agentUrl: "http://agent",
			cwd: "/workspace",
			tier: "FULL_ACCESS",
			poolKey: "pool",
			userId: "user-1",
			scope: "telegram",
			enableSkills: false,
			timeoutMs: 1000,
		})) {
			chunks.push(chunk);
		}

		expect(chunks).toHaveLength(1);
		expect(capturedBody?.sessionToken).toBe("session-token");
		expect(capturedBody?.exposedCredentials).toBeUndefined();
	});
});
