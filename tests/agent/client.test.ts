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
const isDockerEnvironmentImpl = vi.hoisted(() => vi.fn(() => true));
const getGitCredentialsImpl = vi.hoisted(
	() => vi.fn(async () => ({ username: "bot", email: "bot@example.com", token: "github-secret" })),
);
const getOpenAIKeyImpl = vi.hoisted(() => vi.fn(async () => "openai-secret"));

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

vi.mock("../../src/sandbox/mode.js", () => ({
	isDockerEnvironment: (...args: Parameters<typeof isDockerEnvironmentImpl>) =>
		isDockerEnvironmentImpl(...args),
}));

vi.mock("../../src/services/git-credentials.js", () => ({
	getGitCredentials: (...args: Parameters<typeof getGitCredentialsImpl>) =>
		getGitCredentialsImpl(...args),
}));

vi.mock("../../src/services/openai-client.js", () => ({
	getOpenAIKey: (...args: Parameters<typeof getOpenAIKeyImpl>) => getOpenAIKeyImpl(...args),
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
	const originalExposeOptIn = process.env.TELCLAUDE_INSECURE_EXPOSE_NATIVE_CREDENTIALS;
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
		if (originalExposeOptIn === undefined) {
			delete process.env.TELCLAUDE_INSECURE_EXPOSE_NATIVE_CREDENTIALS;
		} else {
			process.env.TELCLAUDE_INSECURE_EXPOSE_NATIVE_CREDENTIALS = originalExposeOptIn;
		}
		vi.clearAllMocks();
	});

	it("does not serialize exposed credentials in Docker mode", async () => {
		isDockerEnvironmentImpl.mockReturnValue(true);

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
		expect(getGitCredentialsImpl).not.toHaveBeenCalled();
		expect(getOpenAIKeyImpl).not.toHaveBeenCalled();
	});

	it("does not forward credentials in native mode by default (secure invariant)", async () => {
		isDockerEnvironmentImpl.mockReturnValue(false);
		delete process.env.TELCLAUDE_INSECURE_EXPOSE_NATIVE_CREDENTIALS;

		for await (const _chunk of executeRemoteQuery("hi", {
			agentUrl: "http://agent",
			cwd: "/workspace",
			tier: "FULL_ACCESS",
			poolKey: "pool",
			userId: "user-1",
			scope: "telegram",
			enableSkills: false,
			timeoutMs: 1000,
		})) {
			// drain stream
		}

		expect(capturedBody?.exposedCredentials).toBeUndefined();
		expect(getGitCredentialsImpl).not.toHaveBeenCalled();
		expect(getOpenAIKeyImpl).not.toHaveBeenCalled();
	});

	it("forwards credentials in native FULL_ACCESS telegram only when insecure opt-in is set", async () => {
		isDockerEnvironmentImpl.mockReturnValue(false);
		process.env.TELCLAUDE_INSECURE_EXPOSE_NATIVE_CREDENTIALS = "1";

		for await (const _chunk of executeRemoteQuery("hi", {
			agentUrl: "http://agent",
			cwd: "/workspace",
			tier: "FULL_ACCESS",
			poolKey: "pool",
			userId: "user-1",
			scope: "telegram",
			enableSkills: false,
			timeoutMs: 1000,
		})) {
			// drain stream
		}

		expect(capturedBody?.exposedCredentials).toEqual({
			githubToken: "github-secret",
			openaiApiKey: "openai-secret",
		});
	});

	it("does not forward credentials even with opt-in when scope is not telegram", async () => {
		isDockerEnvironmentImpl.mockReturnValue(false);
		process.env.TELCLAUDE_INSECURE_EXPOSE_NATIVE_CREDENTIALS = "1";

		for await (const _chunk of executeRemoteQuery("hi", {
			agentUrl: "http://agent",
			cwd: "/workspace",
			tier: "FULL_ACCESS",
			poolKey: "pool",
			userId: "user-1",
			scope: "social",
			enableSkills: false,
			timeoutMs: 1000,
		})) {
			// drain stream
		}

		expect(capturedBody?.exposedCredentials).toBeUndefined();
	});

	it("does not forward credentials even with opt-in for non-FULL_ACCESS tiers", async () => {
		isDockerEnvironmentImpl.mockReturnValue(false);
		process.env.TELCLAUDE_INSECURE_EXPOSE_NATIVE_CREDENTIALS = "1";

		for await (const _chunk of executeRemoteQuery("hi", {
			agentUrl: "http://agent",
			cwd: "/workspace",
			tier: "WRITE_LOCAL",
			poolKey: "pool",
			userId: "user-1",
			scope: "telegram",
			enableSkills: false,
			timeoutMs: 1000,
		})) {
			// drain stream
		}

		expect(capturedBody?.exposedCredentials).toBeUndefined();
	});
});
