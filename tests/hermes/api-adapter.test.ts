import { describe, expect, it } from "vitest";
import {
	type HermesApiFetch,
	type HermesApiResponse,
	HermesApiRuntimeAdapter,
} from "../../src/hermes/api-adapter.js";
import {
	TELCLAUDE_MCP_AUTHORITY_ENDPOINT_HEADER,
	TELCLAUDE_MCP_AUTHORITY_HEADER,
	TELCLAUDE_MCP_AUTHORITY_NETWORK_NAMESPACE_HEADER,
	TELCLAUDE_MCP_AUTHORITY_PROFILE_HEADER,
	TELCLAUDE_MCP_AUTHORITY_SESSION_KEY_HEADER,
} from "../../src/hermes/mcp/authority-registry.js";
import type { HermesRuntimeRequest } from "../../src/hermes/private-runtime.js";

describe("HermesApiRuntimeAdapter", () => {
	it("starts a Hermes run and maps structured SSE events", async () => {
		const promptCredential = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";
		const calls: Array<{ url: string; init: Record<string, unknown> }> = [];
		const fetcher: HermesApiFetch = async (url, init) => {
			calls.push({ url, init });
			if (url === "http://hermes.local/v1/runs") {
				return jsonResponse({ run_id: "run-1", status: "started" }, 202);
			}
			if (url === "http://hermes.local/v1/runs/run-1/events") {
				return sseResponse([
					sse({ event: "message.delta", delta: "hello " }),
					sse({ event: "tool.started", tool: "tc_memory_search", preview: "family" }),
					sse({ event: "tool.completed", tool: "tc_memory_search", duration: 0.25 }),
					sse({ event: "message.delta", delta: "world" }),
					sse({
						event: "run.completed",
						output: "hello world",
						usage: { input_tokens: 10, output_tokens: 2, total_tokens: 12 },
					}),
				]);
			}
			throw new Error(`unexpected fetch: ${url}`);
		};

		const adapter = new HermesApiRuntimeAdapter({
			baseUrl: "http://hermes.local",
			apiKey: "api-key",
			fetch: fetcher,
		});

		await expect(
			collect(
				adapter.run(
					baseRequest({
						prompt: promptCredential,
						resumeHermesSessionId: "hermes-session-1",
					}),
				),
			),
		).resolves.toEqual([
			{ type: "session", hermesSessionId: "hermes-session-1" },
			{ type: "text_delta", text: "hello " },
			{ type: "tool_use", toolName: "tc_memory_search", input: { preview: "family" } },
			{ type: "tool_result", toolName: "tc_memory_search", output: { duration: 0.25 } },
			{ type: "text_delta", text: "world" },
			{
				type: "done",
				response: "hello world",
				success: true,
				numTurns: 1,
			},
		]);

		const [startCall] = calls;
		expect(JSON.stringify({ url: startCall?.url, headers: startCall?.init.headers })).not.toContain(
			promptCredential,
		);
		expect(startCall?.init.headers).toMatchObject({
			Authorization: "Bearer api-key",
			"Content-Type": "application/json",
			"X-Hermes-Session-Key": "tg:123",
		});
		expect(JSON.parse(String(startCall?.init.body))).toMatchObject({
			input: promptCredential,
			session_id: "hermes-session-1",
		});
	});

	it("sends MCP authority only via transport headers, never prompt instructions or memory", async () => {
		const calls: Array<{ url: string; init: Record<string, unknown> }> = [];
		const fetcher: HermesApiFetch = async (url, init) => {
			calls.push({ url, init });
			if (url === "http://hermes.local/v1/runs") {
				return jsonResponse({ run_id: "run-1", status: "started" }, 202);
			}
			if (url === "http://hermes.local/v1/runs/run-1/events") {
				return sseResponse([sse({ event: "run.completed", output: "ok" })]);
			}
			throw new Error(`unexpected fetch: ${url}`);
		};
		const adapter = new HermesApiRuntimeAdapter({
			baseUrl: "http://hermes.local",
			apiKey: "api-key",
			fetch: fetcher,
		});

		await collect(
			adapter.run(
				baseRequest({
					mcpAuthority: {
						handle: "tc_mcp_secret_handle",
						connection: {
							sessionKey: "tg:123",
							profileId: "ops",
							endpointId: "endpoint-private",
							networkNamespace: "netns-private",
						},
						expiresAtMs: 123_456,
					},
				}),
			),
		);

		const [startCall] = calls;
		expect(startCall?.init.headers).toMatchObject({
			[TELCLAUDE_MCP_AUTHORITY_HEADER]: "tc_mcp_secret_handle",
			[TELCLAUDE_MCP_AUTHORITY_SESSION_KEY_HEADER]: "tg:123",
			[TELCLAUDE_MCP_AUTHORITY_PROFILE_HEADER]: "ops",
			[TELCLAUDE_MCP_AUTHORITY_ENDPOINT_HEADER]: "endpoint-private",
			[TELCLAUDE_MCP_AUTHORITY_NETWORK_NAMESPACE_HEADER]: "netns-private",
		});
		const startBody = JSON.parse(String(startCall?.init.body));
		const serializedBody = JSON.stringify(startBody);
		expect(serializedBody).not.toContain("tc_mcp_secret_handle");
		expect(serializedBody).not.toContain("endpoint-private");
		expect(serializedBody).not.toContain("netns-private");
		expect(serializedBody).not.toContain(TELCLAUDE_MCP_AUTHORITY_HEADER);
	});

	it("redacts failed run-start responses", async () => {
		const telegramToken = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";
		const adapter = new HermesApiRuntimeAdapter({
			baseUrl: "http://hermes.local",
			apiKey: "api-key",
			fetch: async () => textResponse(`denied ${telegramToken}`, 401),
		});

		const events = await collect(adapter.run(baseRequest()));

		expect(events).toEqual([
			{
				type: "done",
				response: "",
				success: false,
				error:
					"Hermes API POST /v1/runs failed with HTTP 401: denied [REDACTED:telegram_bot_token]",
			},
		]);
	});

	it("fails closed when the event stream ends without a terminal event", async () => {
		const adapter = new HermesApiRuntimeAdapter({
			baseUrl: "http://hermes.local",
			apiKey: "api-key",
			fetch: async (url) => {
				if (url === "http://hermes.local/v1/runs") {
					return jsonResponse({ run_id: "run-1" }, 202);
				}
				return sseResponse([sse({ event: "message.delta", delta: "partial" })]);
			},
		});

		const events = await collect(adapter.run(baseRequest()));

		expect(events).toEqual([
			{ type: "session", hermesSessionId: "tc-session-1" },
			{ type: "text_delta", text: "partial" },
			{
				type: "done",
				response: "partial",
				success: false,
				error: "Hermes API event stream ended without a terminal run event",
			},
		]);
	});

	it("redacts sensitive text in streamed terminal errors", async () => {
		const telegramToken = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";
		const adapter = new HermesApiRuntimeAdapter({
			baseUrl: "http://hermes.local",
			apiKey: "api-key",
			fetch: async (url) => {
				if (url === "http://hermes.local/v1/runs") {
					return jsonResponse({ run_id: "run-1" }, 202);
				}
				return sseResponse([sse({ event: "run.failed", error: `failed ${telegramToken}` })]);
			},
		});

		const events = await collect(adapter.run(baseRequest()));

		expect(events).toEqual([
			{ type: "session", hermesSessionId: "tc-session-1" },
			{
				type: "done",
				response: "",
				success: false,
				error: "failed [REDACTED:telegram_bot_token]",
			},
		]);
	});

	it("redacts sensitive text in completed terminal output", async () => {
		const telegramToken = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";
		const adapter = new HermesApiRuntimeAdapter({
			baseUrl: "http://hermes.local",
			apiKey: "api-key",
			fetch: async (url) => {
				if (url === "http://hermes.local/v1/runs") {
					return jsonResponse({ run_id: "run-1" }, 202);
				}
				return sseResponse([sse({ event: "run.completed", output: `done ${telegramToken}` })]);
			},
		});

		const events = await collect(adapter.run(baseRequest()));

		expect(events).toEqual([
			{ type: "session", hermesSessionId: "tc-session-1" },
			{
				type: "done",
				response: "done [REDACTED:telegram_bot_token]",
				success: true,
				numTurns: 1,
			},
		]);
	});

	it("redacts thrown fetch errors", async () => {
		const telegramToken = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";
		const adapter = new HermesApiRuntimeAdapter({
			baseUrl: "http://hermes.local",
			apiKey: "api-key",
			fetch: async () => {
				throw new Error(`network leaked ${telegramToken}`);
			},
		});

		const events = await collect(adapter.run(baseRequest()));

		expect(events).toEqual([
			{
				type: "done",
				response: "",
				success: false,
				error: "network leaked [REDACTED:telegram_bot_token]",
			},
		]);
	});
});

function baseRequest(overrides: Partial<HermesRuntimeRequest> = {}): HermesRuntimeRequest {
	return {
		prompt: "hello",
		cwd: "/repo",
		tier: "WRITE_LOCAL",
		sessionKey: "tg:123",
		telclaudeSessionId: "tc-session-1",
		profileId: "ops",
		identity: {
			userId: "operator",
			chatId: 123,
			actorId: 456,
			threadId: 789,
		},
		memory: {
			compiledMemoryMd: "# Memory\n- family prefers WhatsApp",
		},
		model: "anthropic/claude-sonnet",
		systemPromptAppend: "<context />",
		allowedSkills: ["external-provider"],
		isNewSession: true,
		timeoutMs: 60_000,
		signal: new AbortController().signal,
		...overrides,
	};
}

function jsonResponse(body: unknown, status = 200): HermesApiResponse {
	return {
		status,
		ok: status >= 200 && status < 300,
		json: async () => body,
		text: async () => JSON.stringify(body),
		body: null,
	};
}

function textResponse(body: string, status = 200): HermesApiResponse {
	return {
		status,
		ok: status >= 200 && status < 300,
		json: async () => JSON.parse(body),
		text: async () => body,
		body: null,
	};
}

function sseResponse(chunks: string[]): HermesApiResponse {
	return {
		status: 200,
		ok: true,
		json: async () => {
			throw new Error("SSE response has no JSON body");
		},
		text: async () => chunks.join(""),
		body: streamFromChunks(chunks),
	};
}

function streamFromChunks(chunks: string[]): HermesApiResponse["body"] {
	let index = 0;
	return {
		getReader: () => ({
			read: async () => {
				const chunk = chunks[index++];
				if (chunk === undefined) return { done: true };
				return { done: false, value: new TextEncoder().encode(chunk) };
			},
			releaseLock: () => undefined,
		}),
	};
}

function sse(payload: unknown): string {
	return `data: ${JSON.stringify(payload)}\n\n`;
}

async function collect<T>(iterable: AsyncIterable<T>): Promise<T[]> {
	const values: T[] = [];
	for await (const value of iterable) values.push(value);
	return values;
}
