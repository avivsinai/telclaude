import { afterEach, describe, expect, it, vi } from "vitest";

const queryMock = vi.fn();

vi.mock("@anthropic-ai/claude-agent-sdk", () => ({
	query: (...args: unknown[]) => queryMock(...args),
}));

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		debug: vi.fn(),
	}),
}));

import { executePooledQuery } from "../../src/sdk/client.js";

afterEach(() => {
	queryMock.mockReset();
	vi.resetModules();
});

function collectChunks<T>(iterable: AsyncIterable<T>): Promise<T[]> {
	const chunks: T[] = [];
	return (async () => {
		for await (const c of iterable) chunks.push(c);
		return chunks;
	})();
}

describe("executePooledQuery streaming", () => {
	it("emits text -> tool_use -> done with streamed response", async () => {
		queryMock.mockReturnValueOnce(
			(async function* () {
				yield {
					type: "stream_event",
					event: { type: "content_block_delta", delta: { type: "text_delta", text: "Hi" } },
				};
				yield {
					type: "stream_event",
					event: { type: "content_block_start", content_block: { type: "tool_use", name: "Read" } },
				};
				yield { type: "stream_event", event: { type: "content_block_stop" } };
				yield {
					type: "result",
					total_cost_usd: 1,
					num_turns: 1,
					duration_ms: 5,
					subtype: "success",
				};
			})(),
		);

		const chunks = await collectChunks(
			executePooledQuery("prompt", {
				cwd: "/tmp",
				tier: "READ_ONLY",
				poolKey: "chat-1",
			}),
		);

		expect(chunks.map((c: any) => c.type)).toEqual(["text", "tool_use", "done"]);
		expect((chunks[0] as any).content).toBe("Hi");
		expect((chunks[1] as any).toolName).toBe("Read");
		expect((chunks[2] as any).result.response).toBe("Hi");
	});

	it("accumulates tool input from input_json_delta events", async () => {
		queryMock.mockReturnValueOnce(
			(async function* () {
				yield {
					type: "stream_event",
					event: {
						type: "content_block_start",
						content_block: { type: "tool_use", name: "Bash" },
					},
				};
				yield {
					type: "stream_event",
					event: {
						type: "content_block_delta",
						delta: { type: "input_json_delta", partial_json: '{"command":"echo hi"}' },
					},
				};
				yield { type: "stream_event", event: { type: "content_block_stop" } };
				yield {
					type: "result",
					total_cost_usd: 0,
					num_turns: 1,
					duration_ms: 1,
					subtype: "success",
				};
			})(),
		);

		const chunks = await collectChunks(
			executePooledQuery("prompt", {
				cwd: "/tmp",
				tier: "READ_ONLY",
				poolKey: "chat-3",
			}),
		);

		const toolUse = chunks.find((c: any) => c.type === "tool_use") as any;
		expect(toolUse.input).toEqual({ command: "echo hi" });
	});

	it("falls back to assistant message text when no stream events", async () => {
		queryMock.mockReturnValueOnce(
			(async function* () {
				yield {
					type: "assistant",
					message: { content: [{ type: "text", text: "Fallback text" }] },
				};
				yield {
					type: "result",
					total_cost_usd: 0.2,
					num_turns: 1,
					duration_ms: 2,
					subtype: "success",
				};
			})(),
		);

		const chunks = await collectChunks(
			executePooledQuery("prompt", {
				cwd: "/tmp",
				tier: "READ_ONLY",
				poolKey: "chat-2",
			}),
		);

		expect(chunks.map((c: any) => c.type)).toEqual(["text", "done"]);
		expect((chunks[0] as any).content).toBe("Fallback text");
		expect((chunks[1] as any).result.response).toBe("Fallback text");
	});
});
