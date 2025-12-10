import { afterEach, describe, expect, it, vi } from "vitest";

// Capture query invocations
const queryCalls: Array<{ prompt: string; options: Record<string, unknown> }> = [];

vi.mock("@anthropic-ai/claude-agent-sdk", () => {
	return {
		query: ({ prompt, options }: { prompt: string; options: Record<string, unknown> }) => {
			queryCalls.push({ prompt, options });
			async function* gen() {
				yield { type: "system", session_id: "session-abc" };
				yield {
					type: "result",
					session_id: "session-abc",
					total_cost_usd: 0,
					num_turns: 1,
					duration_ms: 1,
					subtype: "success",
				};
			}
			return gen();
		},
	};
});

import {
	destroySessionManager,
	executeWithSession,
	getSessionManager,
} from "../../src/sdk/session-manager.js";

describe("executeWithSession", () => {
	afterEach(() => {
		queryCalls.length = 0;
		destroySessionManager();
		vi.resetModules();
	});

	it("captures session_id and reuses it on subsequent calls", async () => {
		const mgr = getSessionManager();
		const opts = { cwd: "/tmp" };

		// First call should not send resume
		for await (const _ of executeWithSession(mgr, "chat-1", "hello", opts)) {
			// iterate to consume stream
		}
		expect(queryCalls[0].options.resume).toBeUndefined();

		// Second call should resume prior session
		for await (const _ of executeWithSession(mgr, "chat-1", "again", opts)) {
			break; // we only need initial call capture
		}
		expect(queryCalls[1].options.resume).toBe("session-abc");
	});
});
