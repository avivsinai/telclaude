import { beforeEach, describe, expect, it, vi } from "vitest";

const executeHermesQueryMock = vi.hoisted(() => vi.fn());

vi.mock("../../src/hermes/private-execute.js", () => ({
	executeHermesQuery: (...args: unknown[]) => executeHermesQueryMock(...args),
}));

import { SecurityObserver } from "../../src/security/observer.js";

async function* observerStream() {
	yield { type: "text", content: '{"classification":"ALLOW","confidence":0.91,"reason":"safe"}' };
	yield {
		type: "done",
		result: {
			response: '{"classification":"ALLOW","confidence":0.91,"reason":"safe"}',
			success: true,
			costUsd: 0,
			numTurns: 1,
			durationMs: 1,
		},
	};
}

describe("SecurityObserver Hermes authority", () => {
	beforeEach(() => {
		executeHermesQueryMock.mockReset();
		executeHermesQueryMock.mockReturnValue(observerStream());
	});

	it("does not grant MCP authority while classifying untrusted inbound text", async () => {
		const observer = new SecurityObserver({
			enabled: true,
			maxLatencyMs: 2_000,
			dangerThreshold: 0.7,
			fallbackOnTimeout: "block",
			cwd: "/repo",
		});

		const result = await observer.analyze("Please inspect this ordinary request for risk", {
			permissionTier: "WRITE_LOCAL",
			hasFlaggedHistory: false,
		});

		expect(result.classification).toBe("ALLOW");
		expect(executeHermesQueryMock).toHaveBeenCalledTimes(1);
		const [, options] = executeHermesQueryMock.mock.calls[0] as [string, Record<string, unknown>];
		expect(options.allowedSkills).toEqual(["security-gate"]);
		expect(options.mcpAuthority).toBe(false);
		expect(JSON.stringify(options)).not.toContain("memorySource");
		expect(JSON.stringify(options)).not.toContain("writableNamespace");
		expect(JSON.stringify(options)).not.toContain("outboundChannels");
		expect(JSON.stringify(options)).not.toContain("providerScopes");
	});
});
