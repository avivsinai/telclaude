import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const executeRemoteQueryMock = vi.hoisted(() => vi.fn());
const createMoltbookApiClientMock = vi.hoisted(() => vi.fn());
const loadConfigMock = vi.hoisted(() => vi.fn());
const getEntriesMock = vi.hoisted(() => vi.fn());

vi.mock("../../src/agent/client.js", () => ({
	executeRemoteQuery: (...args: unknown[]) => executeRemoteQueryMock(...args),
}));

vi.mock("../../src/moltbook/api-client.js", () => ({
	createMoltbookApiClient: (...args: unknown[]) => createMoltbookApiClientMock(...args),
}));

vi.mock("../../src/config/config.js", () => ({
	loadConfig: () => loadConfigMock(),
}));

vi.mock("../../src/memory/store.js", () => ({
	getEntries: (...args: unknown[]) => getEntriesMock(...args),
}));

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		debug: vi.fn(),
	}),
}));

import * as handler from "../../src/moltbook/handler.js";

const sampleEntries = [
	{
		id: "profile-1",
		category: "profile",
		content: "Name: telclaude",
		_provenance: { source: "telegram", trust: "trusted", createdAt: 1 },
	},
];

async function* mockStream(text: string, success = true, error?: string) {
	yield { type: "text", content: text } as const;
	yield {
		type: "done",
		result: {
			response: text,
			success,
			error,
			costUsd: 0,
			numTurns: 1,
			durationMs: 1,
		},
	} as const;
}

describe("moltbook handler", () => {
	const originalAgentUrl = process.env.TELCLAUDE_MOLTBOOK_AGENT_URL;

	beforeEach(() => {
		executeRemoteQueryMock.mockReset();
		createMoltbookApiClientMock.mockReset();
		loadConfigMock.mockReset();
		getEntriesMock.mockReset();
		getEntriesMock.mockReturnValue(sampleEntries);
		process.env.TELCLAUDE_MOLTBOOK_AGENT_URL = "http://agent-moltbook";
	});

	afterEach(() => {
		if (originalAgentUrl === undefined) {
			delete process.env.TELCLAUDE_MOLTBOOK_AGENT_URL;
		} else {
			process.env.TELCLAUDE_MOLTBOOK_AGENT_URL = originalAgentUrl;
		}
	});

	it("heartbeat returns early when moltbook disabled", async () => {
		loadConfigMock.mockReturnValueOnce({ moltbook: { enabled: false } });
		const res = await handler.handleMoltbookHeartbeat();
		expect(res.ok).toBe(true);
		expect(res.message).toContain("disabled");
		expect(createMoltbookApiClientMock).not.toHaveBeenCalled();
	});

	it("heartbeat processes notifications and continues on errors", async () => {
		const client = {
			fetchNotifications: vi.fn().mockResolvedValue([
				{ id: "n1", postId: "post-1" },
				{ id: "n2", postId: "post-2" },
			]),
			postReply: vi.fn().mockResolvedValue({ ok: true, status: 200 }),
		};
		loadConfigMock.mockReturnValueOnce({ moltbook: { enabled: true } });
		createMoltbookApiClientMock.mockResolvedValue(client);
		executeRemoteQueryMock
			.mockImplementationOnce(() => {
				throw new Error("boom");
			})
			.mockImplementationOnce(() => mockStream("reply"));

		const res = await handler.handleMoltbookHeartbeat();
		expect(res.ok).toBe(true);
		expect(client.postReply).toHaveBeenCalledTimes(1);
	});

	it("heartbeat handles fetch failures", async () => {
		const client = {
			fetchNotifications: vi.fn().mockRejectedValue(new Error("fail")),
		};
		loadConfigMock.mockReturnValueOnce({ moltbook: { enabled: true } });
		createMoltbookApiClientMock.mockResolvedValue(client);

		const res = await handler.handleMoltbookHeartbeat();
		expect(res.ok).toBe(false);
		expect(res.message).toContain("failed to fetch");
	});

	it("heartbeat returns no notifications", async () => {
		const client = {
			fetchNotifications: vi.fn().mockResolvedValue([]),
		};
		loadConfigMock.mockReturnValueOnce({ moltbook: { enabled: true } });
		createMoltbookApiClientMock.mockResolvedValue(client);

		const res = await handler.handleMoltbookHeartbeat();
		expect(res.ok).toBe(true);
		expect(res.message).toContain("no notifications");
	});

	it("handleMoltbookNotification posts reply with trimmed response", async () => {
		const client = {
			postReply: vi.fn().mockResolvedValue({ ok: true, status: 200 }),
		};
		executeRemoteQueryMock.mockReturnValueOnce(mockStream(" hello "));

		const res = await handler.handleMoltbookNotification(
			{ id: "n1", postId: "post-1" },
			client as any,
			{ enabled: true } as any,
			"http://agent",
		);

		expect(res.ok).toBe(true);
		expect(client.postReply).toHaveBeenCalledWith("post-1", "hello");
		expect(executeRemoteQueryMock).toHaveBeenCalled();
		const [prompt, options] = executeRemoteQueryMock.mock.calls[0];
		expect(String(prompt)).toContain("MOLTBOOK NOTIFICATION");
		expect(options.tier).toBe("MOLTBOOK_SOCIAL");
		expect(options.scope).toBe("moltbook");
	});

	it("handleMoltbookNotification skips empty replies", async () => {
		const client = {
			postReply: vi.fn(),
		};
		executeRemoteQueryMock.mockReturnValueOnce(mockStream("   "));

		const res = await handler.handleMoltbookNotification(
			{ id: "n1", postId: "post-1" },
			client as any,
			{ enabled: true } as any,
			"http://agent",
		);

		expect(res.ok).toBe(true);
		expect(res.message).toContain("empty reply");
		expect(client.postReply).not.toHaveBeenCalled();
	});

	it("handleMoltbookNotification reports missing post id", async () => {
		const client = {
			postReply: vi.fn(),
		};
		const res = await handler.handleMoltbookNotification(
			{ id: "n1" },
			client as any,
			{ enabled: true } as any,
			"http://agent",
		);
		expect(res.ok).toBe(false);
		expect(res.message).toContain("missing post id");
	});

	it("handleMoltbookNotification surfaces agent failures", async () => {
		const client = {
			postReply: vi.fn(),
		};
		executeRemoteQueryMock.mockReturnValueOnce(mockStream("oops", false, "agent failed"));

		await expect(
			handler.handleMoltbookNotification(
				{ id: "n1", postId: "post-1" },
				client as any,
				{ enabled: true } as any,
				"http://agent",
			),
		).rejects.toThrow("agent failed");
	});

	it("handleMoltbookNotification returns error when postReply fails", async () => {
		const client = {
			postReply: vi.fn().mockResolvedValue({
				ok: false,
				status: 429,
				error: "rate limit",
				rateLimited: true,
			}),
		};
		executeRemoteQueryMock.mockReturnValueOnce(mockStream("reply"));

		const res = await handler.handleMoltbookNotification(
			{ id: "n1", postId: "post-1" },
			client as any,
			{ enabled: true } as any,
			"http://agent",
		);

		expect(res.ok).toBe(false);
		expect(res.message).toContain("rate limit");
	});
});
