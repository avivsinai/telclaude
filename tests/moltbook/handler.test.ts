import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const executeRemoteQueryMock = vi.hoisted(() => vi.fn());
const createMoltbookApiClientMock = vi.hoisted(() => vi.fn());
const loadConfigMock = vi.hoisted(() => vi.fn());
const getEntriesMock = vi.hoisted(() => vi.fn());
const markEntryPostedMock = vi.hoisted(() => vi.fn());
const checkLimitMock = vi.hoisted(() => vi.fn());
const consumeMock = vi.hoisted(() => vi.fn());

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
	markEntryPosted: (...args: unknown[]) => markEntryPostedMock(...args),
}));

vi.mock("../../src/services/multimedia-rate-limit.js", () => ({
	getMultimediaRateLimiter: () => ({
		checkLimit: (...args: unknown[]) => checkLimitMock(...args),
		consume: (...args: unknown[]) => consumeMock(...args),
	}),
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
		markEntryPostedMock.mockReset();
		checkLimitMock.mockReset();
		consumeMock.mockReset();
		getEntriesMock.mockReturnValue(sampleEntries);
		// Default: rate limit allows proactive posting
		checkLimitMock.mockReturnValue({ allowed: true, remaining: { hour: 1, day: 9 }, resetMs: { hour: 1000, day: 10000 } });
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

	it("heartbeat continues to proactive posting even when fetch fails", async () => {
		const client = {
			fetchNotifications: vi.fn().mockRejectedValue(new Error("fail")),
			createPost: vi.fn(),
		};
		loadConfigMock.mockReturnValueOnce({ moltbook: { enabled: true } });
		createMoltbookApiClientMock.mockResolvedValue(client);
		// No promoted ideas
		getEntriesMock.mockReturnValue([]);

		const res = await handler.handleMoltbookHeartbeat();
		// Now returns ok=true because it continues to proactive posting
		expect(res.ok).toBe(true);
		expect(res.message).toContain("no activity");
	});

	it("heartbeat returns no activity when no notifications and no ideas", async () => {
		const client = {
			fetchNotifications: vi.fn().mockResolvedValue([]),
			createPost: vi.fn(),
		};
		loadConfigMock.mockReturnValueOnce({ moltbook: { enabled: true } });
		createMoltbookApiClientMock.mockResolvedValue(client);
		// No promoted ideas
		getEntriesMock.mockReturnValue([]);

		const res = await handler.handleMoltbookHeartbeat();
		expect(res.ok).toBe(true);
		expect(res.message).toContain("no activity");
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

	it("heartbeat processes proactive posting after notifications", async () => {
		const promotedIdea = {
			id: "idea-1",
			category: "posts",
			content: "A great idea",
			_provenance: { source: "telegram", trust: "trusted", createdAt: 1, promotedAt: 2, promotedBy: "user" },
		};
		const client = {
			fetchNotifications: vi.fn().mockResolvedValue([]),
			createPost: vi.fn().mockResolvedValue({ ok: true, status: 201, postId: "new-post-1" }),
		};
		loadConfigMock.mockReturnValueOnce({ moltbook: { enabled: true } });
		createMoltbookApiClientMock.mockResolvedValue(client);

		// Proactive posting calls getEntries twice:
		// 1. getPromotedIdeas() - returns promoted ideas
		// 2. buildProactivePostPrompt() - returns identity entries
		getEntriesMock
			.mockReturnValueOnce([promotedIdea]) // getPromotedIdeas()
			.mockReturnValueOnce(sampleEntries); // buildProactivePostPrompt() for identity

		executeRemoteQueryMock.mockReturnValueOnce(mockStream("My new post content"));

		const res = await handler.handleMoltbookHeartbeat();

		expect(res.ok).toBe(true);
		expect(res.message).toContain("proactive post created");
		expect(client.createPost).toHaveBeenCalledWith("My new post content");
		expect(markEntryPostedMock).toHaveBeenCalledWith("idea-1");
		expect(consumeMock).toHaveBeenCalledWith("moltbook_post", "moltbook:proactive");
	});

	it("heartbeat skips proactive posting when rate limited", async () => {
		const client = {
			fetchNotifications: vi.fn().mockResolvedValue([]),
			createPost: vi.fn(),
		};
		loadConfigMock.mockReturnValueOnce({ moltbook: { enabled: true } });
		createMoltbookApiClientMock.mockResolvedValue(client);
		checkLimitMock.mockReturnValue({ allowed: false, remaining: { hour: 0, day: 0 }, reason: "Rate limited" });

		const res = await handler.handleMoltbookHeartbeat();

		expect(res.ok).toBe(true);
		expect(res.message).not.toContain("proactive post");
		expect(client.createPost).not.toHaveBeenCalled();
	});

	it("heartbeat skips proactive posting when no promoted ideas", async () => {
		const client = {
			fetchNotifications: vi.fn().mockResolvedValue([]),
			createPost: vi.fn(),
		};
		loadConfigMock.mockReturnValueOnce({ moltbook: { enabled: true } });
		createMoltbookApiClientMock.mockResolvedValue(client);

		// getPromotedIdeas() returns empty
		getEntriesMock.mockReturnValueOnce([]);

		const res = await handler.handleMoltbookHeartbeat();

		expect(res.ok).toBe(true);
		expect(res.message).not.toContain("proactive post");
		expect(client.createPost).not.toHaveBeenCalled();
	});

	it("heartbeat skips proactive posting when agent returns [SKIP]", async () => {
		const promotedIdea = {
			id: "idea-skip",
			category: "posts",
			content: "An idea to skip",
			_provenance: { source: "telegram", trust: "trusted", createdAt: 1, promotedAt: 2, promotedBy: "user" },
		};
		const client = {
			fetchNotifications: vi.fn().mockResolvedValue([]),
			createPost: vi.fn(),
		};
		loadConfigMock.mockReturnValueOnce({ moltbook: { enabled: true } });
		createMoltbookApiClientMock.mockResolvedValue(client);

		// Proactive posting: getPromotedIdeas() then buildProactivePostPrompt()
		getEntriesMock
			.mockReturnValueOnce([promotedIdea]) // getPromotedIdeas()
			.mockReturnValueOnce(sampleEntries); // buildProactivePostPrompt()

		executeRemoteQueryMock.mockReturnValueOnce(mockStream("[SKIP]"));

		const res = await handler.handleMoltbookHeartbeat();

		expect(res.ok).toBe(true);
		expect(res.message).not.toContain("proactive post created");
		expect(client.createPost).not.toHaveBeenCalled();
		expect(markEntryPostedMock).not.toHaveBeenCalled();
	});

	it("proactive posting uses minimal prompt without general memory", async () => {
		const promotedIdea = {
			id: "idea-minimal",
			category: "posts",
			content: "Only this idea should appear",
			_provenance: { source: "telegram", trust: "trusted", createdAt: 1, promotedAt: 2, promotedBy: "user" },
		};
		const client = {
			fetchNotifications: vi.fn().mockResolvedValue([]),
			createPost: vi.fn().mockResolvedValue({ ok: true, status: 201, postId: "new-post" }),
		};
		loadConfigMock.mockReturnValueOnce({ moltbook: { enabled: true } });
		createMoltbookApiClientMock.mockResolvedValue(client);

		// Proactive posting: getPromotedIdeas() then buildProactivePostPrompt()
		getEntriesMock
			.mockReturnValueOnce([promotedIdea]) // getPromotedIdeas()
			.mockReturnValueOnce(sampleEntries); // buildProactivePostPrompt()

		executeRemoteQueryMock.mockReturnValueOnce(mockStream("Post content"));

		await handler.handleMoltbookHeartbeat();

		// Verify the prompt contains only the approved idea
		expect(executeRemoteQueryMock).toHaveBeenCalled();
		const [prompt] = executeRemoteQueryMock.mock.calls[0];
		expect(String(prompt)).toContain("Only this idea should appear");
		expect(String(prompt)).toContain("APPROVED IDEA");
		expect(String(prompt)).toContain("PROACTIVE POST REQUEST");
	});
});
