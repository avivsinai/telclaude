import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const executeRemoteQueryMock = vi.hoisted(() => vi.fn());
const createEntriesMock = vi.hoisted(() => vi.fn());
const getEntriesMock = vi.hoisted(() => vi.fn());
const markEntryPostedMock = vi.hoisted(() => vi.fn());
const checkLimitMock = vi.hoisted(() => vi.fn());
const consumeMock = vi.hoisted(() => vi.fn());

vi.mock("../../src/agent/client.js", () => ({
	executeRemoteQuery: (...args: unknown[]) => executeRemoteQueryMock(...args),
}));

vi.mock("../../src/memory/store.js", () => ({
	createEntries: (...args: unknown[]) => createEntriesMock(...args),
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

vi.mock("../../src/telegram/admin-alert.js", () => ({
	sendAdminAlert: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../../src/telegram/notification-sanitizer.js", () => ({
	formatHeartbeatNotification: vi.fn().mockReturnValue("test notification"),
	sanitizeNotificationText: vi.fn().mockImplementation((text: string) => text),
	shouldNotifyOnHeartbeat: vi.fn().mockReturnValue(false),
}));

import type { SocialServiceClient } from "../../src/social/client.js";
import {
	handleSocialHeartbeat,
	handleSocialNotification,
	queryPublicPersona,
} from "../../src/social/handler.js";

const SERVICE_ID = "moltbook";

// Unified social memory: entries use source: "social" (not per-serviceId)
const sampleEntries = [
	{
		id: "profile-1",
		category: "profile",
		content: "Name: telclaude",
		_provenance: { source: "social", trust: "trusted", createdAt: 1 },
	},
];

async function* mockStream(
	text: string,
	success = true,
	error?: string,
	structuredOutput?: unknown,
) {
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
			...(structuredOutput !== undefined && { structuredOutput }),
		},
	} as const;
}

function mockClient(overrides: Partial<SocialServiceClient> = {}): SocialServiceClient {
	return {
		serviceId: SERVICE_ID,
		fetchNotifications: vi.fn().mockResolvedValue([]),
		postReply: vi.fn().mockResolvedValue({ ok: true, status: 200 }),
		createPost: vi.fn().mockResolvedValue({ ok: true, status: 201, postId: "new-post" }),
		...overrides,
	};
}

describe("social handler", () => {
	const originalAgentUrl = process.env.TELCLAUDE_SOCIAL_AGENT_URL;

	beforeEach(() => {
		executeRemoteQueryMock.mockReset();
		createEntriesMock.mockReset();
		getEntriesMock.mockReset();
		markEntryPostedMock.mockReset();
		checkLimitMock.mockReset();
		consumeMock.mockReset();
		getEntriesMock.mockReturnValue(sampleEntries);
		createEntriesMock.mockImplementation(
			(entries: Array<Record<string, unknown>>, source: string) =>
				entries.map((entry) => ({
					...entry,
					_provenance: { source, trust: "untrusted", createdAt: 1 },
				})),
		);
		// Default: rate limit allows proactive posting
		checkLimitMock.mockReturnValue({
			allowed: true,
			remaining: { hour: 1, day: 9 },
			resetMs: { hour: 1000, day: 10000 },
		});
		process.env.TELCLAUDE_SOCIAL_AGENT_URL = "http://agent-social:8789";
	});

	afterEach(() => {
		if (originalAgentUrl === undefined) {
			delete process.env.TELCLAUDE_SOCIAL_AGENT_URL;
		} else {
			process.env.TELCLAUDE_SOCIAL_AGENT_URL = originalAgentUrl;
		}
	});

	it("heartbeat processes notifications and continues on errors", async () => {
		const client = mockClient({
			fetchNotifications: vi.fn().mockResolvedValue([
				{ id: "n1", postId: "post-1" },
				{ id: "n2", postId: "post-2" },
			]),
		});
		executeRemoteQueryMock
			.mockImplementationOnce(() => {
				throw new Error("boom");
			})
			.mockImplementationOnce(() =>
				mockStream('{"action":"reply","body":"reply","rationale":"worth replying"}'),
			);

		const res = await handleSocialHeartbeat(SERVICE_ID, client);
		expect(res.ok).toBe(true);
		expect(client.postReply).toHaveBeenCalledTimes(1);
	});

	it("heartbeat continues to proactive posting even when fetch fails", async () => {
		const client = mockClient({
			fetchNotifications: vi.fn().mockRejectedValue(new Error("fail")),
		});
		// No promoted ideas; idle autonomous response
		getEntriesMock.mockReturnValue([]);
		executeRemoteQueryMock.mockReturnValue(mockStream("[IDLE]"));

		const res = await handleSocialHeartbeat(SERVICE_ID, client);
		expect(res.ok).toBe(true);
		expect(res.message).toContain("notification fetch failed");
	});

	it("heartbeat returns no activity when no notifications and no ideas", async () => {
		const client = mockClient();
		// No promoted ideas; idle autonomous response
		getEntriesMock.mockReturnValue([]);
		executeRemoteQueryMock.mockReturnValue(mockStream("[IDLE]"));

		const res = await handleSocialHeartbeat(SERVICE_ID, client);
		expect(res.ok).toBe(true);
		expect(res.message).toContain("no activity");
	});

	it("heartbeat executes autonomous reply for a visible timeline post", async () => {
		const client = mockClient({
			fetchTimeline: vi
				.fn()
				.mockResolvedValue([
					{ id: "post-42", text: "Tell me something sharp", authorHandle: "alice" },
				]),
		});
		getEntriesMock.mockReturnValueOnce([]).mockReturnValue(sampleEntries);
		executeRemoteQueryMock.mockReturnValueOnce(
			mockStream(
				'{"action":"reply","targetPostId":"post-42","body":"Here is the sharp reply.","rationale":"worth engaging"}',
			),
		);

		const res = await handleSocialHeartbeat(SERVICE_ID, client);

		expect(res.ok).toBe(true);
		expect(res.message).toContain("autonomous: replied to @alice");
		expect(client.postReply).toHaveBeenCalledWith("post-42", "Here is the sharp reply.");
		expect(createEntriesMock).not.toHaveBeenCalled();
		expect(consumeMock).toHaveBeenCalledWith("moltbook_reply", "social:moltbook:autonomous-reply");
		expect(consumeMock).toHaveBeenCalledWith(
			"moltbook_reply_target",
			"social:moltbook:target:post-42",
		);
	});

	it("heartbeat queues autonomous quote proposals with target metadata", async () => {
		const client = mockClient({
			serviceId: "xtwitter",
			fetchTimeline: vi.fn().mockResolvedValue([
				{
					id: "tweet-7",
					text: "This deserves a bigger response than a plain reply.",
					authorHandle: "writer",
				},
			]),
			quotePost: vi.fn(),
		});
		getEntriesMock.mockReturnValueOnce([]).mockReturnValue(sampleEntries);
		executeRemoteQueryMock.mockReturnValueOnce(
			mockStream(
				'{"action":"quote","targetPostId":"tweet-7","body":"Building on this: here is the quote take.","rationale":"broader audience"}',
			),
		);

		const res = await handleSocialHeartbeat("xtwitter", client);

		expect(res.ok).toBe(true);
		expect(res.message).toContain("autonomous: queued quote proposal");
		expect(createEntriesMock).toHaveBeenCalledTimes(1);
		expect(createEntriesMock).toHaveBeenCalledWith(
			expect.arrayContaining([
				expect.objectContaining({
					category: "posts",
					content: "Building on this: here is the quote take.",
					metadata: expect.objectContaining({
						action: "quote",
						targetPostId: "tweet-7",
						targetAuthor: "@writer",
						targetExcerpt: "This deserves a bigger response than a plain reply.",
					}),
				}),
			]),
			"social",
		);
		expect(client.postReply).not.toHaveBeenCalled();
	});

	it("handleSocialNotification posts reply with trimmed structured response", async () => {
		const client = mockClient();
		executeRemoteQueryMock.mockReturnValueOnce(
			mockStream('{"action":"reply","body":" hello ","rationale":"worth replying"}'),
		);

		const res = await handleSocialNotification(
			{ id: "n1", postId: "post-1" },
			SERVICE_ID,
			client,
			"http://agent",
		);

		expect(res.ok).toBe(true);
		expect(client.postReply).toHaveBeenCalledWith("post-1", "hello");
		expect(executeRemoteQueryMock).toHaveBeenCalled();
		const [prompt, options] = executeRemoteQueryMock.mock.calls[0];
		expect(String(prompt)).toContain("SOCIAL NOTIFICATION (MOLTBOOK)");
		expect(options.tier).toBe("SOCIAL");
		expect(options.scope).toBe("social");
	});

	it("handleSocialNotification ignores empty decisions", async () => {
		const client = mockClient();
		executeRemoteQueryMock.mockReturnValueOnce(mockStream("   "));

		const res = await handleSocialNotification(
			{ id: "n1", postId: "post-1" },
			SERVICE_ID,
			client,
			"http://agent",
		);

		expect(res.ok).toBe(true);
		expect(res.message).toContain("ignored");
		expect(client.postReply).not.toHaveBeenCalled();
	});

	it("handleSocialNotification ignores spam mentions when agent returns ignore", async () => {
		const client = mockClient();
		executeRemoteQueryMock.mockReturnValueOnce(
			mockStream('{"action":"ignore","rationale":"spam mention"}'),
		);

		const res = await handleSocialNotification(
			{ id: "n1", postId: "post-1" },
			SERVICE_ID,
			client,
			"http://agent",
		);

		expect(res.ok).toBe(true);
		expect(res.message).toContain("ignored");
		expect(client.postReply).not.toHaveBeenCalled();
	});

	it("handleSocialNotification ignores legacy plain-text refusal output", async () => {
		const client = mockClient();
		executeRemoteQueryMock.mockReturnValueOnce(
			mockStream("Spam mention - ignoring. No response warranted."),
		);

		const res = await handleSocialNotification(
			{ id: "n1", postId: "post-1" },
			SERVICE_ID,
			client,
			"http://agent",
		);

		expect(res.ok).toBe(true);
		expect(res.message).toContain("ignored");
		expect(client.postReply).not.toHaveBeenCalled();
	});

	it("handleSocialNotification reports missing post id", async () => {
		const client = mockClient();
		const res = await handleSocialNotification({ id: "n1" }, SERVICE_ID, client, "http://agent");
		expect(res.ok).toBe(false);
		expect(res.message).toContain("missing post id");
	});

	it("handleSocialNotification surfaces agent failures", async () => {
		const client = mockClient();
		executeRemoteQueryMock.mockReturnValueOnce(mockStream("oops", false, "agent failed"));

		await expect(
			handleSocialNotification({ id: "n1", postId: "post-1" }, SERVICE_ID, client, "http://agent"),
		).rejects.toThrow("agent failed");
	});

	it("handleSocialNotification returns error when postReply fails", async () => {
		const client = mockClient({
			postReply: vi.fn().mockResolvedValue({
				ok: false,
				status: 429,
				error: "rate limit",
				rateLimited: true,
			}),
		});
		executeRemoteQueryMock.mockReturnValueOnce(
			mockStream('{"action":"reply","body":"reply","rationale":"worth replying"}'),
		);

		const res = await handleSocialNotification(
			{ id: "n1", postId: "post-1" },
			SERVICE_ID,
			client,
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
			_provenance: {
				source: "telegram",
				trust: "trusted",
				createdAt: 1,
				promotedAt: 2,
				promotedBy: "user",
			},
		};
		const client = mockClient();

		// Proactive posting calls getEntries multiple times:
		// 1. getPromotedIdeas() - returns promoted ideas
		// 2. buildProactivePostPrompt() - returns identity entries (social source)
		getEntriesMock
			.mockReturnValueOnce([promotedIdea]) // getPromotedIdeas()
			.mockReturnValueOnce(sampleEntries); // buildProactivePostPrompt() for identity

		executeRemoteQueryMock.mockReturnValueOnce(
			mockStream("", true, undefined, { action: "post", content: "My new post content" }),
		);

		const res = await handleSocialHeartbeat(SERVICE_ID, client);

		expect(res.ok).toBe(true);
		expect(res.message).toContain("proactive post created");
		expect(client.createPost).toHaveBeenCalledWith("My new post content");
		expect(markEntryPostedMock).toHaveBeenCalledWith("idea-1");
		expect(consumeMock).toHaveBeenCalledWith("moltbook_post", "social:moltbook:proactive");
	});

	it("heartbeat skips proactive posting when rate limited", async () => {
		const client = mockClient();
		checkLimitMock.mockReturnValue({
			allowed: false,
			remaining: { hour: 0, day: 0 },
			reason: "Rate limited",
		});

		const res = await handleSocialHeartbeat(SERVICE_ID, client);

		expect(res.ok).toBe(true);
		expect(res.message).not.toContain("proactive post");
		expect(client.createPost).not.toHaveBeenCalled();
	});

	it("heartbeat skips proactive posting when no promoted ideas", async () => {
		const client = mockClient();

		// getPromotedIdeas() returns empty
		getEntriesMock.mockReturnValueOnce([]);

		const res = await handleSocialHeartbeat(SERVICE_ID, client);

		expect(res.ok).toBe(true);
		expect(res.message).not.toContain("proactive post");
		expect(client.createPost).not.toHaveBeenCalled();
	});

	it("heartbeat skips proactive posting when agent returns [SKIP]", async () => {
		const promotedIdea = {
			id: "idea-skip",
			category: "posts",
			content: "An idea to skip",
			_provenance: {
				source: "telegram",
				trust: "trusted",
				createdAt: 1,
				promotedAt: 2,
				promotedBy: "user",
			},
		};
		const client = mockClient();

		// Proactive posting: getPromotedIdeas() then buildProactivePostPrompt()
		getEntriesMock
			.mockReturnValueOnce([promotedIdea]) // getPromotedIdeas()
			.mockReturnValueOnce(sampleEntries); // buildProactivePostPrompt()

		executeRemoteQueryMock.mockReturnValueOnce(
			mockStream("", true, undefined, { action: "skip", reason: "not relevant" }),
		);

		const res = await handleSocialHeartbeat(SERVICE_ID, client);

		expect(res.ok).toBe(true);
		expect(res.message).not.toContain("proactive post created");
		expect(client.createPost).not.toHaveBeenCalled();
		expect(markEntryPostedMock).not.toHaveBeenCalled();
	});

	it("queryPublicPersona enables skills for trusted operator queries", async () => {
		executeRemoteQueryMock.mockReturnValueOnce(mockStream("timeline looks good"));

		await queryPublicPersona("what's on your X timeline?", SERVICE_ID);

		expect(executeRemoteQueryMock).toHaveBeenCalledTimes(1);
		const [, options] = executeRemoteQueryMock.mock.calls[0];
		expect(options.enableSkills).toBe(true);
		expect(options.poolKey).toBe(`${SERVICE_ID}:operator-query`);
	});

	it("heartbeat handles thread action and posts via createThread", async () => {
		const promotedIdea = {
			id: "idea-thread",
			category: "posts",
			content: "A deep thread idea",
			_provenance: {
				source: "telegram",
				trust: "trusted",
				createdAt: 1,
				promotedAt: 2,
				promotedBy: "user",
			},
		};
		const createThreadMock = vi.fn().mockResolvedValue({
			ok: true,
			status: 201,
			postId: "thread-first",
			tweetIds: ["thread-first", "thread-second", "thread-third"],
		});
		const client = Object.assign(mockClient(), { createThread: createThreadMock });

		getEntriesMock.mockReturnValueOnce([promotedIdea]).mockReturnValueOnce(sampleEntries);

		executeRemoteQueryMock.mockReturnValueOnce(
			mockStream("", true, undefined, {
				action: "thread",
				tweets: ["Hook tweet", "Body tweet", "CTA tweet"],
			}),
		);

		const res = await handleSocialHeartbeat(SERVICE_ID, client);

		expect(res.ok).toBe(true);
		expect(res.message).toContain("proactive post created");
		expect(createThreadMock).toHaveBeenCalledWith(["Hook tweet", "Body tweet", "CTA tweet"]);
		expect(markEntryPostedMock).toHaveBeenCalledWith("idea-thread");
		expect(consumeMock).toHaveBeenCalled();
	});

	it("heartbeat publishes promoted quote ideas via quotePost", async () => {
		const promotedIdea = {
			id: "idea-quote",
			category: "posts",
			content: "The approved quote body",
			metadata: {
				action: "quote",
				targetPostId: "tweet-99",
				targetAuthor: "@writer",
				targetExcerpt: "Target post excerpt",
			},
			_provenance: {
				source: "social",
				trust: "trusted",
				createdAt: 1,
				promotedAt: 2,
				promotedBy: "user",
			},
		};
		const quotePostMock = vi.fn().mockResolvedValue({
			ok: true,
			status: 201,
			postId: "quote-1",
		});
		const client = mockClient({
			quotePost: quotePostMock,
		});

		getEntriesMock.mockReturnValueOnce([promotedIdea]).mockReturnValue(sampleEntries);
		executeRemoteQueryMock.mockReturnValueOnce(mockStream('{"action":"idle","rationale":"done"}'));

		const res = await handleSocialHeartbeat(SERVICE_ID, client);

		expect(res.ok).toBe(true);
		expect(res.message).toContain("proactive post created");
		expect(quotePostMock).toHaveBeenCalledWith("tweet-99", "The approved quote body");
		expect(client.createPost).not.toHaveBeenCalled();
		expect(markEntryPostedMock).toHaveBeenCalledWith("idea-quote");
		expect(consumeMock).toHaveBeenCalledWith("moltbook_post", "social:moltbook:proactive");
	});

	it("heartbeat returns unsupported for thread on non-X backends", async () => {
		const promotedIdea = {
			id: "idea-nothread",
			category: "posts",
			content: "Thread on moltbook?",
			_provenance: {
				source: "telegram",
				trust: "trusted",
				createdAt: 1,
				promotedAt: 2,
				promotedBy: "user",
			},
		};
		const client = mockClient(); // moltbook client — no createThread method

		getEntriesMock.mockReturnValueOnce([promotedIdea]).mockReturnValueOnce(sampleEntries);

		executeRemoteQueryMock.mockReturnValueOnce(
			mockStream("", true, undefined, {
				action: "thread",
				tweets: ["Tweet 1", "Tweet 2"],
			}),
		);

		const res = await handleSocialHeartbeat(SERVICE_ID, client);

		// Thread on moltbook should fail (no createThread), idea not marked as posted
		expect(res.ok).toBe(true);
		expect(res.message).not.toContain("thread");
		expect(client.createPost).not.toHaveBeenCalled();
	});

	it("heartbeat skips thread with insufficient tweets", async () => {
		const promotedIdea = {
			id: "idea-short",
			category: "posts",
			content: "Too short for thread",
			_provenance: {
				source: "telegram",
				trust: "trusted",
				createdAt: 1,
				promotedAt: 2,
				promotedBy: "user",
			},
		};
		const client = mockClient();

		getEntriesMock.mockReturnValueOnce([promotedIdea]).mockReturnValueOnce(sampleEntries);

		executeRemoteQueryMock.mockReturnValueOnce(
			mockStream("", true, undefined, {
				action: "thread",
				tweets: ["Only one tweet"],
			}),
		);

		const res = await handleSocialHeartbeat(SERVICE_ID, client);

		expect(res.ok).toBe(true);
		expect(res.message).not.toContain("thread");
		expect(markEntryPostedMock).not.toHaveBeenCalled();
	});

	it("heartbeat marks partial thread as posted to prevent duplicates", async () => {
		const promotedIdea = {
			id: "idea-partial",
			category: "posts",
			content: "Partial failure",
			_provenance: {
				source: "telegram",
				trust: "trusted",
				createdAt: 1,
				promotedAt: 2,
				promotedBy: "user",
			},
		};
		const createThreadMock = vi.fn().mockResolvedValue({
			ok: false,
			status: 403,
			error: "thread failed at tweet 2/3",
			postId: "partial-first", // first tweet was posted
			tweetIds: ["partial-first"],
		});
		const client = Object.assign(mockClient(), { createThread: createThreadMock });

		getEntriesMock.mockReturnValueOnce([promotedIdea]).mockReturnValueOnce(sampleEntries);

		executeRemoteQueryMock.mockReturnValueOnce(
			mockStream("", true, undefined, {
				action: "thread",
				tweets: ["Hook", "Body", "CTA"],
			}),
		);

		const res = await handleSocialHeartbeat(SERVICE_ID, client);

		expect(res.ok).toBe(true);
		// Partial thread: still marked as posted to prevent duplicates
		expect(markEntryPostedMock).toHaveBeenCalledWith("idea-partial");
		expect(res.ok).toBe(true);
		expect(res.message).toContain("proactive post created");
	});

	it("heartbeat passes allowedSkills from serviceConfig to proactive and autonomous queries", async () => {
		const promotedIdea = {
			id: "idea-skills",
			category: "posts",
			content: "Test allowedSkills threading",
			_provenance: {
				source: "telegram",
				trust: "trusted",
				createdAt: 1,
				promotedAt: 2,
				promotedBy: "user",
			},
		};
		const client = mockClient();

		getEntriesMock.mockReturnValueOnce([promotedIdea]).mockReturnValueOnce(sampleEntries);

		executeRemoteQueryMock
			// proactive query
			.mockReturnValueOnce(
				mockStream("", true, undefined, { action: "post", content: "Skills test" }),
			)
			// autonomous query
			.mockReturnValueOnce(mockStream("[IDLE]"));

		await handleSocialHeartbeat(SERVICE_ID, client, {
			id: SERVICE_ID,
			type: "test",
			enabled: true,
			heartbeatIntervalHours: 6,
			enableSkills: true,
			allowedSkills: ["memory", "summarize", "social-posting"],
			notifyOnHeartbeat: "never",
		});

		// Verify proactive query received allowedSkills
		const proactiveCall = executeRemoteQueryMock.mock.calls[0];
		expect(proactiveCall[1].allowedSkills).toEqual(["memory", "summarize", "social-posting"]);

		// Verify autonomous query received allowedSkills
		const autonomousCall = executeRemoteQueryMock.mock.calls[1];
		expect(autonomousCall[1].allowedSkills).toEqual(["memory", "summarize", "social-posting"]);
	});

	it("queryPublicPersona passes allowedSkills from serviceConfig", async () => {
		executeRemoteQueryMock.mockReturnValueOnce(mockStream("response with skills"));

		await queryPublicPersona("test?", SERVICE_ID, {
			id: SERVICE_ID,
			type: "test",
			enabled: true,
			heartbeatIntervalHours: 6,
			enableSkills: true,
			allowedSkills: ["memory", "summarize"],
			notifyOnHeartbeat: "never",
		});

		const [, options] = executeRemoteQueryMock.mock.calls[0];
		expect(options.allowedSkills).toEqual(["memory", "summarize"]);
	});

	it("proactive posting uses minimal prompt without general memory", async () => {
		const promotedIdea = {
			id: "idea-minimal",
			category: "posts",
			content: "Only this idea should appear",
			_provenance: {
				source: "telegram",
				trust: "trusted",
				createdAt: 1,
				promotedAt: 2,
				promotedBy: "user",
			},
		};
		const client = mockClient();

		// Proactive posting: getPromotedIdeas() then buildProactivePostPrompt()
		getEntriesMock
			.mockReturnValueOnce([promotedIdea]) // getPromotedIdeas()
			.mockReturnValueOnce(sampleEntries); // buildProactivePostPrompt()

		executeRemoteQueryMock.mockReturnValueOnce(
			mockStream("", true, undefined, { action: "post", content: "Post content" }),
		);

		await handleSocialHeartbeat(SERVICE_ID, client);

		// Verify the prompt contains only the approved idea
		expect(executeRemoteQueryMock).toHaveBeenCalled();
		const [prompt] = executeRemoteQueryMock.mock.calls[0];
		expect(String(prompt)).toContain("Only this idea should appear");
		expect(String(prompt)).toContain("APPROVED IDEA");
		expect(String(prompt)).toContain("PROACTIVE POST REQUEST");
	});
});
