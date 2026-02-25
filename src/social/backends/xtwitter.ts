import type { SocialServiceConfig } from "../../config/config.js";
import { getChildLogger } from "../../logging.js";
import type { SocialServiceClient } from "../client.js";
import type {
	SocialNotification,
	SocialPostResult,
	SocialReplyResult,
	SocialTimelinePost,
} from "../types.js";

const logger = getChildLogger({ module: "xtwitter-backend" });

const X_TWEET_MAX_LENGTH = 280;

/**
 * Truncate text to fit within X's character limit.
 * Uses code-point-safe slicing (Array.from) to avoid splitting surrogate pairs.
 * Prefers word boundaries to avoid cutting mid-word.
 */
function truncateForX(text: string): string {
	const codePoints = Array.from(text);
	if (codePoints.length <= X_TWEET_MAX_LENGTH) return text;
	logger.warn(
		{ length: codePoints.length, max: X_TWEET_MAX_LENGTH },
		"tweet exceeded char limit, truncating",
	);
	const cut = codePoints.slice(0, X_TWEET_MAX_LENGTH - 1).join(""); // leave room for ellipsis
	const lastSpace = cut.lastIndexOf(" ");
	const breakpoint = lastSpace > X_TWEET_MAX_LENGTH * 0.6 ? lastSpace : cut.length;
	return `${cut.slice(0, breakpoint)}…`;
}

/**
 * X/Twitter API v2 response shapes.
 */
type XMention = {
	id: string;
	text: string;
	author_id?: string;
	created_at?: string;
	in_reply_to_user_id?: string;
	conversation_id?: string;
};

type XMentionsResponse = {
	data?: XMention[];
	meta?: { newest_id?: string; oldest_id?: string; result_count?: number };
};

type XTweetResponse = {
	data?: { id: string; text: string };
	errors?: Array<{ message: string; type: string }>;
};

type XTimelineTweet = {
	id: string;
	text: string;
	author_id?: string;
	created_at?: string;
	public_metrics?: {
		like_count?: number;
		retweet_count?: number;
		reply_count?: number;
	};
};

type XTimelineResponse = {
	data?: XTimelineTweet[];
	includes?: { users?: Array<{ id: string; name: string; username: string }> };
	meta?: { newest_id?: string; oldest_id?: string; result_count?: number };
};

type XApiResult<T> =
	| { ok: true; status: number; data: T }
	| { ok: false; status: number; error: string };

/**
 * Resolve the base URL for X API calls.
 * In production: routed through the vault credential proxy (http://relay:8792/api.x.com).
 * In dev/testing: direct API access with bearer token.
 */
function getApiBase(): string {
	// Vault proxy pattern: http://relay:8792/api.x.com/2/...
	const proxyBase = process.env.TELCLAUDE_X_PROXY_URL;
	if (proxyBase) {
		return proxyBase.replace(/\/+$/, "");
	}
	// Direct API (for testing or when vault injects auth)
	return process.env.X_API_BASE ?? "https://api.x.com";
}

function safeJsonParse(input: string): unknown {
	try {
		return JSON.parse(input);
	} catch {
		return null;
	}
}

function normalizeMention(mention: XMention): SocialNotification {
	return {
		id: mention.id,
		type: "mention",
		postId: mention.conversation_id ?? mention.id,
		post: {
			id: mention.id,
			content: mention.text,
			author: mention.author_id ? { handle: mention.author_id } : undefined,
		},
		content: mention.text,
		createdAt: mention.created_at,
	};
}

/**
 * X/Twitter API v2 client implementing SocialServiceClient.
 *
 * Auth: handled by the vault credential proxy — agent calls
 * http://relay:8792/api.x.com/2/tweets and the proxy injects OAuth2 bearer.
 * The agent NEVER sees raw credentials.
 */
export class XTwitterClient implements SocialServiceClient {
	readonly serviceId = "xtwitter";
	private readonly userId: string;
	private readonly baseUrl: string;
	private readonly fetchImpl: typeof fetch;
	private readonly bearerToken?: string;

	constructor(options: {
		userId: string;
		baseUrl?: string;
		bearerToken?: string;
		fetchImpl?: typeof fetch;
	}) {
		this.userId = options.userId;
		this.baseUrl = (options.baseUrl ?? getApiBase()).replace(/\/+$/, "");
		this.bearerToken = options.bearerToken;
		this.fetchImpl = options.fetchImpl ?? fetch;
	}

	private async request<T>(path: string, init: RequestInit): Promise<XApiResult<T>> {
		const url = `${this.baseUrl}${path}`;
		const headers = new Headers(init.headers ?? {});
		// Bearer token only needed for direct API access (not when using vault proxy)
		if (this.bearerToken) {
			headers.set("Authorization", `Bearer ${this.bearerToken}`);
		}
		if (!headers.has("Content-Type")) {
			headers.set("Content-Type", "application/json");
		}

		const response = await this.fetchImpl(url, { ...init, headers });
		const status = response.status;
		const raw = await response.text();
		const payload = raw ? safeJsonParse(raw) : null;

		if (!response.ok) {
			const error =
				(payload && typeof payload === "object" && "errors" in payload
					? JSON.stringify((payload as { errors?: unknown[] }).errors?.slice(0, 2) ?? "unknown")
					: raw) || response.statusText;
			return { ok: false, status, error };
		}

		return { ok: true, status, data: payload as T };
	}

	async fetchNotifications(): Promise<SocialNotification[]> {
		const result = await this.request<XMentionsResponse>(
			`/2/users/${encodeURIComponent(this.userId)}/mentions`,
			{ method: "GET" },
		);

		if (!result.ok) {
			if (result.status === 429) {
				logger.warn("X mentions rate limited; skipping this heartbeat");
				return [];
			}
			// Free tier: mentions endpoint returns 402 (credits) or 403 (not authorized)
			if (result.status === 402 || result.status === 403) {
				logger.info(
					{ status: result.status },
					"X mentions not available on current tier; skipping",
				);
				return [];
			}
			throw new Error(`X mentions failed (${result.status}): ${result.error}`);
		}

		const mentions = result.data?.data;
		if (!mentions || !Array.isArray(mentions)) {
			return [];
		}

		return mentions.map(normalizeMention);
	}

	async postReply(postId: string, body: string): Promise<SocialReplyResult> {
		const truncated = truncateForX(body);
		const result = await this.request<XTweetResponse>("/2/tweets", {
			method: "POST",
			body: JSON.stringify({
				text: truncated,
				reply: { in_reply_to_tweet_id: postId },
			}),
		});

		if (!result.ok) {
			if (result.status === 429) {
				logger.warn("X reply rate limited");
				return { ok: false, status: result.status, error: result.error, rateLimited: true };
			}
			return { ok: false, status: result.status, error: result.error };
		}

		return { ok: true, status: result.status };
	}

	async createPost(
		content: string,
		_options?: { title?: string; tags?: string[] },
	): Promise<SocialPostResult> {
		const truncated = truncateForX(content);
		const result = await this.request<XTweetResponse>("/2/tweets", {
			method: "POST",
			body: JSON.stringify({ text: truncated }),
		});

		if (!result.ok) {
			if (result.status === 429) {
				logger.warn("X post rate limited");
				return { ok: false, status: result.status, error: result.error, rateLimited: true };
			}
			return { ok: false, status: result.status, error: result.error };
		}

		const tweetId = result.data?.data?.id;
		return { ok: true, status: result.status, postId: tweetId };
	}

	/**
	 * Post a thread (reply-to-self chain).
	 * First tweet is standalone; subsequent tweets reply to the previous one.
	 * Returns the first tweet's ID as the thread ID, plus all individual tweet IDs.
	 */
	async createThread(tweets: string[]): Promise<SocialPostResult & { tweetIds?: string[] }> {
		if (tweets.length === 0) {
			return { ok: false, status: 400, error: "empty thread" };
		}
		if (tweets.length === 1) {
			// Single tweet — just use createPost
			return this.createPost(tweets[0]);
		}

		const tweetIds: string[] = [];

		for (let i = 0; i < tweets.length; i++) {
			const text = truncateForX(tweets[i]);
			const body: Record<string, unknown> = { text };

			if (i > 0) {
				// Chain: reply to the previous tweet in the thread
				body.reply = { in_reply_to_tweet_id: tweetIds[i - 1] };
			}

			const result = await this.request<XTweetResponse>("/2/tweets", {
				method: "POST",
				body: JSON.stringify(body),
			});

			if (!result.ok) {
				if (result.status === 429) {
					logger.warn(
						{ tweetIndex: i, totalTweets: tweets.length },
						"X thread rate limited mid-chain",
					);
					return {
						ok: false,
						status: result.status,
						error: result.error,
						rateLimited: true,
						postId: tweetIds[0],
						tweetIds,
					};
				}
				logger.error(
					{ tweetIndex: i, totalTweets: tweets.length, error: result.error },
					"X thread failed mid-chain",
				);
				return {
					ok: false,
					status: result.status,
					error: `thread failed at tweet ${i + 1}/${tweets.length}: ${result.error}`,
					postId: tweetIds[0],
					tweetIds,
				};
			}

			const tweetId = result.data?.data?.id;
			if (!tweetId) {
				logger.error(
					{ tweetIndex: i, totalTweets: tweets.length },
					"X API returned ok but no tweet ID — cannot continue thread chain",
				);
				return {
					ok: false,
					status: 502,
					error: `thread failed at tweet ${i + 1}/${tweets.length}: missing tweet ID in response`,
					postId: tweetIds[0],
					tweetIds,
				};
			}
			tweetIds.push(tweetId);

			// Small delay between tweets to respect rate limits and ensure ordering
			if (i < tweets.length - 1) {
				await new Promise((resolve) => setTimeout(resolve, 1500));
			}
		}

		logger.info(
			{ threadLength: tweets.length, firstTweetId: tweetIds[0] },
			"X thread posted successfully",
		);

		return {
			ok: true,
			status: 201,
			postId: tweetIds[0],
			tweetIds,
		};
	}

	async fetchTimeline(options?: { maxResults?: number }): Promise<SocialTimelinePost[]> {
		const maxResults = Math.min(Math.max(options?.maxResults ?? 10, 1), 100);
		const params = new URLSearchParams({
			max_results: String(maxResults),
			"tweet.fields": "created_at,public_metrics",
			expansions: "author_id",
			"user.fields": "name,username",
		});

		const result = await this.request<XTimelineResponse>(
			`/2/users/${encodeURIComponent(this.userId)}/timelines/reverse_chronological?${params}`,
			{ method: "GET" },
		);

		if (!result.ok) {
			if (result.status === 429 || result.status === 402 || result.status === 403) {
				logger.info({ status: result.status }, "X timeline not available; returning empty");
				return [];
			}
			throw new Error(`X timeline failed (${result.status}): ${result.error}`);
		}

		const tweets = result.data?.data;
		if (!tweets || !Array.isArray(tweets)) {
			return [];
		}

		// Build author lookup from includes.users expansion
		const userMap = new Map<string, { name: string; username: string }>();
		for (const user of result.data?.includes?.users ?? []) {
			userMap.set(user.id, { name: user.name, username: user.username });
		}

		return tweets.map((tweet): SocialTimelinePost => {
			const author = tweet.author_id ? userMap.get(tweet.author_id) : undefined;
			return {
				id: tweet.id,
				text: tweet.text,
				authorName: author?.name,
				authorHandle: author?.username,
				createdAt: tweet.created_at,
				metrics: tweet.public_metrics
					? {
							likes: tweet.public_metrics.like_count,
							retweets: tweet.public_metrics.retweet_count,
							replies: tweet.public_metrics.reply_count,
						}
					: undefined,
			};
		});
	}
}

/**
 * Create an X/Twitter client from a social service config entry.
 * Returns null if the X user ID is not configured.
 */
export async function createXTwitterClient(
	_config: Pick<SocialServiceConfig, "apiKey">,
): Promise<SocialServiceClient | null> {
	const userId = process.env.X_USER_ID;
	if (!userId) {
		logger.warn("X_USER_ID not set — X/Twitter client disabled");
		return null;
	}

	// Bearer token is optional — when using vault proxy, auth is injected transparently
	const bearerToken = process.env.X_BEARER_TOKEN;

	return new XTwitterClient({ userId, bearerToken, baseUrl: getApiBase() });
}
