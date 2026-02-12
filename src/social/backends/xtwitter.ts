import type { SocialServiceConfig } from "../../config/config.js";
import { getChildLogger } from "../../logging.js";
import type { SocialServiceClient } from "../client.js";
import type { SocialNotification, SocialPostResult, SocialReplyResult } from "../types.js";

const logger = getChildLogger({ module: "xtwitter-backend" });

const X_TWEET_MAX_LENGTH = 280;

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
		const truncated = body.slice(0, X_TWEET_MAX_LENGTH);
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
		const truncated = content.slice(0, X_TWEET_MAX_LENGTH);
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
