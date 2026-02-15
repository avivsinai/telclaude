import type { SocialServiceConfig } from "../../config/config.js";
import { getChildLogger } from "../../logging.js";
import { getSecret, SECRET_KEYS } from "../../secrets/index.js";
import type { SocialServiceClient } from "../client.js";
import type { SocialNotification, SocialPostResult, SocialReplyResult } from "../types.js";

const logger = getChildLogger({ module: "moltbook-backend" });

const DEFAULT_API_BASE = "https://moltbook.com/api/v1";

/**
 * Moltbook-specific notification shape (handles both camelCase and snake_case).
 */
type MoltbookNotification = {
	id: string;
	type?: string;
	postId?: string;
	post_id?: string;
	post?: {
		id?: string;
		content?: string;
		author?: { name?: string; handle?: string };
	};
	comment?: {
		id?: string;
		postId?: string;
		post_id?: string;
		post?: { id?: string };
		content?: string;
		author?: { name?: string; handle?: string };
	};
	actor?: { name?: string; handle?: string };
	message?: string;
	content?: string;
	createdAt?: string;
	created_at?: string;
};

type MoltbookNotificationEnvelope =
	| MoltbookNotification[]
	| { notifications?: MoltbookNotification[] }
	| { data?: MoltbookNotification[] };

type MoltbookApiResult<T> =
	| { ok: true; status: number; data: T }
	| { ok: false; status: number; error: string };

function getApiBase(): string {
	const base = process.env.MOLTBOOK_API_BASE || DEFAULT_API_BASE;
	return base.replace(/\/+$/, "");
}

async function resolveApiKey(config: Pick<SocialServiceConfig, "apiKey">): Promise<string | null> {
	try {
		const stored = await getSecret(SECRET_KEYS.MOLTBOOK_API_KEY);
		if (stored) {
			logger.debug("using Moltbook API key from secrets store");
			return stored;
		}
	} catch (err) {
		logger.debug({ error: String(err) }, "unable to access secrets store for Moltbook API key");
	}

	if (config.apiKey) {
		logger.debug("using Moltbook API key from config");
		return config.apiKey;
	}

	return null;
}

function safeJsonParse(input: string): unknown {
	try {
		return JSON.parse(input);
	} catch {
		return null;
	}
}

/**
 * Normalize Moltbook notification to generic SocialNotification.
 * Resolves snake_case / camelCase field aliases.
 */
function normalizeMoltbookNotification(n: MoltbookNotification): SocialNotification {
	return {
		id: n.id,
		type: n.type,
		postId: n.postId ?? n.post_id,
		post: n.post,
		comment: n.comment
			? {
					id: n.comment.id,
					postId: n.comment.postId ?? n.comment.post_id ?? n.comment.post?.id,
					content: n.comment.content,
					author: n.comment.author,
				}
			: undefined,
		actor: n.actor,
		message: n.message,
		content: n.content,
		createdAt: n.createdAt ?? n.created_at,
	};
}

/**
 * Moltbook API client implementing the generic SocialServiceClient interface.
 */
export class MoltbookClient implements SocialServiceClient {
	readonly serviceId = "moltbook";
	private readonly apiKey: string;
	private readonly baseUrl: string;
	private readonly fetchImpl: typeof fetch;

	constructor(options: { apiKey: string; baseUrl?: string; fetchImpl?: typeof fetch }) {
		this.apiKey = options.apiKey;
		this.baseUrl = (options.baseUrl ?? getApiBase()).replace(/\/+$/, "");
		this.fetchImpl = options.fetchImpl ?? fetch;
	}

	private async request<T>(path: string, init: RequestInit): Promise<MoltbookApiResult<T>> {
		const url = `${this.baseUrl}${path}`;
		const headers = new Headers(init.headers ?? {});
		headers.set("Authorization", `Bearer ${this.apiKey}`);
		if (!headers.has("Content-Type")) {
			headers.set("Content-Type", "application/json");
		}

		const response = await this.fetchImpl(url, { ...init, headers });
		const status = response.status;
		const raw = await response.text();
		const payload = raw ? safeJsonParse(raw) : null;

		if (!response.ok) {
			const error =
				(payload && typeof payload === "object" && "error" in payload
					? String((payload as { error?: unknown }).error)
					: raw) || response.statusText;
			return { ok: false, status, error };
		}

		return { ok: true, status, data: payload as T };
	}

	async fetchNotifications(): Promise<SocialNotification[]> {
		const result = await this.request<MoltbookNotificationEnvelope>("/notifications", {
			method: "GET",
		});

		if (!result.ok) {
			if (result.status === 429) {
				logger.warn("moltbook notifications rate limited; skipping this heartbeat");
				return [];
			}
			throw new Error(`Moltbook notifications failed (${result.status}): ${result.error}`);
		}

		const payload = result.data;
		let raw: MoltbookNotification[];
		if (Array.isArray(payload)) {
			raw = payload;
		} else if (payload && "notifications" in payload && Array.isArray(payload.notifications)) {
			raw = payload.notifications;
		} else if (payload && "data" in payload && Array.isArray(payload.data)) {
			raw = payload.data;
		} else {
			logger.warn("moltbook notifications response format not recognized");
			return [];
		}

		return raw.map(normalizeMoltbookNotification);
	}

	async postReply(postId: string, body: string): Promise<SocialReplyResult> {
		const result = await this.request<Record<string, unknown>>(
			`/posts/${encodeURIComponent(postId)}/comments`,
			{
				method: "POST",
				body: JSON.stringify({ body }),
			},
		);

		if (!result.ok) {
			if (result.status === 429) {
				logger.warn("moltbook reply rate limited; skipping reply");
				return { ok: false, status: result.status, error: result.error, rateLimited: true };
			}
			return { ok: false, status: result.status, error: result.error };
		}

		return { ok: true, status: result.status };
	}

	async createPost(
		content: string,
		options?: { title?: string; tags?: string[] },
	): Promise<SocialPostResult> {
		const payload: Record<string, unknown> = { content };
		if (options?.title) {
			payload.title = options.title;
		}
		if (options?.tags && options.tags.length > 0) {
			payload.tags = options.tags;
		}

		const result = await this.request<{ id?: string; post_id?: string }>("/posts", {
			method: "POST",
			body: JSON.stringify(payload),
		});

		if (!result.ok) {
			if (result.status === 429) {
				logger.warn("moltbook post rate limited");
				return { ok: false, status: result.status, error: result.error, rateLimited: true };
			}
			return { ok: false, status: result.status, error: result.error };
		}

		const id = result.data?.id ?? result.data?.post_id;
		return { ok: true, status: result.status, postId: id ? String(id) : undefined };
	}
}

/**
 * Create a Moltbook client from a social service config entry.
 * Returns null if the API key is not configured.
 */
export async function createMoltbookClient(
	config: Pick<SocialServiceConfig, "apiKey">,
): Promise<SocialServiceClient | null> {
	const apiKey = await resolveApiKey(config);
	if (!apiKey) {
		return null;
	}
	return new MoltbookClient({ apiKey, baseUrl: getApiBase() });
}
