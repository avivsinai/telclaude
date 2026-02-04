import { loadConfig, type MoltbookConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { getSecret, SECRET_KEYS } from "../secrets/index.js";

const logger = getChildLogger({ module: "moltbook-api-client" });

const DEFAULT_API_BASE = "https://moltbook.com/api/v1";

export type MoltbookNotification = {
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

export type MoltbookReplyResult = {
	ok: boolean;
	status: number;
	error?: string;
	rateLimited?: boolean;
};

export type MoltbookPostResult = {
	ok: boolean;
	status: number;
	postId?: string;
	error?: string;
	rateLimited?: boolean;
};

type MoltbookApiResult<T> =
	| { ok: true; status: number; data: T }
	| { ok: false; status: number; error: string };

function getApiBase(): string {
	const base = process.env.MOLTBOOK_API_BASE || DEFAULT_API_BASE;
	return base.replace(/\/+$/, "");
}

async function resolveApiKey(config: MoltbookConfig): Promise<string | null> {
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

export async function createMoltbookApiClient(
	config: MoltbookConfig,
): Promise<MoltbookApiClient | null> {
	const apiKey = await resolveApiKey(config);
	if (!apiKey) {
		return null;
	}
	return new MoltbookApiClient({ apiKey, baseUrl: getApiBase() });
}

export class MoltbookApiClient {
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

	async fetchNotifications(): Promise<MoltbookNotification[]> {
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
		if (Array.isArray(payload)) {
			return payload;
		}
		if (payload && "notifications" in payload && Array.isArray(payload.notifications)) {
			return payload.notifications;
		}
		if (payload && "data" in payload && Array.isArray(payload.data)) {
			return payload.data;
		}

		logger.warn("moltbook notifications response format not recognized");
		return [];
	}

	async postReply(postId: string, body: string): Promise<MoltbookReplyResult> {
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

	/**
	 * Create a new post on Moltbook.
	 *
	 * @param content - The post content/body
	 * @param options - Optional title and tags
	 */
	async createPost(
		content: string,
		options?: { title?: string; tags?: string[] },
	): Promise<MoltbookPostResult> {
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

		const postId = result.data?.id ?? result.data?.post_id;
		return { ok: true, status: result.status, postId: postId ? String(postId) : undefined };
	}
}

export async function getMoltbookConfig(): Promise<MoltbookConfig> {
	const config = loadConfig();
	return config.moltbook;
}

function safeJsonParse(input: string): unknown {
	try {
		return JSON.parse(input);
	} catch {
		return null;
	}
}
