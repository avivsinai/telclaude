/**
 * Web search service backed by the Brave Web Search API.
 *
 * Relay-side only — the API key never reaches agent containers. Results are
 * untrusted external data; callers must redact and risk-wrap before any of it
 * enters a model prompt.
 *
 * API key resolution order:
 * 1. TELCLAUDE_BRAVE_SEARCH_API_KEY environment variable
 * 2. Keychain (SECRET_KEYS.BRAVE_SEARCH_API_KEY)
 */

import { getChildLogger } from "../logging.js";
import { getSecret, SECRET_KEYS } from "../secrets/index.js";

const logger = getChildLogger({ module: "web-search" });

const BRAVE_SEARCH_ENDPOINT = "https://api.search.brave.com/res/v1/web/search";
const SEARCH_TIMEOUT_MS = 10_000;
const DEFAULT_RESULT_COUNT = 5;

export class WebSearchNotConfiguredError extends Error {
	readonly code = "web_search_not_configured";

	constructor() {
		super(
			"Web search is not configured. Set TELCLAUDE_BRAVE_SEARCH_API_KEY " +
				"or store a Brave Search API key in the keychain.",
		);
		this.name = "WebSearchNotConfiguredError";
	}
}

export type WebSearchResult = {
	readonly title: string;
	readonly url: string;
	readonly snippet: string;
};

export type WebSearchResponse = {
	readonly results: readonly WebSearchResult[];
	readonly provider: "brave";
};

export type SearchWebOptions = {
	readonly count?: number;
	/** Injectable HTTP boundary for tests; defaults to global fetch. */
	readonly fetchImpl?: typeof fetch;
};

async function resolveApiKey(): Promise<string | null> {
	const fromEnv = process.env.TELCLAUDE_BRAVE_SEARCH_API_KEY?.trim();
	if (fromEnv) return fromEnv;

	try {
		const fromKeychain = await getSecret(SECRET_KEYS.BRAVE_SEARCH_API_KEY);
		if (fromKeychain) return fromKeychain;
	} catch (err) {
		logger.debug({ error: String(err) }, "keychain not available for Brave Search key");
	}

	return null;
}

export async function isWebSearchConfigured(): Promise<boolean> {
	return (await resolveApiKey()) !== null;
}

function isRetryableStatus(status: number): boolean {
	return status >= 500;
}

async function requestOnce(
	fetchImpl: typeof fetch,
	url: string,
	apiKey: string,
): Promise<Response> {
	return fetchImpl(url, {
		method: "GET",
		headers: {
			Accept: "application/json",
			"X-Subscription-Token": apiKey,
		},
		signal: AbortSignal.timeout(SEARCH_TIMEOUT_MS),
	});
}

/**
 * Execute the search request with bounded retry semantics:
 * no retries on 4xx, a single retry on 5xx or network/timeout failure.
 */
async function requestWithRetry(
	fetchImpl: typeof fetch,
	url: string,
	apiKey: string,
): Promise<Response> {
	let lastFailure: string;
	try {
		const response = await requestOnce(fetchImpl, url, apiKey);
		if (!isRetryableStatus(response.status)) return response;
		lastFailure = `HTTP ${response.status}`;
	} catch (err) {
		lastFailure = String(err);
	}

	logger.warn({ failure: lastFailure }, "Brave Search request failed, retrying once");
	return requestOnce(fetchImpl, url, apiKey);
}

type BraveWebResult = {
	readonly title?: unknown;
	readonly url?: unknown;
	readonly description?: unknown;
};

function parseResults(payload: unknown, count: number): WebSearchResult[] {
	const raw = (payload as { web?: { results?: unknown } } | null)?.web?.results;
	if (!Array.isArray(raw)) return [];

	const results: WebSearchResult[] = [];
	for (const entry of raw as BraveWebResult[]) {
		if (typeof entry?.url !== "string" || !entry.url) continue;
		results.push({
			title: typeof entry.title === "string" ? entry.title : "",
			url: entry.url,
			snippet: typeof entry.description === "string" ? entry.description : "",
		});
		if (results.length >= count) break;
	}
	return results;
}

/**
 * Search the web via the Brave Web Search API.
 * Throws WebSearchNotConfiguredError when no API key is available.
 */
export async function searchWeb(
	query: string,
	options: SearchWebOptions = {},
): Promise<WebSearchResponse> {
	const apiKey = await resolveApiKey();
	if (!apiKey) throw new WebSearchNotConfiguredError();

	const count = options.count ?? DEFAULT_RESULT_COUNT;
	const fetchImpl = options.fetchImpl ?? fetch;

	const url = new URL(BRAVE_SEARCH_ENDPOINT);
	url.searchParams.set("q", query);
	url.searchParams.set("count", String(count));

	const response = await requestWithRetry(fetchImpl, url.toString(), apiKey);
	if (!response.ok) {
		throw new Error(`Brave Search request failed: HTTP ${response.status}`);
	}

	const payload = (await response.json()) as unknown;
	const results = parseResults(payload, count);
	logger.info({ query: query.slice(0, 80), count, returned: results.length }, "web search done");

	return { results, provider: "brave" };
}
