import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	isWebSearchConfigured,
	searchWeb,
	WebSearchNotConfiguredError,
} from "../../src/services/web-search.js";

// Keep tests off the real OS keychain; individual tests control the resolved value.
const keychainSecret = vi.hoisted(() => ({ value: null as string | null }));

vi.mock("../../src/secrets/index.js", async (importOriginal) => {
	const actual = (await importOriginal()) as Record<string, unknown>;
	return {
		...actual,
		getSecret: async () => keychainSecret.value,
	};
});

const ORIGINAL_ENV_KEY = process.env.TELCLAUDE_BRAVE_SEARCH_API_KEY;

function braveResponse(results: Array<Record<string, unknown>>, status = 200): Response {
	return new Response(JSON.stringify({ web: { results } }), {
		status,
		headers: { "content-type": "application/json" },
	});
}

function mockFetch(...responses: Array<Response | Error>): ReturnType<typeof vi.fn> {
	const fn = vi.fn();
	for (const response of responses) {
		if (response instanceof Error) {
			fn.mockRejectedValueOnce(response);
		} else {
			fn.mockResolvedValueOnce(response);
		}
	}
	return fn;
}

describe("web search service (Brave)", () => {
	beforeEach(() => {
		keychainSecret.value = null;
		delete process.env.TELCLAUDE_BRAVE_SEARCH_API_KEY;
	});

	afterEach(() => {
		if (ORIGINAL_ENV_KEY === undefined) {
			delete process.env.TELCLAUDE_BRAVE_SEARCH_API_KEY;
		} else {
			process.env.TELCLAUDE_BRAVE_SEARCH_API_KEY = ORIGINAL_ENV_KEY;
		}
	});

	it("fails with a typed error when no API key is configured", async () => {
		const fetchImpl = mockFetch();

		await expect(isWebSearchConfigured()).resolves.toBe(false);
		await expect(
			searchWeb("telclaude", { fetchImpl: fetchImpl as unknown as typeof fetch }),
		).rejects.toMatchObject({
			name: "WebSearchNotConfiguredError",
			code: "web_search_not_configured",
		});
		await expect(searchWeb("telclaude")).rejects.toBeInstanceOf(WebSearchNotConfiguredError);
		expect(fetchImpl).not.toHaveBeenCalled();
	});

	it("uses the env API key as a fallback and maps results", async () => {
		process.env.TELCLAUDE_BRAVE_SEARCH_API_KEY = "brave-env-key";
		const fetchImpl = mockFetch(
			braveResponse([
				{ title: "Telclaude", url: "https://example.com/telclaude", description: "owl relay" },
				{ url: "https://example.com/untitled" },
				{ title: "no url, must be skipped", description: "broken entry" },
			]),
		);

		const result = await searchWeb("telclaude relay", {
			count: 2,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});

		expect(result).toEqual({
			provider: "brave",
			results: [
				{ title: "Telclaude", url: "https://example.com/telclaude", snippet: "owl relay" },
				{ title: "", url: "https://example.com/untitled", snippet: "" },
			],
		});
		expect(fetchImpl).toHaveBeenCalledTimes(1);
		const [url, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
		const parsed = new URL(url);
		expect(parsed.origin).toBe("https://api.search.brave.com");
		expect(parsed.searchParams.get("q")).toBe("telclaude relay");
		expect(parsed.searchParams.get("count")).toBe("2");
		expect(new Headers(init.headers).get("x-subscription-token")).toBe("brave-env-key");
		expect(init.signal).toBeInstanceOf(AbortSignal);
	});

	it("uses the keychain key when the env var is unset", async () => {
		keychainSecret.value = "brave-keychain-key";
		const fetchImpl = mockFetch(braveResponse([]));

		const result = await searchWeb("anything", {
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});

		expect(result).toEqual({ provider: "brave", results: [] });
		const [, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
		expect(new Headers(init.headers).get("x-subscription-token")).toBe("brave-keychain-key");
	});

	it("prefers the vault/keychain key over the env var", async () => {
		// Vault/keychain-first: when both are present, the keychain wins and the
		// env var is only a bootstrap fallback (matches bot-token precedence).
		keychainSecret.value = "brave-keychain-key";
		process.env.TELCLAUDE_BRAVE_SEARCH_API_KEY = "brave-env-key";
		const fetchImpl = mockFetch(braveResponse([]));

		await searchWeb("anything", { fetchImpl: fetchImpl as unknown as typeof fetch });

		const [, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
		expect(new Headers(init.headers).get("x-subscription-token")).toBe("brave-keychain-key");
	});

	it("does not retry 4xx responses", async () => {
		process.env.TELCLAUDE_BRAVE_SEARCH_API_KEY = "brave-env-key";
		const fetchImpl = mockFetch(new Response("bad request", { status: 400 }));

		await expect(
			searchWeb("telclaude", { fetchImpl: fetchImpl as unknown as typeof fetch }),
		).rejects.toThrow("Brave Search request failed: HTTP 400");
		expect(fetchImpl).toHaveBeenCalledTimes(1);
	});

	it("retries exactly once on 5xx and succeeds on the second attempt", async () => {
		process.env.TELCLAUDE_BRAVE_SEARCH_API_KEY = "brave-env-key";
		const fetchImpl = mockFetch(
			new Response("upstream broke", { status: 503 }),
			braveResponse([{ title: "ok", url: "https://example.com/ok", description: "recovered" }]),
		);

		const result = await searchWeb("telclaude", {
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});

		expect(result.results).toEqual([
			{ title: "ok", url: "https://example.com/ok", snippet: "recovered" },
		]);
		expect(fetchImpl).toHaveBeenCalledTimes(2);
	});

	it("fails after a second consecutive 5xx without further retries", async () => {
		process.env.TELCLAUDE_BRAVE_SEARCH_API_KEY = "brave-env-key";
		const fetchImpl = mockFetch(
			new Response("down", { status: 500 }),
			new Response("still down", { status: 500 }),
		);

		await expect(
			searchWeb("telclaude", { fetchImpl: fetchImpl as unknown as typeof fetch }),
		).rejects.toThrow("Brave Search request failed: HTTP 500");
		expect(fetchImpl).toHaveBeenCalledTimes(2);
	});

	it("retries exactly once on a network failure", async () => {
		process.env.TELCLAUDE_BRAVE_SEARCH_API_KEY = "brave-env-key";
		const fetchImpl = mockFetch(
			new Error("socket hang up"),
			braveResponse([{ title: "ok", url: "https://example.com/ok", description: "back" }]),
		);

		const result = await searchWeb("telclaude", {
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});

		expect(result.results).toHaveLength(1);
		expect(fetchImpl).toHaveBeenCalledTimes(2);
	});

	it("propagates a network failure that persists through the single retry", async () => {
		process.env.TELCLAUDE_BRAVE_SEARCH_API_KEY = "brave-env-key";
		const fetchImpl = mockFetch(new Error("socket hang up"), new Error("socket hang up again"));

		await expect(
			searchWeb("telclaude", { fetchImpl: fetchImpl as unknown as typeof fetch }),
		).rejects.toThrow("socket hang up again");
		expect(fetchImpl).toHaveBeenCalledTimes(2);
	});
});
