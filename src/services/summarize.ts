/**
 * URL content extraction service using @steipete/summarize-core.
 * Dual-mode: relay direct via createLinkPreviewClient() or agent→relay proxy.
 */

import type { SummarizeConfig } from "../config/config.js";
import { loadConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { relaySummarize } from "../relay/capabilities-client.js";
import { getMultimediaRateLimiter } from "./multimedia-rate-limit.js";

const logger = getChildLogger({ module: "summarize" });

export type SummarizeOptions = {
	maxCharacters?: number;
	timeoutMs?: number;
	format?: "text" | "markdown";
	userId?: string;
	skipRateLimit?: boolean;
};

export type SummarizeResult = {
	url: string;
	title: string | null;
	siteName: string | null;
	content: string;
	wordCount: number;
	truncated: boolean;
	transcriptSource: string | null;
};

const DEFAULT_CONFIG: SummarizeConfig = {
	maxPerHourPerUser: 30,
	maxPerDayPerUser: 100,
	maxCharacters: 8000,
	timeoutMs: 30_000,
};

// Lazy singleton — created once per process
let clientPromise: Promise<import("@steipete/summarize-core/content").LinkPreviewClient> | null =
	null;

async function getClient(): Promise<import("@steipete/summarize-core/content").LinkPreviewClient> {
	if (!clientPromise) {
		clientPromise = import("@steipete/summarize-core/content").then((mod) =>
			mod.createLinkPreviewClient({ fetch }),
		);
	}
	return clientPromise;
}

/**
 * Extract and return text content from a URL.
 */
export async function summarizeUrl(
	url: string,
	options?: SummarizeOptions,
): Promise<SummarizeResult> {
	// Route through relay when running on agent container
	if (process.env.TELCLAUDE_CAPABILITIES_URL) {
		logger.debug({ url: url.slice(0, 80) }, "routing summarize through relay");
		return relaySummarize({
			url,
			maxCharacters: options?.maxCharacters,
			timeoutMs: options?.timeoutMs,
			format: options?.format,
			userId: options?.userId,
		});
	}

	const config = loadConfig();
	const summarizeConfig = { ...DEFAULT_CONFIG, ...config.summarize };

	const maxCharacters = options?.maxCharacters ?? summarizeConfig.maxCharacters;
	const timeoutMs = options?.timeoutMs ?? summarizeConfig.timeoutMs;
	const format = options?.format ?? "text";

	// Rate limiting (if userId provided and not skipped)
	const userId = options?.userId;
	if (userId && !options?.skipRateLimit) {
		const rateLimiter = getMultimediaRateLimiter();
		const rateConfig = {
			maxPerHourPerUser: summarizeConfig.maxPerHourPerUser,
			maxPerDayPerUser: summarizeConfig.maxPerDayPerUser,
		};
		const limitResult = rateLimiter.checkLimit("summarize", userId, rateConfig);
		if (!limitResult.allowed) {
			throw new Error(limitResult.reason ?? "Summarize rate limit exceeded");
		}
	}

	logger.info({ url: url.slice(0, 120), maxCharacters, timeoutMs, format }, "extracting content");
	const startTime = Date.now();

	try {
		const client = await getClient();
		const result = await client.fetchLinkContent(url, {
			maxCharacters,
			timeoutMs,
			format,
		});

		const durationMs = Date.now() - startTime;
		logger.info(
			{
				url: url.slice(0, 80),
				wordCount: result.wordCount,
				truncated: result.truncated,
				transcriptSource: result.transcriptSource,
				durationMs,
			},
			"content extracted",
		);

		// Consume rate limit point after success
		if (userId && !options?.skipRateLimit) {
			const rateLimiter = getMultimediaRateLimiter();
			rateLimiter.consume("summarize", userId);
		}

		return {
			url: result.url,
			title: result.title,
			siteName: result.siteName,
			content: result.content,
			wordCount: result.wordCount,
			truncated: result.truncated,
			transcriptSource: result.transcriptSource,
		};
	} catch (error) {
		logger.error({ url: url.slice(0, 80), error: String(error) }, "content extraction failed");
		throw error;
	}
}

/**
 * Check if summarize is available (always true — no API key needed).
 */
export function isSummarizeAvailable(): boolean {
	if (process.env.TELCLAUDE_CAPABILITIES_URL) {
		return Boolean(
			process.env.TELCLAUDE_SESSION_TOKEN ?? process.env.TELEGRAM_RPC_AGENT_PRIVATE_KEY,
		);
	}
	return true;
}
