/**
 * OpenAI API client configuration.
 * Used for Whisper transcription, GPT Image generation, and TTS.
 */

import OpenAI from "openai";

import { loadConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";

const logger = getChildLogger({ module: "openai-client" });

let client: OpenAI | null = null;

/**
 * Get or create the OpenAI client.
 * Uses OPENAI_API_KEY env var or config file.
 */
export function getOpenAIClient(): OpenAI {
	if (client) return client;

	const config = loadConfig();
	const apiKey = process.env.OPENAI_API_KEY ?? config.openai?.apiKey;

	if (!apiKey) {
		throw new Error(
			"OpenAI API key not configured. Set OPENAI_API_KEY environment variable or openai.apiKey in config.",
		);
	}

	const baseURL = config.openai?.baseUrl;

	client = new OpenAI({
		apiKey,
		baseURL,
		timeout: 120_000, // 2 minute timeout for large files
		maxRetries: 3,
	});

	logger.debug({ hasCustomBaseUrl: !!baseURL }, "OpenAI client initialized");

	return client;
}

/**
 * Check if OpenAI is configured.
 */
export function isOpenAIConfigured(): boolean {
	const config = loadConfig();
	return !!(process.env.OPENAI_API_KEY ?? config.openai?.apiKey);
}

/**
 * Reset the client (for testing).
 */
export function resetOpenAIClient(): void {
	client = null;
}
