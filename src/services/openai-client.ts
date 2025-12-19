/**
 * OpenAI API client configuration.
 * Used for Whisper transcription, GPT Image generation, and TTS.
 *
 * API key resolution order:
 * 1. Keychain (via `telclaude setup-openai`)
 * 2. OPENAI_API_KEY environment variable
 * 3. openai.apiKey in config file
 */

import OpenAI from "openai";

import { loadConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { SECRET_KEYS, getSecret } from "../secrets/index.js";

const logger = getChildLogger({ module: "openai-client" });

let client: OpenAI | null = null;
let cachedApiKey: string | null = null;

/**
 * Get the OpenAI API key from keychain, env, or config.
 * Caches the result for performance.
 */
async function getApiKey(): Promise<string | null> {
	if (cachedApiKey) return cachedApiKey;

	// 1. Try keychain first
	try {
		const keychainKey = await getSecret(SECRET_KEYS.OPENAI_API_KEY);
		if (keychainKey) {
			cachedApiKey = keychainKey;
			logger.debug("using OpenAI API key from keychain");
			return keychainKey;
		}
	} catch (err) {
		logger.debug({ error: String(err) }, "keychain not available for OpenAI key");
	}

	// 2. Try environment variable
	if (process.env.OPENAI_API_KEY) {
		cachedApiKey = process.env.OPENAI_API_KEY;
		logger.debug("using OpenAI API key from environment variable");
		return cachedApiKey;
	}

	// 3. Try config file
	const config = loadConfig();
	if (config.openai?.apiKey) {
		cachedApiKey = config.openai.apiKey;
		logger.debug("using OpenAI API key from config file");
		return cachedApiKey;
	}

	return null;
}

/**
 * Get or create the OpenAI client.
 * Checks keychain first, then env var, then config file.
 */
export async function getOpenAIClient(): Promise<OpenAI> {
	if (client) return client;

	const apiKey = await getApiKey();

	if (!apiKey) {
		throw new Error(
			"OpenAI API key not configured.\n" +
				"Run: telclaude setup-openai\n" +
				"Or set OPENAI_API_KEY environment variable.",
		);
	}

	const config = loadConfig();
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
 * Note: This is async now due to keychain check.
 */
export async function isOpenAIConfigured(): Promise<boolean> {
	const apiKey = await getApiKey();
	return !!apiKey;
}

/**
 * Synchronous check if OpenAI might be configured.
 * Only checks env var and config (not keychain).
 * Use isOpenAIConfigured() for accurate check.
 */
export function isOpenAIConfiguredSync(): boolean {
	const config = loadConfig();
	return !!(process.env.OPENAI_API_KEY ?? config.openai?.apiKey);
}

/**
 * Reset the client (for testing).
 */
export function resetOpenAIClient(): void {
	client = null;
}
