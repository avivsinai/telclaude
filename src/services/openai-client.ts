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
let keySourceChecked = false;

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
			keySourceChecked = true;
			logger.debug("using OpenAI API key from keychain");
			return keychainKey;
		}
	} catch (err) {
		logger.debug({ error: String(err) }, "keychain not available for OpenAI key");
	}

	// 2. Try environment variable
	if (process.env.OPENAI_API_KEY) {
		cachedApiKey = process.env.OPENAI_API_KEY;
		keySourceChecked = true;
		logger.debug("using OpenAI API key from environment variable");
		return cachedApiKey;
	}

	// 3. Try config file
	const config = loadConfig();
	if (config.openai?.apiKey) {
		cachedApiKey = config.openai.apiKey;
		keySourceChecked = true;
		logger.debug("using OpenAI API key from config file");
		return cachedApiKey;
	}

	keySourceChecked = true;
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
 * Note: This is async due to keychain check.
 */
export async function isOpenAIConfigured(): Promise<boolean> {
	const apiKey = await getApiKey();
	return !!apiKey;
}

/**
 * Initialize OpenAI key lookup (call at startup).
 * This populates the cache so isOpenAIConfiguredSync() works correctly.
 */
export async function initializeOpenAIKey(): Promise<boolean> {
	const apiKey = await getApiKey();
	return !!apiKey;
}

/**
 * Synchronous check if OpenAI is configured.
 * Returns accurate result if initializeOpenAIKey() was called at startup,
 * otherwise falls back to env/config check only.
 */
export function isOpenAIConfiguredSync(): boolean {
	// If we've already checked all sources (including keychain), use cached result
	if (keySourceChecked) {
		return !!cachedApiKey;
	}

	// Fallback: check env and config only (keychain not yet checked)
	const config = loadConfig();
	return !!(process.env.OPENAI_API_KEY ?? config.openai?.apiKey);
}

/**
 * Clear cached API key and client.
 * Call this after key rotation or deletion.
 */
export function clearOpenAICache(): void {
	cachedApiKey = null;
	keySourceChecked = false;
	client = null;
	logger.debug("OpenAI cache cleared");
}

/**
 * Get cached OpenAI key if we've already checked all sources.
 * Returns null if the key hasn't been initialized yet.
 */
export function getCachedOpenAIKey(): string | null {
	return keySourceChecked ? cachedApiKey : null;
}

/**
 * Pre-warm the OpenAI key cache.
 * Call this at startup so getCachedOpenAIKey() works for sandbox env injection.
 */
export async function prewarmOpenAIKey(): Promise<boolean> {
	const key = await getApiKey();
	return key !== null;
}

/**
 * Get OpenAI API key fresh from storage (async).
 * Use this for hot-loading support - always reads from keychain/env/config.
 * Returns null if not configured.
 */
export async function getOpenAIKey(): Promise<string | null> {
	// Clear cache to force fresh read
	cachedApiKey = null;
	keySourceChecked = false;
	return getApiKey();
}

/**
 * Reset the client (for testing).
 */
export function resetOpenAIClient(): void {
	client = null;
}
