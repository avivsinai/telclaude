/**
 * CLI command for setting up OpenAI API key.
 * Stores the key securely in OS keychain or encrypted file.
 */

import type { Command } from "commander";

import { getChildLogger } from "../logging.js";
import {
	deleteSecret,
	getSecret,
	getStorageProviderName,
	hasSecret,
	SECRET_KEYS,
	storeSecret,
} from "../secrets/index.js";
import { clearOpenAICache } from "../services/openai-client.js";
import { requireSecretsStorage } from "./cli-guards.js";
import { mask } from "./cli-mask.js";
import { promptSecret, promptYesNo } from "./cli-prompt.js";

const logger = getChildLogger({ module: "cmd-setup-openai" });

export function registerSetupOpenAICommand(program: Command): void {
	program
		.command("setup-openai")
		.alias("login-openai")
		.description("Configure OpenAI API key (stored securely in keychain)")
		.option("--delete", "Remove the stored API key")
		.option("--show", "Show the stored API key (masked)")
		.option("--check", "Check if an API key is configured")
		.action(async (opts: { delete?: boolean; show?: boolean; check?: boolean }) => {
			try {
				await requireSecretsStorage();

				const providerName = await getStorageProviderName();

				// Handle --delete
				if (opts.delete) {
					const deleted = await deleteSecret(SECRET_KEYS.OPENAI_API_KEY);
					clearOpenAICache(); // Clear cached key so changes take effect
					if (deleted) {
						console.log("OpenAI API key removed from keychain.");
					} else {
						console.log("No OpenAI API key was stored.");
					}
					return;
				}

				// Handle --check
				if (opts.check) {
					const exists = await hasSecret(SECRET_KEYS.OPENAI_API_KEY);
					if (exists) {
						console.log(`OpenAI API key is configured (stored in ${providerName}).`);
					} else {
						// Check env var and config fallbacks
						const envKey = process.env.OPENAI_API_KEY;
						if (envKey) {
							console.log("OpenAI API key is configured via OPENAI_API_KEY environment variable.");
						} else {
							console.log("No OpenAI API key configured.");
							console.log("Run: telclaude setup-openai");
						}
					}
					return;
				}

				// Handle --show
				if (opts.show) {
					const key = await getSecret(SECRET_KEYS.OPENAI_API_KEY);
					if (key) {
						const masked = mask(key);
						console.log(`OpenAI API key (${providerName}): ${masked}`);
					} else {
						const envKey = process.env.OPENAI_API_KEY;
						if (envKey) {
							const masked = mask(envKey);
							console.log(`OpenAI API key (env var): ${masked}`);
						} else {
							console.log("No OpenAI API key configured.");
						}
					}
					return;
				}

				// Interactive setup
				console.log("OpenAI API Key Setup");
				console.log("====================");
				console.log(`Storage: ${providerName}`);
				console.log("");

				// Check if key already exists
				const existingKey = await hasSecret(SECRET_KEYS.OPENAI_API_KEY);
				if (existingKey) {
					const current = await getSecret(SECRET_KEYS.OPENAI_API_KEY);
					if (current) {
						console.log(`Current key: ${mask(current)}`);
					}
					console.log(
						"A key is already stored. Enter a new key to replace it, or Ctrl+C to cancel.",
					);
					console.log("");
				}

				// Prompt for key
				const apiKey = await promptSecret("Enter OpenAI API key: ");

				if (!apiKey) {
					console.log("Cancelled.");
					return;
				}

				// Validate format
				if (!apiKey.startsWith("sk-")) {
					console.error("Warning: OpenAI API keys typically start with 'sk-'.");
					const proceed = await promptYesNo("Store anyway?");
					if (!proceed) {
						console.log("Cancelled.");
						return;
					}
				}

				// Store the key
				await storeSecret(SECRET_KEYS.OPENAI_API_KEY, apiKey);
				clearOpenAICache(); // Clear cached key so new key takes effect
				console.log("");
				console.log(`OpenAI API key stored securely in ${providerName}.`);
				console.log("");
				console.log("You can now use image generation, TTS, and transcription features.");
				console.log("The key is loaded automatically - no need to set OPENAI_API_KEY.");

				logger.info({ provider: providerName }, "OpenAI API key stored");
			} catch (err) {
				logger.error({ error: String(err) }, "setup-openai command failed");
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exit(1);
			}
		});

	// Command alias is registered above.
}
