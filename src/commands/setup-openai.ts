/**
 * CLI command for setting up OpenAI API key.
 * Stores the key securely in OS keychain or encrypted file.
 */

import * as readline from "node:readline";

import type { Command } from "commander";

import { getChildLogger } from "../logging.js";
import {
	deleteSecret,
	getSecret,
	getStorageProviderName,
	hasSecret,
	isSecretsStorageAvailable,
	SECRET_KEYS,
	storeSecret,
} from "../secrets/index.js";
import { clearOpenAICache } from "../services/openai-client.js";

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
				// Check if storage is available
				if (!(await isSecretsStorageAvailable())) {
					console.error(
						"Error: Secrets storage not available.\n" +
							"On Linux, install libsecret-1-dev, or set SECRETS_ENCRYPTION_KEY for file storage.",
					);
					process.exit(1);
				}

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
						const masked = maskApiKey(key);
						console.log(`OpenAI API key (${providerName}): ${masked}`);
					} else {
						const envKey = process.env.OPENAI_API_KEY;
						if (envKey) {
							const masked = maskApiKey(envKey);
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
						console.log(`Current key: ${maskApiKey(current)}`);
					}
					console.log(
						"A key is already stored. Enter a new key to replace it, or Ctrl+C to cancel.",
					);
					console.log("");
				}

				// Prompt for key
				const apiKey = await promptForApiKey();

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

/**
 * Mask an API key for display.
 */
function maskApiKey(key: string): string {
	if (key.length <= 8) {
		return "****";
	}
	return `${key.slice(0, 4)}...${key.slice(-4)}`;
}

/**
 * Prompt for API key input (hidden).
 */
async function promptForApiKey(): Promise<string | null> {
	return new Promise((resolve) => {
		const rl = readline.createInterface({
			input: process.stdin,
			output: process.stdout,
		});

		// Hide input
		const stdin = process.stdin;
		const wasRaw = stdin.isRaw;

		process.stdout.write("Enter OpenAI API key: ");

		if (stdin.isTTY) {
			stdin.setRawMode(true);
		}

		let input = "";

		const onData = (char: Buffer) => {
			const c = char.toString();

			if (c === "\n" || c === "\r") {
				// Enter pressed
				if (stdin.isTTY) {
					stdin.setRawMode(wasRaw ?? false);
				}
				stdin.removeListener("data", onData);
				process.stdout.write("\n");
				rl.close();
				resolve(input.trim() || null);
			} else if (c === "\u0003") {
				// Ctrl+C
				if (stdin.isTTY) {
					stdin.setRawMode(wasRaw ?? false);
				}
				stdin.removeListener("data", onData);
				process.stdout.write("\n");
				rl.close();
				resolve(null);
			} else if (c === "\u007F" || c === "\b") {
				// Backspace
				if (input.length > 0) {
					input = input.slice(0, -1);
					process.stdout.write("\b \b");
				}
			} else if (c.charCodeAt(0) >= 32) {
				// Printable character
				input += c;
				process.stdout.write("*");
			}
		};

		stdin.on("data", onData);
		stdin.resume();
	});
}

/**
 * Prompt for yes/no confirmation.
 */
async function promptYesNo(question: string): Promise<boolean> {
	return new Promise((resolve) => {
		const rl = readline.createInterface({
			input: process.stdin,
			output: process.stdout,
		});

		rl.question(`${question} (y/N): `, (answer) => {
			rl.close();
			resolve(answer.toLowerCase() === "y" || answer.toLowerCase() === "yes");
		});
	});
}
