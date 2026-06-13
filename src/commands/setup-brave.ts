/**
 * CLI command for setting up the Brave Search API key.
 * Stores the key securely in OS keychain or encrypted file.
 *
 * Like the OpenAI key, this is a relay-side-only credential: tc_web_search
 * runs server-side in the relay, so the contained runtime never sees the key.
 * The TELCLAUDE_BRAVE_SEARCH_API_KEY env var remains a bootstrap fallback only.
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
import { requireSecretsStorage } from "./cli-guards.js";
import { mask } from "./cli-mask.js";
import { promptSecret } from "./cli-prompt.js";

const logger = getChildLogger({ module: "cmd-setup-brave" });

export function registerSetupBraveCommand(program: Command): void {
	program
		.command("setup-brave")
		.alias("login-brave")
		.description("Configure Brave Search API key (stored securely in keychain)")
		.option("--delete", "Remove the stored API key")
		.option("--show", "Show the stored API key (masked)")
		.option("--check", "Check if an API key is configured")
		.action(async (opts: { delete?: boolean; show?: boolean; check?: boolean }) => {
			try {
				await requireSecretsStorage();

				const providerName = await getStorageProviderName();

				if (opts.delete) {
					const deleted = await deleteSecret(SECRET_KEYS.BRAVE_SEARCH_API_KEY);
					if (deleted) {
						console.log("Brave Search API key removed from keychain.");
					} else {
						console.log("No Brave Search API key was stored.");
					}
					return;
				}

				if (opts.check) {
					const exists = await hasSecret(SECRET_KEYS.BRAVE_SEARCH_API_KEY);
					if (exists) {
						console.log(`Brave Search API key is configured (stored in ${providerName}).`);
					} else {
						const envKey = process.env.TELCLAUDE_BRAVE_SEARCH_API_KEY;
						if (envKey) {
							console.log(
								"Brave Search API key is configured via TELCLAUDE_BRAVE_SEARCH_API_KEY environment variable.",
							);
						} else {
							console.log("No Brave Search API key configured.");
							console.log("Run: telclaude secrets setup-brave");
						}
					}
					return;
				}

				if (opts.show) {
					const key = await getSecret(SECRET_KEYS.BRAVE_SEARCH_API_KEY);
					if (key) {
						console.log(`Brave Search API key (${providerName}): ${mask(key)}`);
					} else {
						const envKey = process.env.TELCLAUDE_BRAVE_SEARCH_API_KEY;
						if (envKey) {
							console.log(`Brave Search API key (env var): ${mask(envKey)}`);
						} else {
							console.log("No Brave Search API key configured.");
						}
					}
					return;
				}

				console.log("Brave Search API Key Setup");
				console.log("==========================");
				console.log(`Storage: ${providerName}`);
				console.log("");

				const existingKey = await hasSecret(SECRET_KEYS.BRAVE_SEARCH_API_KEY);
				if (existingKey) {
					const current = await getSecret(SECRET_KEYS.BRAVE_SEARCH_API_KEY);
					if (current) {
						console.log(`Current key: ${mask(current)}`);
					}
					console.log(
						"A key is already stored. Enter a new key to replace it, or Ctrl+C to cancel.",
					);
					console.log("");
				}

				const apiKey = await promptSecret("Enter Brave Search API key: ");

				if (!apiKey) {
					console.log("Cancelled.");
					return;
				}

				await storeSecret(SECRET_KEYS.BRAVE_SEARCH_API_KEY, apiKey);
				console.log("");
				console.log(`Brave Search API key stored securely in ${providerName}.`);
				console.log("");
				console.log("tc_web_search is now configured. The key is loaded automatically;");
				console.log("you do not need to set TELCLAUDE_BRAVE_SEARCH_API_KEY.");

				logger.info({ provider: providerName }, "Brave Search API key stored");
			} catch (err) {
				logger.error({ error: String(err) }, "setup-brave command failed");
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exit(1);
			}
		});
}
