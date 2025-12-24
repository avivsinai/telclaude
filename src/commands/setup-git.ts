/**
 * CLI command for setting up git credentials.
 * Stores credentials securely in OS keychain or encrypted file.
 *
 * This enables telclaude to perform git operations (clone, push, pull)
 * on behalf of a bot user account.
 */

import * as readline from "node:readline";

import type { Command } from "commander";

import { getChildLogger } from "../logging.js";
import {
	deleteSecret,
	type GitCredentials,
	getSecret,
	getStorageProviderName,
	hasSecret,
	isSecretsStorageAvailable,
	SECRET_KEYS,
	storeSecret,
} from "../secrets/index.js";
import {
	applyGitIdentity,
	clearGitCredentialsCache,
	isGitConfigured,
	testGitConnectivity,
} from "../services/git-credentials.js";

const logger = getChildLogger({ module: "cmd-setup-git" });

export function registerSetupGitCommand(program: Command): void {
	program
		.command("setup-git")
		.description("Configure git credentials for bot operations (stored securely)")
		.option("--delete", "Remove stored git credentials")
		.option("--show", "Show stored git credentials (token masked)")
		.option("--check", "Check if git credentials are configured")
		.option("--apply", "Apply git identity to system (user.name/email)")
		.option("--test", "Test git connectivity with stored credentials")
		.action(
			async (opts: {
				delete?: boolean;
				show?: boolean;
				check?: boolean;
				apply?: boolean;
				test?: boolean;
			}) => {
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
						const deleted = await deleteSecret(SECRET_KEYS.GIT_CREDENTIALS);
						clearGitCredentialsCache();
						if (deleted) {
							console.log("Git credentials removed from secure storage.");
						} else {
							console.log("No git credentials were stored.");
						}
						return;
					}

					// Handle --check
					if (opts.check) {
						const exists = await hasSecret(SECRET_KEYS.GIT_CREDENTIALS);
						if (exists) {
							console.log(`Git credentials are configured (stored in ${providerName}).`);
						} else {
							// Check env var fallback
							const envToken = process.env.GITHUB_TOKEN || process.env.GIT_TOKEN;
							if (process.env.GIT_USERNAME && process.env.GIT_EMAIL && envToken) {
								console.log("Git credentials are configured via environment variables.");
							} else {
								console.log("No git credentials configured.");
								console.log("Run: telclaude setup-git");
							}
						}
						return;
					}

					// Handle --show
					if (opts.show) {
						const stored = await getSecret(SECRET_KEYS.GIT_CREDENTIALS);
						if (stored) {
							try {
								const creds = JSON.parse(stored) as GitCredentials;
								console.log(`Git credentials (${providerName}):`);
								console.log(`  Username: ${creds.username}`);
								console.log(`  Email:    ${creds.email}`);
								console.log(`  Token:    ${maskToken(creds.token)}`);
							} catch {
								console.log("Stored credentials are corrupted. Run setup-git again.");
							}
						} else {
							// Check env var fallback
							const envToken = process.env.GITHUB_TOKEN || process.env.GIT_TOKEN;
							if (process.env.GIT_USERNAME && process.env.GIT_EMAIL && envToken) {
								console.log("Git credentials (env vars):");
								console.log(`  Username: ${process.env.GIT_USERNAME}`);
								console.log(`  Email:    ${process.env.GIT_EMAIL}`);
								console.log(`  Token:    ${maskToken(envToken)}`);
							} else {
								console.log("No git credentials configured.");
							}
						}
						return;
					}

					// Handle --apply
					if (opts.apply) {
						const applied = await applyGitIdentity();
						if (applied) {
							console.log("Git identity applied successfully.");
						} else {
							console.error("Failed to apply git identity. Run setup-git first.");
							process.exit(1);
						}
						return;
					}

					// Handle --test
					if (opts.test) {
						console.log("Testing git connectivity...");
						const result = await testGitConnectivity();
						if (result.success) {
							console.log(`✓ ${result.message}`);
						} else {
							console.error(`✗ ${result.message}`);
							process.exit(1);
						}
						return;
					}

					// Interactive setup
					await runInteractiveSetup(providerName);
				} catch (err) {
					logger.error({ error: String(err) }, "setup-git command failed");
					console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
					process.exit(1);
				}
			},
		);

	// Also register git-identity as an alias for --apply
	program
		.command("git-identity")
		.description("Apply git identity from stored credentials")
		.option("--check", "Check if credentials are available without applying")
		.action(async (opts: { check?: boolean }) => {
			if (opts.check) {
				// Check both secure storage AND env vars for consistency with applyGitIdentity
				const exists = await isGitConfigured();
				process.exit(exists ? 0 : 1);
			}

			const applied = await applyGitIdentity();
			process.exit(applied ? 0 : 1);
		});
}

async function runInteractiveSetup(providerName: string): Promise<void> {
	console.log("Git Credentials Setup");
	console.log("=====================");
	console.log(`Storage: ${providerName}`);
	console.log("");
	console.log("This configures git credentials for telclaude to clone/push repositories.");
	console.log("");
	console.log("Prerequisites:");
	console.log("  1. Create a GitHub account for your bot (e.g., 'myproject-bot')");
	console.log("  2. Generate a fine-grained PAT at: https://github.com/settings/tokens?type=beta");
	console.log("     Required scopes: Contents (read/write), Pull requests (read/write)");
	console.log("");

	// Check if credentials already exist
	const existingCreds = await getSecret(SECRET_KEYS.GIT_CREDENTIALS);
	if (existingCreds) {
		try {
			const creds = JSON.parse(existingCreds) as GitCredentials;
			console.log("Current credentials:");
			console.log(`  Username: ${creds.username}`);
			console.log(`  Email:    ${creds.email}`);
			console.log(`  Token:    ${maskToken(creds.token)}`);
			console.log("");
			console.log("Enter new credentials to replace, or Ctrl+C to cancel.");
			console.log("");
		} catch {
			console.log("Existing credentials are corrupted and will be replaced.");
			console.log("");
		}
	}

	// Prompt for username
	const username = await promptForInput("Git username (e.g., myproject-bot): ");
	if (!username) {
		console.log("Cancelled.");
		return;
	}

	// Prompt for email (with default)
	const defaultEmail = `${username}@users.noreply.github.com`;
	const emailPrompt = `Git email [${defaultEmail}]: `;
	const emailInput = await promptForInput(emailPrompt);
	const email = emailInput || defaultEmail;

	// Prompt for token (hidden)
	const token = await promptForSecret("GitHub PAT (fine-grained token): ");
	if (!token) {
		console.log("Cancelled.");
		return;
	}

	// Validate token format
	if (!token.startsWith("github_pat_") && !token.startsWith("ghp_")) {
		console.warn("");
		console.warn("Warning: GitHub tokens typically start with 'github_pat_' or 'ghp_'.");
		const proceed = await promptYesNo("Store anyway?");
		if (!proceed) {
			console.log("Cancelled.");
			return;
		}
	}

	// Store credentials
	const credentials: GitCredentials = { username, email, token };
	await storeSecret(SECRET_KEYS.GIT_CREDENTIALS, JSON.stringify(credentials));
	clearGitCredentialsCache();

	console.log("");
	console.log(`Git credentials stored securely in ${providerName}.`);
	console.log("");

	// Offer to apply identity
	const applyNow = await promptYesNo("Apply git identity now (configure user.name/email)?");
	if (applyNow) {
		const applied = await applyGitIdentity();
		if (applied) {
			console.log("Git identity configured.");
		} else {
			console.warn(
				"Failed to apply git identity. You can try later with: telclaude setup-git --apply",
			);
		}
	}

	// Offer to test connectivity
	const testNow = await promptYesNo("Test git connectivity?");
	if (testNow) {
		console.log("Testing...");
		const result = await testGitConnectivity();
		if (result.success) {
			console.log(`✓ ${result.message}`);
		} else {
			console.warn(`✗ ${result.message}`);
			console.log("");
			console.log("Credentials are saved. You can test again with: telclaude setup-git --test");
		}
	}

	console.log("");
	console.log("Setup complete. Your bot can now perform git operations.");
	console.log("");
	console.log("Usage:");
	console.log("  telclaude setup-git --show   # View stored credentials");
	console.log("  telclaude setup-git --test   # Test connectivity");
	console.log("  telclaude setup-git --apply  # Apply git identity");

	logger.info({ username, email, provider: providerName }, "Git credentials stored");
}

/**
 * Mask a token for display.
 */
function maskToken(token: string): string {
	if (token.length <= 12) {
		return "****";
	}
	return `${token.slice(0, 8)}...${token.slice(-4)}`;
}

/**
 * Prompt for visible input.
 */
async function promptForInput(prompt: string): Promise<string | null> {
	return new Promise((resolve) => {
		const rl = readline.createInterface({
			input: process.stdin,
			output: process.stdout,
		});

		rl.question(prompt, (answer) => {
			rl.close();
			resolve(answer.trim() || null);
		});

		// Handle Ctrl+C
		rl.on("close", () => {
			resolve(null);
		});
	});
}

/**
 * Prompt for secret input (hidden).
 */
async function promptForSecret(prompt: string): Promise<string | null> {
	return new Promise((resolve) => {
		const rl = readline.createInterface({
			input: process.stdin,
			output: process.stdout,
		});

		const stdin = process.stdin;
		const wasRaw = stdin.isRaw;

		process.stdout.write(prompt);

		if (stdin.isTTY) {
			stdin.setRawMode(true);
		}

		let input = "";

		const onData = (char: Buffer) => {
			const c = char.toString();

			if (c === "\n" || c === "\r") {
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
