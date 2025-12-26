/**
 * CLI command for setting up GitHub App credentials.
 *
 * This enables telclaude to authenticate as a GitHub App bot user
 * for git operations with automatically signed commits.
 */

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import * as readline from "node:readline";

import type { Command } from "commander";

import { getChildLogger } from "../logging.js";
import {
	deleteSecret,
	getSecret,
	getStorageProviderName,
	isSecretsStorageAvailable,
	SECRET_KEYS,
	storeSecret,
} from "../secrets/index.js";
import {
	clearGitHubAppCache,
	type GitHubAppConfig,
	listAccessibleRepositories,
	testGitHubAppConnectivity,
} from "../services/github-app.js";

const logger = getChildLogger({ module: "cmd-setup-github-app" });

export function registerSetupGitHubAppCommand(program: Command): void {
	program
		.command("setup-github-app")
		.description("Configure GitHub App credentials for bot operations")
		.option("--delete", "Remove stored GitHub App credentials")
		.option("--show", "Show stored GitHub App config (keys masked)")
		.option("--check", "Check if GitHub App is configured")
		.option("--test", "Test GitHub App connectivity")
		.option("--repos", "List repositories the app can access")
		.option("--app-id <id>", "GitHub App ID")
		.option("--installation-id <id>", "Installation ID")
		.option("--private-key <path>", "Path to private key PEM file")
		.action(
			async (opts: {
				delete?: boolean;
				show?: boolean;
				check?: boolean;
				test?: boolean;
				repos?: boolean;
				appId?: string;
				installationId?: string;
				privateKey?: string;
			}) => {
				try {
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
						const deleted = await deleteSecret(SECRET_KEYS.GITHUB_APP);
						clearGitHubAppCache();
						if (deleted) {
							console.log("GitHub App credentials removed from secure storage.");
						} else {
							console.log("No GitHub App credentials were stored.");
						}
						return;
					}

					// Handle --check
					if (opts.check) {
						const stored = await getSecret(SECRET_KEYS.GITHUB_APP);
						if (stored) {
							console.log(`GitHub App is configured (stored in ${providerName}).`);
						} else {
							console.log("No GitHub App configured.");
							console.log("Run: telclaude setup-github-app");
						}
						return;
					}

					// Handle --show
					if (opts.show) {
						const stored = await getSecret(SECRET_KEYS.GITHUB_APP);
						if (stored) {
							try {
								const config = JSON.parse(stored) as GitHubAppConfig;
								console.log(`GitHub App credentials (${providerName}):`);
								console.log(`  App ID:          ${config.appId}`);
								console.log(`  Installation ID: ${config.installationId}`);
								console.log(`  App Slug:        ${config.appSlug}`);
								console.log(`  Bot User ID:     ${config.botUserId}`);
								console.log(`  Private Key:     ${maskPrivateKey(config.privateKey)}`);
							} catch {
								console.log("Stored credentials are corrupted. Run setup-github-app again.");
							}
						} else {
							console.log("No GitHub App credentials configured.");
						}
						return;
					}

					// Handle --test
					if (opts.test) {
						clearGitHubAppCache(); // Ensure fresh config
						console.log("Testing GitHub App connectivity...");
						const result = await testGitHubAppConnectivity();
						if (result.success) {
							console.log(`✓ ${result.message}`);
							if (result.details) {
								console.log(`  App: ${result.details.appName} (${result.details.appSlug})`);
								console.log(`  Account: ${result.details.installationAccount}`);
								console.log(`  Repo access: ${result.details.repositorySelection}`);
							}
						} else {
							console.error(`✗ ${result.message}`);
							process.exit(1);
						}
						return;
					}

					// Handle --repos
					if (opts.repos) {
						clearGitHubAppCache(); // Ensure fresh config
						console.log("Listing accessible repositories...");
						const repos = await listAccessibleRepositories();
						if (repos.length === 0) {
							console.log("No repositories accessible (or GitHub App not configured).");
						} else {
							console.log(`Accessible repositories (${repos.length}):`);
							for (const repo of repos) {
								console.log(`  - ${repo}`);
							}
						}
						return;
					}

					// Non-interactive setup with CLI options
					if (opts.appId && opts.installationId && opts.privateKey) {
						await setupWithOptions(opts.appId, opts.installationId, opts.privateKey, providerName);
						return;
					}

					// Interactive setup
					await runInteractiveSetup(providerName);
				} catch (err) {
					logger.error({ error: String(err) }, "setup-github-app command failed");
					console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
					process.exit(1);
				}
			},
		);
}

async function setupWithOptions(
	appId: string,
	installationId: string,
	privateKeyPath: string,
	providerName: string,
): Promise<void> {
	const expandedPath = privateKeyPath.replace(/^~/, process.env.HOME || "");
	const resolvedPath = resolve(expandedPath);

	// Validate private key file exists
	if (!existsSync(resolvedPath)) {
		console.error(`Error: Private key file not found: ${resolvedPath}`);
		process.exit(1);
	}

	// Read and validate PEM
	const privateKey = readFileSync(resolvedPath, "utf8");
	if (!privateKey.includes("-----BEGIN")) {
		console.error("Error: Invalid PEM file format");
		process.exit(1);
	}

	const config: GitHubAppConfig = {
		appId,
		installationId,
		privateKey: resolvedPath, // Store path, not content
		appSlug: "telclaude",
		botUserId: 251589752,
	};

	await storeSecret(SECRET_KEYS.GITHUB_APP, JSON.stringify(config));
	clearGitHubAppCache();

	console.log(`GitHub App credentials stored securely in ${providerName}.`);

	// Test connectivity
	console.log("\nTesting connectivity...");
	const result = await testGitHubAppConnectivity();
	if (result.success) {
		console.log(`✓ ${result.message}`);
	} else {
		console.warn(`⚠ ${result.message}`);
		console.log("Credentials saved but connectivity test failed. Check your configuration.");
	}
}

async function runInteractiveSetup(providerName: string): Promise<void> {
	console.log("GitHub App Setup");
	console.log("================");
	console.log(`Storage: ${providerName}`);
	console.log("");
	console.log("This configures telclaude to authenticate as a GitHub App bot user.");
	console.log("Commits will appear as 'telclaude[bot]' and be automatically signed.");
	console.log("");
	console.log("Prerequisites:");
	console.log("  1. Create a GitHub App at: https://github.com/settings/apps/new");
	console.log("  2. Set permissions: Contents (R/W), Pull requests (R/W), Metadata (R)");
	console.log("  3. Generate and download a private key (.pem file)");
	console.log("  4. Install the app on your repositories");
	console.log("");

	// Check existing config
	const existingConfig = await getSecret(SECRET_KEYS.GITHUB_APP);
	if (existingConfig) {
		try {
			const config = JSON.parse(existingConfig) as GitHubAppConfig;
			console.log("Current configuration:");
			console.log(`  App ID:          ${config.appId}`);
			console.log(`  Installation ID: ${config.installationId}`);
			console.log("");
			console.log("Enter new values to replace, or Ctrl+C to cancel.");
			console.log("");
		} catch {
			console.log("Existing config is corrupted and will be replaced.");
			console.log("");
		}
	}

	// Prompt for App ID
	const appId = await promptForInput("GitHub App ID: ");
	if (!appId) {
		console.log("Cancelled.");
		return;
	}

	// Prompt for Installation ID
	console.log("");
	console.log("Find your Installation ID:");
	console.log("  1. Go to https://github.com/settings/installations");
	console.log("  2. Click 'Configure' on your app");
	console.log("  3. The ID is in the URL: /installations/<INSTALLATION_ID>");
	console.log("");
	const installationId = await promptForInput("Installation ID: ");
	if (!installationId) {
		console.log("Cancelled.");
		return;
	}

	// Prompt for private key path
	console.log("");
	const privateKeyPath = await promptForInput("Path to private key (.pem file): ");
	if (!privateKeyPath) {
		console.log("Cancelled.");
		return;
	}

	// Validate PEM file
	const expandedPath = privateKeyPath.replace(/^~/, process.env.HOME || "");
	if (!existsSync(expandedPath)) {
		console.error(`Error: File not found: ${expandedPath}`);
		return;
	}

	const pemContent = readFileSync(expandedPath, "utf8");
	if (!pemContent.includes("-----BEGIN")) {
		console.error("Error: Invalid PEM file format");
		return;
	}

	// Store config
	const config: GitHubAppConfig = {
		appId,
		installationId,
		privateKey: expandedPath,
		appSlug: "telclaude",
		botUserId: 251589752,
	};

	await storeSecret(SECRET_KEYS.GITHUB_APP, JSON.stringify(config));
	clearGitHubAppCache();

	console.log("");
	console.log(`GitHub App credentials stored securely in ${providerName}.`);
	console.log("");

	// Test connectivity
	const testNow = await promptYesNo("Test GitHub App connectivity?");
	if (testNow) {
		console.log("Testing...");
		const result = await testGitHubAppConnectivity();
		if (result.success) {
			console.log(`✓ ${result.message}`);
			if (result.details) {
				console.log(`  App: ${result.details.appName}`);
				console.log(`  Account: ${result.details.installationAccount}`);
			}
		} else {
			console.warn(`✗ ${result.message}`);
			console.log("");
			console.log("Credentials saved. You can test again with: telclaude setup-github-app --test");
		}
	}

	// List repos
	const listRepos = await promptYesNo("List accessible repositories?");
	if (listRepos) {
		const repos = await listAccessibleRepositories();
		if (repos.length === 0) {
			console.log("No repositories accessible yet.");
		} else {
			console.log(`Accessible repositories (${repos.length}):`);
			for (const repo of repos) {
				console.log(`  - ${repo}`);
			}
		}
	}

	console.log("");
	console.log("Setup complete! Telclaude can now authenticate as telclaude[bot].");
	console.log("");
	console.log("Usage:");
	console.log("  telclaude setup-github-app --show   # View stored config");
	console.log("  telclaude setup-github-app --test   # Test connectivity");
	console.log("  telclaude setup-github-app --repos  # List accessible repos");

	logger.info({ appId, installationId, provider: providerName }, "GitHub App credentials stored");
}

function maskPrivateKey(keyOrPath: string): string {
	if (keyOrPath.endsWith(".pem") || keyOrPath.startsWith("/")) {
		return keyOrPath; // It's a path, show it
	}
	// It's inline content, mask it
	return "-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----";
}

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

		rl.on("close", () => {
			resolve(null);
		});
	});
}

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
