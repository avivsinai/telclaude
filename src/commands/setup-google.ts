/**
 * CLI command for setting up Google OAuth2 credentials.
 * Wraps the generic OAuth flow with Google-specific scope bundles.
 */

import type { Command } from "commander";

import { getChildLogger } from "../logging.js";
import { authorize, getCallbackUrl } from "../oauth/flow.js";
import { getService } from "../oauth/registry.js";
import { getVaultClient, isVaultAvailable } from "../vault-daemon/index.js";

const logger = getChildLogger({ module: "cmd-setup-google" });

// ═══════════════════════════════════════════════════════════════════════════════
// Scope Bundles
// ═══════════════════════════════════════════════════════════════════════════════

const SCOPE_BUNDLES: Record<string, string[]> = {
	read_core: [
		"https://www.googleapis.com/auth/gmail.readonly",
		"https://www.googleapis.com/auth/calendar.events.readonly",
		"https://www.googleapis.com/auth/calendar.calendarlist.readonly",
		"https://www.googleapis.com/auth/calendar.freebusy",
		"https://www.googleapis.com/auth/drive.metadata.readonly",
		"https://www.googleapis.com/auth/contacts.readonly",
	],
	read_plus_download: [
		"https://www.googleapis.com/auth/gmail.readonly",
		"https://www.googleapis.com/auth/calendar.events.readonly",
		"https://www.googleapis.com/auth/calendar.calendarlist.readonly",
		"https://www.googleapis.com/auth/calendar.freebusy",
		"https://www.googleapis.com/auth/drive.metadata.readonly",
		"https://www.googleapis.com/auth/drive.readonly",
		"https://www.googleapis.com/auth/contacts.readonly",
	],
	actions_v1: [
		"https://www.googleapis.com/auth/gmail.readonly",
		"https://www.googleapis.com/auth/gmail.compose",
		"https://www.googleapis.com/auth/calendar.events.readonly",
		"https://www.googleapis.com/auth/calendar.calendarlist.readonly",
		"https://www.googleapis.com/auth/calendar.freebusy",
		"https://www.googleapis.com/auth/calendar.events.owned",
		"https://www.googleapis.com/auth/drive.metadata.readonly",
		"https://www.googleapis.com/auth/drive.readonly",
		"https://www.googleapis.com/auth/contacts.readonly",
	],
};

// ═══════════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════════

function mask(value: string): string {
	if (value.length <= 6) return "********";
	return `${value.slice(0, 4)}..${value.slice(-3)}`;
}

async function promptSecret(prompt: string): Promise<string> {
	const { createInterface } = await import("node:readline");
	return new Promise((resolve) => {
		const rl = createInterface({ input: process.stdin, output: process.stdout });
		if (process.stdin.isTTY) {
			process.stdout.write(prompt);
			process.stdin.setRawMode(true);
			let secret = "";
			process.stdin.resume();
			process.stdin.on("data", function handler(char) {
				const c = char.toString();
				if (c === "\n" || c === "\r" || c === "\u0004") {
					process.stdin.setRawMode(false);
					process.stdin.removeListener("data", handler);
					rl.close();
					console.log();
					resolve(secret);
				} else if (c === "\u0003") {
					process.exit(1);
				} else if (c === "\u007F" || c === "\b") {
					secret = secret.slice(0, -1);
				} else {
					secret += c;
				}
			});
		} else {
			rl.question(prompt, (answer) => {
				rl.close();
				resolve(answer);
			});
		}
	});
}

// ═══════════════════════════════════════════════════════════════════════════════
// Command
// ═══════════════════════════════════════════════════════════════════════════════

export function registerSetupGoogleCommand(program: Command): void {
	program
		.command("setup-google")
		.description("Configure Google OAuth2 for Gmail, Calendar, Drive, Contacts")
		.option("--delete", "Remove stored Google credentials from vault")
		.option("--show", "Show current Google auth status")
		.option("--check", "Verify Google credentials are working")
		.option(
			"--scopes <bundle>",
			"Scope bundle: read_core (default), read_plus_download, actions_v1",
			"read_core",
		)
		.option("--port <port>", "Callback server port", "3000")
		.option("--no-browser", "Print authorization URL instead of opening browser")
		.action(
			async (opts: {
				delete?: boolean;
				show?: boolean;
				check?: boolean;
				scopes: string;
				port: string;
				browser: boolean;
			}) => {
				try {
					const service = getService("google");
					if (!service) {
						console.error("Google service not found in OAuth registry.");
						process.exit(1);
					}

					// Handle --delete
					if (opts.delete) {
						if (!(await isVaultAvailable())) {
							console.error("Error: Vault daemon is not running.");
							process.exit(1);
						}
						const client = getVaultClient();
						const result = await client.delete("http", service.vaultTarget);
						if (result.deleted) {
							console.log("Google credentials removed from vault.");
						} else {
							console.log("No Google credentials were stored.");
						}
						return;
					}

					// Handle --check
					if (opts.check) {
						if (!(await isVaultAvailable())) {
							console.error("Error: Vault daemon is not running.");
							process.exit(1);
						}
						const client = getVaultClient();
						const tokenResult = await client.getToken(service.vaultTarget);
						if (tokenResult.ok) {
							console.log("Google credentials are valid.");
							console.log(`Token expires: ${new Date(tokenResult.expiresAt).toISOString()}`);
						} else {
							console.log(`Google credentials error: ${tokenResult.error}`);
						}
						return;
					}

					// Handle --show
					if (opts.show) {
						if (!(await isVaultAvailable())) {
							console.error("Error: Vault daemon is not running.");
							process.exit(1);
						}
						const client = getVaultClient();
						const entry = await client.get("http", service.vaultTarget);
						if (entry.ok) {
							const cred = entry.entry.credential;
							console.log("Google OAuth2 credentials:");
							console.log(`  Target: ${service.vaultTarget}`);
							console.log(`  Type: ${cred.type}`);
							if (cred.type === "oauth2") {
								console.log(`  Client ID: ${mask(cred.clientId)}`);
								console.log(`  Scope: ${cred.scope ?? "(default)"}`);
							}
							console.log(`  Created: ${entry.entry.createdAt}`);
						} else {
							console.log("No Google credentials configured.");
							console.log("Run: telclaude setup-google");
						}
						return;
					}

					// Interactive setup
					if (!(await isVaultAvailable())) {
						console.error("Error: Vault daemon is not running.");
						console.error("Start it with: telclaude vault-daemon");
						process.exit(1);
					}

					// Resolve scope bundle
					const scopes = SCOPE_BUNDLES[opts.scopes];
					if (!scopes) {
						console.error(`Unknown scope bundle: ${opts.scopes}`);
						console.error(`Available: ${Object.keys(SCOPE_BUNDLES).join(", ")}`);
						process.exit(1);
					}

					const port = Number.parseInt(opts.port, 10);
					if (Number.isNaN(port) || port < 1 || port > 65535) {
						console.error("Invalid port.");
						process.exit(1);
					}

					console.log("Google OAuth2 Setup");
					console.log("===================");
					console.log(`Scope bundle: ${opts.scopes} (${scopes.length} scopes)`);
					console.log();

					const clientId = await promptSecret("Google Client ID: ");
					if (!clientId) {
						console.error("Client ID is required.");
						process.exit(1);
					}

					const clientSecret = await promptSecret("Google Client Secret: ");
					if (!clientSecret) {
						console.error("Client Secret is required.");
						process.exit(1);
					}

					const callbackUrl = getCallbackUrl(port);
					console.log();
					console.log(`Callback URL (register in Google Cloud Console):`);
					console.log(`  ${callbackUrl}`);
					console.log();

					const result = await authorize({
						service,
						clientId,
						clientSecret,
						scopes,
						port,
						timeout: 120,
						noBrowser: !opts.browser,
						onAuthUrl: !opts.browser
							? (url) => {
									console.log("Open this URL in your browser:");
									console.log(`  ${url}`);
									console.log();
								}
							: undefined,
					});

					// Store in vault
					const client = getVaultClient();
					await client.store({
						protocol: "http",
						target: service.vaultTarget,
						label: service.vaultLabel,
						credential: {
							type: "oauth2",
							clientId,
							clientSecret,
							refreshToken: result.refreshToken,
							tokenEndpoint: service.tokenEndpoint,
							scope: result.scope,
						},
					});

					console.log();
					console.log("Google credentials stored in vault.");
					if (result.userId) {
						console.log(`Authenticated as: ${result.userId}`);
					}
					console.log();
					console.log("Next steps:");
					console.log("  1. Deploy google-services sidecar");
					console.log("  2. Add google provider to telclaude.json");

					logger.info(
						{ scopes: opts.scopes, userId: result.userId },
						"Google OAuth2 setup complete",
					);
				} catch (err) {
					logger.error({ error: String(err) }, "setup-google failed");
					console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
					process.exit(1);
				}
			},
		);
}
