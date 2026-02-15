/**
 * CLI commands for OAuth2 authorization flows.
 *
 * Automates the full OAuth2 Authorization Code + PKCE flow:
 * PKCE generation, browser redirect, callback capture, token exchange, vault storage.
 *
 * Commands:
 * - telclaude oauth authorize <service> - Run the full flow
 * - telclaude oauth list - Show known services + vault status
 * - telclaude oauth revoke <service> - Revoke + remove from vault
 */

import { createInterface } from "node:readline";
import type { Command } from "commander";

import { getChildLogger } from "../logging.js";
import { authorize, getCallbackUrl } from "../oauth/flow.js";
import { getService, listServices } from "../oauth/registry.js";
import { getVaultClient, isVaultAvailable } from "../vault-daemon/index.js";

const logger = getChildLogger({ module: "cmd-oauth" });

// ═══════════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Prompt for a secret without echoing to terminal.
 */
async function promptSecret(prompt: string): Promise<string> {
	return new Promise((resolve) => {
		const rl = createInterface({
			input: process.stdin,
			output: process.stdout,
		});

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

function mask(value: string): string {
	if (value.length <= 6) return "********";
	return `${value.slice(0, 4)}..${value.slice(-3)}`;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Command Registration
// ═══════════════════════════════════════════════════════════════════════════════

export function registerOAuthCommand(program: Command): void {
	const oauth = program.command("oauth").description("OAuth2 authorization flows");

	// ═══════════════════════════════════════════════════════════════════════════
	// Authorize
	// ═══════════════════════════════════════════════════════════════════════════

	oauth
		.command("authorize")
		.description("Run OAuth2 Authorization Code + PKCE flow")
		.argument("<service>", "Service ID (e.g., xtwitter)")
		.option("--client-id <id>", "OAuth2 client ID (or prompted interactively)")
		.option("--client-secret <secret>", "OAuth2 client secret (or prompted securely)")
		.option("--scope <scopes>", "Override default scopes (space-separated)")
		.option("--port <port>", "Callback server port", "3000")
		.option("--timeout <seconds>", "Callback timeout in seconds", "120")
		.option("--no-browser", "Print authorization URL instead of opening browser")
		.option("--skip-vault", "Print tokens instead of storing in vault")
		.option("--skip-user-id", "Skip fetching user ID after authorization")
		.action(
			async (
				serviceId: string,
				opts: {
					clientId?: string;
					clientSecret?: string;
					scope?: string;
					port: string;
					timeout: string;
					browser: boolean;
					skipVault?: boolean;
					skipUserId?: boolean;
				},
			) => {
				try {
					// Resolve service definition
					const service = getService(serviceId);
					if (!service) {
						const known = listServices()
							.map((s) => s.id)
							.join(", ");
						console.error(`Unknown service: ${serviceId}`);
						console.error(`Known services: ${known || "(none)"}`);
						process.exit(1);
					}

					// Check vault availability (unless skipping)
					if (!opts.skipVault && !(await isVaultAvailable())) {
						console.error("Error: Vault daemon is not running.");
						console.error("Start it with: telclaude vault-daemon");
						console.error("Or use --skip-vault to print tokens instead.");
						process.exit(1);
					}

					const port = Number.parseInt(opts.port, 10);
					const timeout = Number.parseInt(opts.timeout, 10);

					if (Number.isNaN(port) || port < 1 || port > 65535) {
						console.error("Invalid port. Must be 1-65535.");
						process.exit(1);
					}
					if (Number.isNaN(timeout) || timeout <= 0) {
						console.error("Invalid timeout. Must be a positive number of seconds.");
						process.exit(1);
					}

					const callbackUrl = getCallbackUrl(port);
					const scopes = opts.scope?.split(" ") ?? service.defaultScopes;

					// Collect credentials
					const clientId = opts.clientId ?? (await promptSecret("Client ID: "));
					if (!clientId) {
						console.error("Client ID is required.");
						process.exit(1);
					}

					let clientSecret = "";
					if (service.confidentialClient) {
						clientSecret = opts.clientSecret ?? (await promptSecret("Client Secret: "));
						if (!clientSecret) {
							console.error("Client Secret is required for confidential clients.");
							process.exit(1);
						}
					}

					// Print flow summary
					console.log();
					console.log(`${service.displayName} OAuth2 Authorization`);
					console.log("=".repeat(40));
					console.log(`Callback URL (must be registered in Developer Console):`);
					console.log(`  ${callbackUrl}`);
					console.log();
					console.log(`Client ID: ${mask(clientId)}`);
					if (service.confidentialClient) {
						console.log(`Client Secret: ********`);
					}
					console.log(`Scopes: ${scopes.join(" ")}`);
					console.log();

					console.log(`Starting callback server on port ${port}...`);
					if (opts.browser) {
						console.log("Opening browser...");
					} else {
						console.log("Browser launch disabled — URL will be printed below.");
					}
					console.log();
					console.log(`Waiting for authorization (timeout: ${timeout} seconds)...`);
					console.log();

					// Build modified service if skipping user ID
					const effectiveService = opts.skipUserId
						? { ...service, userIdEndpoint: undefined }
						: service;

					// Run the flow
					const result = await authorize({
						service: effectiveService,
						clientId,
						clientSecret,
						scopes,
						port,
						timeout,
						noBrowser: !opts.browser,
						onAuthUrl: !opts.browser
							? (url) => {
									console.log("Open this URL in your browser:");
									console.log(`  ${url}`);
									console.log();
								}
							: undefined,
					});

					// Success output
					console.log("Authorization code received");
					console.log("Token exchange successful");

					if (result.userId) {
						const display = result.username
							? `${result.userId} (@${result.username})`
							: result.userId;
						console.log(`User ID: ${display}`);
					}

					// Store in vault
					if (!opts.skipVault) {
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
							allowedPaths: service.vaultAllowedPaths,
						});
						console.log(`Credentials stored in vault: http:${service.vaultTarget}`);
					} else {
						console.log();
						console.log("--- Tokens (--skip-vault) ---");
						console.log(`Access Token: ${result.accessToken}`);
						console.log(`Refresh Token: ${result.refreshToken}`);
						console.log(`Expires In: ${result.expiresIn}s`);
						console.log(`Scope: ${result.scope}`);
					}

					// Next steps
					if (service.userIdEnvVar && result.userId) {
						console.log();
						console.log("Next steps:");
						console.log(`  1. Set ${service.userIdEnvVar}=${result.userId} in docker/.env`);
						console.log("  2. Restart social agent container");
					}
				} catch (err) {
					logger.error({ error: String(err) }, "oauth authorize failed");
					console.error(`\nError: ${err instanceof Error ? err.message : String(err)}`);
					process.exit(1);
				}
			},
		);

	// ═══════════════════════════════════════════════════════════════════════════
	// List
	// ═══════════════════════════════════════════════════════════════════════════

	oauth
		.command("list")
		.description("Show known OAuth2 services and vault status")
		.action(async () => {
			try {
				const services = listServices();
				const vaultUp = await isVaultAvailable();

				let vaultEntries: Map<string, string> | undefined;
				if (vaultUp) {
					const client = getVaultClient();
					const list = await client.list("http");
					vaultEntries = new Map();
					for (const entry of list.entries) {
						if (entry.credentialType === "oauth2") {
							vaultEntries.set(entry.target, entry.createdAt);
						}
					}
				}

				console.log("Known OAuth2 services:");
				console.log();

				for (const svc of services) {
					const stored = vaultEntries?.get(svc.vaultTarget);
					const status = vaultUp
						? stored
							? `stored (${new Date(stored).toLocaleDateString()})`
							: "not configured"
						: "vault unavailable";

					console.log(`  ${svc.id} (${svc.displayName})`);
					console.log(`    Target: ${svc.vaultTarget}`);
					console.log(`    Scopes: ${svc.defaultScopes.join(" ")}`);
					console.log(`    Vault:  ${status}`);
					console.log();
				}
			} catch (err) {
				logger.error({ error: String(err) }, "oauth list failed");
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exit(1);
			}
		});

	// ═══════════════════════════════════════════════════════════════════════════
	// Revoke
	// ═══════════════════════════════════════════════════════════════════════════

	oauth
		.command("revoke")
		.description("Remove OAuth2 credentials from vault")
		.argument("<service>", "Service ID (e.g., xtwitter)")
		.action(async (serviceId: string) => {
			try {
				const service = getService(serviceId);
				if (!service) {
					console.error(`Unknown service: ${serviceId}`);
					process.exit(1);
				}

				if (!(await isVaultAvailable())) {
					console.error("Error: Vault daemon is not running.");
					process.exit(1);
				}

				const client = getVaultClient();
				const result = await client.delete("http", service.vaultTarget);

				if (result.deleted) {
					console.log(`Removed: http:${service.vaultTarget}`);
					console.log(
						"Note: The refresh token may still be valid on the provider side. " +
							"Revoke it in the service's developer console if needed.",
					);
				} else {
					console.log(`No credential found for http:${service.vaultTarget}`);
				}
			} catch (err) {
				logger.error({ error: String(err) }, "oauth revoke failed");
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exit(1);
			}
		});
}
