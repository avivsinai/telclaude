/**
 * CLI commands for managing vault credentials.
 *
 * The vault stores credentials that are injected into HTTP requests
 * through the credential proxy. Agents never see raw credentials.
 *
 * Commands:
 * - telclaude vault list - List configured credentials
 * - telclaude vault add <protocol> <target> - Add a new credential
 * - telclaude vault remove <protocol> <target> - Remove a credential
 * - telclaude vault test <protocol> <target> - Test if vault can retrieve credential
 */

import { createInterface } from "node:readline";
import type { Command } from "commander";

import { getChildLogger } from "../logging.js";
import {
	type Credential,
	getVaultClient,
	isVaultAvailable,
	type Protocol,
	ProtocolSchema,
} from "../vault-daemon/index.js";

const logger = getChildLogger({ module: "cmd-vault" });

// ═══════════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Prompt for a password/secret without echoing to terminal.
 */
async function promptSecret(prompt: string): Promise<string> {
	return new Promise((resolve) => {
		const rl = createInterface({
			input: process.stdin,
			output: process.stdout,
		});

		// Disable echo (best effort - may not work on all terminals)
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
					console.log(); // Newline after hidden input
					resolve(secret);
				} else if (c === "\u0003") {
					// Ctrl+C
					process.exit(1);
				} else if (c === "\u007F" || c === "\b") {
					// Backspace
					secret = secret.slice(0, -1);
				} else {
					secret += c;
				}
			});
		} else {
			// Non-TTY fallback
			rl.question(prompt, (answer) => {
				rl.close();
				resolve(answer);
			});
		}
	});
}

/**
 * Validate protocol string.
 */
function parseProtocol(value: string): Protocol | null {
	const result = ProtocolSchema.safeParse(value.toLowerCase());
	return result.success ? result.data : null;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Command Registration
// ═══════════════════════════════════════════════════════════════════════════════

export function registerVaultCommand(program: Command): void {
	const vault = program.command("vault").description("Manage vault credentials");

	// ═══════════════════════════════════════════════════════════════════════════
	// List command
	// ═══════════════════════════════════════════════════════════════════════════

	vault
		.command("list")
		.description("List configured credentials (secrets not shown)")
		.option("--protocol <protocol>", "Filter by protocol (http, postgres, mysql, ssh)")
		.option("--json", "Output as JSON")
		.action(async (opts: { protocol?: string; json?: boolean }) => {
			try {
				if (!(await isVaultAvailable())) {
					console.error("Error: Vault daemon is not running.");
					console.error("Start it with: telclaude vault-daemon");
					process.exit(1);
				}

				const protocol = opts.protocol ? parseProtocol(opts.protocol) : undefined;
				if (opts.protocol && !protocol) {
					console.error(`Invalid protocol: ${opts.protocol}`);
					console.error("Valid protocols: http, postgres, mysql, ssh");
					process.exit(1);
				}

				const client = getVaultClient();
				const response = await client.list(protocol ?? undefined);

				if (opts.json) {
					console.log(JSON.stringify(response.entries, null, 2));
					return;
				}

				if (response.entries.length === 0) {
					console.log("No credentials configured.");
					return;
				}

				// Table format
				console.log("\nCONFIGURED CREDENTIALS\n");
				console.log(
					"PROTOCOL".padEnd(12) +
						"TARGET".padEnd(35) +
						"TYPE".padEnd(15) +
						"LABEL".padEnd(20) +
						"CREATED",
				);
				console.log("-".repeat(95));

				for (const entry of response.entries) {
					const created = new Date(entry.createdAt).toLocaleDateString();
					console.log(
						entry.protocol.padEnd(12) +
							entry.target.slice(0, 33).padEnd(35) +
							entry.credentialType.padEnd(15) +
							(entry.label ?? "").slice(0, 18).padEnd(20) +
							created,
					);
				}

				console.log();
			} catch (err) {
				logger.error({ error: String(err) }, "vault list failed");
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exit(1);
			}
		});

	// ═══════════════════════════════════════════════════════════════════════════
	// Add command (HTTP)
	// ═══════════════════════════════════════════════════════════════════════════

	vault
		.command("add")
		.description("Add a credential to the vault")
		.argument("<protocol>", "Protocol (http, postgres, mysql, ssh)")
		.argument("<target>", "Target host or host:port")
		.option(
			"--type <type>",
			"Credential type (bearer, api-key, basic, oauth2, db, ssh-key, ssh-password)",
		)
		.option("--label <label>", "Human-readable label")
		.option("--token <token>", "Token/password (will prompt if not provided)")
		.option("--header <header>", "Header name for api-key type (e.g., X-API-Key)")
		.option("--username <username>", "Username for basic/db/ssh auth")
		.option("--param <param>", "Query parameter name for query type")
		.option("--client-id <clientId>", "OAuth2 client ID")
		.option("--client-secret <clientSecret>", "OAuth2 client secret (will prompt if not provided)")
		.option("--refresh-token <refreshToken>", "OAuth2 refresh token (will prompt if not provided)")
		.option("--token-endpoint <url>", "OAuth2 token endpoint URL")
		.option("--scope <scope>", "OAuth2 scope")
		.option("--key <keyPath>", "Path to SSH private key file")
		.option("--passphrase <passphrase>", "SSH key passphrase (will prompt if not provided)")
		.option("--database <database>", "Database name for db credentials")
		.option("--allowed-paths <paths>", "Comma-separated path regex allowlist")
		.option("--rate-limit <limit>", "Requests per minute limit", parseInt)
		.action(
			async (
				protocolArg: string,
				target: string,
				opts: {
					type?: string;
					label?: string;
					token?: string;
					header?: string;
					username?: string;
					param?: string;
					clientId?: string;
					clientSecret?: string;
					refreshToken?: string;
					tokenEndpoint?: string;
					scope?: string;
					key?: string;
					passphrase?: string;
					database?: string;
					allowedPaths?: string;
					rateLimit?: number;
				},
			) => {
				try {
					if (!(await isVaultAvailable())) {
						console.error("Error: Vault daemon is not running.");
						console.error("Start it with: telclaude vault-daemon");
						process.exit(1);
					}

					const protocol = parseProtocol(protocolArg);
					if (!protocol) {
						console.error(`Invalid protocol: ${protocolArg}`);
						console.error("Valid protocols: http, postgres, mysql, ssh");
						process.exit(1);
					}

					// Build credential based on type
					let credential: Credential;

					if (protocol === "http") {
						const type = opts.type ?? "bearer";

						switch (type) {
							case "bearer": {
								const token = opts.token ?? (await promptSecret("Token: "));
								if (!token) {
									console.error("Token is required for bearer auth");
									process.exit(1);
								}
								credential = { type: "bearer", token };
								break;
							}

							case "api-key": {
								const token = opts.token ?? (await promptSecret("API Key: "));
								const header = opts.header ?? "X-API-Key";
								if (!token) {
									console.error("Token is required for api-key auth");
									process.exit(1);
								}
								credential = { type: "api-key", token, header };
								break;
							}

							case "basic": {
								const username = opts.username;
								if (!username) {
									console.error("--username is required for basic auth");
									process.exit(1);
								}
								const password = opts.token ?? (await promptSecret("Password: "));
								credential = { type: "basic", username, password };
								break;
							}

							case "query": {
								const token = opts.token ?? (await promptSecret("Token: "));
								const param = opts.param ?? "api_key";
								if (!token) {
									console.error("Token is required for query auth");
									process.exit(1);
								}
								credential = { type: "query", token, param };
								break;
							}

							case "oauth2": {
								if (!opts.clientId) {
									console.error("--client-id is required for oauth2");
									process.exit(1);
								}
								if (!opts.tokenEndpoint) {
									console.error("--token-endpoint is required for oauth2");
									process.exit(1);
								}
								const clientSecret = opts.clientSecret ?? (await promptSecret("Client Secret: "));
								const refreshToken = opts.refreshToken ?? (await promptSecret("Refresh Token: "));

								if (!clientSecret || !refreshToken) {
									console.error("Client secret and refresh token are required for oauth2");
									process.exit(1);
								}

								credential = {
									type: "oauth2",
									clientId: opts.clientId,
									clientSecret,
									refreshToken,
									tokenEndpoint: opts.tokenEndpoint,
									scope: opts.scope,
								};
								break;
							}

							default:
								console.error(`Invalid HTTP credential type: ${type}`);
								console.error("Valid types: bearer, api-key, basic, query, oauth2");
								process.exit(1);
						}
					} else if (protocol === "postgres" || protocol === "mysql") {
						const username = opts.username;
						if (!username) {
							console.error("--username is required for database credentials");
							process.exit(1);
						}
						const password = opts.token ?? (await promptSecret("Password: "));
						credential = {
							type: "db",
							username,
							password,
							database: opts.database,
						};
					} else if (protocol === "ssh") {
						const type = opts.type ?? "ssh-key";
						const username = opts.username;
						if (!username) {
							console.error("--username is required for SSH credentials");
							process.exit(1);
						}

						if (type === "ssh-key") {
							if (!opts.key) {
								console.error("--key is required for ssh-key auth");
								process.exit(1);
							}
							const fs = await import("node:fs");
							const privateKey = fs.readFileSync(opts.key, "utf-8");
							const passphrase =
								opts.passphrase ?? (await promptSecret("Key passphrase (or empty): "));
							credential = {
								type: "ssh-key",
								username,
								privateKey,
								passphrase: passphrase || undefined,
							};
						} else if (type === "ssh-password") {
							const password = opts.token ?? (await promptSecret("Password: "));
							credential = { type: "ssh-password", username, password };
						} else {
							console.error(`Invalid SSH credential type: ${type}`);
							console.error("Valid types: ssh-key, ssh-password");
							process.exit(1);
						}
					} else {
						console.error(`Protocol ${protocol} is not yet supported`);
						process.exit(1);
					}

					// Parse allowed paths
					const allowedPaths = opts.allowedPaths?.split(",").map((p) => p.trim());

					// Store the credential
					const client = getVaultClient();
					await client.store({
						protocol,
						target,
						credential,
						label: opts.label,
						allowedPaths,
						rateLimitPerMinute: opts.rateLimit,
					});

					console.log(`Credential added: ${protocol}:${target}`);
				} catch (err) {
					logger.error({ error: String(err) }, "vault add failed");
					console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
					process.exit(1);
				}
			},
		);

	// ═══════════════════════════════════════════════════════════════════════════
	// Remove command
	// ═══════════════════════════════════════════════════════════════════════════

	vault
		.command("remove")
		.description("Remove a credential from the vault")
		.argument("<protocol>", "Protocol (http, postgres, mysql, ssh)")
		.argument("<target>", "Target host or host:port")
		.action(async (protocolArg: string, target: string) => {
			try {
				if (!(await isVaultAvailable())) {
					console.error("Error: Vault daemon is not running.");
					console.error("Start it with: telclaude vault-daemon");
					process.exit(1);
				}

				const protocol = parseProtocol(protocolArg);
				if (!protocol) {
					console.error(`Invalid protocol: ${protocolArg}`);
					process.exit(1);
				}

				const client = getVaultClient();
				const response = await client.delete(protocol, target);

				if (response.deleted) {
					console.log(`Credential removed: ${protocol}:${target}`);
				} else {
					console.log(`Credential not found: ${protocol}:${target}`);
				}
			} catch (err) {
				logger.error({ error: String(err) }, "vault remove failed");
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exit(1);
			}
		});

	// ═══════════════════════════════════════════════════════════════════════════
	// Test command
	// ═══════════════════════════════════════════════════════════════════════════

	vault
		.command("test")
		.description("Test if a credential can be retrieved")
		.argument("<protocol>", "Protocol (http, postgres, mysql, ssh)")
		.argument("<target>", "Target host or host:port")
		.action(async (protocolArg: string, target: string) => {
			try {
				if (!(await isVaultAvailable())) {
					console.error("Error: Vault daemon is not running.");
					console.error("Start it with: telclaude vault-daemon");
					process.exit(1);
				}

				const protocol = parseProtocol(protocolArg);
				if (!protocol) {
					console.error(`Invalid protocol: ${protocolArg}`);
					process.exit(1);
				}

				const client = getVaultClient();
				const response = await client.get(protocol, target);

				if (!response.ok) {
					console.log(`FAIL: Credential not found for ${protocol}:${target}`);
					process.exit(1);
				}

				console.log(`OK: Credential found for ${protocol}:${target}`);
				console.log(`  Type: ${response.entry.credential.type}`);
				console.log(`  Created: ${response.entry.createdAt}`);
				if (response.entry.label) {
					console.log(`  Label: ${response.entry.label}`);
				}
				if (response.entry.expiresAt) {
					console.log(`  Expires: ${response.entry.expiresAt}`);
				}
				if (response.entry.allowedPaths?.length) {
					console.log(`  Allowed paths: ${response.entry.allowedPaths.join(", ")}`);
				}
				if (response.entry.rateLimitPerMinute) {
					console.log(`  Rate limit: ${response.entry.rateLimitPerMinute}/min`);
				}

				// For OAuth2, also test token refresh
				if (response.entry.credential.type === "oauth2") {
					console.log("\nTesting OAuth2 token refresh...");
					const tokenResponse = await client.getToken(target);
					if (tokenResponse.ok) {
						console.log(
							`  Token obtained, expires at: ${new Date(tokenResponse.expiresAt).toISOString()}`,
						);
					} else {
						console.log(`  Token refresh FAILED: ${tokenResponse.error}`);
						process.exit(1);
					}
				}
			} catch (err) {
				logger.error({ error: String(err) }, "vault test failed");
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exit(1);
			}
		});
}
