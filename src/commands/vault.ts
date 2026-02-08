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

import { readFileSync, unlinkSync } from "node:fs";
import os from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import type { Command } from "commander";

import { getChildLogger } from "../logging.js";
import { getSecret as getKeychainSecret, SECRET_KEYS } from "../secrets/keychain.js";
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
		.argument("<protocol>", "Protocol (http, postgres, mysql, ssh, secret, signing)")
		.argument("<target>", "Target host, key name, or host:port")
		.option(
			"--type <type>",
			"Credential type (bearer, api-key, basic, oauth2, db, ssh-key, ssh-password, opaque)",
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
					} else if (protocol === "secret") {
						const value = opts.token ?? (await promptSecret("Secret value: "));
						if (!value) {
							console.error("Secret value is required");
							process.exit(1);
						}
						credential = { type: "opaque", value };
					} else if (protocol === "signing") {
						console.error("Signing keys are auto-generated by the vault daemon.");
						console.error("Use 'telclaude vault test signing rpc-master' to check.");
						process.exit(1);
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

	// ═══════════════════════════════════════════════════════════════════════════
	// Import secrets from keychain
	// ═══════════════════════════════════════════════════════════════════════════

	vault
		.command("import-secrets")
		.description("Import secrets from the encrypted keychain into the vault")
		.option("--dry-run", "Show what would be imported without actually importing")
		.action(async (opts: { dryRun?: boolean }) => {
			try {
				if (!(await isVaultAvailable())) {
					console.error("Error: Vault daemon is not running.");
					process.exit(1);
				}

				const client = getVaultClient();
				const keychainMap: Array<{
					keychainKey: string;
					vaultProtocol: Protocol;
					vaultTarget: string;
					label: string;
				}> = [
					{
						keychainKey: SECRET_KEYS.OPENAI_API_KEY,
						vaultProtocol: "http",
						vaultTarget: "api.openai.com",
						label: "OpenAI API key",
					},
					{
						keychainKey: SECRET_KEYS.GIT_CREDENTIALS,
						vaultProtocol: "http",
						vaultTarget: "github.com",
						label: "Git credentials",
					},
					{
						keychainKey: SECRET_KEYS.MOLTBOOK_API_KEY,
						vaultProtocol: "secret",
						vaultTarget: "moltbook-api-key",
						label: "Moltbook API key",
					},
				];

				let imported = 0;
				let skipped = 0;

				for (const { keychainKey, vaultProtocol, vaultTarget, label } of keychainMap) {
					const value = await getKeychainSecret(keychainKey);
					if (!value) {
						console.log(`  SKIP: ${label} (not in keychain)`);
						skipped++;
						continue;
					}

					if (opts.dryRun) {
						console.log(`  WOULD IMPORT: ${label} → ${vaultProtocol}:${vaultTarget}`);
						imported++;
						continue;
					}

					let credential: Credential;
					if (vaultProtocol === "http" && vaultTarget === "api.openai.com") {
						credential = { type: "bearer", token: value };
					} else if (vaultProtocol === "http" && vaultTarget === "github.com") {
						try {
							const parsed = JSON.parse(value) as { token?: string };
							if (!parsed.token) {
								console.log(`  SKIP: ${label} (no token field)`);
								skipped++;
								continue;
							}
							credential = { type: "bearer", token: parsed.token };
						} catch {
							credential = { type: "bearer", token: value };
						}
					} else if (vaultProtocol === "secret") {
						credential = { type: "opaque", value };
					} else {
						console.log(`  SKIP: ${label} (unsupported protocol)`);
						skipped++;
						continue;
					}

					await client.store({
						protocol: vaultProtocol,
						target: vaultTarget,
						credential,
						label,
					});
					console.log(`  IMPORTED: ${label} → ${vaultProtocol}:${vaultTarget}`);
					imported++;
				}

				// Also import bot token from env/config if available
				const botToken = process.env.TELEGRAM_BOT_TOKEN;
				if (botToken) {
					if (opts.dryRun) {
						console.log("  WOULD IMPORT: Telegram bot token → secret:telegram-bot-token");
						imported++;
					} else {
						await client.store({
							protocol: "secret",
							target: "telegram-bot-token",
							credential: { type: "opaque", value: botToken },
							label: "Telegram bot token",
						});
						console.log("  IMPORTED: Telegram bot token → secret:telegram-bot-token");
						imported++;
					}
				}

				console.log(
					`\n${opts.dryRun ? "Would import" : "Imported"}: ${imported}, Skipped: ${skipped}`,
				);
			} catch (err) {
				logger.error({ error: String(err) }, "vault import-secrets failed");
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exit(1);
			}
		});

	// ═══════════════════════════════════════════════════════════════════════════
	// Import Anthropic credentials from claude login
	// ═══════════════════════════════════════════════════════════════════════════

	vault
		.command("import-anthropic")
		.description("Import Anthropic credentials from claude login into the vault")
		.option("--path <path>", "Path to .credentials.json file")
		.action(async (opts: { path?: string }) => {
			try {
				if (!(await isVaultAvailable())) {
					console.error("Error: Vault daemon is not running.");
					process.exit(1);
				}

				const candidates = [
					opts.path,
					process.env.CLAUDE_CODE_CREDENTIALS_PATH,
					join(process.env.TELCLAUDE_AUTH_DIR ?? "", ".credentials.json"),
					join(process.env.TELCLAUDE_AUTH_DIR ?? "", ".claude", ".credentials.json"),
					join(process.env.HOME ?? os.homedir(), ".claude", ".credentials.json"),
				].filter((p): p is string => typeof p === "string" && p.length > 1);

				type OAuthCreds = {
					accessToken: string;
					refreshToken: string;
					expiresAt: number;
					scopes?: string[];
				};

				let oauthCreds: OAuthCreds | undefined;
				let source: string | undefined;

				for (const candidate of candidates) {
					try {
						const raw = readFileSync(candidate, "utf8");
						const parsed = JSON.parse(raw) as Record<string, unknown>;

						// Standard claude login: { claudeAiOauth: { accessToken, refreshToken, expiresAt } }
						const nested = parsed.claudeAiOauth as Record<string, unknown> | undefined;
						const obj = nested ?? parsed;

						if (
							typeof obj.accessToken === "string" &&
							typeof obj.refreshToken === "string" &&
							typeof obj.expiresAt === "number"
						) {
							oauthCreds = obj as unknown as OAuthCreds;
							source = candidate;
							break;
						}
					} catch {
						// Try next candidate
					}
				}

				if (!oauthCreds) {
					const apiKey = process.env.ANTHROPIC_API_KEY;
					if (apiKey) {
						const client = getVaultClient();
						await client.store({
							protocol: "http",
							target: "api.anthropic.com",
							credential: { type: "api-key", token: apiKey, header: "x-api-key" },
							label: "Anthropic API key (from env)",
						});
						console.log("  IMPORTED: Anthropic API key → http:api.anthropic.com");
						return;
					}

					console.error("No Anthropic credentials found.");
					console.error("\nSearched:");
					for (const c of candidates) {
						console.error(`  - ${c}`);
					}
					console.error("  - ANTHROPIC_API_KEY env var");
					console.error("\nRun 'claude login' first, or provide --path.");
					process.exit(1);
				}

				const client = getVaultClient();
				await client.store({
					protocol: "secret",
					target: "anthropic-oauth",
					credential: { type: "opaque", value: JSON.stringify(oauthCreds) },
					label: "Anthropic OAuth (claude login)",
				});
				console.log(`  IMPORTED: OAuth credentials from ${source} → secret:anthropic-oauth`);

				// Delete the credentials file (secrets now live in vault)
				if (source) {
					try {
						unlinkSync(source);
						console.log(`  DELETED: ${source} (credentials moved to vault)`);
					} catch {
						console.warn(`  WARNING: Could not delete ${source}`);
					}
				}
			} catch (err) {
				logger.error({ error: String(err) }, "vault import-anthropic failed");
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exit(1);
			}
		});
}
