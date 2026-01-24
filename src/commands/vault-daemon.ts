/**
 * CLI command for running the vault daemon.
 *
 * The vault daemon is a sidecar service that stores credentials and handles
 * OAuth token refresh. It communicates via Unix socket and has no network
 * access (except for OAuth token refresh).
 *
 * Usage:
 *   telclaude vault-daemon [--socket <path>]
 */

import type { Command } from "commander";

import { getChildLogger } from "../logging.js";
import { getDefaultSocketPath, startServer } from "../vault-daemon/index.js";

const logger = getChildLogger({ module: "cmd-vault-daemon" });

export function registerVaultDaemonCommand(program: Command): void {
	program
		.command("vault-daemon")
		.description("Run the credential vault daemon")
		.option("--socket <path>", "Path to Unix socket", getDefaultSocketPath())
		.action(async (opts: { socket: string }) => {
			try {
				// Check for encryption key
				if (!process.env.VAULT_ENCRYPTION_KEY) {
					console.error("Error: VAULT_ENCRYPTION_KEY environment variable is required.");
					console.error("Generate a strong key with: openssl rand -base64 32");
					process.exit(1);
				}

				logger.info({ socketPath: opts.socket }, "starting vault daemon");

				const handle = await startServer({
					socketPath: opts.socket,
				});

				console.log(`Vault daemon listening on ${handle.socketPath}`);

				// Handle graceful shutdown
				const shutdown = async (signal: string) => {
					logger.info({ signal }, "received shutdown signal");
					console.log(`\nReceived ${signal}, shutting down...`);
					await handle.stop();
					process.exit(0);
				};

				process.on("SIGINT", () => shutdown("SIGINT"));
				process.on("SIGTERM", () => shutdown("SIGTERM"));

				// Keep process running
				await new Promise(() => {
					// Never resolves - daemon runs until signaled
				});
			} catch (err) {
				logger.error({ error: String(err) }, "vault-daemon command failed");
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exit(1);
			}
		});
}
