/**
 * CLI command to run the TOTP daemon.
 *
 * The daemon manages TOTP secrets in the OS keychain and exposes
 * a verification-only API over a Unix socket.
 */

import type { Command } from "commander";
import { setVerbose } from "../globals.js";
import { getChildLogger } from "../logging.js";
import { getDefaultSocketPath, startServer } from "../totp-daemon/index.js";

const logger = getChildLogger({ module: "cmd-totp-daemon" });

export type TOTPDaemonOptions = {
	verbose?: boolean;
	socketPath?: string;
};

export function registerTOTPDaemonCommand(program: Command): void {
	program
		.command("totp-daemon")
		.description("Start the TOTP daemon (manages 2FA secrets)")
		.option("--socket-path <path>", `Unix socket path (default: ${getDefaultSocketPath()})`)
		.action(async (opts: TOTPDaemonOptions) => {
			const verbose = program.opts().verbose || opts.verbose;

			if (verbose) {
				setVerbose(true);
			}

			try {
				console.log("Starting TOTP daemon...");

				// Use same resolution as client: CLI option → env var → default
				const socketPath =
					opts.socketPath ?? process.env.TELCLAUDE_TOTP_SOCKET ?? getDefaultSocketPath();

				const handle = await startServer({
					socketPath,
				});

				console.log(`TOTP daemon listening on: ${handle.socketPath}`);
				console.log("Secrets stored in: OS keychain (keytar)");
				console.log("Press Ctrl+C to stop.");

				// Set up graceful shutdown
				const shutdown = async () => {
					console.log("\nShutting down TOTP daemon...");
					await handle.stop();
					process.exit(0);
				};

				process.on("SIGINT", shutdown);
				process.on("SIGTERM", shutdown);

				// Keep the process running
				await new Promise(() => {
					// Never resolves - daemon runs until signal
				});
			} catch (err) {
				logger.error({ error: String(err) }, "totp-daemon command failed");
				console.error(`Error: ${err}`);
				process.exit(1);
			}
		});
}
