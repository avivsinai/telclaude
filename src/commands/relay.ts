import type { Command } from "commander";
import { loadConfig } from "../config/config.js";
import { readEnv } from "../env.js";
import { setVerbose } from "../globals.js";
import { getChildLogger } from "../logging.js";
import { initializeSandbox, isSandboxAvailable, resetSandbox } from "../sandbox/index.js";
import { destroySessionPool } from "../sdk/session-pool.js";
import { isTOTPDaemonAvailable } from "../security/totp.js";
import { monitorTelegramProvider } from "../telegram/auto-reply.js";

const logger = getChildLogger({ module: "cmd-relay" });

export type RelayOptions = {
	verbose?: boolean;
	dryRun?: boolean;
};

export function registerRelayCommand(program: Command): void {
	program
		.command("relay")
		.description("Start the Telegram relay with auto-reply")
		.option("--dry-run", "Don't actually send replies (for testing)")
		.action(async (opts: RelayOptions) => {
			const verbose = program.opts().verbose || opts.verbose;

			if (verbose) {
				setVerbose(true);
			}

			try {
				const cfg = loadConfig();
				readEnv(); // Validates environment variables

				console.log("Starting Telclaude relay...");
				console.log(
					`Security observer: ${cfg.security?.observer?.enabled !== false ? "enabled" : "disabled"}`,
				);
				console.log("Rate limiting: enabled");
				console.log(
					`Audit logging: ${cfg.security?.audit?.enabled !== false ? "enabled" : "disabled"}`,
				);

				// Initialize sandbox for OS-level isolation (MANDATORY)
				const sandboxAvailable = await isSandboxAvailable();
				if (!sandboxAvailable) {
					console.error(
						"\n❌ Sandbox unavailable - telclaude requires OS-level sandboxing for security.\n",
					);
					console.error("Install dependencies:");
					console.error("  macOS: Built-in (Seatbelt) - should work out of the box");
					console.error("  Linux: apt install bubblewrap (Debian/Ubuntu)");
					console.error("         dnf install bubblewrap (Fedora)");
					console.error("         pacman -S bubblewrap (Arch)");
					console.error("  Windows: Not supported\n");
					console.error("Or run in Docker for containerized isolation.");
					process.exit(1);
				}

				await initializeSandbox();
				console.log("Sandbox: enabled (OS-level isolation)");

				// Check TOTP daemon availability
				const totpAvailable = await isTOTPDaemonAvailable();
				if (totpAvailable) {
					console.log("TOTP daemon: connected");
				} else {
					console.log("TOTP daemon: not running (2FA will be unavailable)");
					console.log("  Start with: telclaude totp-daemon");
				}

				if (cfg.telegram?.allowedChats?.length) {
					console.log(`Allowed chats: ${cfg.telegram.allowedChats.join(", ")}`);
				} else {
					console.log("Warning: No allowed chats configured - bot will respond to all chats");
				}

				// Set up graceful shutdown
				const abortController = new AbortController();

				const shutdown = async () => {
					console.log("\nShutting down...");
					abortController.abort();

					// Clean up session pool
					await destroySessionPool();
					logger.info("session pool destroyed");

					// Clean up sandbox
					await resetSandbox();
					logger.info("sandbox reset");
				};

				process.on("SIGINT", () => void shutdown());
				process.on("SIGTERM", () => void shutdown());

				await monitorTelegramProvider({
					verbose,
					keepAlive: true,
					abortSignal: abortController.signal,
				});

				// Final cleanup after monitor exits
				await destroySessionPool();
				await resetSandbox();

				console.log("Relay stopped.");
			} catch (err) {
				logger.error({ error: String(err) }, "relay command failed");
				console.error(`Error: ${err}`);
				process.exit(1);
			}
		});
}
