import type { Command } from "commander";
import { loadConfig } from "../config/config.js";
import { readEnv } from "../env.js";
import { setVerbose } from "../globals.js";
import { getChildLogger } from "../logging.js";
import {
	getNetworkIsolationSummary,
	initializeSandbox,
	isSandboxAvailable,
	resetSandbox,
} from "../sandbox/index.js";
import { destroySessionManager } from "../sdk/session-manager.js";
import { isTOTPDaemonAvailable } from "../security/totp.js";
import { monitorTelegramProvider } from "../telegram/auto-reply.js";

const logger = getChildLogger({ module: "cmd-relay" });

export type RelayOptions = {
	verbose?: boolean;
	dryRun?: boolean;
	profile?: "simple" | "strict" | "test";
};

export function registerRelayCommand(program: Command): void {
	program
		.command("relay")
		.description("Start the Telegram relay with auto-reply")
		.option("--dry-run", "Don't actually send replies (for testing)")
		.option("--profile <profile>", "Security profile: simple, strict, or test (overrides config)")
		.action(async (opts: RelayOptions) => {
			const verbose = program.opts().verbose || opts.verbose;

			if (verbose) {
				setVerbose(true);
			}

			try {
				const cfg = loadConfig();
				readEnv(); // Validates environment variables

				// SECURITY: Block dangerous defaultTier=FULL_ACCESS config
				if (cfg.security?.permissions?.defaultTier === "FULL_ACCESS") {
					console.error("\n❌ SECURITY ERROR: defaultTier=FULL_ACCESS is not allowed.\n");
					console.error(
						"Setting defaultTier to FULL_ACCESS would give unrestricted access to ALL users,",
					);
					console.error(
						"bypassing all security controls. This is almost certainly not what you want.\n",
					);
					console.error("Instead, assign FULL_ACCESS to specific users:");
					console.error('  "permissions": {');
					console.error('    "defaultTier": "READ_ONLY",');
					console.error('    "users": {');
					console.error('      "tg:YOUR_CHAT_ID": { "tier": "FULL_ACCESS" }');
					console.error("    }");
					console.error("  }\n");
					process.exit(1);
				}

				// SECURITY: Warn on fallbackOnTimeout=allow
				if (cfg.security?.observer?.fallbackOnTimeout === "allow") {
					console.warn("\n⚠️  WARNING: security.observer.fallbackOnTimeout=allow is risky.\n");
					console.warn(
						"If the security observer times out, requests will be ALLOWED without review.",
					);
					console.warn("An attacker could DoS the observer to bypass security checks.");
					console.warn('Consider using "block" (safer) or "escalate" instead.\n');
				}

				// Determine effective security profile (CLI flag overrides config)
				const effectiveProfile = opts.profile ?? cfg.security?.profile ?? "simple";

				// SECURITY: Warn about test profile
				if (effectiveProfile === "test") {
					console.warn("\n⚠️  WARNING: Using 'test' security profile - NO SECURITY ENFORCEMENT.\n");
					console.warn(
						"This profile is for testing only and should NEVER be used in production.\n",
					);
				}

				console.log("Starting Telclaude relay...");
				console.log(`Security profile: ${effectiveProfile}`);
				if (effectiveProfile === "strict") {
					console.log(
						`  Observer: ${cfg.security?.observer?.enabled !== false ? "enabled" : "disabled"}`,
					);
					console.log("  Approvals: enabled");
				}
				console.log("  Rate limiting: enabled");
				console.log(
					`  Audit logging: ${cfg.security?.audit?.enabled !== false ? "enabled" : "disabled"}`,
				);
				console.log("  Secret filtering: enabled (CORE patterns + entropy detection)");

				// Initialize sandbox for OS-level isolation (MANDATORY)
				const sandboxAvailable = await isSandboxAvailable();
				if (!sandboxAvailable) {
					console.error(
						"\n❌ Sandbox unavailable - telclaude requires OS-level sandboxing for security.\n",
					);
					console.error("Install dependencies:");
					console.error("  macOS: brew install ripgrep");
					console.error("         (Seatbelt is built-in)");
					console.error("  Linux: apt install bubblewrap ripgrep socat (Debian/Ubuntu)");
					console.error("         dnf install bubblewrap ripgrep socat (Fedora)");
					console.error("         pacman -S bubblewrap ripgrep socat (Arch)");
					console.error("  Windows: Not supported\n");
					console.error("Required tools:");
					console.error("  - ripgrep (rg): Used by sandbox-runtime for file operations");
					console.error("  - socat: Required on Linux for network proxying\n");
					console.error("Or run in Docker for containerized isolation.");
					process.exit(1);
				}

				const sandboxResult = await initializeSandbox();
				if (sandboxResult.wrapperEnabled) {
					console.log("Sandbox: enabled (full wrapper - all Claude tools sandboxed)");
				} else {
					console.warn("\n⚠️  Sandbox: DEGRADED (Bash-only isolation, wrapper failed)");
					if (sandboxResult.wrapperError) {
						console.warn(`   Reason: ${sandboxResult.wrapperError}`);
					}
					console.warn("   Claude Read/Write/Edit tools run WITHOUT sandbox protection.\n");
				}

				// Network policy - default is strict allowlist
				const netSummary = getNetworkIsolationSummary();
				if (netSummary.isPermissive) {
					console.log("Network: OPEN (wildcard egress; metadata endpoints still blocked)");
				} else {
					console.log(`Network: RESTRICTED (${netSummary.allowedDomains} domains allowed)`);
				}
				if (process.env.TELCLAUDE_NETWORK_MODE) {
					console.log(
						`  Network mode override: TELCLAUDE_NETWORK_MODE=${process.env.TELCLAUDE_NETWORK_MODE}`,
					);
				}

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
					console.log(
						"Warning: No allowed chats configured - bot will DENY all chats (fail-closed). Add chat IDs to ~/.telclaude/telclaude.json to permit access.",
					);
				}

				// Set up graceful shutdown
				const abortController = new AbortController();

				const shutdown = async () => {
					console.log("\nShutting down...");
					abortController.abort();

					// Clean up session pool
					await destroySessionManager();
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
					securityProfile: effectiveProfile,
				});

				// Final cleanup after monitor exits
				await destroySessionManager();
				await resetSandbox();

				console.log("Relay stopped.");
			} catch (err) {
				logger.error({ error: String(err) }, "relay command failed");
				console.error(`Error: ${err}`);
				process.exit(1);
			}
		});
}
