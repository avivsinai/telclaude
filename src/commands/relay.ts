import { execSync } from "node:child_process";
import fsSync from "node:fs";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { Command } from "commander";
import { loadConfig } from "../config/config.js";
import { readEnv } from "../env.js";
import { setVerbose } from "../globals.js";
import { getChildLogger } from "../logging.js";
import {
	DEFAULT_NETWORK_CONFIG,
	buildAllowedDomainNames,
	buildAllowedDomains,
	getNetworkIsolationSummary,
	getSandboxMode,
	getSandboxRuntimeVersion,
} from "../sandbox/index.js";
import { destroySessionManager } from "../sdk/session-manager.js";
import { isTOTPDaemonAvailable } from "../security/totp.js";
import { monitorTelegramProvider } from "../telegram/auto-reply.js";
import { CONFIG_DIR } from "../utils.js";

const logger = getChildLogger({ module: "cmd-relay" });

/**
 * Check if a binary is available on PATH.
 */
function isBinaryAvailable(name: string): boolean {
	try {
		execSync(`which ${name}`, { stdio: "ignore" });
		return true;
	} catch {
		return false;
	}
}

/**
 * Check host dependencies for native sandbox mode.
 * Returns list of missing dependencies.
 */
interface SandboxDepsCheck {
	criticalMissing: string[]; // Security-critical, hard fail
	optionalMissing: string[]; // Nice-to-have, warn only
}

function checkNativeSandboxDeps(): SandboxDepsCheck {
	const criticalMissing: string[] = [];
	const optionalMissing: string[] = [];
	const platform = os.platform();

	if (platform === "linux") {
		// Linux REQUIRES bubblewrap for sandbox (security-critical)
		if (!isBinaryAvailable("bwrap")) {
			criticalMissing.push("bubblewrap (bwrap)");
		}
		// socat needed for network proxy (security-critical for network isolation)
		if (!isBinaryAvailable("socat")) {
			criticalMissing.push("socat");
		}
	}
	// ripgrep is nice-to-have for Grep tool but not security-critical
	if (!isBinaryAvailable("rg")) {
		optionalMissing.push("ripgrep (rg)");
	}

	return { criticalMissing, optionalMissing };
}

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
				const additionalDomains = cfg.security?.network?.additionalDomains ?? [];
				const allowedDomainNames = buildAllowedDomainNames(additionalDomains);
				const allowedDomains = buildAllowedDomains(additionalDomains);
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

				// Detect sandbox mode and verify sandbox availability
				const sandboxMode = getSandboxMode();
				if (sandboxMode === "docker") {
					console.log("Sandbox: Docker mode (SDK sandbox disabled, container provides isolation)");
					// SECURITY: Docker mode REQUIRES firewall for network isolation
					// Without firewall, Bash can reach arbitrary endpoints including private/metadata
					if (process.env.TELCLAUDE_FIREWALL !== "1") {
						if (process.env.TELCLAUDE_ACCEPT_NO_FIREWALL === "1") {
							console.warn("  ⚠️  TELCLAUDE_FIREWALL not enabled - Bash has NO network isolation");
							console.warn("     Running anyway due to TELCLAUDE_ACCEPT_NO_FIREWALL=1");
							console.warn("     THIS IS A SECURITY RISK - use only for testing");
							// AUDIT: Log the security bypass
							logger.warn(
								{ bypass: "TELCLAUDE_ACCEPT_NO_FIREWALL" },
								"SECURITY BYPASS: Running Docker mode without network firewall",
							);
						} else {
							console.error("\n❌ SECURITY ERROR: Docker mode requires network firewall.\n");
							console.error("In Docker mode, the SDK sandbox is disabled.");
							console.error(
								"Without TELCLAUDE_FIREWALL=1, Bash commands have NO network isolation",
							);
							console.error("and can reach arbitrary endpoints (including cloud metadata).\n");
							console.error("To fix:");
							console.error("  - Set TELCLAUDE_FIREWALL=1 in your docker/.env file");
							console.error("  - Ensure init-firewall.sh runs (requires NET_ADMIN capability)\n");
							console.error("To bypass (TESTING ONLY - NOT FOR PRODUCTION):");
							console.error("  - Set TELCLAUDE_ACCEPT_NO_FIREWALL=1\n");
							process.exit(1);
						}
					} else {
						// TELCLAUDE_FIREWALL=1 - verify firewall is actually applied via sentinel file
						const sentinelPath = "/run/telclaude/firewall-active";
						if (!fsSync.existsSync(sentinelPath)) {
							console.error("\n❌ SECURITY ERROR: Firewall enabled but not verified.\n");
							console.error(
								"TELCLAUDE_FIREWALL=1 is set, but the firewall sentinel file is missing.",
							);
							console.error(`Expected: ${sentinelPath}\n`);
							console.error("This means init-firewall.sh failed or didn't run.");
							console.error("Possible causes:");
							console.error("  - Container missing --cap-add=NET_ADMIN capability");
							console.error("  - iptables not available in container");
							console.error("  - init-firewall.sh not executed at container start\n");
							console.error("To fix:");
							console.error("  - Ensure docker-compose.yml has cap_add: [NET_ADMIN]");
							console.error("  - Check container logs for firewall setup errors\n");
							process.exit(1);
						}
						console.log("  Firewall: verified (sentinel file present)");
					}
				} else {
					// Native mode: verify SDK sandbox runtime is available
					const sandboxVersion = getSandboxRuntimeVersion();
					if (!sandboxVersion) {
						console.error("\n❌ SECURITY ERROR: Sandbox runtime not available.\n");
						console.error(
							"In native mode, the SDK sandbox (@anthropic-ai/sandbox-runtime) is required.",
						);
						console.error(
							"This provides filesystem and network isolation via bubblewrap (Linux) or Seatbelt (macOS).\n",
						);
						console.error("To fix:");
						console.error(
							"  - Run: pnpm install (sandbox-runtime should be installed as a dependency)",
						);
						console.error("  - On Linux: ensure bubblewrap is installed (apt install bubblewrap)");
						console.error("  - Alternatively, run in Docker mode for container-based isolation\n");
						process.exit(1);
					}
					console.log(`Sandbox: Native mode (SDK sandbox v${sandboxVersion})`);

					// Check for host dependencies (bwrap, socat, rg)
					const { criticalMissing, optionalMissing } = checkNativeSandboxDeps();

					// Security-critical deps are a hard fail
					if (criticalMissing.length > 0) {
						console.error(
							`\n❌ SECURITY ERROR: Missing critical sandbox dependencies: ${criticalMissing.join(", ")}\n`,
						);
						console.error("These are required for secure sandbox operation on Linux.");
						console.error(
							"Without them, the sandbox cannot provide filesystem/network isolation.\n",
						);
						console.error("To fix:");
						console.error("  - Install: apt install bubblewrap socat");
						console.error("  - Or run in Docker mode for container-based isolation\n");
						process.exit(1);
					}

					// Optional deps are just a warning
					if (optionalMissing.length > 0) {
						console.warn(`  ⚠️  Missing optional: ${optionalMissing.join(", ")}`);
						if (os.platform() === "linux") {
							console.warn("     Install: apt install ripgrep");
						} else {
							console.warn("     Install: brew install ripgrep");
						}
					}
				}

				// Network policy - default is strict allowlist
				const netSummary = getNetworkIsolationSummary(
					{ ...DEFAULT_NETWORK_CONFIG, allowedDomains },
					allowedDomainNames,
				);
				if (netSummary.isPermissive) {
					console.log("Network: OPEN (wildcard egress; metadata endpoints still blocked)");
				} else {
					console.log(`Network: RESTRICTED (${netSummary.allowedDomains} domains allowed)`);
				}
				if (additionalDomains.length > 0) {
					console.log(`  Additional domains: ${additionalDomains.length}`);
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

				// Check skills availability
				const skillsDir = path.join(process.cwd(), ".claude", "skills");
				try {
					const skillDirs = await fs.readdir(skillsDir, { withFileTypes: true });
					const skills = skillDirs
						.filter((entry) => entry.isDirectory() && !entry.name.startsWith("."))
						.map((entry) => entry.name)
						.sort();
					if (skills.length > 0) {
						console.log(`Skills: ${skills.length} available (${skills.join(", ")})`);
					} else {
						console.log("Skills: none found in .claude/skills/");
					}
				} catch (err) {
					const errno = err as NodeJS.ErrnoException | undefined;
					if (errno?.code === "ENOENT") {
						console.log("Skills: directory not found (.claude/skills/)");
						console.log("  Skills like image-generator won't be available");
					} else {
						console.log("Skills: unable to read .claude/skills/");
						logger.warn({ error: String(err) }, "skills directory read failed");
					}
				}

				if (cfg.telegram?.allowedChats?.length) {
					console.log(`Allowed chats: ${cfg.telegram.allowedChats.join(", ")}`);
				} else {
					console.log(
						`Warning: No allowed chats configured - bot will DENY all chats (fail-closed). Add chat IDs to ${CONFIG_DIR}/telclaude.json to permit access.`,
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
				};

				process.on("SIGINT", () => void shutdown());
				process.on("SIGTERM", () => void shutdown());

				await monitorTelegramProvider({
					verbose,
					keepAlive: true,
					abortSignal: abortController.signal,
					securityProfile: effectiveProfile,
					dryRun: opts.dryRun ?? false,
				});

				// Final cleanup after monitor exits
				await destroySessionManager();

				console.log("Relay stopped.");
			} catch (err) {
				logger.error({ error: String(err) }, "relay command failed");
				console.error(`Error: ${err}`);
				process.exit(1);
			}
		});
}
