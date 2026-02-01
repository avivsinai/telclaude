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
import { handleMoltbookHeartbeat } from "../moltbook/handler.js";
import { type MoltbookScheduler, startMoltbookScheduler } from "../moltbook/scheduler.js";
import {
	checkProviderHealth,
	computeProviderHealthExitCode,
	formatProviderHealthSummary,
	logProviderHealthResults,
} from "../providers/provider-health.js";
import { refreshExternalProviderSkill } from "../providers/provider-skill.js";
import { startCapabilityServer } from "../relay/capabilities.js";
import { startGitProxyServer } from "../relay/git-proxy.js";
import { startHttpCredentialProxy } from "../relay/http-credential-proxy.js";
import {
	buildAllowedDomainNames,
	buildAllowedDomains,
	DEFAULT_NETWORK_CONFIG,
	getNetworkIsolationSummary,
	getSandboxMode,
	getSandboxRuntimeVersion,
} from "../sandbox/index.js";
import { destroySessionManager } from "../sdk/session-manager.js";
import { isTOTPDaemonAvailable } from "../security/totp.js";
import { monitorTelegramProvider } from "../telegram/auto-reply.js";
import { CONFIG_DIR } from "../utils.js";
import { isVaultAvailable } from "../vault-daemon/index.js";

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
				let moltbookScheduler: MoltbookScheduler | null = null;

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

				const capabilitiesEnabled = process.env.TELCLAUDE_CAPABILITIES_ENABLED !== "0";
				if (capabilitiesEnabled) {
					startCapabilityServer();
					console.log("  Capabilities: enabled (relay broker)");

					// Start git proxy if in Docker mode with remote agent
					// This allows secure git operations without exposing tokens to the agent
					if (process.env.TELCLAUDE_AGENT_URL) {
						startGitProxyServer();
						console.log("  Git proxy: enabled (transparent auth injection)");

						// Start HTTP credential proxy if vault daemon is available
						// This allows agents to call HTTP APIs without seeing credentials
						const vaultSocketPath = process.env.TELCLAUDE_VAULT_SOCKET;
						const vaultAvailable = await isVaultAvailable(
							vaultSocketPath ? { socketPath: vaultSocketPath } : undefined,
						);
						if (vaultAvailable) {
							startHttpCredentialProxy({ vaultSocketPath });
							console.log("  HTTP proxy: enabled (credential injection via vault)");
						} else {
							console.log("  HTTP proxy: disabled (vault daemon not running)");
						}
					}
				} else {
					console.log("  Capabilities: disabled");
				}

				if (cfg.moltbook?.enabled) {
					const intervalHours = cfg.moltbook.heartbeatIntervalHours ?? 4;
					const intervalMs = intervalHours * 60 * 60 * 1000;
					moltbookScheduler = startMoltbookScheduler({
						intervalMs,
						onHeartbeat: async () => {
							const result = await handleMoltbookHeartbeat();
							if (!result.ok) {
								logger.warn({ message: result.message }, "moltbook heartbeat reported errors");
							}
						},
					});
					console.log(`  Moltbook: enabled (heartbeat every ${intervalHours}h)`);
				} else {
					console.log("  Moltbook: disabled");
				}

				// Detect sandbox mode and verify sandbox availability
				const sandboxMode = getSandboxMode();
				const usesRemoteAgent = Boolean(process.env.TELCLAUDE_AGENT_URL);
				if (sandboxMode === "docker") {
					if (usesRemoteAgent) {
						console.log("Sandbox: Docker mode (relay-only, SDK runs in agent container)");
					} else {
						console.log(
							"Sandbox: Docker mode (SDK sandbox disabled, container provides isolation)",
						);
					}
					// SECURITY: Docker mode REQUIRES firewall for network isolation
					if (process.env.TELCLAUDE_FIREWALL !== "1") {
						if (process.env.TELCLAUDE_ACCEPT_NO_FIREWALL === "1") {
							console.warn("  ⚠️  TELCLAUDE_FIREWALL not enabled - network isolation is OFF");
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
							console.error("Without TELCLAUDE_FIREWALL=1, container egress is not isolated");
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

				// External providers: update skills and verify health before continuing
				const providers = cfg.providers ?? [];
				if (providers.length > 0) {
					console.log(`Providers: ${providers.length} configured`);
					await refreshExternalProviderSkill(providers);

					const results = await Promise.all(
						providers.map((provider) => checkProviderHealth(provider.id, provider.baseUrl)),
					);

					logProviderHealthResults(results);
					const exitCode = computeProviderHealthExitCode(results);
					const allowDegraded = process.env.TELCLAUDE_ALLOW_DEGRADED_PROVIDERS === "1";
					// Exit code 1 = degraded (warn), exit code 2 = error (unreachable/unhealthy)
					const shouldExit = exitCode === 2 || (exitCode === 1 && !allowDegraded);
					if (shouldExit) {
						console.error(`Provider health check failed: ${formatProviderHealthSummary(results)}`);
						process.exit(exitCode);
					}
					if (exitCode === 1 && allowDegraded) {
						console.warn(
							`Provider health degraded but continuing due to TELCLAUDE_ALLOW_DEGRADED_PROVIDERS=1`,
						);
					}
				}

				// Check TOTP daemon availability
				const totpAvailable = await isTOTPDaemonAvailable();
				if (totpAvailable) {
					console.log("TOTP daemon: connected");
				} else {
					console.log("TOTP daemon: not running (2FA will be unavailable)");
					console.log("  Start with: telclaude totp-daemon");
				}

				// Check skills availability (project-level and user-level)
				const skillsDirs = [
					path.join(process.cwd(), ".claude", "skills"), // project-level
					path.join(os.homedir(), ".claude", "skills"), // user-level
				];
				const allSkills = new Set<string>();
				let foundDir: string | null = null;

				for (const skillsDir of skillsDirs) {
					try {
						const skillDirs = await fs.readdir(skillsDir, { withFileTypes: true });
						const skills = skillDirs
							.filter((entry) => entry.isDirectory() && !entry.name.startsWith("."))
							.map((entry) => entry.name);
						for (const skill of skills) {
							allSkills.add(skill);
						}
						if (skills.length > 0 && !foundDir) {
							foundDir = skillsDir;
						}
					} catch {
						// Directory doesn't exist or not readable, try next
					}
				}

				if (allSkills.size > 0) {
					const skillList = Array.from(allSkills).sort();
					console.log(`Skills: ${skillList.length} available (${skillList.join(", ")})`);
				} else {
					console.log("Skills: none found");
					console.log("  Skills like image-generator won't be available");
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

					if (moltbookScheduler) {
						moltbookScheduler.stop();
						logger.info("moltbook scheduler stopped");
					}

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
				if (moltbookScheduler) {
					moltbookScheduler.stop();
					logger.info("moltbook scheduler stopped");
				}
				await destroySessionManager();

				console.log("Relay stopped.");
			} catch (err) {
				logger.error({ error: String(err) }, "relay command failed");
				console.error(`Error: ${err}`);
				process.exit(1);
			}
		});
}
