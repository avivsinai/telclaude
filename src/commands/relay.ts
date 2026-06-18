import fsSync from "node:fs";
import path from "node:path";
import type { Command } from "commander";
import { loadConfig } from "../config/config.js";
import { executeCronAction } from "../cron/actions.js";
import { startCronScheduler } from "../cron/scheduler.js";
import { getCronCoverage, getCronStatusSummary } from "../cron/store.js";
import { readEnv } from "../env.js";
import { setVerbose } from "../globals.js";
import { TelclaudeEdgeRuntime } from "../hermes/edge-adapter-runtime.js";
import {
	createTelclaudeMcpSideEffectApprovalVerifier,
	generateTelclaudeMcpSideEffectApprovalToken,
	TelclaudeMcpSideEffectJtiStore,
} from "../hermes/mcp/approval-token.js";
import { hermesMcpAuthorityRegistry } from "../hermes/mcp/authority-registry.js";
import type { TelclaudeMcpSideEffectApprovalTokenResolver } from "../hermes/mcp/ledger-execute.js";
import {
	createTelclaudeLiveMcpProbeAdminStarter,
	readTelclaudeLiveMcpAdminConfig,
} from "../hermes/mcp/live-admin.js";
import {
	createStoredAttachmentOutboundMediaResolver,
	createTelclaudeLiveMcpRelayClients,
} from "../hermes/mcp/live-relay-clients.js";
import {
	readTelclaudeLiveMcpRuntimeConfig,
	startTelclaudeLiveMcpRuntime,
} from "../hermes/mcp/live-runtime.js";
import {
	requestTelclaudeLiveMcpSideEffectApproval,
	setTelclaudeLiveMcpSideEffectApprovalBinding,
} from "../hermes/mcp/live-side-effect-approvals.js";
import { createGoogleProviderSidecarApprovalTokenIssuer } from "../hermes/mcp/provider-sidecar-token.js";
import { createSideEffectHumanApprovalController } from "../hermes/mcp/side-effect-human-approval.js";
import { createTelclaudeMcpSideEffectLedger } from "../hermes/mcp/side-effect-ledger.js";
import { setHermesPrivateRuntimeMcpAuthorityActivation } from "../hermes/private-execute.js";
import { createRelayConversationStore } from "../hermes/relay-conversation-store.js";
import { installUnhandledRejectionHandler } from "../infra/unhandled-rejections.js";
import { getChildLogger } from "../logging.js";
import {
	checkProviderHealth,
	computeProviderHealthExitCode,
	formatProviderHealthSummary,
	logProviderHealthResults,
} from "../providers/provider-health.js";
import { refreshExternalProviderSkill } from "../providers/provider-skill.js";
import { startAnthropicOauthRefreshScheduler } from "../relay/anthropic-proxy.js";
import { createAttachmentQuarantineStore } from "../relay/attachment-quarantine-store.js";
import {
	BrowserBroker,
	createPlaywrightBrowserDriver,
	resolveBrowserBrokerConfig,
} from "../relay/browser-broker.js";
import { startBrowserConnectProxy } from "../relay/browser-connect-proxy.js";
import { resolveBrowserConnectProxyStartup } from "../relay/browser-context-token.js";
import { bufferStartupReady, startCapabilityServer } from "../relay/capabilities.js";
import { createDefaultEdgeOutboundExecutorRegistry } from "../relay/edge-outbound-executor-registry.js";
import { startGitProxyServer } from "../relay/git-proxy.js";
import { startHttpCredentialProxy } from "../relay/http-credential-proxy.js";
import { createOutboundDeliveryDispatcher } from "../relay/outbound-delivery-dispatcher.js";
import { initTokenManager } from "../relay/token-manager.js";
import {
	buildAllowedDomainNames,
	buildAllowedDomains,
	DEFAULT_NETWORK_CONFIG,
	getNetworkIsolationSummary,
	getSandboxMode,
} from "../sandbox/index.js";
import { isTOTPDaemonAvailable } from "../security/totp.js";
import { ensureActivityLogTable } from "../social/activity-log.js";
import {
	createSocialClient,
	handleSocialHeartbeat,
	startSocialScheduler,
} from "../social/index.js";
import { getEnabledSocialServices, isAutomaticHeartbeatEnabled } from "../social/service-config.js";
import { getServiceRevision, getServiceVersion } from "../system-metadata.js";
import { type MonitorOptions, monitorTelegramProvider } from "../telegram/auto-reply.js";
import { handlePrivateHeartbeat } from "../telegram/heartbeat.js";
import { CONFIG_DIR } from "../utils.js";
import { isVaultAvailable, VaultClient } from "../vault-daemon/index.js";
import { startWebhookServer } from "../webhooks/server.js";
import { findInstalledSkills } from "./doctor-helpers.js";

const logger = getChildLogger({ module: "cmd-relay" });
const LIVE_MCP_ATTACHMENT_QUARANTINE_CLEANUP_INTERVAL_MS = 60 * 1000;

export type RelayOptions = {
	verbose?: boolean;
	dryRun?: boolean;
	probeNoTelegram?: boolean;
	profile?: "simple" | "strict" | "test";
};

export function buildRelayTelegramMonitorOptions(input: {
	readonly verbose?: boolean;
	readonly abortSignal: AbortSignal;
	readonly securityProfile: "simple" | "strict" | "test";
	readonly dryRun: boolean;
	readonly onReady: () => void;
	readonly mcpConversationStore?: MonitorOptions["mcpConversationStore"];
}): MonitorOptions {
	return {
		verbose: input.verbose ?? false,
		keepAlive: true,
		abortSignal: input.abortSignal,
		securityProfile: input.securityProfile,
		dryRun: input.dryRun,
		onReady: input.onReady,
		...(input.mcpConversationStore ? { mcpConversationStore: input.mcpConversationStore } : {}),
	};
}

export function shouldValidateTelegramEnv(input: { readonly probeNoTelegram?: boolean }): boolean {
	return !input.probeNoTelegram;
}

export function validateProbeNoTelegramRelayMode(input: {
	readonly probeNoTelegram?: boolean;
	readonly dryRun?: boolean;
	readonly liveMcpEnabled?: boolean;
	readonly liveMcpAdminEnabled?: boolean;
}): string | null {
	if (!input.probeNoTelegram) return null;
	if (!input.dryRun) return "--probe-no-telegram requires --dry-run";
	if (!input.liveMcpEnabled) {
		return "--probe-no-telegram requires TELCLAUDE_HERMES_LIVE_MCP_ENABLED=1";
	}
	if (!input.liveMcpAdminEnabled) {
		return "--probe-no-telegram requires TELCLAUDE_HERMES_LIVE_MCP_ADMIN_ENABLED=1";
	}
	return null;
}

export function registerRelayCommand(program: Command): void {
	program
		.command("relay")
		.description("Start the Telegram relay with auto-reply")
		.option("--dry-run", "Don't actually send replies (for testing)")
		.option(
			"--probe-no-telegram",
			"Local Hermes live-probe mode: keep relay/MCP services up without connecting to Telegram",
		)
		.option("--profile <profile>", "Security profile: simple, strict, or test (overrides config)")
		.action(async (opts: RelayOptions) => {
			installUnhandledRejectionHandler("relay");

			const verbose = program.opts().verbose || opts.verbose;

			if (verbose) {
				setVerbose(true);
			}

			try {
				const cfg = loadConfig();
				const additionalDomains = cfg.security?.network?.additionalDomains ?? [];
				const allowedDomainNames = buildAllowedDomainNames(additionalDomains);
				const allowedDomains = buildAllowedDomains(additionalDomains);
				if (shouldValidateTelegramEnv(opts)) {
					await readEnv(); // Validates Telegram environment variables for normal relay mode.
				}
				const schedulerHandles: Array<{ stop: () => void | Promise<void> }> = [];
				const liveMcpAdminConfig = readTelclaudeLiveMcpAdminConfig();
				const liveMcpRuntimeConfig = readTelclaudeLiveMcpRuntimeConfig();
				const liveMcpProviderWriteApproverActorId =
					process.env.TELCLAUDE_HERMES_PROVIDER_WRITE_APPROVER_ACTOR_ID?.trim();
				const liveMcpOutboundApproverActorId =
					process.env.TELCLAUDE_HERMES_OUTBOUND_APPROVER_ACTOR_ID?.trim();
				const vaultSocketPath = process.env.TELCLAUDE_VAULT_SOCKET;
				const vaultAvailable = await isVaultAvailable(
					vaultSocketPath ? { socketPath: vaultSocketPath } : undefined,
				);
				const probeNoTelegramError = validateProbeNoTelegramRelayMode({
					probeNoTelegram: opts.probeNoTelegram,
					dryRun: opts.dryRun ?? false,
					liveMcpEnabled: liveMcpRuntimeConfig.enabled,
					liveMcpAdminEnabled: liveMcpAdminConfig.enabled,
				});
				if (probeNoTelegramError) {
					console.error(`\n❌ HERMES LIVE-PROBE ERROR: ${probeNoTelegramError}.\n`);
					console.error(
						"--probe-no-telegram is a local evidence harness only. It does not prove Telegram connectivity.",
					);
					process.exit(1);
				}

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

					if (vaultAvailable) {
						schedulerHandles.push(startAnthropicOauthRefreshScheduler());
						console.log("  Anthropic OAuth refresh: enabled (proactive vault refresh)");
					} else {
						console.log("  Anthropic OAuth refresh: disabled (vault daemon not running)");
					}

					startGitProxyServer();
					console.log("  Git proxy: enabled (transparent auth injection)");

					const browserProxyDecision = resolveBrowserConnectProxyStartup();
					if (browserProxyDecision.action === "start") {
						const browserConnectProxy = startBrowserConnectProxy({
							contextVerifier: browserProxyDecision.contextVerifier,
						});
						schedulerHandles.push(browserConnectProxy);
						console.log("  Browser CONNECT proxy: enabled (no TLS MITM, context-token verified)");
					} else if (browserProxyDecision.action === "fail-closed") {
						console.log(
							`  Browser CONNECT proxy: disabled (fail-closed: ${browserProxyDecision.reason})`,
						);
					} else {
						console.log("  Browser CONNECT proxy: disabled");
					}

					if (vaultAvailable) {
						startHttpCredentialProxy({ vaultSocketPath });
						console.log("  HTTP proxy: enabled (credential injection via vault)");

						const tokenInit = await initTokenManager();
						if (tokenInit) {
							console.log("  Session tokens: enabled (Ed25519 v3)");
						} else {
							console.log("  Session tokens: disabled (vault signing key unavailable)");
						}
					} else {
						console.log("  HTTP proxy: disabled (vault daemon not running)");
					}
				} else {
					console.log("  Capabilities: disabled");
				}

				const liveMcpSideEffectApprovals =
					liveMcpRuntimeConfig.enabled && vaultAvailable
						? createLiveMcpSideEffectApprovalKit(vaultSocketPath)
						: null;
				const liveMcpConversationStore = createRelayConversationStore();
				const liveMcpLedger = createTelclaudeMcpSideEffectLedger({
					verifyApproval: liveMcpSideEffectApprovals?.verifyApproval ?? denyRelayLiveMcpApproval,
				});
				const liveMcpEdgeRuntime = new TelclaudeEdgeRuntime();
				// tc_browse broker: live only when the browser overlay env is set
				// (TELCLAUDE_BROWSER_WS_ENDPOINT/_CONNECT_PROXY_URL/_PEER_ADDRESS/
				// _CONTEXT_TOKEN_SECRET). Otherwise omitted → tc_browse fails closed.
				const liveMcpBrowserBrokerConfig = resolveBrowserBrokerConfig();
				const liveMcpBrowserBroker = liveMcpBrowserBrokerConfig
					? new BrowserBroker(createPlaywrightBrowserDriver(), liveMcpBrowserBrokerConfig)
					: undefined;
				if (liveMcpBrowserBroker) {
					console.log("  tc_browse: enabled (contained browser broker wired)");
				}
				const liveMcpAttachmentQuarantineStore = createAttachmentQuarantineStore();
				const liveMcpAttachmentQuarantineCleanup = setInterval(() => {
					const removed = liveMcpAttachmentQuarantineStore.cleanupExpired();
					if (removed > 0) {
						logger.debug(
							{ removed },
							"expired Hermes live-MCP attachment quarantine entries cleaned",
						);
					}
				}, LIVE_MCP_ATTACHMENT_QUARANTINE_CLEANUP_INTERVAL_MS);
				liveMcpAttachmentQuarantineCleanup.unref();
				schedulerHandles.push({
					stop: () => clearInterval(liveMcpAttachmentQuarantineCleanup),
				});
				const liveMcpOutboundDeliveryDispatcher = createOutboundDeliveryDispatcher({
					registry: createDefaultEdgeOutboundExecutorRegistry(),
					resolveConversation: async (prepared) => {
						const record = liveMcpLedger.get(prepared.sideEffectLedgerRef);
						if (
							record?.kind !== "outbound" ||
							record.edgePreparedRef !== prepared.outboundRef ||
							record.channel !== prepared.channel
						) {
							return null;
						}
						const conversation = liveMcpConversationStore.resolveAuthorized(record.conversationRef);
						return conversation
							? {
									conversationToken: conversation.token,
									threadMessageIds: conversation.threadMessageIds,
								}
							: null;
					},
					quarantineStore: liveMcpAttachmentQuarantineStore,
					onDelivered: async (_prepared, context, outcome) => {
						const threadMessageId = outcome.observedThreadMessageId ?? outcome.platformMessageId;
						if (threadMessageId) {
							liveMcpConversationStore.recordThreadMessageId(
								context.conversationToken,
								threadMessageId,
							);
						}
					},
					onDeliveredError: (_prepared, context, _outcome, error) => {
						logger.warn(
							{
								conversationToken: context.conversationToken,
								error: error instanceof Error ? error.message : String(error),
							},
							"failed to record Hermes outbound delivery thread id",
						);
					},
					onSendFailure: (prepared, failure) => {
						logger.warn(
							{
								channel: prepared.channel,
								outboundRef: prepared.outboundRef,
								code: failure.code,
								retryable: failure.retryable,
							},
							"Hermes outbound delivery failed",
						);
					},
				});
				const liveMcpRuntime = await startTelclaudeLiveMcpRuntime({
					config: liveMcpRuntimeConfig,
					registry: hermesMcpAuthorityRegistry,
					ledger: liveMcpLedger,
					sideEffectApprovalTokenResolver:
						liveMcpSideEffectApprovals?.sideEffectApprovalTokenResolver,
					resolveAuthorizedOutboundConversation: (conversationRef, nowMs) =>
						liveMcpConversationStore.resolveAuthorized(conversationRef, nowMs),
					resolveAuthorizedInboundTurn: (request) => {
						const turn = request.expectedConversationRef
							? liveMcpConversationStore.resolveAuthorizedInboundTurn(
									request.turnConversationRef,
									request.expectedConversationRef,
									request.nowMs,
								)
							: liveMcpConversationStore.resolveInboundTurn(
									request.turnConversationRef,
									request.nowMs,
								);
						if (!turn) return null;
						if (
							!liveMcpConversationStore.resolveAuthorized(turn.conversationToken, request.nowMs)
						) {
							return null;
						}
						if (
							turn.senderActorId !== request.actorId ||
							turn.profileId !== request.profileId ||
							turn.mcpDomain !== request.domain ||
							(request.channel && turn.channel !== request.channel) ||
							(request.conversationId && turn.conversationId !== request.conversationId)
						) {
							return null;
						}
						return turn;
					},
					outboundDeliveryDispatcher: liveMcpOutboundDeliveryDispatcher,
					providerApprovalTokenIssuer: liveMcpSideEffectApprovals?.providerApprovalTokenIssuer,
					createRelayClients: ({ ledger }) => {
						if (liveMcpSideEffectApprovals) {
							setTelclaudeLiveMcpSideEffectApprovalBinding({
								ledger,
								controller: liveMcpSideEffectApprovals.controller,
							});
						}
						return createTelclaudeLiveMcpRelayClients({
							ledger,
							conversationStore: liveMcpConversationStore,
							edgeRuntime: liveMcpEdgeRuntime,
							browser: liveMcpBrowserBroker,
							resolveOutboundMediaRefs: createStoredAttachmentOutboundMediaResolver({
								edgeRuntime: liveMcpEdgeRuntime,
								quarantineStore: liveMcpAttachmentQuarantineStore,
							}),
							providerWriteApproverActorId: liveMcpProviderWriteApproverActorId,
							outboundApproverActorId: liveMcpOutboundApproverActorId,
							requestSideEffectApproval: liveMcpSideEffectApprovals
								? (record) =>
										requestTelclaudeLiveMcpSideEffectApproval(
											liveMcpSideEffectApprovals.controller,
											record,
										)
								: undefined,
						});
					},
					admin: createTelclaudeLiveMcpProbeAdminStarter(liveMcpAdminConfig),
				});
				if (liveMcpRuntime.enabled && liveMcpRuntime.endpoint) {
					setHermesPrivateRuntimeMcpAuthorityActivation({
						activate: (input) => liveMcpRuntime.activateRuntimeAuthority(input),
						revoke: (id, reason, nowMs) => liveMcpRuntime.revokeRuntimeAuthority(id, reason, nowMs),
					});
					schedulerHandles.push({
						stop: async () => {
							try {
								await liveMcpRuntime.stop();
							} finally {
								setHermesPrivateRuntimeMcpAuthorityActivation(null);
								liveMcpSideEffectApprovals?.close();
							}
						},
					});
					console.log(`  Hermes live MCP: enabled (${liveMcpRuntime.endpoint.url})`);
					console.log(
						`  Hermes provider write approver: ${
							liveMcpProviderWriteApproverActorId
								? "configured"
								: "not configured (provider writes fail closed)"
						}`,
					);
					console.log(
						`  Hermes outbound approver: ${
							liveMcpOutboundApproverActorId
								? "configured"
								: "not configured (outbound sends fail closed)"
						}`,
					);
					if (liveMcpAdminConfig.enabled) {
						console.log(`  Hermes live MCP admin: enabled (${liveMcpAdminConfig.socketPath})`);
					}
					console.log(
						`  Hermes side-effect approvals: ${
							liveMcpSideEffectApprovals
								? "enabled (vault-backed)"
								: "disabled (vault daemon not running)"
						}`,
					);
				} else {
					setHermesPrivateRuntimeMcpAuthorityActivation(null);
					console.log("  Hermes live MCP: disabled");
				}

				// Initialize activity log table for cross-persona queries
				ensureActivityLogTable();

				const cronEnabled = cfg.cron.enabled !== false;
				let cronCoverage = {
					allSocial: false,
					socialServiceIds: [] as string[],
					hasPrivateHeartbeat: false,
				};
				if (cronEnabled) {
					const scheduler = startCronScheduler({
						pollIntervalMs: cfg.cron.pollIntervalSeconds * 1000,
						timeoutMs: cfg.cron.timeoutSeconds * 1000,
						executor: (job, signal) => executeCronAction(job, cfg, signal),
					});
					schedulerHandles.push(scheduler);

					const summary = getCronStatusSummary();
					cronCoverage = getCronCoverage();
					console.log(
						`  Cron scheduler: enabled (${summary.enabledJobs}/${summary.totalJobs} jobs, poll ${cfg.cron.pollIntervalSeconds}s)`,
					);
				} else {
					console.log("  Cron scheduler: disabled in config");
				}

				if (cfg.webhooks.enabled) {
					const webhookServer = await startWebhookServer({ config: cfg.webhooks });
					schedulerHandles.push({
						stop: () => webhookServer.close(),
					});
					console.log(
						`  Webhook receiver: enabled (http://${webhookServer.host}:${webhookServer.port})`,
					);
				} else {
					console.log("  Webhook receiver: disabled in config");
				}

				const enabledServices = getEnabledSocialServices(cfg);
				if (enabledServices.length > 0) {
					for (const svc of enabledServices) {
						if (!isAutomaticHeartbeatEnabled(svc)) {
							console.log(`  Social service ${svc.id}: enabled (automatic heartbeat disabled)`);
							continue;
						}

						const coveredByCron =
							cronEnabled &&
							(cronCoverage.allSocial || cronCoverage.socialServiceIds.includes(svc.id));
						if (coveredByCron) {
							console.log(`  Social service ${svc.id}: cron-managed (interval heartbeat disabled)`);
							continue;
						}

						const intervalHours = svc.heartbeatIntervalHours ?? 4;
						const intervalMs = intervalHours * 60 * 60 * 1000;
						const scheduler = startSocialScheduler({
							serviceId: svc.id,
							intervalMs,
							onHeartbeat: async () => {
								const client = await createSocialClient(svc);
								if (!client) {
									logger.warn({ serviceId: svc.id }, "social client not configured");
									return;
								}
								const result = await handleSocialHeartbeat(svc.id, client, svc);
								if (!result.ok) {
									logger.warn(
										{ message: result.message, serviceId: svc.id },
										"social heartbeat reported errors",
									);
								}
							},
						});
						schedulerHandles.push(scheduler);
						console.log(`  Social service ${svc.id}: enabled (heartbeat every ${intervalHours}h)`);
					}
				} else {
					console.log("  Social services: none enabled");
				}

				// Private heartbeat scheduler (autonomous tasks for telegram persona)
				if (cfg.telegram?.heartbeat?.enabled) {
					if (cronEnabled && cronCoverage.hasPrivateHeartbeat) {
						console.log("  Private heartbeat: cron-managed (interval heartbeat disabled)");
					} else {
						const privateIntervalHours = cfg.telegram.heartbeat.intervalHours ?? 6;
						const privateIntervalMs = privateIntervalHours * 60 * 60 * 1000;
						const privateScheduler = startSocialScheduler({
							serviceId: "telegram-private",
							intervalMs: privateIntervalMs,
							onHeartbeat: async () => {
								const result = await handlePrivateHeartbeat(cfg);
								if (result.acted) {
									logger.info(
										{ summary: result.summary },
										"private heartbeat completed with activity",
									);
								}
							},
						});
						schedulerHandles.push(privateScheduler);
						console.log(`  Private heartbeat: enabled (every ${privateIntervalHours}h)`);
					}
				}

				// Detect sandbox mode and verify host isolation posture
				const sandboxMode = getSandboxMode();
				if (sandboxMode === "docker") {
					console.log("Sandbox: Docker mode (container provides isolation)");
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
							console.error("In Docker mode, container isolation is the active boundary.");
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
					console.log("Sandbox: Native relay process; LLM/persona runtime is contained Hermes");
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

				// External providers: verify health first, then update skills
				const providers = cfg.providers ?? [];
				if (providers.length > 0) {
					console.log(`Providers: ${providers.length} configured`);

					const results = await Promise.all(
						providers.map((provider) => checkProviderHealth(provider.id, provider.baseUrl)),
					);

					logProviderHealthResults(results);
					const exitCode = computeProviderHealthExitCode(results);
					const allowDegraded = process.env.TELCLAUDE_ALLOW_DEGRADED_PROVIDERS === "1";
					// Exit code 1 = degraded (warn), exit code 2 = error (unreachable/unhealthy)
					if (exitCode > 0 && !allowDegraded) {
						console.error(`Provider health check failed: ${formatProviderHealthSummary(results)}`);
						process.exit(exitCode);
					}
					if (exitCode > 0 && allowDegraded) {
						console.warn(
							`Provider health degraded but continuing due to TELCLAUDE_ALLOW_DEGRADED_PROVIDERS=1`,
						);
					}

					// Fetch schemas AFTER health check passes (provider is ready)
					await refreshExternalProviderSkill(providers);
				}

				// Check TOTP daemon availability
				const totpAvailable = await isTOTPDaemonAvailable();
				if (totpAvailable) {
					console.log("TOTP daemon: connected");
				} else {
					console.log("TOTP daemon: not running (2FA will be unavailable)");
					console.log("  Start with: telclaude maintenance totp-daemon");
				}

				// Check skills availability via the canonical doctor helper.
				// This covers project-local, CLAUDE_CONFIG_DIR, and bundled roots,
				// and treats symlinked skill directories as real skills
				// (required for Docker profiles that symlink individual skills).
				const skillList = findInstalledSkills().map((s) => s.name);

				if (skillList.length > 0) {
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

					for (const scheduler of schedulerHandles) {
						await scheduler.stop();
					}
					if (schedulerHandles.length > 0) {
						logger.info({ count: schedulerHandles.length }, "schedulers stopped");
					}
				};

				process.on("SIGINT", () => void shutdown());
				process.on("SIGTERM", () => void shutdown());

				if (opts.probeNoTelegram) {
					console.warn("  Hermes live-probe: Telegram connection skipped (--probe-no-telegram).");
					console.warn("  This is local dry-run evidence only, not Telegram cutover proof.");
					bufferStartupReady({
						label: "relay-probe-no-telegram",
						version: getServiceVersion(),
						revision: getServiceRevision(),
					});
					await new Promise<void>((resolve) => {
						if (abortController.signal.aborted) {
							resolve();
							return;
						}
						abortController.signal.addEventListener("abort", () => resolve(), { once: true });
					});
					return;
				}

				await monitorTelegramProvider(
					buildRelayTelegramMonitorOptions({
						verbose,
						abortSignal: abortController.signal,
						securityProfile: effectiveProfile,
						dryRun: opts.dryRun ?? false,
						onReady: () => {
							bufferStartupReady({
								label: "relay",
								version: getServiceVersion(),
								revision: getServiceRevision(),
							});
							logger.info("relay ready — buffered startup notification");
						},
						mcpConversationStore: liveMcpConversationStore,
					}),
				);

				// Final cleanup after monitor exits
				for (const scheduler of schedulerHandles) {
					await scheduler.stop();
				}
				console.log("Relay stopped.");
			} catch (err) {
				logger.error({ error: String(err) }, "relay command failed");
				console.error(`Error: ${err}`);
				process.exit(1);
			}
		});
}

function createLiveMcpSideEffectApprovalKit(vaultSocketPath: string | undefined) {
	const vaultClient = new VaultClient(
		vaultSocketPath ? { socketPath: vaultSocketPath } : undefined,
	);
	const jtiStore = new TelclaudeMcpSideEffectJtiStore(
		path.join(CONFIG_DIR, "hermes", "mcp-side-effect-approval-jti"),
	);
	const controller = createSideEffectHumanApprovalController({
		autoGrant: { enabled: true },
		mintApprovalToken: ({ binding, jti, ttlMs, nowMs }) =>
			generateTelclaudeMcpSideEffectApprovalToken(binding, vaultClient, {
				jti,
				ttlSeconds: Math.max(1, Math.ceil(ttlMs / 1_000)),
				nowSeconds: () => Math.floor(nowMs / 1_000),
			}),
	});
	const sideEffectApprovalTokenResolver: TelclaudeMcpSideEffectApprovalTokenResolver = ({
		actionRef,
		record,
	}) => controller.takeServerSideApproval({ actionRef, record });

	return {
		controller,
		verifyApproval: createTelclaudeMcpSideEffectApprovalVerifier({
			vaultClient,
			jtiStore,
		}),
		sideEffectApprovalTokenResolver,
		providerApprovalTokenIssuer: createGoogleProviderSidecarApprovalTokenIssuer({
			vaultClient,
			subjectUserId: process.env.GOOGLE_USER_EMAIL,
		}),
		close() {
			setTelclaudeLiveMcpSideEffectApprovalBinding(null);
			jtiStore.close();
		},
	};
}

async function denyRelayLiveMcpApproval() {
	return {
		ok: false as const,
		code: "approval_required",
		reason: "live MCP side-effect approvals are disabled",
	};
}
