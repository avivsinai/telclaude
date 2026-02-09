import fsSync from "node:fs";
import type { Command } from "commander";
import { startAgentServer } from "../agent/server.js";
import { bootstrapSessionToken } from "../agent/token-client.js";
import { getChildLogger } from "../logging.js";
import { refreshExternalProviderSkill } from "../providers/provider-skill.js";
import { relayGetProviders } from "../relay/capabilities-client.js";
import { getSandboxMode } from "../sandbox/index.js";

const logger = getChildLogger({ module: "cmd-agent" });

export function registerAgentCommand(program: Command): void {
	program
		.command("agent")
		.description("Start the agent worker server (SDK runner)")
		.option("--port <port>", "Port to bind the agent server")
		.option("--host <host>", "Host to bind the agent server")
		.action(async (opts: { port?: string; host?: string }) => {
			const port = opts.port ? Number.parseInt(opts.port, 10) : undefined;
			const host = opts.host;
			const isMoltbookAgent = Boolean(
				process.env.MOLTBOOK_RPC_RELAY_PUBLIC_KEY || process.env.MOLTBOOK_RPC_AGENT_PRIVATE_KEY,
			);

			if (getSandboxMode() === "docker") {
				if (process.env.TELCLAUDE_FIREWALL !== "1") {
					if (isMoltbookAgent) {
						console.error("\n❌ SECURITY ERROR: Moltbook agent requires firewall.\n");
						console.error("Moltbook runs untrusted inputs and must be isolated.");
						console.error("Set TELCLAUDE_FIREWALL=1 and ensure init-firewall.sh succeeds.\n");
						process.exit(1);
					}
					if (process.env.TELCLAUDE_ACCEPT_NO_FIREWALL === "1") {
						logger.warn("TELCLAUDE_FIREWALL not enabled - agent tools have NO network isolation");
					} else {
						console.error("\n❌ SECURITY ERROR: Docker mode requires network firewall.\n");
						console.error("The agent runs tools without the SDK sandbox in Docker mode.");
						console.error("Without TELCLAUDE_FIREWALL=1, Bash can reach arbitrary endpoints.\n");
						console.error("To fix:");
						console.error("  - Set TELCLAUDE_FIREWALL=1 in your docker/.env file");
						console.error("  - Ensure init-firewall.sh runs (requires NET_ADMIN capability)\n");
						console.error("To bypass (TESTING ONLY - NOT FOR PRODUCTION):");
						console.error("  - Set TELCLAUDE_ACCEPT_NO_FIREWALL=1\n");
						process.exit(1);
					}
				} else {
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
					logger.info("Firewall: verified (sentinel file present)");
				}
			}

			startAgentServer({
				port,
				host,
			});

			logger.info({ port, host }, "agent server started");

			// Bootstrap session token (non-blocking, falls back to v1/v2 if unavailable)
			const relayUrl = process.env.TELCLAUDE_CAPABILITIES_URL;
			if (relayUrl) {
				const scope = isMoltbookAgent ? "moltbook" : "telegram";
				bootstrapSessionToken(relayUrl, scope)
					.then((ok) => {
						if (ok) {
							logger.info({ scope }, "session token bootstrapped (Ed25519 v3)");
						} else {
							logger.info({ scope }, "session token unavailable, using static auth");
						}
					})
					.catch((err) => {
						logger.warn({ error: String(err) }, "session token bootstrap failed");
					});

				// Fetch provider config from relay (with retry — relay may start after agent)
				if (!isMoltbookAgent) {
					const fetchProviders = async (attempt: number): Promise<void> => {
						try {
							const result = await relayGetProviders();
							if (result.ok && result.providers.length > 0) {
								await refreshExternalProviderSkill(result.providers);
								logger.info(
									{ count: result.providers.length },
									"provider config fetched from relay",
								);
							}
						} catch (err) {
							if (attempt < 3) {
								const delay = attempt * 10_000; // 10s, 20s
								logger.debug({ attempt, delay }, "relay not ready, retrying provider fetch");
								setTimeout(() => fetchProviders(attempt + 1), delay);
							} else {
								logger.warn({ error: String(err) }, "failed to fetch provider config from relay");
							}
						}
					};
					// Delay first attempt to give relay time to start
					setTimeout(() => fetchProviders(1), 15_000);
				}
			}

			// Keep the process alive (server runs indefinitely)
			await new Promise(() => {});
		});
}
