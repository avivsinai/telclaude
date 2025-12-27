/**
 * Git Proxy Initialization Command
 *
 * Configures git in the agent container to route through the relay's git proxy.
 * The proxy adds authentication transparently - the agent never sees the real token.
 *
 * This command:
 * 1. Generates a session token (HMAC-signed, scoped to our system)
 * 2. Configures git URL rewriting to route GitHub traffic through the proxy
 * 3. Adds the session token as an HTTP header for proxy authentication
 * 4. Fetches and configures git identity from the proxy
 *
 * Usage:
 *   telclaude git-proxy-init
 *
 * Environment:
 *   TELCLAUDE_GIT_PROXY_URL   - URL of the git proxy (e.g., http://telclaude:8791)
 *   TELCLAUDE_GIT_PROXY_SECRET - Shared secret for token generation
 */

import { execSync } from "node:child_process";
import type { Command } from "commander";
import { getChildLogger } from "../logging.js";
import { generateSessionId, generateSessionToken } from "../relay/git-proxy-auth.js";

const logger = getChildLogger({ module: "git-proxy-init" });

// Refresh interval for daemon mode: 45 minutes (refresh before expiry)
const REFRESH_INTERVAL_MS = 45 * 60 * 1000;

interface GitIdentity {
	username: string;
	email: string;
}

/**
 * Fetch git identity from the proxy's /identity endpoint.
 */
async function fetchGitIdentity(proxyUrl: string): Promise<GitIdentity | null> {
	try {
		const response = await fetch(`${proxyUrl}/identity`);
		if (!response.ok) {
			logger.debug({ status: response.status }, "failed to fetch git identity from proxy");
			return null;
		}

		const data = (await response.json()) as { username?: string; email?: string };
		if (data.username && data.email) {
			return { username: data.username, email: data.email };
		}
		return null;
	} catch (err) {
		logger.debug({ error: String(err) }, "error fetching git identity");
		return null;
	}
}

/**
 * Configure git to use the proxy.
 *
 * IMPORTANT: Uses --replace-all to prevent duplicate headers on repeated runs.
 * Without this, multiple X-Telclaude-Session headers would be sent, causing
 * validation failures in the proxy.
 */
function configureGit(proxyUrl: string, sessionToken: string, identity: GitIdentity): void {
	// Helper to set a git config value, replacing any existing value
	const gitConfigSet = (key: string, value: string) => {
		// First unset any existing values to avoid duplicates
		try {
			execSync(`git config --global --unset-all ${key}`, { stdio: "ignore" });
		} catch {
			// Ignore errors if key doesn't exist
		}
		execSync(`git config --global ${key} "${value}"`, { stdio: "inherit" });
	};

	// Helper for extraHeader which needs special handling
	// extraHeader can have multiple values, but we want exactly one session header
	const gitConfigHeader = (section: string, header: string) => {
		// Remove any existing X-Telclaude-Session headers for this section
		try {
			execSync(`git config --global --unset-all http."${section}".extraHeader`, {
				stdio: "ignore",
			});
		} catch {
			// Ignore errors if key doesn't exist
		}
		execSync(`git config --global --add http."${section}".extraHeader "${header}"`, {
			stdio: "inherit",
		});
	};

	// URL rewriting: GitHub URLs → proxy
	// This covers all common forms of GitHub URLs
	gitConfigSet(`url."${proxyUrl}/github.com/".insteadOf`, "https://github.com/");
	gitConfigSet(`url."${proxyUrl}/github.com/".insteadOf`, "git@github.com:");
	gitConfigSet(`url."${proxyUrl}/github.com/".insteadOf`, "ssh://git@github.com/");

	// Add session token header for proxy authentication
	gitConfigHeader(`${proxyUrl}/`, `X-Telclaude-Session: ${sessionToken}`);

	// Disable SSL verification for the proxy (internal HTTP)
	gitConfigSet(`http."${proxyUrl}/".sslVerify`, "false");

	// Disable credential helpers (proxy handles auth)
	gitConfigSet("credential.helper", "");

	// Configure git identity
	gitConfigSet("user.name", identity.username);
	gitConfigSet("user.email", identity.email);
}

/**
 * Initialize git proxy configuration once.
 */
async function initializeGitProxy(
	proxyUrl: string,
	ttlMs: number,
	showToken: boolean,
): Promise<void> {
	// Generate session token
	const sessionId = generateSessionId();
	const sessionToken = generateSessionToken(sessionId, ttlMs);

	logger.info({ sessionId, ttlMs }, "generated git proxy session token");

	if (showToken) {
		console.log(`[git-proxy-init] Session ID: ${sessionId}`);
		console.log(`[git-proxy-init] Session token: ${sessionToken}`);
	}

	// Fetch git identity from proxy
	let identity = await fetchGitIdentity(proxyUrl);

	if (!identity) {
		// Fallback to environment variables or defaults
		const envName = process.env.GIT_USER_NAME;
		const envEmail = process.env.GIT_USER_EMAIL;

		if (envName && envEmail) {
			console.log("[git-proxy-init] Using git identity from environment");
			identity = { username: envName, email: envEmail };
		} else {
			console.log("[git-proxy-init] Using default git identity");
			identity = {
				username: "telclaude[bot]",
				email: "noreply@telclaude.local",
			};
		}
	} else {
		console.log(`[git-proxy-init] Using git identity from proxy: ${identity.username}`);
	}

	// Configure git
	console.log("[git-proxy-init] Configuring git...");
	try {
		configureGit(proxyUrl, sessionToken, identity);
	} catch (err) {
		console.error(`[git-proxy-init] Failed to configure git: ${String(err)}`);
		throw err;
	}

	const expiresAt = new Date(Date.now() + ttlMs);
	console.log(`[git-proxy-init] Token expires at: ${expiresAt.toISOString()}`);
}

export function registerGitProxyInitCommand(program: Command): void {
	program
		.command("git-proxy-init")
		.description("Configure git to use the relay git proxy (agent container only)")
		.option("--show-token", "Output the session token (for debugging)")
		.option("--ttl <minutes>", "Token TTL in minutes (default: 60)", "60")
		.option("--daemon", "Run as daemon, refreshing token periodically before expiry")
		.action(async (opts: { showToken?: boolean; ttl?: string; daemon?: boolean }) => {
			const proxyUrl = process.env.TELCLAUDE_GIT_PROXY_URL;
			if (!proxyUrl) {
				console.error("TELCLAUDE_GIT_PROXY_URL is not set - skipping git proxy configuration");
				console.error("This command should only be run in the agent container.");
				process.exit(0); // Not an error - just not applicable
			}

			const proxySecret = process.env.TELCLAUDE_GIT_PROXY_SECRET;
			if (!proxySecret) {
				console.error("TELCLAUDE_GIT_PROXY_SECRET is not set - cannot generate session token");
				console.error("Ensure both relay and agent have the same secret configured.");
				process.exit(1);
			}

			const ttlMinutes = Number.parseInt(opts.ttl ?? "60", 10);
			const ttlMs = ttlMinutes * 60 * 1000;

			console.log("[git-proxy-init] Configuring git to use relay proxy...");
			console.log(`[git-proxy-init] Proxy URL: ${proxyUrl}`);
			console.log(`[git-proxy-init] Token TTL: ${ttlMinutes} minutes`);

			// Initial configuration
			await initializeGitProxy(proxyUrl, ttlMs, opts.showToken ?? false);

			console.log("[git-proxy-init] Git configured successfully");

			// Verify configuration
			console.log("[git-proxy-init] URL rewrites:");
			try {
				execSync("git config --global --get-regexp '^url\\.' | head -3", { stdio: "inherit" });
			} catch {
				// Ignore errors from git config --get-regexp
			}

			if (opts.daemon) {
				// Daemon mode: refresh token periodically before expiry
				const refreshMs = Math.min(REFRESH_INTERVAL_MS, ttlMs * 0.75);
				console.log(
					`[git-proxy-init] Running as daemon, refreshing every ${Math.round(refreshMs / 60000)} minutes`,
				);

				const refresh = async () => {
					try {
						console.log("[git-proxy-init] Refreshing session token...");
						await initializeGitProxy(proxyUrl, ttlMs, false);
						console.log("[git-proxy-init] Token refreshed successfully");
					} catch (err) {
						console.error(`[git-proxy-init] Token refresh failed: ${String(err)}`);
						// Don't exit - keep trying
					}
				};

				setInterval(() => void refresh(), refreshMs);

				// Keep the process alive
				await new Promise(() => {});
			}
		});
}
