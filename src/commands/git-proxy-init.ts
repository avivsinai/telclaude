/**
 * Git Proxy Initialization Command
 *
 * Configures git to route through the relay's git proxy.
 * The proxy adds authentication transparently - runtime code never sees the real token.
 *
 * This command:
 * 1. Mints a scoped git proxy token through relay capabilities
 * 2. Configures git URL rewriting to route GitHub traffic through the proxy
 * 3. Adds the scoped token as an HTTP header for proxy authentication
 * 4. Fetches and configures git identity from the proxy
 *
 * Usage:
 *   telclaude git-proxy-init
 *
 * Environment:
 *   TELCLAUDE_GIT_PROXY_URL    - URL of the git proxy (e.g., http://telclaude:8791)
 *   TELCLAUDE_CAPABILITIES_URL - URL of the relay capabilities server (for scoped token mint)
 */

import { execFileSync } from "node:child_process";
import type { Command } from "commander";
import { getChildLogger } from "../logging.js";
import { buildRpcAuthHeaders } from "../relay/rpc-auth-client.js";

const logger = getChildLogger({ module: "git-proxy-init" });

// Refresh interval for daemon mode: 45 minutes (refresh before expiry)
const REFRESH_INTERVAL_MS = 45 * 60 * 1000;

interface GitIdentity {
	username: string;
	email: string;
}

interface GitProxyTokenResponse {
	token: string;
	expiresInMs: number;
	policy?: {
		repositories: string[];
		permissions: string[];
		allowedRefs: string[];
		deniedRefs: string[];
	};
}

export function buildGitProxyConfigKeys(proxyUrl: string): {
	urlRewrite: string;
	extraHeader: string;
	sslVerify?: string;
} {
	const parsed = new URL(proxyUrl);
	return {
		urlRewrite: `url.${proxyUrl}/github.com/.insteadOf`,
		extraHeader: `http.${proxyUrl}/.extraHeader`,
		...(parsed.protocol === "http:" ? { sslVerify: `http.${proxyUrl}/.sslVerify` } : {}),
	};
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

async function mintGitProxyToken(ttlMs: number): Promise<GitProxyTokenResponse> {
	const capabilitiesUrl = process.env.TELCLAUDE_CAPABILITIES_URL?.replace(/\/+$/, "");
	if (!capabilitiesUrl) {
		throw new Error("TELCLAUDE_CAPABILITIES_URL is not set - cannot mint git proxy token");
	}
	const path = "/v1/git-proxy-token";
	const body = JSON.stringify({ ttlMs });
	const response = await fetch(`${capabilitiesUrl}${path}`, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			...buildRpcAuthHeaders("POST", path, body, "telegram"),
		},
		body,
	});
	if (!response.ok) {
		const text = await response.text();
		throw new Error(`git proxy token mint failed: ${response.status} ${text.slice(0, 200)}`);
	}
	const parsed = (await response.json()) as Partial<GitProxyTokenResponse>;
	if (!parsed.token || typeof parsed.expiresInMs !== "number") {
		throw new Error("git proxy token mint returned an invalid response");
	}
	return parsed as GitProxyTokenResponse;
}

/**
 * Configure git to use the proxy.
 *
 * IMPORTANT: Uses --replace-all to prevent duplicate headers on repeated runs.
 * Without this, multiple X-Telclaude-Session headers would be sent, causing
 * validation failures in the proxy.
 */
function configureGit(proxyUrl: string, sessionToken: string, identity: GitIdentity): void {
	// Helper to set a single-value git config, replacing any existing
	// Uses execFileSync with argument arrays to prevent command injection
	const gitConfigSet = (key: string, value: string) => {
		try {
			execFileSync("git", ["config", "--global", "--unset-all", key], { stdio: "ignore" });
		} catch {
			// Ignore if key doesn't exist
		}
		execFileSync("git", ["config", "--global", key, value], { stdio: "inherit" });
	};

	// Helper to add a multi-value git config (like insteadOf)
	// Unsets all values first, then adds each one
	const gitConfigMulti = (key: string, values: string[]) => {
		try {
			execFileSync("git", ["config", "--global", "--unset-all", key], { stdio: "ignore" });
		} catch {
			// Ignore if key doesn't exist
		}
		for (const value of values) {
			execFileSync("git", ["config", "--global", "--add", key, value], { stdio: "inherit" });
		}
	};

	// Helper for extraHeader
	const gitConfigHeader = (key: string, header: string) => {
		try {
			execFileSync("git", ["config", "--global", "--unset-all", key], {
				stdio: "ignore",
			});
		} catch {
			// Ignore if key doesn't exist
		}
		execFileSync("git", ["config", "--global", "--add", key, header], {
			stdio: "inherit",
		});
	};
	const configKeys = buildGitProxyConfigKeys(proxyUrl);

	// URL rewriting: GitHub URLs → proxy
	// All three URL schemes need to be rewritten to the proxy
	gitConfigMulti(configKeys.urlRewrite, [
		"https://github.com/",
		"git@github.com:",
		"ssh://git@github.com/",
	]);

	// Add session token header for proxy authentication
	gitConfigHeader(configKeys.extraHeader, `X-Telclaude-Session: ${sessionToken}`);

	// Keep HTTPS proxy URLs on normal certificate validation.
	if (configKeys.sslVerify) {
		gitConfigSet(configKeys.sslVerify, "false");
	}

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
	const minted = await mintGitProxyToken(ttlMs);
	const sessionToken = minted.token;

	logger.info({ ttlMs, policy: minted.policy }, "minted scoped git proxy token");

	if (showToken) {
		console.log(`[git-proxy-init] Session token: ${sessionToken}`);
	}

	// Fetch git identity from proxy
	let identity = await fetchGitIdentity(proxyUrl);

	if (!identity) {
		// Fallback to environment variables or defaults
		const envName = process.env.GIT_USERNAME;
		const envEmail = process.env.GIT_EMAIL;

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

	const expiresAt = new Date(Date.now() + minted.expiresInMs);
	console.log(`[git-proxy-init] Token expires at: ${expiresAt.toISOString()}`);
}

export function registerGitProxyInitCommand(program: Command): void {
	program
		.command("git-proxy-init")
		.description("Configure git to use the relay git proxy")
		.option("--show-token", "Output the session token (for debugging)")
		.option("--ttl <minutes>", "Token TTL in minutes (default: 60)", "60")
		.option("--daemon", "Run as daemon, refreshing token periodically before expiry")
		.action(async (opts: { showToken?: boolean; ttl?: string; daemon?: boolean }) => {
			const proxyUrl = process.env.TELCLAUDE_GIT_PROXY_URL;
			if (!proxyUrl) {
				console.error("TELCLAUDE_GIT_PROXY_URL is not set - skipping git proxy configuration");
				console.error(
					"This command should only run when relay git proxy configuration is present.",
				);
				process.exit(0); // Not an error - just not applicable
			}

			const ttlMinutes = Number.parseInt(opts.ttl ?? "60", 10);
			if (Number.isNaN(ttlMinutes) || ttlMinutes < 1) {
				console.error(`[git-proxy-init] Invalid TTL: ${opts.ttl} (must be a positive integer)`);
				process.exit(1);
			}
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
				const output = execFileSync("git", ["config", "--global", "--get-regexp", "^url\\."], {
					encoding: "utf8",
				});
				// Show first 3 lines
				const lines = output.split("\n").slice(0, 3);
				for (const line of lines) {
					if (line.trim()) console.log(line);
				}
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
				const { runDaemon } = await import("./cli-utils.js");
				await runDaemon();
			}
		});
}
