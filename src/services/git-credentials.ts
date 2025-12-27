/**
 * Git credentials service.
 * Provides secure credential retrieval for git operations.
 *
 * Credential resolution order:
 * 1. Keychain/encrypted storage (via `telclaude setup-git`)
 * 2. Environment variables (GIT_USERNAME, GIT_EMAIL, GITHUB_TOKEN)
 * 3. GitHub App installation token (via `telclaude setup-github-app`)
 */

import { spawnSync } from "node:child_process";

import { getChildLogger } from "../logging.js";
import { type GitCredentials, getSecret, hasSecret, SECRET_KEYS } from "../secrets/index.js";
import {
	getGitHubAppIdentity,
	getInstallationTokenInfo,
	isGitHubAppConfigured,
} from "./github-app.js";

const logger = getChildLogger({ module: "git-credentials" });

const GITHUB_APP_TOKEN_REFRESH_BUFFER_MS = 5 * 60 * 1000;

let cachedCredentials: GitCredentials | null = null;
let cachedCredentialsSource: "secure-storage" | "environment" | "github-app" | null = null;
let cachedGitHubTokenExpiresAt: Date | null = null;

function isCachedGitHubTokenFresh(): boolean {
	if (!cachedGitHubTokenExpiresAt) return false;
	return cachedGitHubTokenExpiresAt.getTime() - GITHUB_APP_TOKEN_REFRESH_BUFFER_MS > Date.now();
}

/**
 * Get git credentials from keychain, env, or config.
 * Caches the result for performance.
 */
export async function getGitCredentials(): Promise<GitCredentials | null> {
	if (cachedCredentials) {
		if (cachedCredentialsSource !== "github-app" || isCachedGitHubTokenFresh()) {
			return cachedCredentials;
		}
	}

	// 1. Try keychain/encrypted storage first
	try {
		const stored = await getSecret(SECRET_KEYS.GIT_CREDENTIALS);
		if (stored) {
			try {
				const parsed = JSON.parse(stored) as GitCredentials;
				// Validate required fields
				if (parsed.username && parsed.email && parsed.token) {
					cachedCredentials = parsed;
					cachedCredentialsSource = "secure-storage";
					cachedGitHubTokenExpiresAt = null;
					logger.debug("using git credentials from secure storage");
					return cachedCredentials;
				}
				logger.warn("stored git credentials missing required fields, ignoring");
			} catch (parseErr) {
				logger.warn({ error: String(parseErr) }, "stored git credentials are corrupted, ignoring");
			}
		}
	} catch (err) {
		logger.debug({ error: String(err) }, "secure storage not available for git credentials");
	}

	// 2. Try environment variables
	const envUsername = process.env.GIT_USERNAME;
	const envEmail = process.env.GIT_EMAIL;
	const envToken = process.env.GITHUB_TOKEN || process.env.GIT_TOKEN;

	if (envUsername && envEmail && envToken) {
		cachedCredentials = {
			username: envUsername,
			email: envEmail,
			token: envToken,
		};
		cachedCredentialsSource = "environment";
		cachedGitHubTokenExpiresAt = null;
		logger.debug("using git credentials from environment variables");
		return cachedCredentials;
	}

	// 3. Try GitHub App installation token
	if (await isGitHubAppConfigured()) {
		const [tokenInfo, identity] = await Promise.all([
			getInstallationTokenInfo(),
			getGitHubAppIdentity(),
		]);
		if (tokenInfo && identity) {
			cachedCredentials = {
				username: identity.username,
				email: identity.email,
				token: tokenInfo.token,
			};
			cachedCredentialsSource = "github-app";
			cachedGitHubTokenExpiresAt = tokenInfo.expiresAt;
			logger.debug("using git credentials from GitHub App");
			return cachedCredentials;
		}
	}

	// Warn about partial env config only if no other source worked
	if (envUsername || envEmail || envToken) {
		logger.debug(
			{
				hasUsername: !!envUsername,
				hasEmail: !!envEmail,
				hasToken: !!envToken,
			},
			"partial git credentials in environment (GitHub App not configured)",
		);
	}

	return null;
}

/**
 * Check if git credentials are configured.
 */
export async function isGitConfigured(): Promise<boolean> {
	const creds = await getGitCredentials();
	return !!creds;
}

/**
 * Check if git credentials exist in secure storage.
 */
export async function hasGitCredentialsStored(): Promise<boolean> {
	try {
		return await hasSecret(SECRET_KEYS.GIT_CREDENTIALS);
	} catch {
		return false;
	}
}

/**
 * Get the credential source description.
 * Only returns "secure storage" if the stored credentials are valid JSON
 * with all required fields.
 */
export async function getGitCredentialsSource(): Promise<string | null> {
	try {
		const stored = await getSecret(SECRET_KEYS.GIT_CREDENTIALS);
		if (stored) {
			// Validate that stored JSON is valid and has required fields
			try {
				const parsed = JSON.parse(stored) as GitCredentials;
				if (parsed.username && parsed.email && parsed.token) {
					return "secure storage";
				}
			} catch {
				// JSON is corrupted, fall through to env vars
			}
		}
	} catch {
		// Keychain not available
	}

	const envToken = process.env.GITHUB_TOKEN || process.env.GIT_TOKEN;
	if (process.env.GIT_USERNAME && process.env.GIT_EMAIL && envToken) {
		return "environment variables";
	}

	// Check GitHub App
	if (await isGitHubAppConfigured()) {
		return "GitHub App";
	}

	return null;
}

/**
 * Clear cached git credentials.
 * Call this after credential rotation or deletion.
 */
export function clearGitCredentialsCache(): void {
	cachedCredentials = null;
	cachedCredentialsSource = null;
	cachedGitHubTokenExpiresAt = null;
	logger.debug("git credentials cache cleared");
}

/**
 * Get cached GitHub token if credentials have been loaded.
 * Returns null if credentials haven't been initialized yet.
 * Use this for sync access to the token (e.g., in sandbox env building).
 */
export function getCachedGitToken(): string | null {
	if (cachedCredentialsSource === "github-app" && !isCachedGitHubTokenFresh()) {
		return null;
	}
	return cachedCredentials?.token ?? null;
}

/**
 * Initialize git credentials lookup (call at startup).
 * This populates the cache so getCachedGitToken() works correctly.
 */
export async function initializeGitCredentials(): Promise<boolean> {
	const creds = await getGitCredentials();
	return !!creds;
}

/**
 * Apply git identity configuration to the system.
 * This configures git user.name and user.email globally.
 *
 * Uses spawnSync with array arguments to prevent command injection.
 */
export async function applyGitIdentity(): Promise<boolean> {
	const creds = await getGitCredentials();
	if (!creds) {
		logger.debug("no git credentials available to apply");
		return false;
	}

	try {
		// Use spawnSync with array args to prevent command injection
		const nameResult = spawnSync("git", ["config", "--global", "user.name", creds.username], {
			stdio: "pipe",
		});
		if (nameResult.status !== 0) {
			throw new Error(`git config user.name failed: ${nameResult.stderr?.toString()}`);
		}

		const emailResult = spawnSync("git", ["config", "--global", "user.email", creds.email], {
			stdio: "pipe",
		});
		if (emailResult.status !== 0) {
			throw new Error(`git config user.email failed: ${emailResult.stderr?.toString()}`);
		}

		logger.info({ username: creds.username, email: creds.email }, "git identity configured");
		return true;
	} catch (err) {
		logger.error({ error: String(err) }, "failed to configure git identity");
		return false;
	}
}

/** Hosts we provide credentials for (exact match or subdomain). */
export const ALLOWED_HOSTS = ["github.com", "gitlab.com", "bitbucket.org"] as const;

/**
 * Normalize a hostname for allowlist comparison.
 * Strips port numbers and IPv6 brackets.
 */
function normalizeHostname(host: string): string {
	let normalized = host.toLowerCase();
	// Strip IPv6 brackets: [::1] -> ::1
	if (normalized.startsWith("[") && normalized.includes("]")) {
		normalized = normalized.slice(1, normalized.indexOf("]"));
	}
	// Strip port: github.com:443 -> github.com
	const colonIdx = normalized.lastIndexOf(":");
	if (colonIdx > 0 && !normalized.includes("[")) {
		normalized = normalized.slice(0, colonIdx);
	}
	return normalized;
}

/**
 * Check if a host is in the allowlist for git credentials.
 * Matches exact host or subdomains (e.g., "api.github.com" matches "github.com").
 * Prevents bypass attacks like "evil-github.com" or "github.com.evil.com".
 * Handles ports (github.com:443) and IPv6 brackets.
 */
export function isHostAllowed(host: string): boolean {
	const normalized = normalizeHostname(host);
	return ALLOWED_HOSTS.some((allowed) => {
		return normalized === allowed || normalized.endsWith(`.${allowed}`);
	});
}

/**
 * Convert a repo URL to HTTPS format (normalizes SSH URLs).
 * Does NOT inject credentials - use for clean URLs only.
 */
function toHttpsUrl(repoUrl: string): string | null {
	let url = repoUrl;

	// Convert SSH URLs to HTTPS (git@host:path -> https://host/path)
	const sshMatch = url.match(/^git@([^:]+):(.+)$/);
	if (sshMatch) {
		const [, host, path] = sshMatch;
		url = `https://${host}/${path}`;
	}

	if (url.startsWith("https://")) {
		return url;
	}

	return null;
}

/**
 * Get the HTTPS URL with embedded credentials for a git repo.
 * Format: https://username:token@host/owner/repo.git
 *
 * SECURITY: Only injects credentials for allowed hosts.
 * Returns null for non-allowed hosts to prevent credential exfiltration.
 *
 * @deprecated Use runGitWithAuth() instead to avoid token exposure in process args.
 */
export async function getAuthenticatedUrl(repoUrl: string): Promise<string | null> {
	const creds = await getGitCredentials();
	if (!creds) return null;

	try {
		const url = toHttpsUrl(repoUrl);
		if (!url) return null;

		const parsed = new URL(url);

		// CRITICAL: Enforce host allowlist to prevent credential exfiltration
		if (!isHostAllowed(parsed.hostname)) {
			logger.warn({ host: parsed.hostname }, "refusing credentials for non-allowed host");
			return null;
		}

		parsed.username = creds.username;
		parsed.password = creds.token;
		return parsed.toString();
	} catch (err) {
		logger.error({ error: String(err), repoUrl }, "failed to parse git URL");
		return null;
	}
}

/**
 * Run a git command with authentication via http.extraHeader.
 * This avoids exposing credentials in process args (visible in `ps`).
 *
 * SECURITY: Only provides auth for allowed hosts. The repoUrl parameter
 * is validated against the allowlist before adding auth headers.
 *
 * @param args - Git command arguments (e.g., ["ls-remote", url, "HEAD"])
 * @param options.repoUrl - Repository URL to authenticate against (REQUIRED for auth)
 * @param options.timeout - Command timeout in ms
 * @param options.cwd - Working directory
 */
export async function runGitWithAuth(
	args: string[],
	options: { repoUrl?: string; timeout?: number; cwd?: string } = {},
): Promise<{ status: number | null; stdout: string; stderr: string; error?: Error }> {
	const creds = await getGitCredentials();
	const extraArgs: string[] = [];

	// Only add auth if we have credentials AND the host is allowed
	if (creds && options.repoUrl) {
		const url = toHttpsUrl(options.repoUrl);
		if (url) {
			try {
				const parsed = new URL(url);
				if (isHostAllowed(parsed.hostname)) {
					const authHeader = `Authorization: Basic ${Buffer.from(`${creds.username}:${creds.token}`).toString("base64")}`;
					extraArgs.push("-c", `http.extraHeader=${authHeader}`);
				} else {
					logger.warn(
						{ host: parsed.hostname },
						"runGitWithAuth: refusing auth for non-allowed host",
					);
				}
			} catch {
				logger.warn({ url: options.repoUrl }, "runGitWithAuth: invalid URL");
			}
		}
	}

	const result = spawnSync("git", [...extraArgs, ...args], {
		timeout: options.timeout ?? 30000,
		stdio: "pipe",
		cwd: options.cwd,
	});

	return {
		status: result.status,
		stdout: result.stdout?.toString() || "",
		stderr: result.stderr?.toString() || "",
		error: result.error,
	};
}

/**
 * Format credentials for git credential helper protocol.
 * Used by the custom credential helper.
 *
 * Protocol requires blank line terminator.
 */
export async function formatForCredentialHelper(host: string): Promise<string | null> {
	const creds = await getGitCredentials();
	if (!creds) return null;

	// Only provide credentials for known hosts (exact match or subdomain)
	if (!isHostAllowed(host)) {
		logger.debug({ host }, "credential helper: host not in allowlist");
		return null;
	}

	// Protocol: key=value lines terminated by blank line
	return `protocol=https
host=${host}
username=${creds.username}
password=${creds.token}

`;
}

/**
 * Sanitize a string to remove any embedded credentials.
 * - Replaces URL patterns like https://user:token@host with https://***@host
 * - Replaces the actual cached token if present
 */
function sanitizeCredentials(str: string): string {
	let sanitized = str;

	// Remove credentials from URLs (https://user:pass@host -> https://***@host)
	sanitized = sanitized.replace(/https?:\/\/[^@\s]+@/gi, "https://***@");

	// Also redact the actual token if we have it cached
	if (cachedCredentials?.token) {
		sanitized = sanitized.replaceAll(cachedCredentials.token, "***");
	}

	return sanitized;
}

/**
 * Test git connectivity by attempting to access a remote.
 * Returns success status and any error message.
 *
 * @param testUrl - Either a base URL (https://github.com) or full repo URL
 *                  (https://github.com/owner/repo.git). If base URL, uses
 *                  a public test repo. If full URL, uses that directly.
 *
 * SECURITY: Uses http.extraHeader to pass credentials, avoiding exposure
 * in process args (visible via `ps`). Sanitizes all error output.
 */
export async function testGitConnectivity(
	testUrl = "https://github.com",
): Promise<{ success: boolean; message: string }> {
	const creds = await getGitCredentials();
	if (!creds) {
		return { success: false, message: "No git credentials configured" };
	}

	try {
		// Determine if testUrl is a full repo URL or just a base URL
		// Full repo URLs typically end with .git or have /owner/repo pattern
		let repoUrl: string;
		if (testUrl.endsWith(".git") || /\/[^/]+\/[^/]+\/?$/.test(testUrl)) {
			// Full repo URL - use as-is
			repoUrl = testUrl;
		} else {
			// Base URL - append test repo (GitHub's public Hello-World)
			repoUrl = `${testUrl.replace(/\/$/, "")}/octocat/Hello-World.git`;
		}

		// Normalize to HTTPS
		const cleanUrl = toHttpsUrl(repoUrl);
		if (!cleanUrl) {
			return { success: false, message: "Invalid repository URL format" };
		}

		// Verify host is allowed before sending credentials
		const parsed = new URL(cleanUrl);
		if (!isHostAllowed(parsed.hostname)) {
			return { success: false, message: `Host not in allowlist: ${parsed.hostname}` };
		}

		// Test with git ls-remote using http.extraHeader (not URL-embedded token)
		const result = await runGitWithAuth(["ls-remote", "--exit-code", cleanUrl, "HEAD"], {
			repoUrl: cleanUrl,
			timeout: 15000,
		});

		if (result.status === 0) {
			return { success: true, message: "Successfully connected to GitHub" };
		}

		// Handle error - sanitize output to prevent credential leakage
		const stderr = sanitizeCredentials(result.stderr);
		const errorStr = sanitizeCredentials(String(result.error || stderr));

		if (
			errorStr.includes("401") ||
			errorStr.includes("403") ||
			errorStr.includes("Authentication")
		) {
			return {
				success: false,
				message: "Authentication failed - check your token has correct permissions",
			};
		}

		if (errorStr.includes("ETIMEDOUT") || errorStr.includes("timeout")) {
			return { success: false, message: "Connection timed out - check network connectivity" };
		}

		return { success: false, message: `Connection failed: ${errorStr.slice(0, 100)}` };
	} catch (err) {
		// Sanitize any error message to prevent credential leakage
		const errorStr = sanitizeCredentials(String(err));

		if (errorStr.includes("401") || errorStr.includes("403")) {
			return {
				success: false,
				message: "Authentication failed - check your token has correct permissions",
			};
		}

		if (errorStr.includes("ETIMEDOUT") || errorStr.includes("timeout")) {
			return { success: false, message: "Connection timed out - check network connectivity" };
		}

		return { success: false, message: `Connection failed: ${errorStr.slice(0, 100)}` };
	}
}
