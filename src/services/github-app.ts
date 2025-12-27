/**
 * GitHub App authentication service.
 *
 * Provides installation token generation for GitHub App-based authentication.
 * Tokens are short-lived (1 hour) and automatically refreshed.
 *
 * Benefits over PAT:
 * - No long-lived secrets (tokens expire in 1 hour)
 * - Fine-grained permissions per repository
 * - Commits are signed automatically by GitHub
 * - Bot identity (telclaude[bot]) instead of personal account
 */

import { readFileSync } from "node:fs";

import { createAppAuth } from "@octokit/auth-app";
import { Octokit } from "@octokit/rest";

import { getChildLogger } from "../logging.js";
import { getSecret, SECRET_KEYS } from "../secrets/index.js";

const logger = getChildLogger({ module: "github-app" });

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

/** GitHub App configuration stored in secrets */
export interface GitHubAppConfig {
	appId: string | number;
	installationId: string | number;
	/** Path to PEM file OR inline PEM content */
	privateKey: string;
	/** Bot user ID for commit attribution */
	botUserId: number;
	/** App slug (e.g., "telclaude") */
	appSlug: string;
}

/** Cached installation token */
interface CachedToken {
	token: string;
	expiresAt: Date;
}

export interface InstallationTokenInfo {
	token: string;
	expiresAt: Date;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Token Cache
// ═══════════════════════════════════════════════════════════════════════════════

let cachedToken: CachedToken | null = null;
let cachedConfig: GitHubAppConfig | null = null;

/**
 * Clear the cached token and config.
 * Call after credential changes.
 */
export function clearGitHubAppCache(): void {
	cachedToken = null;
	cachedConfig = null;
	logger.debug("github app cache cleared");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Load GitHub App configuration from secrets storage.
 */
export async function getGitHubAppConfig(): Promise<GitHubAppConfig | null> {
	if (cachedConfig) return cachedConfig;

	try {
		const stored = await getSecret(SECRET_KEYS.GITHUB_APP);
		if (!stored) {
			logger.debug("no github app config in secrets storage");
			return null;
		}

		const config = JSON.parse(stored) as GitHubAppConfig;

		// Validate required fields
		if (!config.appId || !config.installationId || !config.privateKey) {
			logger.warn("stored github app config missing required fields");
			return null;
		}

		cachedConfig = config;
		return config;
	} catch (err) {
		logger.error({ error: String(err) }, "failed to load github app config");
		return null;
	}
}

/**
 * Check if GitHub App is configured.
 */
export async function isGitHubAppConfigured(): Promise<boolean> {
	const config = await getGitHubAppConfig();
	return config !== null;
}

/**
 * Get the private key content (handles both path and inline).
 */
function getPrivateKeyContent(privateKey: string): string {
	// If it looks like a PEM file path, read it
	if (privateKey.endsWith(".pem") || privateKey.startsWith("/")) {
		try {
			return readFileSync(privateKey, "utf8");
		} catch (err) {
			throw new Error(`Failed to read private key from ${privateKey}: ${String(err)}`);
		}
	}

	// Otherwise, assume it's inline PEM content
	// Handle escaped newlines from env vars
	return privateKey.replace(/\\n/g, "\n");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Token Generation
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Get a valid installation token.
 * Returns cached token if still valid, otherwise generates a new one.
 *
 * Token is valid for 1 hour from generation.
 */
export async function getInstallationTokenInfo(): Promise<InstallationTokenInfo | null> {
	const config = await getGitHubAppConfig();
	if (!config) {
		return null;
	}

	// Check if cached token is still valid (with 5 min buffer)
	if (cachedToken) {
		const now = new Date();
		const bufferMs = 5 * 60 * 1000; // 5 minutes
		if (cachedToken.expiresAt.getTime() - bufferMs > now.getTime()) {
			logger.debug("using cached installation token");
			return { token: cachedToken.token, expiresAt: cachedToken.expiresAt };
		}
		logger.debug("cached token expired, generating new one");
	}

	try {
		const privateKey = getPrivateKeyContent(config.privateKey);

		const auth = createAppAuth({
			appId: Number(config.appId),
			privateKey,
			installationId: Number(config.installationId),
		});

		const { token, expiresAt } = await auth({ type: "installation" });

		cachedToken = {
			token,
			expiresAt: new Date(expiresAt),
		};

		logger.info(
			{ expiresAt: cachedToken.expiresAt.toISOString() },
			"generated new installation token",
		);

		return { token, expiresAt: cachedToken.expiresAt };
	} catch (err) {
		logger.error({ error: String(err) }, "failed to generate installation token");
		return null;
	}
}

export async function getInstallationToken(): Promise<string | null> {
	const info = await getInstallationTokenInfo();
	return info?.token ?? null;
}

/**
 * Get an authenticated Octokit instance.
 */
export async function getOctokit(): Promise<Octokit | null> {
	const token = await getInstallationToken();
	if (!token) return null;

	return new Octokit({ auth: token });
}

// ═══════════════════════════════════════════════════════════════════════════════
// Git Identity
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Get git identity for commits.
 * Returns the bot user identity for commit attribution.
 */
export async function getGitHubAppIdentity(): Promise<{ username: string; email: string } | null> {
	const config = await getGitHubAppConfig();
	if (!config) return null;

	const slug = config.appSlug || "telclaude";
	const userId = config.botUserId || 251589752; // Default to telclaude[bot] ID

	return {
		username: `${slug}[bot]`,
		email: `${userId}+${slug}[bot]@users.noreply.github.com`,
	};
}

// ═══════════════════════════════════════════════════════════════════════════════
// App Metadata
// ═══════════════════════════════════════════════════════════════════════════════

export interface GitHubAppMetadata {
	appId: number;
	appSlug: string;
	appName: string;
	botUserId: number;
}

/**
 * Fetch app metadata from GitHub API.
 * Used during setup to get the correct slug and bot user ID.
 */
export async function fetchGitHubAppMetadata(
	appId: string | number,
	privateKeyPath: string,
): Promise<GitHubAppMetadata> {
	const privateKey = getPrivateKeyContent(privateKeyPath);

	const auth = createAppAuth({
		appId: Number(appId),
		privateKey,
	});

	// Get app-level token (JWT) to query /app endpoint
	const { token } = await auth({ type: "app" });
	const octokit = new Octokit({ auth: token });

	// GET /app returns the authenticated app's info
	const { data: app } = await octokit.rest.apps.getAuthenticated();

	if (!app) {
		throw new Error("Failed to fetch app info: empty response");
	}

	const appSlug = app.slug ?? app.name.toLowerCase().replace(/\s+/g, "-");

	// The bot user ID is derived from the app ID
	// GitHub assigns bot users with IDs in a specific pattern
	// We can get the actual bot user by looking up the slug
	let botUserId = app.id;
	try {
		// Try to get the actual bot user ID by looking up the bot user
		const { data: botUser } = await octokit.rest.users.getByUsername({
			username: `${appSlug}[bot]`,
		});
		botUserId = botUser.id;
	} catch {
		// Fall back to app ID if bot user lookup fails
		// This can happen for new apps that haven't been used yet
	}

	return {
		appId: app.id,
		appSlug,
		appName: app.name,
		botUserId,
	};
}

// ═══════════════════════════════════════════════════════════════════════════════
// Verification
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Test GitHub App connectivity.
 */
export async function testGitHubAppConnectivity(): Promise<{
	success: boolean;
	message: string;
	details?: Record<string, unknown>;
}> {
	const config = await getGitHubAppConfig();
	if (!config) {
		return { success: false, message: "GitHub App not configured" };
	}

	try {
		const octokit = await getOctokit();
		if (!octokit) {
			return { success: false, message: "Failed to get authenticated client" };
		}

		// Test by listing accessible repos (uses installation token correctly)
		const { data: reposData } = await octokit.rest.apps.listReposAccessibleToInstallation({
			per_page: 5,
		});

		let installationAccount: string | undefined;
		try {
			const privateKey = getPrivateKeyContent(config.privateKey);
			const appAuth = createAppAuth({
				appId: Number(config.appId),
				privateKey,
			});
			const { token: appToken } = await appAuth({ type: "app" });
			const appOctokit = new Octokit({ auth: appToken });
			const { data: installation } = await appOctokit.rest.apps.getInstallation({
				installation_id: Number(config.installationId),
			});
			const account = installation.account;
			installationAccount =
				account && "login" in account ? account.login : (account?.name ?? undefined);
		} catch (err) {
			logger.debug({ error: String(err) }, "failed to fetch installation account");
		}

		const repoCount = reposData.total_count;
		const repoNames = reposData.repositories.map((r) => r.name).slice(0, 3);
		const details: Record<string, unknown> = {
			appName: config.appSlug,
			appSlug: config.appSlug,
			repositorySelection: `${repoCount} repos (${repoNames.join(", ")}${repoCount > 3 ? "..." : ""})`,
			permissions: {},
		};
		if (installationAccount) {
			details.installationAccount = installationAccount;
		}

		return {
			success: true,
			message: `Connected as ${config.appSlug}[bot]`,
			details,
		};
	} catch (err) {
		const errorStr = String(err);

		if (errorStr.includes("401") || errorStr.includes("Bad credentials")) {
			return { success: false, message: "Invalid private key or app ID" };
		}

		if (errorStr.includes("404")) {
			return { success: false, message: "Installation not found - check installation ID" };
		}

		return { success: false, message: `Connection failed: ${errorStr.slice(0, 100)}` };
	}
}

/**
 * List repositories the app has access to.
 */
export async function listAccessibleRepositories(): Promise<string[]> {
	const octokit = await getOctokit();
	if (!octokit) return [];

	try {
		const { data } = await octokit.rest.apps.listReposAccessibleToInstallation({
			per_page: 100,
		});

		return data.repositories.map((repo) => repo.full_name);
	} catch (err) {
		logger.error({ error: String(err) }, "failed to list accessible repositories");
		return [];
	}
}
