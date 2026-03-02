/**
 * Shared CLI precondition guards.
 *
 * Consolidates duplicate "is X available? if not, exit(1)" patterns from
 * setup-openai, setup-git, setup-google, oauth, vault, provider-query,
 * fetch-attachment, send-attachment, and send-local-file commands.
 */

import { isSecretsStorageAvailable } from "../secrets/index.js";
import { getVaultClient, isVaultAvailable, type VaultClient } from "../vault-daemon/index.js";

/**
 * Require TELCLAUDE_CAPABILITIES_URL to be set (relay available).
 * Exits with code 1 if missing.
 */
export function requireRelay(): string {
	const url = process.env.TELCLAUDE_CAPABILITIES_URL;
	if (!url) {
		console.error("Error: TELCLAUDE_CAPABILITIES_URL is not configured.");
		console.error("This command requires the relay capabilities server.");
		process.exit(1);
	}
	return url;
}

/**
 * Require vault daemon to be running.
 * Exits with code 1 if unavailable.
 */
export async function requireVault(): Promise<VaultClient> {
	if (!(await isVaultAvailable())) {
		console.error("Error: Vault daemon is not running.");
		console.error("Start it with: telclaude vault-daemon");
		process.exit(1);
	}
	return getVaultClient();
}

/**
 * Require secrets storage to be available (keychain or encrypted file).
 * Exits with code 1 if unavailable.
 */
export async function requireSecretsStorage(): Promise<void> {
	if (!(await isSecretsStorageAvailable())) {
		console.error(
			"Error: Secrets storage not available.\n" +
				"On Linux, install libsecret-1-dev, or set SECRETS_ENCRYPTION_KEY for file storage.",
		);
		process.exit(1);
	}
}
