/**
 * Central remediation table for health-issue → suggested command mapping.
 *
 * This is consumed by the `/system` health card (W10) and forms the source of
 * truth for remediation hints surfaced to operators. Wave 2's W13 command
 * surface sweep keeps this authoritative — no renderer should hardcode
 * remediation strings.
 *
 * Each entry is keyed by a stable `RemediationKey` and carries:
 *  - `title`: short human label for the issue category
 *  - `command`: the CLI command to run (or a Telegram command with `/` prefix)
 *  - `explanation`: 1-2 sentence reason/what the command does
 *  - `docsPath` (optional): repo-relative path to deeper docs
 *
 * Keep this file short — extend via new keys rather than growing descriptions.
 */
export type RemediationKey =
	| "anthropic_auth_expired"
	| "openai_key_missing"
	| "openai_key_expired"
	| "google_oauth_missing"
	| "google_oauth_expired"
	| "provider_unreachable"
	| "provider_degraded"
	| "provider_auth_expired"
	| "vault_unreachable"
	| "cron_lagging"
	| "cron_disabled"
	| "heartbeat_stale"
	| "heartbeat_disabled"
	| "pending_approvals"
	| "active_background_jobs"
	| "session_stale"
	| "tier_misconfigured"
	| "model_fallback_active";

export type RemediationEntry = {
	key: RemediationKey;
	title: string;
	command: string;
	explanation: string;
	docsPath?: string;
};

/**
 * Central remediation catalog. Ordered for deterministic iteration in tests.
 */
const REMEDIATION_CATALOG: Record<RemediationKey, RemediationEntry> = {
	anthropic_auth_expired: {
		key: "anthropic_auth_expired",
		title: "Anthropic auth",
		command: "claude login",
		explanation: "Re-authenticate the Claude CLI so the relay can proxy Anthropic requests.",
	},
	openai_key_missing: {
		key: "openai_key_missing",
		title: "OpenAI key missing",
		command: "telclaude setup-openai",
		explanation: "Store an OpenAI API key in the vault for image, TTS, and transcription services.",
	},
	openai_key_expired: {
		key: "openai_key_expired",
		title: "OpenAI key expired",
		command: "telclaude setup-openai",
		explanation: "The stored OpenAI credential failed auth — rotate and re-save it in the vault.",
	},
	google_oauth_missing: {
		key: "google_oauth_missing",
		title: "Google OAuth missing",
		command: "telclaude secrets setup-google",
		explanation: "Install Google OAuth credentials in the vault to enable Gmail/Calendar/Drive.",
	},
	google_oauth_expired: {
		key: "google_oauth_expired",
		title: "Google OAuth expired",
		command: "telclaude secrets setup-google",
		explanation: "Google refresh token was revoked or expired. Re-run the OAuth setup flow.",
		docsPath: "docs/providers.md",
	},
	provider_unreachable: {
		key: "provider_unreachable",
		title: "Provider unreachable",
		command: "telclaude providers health",
		explanation: "The sidecar did not respond. Check the container and network allowlist.",
	},
	provider_degraded: {
		key: "provider_degraded",
		title: "Provider degraded",
		command: "telclaude providers health",
		explanation: "The sidecar reported a degraded connector. Inspect per-connector status.",
	},
	provider_auth_expired: {
		key: "provider_auth_expired",
		title: "Provider auth expired",
		command: "telclaude providers setup",
		explanation: "A sidecar connector requires re-authentication. Re-run the provider setup flow.",
		docsPath: "docs/providers.md",
	},
	vault_unreachable: {
		key: "vault_unreachable",
		title: "Vault unreachable",
		command: "telclaude vault-daemon",
		explanation:
			"The credential vault is not responding on its Unix socket. Start the daemon and retry.",
	},
	cron_lagging: {
		key: "cron_lagging",
		title: "Cron lag",
		command: "/system cron",
		explanation:
			"At least one enabled cron job is overdue. Review the scheduler for stuck or slow runs.",
	},
	cron_disabled: {
		key: "cron_disabled",
		title: "Cron disabled",
		command: "telclaude maintenance cron status",
		explanation: "The cron scheduler is disabled in config. Enable it or run jobs manually.",
	},
	heartbeat_stale: {
		key: "heartbeat_stale",
		title: "Heartbeat stale",
		command: "telclaude maintenance cron run <job-id>",
		explanation:
			"The private heartbeat has not run within its interval. Trigger a manual run to investigate.",
	},
	heartbeat_disabled: {
		key: "heartbeat_disabled",
		title: "Heartbeat disabled",
		command: "telclaude maintenance cron add --name private-heartbeat --every 6h",
		explanation: "No private heartbeat cron is scheduled. Add one to enable autonomous activity.",
	},
	pending_approvals: {
		key: "pending_approvals",
		title: "Pending approvals",
		command: "/approve <code>",
		explanation:
			"Approvals are blocking a tiered action. Review the pending approval card and respond.",
	},
	active_background_jobs: {
		key: "active_background_jobs",
		title: "Background jobs active",
		command: "/background list",
		explanation: "Background jobs are in flight. Use `/background list` for details and cancel.",
	},
	session_stale: {
		key: "session_stale",
		title: "Sessions stale",
		command: "/system sessions",
		explanation:
			"One or more sessions have not been touched in over 24h. Review and reset if unused.",
	},
	tier_misconfigured: {
		key: "tier_misconfigured",
		title: "Tier misconfigured",
		command: "telclaude permissions show",
		explanation: "The default permission tier is not set. Verify security.permissions in config.",
	},
	model_fallback_active: {
		key: "model_fallback_active",
		title: "Model fallback active",
		command: "/system",
		explanation: "Claude is running on a fallback model. Check CLI auth and network egress.",
	},
};

/**
 * Lookup a remediation entry by key. Returns undefined for unknown keys so
 * callers can decide how to handle missing metadata.
 */
export function getRemediation(key: RemediationKey): RemediationEntry | undefined {
	return REMEDIATION_CATALOG[key];
}

/**
 * Enumerate every remediation entry in catalog order. Useful for tests and
 * command-surface sweeps that need to validate coverage.
 */
export function listRemediations(): RemediationEntry[] {
	return Object.values(REMEDIATION_CATALOG);
}

/**
 * All valid remediation keys (for runtime validation in tests or schemas).
 */
export const REMEDIATION_KEYS: readonly RemediationKey[] = Object.keys(
	REMEDIATION_CATALOG,
) as RemediationKey[];
