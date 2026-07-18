/**
 * Typed health-check primitives shared by `telclaude dev doctor` and
 * other surfaces that need structured pass/warn/fail status (e.g.
 * `telclaude relay` startup banner, `/system doctor` card).
 *
 * Every check returns a {status, detail} pair. `checks` is ordered
 * and stable so JSON consumers (CI, dashboards) can pin on `name`.
 *
 * Kept deliberately small and dependency-free: all side effects
 * (process.exit, logger, etc.) belong in the CLI entrypoint; the
 * helpers here only *describe* status.
 */

import { execSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { collectAgentRuntimeStatuses } from "../agent-runtime/status.js";
import type { TelclaudeConfig } from "../config/config.js";
import { fetchWithTimeout } from "../infra/timeout.js";
import { getChildLogger } from "../logging.js";
import {
	PROVIDER_SIDECAR_HMAC_DEFAULT_VAULT_TARGET,
	PROVIDER_SIDECAR_HMAC_SECRET_ENV,
	PROVIDER_SIDECAR_HMAC_VAULT_TARGET_ENV,
} from "../relay/provider-sidecar-auth.js";
import {
	TELCLAUDE_WHATSAPP_ALLOWED_RECIPIENTS_ENV,
	TELCLAUDE_WHATSAPP_BRIDGE_SECRET_ENV,
	TELCLAUDE_WHATSAPP_SIDECAR_URL_ENV,
	WHATSAPP_SIDECAR_ALLOWED_HOST,
} from "../relay/whatsapp-edge-channel-connector.js";
import {
	TELCLAUDE_WHATSAPP_INBOUND_OPERATOR_ADDRESSES_ENV,
	TELCLAUDE_WHATSAPP_INBOUND_SECRET_ENV,
} from "../relay/whatsapp-inbound-http.js";
import { getAllDraftSkillRoots, getAllSkillRoots } from "./skill-path.js";

const logger = getChildLogger({ module: "doctor-helpers" });
const SIDECAR_REQUIRE_RELAY_HMAC_ENV = "SIDECAR_REQUIRE_RELAY_HMAC";

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export type CheckStatus = "pass" | "warn" | "fail" | "skip";

export interface CheckResult {
	/** Stable identifier, e.g. "config.loaded" or "providers.google.health" */
	name: string;
	/** Human-readable category heading (group header only, not machine-keyed) */
	category: string;
	/** Pass / warn / fail / skip */
	status: CheckStatus;
	/** One-line summary of what was observed */
	summary: string;
	/** Optional multi-line detail (remediation, raw output, etc.) */
	detail?: string;
	/**
	 * Remediation command suggestion (always a current namespaced form).
	 * Consumers may render this as a "try:" line.
	 */
	remediation?: string;
}

export interface DoctorReport {
	checks: CheckResult[];
	summary: {
		pass: number;
		warn: number;
		fail: number;
		skip: number;
	};
}

// ─────────────────────────────────────────────────────────────────────────────
// Check builders
// ─────────────────────────────────────────────────────────────────────────────

export function pass(
	name: string,
	category: string,
	summary: string,
	detail?: string,
): CheckResult {
	return { name, category, status: "pass", summary, detail };
}

export function warn(
	name: string,
	category: string,
	summary: string,
	detail?: string,
	remediation?: string,
): CheckResult {
	return { name, category, status: "warn", summary, detail, remediation };
}

export function fail(
	name: string,
	category: string,
	summary: string,
	detail?: string,
	remediation?: string,
): CheckResult {
	return { name, category, status: "fail", summary, detail, remediation };
}

export function skip(
	name: string,
	category: string,
	summary: string,
	detail?: string,
): CheckResult {
	return { name, category, status: "skip", summary, detail };
}

// ─────────────────────────────────────────────────────────────────────────────
// Reporting
// ─────────────────────────────────────────────────────────────────────────────

export function summarize(checks: readonly CheckResult[]): DoctorReport["summary"] {
	const summary = { pass: 0, warn: 0, fail: 0, skip: 0 };
	for (const c of checks) summary[c.status]++;
	return summary;
}

/**
 * Worst status in an ordered list. Used to decide exit codes and
 * whether the high-level banner says "all green".
 */
export function worstStatus(checks: readonly CheckResult[]): CheckStatus {
	if (checks.some((c) => c.status === "fail")) return "fail";
	if (checks.some((c) => c.status === "warn")) return "warn";
	if (checks.every((c) => c.status === "skip")) return "skip";
	return "pass";
}

export function buildReport(checks: readonly CheckResult[]): DoctorReport {
	return { checks: [...checks], summary: summarize(checks) };
}

// ─────────────────────────────────────────────────────────────────────────────
// Individual check helpers
//
// Each helper is pure-ish (reads env/disk/network but returns a value
// rather than printing). They are exported so callers like the relay
// startup banner can reuse the same logic.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Enumerate all installed skills across every canonical root.
 * Replaces the hard-coded `path.join(cwd, ".claude/skills")` patterns
 * scattered through relay.ts / doctor.ts and correctly covers the
 * CLAUDE_CONFIG_DIR (Docker) and bundled (node_modules) roots.
 */
export interface InstalledSkill {
	name: string;
	root: string;
}

export function findInstalledSkills(cwd: string = process.cwd()): InstalledSkill[] {
	const seen = new Map<string, InstalledSkill>();
	for (const root of getAllSkillRoots(cwd)) {
		let entries: fs.Dirent[];
		try {
			entries = fs.readdirSync(root, { withFileTypes: true });
		} catch {
			continue;
		}
		for (const entry of entries) {
			if (entry.name.startsWith(".")) continue;
			// Accept real directories AND symlinks that resolve to directories
			// (Docker profiles symlink per-skill into the shared skills root).
			let isDir = entry.isDirectory();
			if (!isDir && entry.isSymbolicLink()) {
				try {
					isDir = fs.statSync(path.join(root, entry.name)).isDirectory();
				} catch {
					isDir = false;
				}
			}
			if (!isDir) continue;
			if (!seen.has(entry.name)) {
				seen.set(entry.name, { name: entry.name, root });
			}
		}
	}
	return [...seen.values()].sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * Check that the `claude` CLI is installed.
 */
export function checkClaudeCli(): CheckResult {
	try {
		const version = execSync("claude --version", {
			encoding: "utf8",
			stdio: ["ignore", "pipe", "pipe"],
		}).trim();
		return pass("claude-cli.present", "Claude CLI", `claude ${version} on PATH`);
	} catch {
		return fail(
			"claude-cli.present",
			"Claude CLI",
			"claude CLI not found on PATH",
			undefined,
			"brew install anthropic-ai/cli/claude (or see https://docs.anthropic.com)",
		);
	}
}

export function checkClaudeLogin(): CheckResult {
	// `claude auth status` is the real auth-state subcommand. (An earlier
	// version ran `claude whoami`, which is NOT a subcommand — the CLI treats
	// "whoami" as a prompt, exits 0 with conversational text, and the check
	// passed meaninglessly.) Use spawnSync so a non-zero exit (not logged in)
	// doesn't throw, and so we can inspect the combined output.
	const res = spawnSync("claude", ["auth", "status"], {
		encoding: "utf8",
		stdio: ["ignore", "pipe", "pipe"],
	});

	if (res.error) {
		// CLI not spawnable (missing binary, etc.).
		return fail(
			"claude-cli.logged-in",
			"Claude CLI",
			"could not run claude auth status",
			res.error.message,
			"claude login",
		);
	}

	const output = `${res.stdout ?? ""}${res.stderr ?? ""}`.trim();

	// Older/newer CLIs may not expose `auth status`. Treat an unknown-subcommand
	// response as "cannot determine" (warn) rather than a false pass/fail.
	if (/unknown\s+(?:command|subcommand|option)|usage:/i.test(output)) {
		return warn(
			"claude-cli.logged-in",
			"Claude CLI",
			"claude auth status unavailable; cannot determine login state",
			output || undefined,
			"claude login",
		);
	}

	const loggedOut =
		/not\s+logged\s+in|logged\s+out|please\s+log\s*in|no\s+(?:active\s+)?(?:session|account|credentials)/i.test(
			output,
		);
	const loggedIn =
		!loggedOut && (/logged\s+in/i.test(output) || (res.status === 0 && /@/.test(output)));

	if (loggedIn) {
		return pass(
			"claude-cli.logged-in",
			"Claude CLI",
			"logged in to Anthropic",
			output || undefined,
		);
	}

	if (loggedOut || res.status !== 0) {
		return warn(
			"claude-cli.logged-in",
			"Claude CLI",
			"not logged in to Anthropic",
			output || undefined,
			"claude login",
		);
	}

	return warn(
		"claude-cli.logged-in",
		"Claude CLI",
		output
			? "claude auth status returned unrecognized output; cannot determine login state"
			: "claude auth status returned empty output; cannot determine login state",
		output || undefined,
		"claude login",
	);
}

export function checkAgentRuntimes(): CheckResult[] {
	return collectAgentRuntimeStatuses().map((runtime) => {
		const name = `agent-runtime.${runtime.id}`;
		const category = "Agent Runtimes";
		const detail = runtime.remediation
			? `${runtime.detail}\ntry: ${runtime.remediation}`
			: runtime.detail;
		if (runtime.readiness === "ready") {
			return pass(name, category, `${runtime.label} ready`, detail);
		}
		if (runtime.readiness === "warning") {
			return warn(name, category, `${runtime.label} available with warnings`, detail);
		}
		return fail(name, category, `${runtime.label} unavailable`, detail, runtime.remediation);
	});
}

/**
 * Check the config file loads cleanly and has the minimum required fields.
 */
export function checkConfigLoaded(cfg: TelclaudeConfig): CheckResult[] {
	const checks: CheckResult[] = [];

	checks.push(pass("config.loaded", "Config", "config parsed successfully"));

	// Secrets are commonly provided via env (Docker) rather than the config file,
	// so honor TELEGRAM_BOT_TOKEN the same way the relay does at runtime.
	const bot = cfg.telegram?.botToken ?? process.env.TELEGRAM_BOT_TOKEN;
	const fromEnv = !cfg.telegram?.botToken && !!process.env.TELEGRAM_BOT_TOKEN;
	if (!bot) {
		checks.push(
			fail(
				"config.telegram.botToken",
				"Config",
				"telegram.botToken is not set",
				"Without a bot token, telclaude cannot connect to the Telegram Bot API.",
				"telclaude onboard  # or set TELEGRAM_BOT_TOKEN / edit telclaude.json",
			),
		);
	} else if (!/:/.test(bot)) {
		checks.push(
			fail(
				"config.telegram.botToken",
				"Config",
				"telegram.botToken format is invalid",
				"Expected format is <id>:<secret> (from @BotFather).",
				"telclaude onboard",
			),
		);
	} else {
		checks.push(
			pass(
				"config.telegram.botToken",
				"Config",
				fromEnv ? "bot token is present (from TELEGRAM_BOT_TOKEN env)" : "bot token is present",
			),
		);
	}

	const allowed = cfg.telegram?.allowedChats;
	if (!allowed || allowed.length === 0) {
		checks.push(
			warn(
				"config.telegram.allowedChats",
				"Config",
				"telegram.allowedChats is empty",
				"With no allowlist the bot will DENY all chats (fail-closed).",
				"telclaude onboard  # or add your chat ID to allowedChats",
			),
		);
	} else {
		checks.push(
			pass(
				"config.telegram.allowedChats",
				"Config",
				`${allowed.length} chat${allowed.length === 1 ? "" : "s"} allowed`,
			),
		);
	}

	return checks;
}

/**
 * Verify the Telegram bot token reaches the Bot API.
 */
export async function checkTelegramToken(cfg: TelclaudeConfig): Promise<CheckResult> {
	const token = cfg.telegram?.botToken;
	if (!token) {
		return skip("telegram.api.reachable", "Telegram", "skipped (no bot token configured)");
	}
	if (!/:/.test(token)) {
		return fail(
			"telegram.api.reachable",
			"Telegram",
			"bot token format invalid",
			undefined,
			"telclaude onboard",
		);
	}
	try {
		const response = await fetchWithTimeout(
			`https://api.telegram.org/bot${token}/getMe`,
			{ method: "GET" },
			5_000,
		);
		if (!response.ok) {
			return fail(
				"telegram.api.reachable",
				"Telegram",
				`Telegram API returned HTTP ${response.status}`,
				"Common causes: revoked token, rate limit, Telegram API outage.",
				"Check the bot token via @BotFather, then re-run telclaude onboard",
			);
		}
		const body = (await response.json()) as {
			ok?: boolean;
			result?: { username?: string };
			description?: string;
		};
		if (body.ok && body.result?.username) {
			return pass(
				"telegram.api.reachable",
				"Telegram",
				`authenticated as @${body.result.username}`,
			);
		}
		return fail(
			"telegram.api.reachable",
			"Telegram",
			body.description ?? "Telegram API rejected the token",
			undefined,
			"telclaude onboard",
		);
	} catch (err) {
		return fail(
			"telegram.api.reachable",
			"Telegram",
			"could not reach api.telegram.org",
			err instanceof Error ? err.message : String(err),
			"Check outbound network and firewall rules",
		);
	}
}

/**
 * Vault daemon reachability.
 */
export async function checkVaultDaemon(): Promise<CheckResult> {
	const { isVaultAvailable } = await import("../vault-daemon/index.js");
	if (await isVaultAvailable()) {
		return pass("vault.daemon", "Vault", "daemon reachable on Unix socket");
	}
	return warn(
		"vault.daemon",
		"Vault",
		"vault daemon is not running",
		"OAuth-bearing features (providers, git credentials) need the daemon.",
		"telclaude maintenance vault-daemon",
	);
}

/**
 * TOTP daemon reachability.
 */
export async function checkTotpDaemon(): Promise<CheckResult> {
	const { isTOTPDaemonAvailable } = await import("../security/totp.js");
	if (await isTOTPDaemonAvailable()) {
		return pass("totp.daemon", "TOTP", "TOTP daemon reachable");
	}
	return warn(
		"totp.daemon",
		"TOTP",
		"TOTP daemon is not running",
		"2FA via /auth verify will be unavailable until the daemon is started.",
		"telclaude maintenance totp-daemon",
	);
}

/**
 * Network allowlist / private-endpoint check.
 */
export function checkNetworkConfig(cfg: TelclaudeConfig): CheckResult[] {
	const checks: CheckResult[] = [];
	const network = cfg.security?.network;
	const additional = network?.additionalDomains ?? [];
	const endpoints = network?.privateEndpoints ?? [];

	const mode = process.env.TELCLAUDE_NETWORK_MODE ?? "restricted";
	if (mode === "open") {
		checks.push(
			warn(
				"network.mode",
				"Network",
				"TELCLAUDE_NETWORK_MODE=open (wildcard egress)",
				"RFC1918 and metadata endpoints are still blocked, but every public host is reachable.",
			),
		);
	} else {
		checks.push(
			pass("network.mode", "Network", `mode=${mode} (+${additional.length} additional domains)`),
		);
	}

	if ((cfg.providers ?? []).length > 0 && endpoints.length === 0) {
		checks.push(
			fail(
				"network.privateEndpoints",
				"Network",
				"providers configured but no privateEndpoints allowlist",
				"Provider URLs must resolve to an allowlisted private endpoint.",
				"telclaude providers setup <id>  # (or edit security.network.privateEndpoints)",
			),
		);
	} else {
		checks.push(
			pass(
				"network.privateEndpoints",
				"Network",
				`${endpoints.length} private endpoint(s) configured`,
			),
		);
	}

	return checks;
}

/**
 * Whether a `/v1/schema` body carries a recognizable service container.
 *
 * Mirrors the authoritative parser in `provider-skill.ts`
 * (`extractServiceDocs`): the container may live under `services`,
 * `connectors`, `providers`, `service`, or `connector`, and may be either a
 * non-empty array or a non-empty object. The doctor check must accept exactly
 * this set so it doesn't false-fail providers the runtime parses fine.
 */
function hasServiceContainer(body: Record<string, unknown> | null | undefined): boolean {
	if (!body || typeof body !== "object") return false;
	const container =
		body.services ?? body.connectors ?? body.providers ?? body.service ?? body.connector;
	if (Array.isArray(container)) return container.length > 0;
	if (container && typeof container === "object") {
		return Object.keys(container).length > 0;
	}
	return false;
}

/**
 * Provider reachability + schema validity. One check per configured
 * provider, so operators can see which is healthy.
 */
export async function checkProviders(cfg: TelclaudeConfig): Promise<CheckResult[]> {
	const providers = cfg.providers ?? [];
	if (providers.length === 0) {
		return [skip("providers", "Providers", "no providers configured")];
	}

	const checks: CheckResult[] = [];
	const { checkProviderHealth } = await import("../providers/provider-health.js");

	for (const provider of providers) {
		try {
			const result = await checkProviderHealth(provider.id, provider.baseUrl);
			if (!result.reachable) {
				checks.push(
					fail(
						`providers.${provider.id}.health`,
						"Providers",
						`${provider.id}: unreachable`,
						result.error ?? "no response",
						`telclaude providers setup ${provider.id}`,
					),
				);
				continue;
			}
			const status = result.response?.status ?? "unknown";
			if (status === "degraded" || status === "unhealthy") {
				checks.push(
					warn(
						`providers.${provider.id}.health`,
						"Providers",
						`${provider.id}: ${status}`,
						result.response?.error,
						`telclaude providers setup ${provider.id}`,
					),
				);
			} else {
				checks.push(
					pass(`providers.${provider.id}.health`, "Providers", `${provider.id}: ${status}`),
				);
			}

			// Schema endpoint
			try {
				const schemaUrl = new URL("/v1/schema", provider.baseUrl).toString();
				const schemaRes = await fetchWithTimeout(
					schemaUrl,
					{ method: "GET", headers: { accept: "application/json" } },
					5_000,
				);
				if (!schemaRes.ok) {
					checks.push(
						warn(
							`providers.${provider.id}.schema`,
							"Providers",
							`${provider.id}: /v1/schema returned HTTP ${schemaRes.status}`,
						),
					);
				} else {
					const body = (await schemaRes.json()) as Record<string, unknown> | null;
					if (!hasServiceContainer(body)) {
						checks.push(
							warn(
								`providers.${provider.id}.schema`,
								"Providers",
								`${provider.id}: /v1/schema returned unexpected shape`,
							),
						);
					} else {
						checks.push(
							pass(
								`providers.${provider.id}.schema`,
								"Providers",
								`${provider.id}: /v1/schema reachable`,
							),
						);
					}
				}
			} catch (err) {
				checks.push(
					warn(
						`providers.${provider.id}.schema`,
						"Providers",
						`${provider.id}: could not fetch /v1/schema`,
						err instanceof Error ? err.message : String(err),
					),
				);
			}
		} catch (err) {
			checks.push(
				fail(
					`providers.${provider.id}.health`,
					"Providers",
					`${provider.id}: health check threw`,
					err instanceof Error ? err.message : String(err),
					`telclaude providers setup ${provider.id}`,
				),
			);
		}
	}

	return checks;
}

export interface HermesConnectorReadinessOptions {
	readonly env?: Partial<Record<string, string | undefined>>;
	readonly webSearchConfigured?: boolean | (() => boolean | Promise<boolean>);
	readonly providerSidecarHmacConfigured?: boolean | (() => boolean | Promise<boolean>);
}

/**
 * Advisory readiness for the practical Hermes connector surface. These checks
 * intentionally do not fail a minimal deployment: connector omission should be
 * visible, while the security posture remains fail-closed at the relay/MCP
 * authority layer.
 */
export async function checkHermesConnectorReadiness(
	cfg: TelclaudeConfig,
	options: HermesConnectorReadinessOptions = {},
): Promise<CheckResult[]> {
	const env = options.env ?? process.env;
	const checks: CheckResult[] = [];
	const providerScopes = new Set(cfg.hermes?.privateRuntime?.providerScopes ?? []);
	const capabilityScopes = new Set(cfg.hermes?.privateRuntime?.capabilityScopes ?? []);
	const outboundChannels = new Set(cfg.hermes?.privateRuntime?.outboundChannels ?? []);
	const providers = cfg.providers ?? [];

	checks.push(...checkHermesGoogleReadiness(cfg, providerScopes, providers));
	checks.push(await checkHermesWebFetchReadiness(capabilityScopes, env));
	checks.push(await checkHermesWebSearchReadiness(capabilityScopes, options));
	checks.push(...checkHermesWhatsAppReadiness(outboundChannels, env));
	checks.push(await checkHermesIsraelServicesHmacReadiness(providers, env, options));

	return checks;
}

function checkHermesGoogleReadiness(
	cfg: TelclaudeConfig,
	providerScopes: ReadonlySet<string>,
	providers: NonNullable<TelclaudeConfig["providers"]>,
): CheckResult[] {
	const category = "Hermes Connectors";
	if (!providerScopes.has("google")) {
		return [
			skip(
				"hermes.connectors.google.scope",
				category,
				"Google provider not scoped for Hermes private runtime",
				'Set hermes.privateRuntime.providerScopes to include google, or bind a profile with providerScopes: ["google"].',
			),
		];
	}

	const checks: CheckResult[] = [
		pass(
			"hermes.connectors.google.scope",
			category,
			"Google provider scoped through Hermes authority",
		),
	];
	const google = providers.find((provider) => provider.id === "google");
	if (!google) {
		checks.push(
			warn(
				"hermes.connectors.google.provider",
				category,
				"Google scope granted but provider is not configured",
				"Provider authority remains fail-closed until providers[] contains id=google.",
				"telclaude providers setup google --base-url http://google-services:3002",
			),
		);
		return checks;
	}

	checks.push(
		pass(
			"hermes.connectors.google.provider",
			category,
			"Google provider configured",
			`services=${google.services.join(",") || "(none)"}`,
		),
	);

	const requiredServices = ["gmail", "calendar", "drive", "contacts"];
	const missingServices = requiredServices.filter((service) => !google.services.includes(service));
	if (missingServices.length > 0) {
		checks.push(
			warn(
				"hermes.connectors.google.services",
				category,
				`Google provider missing service(s): ${missingServices.join(", ")}`,
				"Reads and approval-gated writes are available only for advertised provider services.",
			),
		);
	} else {
		checks.push(
			pass(
				"hermes.connectors.google.services",
				category,
				"Google Gmail/Calendar/Drive/Contacts services advertised",
			),
		);
	}

	const endpointCheck = providerHasPrivateEndpoint(cfg, google.baseUrl);
	if (!endpointCheck.ok) {
		checks.push(
			warn(
				"hermes.connectors.google.private-endpoint",
				category,
				"Google provider baseUrl is not in privateEndpoints",
				endpointCheck.detail,
				"Add google-services to security.network.privateEndpoints.",
			),
		);
	} else {
		checks.push(
			pass(
				"hermes.connectors.google.private-endpoint",
				category,
				"Google provider has matching private endpoint allowlist",
			),
		);
	}

	return checks;
}

function providerHasPrivateEndpoint(
	cfg: TelclaudeConfig,
	baseUrl: string,
): { readonly ok: true } | { readonly ok: false; readonly detail: string } {
	let parsed: URL;
	try {
		parsed = new URL(baseUrl);
	} catch {
		return { ok: false, detail: `Invalid provider baseUrl: ${baseUrl}` };
	}
	const port = parsed.port ? Number(parsed.port) : parsed.protocol === "https:" ? 443 : 80;
	const endpoints = cfg.security?.network?.privateEndpoints ?? [];
	for (const endpoint of endpoints) {
		if (endpoint.host !== parsed.hostname) continue;
		const ports = endpoint.ports ?? [80, 443];
		if (ports.includes(port)) return { ok: true };
	}
	return {
		ok: false,
		detail: `No private endpoint matched host=${parsed.hostname} port=${port}.`,
	};
}

async function checkHermesWebFetchReadiness(
	capabilityScopes: ReadonlySet<string>,
	env: Partial<Record<string, string | undefined>>,
): Promise<CheckResult> {
	const category = "Hermes Connectors";
	if (!capabilityScopes.has("web.fetch")) {
		return skip(
			"hermes.connectors.web.fetch",
			category,
			"web.fetch capability not scoped for Hermes private runtime",
		);
	}
	const networkMode = env.TELCLAUDE_NETWORK_MODE?.trim() || "restricted";
	if (networkMode === "permissive" || networkMode === "open") {
		return pass(
			"hermes.connectors.web.fetch",
			category,
			`public web fetch available through relay egress mode=${networkMode}`,
		);
	}
	return skip(
		"hermes.connectors.web.fetch",
		category,
		"web.fetch scoped but arbitrary public browsing is not enabled",
		"Set TELCLAUDE_NETWORK_MODE=permissive for relay-served public fetch. RFC1918 and metadata endpoints remain blocked.",
	);
}

async function checkHermesWebSearchReadiness(
	capabilityScopes: ReadonlySet<string>,
	options: HermesConnectorReadinessOptions,
): Promise<CheckResult> {
	const category = "Hermes Connectors";
	if (!capabilityScopes.has("web.search")) {
		return skip(
			"hermes.connectors.web.search",
			category,
			"web.search capability not scoped for Hermes private runtime",
		);
	}

	const configured = await resolveWebSearchConfigured(options);
	if (configured) {
		return pass(
			"hermes.connectors.web.search",
			category,
			"web search configured through relay-owned Brave credentials",
		);
	}
	return skip(
		"hermes.connectors.web.search",
		category,
		"web.search scoped but Brave Search credentials are unavailable",
		"Set TELCLAUDE_BRAVE_SEARCH_API_KEY or store the Brave key in the host keychain.",
	);
}

async function resolveWebSearchConfigured(
	options: HermesConnectorReadinessOptions,
): Promise<boolean> {
	const override = options.webSearchConfigured;
	if (typeof override === "boolean") return override;
	if (typeof override === "function") return await override();
	try {
		const { isWebSearchConfigured } = await import("../services/web-search.js");
		return await isWebSearchConfigured();
	} catch (err) {
		logger.debug({ error: String(err) }, "web search readiness check failed");
		return false;
	}
}

export function checkHermesWhatsAppReadiness(
	outboundChannels: ReadonlySet<string>,
	env: Partial<Record<string, string | undefined>>,
): CheckResult[] {
	const category = "Hermes Connectors";
	if (!outboundChannels.has("whatsapp")) {
		return [
			skip(
				"hermes.connectors.whatsapp.scope",
				category,
				"WhatsApp outbound channel not scoped for Hermes private runtime",
			),
		];
	}

	const checks: CheckResult[] = [
		pass(
			"hermes.connectors.whatsapp.scope",
			category,
			"WhatsApp outbound channel scoped through Hermes authority",
		),
	];
	const sidecarUrl = env[TELCLAUDE_WHATSAPP_SIDECAR_URL_ENV]?.trim();
	if (!sidecarUrl) {
		checks.push(
			skip(
				"hermes.connectors.whatsapp.sidecar",
				category,
				"WhatsApp sidecar URL not set in this environment",
				"Docker compose injects http://whatsapp-bridge:3004; native runs must set TELCLAUDE_WHATSAPP_SIDECAR_URL.",
			),
		);
	} else {
		checks.push(checkWhatsAppSidecarUrl(sidecarUrl));
	}
	const bridgeSecret = env[TELCLAUDE_WHATSAPP_BRIDGE_SECRET_ENV]?.trim();
	if (!sidecarUrl) {
		checks.push(
			skip(
				"hermes.connectors.whatsapp.bridge-auth",
				category,
				"WhatsApp bridge auth not checked because sidecar URL is unset",
			),
		);
	} else if (!bridgeSecret) {
		checks.push(
			warn(
				"hermes.connectors.whatsapp.bridge-auth",
				category,
				"WhatsApp sidecar URL set without shared bridge secret",
				`Set ${TELCLAUDE_WHATSAPP_BRIDGE_SECRET_ENV}; outbound bridge calls fail closed without it.`,
			),
		);
	} else {
		checks.push(
			pass(
				"hermes.connectors.whatsapp.bridge-auth",
				category,
				"WhatsApp bridge shared-secret auth configured",
			),
		);
	}

	const allowedRecipients = csvEnv(env[TELCLAUDE_WHATSAPP_ALLOWED_RECIPIENTS_ENV]);
	if (allowedRecipients.length === 0) {
		checks.push(
			skip(
				"hermes.connectors.whatsapp.outbound-allowlist",
				category,
				"WhatsApp outbound recipient allowlist is empty",
				"Outbound sends stay fail-closed until TELCLAUDE_WHATSAPP_ALLOWED_RECIPIENTS is set to operator-owned E.164 addresses.",
			),
		);
	} else {
		checks.push(
			pass(
				"hermes.connectors.whatsapp.outbound-allowlist",
				category,
				`${allowedRecipients.length} WhatsApp outbound recipient(s) allowlisted`,
			),
		);
	}

	const inboundSecret = env[TELCLAUDE_WHATSAPP_INBOUND_SECRET_ENV]?.trim();
	const inboundAddresses = csvEnv(env[TELCLAUDE_WHATSAPP_INBOUND_OPERATOR_ADDRESSES_ENV]);
	if (!inboundSecret && inboundAddresses.length === 0) {
		checks.push(
			skip(
				"hermes.connectors.whatsapp.inbound",
				category,
				"WhatsApp inbound bridge not configured",
				"Set TELCLAUDE_WHATSAPP_INBOUND_SECRET and operator addresses when enabling the bridge.",
			),
		);
	} else if (!inboundSecret) {
		checks.push(
			warn(
				"hermes.connectors.whatsapp.inbound",
				category,
				"WhatsApp inbound addresses set without HMAC secret",
				"Relay endpoint will reject inbound bridge events until TELCLAUDE_WHATSAPP_INBOUND_SECRET is set.",
			),
		);
	} else if (inboundAddresses.length === 0) {
		checks.push(
			skip(
				"hermes.connectors.whatsapp.inbound",
				category,
				"WhatsApp inbound HMAC secret set; waiting for operator phone addresses",
				"TELCLAUDE_WHATSAPP_INBOUND_OPERATOR_ADDRESSES must be set before inbound events dispatch to Hermes.",
			),
		);
	} else {
		checks.push(
			pass(
				"hermes.connectors.whatsapp.inbound",
				category,
				`${inboundAddresses.length} WhatsApp inbound operator address(es) linked`,
			),
		);
	}

	return checks;
}

async function checkHermesIsraelServicesHmacReadiness(
	providers: NonNullable<TelclaudeConfig["providers"]>,
	env: Partial<Record<string, string | undefined>>,
	options: HermesConnectorReadinessOptions,
): Promise<CheckResult> {
	const category = "Hermes Connectors";
	if (!providers.some((provider) => provider.id === "israel-services")) {
		return skip(
			"hermes.connectors.israel-services.hmac",
			category,
			"Israel services provider not configured",
		);
	}

	if (await resolveProviderSidecarHmacConfigured(env, options)) {
		return pass(
			"hermes.connectors.israel-services.hmac",
			category,
			"Israel services relay HMAC signing secret configured",
		);
	}

	const vaultTarget =
		env[PROVIDER_SIDECAR_HMAC_VAULT_TARGET_ENV]?.trim() ||
		PROVIDER_SIDECAR_HMAC_DEFAULT_VAULT_TARGET;
	const detail = `Set ${PROVIDER_SIDECAR_HMAC_SECRET_ENV} with at least 32 bytes or store the secret in vault target ${vaultTarget}. Run a signed canary before setting ${SIDECAR_REQUIRE_RELAY_HMAC_ENV}=1.`;
	if (isTruthyEnv(env[SIDECAR_REQUIRE_RELAY_HMAC_ENV])) {
		return fail(
			"hermes.connectors.israel-services.hmac",
			category,
			"Israel services sidecar HMAC enforcement is enabled but relay signing is not configured",
			`${SIDECAR_REQUIRE_RELAY_HMAC_ENV}=1 requires relay signing first. ${detail}`,
			`telclaude vault add secret ${vaultTarget}`,
		);
	}
	return warn(
		"hermes.connectors.israel-services.hmac",
		category,
		"Israel services provider configured without relay HMAC signing secret",
		detail,
		`telclaude vault add secret ${vaultTarget}`,
	);
}

async function resolveProviderSidecarHmacConfigured(
	env: Partial<Record<string, string | undefined>>,
	options: HermesConnectorReadinessOptions,
): Promise<boolean> {
	const override = options.providerSidecarHmacConfigured;
	if (typeof override === "boolean") return override;
	if (typeof override === "function") return await override();

	if (isUsableProviderSidecarHmacSecret(env[PROVIDER_SIDECAR_HMAC_SECRET_ENV])) {
		return true;
	}

	const vaultTarget =
		env[PROVIDER_SIDECAR_HMAC_VAULT_TARGET_ENV]?.trim() ||
		PROVIDER_SIDECAR_HMAC_DEFAULT_VAULT_TARGET;
	try {
		const { getVaultClient } = await import("../vault-daemon/client.js");
		const response = await getVaultClient().getSecret(vaultTarget, { timeout: 2_000 });
		return (
			response.ok &&
			response.type === "get-secret" &&
			isUsableProviderSidecarHmacSecret(response.value)
		);
	} catch (err) {
		logger.debug({ error: String(err), vaultTarget }, "provider sidecar HMAC doctor check failed");
		return false;
	}
}

function isUsableProviderSidecarHmacSecret(value: string | undefined): boolean {
	const trimmed = value?.trim();
	return !!trimmed && Buffer.byteLength(trimmed, "utf8") >= 32;
}

function isTruthyEnv(value: string | undefined): boolean {
	const normalized = value?.trim().toLowerCase();
	return normalized === "1" || normalized === "true" || normalized === "yes" || normalized === "on";
}

function checkWhatsAppSidecarUrl(sidecarUrl: string): CheckResult {
	const category = "Hermes Connectors";
	let parsed: URL;
	try {
		parsed = new URL(sidecarUrl);
	} catch {
		return warn(
			"hermes.connectors.whatsapp.sidecar",
			category,
			"WhatsApp sidecar URL is invalid",
			`Value of ${TELCLAUDE_WHATSAPP_SIDECAR_URL_ENV} could not be parsed as a URL.`,
		);
	}
	if (parsed.hostname !== WHATSAPP_SIDECAR_ALLOWED_HOST) {
		return warn(
			"hermes.connectors.whatsapp.sidecar",
			category,
			"WhatsApp sidecar must use the isolated bridge hostname",
			`Expected host ${WHATSAPP_SIDECAR_ALLOWED_HOST}, got ${parsed.hostname}.`,
		);
	}
	return pass(
		"hermes.connectors.whatsapp.sidecar",
		category,
		"WhatsApp sidecar URL targets isolated bridge hostname",
		sidecarUrl,
	);
}

function csvEnv(value: string | undefined): string[] {
	return (value ?? "")
		.split(",")
		.map((entry) => entry.trim())
		.filter(Boolean);
}

/**
 * Run the skill static scanner across every canonical skill root.
 *
 * Bug #13 (symlink-aware criticals) is a separate Wave-3 item; for
 * this release we surface those as WARN with a TODO tag rather than
 * letting them fail the overall doctor run.
 */
export async function checkSkills(cwd: string = process.cwd()): Promise<CheckResult[]> {
	const { scanAllSkills } = await import("../security/skill-scanner.js");
	const roots = [...getAllSkillRoots(cwd), ...getAllDraftSkillRoots(cwd)];

	const checks: CheckResult[] = [];
	let totalScanned = 0;
	let totalBlocked = 0;
	let totalBug13 = 0;
	const bug13Notes: string[] = [];
	const blockedNotes: string[] = [];

	for (const root of roots) {
		if (!fs.existsSync(root)) continue;
		const results = scanAllSkills(root);
		totalScanned += results.length;
		for (const result of results) {
			if (!result.blocked) continue;
			// Heuristic: if the only critical findings come from symlink
			// traversal, treat as bug #13 (symlink-critical) which is a
			// known Wave-3 item tracked separately.
			const symlinkOnly = result.findings.every(
				(f) =>
					f.severity !== "critical" ||
					/symlink|Symlink|SYMLINK|path traversal.*\.\.\//.test(f.message),
			);
			if (symlinkOnly) {
				totalBug13++;
				bug13Notes.push(`${result.skillName} (${root})`);
			} else {
				totalBlocked++;
				blockedNotes.push(`${result.skillName} (${root})`);
			}
		}
	}

	if (totalScanned === 0) {
		checks.push(skip("skills.scan", "Skills", "no skills discovered"));
		return checks;
	}

	if (totalBlocked > 0) {
		checks.push(
			fail(
				"skills.scan",
				"Skills",
				`${totalBlocked}/${totalScanned} skill(s) blocked by scanner`,
				blockedNotes.join("\n"),
				"telclaude dev doctor --skills  # for the full scanner report",
			),
		);
	} else {
		checks.push(pass("skills.scan", "Skills", `${totalScanned} skill(s) scanned, 0 blocked`));
	}

	if (totalBug13 > 0) {
		checks.push(
			warn(
				"skills.bug13-symlink",
				"Skills",
				`[TODO bug #13] ${totalBug13} skill(s) flagged only on symlink-path critical`,
				`Symlink-aware skill criticals are being re-tuned in Wave 3 (bug #13); surfaced as warning for this release:\n${bug13Notes.join("\n")}`,
			),
		);
	}

	return checks;
}

/**
 * Native / Docker isolation check.
 */
export async function checkSandbox(): Promise<CheckResult[]> {
	const checks: CheckResult[] = [];
	const { getSandboxMode } = await import("../sandbox/index.js");

	const mode = getSandboxMode();
	checks.push(
		pass(
			"sandbox.mode",
			"Sandbox",
			`mode=${mode}`,
			mode === "docker"
				? "Docker container provides relay isolation; LLM/persona runtime uses contained Hermes."
				: "Native relay process; LLM/persona runtime uses contained Hermes.",
		),
	);

	return checks;
}

/**
 * Docker container health check.
 *
 * Three states:
 * - docker CLI not on PATH → skip (probably running natively on a host
 *   without Docker installed).
 * - docker available but none of the telclaude containers exist and
 *   runtime mode is native → skip (operator is running natively; the
 *   container list is noise).
 * - docker available AND mode=docker OR at least one telclaude
 *   container was seen → full per-container report.
 */
export async function checkDockerContainers(): Promise<CheckResult[]> {
	const checks: CheckResult[] = [];

	// Is docker available at all?
	const hasDocker =
		spawnSync("docker", ["--version"], {
			stdio: ["ignore", "pipe", "pipe"],
		}).status === 0;
	if (!hasDocker) {
		return [
			skip("docker.available", "Docker", "docker CLI not on PATH; skipping container checks"),
		];
	}

	const expected = ["telclaude", "google-services", "totp", "vault"];

	let output = "";
	try {
		const res = spawnSync("docker", ["ps", "--format", "{{.Names}}\t{{.State}}\t{{.Status}}"], {
			encoding: "utf8",
		});
		if (res.status !== 0) {
			return [
				skip(
					"docker.ps",
					"Docker",
					"docker ps failed; skipping container checks",
					res.stderr?.toString() ?? undefined,
				),
			];
		}
		output = res.stdout ?? "";
	} catch (err) {
		logger.debug({ error: String(err) }, "docker ps failed");
		return [skip("docker.ps", "Docker", "docker ps failed; skipping container checks")];
	}

	const containerMap = new Map<string, { state: string; status: string }>();
	for (const line of output.split("\n")) {
		if (!line.trim()) continue;
		const [name, state, ...status] = line.split("\t");
		if (!name) continue;
		containerMap.set(name, { state: state ?? "", status: status.join("\t") });
	}

	// If we're running natively and there's no telclaude container
	// running at all, there's nothing meaningful to report here.
	const { getSandboxMode } = await import("../sandbox/index.js");
	const mode = getSandboxMode();
	const anyPresent = expected.some((name) => containerMap.has(name));
	if (mode === "native" && !anyPresent) {
		return [
			skip("docker.containers", "Docker", "no telclaude containers present; native mode detected"),
		];
	}

	for (const name of expected) {
		const entry = containerMap.get(name);
		if (!entry) {
			// In docker mode we expect every container; in native mode we
			// warn only if some (but not all) are up, which is a partial
			// deployment worth flagging.
			checks.push(
				warn(
					`docker.${name}`,
					"Docker",
					`container '${name}' not running`,
					mode === "docker"
						? "Expected to be running in docker mode."
						: "Partial deployment detected (other telclaude containers are up).",
					"cd docker && docker compose up -d",
				),
			);
			continue;
		}
		if (entry.state !== "running") {
			checks.push(
				fail(
					`docker.${name}`,
					"Docker",
					`container '${name}' state=${entry.state}`,
					entry.status,
					"cd docker && docker compose up -d",
				),
			);
		} else if (/unhealthy/i.test(entry.status)) {
			checks.push(
				warn(
					`docker.${name}`,
					"Docker",
					`container '${name}' is unhealthy`,
					entry.status,
					`cd docker && docker compose restart ${name}`,
				),
			);
		} else {
			checks.push(pass(`docker.${name}`, "Docker", `container '${name}' running`, entry.status));
		}
	}

	return checks;
}
