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
import type { TelclaudeConfig } from "../config/config.js";
import { fetchWithTimeout } from "../infra/timeout.js";
import { getChildLogger } from "../logging.js";
import { getAllDraftSkillRoots, getAllSkillRoots } from "./skill-path.js";

const logger = getChildLogger({ module: "doctor-helpers" });

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
	try {
		const who = execSync("claude whoami", {
			encoding: "utf8",
			stdio: ["ignore", "pipe", "pipe"],
		}).trim();
		const loggedIn = /Logged in/i.test(who) || who.length > 0;
		if (loggedIn) {
			return pass("claude-cli.logged-in", "Claude CLI", "logged in to Anthropic");
		}
		return warn(
			"claude-cli.logged-in",
			"Claude CLI",
			"claude whoami returned empty output",
			undefined,
			"claude login",
		);
	} catch {
		return fail(
			"claude-cli.logged-in",
			"Claude CLI",
			"claude login appears to be missing",
			undefined,
			"claude login",
		);
	}
}

/**
 * Check the config file loads cleanly and has the minimum required fields.
 */
export function checkConfigLoaded(cfg: TelclaudeConfig): CheckResult[] {
	const checks: CheckResult[] = [];

	checks.push(pass("config.loaded", "Config", "config parsed successfully"));

	const bot = cfg.telegram?.botToken;
	if (!bot) {
		checks.push(
			fail(
				"config.telegram.botToken",
				"Config",
				"telegram.botToken is not set",
				"Without a bot token, telclaude cannot connect to the Telegram Bot API.",
				"telclaude onboard  # or edit telclaude.json directly",
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
		checks.push(pass("config.telegram.botToken", "Config", "bot token is present"));
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
					const body = (await schemaRes.json()) as { services?: unknown };
					if (!body || typeof body !== "object") {
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
	const {
		getSandboxMode,
		getSandboxRuntimeVersion,
		isSandboxRuntimeAtLeast,
		MIN_SANDBOX_RUNTIME_VERSION,
	} = await import("../sandbox/index.js");

	const mode = getSandboxMode();
	checks.push(
		pass(
			"sandbox.mode",
			"Sandbox",
			`mode=${mode}`,
			mode === "docker"
				? "Docker container provides isolation; SDK sandbox disabled."
				: "Native: SDK sandbox (bubblewrap / Seatbelt) provides isolation.",
		),
	);

	if (mode === "native") {
		const version = getSandboxRuntimeVersion() as string | null;
		if (!version) {
			checks.push(
				fail(
					"sandbox.runtime",
					"Sandbox",
					"@anthropic-ai/sandbox-runtime not found",
					"Native mode requires the SDK sandbox runtime to enforce isolation.",
					"npm install -g @anthropic-ai/sandbox-runtime",
				),
			);
		} else if (!isSandboxRuntimeAtLeast()) {
			checks.push(
				warn(
					"sandbox.runtime",
					"Sandbox",
					`sandbox-runtime ${version} found`,
					`Upgrade to >= ${MIN_SANDBOX_RUNTIME_VERSION} (fixes CVE-2025-66479).`,
					"npm install -g @anthropic-ai/sandbox-runtime@latest",
				),
			);
		} else {
			checks.push(pass("sandbox.runtime", "Sandbox", `sandbox-runtime ${version} (patched)`));
		}
	}

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

	const expected = [
		"telclaude",
		"telclaude-agent",
		"agent-social",
		"google-services",
		"totp",
		"vault",
	];

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
