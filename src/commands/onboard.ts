/**
 * `telclaude onboard` — interactive first-run wizard.
 *
 * Walks a new operator through the minimum set of decisions needed to
 * reach a working relay: mode confirmation, Telegram bot token, admin
 * chat claim, optional OAuth setups, optional social persona config,
 * and a final health check that reuses the doctor helpers.
 *
 * Design goals:
 * - Idempotent. Re-running touches only unset fields unless the operator
 *   explicitly asks to overwrite.
 * - Pure orchestration. Any heavy lifting (OAuth flows, vault access,
 *   provider health) routes through the existing namespaced commands so
 *   there is exactly one implementation per concern.
 * - Fail-closed. If a step is skipped, the wizard records that as a
 *   pending TODO in the summary rather than silently moving on.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { Command } from "commander";
import JSON5 from "json5";
import { getConfigPath, resetConfigCache } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { getSandboxMode } from "../sandbox/index.js";
import { CONFIG_DIR } from "../utils.js";
import { promptLine, promptYesNo } from "./cli-prompt.js";
import { runDoctor } from "./doctor.js";
import { worstStatus } from "./doctor-helpers.js";

const logger = getChildLogger({ module: "cmd-onboard" });

export interface OnboardOptions {
	token?: string;
	chatId?: string;
	/** Non-interactive mode: accept defaults without prompting (CI). */
	yes?: boolean;
	/** Skip the final doctor run (used in smoke tests). */
	skipDoctor?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// Config read/write helpers. Kept narrow + file-only so the wizard
// never pulls in the strict Zod schema during mid-edit writes.
// ─────────────────────────────────────────────────────────────────────────────

function readRawConfig(): Record<string, unknown> {
	const configPath = getConfigPath();
	try {
		const content = fs.readFileSync(configPath, "utf8");
		return JSON5.parse(content) as Record<string, unknown>;
	} catch (err) {
		if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
		throw err;
	}
}

function writeRawConfig(raw: Record<string, unknown>): void {
	const configPath = getConfigPath();
	fs.mkdirSync(path.dirname(configPath), { recursive: true, mode: 0o700 });
	const tmp = path.join(
		path.dirname(configPath),
		`.config.${crypto.randomBytes(8).toString("hex")}.tmp`,
	);
	fs.writeFileSync(tmp, JSON.stringify(raw, null, 2), { mode: 0o600 });
	fs.renameSync(tmp, configPath);
	resetConfigCache();
}

function ensureObject(raw: Record<string, unknown>, key: string): Record<string, unknown> {
	if (!raw[key] || typeof raw[key] !== "object" || Array.isArray(raw[key])) {
		raw[key] = {};
	}
	return raw[key] as Record<string, unknown>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Wizard state machine
// ─────────────────────────────────────────────────────────────────────────────

type StepStatus = "done" | "skipped" | "already-configured" | "failed";

interface StepSummary {
	label: string;
	status: StepStatus;
	note?: string;
}

export function registerOnboardCommand(program: Command): void {
	program
		.command("onboard")
		.description(
			"Interactive first-run wizard (bot token, admin claim, optional OAuth, health check)",
		)
		.option("-t, --token <token>", "Telegram bot token (from @BotFather)")
		.option("-c, --chat-id <chatId>", "Your Telegram chat ID (numeric)")
		.option("-y, --yes", "Non-interactive (skip optional prompts, accept safe defaults)")
		.option("--skip-doctor", "Skip the final doctor run (for CI smoke tests)")
		.action(async (opts: OnboardOptions) => {
			try {
				await runOnboard(opts);
			} catch (err) {
				logger.error({ error: String(err) }, "onboard failed");
				console.error(`\nError: ${err instanceof Error ? err.message : String(err)}`);
				process.exit(1);
			}
		});
}

export async function runOnboard(opts: OnboardOptions): Promise<void> {
	const steps: StepSummary[] = [];

	console.log("\n🦉 telclaude onboard\n");
	console.log("This wizard will set up a working relay step by step.");
	console.log("You can re-run it any time — it only touches fields you change.\n");

	// ── Step 1: Mode detection ────────────────────────────────────────────
	const mode = getSandboxMode();
	console.log(`1) Runtime mode: ${mode === "docker" ? "Docker" : "Native"}`);
	console.log(
		mode === "docker"
			? "   Isolation is provided by the container; SDK sandbox is disabled."
			: "   Isolation is provided by the SDK sandbox (bubblewrap / Seatbelt).",
	);
	steps.push({ label: "Detect runtime mode", status: "done", note: `mode=${mode}` });

	// ── Step 2: Bot token ────────────────────────────────────────────────
	const raw = readRawConfig();
	const telegram = ensureObject(raw, "telegram");
	const existingToken = typeof telegram.botToken === "string" ? telegram.botToken : "";

	console.log("\n2) Telegram bot token");
	let token = opts.token ?? existingToken;
	if (!token) {
		if (opts.yes) {
			steps.push({
				label: "Telegram bot token",
				status: "skipped",
				note: "Re-run `telclaude onboard` without -y to enter a token.",
			});
			console.log(
				"   Skipped (no token supplied in non-interactive mode). The bot will not start until a token is set.",
			);
		} else {
			console.log("   Get one from @BotFather (send /newbot).");
			token = (await promptLine("   Bot token: ")) ?? "";
		}
	} else if (existingToken && !opts.token) {
		console.log("   Already configured (leaving unchanged).");
		steps.push({
			label: "Telegram bot token",
			status: "already-configured",
		});
	}
	if (token && token !== existingToken) {
		if (!/^\d+:/.test(token)) {
			throw new Error("Invalid bot token format. Expected `<id>:<secret>` from @BotFather.");
		}
		telegram.botToken = token;
		writeRawConfig(raw);
		steps.push({ label: "Telegram bot token", status: "done" });
	}

	// ── Step 3: Admin chat claim ─────────────────────────────────────────
	const existingAllowed = Array.isArray(telegram.allowedChats)
		? (telegram.allowedChats as (string | number)[])
		: [];

	console.log("\n3) Admin chat claim");
	let chatId = opts.chatId;
	if (!chatId && existingAllowed.length > 0) {
		console.log(`   ${existingAllowed.length} chat(s) already allowlisted (leaving unchanged).`);
		steps.push({
			label: "Admin chat",
			status: "already-configured",
			note: `${existingAllowed.length} chat(s)`,
		});
	} else if (!chatId) {
		if (opts.yes) {
			steps.push({
				label: "Admin chat",
				status: "skipped",
				note: "Add your chat ID to telegram.allowedChats before starting the relay.",
			});
			console.log(
				"   Skipped (no chat ID supplied). The relay will reject all chats until allowlist is populated.",
			);
		} else {
			console.log("   Send /start to your bot, then visit:");
			if (token) {
				console.log(`     https://api.telegram.org/bot${token}/getUpdates`);
			}
			console.log('   Look for "chat":{"id": YOUR_CHAT_ID}');
			chatId = (await promptLine("   Your chat ID (numeric): ")) ?? undefined;
		}
	}
	if (chatId) {
		const numeric = Number.parseInt(chatId, 10);
		if (Number.isNaN(numeric)) {
			throw new Error("Invalid chat ID. Must be a number.");
		}
		if (!existingAllowed.includes(numeric)) {
			existingAllowed.push(numeric);
			telegram.allowedChats = existingAllowed;

			// Also mint a per-user tier entry so the operator at least has
			// WRITE_LOCAL out of the box. Admin claim inside Telegram can
			// promote to FULL_ACCESS later; we stay intentionally conservative.
			const security = ensureObject(raw, "security");
			const permissions = ensureObject(security, "permissions");
			const users = ensureObject(permissions, "users");
			const userKey = `tg:${numeric}`;
			if (!users[userKey]) {
				users[userKey] = { tier: "WRITE_LOCAL" };
			}
			if (!permissions.defaultTier) {
				permissions.defaultTier = "READ_ONLY";
			}

			writeRawConfig(raw);
			steps.push({ label: "Admin chat", status: "done", note: String(numeric) });
		} else {
			steps.push({
				label: "Admin chat",
				status: "already-configured",
				note: String(numeric),
			});
		}
	}

	// ── Step 4: Optional OAuth / secret setups ───────────────────────────
	console.log("\n4) Optional integrations (safe to skip)");
	const interactive = !opts.yes;
	if (!interactive) {
		steps.push({
			label: "Optional integrations",
			status: "skipped",
			note: "Re-run without -y to see OpenAI / GitHub / Google prompts.",
		});
	} else {
		const wantOpenAI = await promptYesNo(
			"   Configure OpenAI (image generation, TTS, transcription)?",
		);
		if (wantOpenAI) {
			console.log("   → Run `telclaude secrets setup-openai` in a second terminal.");
			steps.push({
				label: "OpenAI",
				status: "skipped",
				note: "Run `telclaude secrets setup-openai` when ready.",
			});
		} else {
			steps.push({ label: "OpenAI", status: "skipped" });
		}

		const wantGit = await promptYesNo("   Configure git credentials (clone/push as the bot)?");
		if (wantGit) {
			console.log("   → Run `telclaude secrets setup-git` in a second terminal.");
			steps.push({
				label: "Git credentials",
				status: "skipped",
				note: "Run `telclaude secrets setup-git` when ready.",
			});
		} else {
			steps.push({ label: "Git credentials", status: "skipped" });
		}

		const wantGoogle = await promptYesNo(
			"   Configure Google services (Gmail / Calendar / Drive / Contacts)?",
		);
		if (wantGoogle) {
			console.log(
				"   → Run `telclaude providers setup google` after the relay is up (OAuth flow needs the vault daemon).",
			);
			steps.push({
				label: "Google provider",
				status: "skipped",
				note: "Run `telclaude providers setup google` when ready.",
			});
		} else {
			steps.push({ label: "Google provider", status: "skipped" });
		}
	}

	// ── Step 5: Optional social persona ──────────────────────────────────
	console.log("\n5) Social persona (optional)");
	const raw2 = readRawConfig();
	const existingSocial = Array.isArray(raw2.socialServices)
		? (raw2.socialServices as unknown[])
		: [];
	if (existingSocial.length > 0) {
		console.log(`   ${existingSocial.length} social service(s) already configured.`);
		steps.push({
			label: "Social persona",
			status: "already-configured",
			note: `${existingSocial.length} service(s)`,
		});
	} else if (!interactive) {
		steps.push({
			label: "Social persona",
			status: "skipped",
			note: "Add services under socialServices[] in telclaude.json when ready.",
		});
	} else {
		const wantSocial = await promptYesNo("   Set up a social persona (X/Twitter, Moltbook)?");
		if (wantSocial) {
			console.log(
				"   Edit telclaude.json and add entries under `socialServices`. See docs/architecture.md for schema.",
			);
			steps.push({
				label: "Social persona",
				status: "skipped",
				note: "Edit socialServices[] in telclaude.json.",
			});
		} else {
			steps.push({ label: "Social persona", status: "skipped" });
		}
	}

	// ── Step 6: Final health check ───────────────────────────────────────
	console.log("\n6) Health check");
	if (opts.skipDoctor) {
		steps.push({ label: "Doctor run", status: "skipped", note: "--skip-doctor" });
	} else {
		try {
			const report = await runDoctor();
			const worst = worstStatus(report.checks);
			const failed = report.checks.filter((c) => c.status === "fail");
			const warned = report.checks.filter((c) => c.status === "warn");
			console.log(
				`   doctor: pass=${report.summary.pass} warn=${report.summary.warn} fail=${report.summary.fail}`,
			);
			if (failed.length > 0) {
				console.log("   Failures:");
				for (const f of failed) {
					console.log(`     • ${f.summary}${f.remediation ? ` → try: ${f.remediation}` : ""}`);
				}
			}
			if (warned.length > 0 && worst !== "fail") {
				console.log("   Warnings (not blocking):");
				for (const w of warned.slice(0, 5)) {
					console.log(`     • ${w.summary}`);
				}
			}
			steps.push({
				label: "Doctor run",
				status: worst === "fail" ? "failed" : "done",
				note:
					worst === "fail"
						? `${failed.length} failing check(s)`
						: worst === "warn"
							? `${warned.length} warning(s)`
							: "all green",
			});
		} catch (err) {
			logger.warn({ error: String(err) }, "doctor invocation failed during onboard");
			steps.push({
				label: "Doctor run",
				status: "failed",
				note: err instanceof Error ? err.message : String(err),
			});
		}
	}

	// ── Summary ──────────────────────────────────────────────────────────
	console.log("\n┌──────────────────────────────────────────");
	console.log("│ Summary");
	console.log("├──────────────────────────────────────────");
	for (const step of steps) {
		const icon =
			step.status === "done"
				? "✓"
				: step.status === "already-configured"
					? "•"
					: step.status === "skipped"
						? "↷"
						: "✗";
		const suffix = step.note ? ` — ${step.note}` : "";
		console.log(`│ ${icon} ${step.label}${suffix}`);
	}
	console.log("└──────────────────────────────────────────\n");

	console.log(`Config: ${getConfigPath()}`);
	console.log(`Data dir: ${CONFIG_DIR}`);
	console.log("\nNext steps:");
	if (
		steps.some(
			(s) => s.label === "Telegram bot token" && (s.status === "skipped" || s.status === "failed"),
		)
	) {
		console.log(
			"  1. Add a bot token via `telclaude onboard` (interactive) or by editing telclaude.json.",
		);
	}
	console.log(
		"  1. `telclaude maintenance vault-daemon` (if you plan to use OAuth / git credentials)",
	);
	console.log("  2. `telclaude maintenance totp-daemon`  (if you want 2FA via /auth verify)");
	console.log("  3. `telclaude relay`                    (start the bot)");
	console.log("  4. `telclaude dev doctor`               (verify health at any time)\n");

	// Basic guard: if we have neither token nor allowlist we can't start.
	// Exit 0 anyway — the wizard is idempotent and the operator may want
	// to re-run it later. Failure-of-doctor maps to exit 1 so CI catches it.
	const doctorStep = steps.find((s) => s.label === "Doctor run");
	if (doctorStep?.status === "failed") {
		process.exitCode = 1;
	}
}

// Exported for tests.
export const __internals = {
	readRawConfig,
	writeRawConfig,
	ensureObject,
};
