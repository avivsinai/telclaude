/**
 * DM pairing CLI (Workstream W4).
 *
 * Commands:
 *   telclaude pairing list                    → pending + approved + lockouts
 *   telclaude pairing approve <code>          → approve a pending code
 *   telclaude pairing revoke <user-id>        → revoke all pending codes for a user
 *   telclaude pairing clear-pending           → expire & prune stale rows
 *
 * The pairing flow augments `telegram.allowedChats`: approved pairs are stored
 * in SQLite (`paired_chats`) and automatically granted the configured tier
 * (default READ_ONLY). See `docs/plans/2026-04-18-dx-ecosystem-review.md` §W4.
 */

import type { Command } from "commander";
import type { PermissionTier } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import {
	approvePairingCode,
	clearExpiredPending,
	DEFAULT_PAIRED_TIER,
	listActiveLockouts,
	listPairedChats,
	listPairingRequests,
	revokePendingForUser,
} from "../security/pairing.js";

const logger = getChildLogger({ module: "cmd-pairing" });

const VALID_TIERS: ReadonlyArray<PermissionTier> = [
	"READ_ONLY",
	"WRITE_LOCAL",
	"SOCIAL",
	"FULL_ACCESS",
];

function parseTier(raw: string | undefined): PermissionTier | undefined {
	if (!raw) return undefined;
	const upper = raw.toUpperCase();
	if ((VALID_TIERS as string[]).includes(upper)) {
		return upper as PermissionTier;
	}
	return undefined;
}

function formatTimestamp(ts: number | undefined): string {
	if (!ts) return "-";
	return new Date(ts).toISOString().replace("T", " ").slice(0, 19);
}

function formatDurationShort(ms: number): string {
	if (ms <= 0) return "expired";
	const seconds = Math.floor(ms / 1000);
	if (seconds < 60) return `${seconds}s`;
	const minutes = Math.floor(seconds / 60);
	if (minutes < 60) return `${minutes}m`;
	const hours = Math.floor(minutes / 60);
	return `${hours}h ${minutes % 60}m`;
}

/**
 * Register the `pairing` command group.
 */
export function registerPairingCommand(program: Command): void {
	const pairing = program.command("pairing").description("Manage DM pairing codes");

	pairing
		.command("list")
		.description("Show pending codes, recently approved pairs, and active lockouts")
		.option("--json", "Emit machine-readable JSON")
		.action(async (opts: { json?: boolean }) => {
			const now = Date.now();
			const pendingRequests = listPairingRequests({ status: "pending" }).filter(
				(r) => r.expiresAt > now,
			);
			const approvedRequests = listPairingRequests({ status: "approved" }).slice(0, 20);
			const pairedChats = listPairedChats();
			const lockouts = listActiveLockouts(now);

			if (opts.json) {
				console.log(
					JSON.stringify(
						{
							pending: pendingRequests.map((r) => ({
								userId: r.userId,
								chatId: r.chatId,
								username: r.username,
								tier: r.tier,
								createdAt: r.createdAt,
								expiresAt: r.expiresAt,
								retryableInMs: Math.max(0, r.expiresAt - now),
							})),
							approved: pairedChats.map((p) => ({
								chatId: p.chatId,
								userId: p.userId,
								tier: p.tier,
								pairedAt: p.pairedAt,
								approvedBy: p.approvedBy,
								username: p.username,
							})),
							recentlyApprovedRequests: approvedRequests.map((r) => ({
								userId: r.userId,
								chatId: r.chatId,
								tier: r.tier,
								approvedAt: r.approvedAt,
								approvedBy: r.approvedBy,
							})),
							lockouts: lockouts.map((l) => ({
								userId: l.userId,
								attempts: l.attempts,
								lockedUntil: l.lockedUntil,
								remainingMs: Math.max(0, l.lockedUntil - now),
							})),
						},
						null,
						2,
					),
				);
				return;
			}

			console.log("");
			console.log("PENDING PAIRING CODES");
			console.log("─".repeat(70));
			if (pendingRequests.length === 0) {
				console.log("  (none)");
			} else {
				console.log("  User ID          Chat ID          Tier          Expires in   Username");
				for (const r of pendingRequests) {
					const remaining = formatDurationShort(r.expiresAt - now);
					console.log(
						`  ${String(r.userId).padEnd(16)} ${String(r.chatId).padEnd(16)} ${r.tier.padEnd(13)} ${remaining.padEnd(11)} ${r.username ?? "-"}`,
					);
				}
			}

			console.log("");
			console.log("APPROVED PAIRS");
			console.log("─".repeat(70));
			if (pairedChats.length === 0) {
				console.log("  (none)");
			} else {
				console.log(
					"  Chat ID          User ID          Tier          Paired At            Approved By",
				);
				for (const p of pairedChats) {
					console.log(
						`  ${String(p.chatId).padEnd(16)} ${String(p.userId).padEnd(16)} ${p.tier.padEnd(13)} ${formatTimestamp(p.pairedAt).padEnd(20)} ${p.approvedBy}`,
					);
				}
			}

			console.log("");
			console.log("ACTIVE LOCKOUTS");
			console.log("─".repeat(70));
			if (lockouts.length === 0) {
				console.log("  (none)");
			} else {
				console.log("  User ID          Attempts    Locked Until         Remaining");
				for (const l of lockouts) {
					console.log(
						`  ${String(l.userId).padEnd(16)} ${String(l.attempts).padEnd(11)} ${formatTimestamp(l.lockedUntil).padEnd(20)} ${formatDurationShort(l.lockedUntil - now)}`,
					);
				}
			}
			console.log("");
		});

	pairing
		.command("approve")
		.description("Approve a pending pairing code")
		.argument("<code>", "Pairing code issued by the bot")
		.option("-t, --tier <tier>", "Override the tier (READ_ONLY, WRITE_LOCAL, SOCIAL, FULL_ACCESS)")
		.option("-b, --approved-by <actor>", "Record who approved the pairing", "cli:admin")
		.action(async (code: string, options: { tier?: string; approvedBy?: string }) => {
			const tierOverride = parseTier(options.tier);
			if (options.tier && !tierOverride) {
				console.error(`Invalid tier: ${options.tier}. Expected one of ${VALID_TIERS.join(", ")}.`);
				process.exit(1);
			}

			const result = await approvePairingCode(code, options.approvedBy ?? "cli:admin");
			if (!result.success) {
				console.error(`Pairing approval failed: ${result.error}`);
				process.exit(1);
			}

			// Tier override support: we apply it on top of the stored tier if requested.
			// Approve uses the request's original tier; the override lets the operator
			// upgrade a READ_ONLY-by-default pairing to something broader without editing the DB.
			const { request, paired } = result.data;
			if (tierOverride && tierOverride !== request.tier) {
				const { removePairedChat } = await import("../security/pairing.js");
				removePairedChat(paired.chatId);
				// Re-create paired chat with the requested tier via direct SQL.
				const { getDb } = await import("../storage/db.js");
				const db = getDb();
				db.prepare(
					`INSERT INTO paired_chats (chat_id, user_id, tier, paired_at, approved_by, username)
					 VALUES (?, ?, ?, ?, ?, ?)`,
				).run(
					paired.chatId,
					paired.userId,
					tierOverride,
					paired.pairedAt,
					paired.approvedBy,
					paired.username ?? null,
				);
				console.log(
					`Pairing approved for user ${paired.userId} (chat ${paired.chatId}) with tier ${tierOverride} (overridden from ${request.tier}).`,
				);
				logger.info(
					{
						userId: paired.userId,
						chatId: paired.chatId,
						tier: tierOverride,
						originalTier: request.tier,
						approvedBy: options.approvedBy ?? "cli:admin",
					},
					"pairing approved via CLI (tier overridden)",
				);
			} else {
				console.log(
					`Pairing approved for user ${paired.userId} (chat ${paired.chatId}) with tier ${paired.tier}.`,
				);
				logger.info(
					{
						userId: paired.userId,
						chatId: paired.chatId,
						tier: paired.tier,
						approvedBy: options.approvedBy ?? "cli:admin",
					},
					"pairing approved via CLI",
				);
			}
		});

	pairing
		.command("revoke")
		.description("Revoke all pending pairing codes for a user")
		.argument("<user-id>", "Telegram user ID")
		.action(async (userIdRaw: string) => {
			const userId = Number.parseInt(userIdRaw, 10);
			if (Number.isNaN(userId)) {
				console.error(`Invalid user ID: ${userIdRaw}`);
				process.exit(1);
			}
			const n = revokePendingForUser(userId);
			if (n === 0) {
				console.log(`No pending pairing codes for user ${userId}.`);
			} else {
				console.log(`Revoked ${n} pending pairing code(s) for user ${userId}.`);
				logger.info({ userId, revoked: n }, "pairing codes revoked via CLI");
			}
		});

	pairing
		.command("clear-pending")
		.description("Expire stale pending codes and prune terminal rows older than a week")
		.action(async () => {
			const n = clearExpiredPending();
			if (n === 0) {
				console.log("Nothing to clear.");
			} else {
				console.log(`Cleared ${n} pairing row(s).`);
				logger.info({ cleared: n }, "pairing codes cleared via CLI");
			}
		});

	// Informational footer so `telclaude pairing --help` points at the default tier.
	pairing.addHelpText(
		"afterAll",
		`\n  Default tier granted on approval: ${DEFAULT_PAIRED_TIER}. Override with --tier on \`approve\`.`,
	);
}
