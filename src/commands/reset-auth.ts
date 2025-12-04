/**
 * Reset Auth Command - V2 Security
 *
 * Nukes all local auth state, forcing re-claim on next Telegram message.
 *
 * SAFETY: This is a dangerous operation that requires explicit confirmation.
 * If an attacker gains access to the machine, they could run this command
 * and then claim admin on the next Telegram message.
 *
 * Mitigation:
 * - Requires explicit "RESET" confirmation
 * - Audit logged
 * - Warning messages explain the risk
 */

import * as readline from "node:readline";
import type { Command } from "commander";
import { getChildLogger } from "../logging.js";
import { getDb } from "../storage/db.js";

const logger = getChildLogger({ module: "cmd-reset-auth" });

/**
 * Prompt for user input with readline.
 */
async function prompt(question: string): Promise<string> {
	const rl = readline.createInterface({
		input: process.stdin,
		output: process.stdout,
	});

	return new Promise((resolve) => {
		rl.question(question, (answer) => {
			rl.close();
			resolve(answer);
		});
	});
}

export function registerResetAuthCommand(program: Command): void {
	program
		.command("reset-auth")
		.description("Reset all identity links and TOTP sessions (DANGEROUS)")
		.option("--force", "Skip confirmation prompt")
		.action(async (options: { force?: boolean }) => {
			try {
				console.log("");
				console.log("⚠️  WARNING: This will remove ALL identity links and TOTP sessions.");
				console.log("   The next Telegram message will be able to claim admin.");
				console.log("");
				console.log("   If you did NOT run this command, something is seriously wrong.");
				console.log("   An attacker with shell access could take over your bot.");
				console.log("");

				if (!options.force) {
					const answer = await prompt('Type "RESET" to confirm: ');
					if (answer.trim() !== "RESET") {
						console.log("");
						console.log("Aborted. No changes made.");
						return;
					}
				}

				const db = getDb();

				// Get counts before deletion for logging
				const identityCount = (
					db.prepare("SELECT COUNT(*) as count FROM identity_links").get() as { count: number }
				).count;
				const totpSessionCount = (
					db.prepare("SELECT COUNT(*) as count FROM totp_sessions").get() as { count: number }
				).count;
				const pendingClaimsCount = getPendingAdminClaimsCount(db);

				// Delete all auth state
				db.transaction(() => {
					db.prepare("DELETE FROM identity_links").run();
					db.prepare("DELETE FROM totp_sessions").run();
					db.prepare("DELETE FROM pending_link_codes").run();
					// Also clean up pending admin claims if table exists
					try {
						db.prepare("DELETE FROM pending_admin_claims").run();
					} catch {
						// Table may not exist yet
					}
				})();

				// Log the action
				logger.warn(
					{
						identityLinksDeleted: identityCount,
						totpSessionsDeleted: totpSessionCount,
						pendingClaimsDeleted: pendingClaimsCount,
					},
					"auth state reset via CLI command",
				);

				console.log("");
				console.log("✓ Auth state reset complete.");
				console.log(`   Deleted ${identityCount} identity link(s)`);
				console.log(`   Deleted ${totpSessionCount} TOTP session(s)`);
				if (pendingClaimsCount > 0) {
					console.log(`   Deleted ${pendingClaimsCount} pending claim(s)`);
				}
				console.log("");
				console.log("Next Telegram message to this bot can claim admin.");
				console.log("");
			} catch (err) {
				logger.error({ error: String(err) }, "reset-auth command failed");
				console.error(`Error: ${err}`);
				process.exit(1);
			}
		});
}

/**
 * Get count of pending admin claims, handling case where table doesn't exist.
 */
function getPendingAdminClaimsCount(db: ReturnType<typeof getDb>): number {
	try {
		const row = db.prepare("SELECT COUNT(*) as count FROM pending_admin_claims").get() as {
			count: number;
		};
		return row.count;
	} catch {
		return 0;
	}
}
