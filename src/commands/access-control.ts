/**
 * Access Control Commands
 *
 * CLI commands for managing user access:
 * - ban: Block a chat from using the bot
 * - unban: Restore access for a banned chat
 * - force-reauth: Invalidate TOTP session, requiring re-verification
 * - list-bans: Show all banned chats
 *
 * SECURITY: These commands require CLI access (machine access).
 * This is intentional - ban/unban operations should not be possible remotely
 * to prevent an attacker with Telegram+TOTP access from unbanning themselves.
 */

import type { Command } from "commander";
import { getChildLogger } from "../logging.js";
import {
	banChat,
	getBannedChatCount,
	listBannedChats,
	unbanChat,
} from "../security/banned-chats.js";
import { getIdentityLink } from "../security/linking.js";
import { invalidateTOTPSession } from "../security/totp-session.js";
import { parseChatId } from "./cli-utils.js";

const logger = getChildLogger({ module: "cmd-access-control" });

/**
 * Register admin subcommands (ban, unban, list-bans) on a parent command group.
 */
export function registerAdminSubcommands(parent: Command): void {
	parent
		.command("ban")
		.description("Ban a chat from using the bot")
		.argument("<chat-id>", "Telegram chat ID to ban")
		.option("-r, --reason <reason>", "Reason for the ban")
		.action(async (chatIdStr: string, options: { reason?: string }) => {
			try {
				const chatId = parseChatId(chatIdStr);

				const result = banChat(chatId, "cli:admin", options.reason);

				if (result) {
					console.log(`Chat ${chatId} has been banned.`);
					if (options.reason) {
						console.log(`  Reason: ${options.reason}`);
					}
					logger.warn({ chatId, reason: options.reason }, "chat banned via CLI");
				} else {
					console.log(`Chat ${chatId} is already banned.`);
				}
			} catch (err) {
				logger.error({ error: String(err) }, "ban command failed");
				console.error(`Error: ${err}`);
				process.exit(1);
			}
		});

	parent
		.command("unban")
		.description("Restore access for a banned chat")
		.argument("<chat-id>", "Telegram chat ID to unban")
		.action(async (chatIdStr: string) => {
			try {
				const chatId = parseChatId(chatIdStr);

				const result = unbanChat(chatId);

				if (result) {
					console.log(`Chat ${chatId} has been unbanned.`);
					logger.warn({ chatId }, "chat unbanned via CLI");
				} else {
					console.log(`Chat ${chatId} was not banned.`);
				}
			} catch (err) {
				logger.error({ error: String(err) }, "unban command failed");
				console.error(`Error: ${err}`);
				process.exit(1);
			}
		});

	parent
		.command("list-bans")
		.description("List all banned chats")
		.action(async () => {
			try {
				const banned = listBannedChats();
				const count = getBannedChatCount();

				if (count === 0) {
					console.log("No banned chats.");
					return;
				}

				console.log(`Banned chats (${count}):\n`);
				console.log("  Chat ID        Banned At              Banned By    Reason");
				console.log("  ─────────────  ─────────────────────  ───────────  ──────────────────────");

				for (const ban of banned) {
					const bannedAt = new Date(ban.bannedAt).toISOString().replace("T", " ").slice(0, 19);
					const reason = ban.reason ? ban.reason.slice(0, 20) : "-";
					console.log(
						`  ${String(ban.chatId).padEnd(13)}  ${bannedAt}  ${ban.bannedBy.padEnd(11)}  ${reason}`,
					);
				}

				console.log("");
			} catch (err) {
				logger.error({ error: String(err) }, "list-bans command failed");
				console.error(`Error: ${err}`);
				process.exit(1);
			}
		});
}

/**
 * Register force-reauth as a subcommand on a parent (auth group).
 */
export function registerForceReauthSubcommand(parent: Command): void {
	parent
		.command("force-reauth")
		.description("Invalidate TOTP session for a chat, requiring re-verification")
		.argument("[chat-id]", "Telegram chat ID to force re-authentication")
		.action(async (chatIdStr: string) => {
			try {
				if (!chatIdStr) {
					console.error("Usage: telclaude auth force-reauth <chat-id>");
					console.error("  Invalidates the TOTP session for the given chat.");
					process.exit(1);
				}
				const chatId = parseChatId(chatIdStr);

				const link = getIdentityLink(chatId);
				if (!link) {
					console.log(`Chat ${chatId} has no identity link. Nothing to invalidate.`);
					return;
				}

				const result = invalidateTOTPSession(link.localUserId);

				if (result) {
					console.log(`TOTP session invalidated for chat ${chatId} (user: ${link.localUserId}).`);
					console.log("  Next message will require 2FA verification.");
					logger.warn(
						{ chatId, localUserId: link.localUserId },
						"TOTP session invalidated via CLI",
					);
				} else {
					console.log(`Chat ${chatId} (user: ${link.localUserId}) had no active TOTP session.`);
				}
			} catch (err) {
				logger.error({ error: String(err) }, "force-reauth command failed");
				console.error(`Error: ${err}`);
				process.exit(1);
			}
		});
}
