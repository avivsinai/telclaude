import type { Command } from "commander";
import { generateLinkCode, listIdentityLinks, removeIdentityLink } from "../security/linking.js";
import { parseChatId } from "./cli-utils.js";

/**
 * Register identity subcommands on a parent command group.
 * Parent is expected to be the "identity" group.
 */
export function registerIdentitySubcommands(parent: Command): void {
	parent
		.command("link")
		.description("Generate an identity link code")
		.argument("<user-id>", "Local user identifier to link")
		.action(async (userId: string) => {
			const code = generateLinkCode(userId);

			console.log("\n══════════════════════════════════════════════════════════");
			console.log("              IDENTITY LINK CODE GENERATED                ");
			console.log("══════════════════════════════════════════════════════════");
			console.log(`  Code: ${code}`);
			console.log(`  User: ${userId}`);
			console.log("  Expires: 10 minutes");
			console.log("──────────────────────────────────────────────────────────");
			console.log("  In Telegram, send this message to your bot:");
			console.log(`  /link ${code}`);
			console.log("══════════════════════════════════════════════════════════\n");
		});

	parent
		.command("list")
		.description("List all identity links")
		.action(async () => {
			const links = listIdentityLinks();
			if (links.length === 0) {
				console.log("No identity links configured.");
				return;
			}

			console.log("Identity Links:");
			console.log("─".repeat(60));
			for (const link of links) {
				const linkedDate = new Date(link.linkedAt).toLocaleString();
				console.log(`  Chat ID: ${link.chatId}`);
				console.log(`  Local User: ${link.localUserId}`);
				console.log(`  Linked: ${linkedDate}`);
				console.log(`  Linked by: ${link.linkedBy}`);
				console.log("─".repeat(60));
			}
		});

	parent
		.command("remove")
		.description("Remove an identity link")
		.argument("<chat-id>", "Chat ID to remove the link for")
		.action(async (chatIdStr: string) => {
			const chatId = parseChatId(chatIdStr);

			const removed = removeIdentityLink(chatId);
			if (removed) {
				console.log(`Identity link for chat ${chatId} removed.`);
			} else {
				console.log(`No identity link found for chat ${chatId}.`);
			}
		});
}
