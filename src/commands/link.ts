import type { Command } from "commander";
import { generateLinkCode, listIdentityLinks, removeIdentityLink } from "../security/linking.js";
import { parseChatId } from "./cli-utils.js";

export type LinkOptions = {
	list?: boolean;
	remove?: string;
};

export function registerLinkCommand(program: Command): void {
	program
		.command("link")
		.description("Generate or manage identity link codes")
		.argument("[user-id]", "Local user identifier to link")
		.option("-l, --list", "List all identity links")
		.option("-r, --remove <chat-id>", "Remove an identity link")
		.action(async (userId: string | undefined, opts: LinkOptions) => {
			if (opts.list) {
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
				return;
			}

			if (opts.remove) {
				const chatId = parseChatId(opts.remove);

				const removed = removeIdentityLink(chatId);
				if (removed) {
					console.log(`Identity link for chat ${chatId} removed.`);
				} else {
					console.log(`No identity link found for chat ${chatId}.`);
				}
				return;
			}

			if (!userId) {
				console.error("Error: User ID required. Usage: telclaude link <user-id>");
				console.log("\nExamples:");
				console.log("  telclaude link aviv        # Generate code for user 'aviv'");
				console.log("  telclaude link --list      # List all identity links");
				console.log("  telclaude link -r 123456   # Remove link for chat 123456");
				process.exit(1);
			}

			const code = generateLinkCode(userId);

			console.log("\n╔══════════════════════════════════════════════════════════╗");
			console.log("║              IDENTITY LINK CODE GENERATED                ║");
			console.log("╠══════════════════════════════════════════════════════════╣");
			console.log(`║  Code: ${code}                                       ║`);
			console.log(`║  User: ${userId.padEnd(49)}║`);
			console.log("║  Expires: 10 minutes                                     ║");
			console.log("╠══════════════════════════════════════════════════════════╣");
			console.log("║  In Telegram, send this message to your bot:             ║");
			console.log(`║  /link ${code}                                       ║`);
			console.log("╚══════════════════════════════════════════════════════════╝\n");
		});
}
