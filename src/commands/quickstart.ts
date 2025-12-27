import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import type { Command } from "commander";
import { CONFIG_DIR } from "../utils.js";

/**
 * Quickstart command - creates a minimal config for first-time users.
 *
 * Sets up:
 * - READ_ONLY tier (safe default)
 * - Simple security profile (no observer, no approvals)
 * - No TOTP requirement
 * - Minimal friction to get started
 */

function prompt(rl: readline.Interface, question: string): Promise<string> {
	return new Promise((resolve) => {
		rl.question(question, (answer) => {
			resolve(answer.trim());
		});
	});
}

export interface QuickstartOptions {
	token?: string;
	chatId?: string;
	force?: boolean;
}

export function registerQuickstartCommand(program: Command): void {
	program
		.command("quickstart")
		.description("Create a minimal config to get started quickly (READ_ONLY, no TOTP)")
		.option("-t, --token <token>", "Telegram bot token (from @BotFather)")
		.option("-c, --chat-id <chatId>", "Your Telegram chat ID (numeric)")
		.option("-f, --force", "Overwrite existing config without prompting")
		.action(async (opts: QuickstartOptions) => {
			const configPath = path.join(CONFIG_DIR, "telclaude.json");
			const configExists = fs.existsSync(configPath);

			const rl = readline.createInterface({
				input: process.stdin,
				output: process.stdout,
			});

			try {
				console.log("\n🚀 Telclaude Quickstart\n");
				console.log("This will create a minimal config with:");
				console.log("  • READ_ONLY permission tier (safe for testing)");
				console.log("  • Simple security profile (no observer, no TOTP)");
				console.log("  • Fast setup - start chatting in minutes\n");

				// Check for existing config
				if (configExists && !opts.force) {
					const overwrite = await prompt(
						rl,
						`Config already exists at ${configPath}. Overwrite? [y/N]: `,
					);
					if (overwrite.toLowerCase() !== "y" && overwrite.toLowerCase() !== "yes") {
						console.log("\nAborted. Your existing config is unchanged.");
						return;
					}
				}

				// Get bot token
				let token = opts.token;
				if (!token) {
					console.log("Step 1: Get your bot token from @BotFather on Telegram");
					console.log("        (Send /newbot to @BotFather to create one)\n");
					token = await prompt(rl, "Bot token: ");
				}

				if (!token || !token.includes(":")) {
					console.error("\n❌ Invalid token format. Expected format: 123456789:ABC-DEF...");
					process.exit(1);
				}

				// Get chat ID
				let chatId = opts.chatId;
				if (!chatId) {
					console.log("\nStep 2: Get your chat ID");
					console.log("        Send a message to your bot, then visit:");
					console.log(`        https://api.telegram.org/bot${token}/getUpdates`);
					console.log('        Look for "chat":{"id": YOUR_CHAT_ID}\n');
					chatId = await prompt(rl, "Your chat ID (numeric): ");
				}

				const numericChatId = Number.parseInt(chatId, 10);
				if (Number.isNaN(numericChatId)) {
					console.error("\n❌ Invalid chat ID. Must be a number.");
					process.exit(1);
				}

				// Create config
				const config = {
					telegram: {
						botToken: token,
						allowedChats: [numericChatId],
					},
					security: {
						profile: "simple",
						permissions: {
							defaultTier: "READ_ONLY",
							users: {
								[`tg:${numericChatId}`]: { tier: "READ_ONLY" },
							},
						},
					},
					inbound: {
						reply: {
							enabled: true,
							timeoutSeconds: 300,
							typingIntervalSeconds: 5,
						},
					},
				};

				// Ensure config directory exists
				fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });

				// Write config with secure permissions
				fs.writeFileSync(configPath, JSON.stringify(config, null, 2), { mode: 0o600 });

				console.log("\n✅ Config created successfully!\n");
				console.log(`   Location: ${configPath}`);
				console.log(`   Chat ID: ${numericChatId}`);
				console.log("   Tier: READ_ONLY (can read files, search, web access)");
				console.log("   Profile: simple (no approvals needed)\n");

				console.log("Next steps:");
				console.log("  1. Ensure Claude CLI is installed: brew install anthropic-ai/cli/claude");
				console.log("  2. Log in to Claude: claude login");
				console.log("  3. Start the relay: telclaude relay\n");

				console.log("Optional: Upgrade your permissions later with:");
				console.log('  - WRITE_LOCAL: Can edit files (blocks destructive commands like "rm")');
				console.log("  - FULL_ACCESS: Full control (requires approvals)\n");

				console.log("Edit the config to change permissions:");
				console.log(`  ${configPath}\n`);
			} finally {
				rl.close();
			}
		});
}
