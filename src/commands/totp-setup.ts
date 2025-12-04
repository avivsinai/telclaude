import * as readline from "node:readline";
import type { Command } from "commander";
import qrcode from "qrcode-terminal";
import { getTOTPClient } from "../totp-client/client.js";

export type TOTPSetupOptions = {
	user?: string;
};

/**
 * Display a QR code in the terminal.
 */
function displayQRCode(uri: string): Promise<void> {
	return new Promise((resolve) => {
		qrcode.generate(uri, { small: true }, () => {
			resolve();
		});
	});
}

/**
 * Read a line from stdin.
 */
async function readLine(prompt: string): Promise<string> {
	const rl = readline.createInterface({
		input: process.stdin,
		output: process.stdout,
	});

	return new Promise((resolve) => {
		rl.question(prompt, (answer) => {
			rl.close();
			resolve(answer);
		});
	});
}

export function registerTOTPSetupCommand(program: Command): void {
	program
		.command("totp-setup")
		.description("Set up TOTP 2FA for a user (secrets displayed locally, never sent via network)")
		.argument("<user-id>", "Local user identifier to set up TOTP for")
		.action(async (userId: string) => {
			const client = getTOTPClient();

			// Check daemon availability
			const available = await client.isAvailable();
			if (!available) {
				console.error("\n❌ TOTP daemon is not running.");
				console.error("Start it with: telclaude totp-daemon\n");
				process.exit(1);
			}

			// Check if TOTP is already enabled
			const checkResult = await client.check(userId);
			if (checkResult.status === "enabled") {
				console.log(`\n⚠️  TOTP is already enabled for user '${userId}'.`);
				const answer = await readLine("Do you want to reset it? (yes/no): ");
				if (answer.toLowerCase() !== "yes") {
					console.log("Aborted.");
					process.exit(0);
				}
				// Disable first
				await client.disable(userId);
			}

			// Set up TOTP
			const setupResult = await client.setup(userId, `Telclaude:${userId}`);
			if (!setupResult.success) {
				console.error(`\n❌ Failed to set up TOTP: ${setupResult.error}`);
				process.exit(1);
			}

			// Extract secret from URI for manual entry
			const secretMatch = setupResult.uri.match(/secret=([A-Z2-7]+)/);
			const secret = secretMatch?.[1] ?? "";

			console.log("\n╔══════════════════════════════════════════════════════════╗");
			console.log("║           TWO-FACTOR AUTHENTICATION SETUP                ║");
			console.log("╠══════════════════════════════════════════════════════════╣");
			console.log("║                                                          ║");
			console.log("║  SECURITY: This secret is displayed LOCALLY ONLY.        ║");
			console.log("║  It is never sent over the network or stored in logs.    ║");
			console.log("║                                                          ║");
			console.log("╚══════════════════════════════════════════════════════════╝");

			console.log("\n📱 Scan this QR code with your authenticator app:\n");

			// Display QR code
			await displayQRCode(setupResult.uri);

			console.log("\n╔══════════════════════════════════════════════════════════╗");
			console.log("║  MANUAL ENTRY (if QR scan fails)                         ║");
			console.log("╠══════════════════════════════════════════════════════════╣");
			console.log("║                                                          ║");
			console.log(`║  User: ${userId.padEnd(50)}║`);
			console.log("║                                                          ║");
			console.log("║  Secret:                                                 ║");
			console.log(`║  ${secret.padEnd(56)}║`);
			console.log("║                                                          ║");
			console.log("╚══════════════════════════════════════════════════════════╝\n");

			// Verify setup
			console.log("Enter the 6-digit code from your authenticator to verify setup:");
			const code = await readLine("> ");

			if (!/^\d{6}$/.test(code)) {
				console.error("\n❌ Invalid code format. Please enter a 6-digit number.");
				console.error(`Setup incomplete - you can try again with: telclaude totp-setup ${userId}`);
				process.exit(1);
			}

			const valid = await client.verify(userId, code);
			if (!valid) {
				console.error("\n❌ Invalid code. Please check your authenticator and try again.");
				console.error(`Setup incomplete - you can try again with: telclaude totp-setup ${userId}`);
				process.exit(1);
			}

			console.log("\n✅ TOTP 2FA setup complete!");
			console.log(`   User '${userId}' can now approve requests with their authenticator code.`);
			console.log(`\n   To disable 2FA later: telclaude totp-disable ${userId}`);
		});
}
