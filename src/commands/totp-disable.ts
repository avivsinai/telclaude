import type { Command } from "commander";
import { getTOTPClient } from "../totp-client/client.js";

export function registerTOTPDisableCommand(program: Command): void {
	program
		.command("totp-disable")
		.description("Disable TOTP 2FA for a user")
		.argument("<user-id>", "Local user identifier to disable TOTP for")
		.action(async (userId: string) => {
			const client = getTOTPClient();

			const available = await client.isAvailable();
			if (!available) {
				console.error("\n❌ TOTP daemon is not running.");
				console.error("Start it with: telclaude totp-daemon\n");
				process.exit(1);
			}

			const removed = await client.disable(userId);
			if (!removed) {
				console.error(`\n⚠️  No TOTP configuration found for user '${userId}'.`);
				process.exit(1);
			}

			console.log(`\n✅ TOTP 2FA disabled for user '${userId}'.`);
		});
}
