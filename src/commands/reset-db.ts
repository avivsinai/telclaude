import crypto from "node:crypto";
import * as readline from "node:readline";
import type { Command } from "commander";
import { getChildLogger } from "../logging.js";
import { resetDatabase } from "../storage/db.js";

const logger = getChildLogger({ module: "cmd-reset-db" });

async function prompt(question: string): Promise<string> {
	const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
	return new Promise((resolve) => {
		rl.question(question, (answer) => {
			rl.close();
			resolve(answer);
		});
	});
}

export function registerResetDbCommand(program: Command): void {
	program
		.command("reset-db")
		.description("Delete Telclaude SQLite database (DANGEROUS: removes links, approvals, sessions)")
		.option("--force", "Skip interactive confirmations (non-TTY only)")
		.action(async (options: { force?: boolean }) => {
			try {
				if (process.env.TELCLAUDE_ENABLE_RESET_DB !== "1") {
					console.error(
						"TELCLAUDE_ENABLE_RESET_DB=1 is required to run this command. Set it explicitly to acknowledge the risk.",
					);
					process.exit(1);
				}

				console.log("");
				console.log("⚠️  WARNING: This will delete the Telclaude database file.");
				console.log("   Identity links, approvals, sessions, and admin claims will be lost.");
				console.log("   Audit logs and media files are NOT affected.");
				console.log("");

				const isTty = Boolean(process.stdin.isTTY && process.stdout.isTTY);

				if (options.force && isTty) {
					console.log("--force ignored on TTY; interactive confirmations are required.");
				}

				if (!options.force || isTty) {
					const answer = await prompt('Type "RESET DB" to confirm: ');
					if (answer.trim().toUpperCase() !== "RESET DB") {
						console.log("Aborted. No changes made.");
						return;
					}
				}

				if (isTty) {
					const confirmationCode = crypto.randomBytes(3).toString("hex").toUpperCase();
					const codeAnswer = await prompt(`Enter confirmation code ${confirmationCode}: `);
					if (codeAnswer.trim().toUpperCase() !== confirmationCode) {
						console.log("Aborted. No changes made.");
						return;
					}
				}

				resetDatabase();
				console.log("\n✓ Database reset complete.\n");
			} catch (err) {
				logger.error({ error: String(err) }, "reset-db command failed");
				console.error(`Error: ${err}`);
				process.exit(1);
			}
		});
}
