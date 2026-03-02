import type { Command } from "commander";
import { getChildLogger } from "../logging.js";
import { resetDatabase } from "../storage/db.js";
import { confirmDangerousReset } from "./cli-utils.js";

const logger = getChildLogger({ module: "cmd-reset-db" });

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

				const confirmed = await confirmDangerousReset({ label: "RESET DB", force: options.force });
				if (!confirmed) {
					return;
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
