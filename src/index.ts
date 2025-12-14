#!/usr/bin/env node

import { createProgram } from "./cli/program.js";
import { registerDoctorCommand } from "./commands/doctor.js";
import { registerLinkCommand } from "./commands/link.js";
import { registerRelayCommand } from "./commands/relay.js";
import { registerResetAuthCommand } from "./commands/reset-auth.js";
import { registerResetDbCommand } from "./commands/reset-db.js";
import { registerSendCommand } from "./commands/send.js";
import { registerStatusCommand } from "./commands/status.js";
import { registerTOTPDaemonCommand } from "./commands/totp-daemon.js";
import { registerTOTPDisableCommand } from "./commands/totp-disable.js";
import { registerTOTPSetupCommand } from "./commands/totp-setup.js";
import { setConfigPath } from "./config/path.js";
import { setVerbose } from "./globals.js";
import { closeLogger, getLogger } from "./logging.js";
import { closeDb } from "./storage/db.js";

// Create CLI program
const program = createProgram();

// Register commands
registerSendCommand(program);
registerRelayCommand(program);
registerStatusCommand(program);
registerLinkCommand(program);
registerDoctorCommand(program);
registerTOTPDaemonCommand(program);
registerTOTPDisableCommand(program);
registerTOTPSetupCommand(program);
registerResetAuthCommand(program);
registerResetDbCommand(program);

// Pre-parse to extract global options before commands run
// This ensures --config and --verbose are set before any config loading happens
program.hook("preAction", (thisCommand) => {
	const opts = thisCommand.opts();
	if (opts.config) {
		setConfigPath(opts.config);
	}
	if (opts.verbose) {
		setVerbose(true);
	}
	// Initialize logger after config path is set
	getLogger();
});

async function main(): Promise<void> {
	await program.parseAsync();
}

main()
	.catch((err) => {
		// Commander prints some errors itself; keep this minimal.
		console.error(`Error: ${String(err)}`);
		process.exitCode = 1;
	})
	.finally(() => {
		// Ensure CLI commands can exit cleanly (pino destination + SQLite keep handles open).
		closeDb();
		closeLogger();
	});
