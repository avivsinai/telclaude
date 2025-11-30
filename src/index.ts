#!/usr/bin/env node

import { createProgram } from "./cli/program.js";
import { registerDoctorCommand } from "./commands/doctor.js";
import { registerLinkCommand } from "./commands/link.js";
import { registerRelayCommand } from "./commands/relay.js";
import { registerSendCommand } from "./commands/send.js";
import { registerStatusCommand } from "./commands/status.js";
import { setConfigPath } from "./config/path.js";
import { setVerbose } from "./globals.js";
import { getLogger } from "./logging.js";

// Create CLI program
const program = createProgram();

// Register commands
registerSendCommand(program);
registerRelayCommand(program);
registerStatusCommand(program);
registerLinkCommand(program);
registerDoctorCommand(program);

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

// Parse and execute
program.parse();
