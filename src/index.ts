#!/usr/bin/env node

import { createProgram } from "./cli/program.js";
import { registerRelayCommand } from "./commands/relay.js";
import { registerSendCommand } from "./commands/send.js";
import { registerStatusCommand } from "./commands/status.js";
import { getLogger } from "./logging.js";

// Initialize logger
getLogger();

// Create CLI program
const program = createProgram();

// Register commands
registerSendCommand(program);
registerRelayCommand(program);
registerStatusCommand(program);

// Parse and execute
program.parse();
