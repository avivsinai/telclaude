#!/usr/bin/env node

import { createProgram } from "./cli/program.js";
import { registerAccessControlCommands } from "./commands/access-control.js";
import { registerAgentCommand } from "./commands/agent.js";
import { registerDiagnoseSandboxNetworkCommand } from "./commands/diagnose-sandbox-network.js";
import { registerDoctorCommand } from "./commands/doctor.js";
import { registerGenerateImageCommand } from "./commands/generate-image.js";
import { registerGitCredentialCommand } from "./commands/git-credential.js";
import { registerGitProxyInitCommand } from "./commands/git-proxy-init.js";
import { registerGitTestCommand } from "./commands/git-test.js";
import { registerIntegrationTestCommand } from "./commands/integration-test.js";
import { registerLinkCommand } from "./commands/link.js";
import { registerQuickstartCommand } from "./commands/quickstart.js";
import { registerRelayCommand } from "./commands/relay.js";
import { registerResetAuthCommand } from "./commands/reset-auth.js";
import { registerResetDbCommand } from "./commands/reset-db.js";
import { registerSendCommand } from "./commands/send.js";
import { registerSetupGitCommand } from "./commands/setup-git.js";
import { registerSetupGitHubAppCommand } from "./commands/setup-github-app.js";
import { registerSetupOpenAICommand } from "./commands/setup-openai.js";
import { registerStatusCommand } from "./commands/status.js";
import { registerTextToSpeechCommand } from "./commands/text-to-speech.js";
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
registerAgentCommand(program);
registerStatusCommand(program);
registerLinkCommand(program);
registerDoctorCommand(program);
registerTOTPDaemonCommand(program);
registerTOTPDisableCommand(program);
registerTOTPSetupCommand(program);
registerResetAuthCommand(program);
registerResetDbCommand(program);
registerAccessControlCommands(program);
registerGenerateImageCommand(program);
registerTextToSpeechCommand(program);
registerSetupOpenAICommand(program);
registerSetupGitCommand(program);
registerSetupGitHubAppCommand(program);
registerGitTestCommand(program);
registerGitCredentialCommand(program);
registerGitProxyInitCommand(program);
registerIntegrationTestCommand(program);
registerDiagnoseSandboxNetworkCommand(program);
registerQuickstartCommand(program);

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
