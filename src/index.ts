#!/usr/bin/env node

import { createProgram } from "./cli/program.js";
import {
	registerAdminSubcommands,
	registerForceReauthSubcommand,
} from "./commands/access-control.js";
import { registerAgentCommand } from "./commands/agent.js";
import { registerBackgroundCommand } from "./commands/background.js";
import { registerCronCommand } from "./commands/cron.js";
import { registerDiagnoseSandboxNetworkCommand } from "./commands/diagnose-sandbox-network.js";
import { registerDoctorCommand } from "./commands/doctor.js";
import { registerFetchAttachmentCommand } from "./commands/fetch-attachment.js";
import { registerGenerateImageCommand } from "./commands/generate-image.js";
import { registerGitCredentialCommand } from "./commands/git-credential.js";
import { registerGitProxyInitCommand } from "./commands/git-proxy-init.js";
import { registerGitTestCommand } from "./commands/git-test.js";
import { registerIntegrationTestCommand } from "./commands/integration-test.js";
import { registerKeygenCommand } from "./commands/keygen.js";
import { registerIdentitySubcommands } from "./commands/link.js";
import { registerMemoryCommands } from "./commands/memory.js";
import { registerNetworkCommand } from "./commands/network.js";
import { registerOAuthCommand } from "./commands/oauth.js";
import { registerProviderHealthCommand } from "./commands/provider-health.js";
import { registerProviderQueryCommand } from "./commands/provider-query.js";
import { registerQuickstartCommand } from "./commands/quickstart.js";
import { registerRelayCommand } from "./commands/relay.js";
import { registerResetAuthCommand } from "./commands/reset-auth.js";
import { registerResetDbCommand } from "./commands/reset-db.js";
import { registerSendCommand } from "./commands/send.js";
import { registerSendAttachmentCommand } from "./commands/send-attachment.js";
import { registerSendLocalFileCommand } from "./commands/send-local-file.js";
import { registerSessionsCommand } from "./commands/sessions.js";
import { registerSetupGitCommand } from "./commands/setup-git.js";
import { registerSetupGitHubAppCommand } from "./commands/setup-github-app.js";
import { registerSetupGoogleCommand } from "./commands/setup-google.js";
import { registerSetupOpenAICommand } from "./commands/setup-openai.js";
import { registerSkillPathCommand } from "./commands/skill-path.js";
import { registerSkillsImportSubcommands } from "./commands/skills-import.js";
import { registerSkillsPromoteSubcommands } from "./commands/skills-promote.js";
import { registerStatusCommand } from "./commands/status.js";
import { registerSummarizeCommand } from "./commands/summarize.js";
import { registerTextToSpeechCommand } from "./commands/text-to-speech.js";
import { registerTOTPDaemonCommand } from "./commands/totp-daemon.js";
import { registerTOTPDisableCommand } from "./commands/totp-disable.js";
import { registerTOTPSetupCommand } from "./commands/totp-setup.js";
import { registerVaultCommand } from "./commands/vault.js";
import { registerVaultDaemonCommand } from "./commands/vault-daemon.js";
import { setConfigPath } from "./config/path.js";
import { setVerbose } from "./globals.js";
import { closeLogger, getLogger } from "./logging.js";
import { closeDb } from "./storage/db.js";

// Create CLI program
const program = createProgram();

// ═══════════════════════════════════════════════════════════════════════════════
// Top-level commands (frequently used, kept at root)
// ═══════════════════════════════════════════════════════════════════════════════

registerRelayCommand(program);
registerAgentCommand(program);
registerStatusCommand(program);
registerSendCommand(program);
registerSessionsCommand(program);

// ═══════════════════════════════════════════════════════════════════════════════
// Command groups (namespaced subcommands)
// ═══════════════════════════════════════════════════════════════════════════════

// --- identity ---
const identity = program.command("identity").description("Manage identity links");
registerIdentitySubcommands(identity);

// --- auth ---
const auth = program.command("auth").description("Authentication and authorization");
registerTOTPSetupCommand(auth);
registerTOTPDisableCommand(auth);
registerForceReauthSubcommand(auth);
registerOAuthCommand(auth);

// --- secrets ---
const secrets = program.command("secrets").description("Manage API keys and credentials");
registerSetupOpenAICommand(secrets);
registerSetupGitCommand(secrets);
registerSetupGitHubAppCommand(secrets);
registerSetupGoogleCommand(secrets);

// --- skills ---
const skills = program.command("skills").description("Manage telclaude skills");
registerSkillsImportSubcommands(skills);
registerSkillsPromoteSubcommands(skills);

// --- admin ---
const admin = program.command("admin").description("Access control and moderation");
registerAdminSubcommands(admin);

// --- dev ---
const dev = program.command("dev").description("Development and diagnostic tools");
registerDoctorCommand(dev);
registerIntegrationTestCommand(dev);
registerDiagnoseSandboxNetworkCommand(dev);
registerQuickstartCommand(dev);
registerKeygenCommand(dev);
registerNetworkCommand(dev);
registerGitTestCommand(dev);

// --- maintenance ---
const maintenance = program.command("maintenance").description("System maintenance and daemons");
registerResetAuthCommand(maintenance);
registerResetDbCommand(maintenance);
registerVaultDaemonCommand(maintenance);
registerTOTPDaemonCommand(maintenance);
registerCronCommand(maintenance);
registerVaultCommand(maintenance);

// ═══════════════════════════════════════════════════════════════════════════════
// Internal commands (used by agent skills, not in the public hierarchy)
// ═══════════════════════════════════════════════════════════════════════════════

registerFetchAttachmentCommand(program);
registerSendAttachmentCommand(program);
registerSendLocalFileCommand(program);
registerGenerateImageCommand(program);
registerTextToSpeechCommand(program);
registerSkillPathCommand(program);
registerProviderQueryCommand(program);
registerProviderHealthCommand(program);
registerGitCredentialCommand(program);
registerGitProxyInitCommand(program);
registerMemoryCommands(program);
registerSummarizeCommand(program);
registerBackgroundCommand(program);

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
		// Close handles that keep the event loop alive.
		closeDb();
		closeLogger();
		// Force exit after a short grace period — fetch() keep-alive connections
		// can keep the event loop alive indefinitely in one-shot CLI commands.
		// Daemons (relay, agent, totp-daemon, vault-daemon) never reach .finally()
		// during normal operation since their parseAsync() never resolves.
		// Use 500ms grace to allow stdout/stderr to flush on slow pipes.
		setTimeout(() => process.exit(process.exitCode ?? 0), 500);
	});
