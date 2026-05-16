/**
 * CLI alias for sending workspace files to Telegram.
 *
 * `send-local-file` is the original internal command name. `send-file` is the
 * shorter operator-facing spelling documented for agents.
 */

import type { Command } from "commander";
import { executeSendLocalFileCommand, type SendLocalFileOptions } from "./send-local-file.js";

export function registerSendFileCommand(program: Command): void {
	program
		.command("send-file")
		.description("Copy a workspace file to the Telegram delivery outbox")
		.option("--path <path>", "Path to the local file (required)")
		.option("--filename <name>", "Override the filename for display")
		.option("--user-id <id>", "User ID for logging (optional)")
		.action((opts: SendLocalFileOptions) =>
			executeSendLocalFileCommand(opts, {
				commandName: "send-file",
				usage: "telclaude send-file --path /workspace/file.pdf",
				successLabel: "File ready",
			}),
		);
}
