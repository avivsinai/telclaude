/**
 * CLI command for sending local workspace files to Telegram.
 *
 * Used by Claude to send files that exist in the workspace (not from external providers).
 * The command copies the file to the media outbox via the relay, which triggers
 * the outbox watcher to send it to Telegram.
 */

import type { Command } from "commander";
import { getChildLogger } from "../logging.js";
import { relayDeliverLocalFile } from "../relay/capabilities-client.js";

const logger = getChildLogger({ module: "cmd-send-local-file" });

export type SendLocalFileOptions = {
	path?: string;
	filename?: string;
	userId?: string;
};

export function registerSendLocalFileCommand(program: Command): void {
	program
		.command("send-local-file")
		.description("Send a local workspace file to Telegram")
		.option("--path <path>", "Path to the local file (required)")
		.option("--filename <name>", "Override the filename for display")
		.option("--user-id <id>", "User ID for logging (optional)")
		.action(async (opts: SendLocalFileOptions) => {
			try {
				const useRelay = Boolean(process.env.TELCLAUDE_CAPABILITIES_URL);
				if (!useRelay) {
					console.error("Error: TELCLAUDE_CAPABILITIES_URL is not configured.");
					console.error("This command requires the relay capabilities server.");
					process.exit(1);
				}

				const sourcePath = opts.path?.trim();
				if (!sourcePath) {
					console.error("Error: --path is required.");
					console.error("Usage: telclaude send-local-file --path /workspace/file.pdf");
					process.exit(1);
				}

				const result = await relayDeliverLocalFile({
					sourcePath,
					filename: opts.filename,
					userId: opts.userId ?? process.env.TELCLAUDE_REQUEST_USER_ID,
				});

				if (result.status !== "ok") {
					console.error(`Error: ${result.error ?? "Delivery failed"}`);
					process.exit(1);
				}

				// Output the path - the outbox watcher will detect and send to Telegram
				console.log(`File delivered: ${result.path}`);
				console.log(`Filename: ${result.filename}`);
				console.log(`Size: ${result.size} bytes`);
			} catch (err) {
				logger.error({ error: String(err) }, "send-local-file command failed");
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exit(1);
			}
		});
}
