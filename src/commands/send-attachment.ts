/**
 * CLI command for sending provider attachments via ref.
 *
 * Used by Claude via the external-provider skill after the proxy
 * has intercepted and stored the attachment.
 *
 * The file is already in the outbox (stored by the proxy).
 * This command validates the ref via the relay and outputs the path,
 * which triggers the outbox watcher to send to Telegram.
 */

import fs from "node:fs";
import type { Command } from "commander";
import { getChildLogger } from "../logging.js";
import { relayValidateAttachment } from "../relay/capabilities-client.js";

const logger = getChildLogger({ module: "cmd-send-attachment" });

export type SendAttachmentOptions = {
	ref?: string;
	userId?: string;
};

export function registerSendAttachmentCommand(program: Command): void {
	program
		.command("send-attachment")
		.description("Send a previously-stored attachment via its ref")
		.option("--ref <ref>", "Attachment ref token from provider proxy")
		.option("--user-id <id>", "User ID for validation (optional)")
		.action(async (opts: SendAttachmentOptions) => {
			try {
				const useRelay = Boolean(process.env.TELCLAUDE_CAPABILITIES_URL);
				if (!useRelay) {
					console.error("Error: TELCLAUDE_CAPABILITIES_URL is not configured.");
					console.error("This command requires the relay capabilities server.");
					process.exit(1);
				}

				const ref = opts.ref?.trim();
				if (!ref) {
					console.error("Error: --ref is required.");
					console.error("Usage: telclaude send-attachment --ref att_xxx.xxx.xxx");
					process.exit(1);
				}

				// Validate the ref via relay
				const userId = opts.userId ?? process.env.TELCLAUDE_REQUEST_USER_ID;
				const result = await relayValidateAttachment({ ref, userId });

				if (result.status !== "ok" || !result.attachment) {
					console.error(`Error: ${result.error ?? "Attachment not found or expired"}`);
					process.exit(1);
				}

				const { attachment } = result;

				// Verify file still exists
				try {
					await fs.promises.access(attachment.filepath, fs.constants.R_OK);
				} catch {
					logger.error({ ref, filepath: attachment.filepath }, "attachment file not found");
					console.error("Error: Attachment file no longer exists.");
					process.exit(1);
				}

				// Output the path - the outbox watcher will handle sending to Telegram
				console.log(`Attachment ready: ${attachment.filepath}`);
				console.log(`Filename: ${attachment.filename}`);
				if (attachment.mimeType) {
					console.log(`Type: ${attachment.mimeType}`);
				}
				if (attachment.size) {
					console.log(`Size: ${attachment.size} bytes`);
				}
			} catch (err) {
				logger.error({ error: String(err) }, "send-attachment command failed");
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exit(1);
			}
		});
}
