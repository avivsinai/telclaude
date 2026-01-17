/**
 * CLI command for fetching external provider attachments via relay.
 * Used by Claude via the external-provider skill.
 */

import type { Command } from "commander";
import { getChildLogger } from "../logging.js";
import { relayFetchAttachment } from "../relay/capabilities-client.js";

const logger = getChildLogger({ module: "cmd-fetch-attachment" });

export type FetchAttachmentOptions = {
	provider?: string;
	id?: string;
	filename?: string;
	mime?: string;
	inline?: string;
	size?: string;
	userId?: string;
};

export function registerFetchAttachmentCommand(program: Command): void {
	program
		.command("fetch-attachment")
		.description("Fetch an external provider attachment via the relay")
		.option("--provider <id>", "Provider ID (from telclaude.json)")
		.option("--id <attachment-id>", "Attachment ID/token from provider")
		.option("--filename <name>", "Suggested filename for saving")
		.option("--mime <type>", "MIME type (e.g., application/pdf)")
		.option("--inline <base64>", "Inline base64 content (for small attachments)")
		.option("--size <bytes>", "Attachment size in bytes")
		.option("--user-id <id>", "User ID for rate limiting (optional)")
		.action(async (opts: FetchAttachmentOptions) => {
			try {
				const useRelay = Boolean(process.env.TELCLAUDE_CAPABILITIES_URL);
				if (!useRelay) {
					console.error("Error: TELCLAUDE_CAPABILITIES_URL is not configured.");
					console.error("This command requires the relay capabilities server.");
					process.exit(1);
				}

				const providerId = opts.provider?.trim() ?? "";
				const attachmentId = opts.id?.trim() ?? "";
				if (!providerId || !attachmentId) {
					console.error("Error: --provider and --id are required.");
					process.exit(1);
				}

				const size = parseSize(opts.size);
				if (size.error) {
					console.error(`Error: ${size.error}`);
					process.exit(1);
				}

				const result = await relayFetchAttachment({
					providerId,
					attachmentId,
					filename: opts.filename,
					mimeType: opts.mime,
					size: size.value,
					inlineBase64: opts.inline,
					userId: opts.userId ?? process.env.TELCLAUDE_REQUEST_USER_ID,
				});

				if (result.status !== "ok") {
					console.error(`Error: ${result.error ?? "Fetch failed"}`);
					process.exit(1);
				}

				console.log(`Attachment saved to: ${result.path}`);
			} catch (err) {
				logger.error({ error: String(err) }, "fetch-attachment command failed");
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exit(1);
			}
		});
}

function parseSize(input?: string): { value?: number; error?: string } {
	if (!input) return {};
	const parsed = Number.parseInt(input, 10);
	if (!Number.isFinite(parsed) || parsed < 0) {
		return { error: "Invalid size (expected non-negative integer)" };
	}
	return { value: parsed };
}
