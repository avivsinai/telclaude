/**
 * CLI command for extracting and summarizing web content.
 * Used by Claude via the summarize skill.
 */

import type { Command } from "commander";
import { getChildLogger } from "../logging.js";
import { summarizeUrl } from "../services/summarize.js";

const logger = getChildLogger({ module: "cmd-summarize" });

export type SummarizeCommandOptions = {
	maxChars?: string;
	format?: "text" | "markdown";
	timeout?: string;
	userId?: string;
	verbose?: boolean;
};

export function registerSummarizeCommand(program: Command): void {
	program
		.command("summarize")
		.description("Extract and summarize content from a URL")
		.argument("<url>", "URL to extract content from")
		.option("--max-chars <n>", "Maximum characters to extract (default: 8000)")
		.option("--format <format>", "Output format: text or markdown", "text")
		.option("--timeout <ms>", "Timeout in milliseconds (default: 30000)")
		.option("--user-id <id>", "User ID for rate limiting (optional)")
		.action(async (url: string, opts: SummarizeCommandOptions) => {
			try {
				const maxCharacters = opts.maxChars ? Number.parseInt(opts.maxChars, 10) : undefined;
				const timeoutMs = opts.timeout ? Number.parseInt(opts.timeout, 10) : undefined;
				const format = opts.format === "markdown" ? "markdown" : "text";
				const userId = opts.userId ?? process.env.TELCLAUDE_REQUEST_USER_ID;

				if (maxCharacters !== undefined && (!Number.isFinite(maxCharacters) || maxCharacters < 1)) {
					console.error("Error: --max-chars must be a positive integer");
					process.exit(1);
				}
				if (maxCharacters !== undefined && maxCharacters > 100_000) {
					console.error("Error: --max-chars cannot exceed 100000");
					process.exit(1);
				}
				if (timeoutMs !== undefined && (!Number.isFinite(timeoutMs) || timeoutMs < 1)) {
					console.error("Error: --timeout must be a positive integer");
					process.exit(1);
				}
				if (timeoutMs !== undefined && timeoutMs > 120_000) {
					console.error("Error: --timeout cannot exceed 120000 (2 minutes)");
					process.exit(1);
				}

				const result = await summarizeUrl(url, {
					maxCharacters,
					timeoutMs,
					format,
					userId,
				});

				// Output in a structured format for easy parsing
				if (result.title) {
					console.log(`Title: ${result.title}`);
				}
				if (result.siteName) {
					console.log(`Site: ${result.siteName}`);
				}
				console.log(`Words: ${result.wordCount}`);
				if (result.transcriptSource) {
					console.log(`Transcript: ${result.transcriptSource}`);
				}
				if (result.truncated) {
					console.log("Note: Content was truncated to fit character limit");
				}
				console.log("---");
				console.log(result.content);
			} catch (err) {
				logger.error({ error: String(err) }, "summarize command failed");
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exit(1);
			}
		});
}
