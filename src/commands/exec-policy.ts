/**
 * Workstream W8 — Exec-policy CLI.
 *
 * Per-chat glob allowlists persisted at ~/.telclaude/exec-policy.json.
 * Pair with the safe-bin catalog in src/security/exec-policy.ts: the
 * catalog covers read-only stdin commands without explicit config, and
 * the CLI lets operators add broader globs when they want "always"
 * behaviour for a particular chat.
 *
 *   telclaude exec-policy list   [--chat <id>] [--json]
 *   telclaude exec-policy add    [--chat <id>] --glob <pattern>
 *   telclaude exec-policy revoke [--chat <id>] [--glob <pattern>]
 */

import type { Command } from "commander";
import { getChildLogger } from "../logging.js";
import {
	addExecPolicyGlob,
	listExecPolicy,
	resolveExecPolicyPath,
	revokeExecPolicyGlob,
	SAFE_BINS,
} from "../security/exec-policy.js";

const logger = getChildLogger({ module: "cmd-exec-policy" });

function resolveChatId(explicit: string | undefined): string {
	const raw = (explicit ?? process.env.TELCLAUDE_CHAT_ID ?? "").trim();
	if (!raw) {
		throw new Error("Chat ID is required. Pass --chat <id> or set TELCLAUDE_CHAT_ID.");
	}
	return raw;
}

function pad(value: string, width: number): string {
	if (value.length >= width) return value;
	return `${value}${" ".repeat(width - value.length)}`;
}

export function registerExecPolicyCommand(program: Command): void {
	const cmd = program
		.command("exec-policy")
		.description("Manage per-chat Bash execution allowlists (safe-bin catalog is always on)");

	cmd
		.command("list")
		.description("List allowlist globs per chat")
		.option("--chat <id>", "Filter to a single chat id")
		.option("--json", "Output as JSON")
		.action((opts: { chat?: string; json?: boolean }) => {
			try {
				const entries = listExecPolicy(opts.chat ? { chatId: opts.chat.trim() } : {});
				if (opts.json) {
					console.log(
						JSON.stringify(
							{
								path: resolveExecPolicyPath(),
								safeBins: SAFE_BINS,
								chats: entries,
							},
							null,
							2,
						),
					);
					return;
				}

				console.log(`Exec-policy file: ${resolveExecPolicyPath()}`);
				console.log(`Safe bins (stdin-only auto-allow): ${SAFE_BINS.join(", ")}`);
				console.log("");
				if (entries.length === 0) {
					console.log("No per-chat globs configured.");
					return;
				}
				console.log(`${pad("Chat", 16)} Glob`);
				for (const entry of entries) {
					for (const glob of entry.globs) {
						console.log(`${pad(entry.chatId, 16)} ${glob}`);
					}
				}
			} catch (err) {
				logger.error({ err: String(err) }, "exec-policy list failed");
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exitCode = 1;
			}
		});

	cmd
		.command("add")
		.description("Add a glob pattern to a chat's Bash allowlist")
		.option("--chat <id>", "Chat id (defaults to TELCLAUDE_CHAT_ID)")
		.requiredOption("--glob <pattern>", 'Glob pattern to allow (e.g. "npm test*")')
		.action((opts: { chat?: string; glob: string }) => {
			try {
				const chatId = resolveChatId(opts.chat);
				const added = addExecPolicyGlob(chatId, opts.glob);
				if (added) {
					console.log(`Added glob "${opts.glob}" for chat ${chatId}.`);
				} else {
					console.log(`Glob "${opts.glob}" already present for chat ${chatId}.`);
				}
			} catch (err) {
				logger.error({ err: String(err) }, "exec-policy add failed");
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exitCode = 1;
			}
		});

	cmd
		.command("revoke")
		.description("Remove a glob (or clear all globs for a chat when --glob is omitted)")
		.option("--chat <id>", "Chat id (defaults to TELCLAUDE_CHAT_ID)")
		.option("--glob <pattern>", "Glob pattern to remove. If omitted, clears the chat.")
		.action((opts: { chat?: string; glob?: string }) => {
			try {
				const chatId = resolveChatId(opts.chat);
				const removed = revokeExecPolicyGlob(chatId, opts.glob);
				if (removed === 0) {
					if (opts.glob) {
						console.log(`No glob "${opts.glob}" found for chat ${chatId}.`);
					} else {
						console.log(`No entries for chat ${chatId}.`);
					}
					process.exitCode = 1;
					return;
				}
				if (opts.glob) {
					console.log(`Revoked glob "${opts.glob}" for chat ${chatId}.`);
				} else {
					console.log(`Cleared ${removed} glob(s) for chat ${chatId}.`);
				}
			} catch (err) {
				logger.error({ err: String(err) }, "exec-policy revoke failed");
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exitCode = 1;
			}
		});
}
