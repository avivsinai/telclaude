/**
 * Graduated approval allowlist CLI (Workstream W1).
 *
 * Commands:
 *   telclaude approvals list [--user <id>] [--json]
 *   telclaude approvals revoke <id>
 *
 * The allowlist lets operators audit which (user, tool) pairs have been
 * granted a "once"/"session"/"always" approval, and revoke them by id.
 */

import type { Command } from "commander";
import { getChildLogger } from "../logging.js";
import { type AllowlistEntry, listAllowlist, revokeAllowlistEntry } from "../security/approvals.js";

const logger = getChildLogger({ module: "cmd-approvals" });

function formatTimestamp(ts: number | null | undefined): string {
	if (!ts) return "-";
	return new Date(ts).toISOString().replace("T", " ").slice(0, 19);
}

function pad(value: string, width: number): string {
	if (value.length >= width) return value;
	return `${value}${" ".repeat(width - value.length)}`;
}

function truncate(value: string, max: number): string {
	if (value.length <= max) return value;
	const keep = Math.max(4, max - 3);
	return `${value.slice(0, keep)}...`;
}

function renderTable(entries: AllowlistEntry[]): string {
	if (entries.length === 0) return "No allowlist entries.";

	const header = [
		pad("ID", 6),
		pad("User", 14),
		pad("Tier", 11),
		pad("Tool", 24),
		pad("Scope", 8),
		pad("Granted", 19),
		pad("Expires", 19),
		"Last used",
	].join(" ");

	const lines = [header];
	for (const entry of entries) {
		lines.push(
			[
				pad(String(entry.id), 6),
				pad(truncate(entry.userId, 14), 14),
				pad(entry.tier, 11),
				pad(truncate(entry.toolKey, 24), 24),
				pad(entry.scope, 8),
				pad(formatTimestamp(entry.grantedAt), 19),
				pad(formatTimestamp(entry.expiresAt), 19),
				formatTimestamp(entry.lastUsedAt),
			].join(" "),
		);
	}
	return lines.join("\n");
}

export function registerApprovalsCommand(program: Command): void {
	const approvals = program
		.command("approvals")
		.description("Inspect and manage the graduated approval allowlist");

	approvals
		.command("list")
		.description("List approval allowlist entries (granted scopes per user+tool)")
		.option("--user <id>", "Filter to a specific user id")
		.option("--json", "Output as JSON")
		.action((opts: { user?: string; json?: boolean }) => {
			try {
				const entries = listAllowlist({ userId: opts.user });
				if (opts.json) {
					console.log(
						JSON.stringify(
							{
								count: entries.length,
								entries: entries.map((e) => ({
									id: e.id,
									userId: e.userId,
									tier: e.tier,
									toolKey: e.toolKey,
									scope: e.scope,
									sessionKey: e.sessionKey,
									chatId: e.chatId,
									grantedAt: e.grantedAt,
									expiresAt: e.expiresAt,
									lastUsedAt: e.lastUsedAt,
								})),
							},
							null,
							2,
						),
					);
					return;
				}
				console.log(`Allowlist entries: ${entries.length}`);
				if (opts.user) {
					console.log(`Filtered to user ${opts.user}`);
				}
				console.log("");
				console.log(renderTable(entries));
			} catch (err) {
				logger.error({ err: String(err) }, "approvals list failed");
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exitCode = 1;
			}
		});

	approvals
		.command("revoke <id>")
		.description("Revoke a single allowlist entry by id")
		.action((idRaw: string) => {
			try {
				const id = Number.parseInt(idRaw, 10);
				if (!Number.isFinite(id) || id <= 0) {
					console.error(`Error: id must be a positive integer, got "${idRaw}"`);
					process.exitCode = 1;
					return;
				}
				const removed = revokeAllowlistEntry(id);
				if (removed) {
					console.log(`Revoked allowlist entry ${id}.`);
				} else {
					console.error(`No allowlist entry found with id ${id}.`);
					process.exitCode = 1;
				}
			} catch (err) {
				logger.error({ err: String(err) }, "approvals revoke failed");
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exitCode = 1;
			}
		});
}
