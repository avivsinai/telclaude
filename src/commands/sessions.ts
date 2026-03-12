import type { Command } from "commander";
import { getAllSessions, type SessionEntry } from "../config/sessions.js";
import { formatDuration } from "./cli-utils.js";

export type SessionListRow = {
	key: string;
	kind: "direct" | "group" | "global" | "unknown";
	sessionId: string;
	updatedAt: number;
	ageMs: number;
	systemSent: boolean;
};

function classifySessionKey(key: string): SessionListRow["kind"] {
	if (key === "global") {
		return "global";
	}
	if (key.startsWith("tg:-") || key.startsWith("-")) {
		return "group";
	}
	if (key.startsWith("tg:")) {
		return "direct";
	}
	return "unknown";
}

function toRows(store: Record<string, SessionEntry>): SessionListRow[] {
	const now = Date.now();
	return Object.entries(store)
		.map(([key, entry]) => ({
			key,
			kind: classifySessionKey(key),
			sessionId: entry.sessionId,
			updatedAt: entry.updatedAt,
			ageMs: Math.max(0, now - entry.updatedAt),
			systemSent: entry.systemSent === true,
		}))
		.sort((a, b) => b.updatedAt - a.updatedAt);
}

function pad(value: string, width: number): string {
	if (value.length >= width) {
		return value;
	}
	return `${value}${" ".repeat(width - value.length)}`;
}

function truncate(value: string, max: number): string {
	if (value.length <= max) {
		return value;
	}
	const keep = Math.max(4, max - 3);
	return `${value.slice(0, keep)}...`;
}

function parsePositiveIntegerOption(name: string, value: string | undefined): number | undefined {
	if (value === undefined) {
		return undefined;
	}
	const parsed = Number.parseInt(value, 10);
	if (!Number.isFinite(parsed) || parsed <= 0) {
		throw new Error(`${name} must be a positive integer`);
	}
	return parsed;
}

export function collectSessionRows(options?: {
	activeMinutes?: number;
	limit?: number;
}): SessionListRow[] {
	const activeMinutes = options?.activeMinutes;
	const limit = options?.limit;
	const rows = toRows(getAllSessions()).filter((row) => {
		if (!activeMinutes) {
			return true;
		}
		return row.ageMs <= activeMinutes * 60_000;
	});
	if (!limit) {
		return rows;
	}
	return rows.slice(0, limit);
}

export function formatSessionRows(
	rows: SessionListRow[],
	options?: {
		activeMinutes?: number;
		limit?: number;
	},
): string {
	const lines = [`Sessions: ${rows.length}`];
	if (options?.activeMinutes) {
		lines.push(`Filtered to the last ${options.activeMinutes} minute(s).`);
	}
	if (options?.limit) {
		lines.push(`Showing up to ${options.limit} most recent session(s).`);
	}
	if (rows.length === 0) {
		lines.push("No sessions found.");
		return lines.join("\n");
	}

	lines.push("");
	for (const row of rows) {
		const flags = [row.systemSent ? "system prompt sent" : null].filter(Boolean).join(", ");
		const suffix = flags ? ` (${flags})` : "";
		lines.push(`- ${row.kind} ${row.key} updated ${formatDuration(row.ageMs)} ago${suffix}`);
	}

	return lines.join("\n");
}

export function registerSessionsCommand(program: Command): void {
	program
		.command("sessions")
		.description("Inspect local session state (SQLite-backed)")
		.option("--json", "Output as JSON")
		.option("--active <minutes>", "Only include sessions active in the last N minutes")
		.option("--limit <n>", "Maximum number of sessions to show", "50")
		.action((opts: { json?: boolean; active?: string; limit?: string }) => {
			try {
				const activeMinutes = parsePositiveIntegerOption("--active", opts.active);
				const limit = parsePositiveIntegerOption("--limit", opts.limit);
				const rows = collectSessionRows({ activeMinutes, limit });

				if (opts.json) {
					console.log(
						JSON.stringify(
							{
								count: rows.length,
								activeMinutes: activeMinutes ?? null,
								sessions: rows,
							},
							null,
							2,
						),
					);
					return;
				}

				console.log(`Sessions listed: ${rows.length}`);
				if (activeMinutes) {
					console.log(`Filtered to last ${activeMinutes} minute(s)`);
				}
				if (rows.length === 0) {
					console.log("No sessions found.");
					return;
				}

				const header = [
					pad("Kind", 7),
					pad("Key", 20),
					pad("Age", 8),
					pad("Session", 14),
					"Flags",
				].join(" ");
				console.log(header);
				for (const row of rows) {
					const flags = [row.systemSent ? "system" : null].filter(Boolean).join(" ");
					console.log(
						[
							pad(row.kind, 7),
							pad(truncate(row.key, 20), 20),
							pad(formatDuration(row.ageMs), 8),
							pad(truncate(row.sessionId, 14), 14),
							flags,
						]
							.join(" ")
							.trimEnd(),
					);
				}
			} catch (err) {
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exitCode = 1;
			}
		});
}
