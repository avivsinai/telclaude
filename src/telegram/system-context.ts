/**
 * Lightweight system context for agent awareness.
 *
 * Injected into the agent's system prompt so it can answer natural questions
 * like "what's my system status?" without relay-side NL classification.
 * Kept small to avoid bloating the context window.
 */

import { getAllSessions } from "../config/sessions.js";
import { getCronStatusSummary } from "../cron/store.js";
import { getIdentityLink, isAdmin } from "../security/linking.js";

const RELAY_STARTED_AT = Date.now();

/**
 * Build a compact system-info block for the agent's system prompt.
 *
 * Returns an XML-tagged string or null if nothing useful to report.
 * Called per-request — must be fast (no shell commands, no config reload).
 *
 * Global ops data (sessions, cron) is only included for admin chats
 * to avoid leaking system state to non-admin users.
 */
export function buildSystemInfoContext(chatId: number): string | null {
	const lines: string[] = [];
	const admin = isAdmin(chatId);

	try {
		// Identity (per-chat, always safe)
		const link = getIdentityLink(chatId);
		lines.push(link ? `identity: ${link.localUserId} (linked)` : "identity: not linked");

		// Uptime (non-sensitive)
		const uptimeMs = Date.now() - RELAY_STARTED_AT;
		const uptimeMin = Math.floor(uptimeMs / 60_000);
		if (uptimeMin < 60) {
			lines.push(`relay uptime: ${uptimeMin}m`);
		} else {
			const hours = Math.floor(uptimeMin / 60);
			const mins = uptimeMin % 60;
			lines.push(`relay uptime: ${hours}h ${mins}m`);
		}

		// Global ops data — admin only
		if (admin) {
			// Active sessions
			try {
				const sessions = getAllSessions();
				lines.push(`active sessions: ${Object.keys(sessions).length}`);
			} catch {
				// session store may not be initialized
			}

			// Cron
			try {
				const cron = getCronStatusSummary();
				if (cron.totalJobs > 0) {
					const parts = [`${cron.enabledJobs}/${cron.totalJobs} enabled`];
					if (cron.runningJobs > 0) parts.push(`${cron.runningJobs} running`);
					if (cron.nextRunAtMs) {
						const deltaMin = Math.max(0, Math.round((cron.nextRunAtMs - Date.now()) / 60_000));
						parts.push(`next in ${deltaMin}m`);
					}
					lines.push(`cron: ${parts.join(", ")}`);
				}
			} catch {
				// cron store may not be initialized
			}
		}
	} catch {
		// Best-effort — don't break message processing for system info
		return null;
	}

	return [
		"<system-info>",
		"The control plane uses /commands and inline buttons only.",
		"Anything not starting with / is addressed to you (the agent).",
		"You can reference the info below to answer system questions naturally.",
		"",
		...lines,
		"</system-info>",
	].join("\n");
}
