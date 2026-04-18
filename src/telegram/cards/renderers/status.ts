import { collectCronOverview, formatCronOverview } from "../../../commands/cron.js";
import { collectSessionRows, formatSessionRows } from "../../../commands/sessions.js";
import { collectTelclaudeStatus, formatTelclaudeStatus } from "../../../commands/status.js";
import { deleteSession } from "../../../config/sessions.js";
import { getSessionManager } from "../../../sdk/session-manager.js";
import { revokeSessionAllowlist } from "../../../security/approvals.js";
import { collectStatusOverview } from "../../status-overview.js";
import type {
	CardExecutionContext,
	CardExecutionResult,
	CardInstance,
	CardKind,
	CardRenderer,
	CardRenderResult,
	StatusCardAction,
	StatusCardState,
} from "../types.js";
import { btn, esc, formatAge, keyboard, renderTerminalState } from "./helpers.js";

type K = typeof CardKind.Status;

function renderOverviewView(card: CardInstance<K>, s: StatusCardState): CardRenderResult {
	let text = `\uD83D\uDCCA *${esc(s.title)}*\n\n${esc(s.summary)}`;

	if (s.details && s.details.length > 0) {
		text += "\n";
		for (const detail of s.details) {
			text += `\n\u2022 ${esc(detail)}`;
		}
	}

	if (s.lastRefreshedAt) {
		text += `\n\n_Updated ${esc(formatAge(s.lastRefreshedAt))}_`;
	}

	const kb = keyboard()
		.text("\uD83D\uDCCB Sessions", btn(card, "view-sessions"))
		.text("\u23F0 Cron Jobs", btn(card, "view-cron"))
		.row()
		.text("\uD83D\uDD04 Refresh", btn(card, "refresh"))
		.row()
		.text("\uD83E\uDE7A Health Check", btn(card, "run-health-check"))
		.text("\uD83D\uDD04 Reset", btn(card, "reset-session"));

	return { text, parseMode: "MarkdownV2", keyboard: kb };
}

function renderSessionsView(card: CardInstance<K>, s: StatusCardState): CardRenderResult {
	let text = `\uD83D\uDCCB *${esc("Sessions")}*\n\n${esc(s.summary)}`;

	if (s.details && s.details.length > 0) {
		text += "\n";
		for (const detail of s.details) {
			text += `\n\u2022 ${esc(detail)}`;
		}
	}

	if (s.lastRefreshedAt) {
		text += `\n\n_Updated ${esc(formatAge(s.lastRefreshedAt))}_`;
	}

	const kb = keyboard()
		.text("\u25C0 Back", btn(card, "view-overview"))
		.text("\uD83D\uDD04 Refresh", btn(card, "refresh"));

	return { text, parseMode: "MarkdownV2", keyboard: kb };
}

function renderCronView(card: CardInstance<K>, s: StatusCardState): CardRenderResult {
	let text = `\u23F0 *${esc("Cron Jobs")}*\n\n${esc(s.summary)}`;

	if (s.details && s.details.length > 0) {
		text += "\n";
		for (const detail of s.details) {
			text += `\n\u2022 ${esc(detail)}`;
		}
	}

	if (s.lastRefreshedAt) {
		text += `\n\n_Updated ${esc(formatAge(s.lastRefreshedAt))}_`;
	}

	const kb = keyboard()
		.text("\u25C0 Back", btn(card, "view-overview"))
		.text("\uD83D\uDD04 Refresh", btn(card, "refresh"));

	return { text, parseMode: "MarkdownV2", keyboard: kb };
}

function buildSessionsViewState(base: StatusCardState): StatusCardState {
	const limit = 8;
	const rows = collectSessionRows({ limit });
	const formatted = formatSessionRows(rows, { limit });
	const lines = formatted.split("\n");
	const summaryLine = lines[0] ?? "Sessions";
	const details = lines.slice(1).filter((line) => line.trim().length > 0);

	return {
		...base,
		view: "sessions",
		summary: summaryLine,
		details,
		lastRefreshedAt: Date.now(),
	};
}

function buildCronViewState(base: StatusCardState): StatusCardState {
	const overview = collectCronOverview({ includeDisabled: true, limit: 8 });
	const formatted = formatCronOverview(overview);
	const lines = formatted.split("\n");
	const summaryLine = lines[0] ?? "Cron scheduler";
	const details = lines.slice(1).filter((line) => line.trim().length > 0);

	return {
		...base,
		view: "cron",
		summary: summaryLine,
		details,
		lastRefreshedAt: Date.now(),
	};
}

async function buildOverviewState(base: StatusCardState): Promise<StatusCardState> {
	const status = await collectTelclaudeStatus();
	const formatted = formatTelclaudeStatus(status, true);
	const lines = formatted.split("\n");
	// Skip the "=== Telclaude Status ===" header and empty lines
	const details = lines.slice(1).filter((line) => line.trim().length > 0);

	return {
		...base,
		view: "overview",
		title: "System Status",
		summary: "System overview ready.",
		details,
		lastRefreshedAt: Date.now(),
	};
}

export const statusRenderer: CardRenderer<K> = {
	render(card: CardInstance<K>): CardRenderResult {
		const s = card.state;

		const terminal = renderTerminalState(card, s.title);
		if (terminal) return terminal;

		const view = s.view ?? "overview";
		switch (view) {
			case "sessions":
				return renderSessionsView(card, s);
			case "cron":
				return renderCronView(card, s);
			default:
				return renderOverviewView(card, s);
		}
	},

	reduce(card: CardInstance<K>, action: StatusCardAction): StatusCardState {
		const s = { ...card.state };
		switch (action.type) {
			case "refresh":
				return { ...s, lastRefreshedAt: Date.now() };
			case "run-health-check":
				return s;
			case "reset-session":
				return s;
			case "view-sessions":
				return buildSessionsViewState(s);
			case "view-cron":
				return buildCronViewState(s);
			case "view-overview":
				return { ...s, view: "overview" };
		}
	},

	async execute(context: CardExecutionContext<K>): Promise<CardExecutionResult<K>> {
		const { action, card } = context;

		switch (action.type) {
			case "refresh": {
				const view = card.state.view ?? "overview";
				if (view === "sessions") {
					return {
						state: buildSessionsViewState(card.state),
						callbackText: "Sessions refreshed",
						rerender: true,
					};
				}
				if (view === "cron") {
					return {
						state: buildCronViewState(card.state),
						callbackText: "Cron jobs refreshed",
						rerender: true,
					};
				}
				// overview refresh
				const overviewState = await buildOverviewState(card.state);
				return {
					state: overviewState,
					callbackText: "Status refreshed",
					rerender: true,
				};
			}

			case "run-health-check": {
				const overview = await collectStatusOverview({ includeProviderHealth: true });
				return {
					state: {
						...card.state,
						view: "overview",
						summary: overview.summary,
						details: overview.details,
						lastRefreshedAt: Date.now(),
					},
					callbackText:
						overview.providerIssues.length === 0
							? "Health check passed"
							: `Health check found ${overview.providerIssues.length} issue(s)`,
					rerender: true,
				};
			}

			case "reset-session": {
				const sessionKey = card.state.sessionKey;
				if (!sessionKey) {
					return { callbackText: "No session to reset", callbackAlert: true };
				}
				deleteSession(sessionKey);
				getSessionManager().clearSession(sessionKey);
				// W1 — drop session-scoped approval grants alongside the session.
				revokeSessionAllowlist(sessionKey);
				return {
					callbackText: "Session reset",
				};
			}

			case "view-sessions": {
				return {
					state: buildSessionsViewState(card.state),
					callbackText: "Viewing sessions",
					rerender: true,
				};
			}

			case "view-cron": {
				return {
					state: buildCronViewState(card.state),
					callbackText: "Viewing cron jobs",
					rerender: true,
				};
			}

			case "view-overview": {
				const overviewState = await buildOverviewState(card.state);
				return {
					state: overviewState,
					callbackText: "Back to overview",
					rerender: true,
				};
			}
		}
	},
};
