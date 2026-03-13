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
import { btn, esc, keyboard, renderTerminalState } from "./helpers.js";

type K = typeof CardKind.Status;

function formatAge(ts: number): string {
	const seconds = Math.floor((Date.now() - ts) / 1000);
	if (seconds < 60) return `${seconds}s ago`;
	const minutes = Math.floor(seconds / 60);
	if (minutes < 60) return `${minutes}m ago`;
	const hours = Math.floor(minutes / 60);
	return `${hours}h ago`;
}

export const statusRenderer: CardRenderer<K> = {
	render(card: CardInstance<K>): CardRenderResult {
		const s = card.state;

		const terminal = renderTerminalState(card, s.title);
		if (terminal) return terminal;

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
			.text("\uD83D\uDD04 Refresh", btn(card, "refresh"))
			.row()
			.text("\uD83E\uDE7A Run Health Check", btn(card, "run-health-check"))
			.text("\uD83D\uDD04 Reset Session", btn(card, "reset-session"));

		return { text, parseMode: "MarkdownV2", keyboard: kb };
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
		}
	},

	async execute(context: CardExecutionContext<K>): Promise<CardExecutionResult<K>> {
		const { action, card } = context;

		switch (action.type) {
			case "refresh":
				return {
					state: { ...card.state, lastRefreshedAt: Date.now() },
					callbackText: "Status refreshed",
					rerender: true,
				};

			case "run-health-check": {
				const overview = await collectStatusOverview({ includeProviderHealth: true });
				return {
					state: {
						...card.state,
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

			case "reset-session":
				// TODO: clear current SDK session (similar to keyboard-handlers handleNewSession)
				return {
					callbackText: "Session reset",
				};
		}
	},
};
