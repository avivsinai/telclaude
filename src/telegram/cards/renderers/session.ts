import type {
	CardExecutionContext,
	CardExecutionResult,
	CardInstance,
	CardKind,
	CardRenderer,
	CardRenderResult,
	SessionCardAction,
	SessionCardState,
} from "../types.js";
import { btn, esc, keyboard, renderTerminalState } from "./helpers.js";

type K = typeof CardKind.Session;

function formatAge(ts: number): string {
	const seconds = Math.floor((Date.now() - ts) / 1000);
	if (seconds < 60) return `${seconds}s ago`;
	const minutes = Math.floor(seconds / 60);
	if (minutes < 60) return `${minutes}m ago`;
	const hours = Math.floor(minutes / 60);
	if (hours < 24) return `${hours}h ago`;
	const days = Math.floor(hours / 24);
	return `${days}d ago`;
}

export const sessionRenderer: CardRenderer<K> = {
	render(card: CardInstance<K>): CardRenderResult {
		const s = card.state;

		const terminal = renderTerminalState(card, s.title);
		if (terminal) return terminal;

		let text = `\uD83D\uDCE1 *${esc(s.title)}*\n\n${esc(s.summary)}`;

		if (s.sessionKey) {
			text += `\n\n\uD83D\uDD11 Key: \`${esc(s.sessionKey)}\``;
		}

		if (s.historyPreview && s.historyPreview.length > 0) {
			text += "\n\n*Recent history:*";
			for (const entry of s.historyPreview.slice(0, 5)) {
				text += `\n\u2022 ${esc(entry)}`;
			}
		}

		text += `\n\n_Created ${esc(formatAge(card.createdAt))}_`;

		const kb = keyboard()
			.text("\uD83D\uDD04 Reset", btn(card, "reset"))
			.text("\uD83D\uDCDC History", btn(card, "view-history"))
			.row()
			.text("\u21BB Refresh", btn(card, "refresh"));

		return { text, parseMode: "MarkdownV2", keyboard: kb };
	},

	reduce(card: CardInstance<K>, action: SessionCardAction): SessionCardState {
		const s = { ...card.state };
		switch (action.type) {
			case "reset":
				return { ...s, sessionKey: undefined, historyPreview: undefined };
			case "view-history":
				return s;
			case "refresh":
				return s;
		}
	},

	async execute(context: CardExecutionContext<K>): Promise<CardExecutionResult<K>> {
		const { action, card } = context;

		switch (action.type) {
			case "reset":
				// TODO: delete the SDK session (call deleteSession + sessionManager.clearSession)
				return {
					state: {
						...card.state,
						summary: "Session cleared",
						sessionKey: undefined,
						historyPreview: undefined,
					},
					status: "consumed",
					callbackText: "Session reset",
					rerender: true,
				};

			case "view-history":
				// TODO: fetch recent message history for this session
				return {
					state: {
						...card.state,
						historyPreview: ["(History loading not yet implemented)"],
					},
					callbackText: "History loaded",
					rerender: true,
				};

			case "refresh":
				// TODO: re-fetch session metadata
				return {
					callbackText: "Refreshed",
					rerender: true,
				};
		}
	},
};
