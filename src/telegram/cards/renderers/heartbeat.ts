import type {
	CardExecutionContext,
	CardExecutionResult,
	CardInstance,
	CardKind,
	CardRenderer,
	CardRenderResult,
	HeartbeatCardAction,
	HeartbeatCardState,
} from "../types.js";
import { btn, esc, formatAge, keyboard, renderTerminalState } from "./helpers.js";

type K = typeof CardKind.Heartbeat;

export const heartbeatRenderer: CardRenderer<K> = {
	render(card: CardInstance<K>): CardRenderResult {
		const s = card.state;

		const terminal = renderTerminalState(card, s.title);
		if (terminal) return terminal;

		let text = `\uD83D\uDC93 *${esc(s.title)}*\n`;

		if (s.services.length === 0) {
			text += "\n_No social services configured_";
		} else {
			for (const svc of s.services) {
				const statusIcon = svc.summary?.includes("error")
					? "\uD83D\uDD34"
					: svc.summary?.includes("ok")
						? "\uD83D\uDFE2"
						: "\u26AA";
				text += `\n${statusIcon} *${esc(svc.label)}*`;
				if (svc.summary) {
					text += ` \\- ${esc(svc.summary)}`;
				}
			}
		}

		if (s.lastRunAt) {
			text += `\n\n_Last run: ${esc(formatAge(s.lastRunAt))}_`;
		}

		const kb = keyboard()
			.text("\uD83D\uDCDC View Log", btn(card, "view-log"))
			.row()
			.text("\uD83D\uDD04 Refresh", btn(card, "refresh"));

		return { text, parseMode: "MarkdownV2", keyboard: kb };
	},

	reduce(card: CardInstance<K>, action: HeartbeatCardAction): HeartbeatCardState {
		const s = { ...card.state };
		switch (action.type) {
			case "run-service":
				return { ...s, selectedServiceId: s.services[0]?.id };
			case "run-all":
				return { ...s, selectedServiceId: undefined };
			case "view-log":
				return s;
			case "refresh":
				return s;
		}
	},

	async execute(context: CardExecutionContext<K>): Promise<CardExecutionResult<K>> {
		const { action, card } = context;

		switch (action.type) {
			case "run-service":
				return {
					callbackText: "Use /social run <service> to trigger a heartbeat",
					callbackAlert: true,
				};

			case "run-all":
				return {
					callbackText: "Use /social run to trigger all heartbeats",
					callbackAlert: true,
				};

			case "view-log":
				return {
					callbackText: "Use /social log to view heartbeat history",
					callbackAlert: true,
				};

			case "refresh":
				return {
					state: { ...card.state, lastRunAt: card.state.lastRunAt },
					callbackText: "Refreshed",
					rerender: true,
				};
		}
	},
};
