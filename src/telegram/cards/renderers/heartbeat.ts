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
import { btn, esc, keyboard, renderTerminalState } from "./helpers.js";

type K = typeof CardKind.Heartbeat;

function formatAge(ts: number): string {
	const seconds = Math.floor((Date.now() - ts) / 1000);
	if (seconds < 60) return `${seconds}s ago`;
	const minutes = Math.floor(seconds / 60);
	if (minutes < 60) return `${minutes}m ago`;
	const hours = Math.floor(minutes / 60);
	return `${hours}h ago`;
}

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

		const kb = keyboard();

		// Per-service run buttons (compact, 2 per row)
		for (let i = 0; i < s.services.length; i++) {
			const svc = s.services[i];
			kb.text(`\u25B6 ${svc.label}`, btn(card, "run-service"));
			if (i % 2 === 1 || i === s.services.length - 1) {
				kb.row();
			}
		}

		kb.text("\uD83D\uDE80 Run All", btn(card, "run-all"))
			.text("\uD83D\uDCDC View Log", btn(card, "view-log"))
			.row()
			.text("\uD83D\uDD04 Refresh", btn(card, "refresh"));

		return { text, parseMode: "MarkdownV2", keyboard: kb };
	},

	reduce(card: CardInstance<K>, action: HeartbeatCardAction): HeartbeatCardState {
		const s = { ...card.state };
		switch (action.type) {
			case "run-service":
				// In a full implementation, selectedServiceId would be passed via action payload.
				// With the current flat action types, select the first service as default.
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
			case "run-service": {
				const serviceId = card.state.selectedServiceId ?? card.state.services[0]?.id;
				if (!serviceId) {
					return { callbackText: "No service selected", callbackAlert: true };
				}
				// TODO: trigger heartbeat for specific service via relay
				return {
					state: { ...card.state, lastRunAt: Date.now() },
					callbackText: `Heartbeat triggered for ${serviceId}`,
					rerender: true,
				};
			}

			case "run-all":
				// TODO: trigger heartbeat for all services via relay
				return {
					state: { ...card.state, lastRunAt: Date.now(), selectedServiceId: undefined },
					callbackText: "All heartbeats triggered",
					rerender: true,
				};

			case "view-log":
				// TODO: fetch recent heartbeat log and display
				return {
					callbackText: "Use /public-log for heartbeat history",
					callbackAlert: true,
				};

			case "refresh":
				// TODO: re-fetch service statuses
				return {
					callbackText: "Refreshed",
					rerender: true,
				};
		}
	},
};
