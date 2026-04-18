import { deleteSession, getSession } from "../../../config/sessions.js";
import { getSessionManager } from "../../../sdk/session-manager.js";
import { revokeSessionAllowlist } from "../../../security/approvals.js";
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
import { btn, esc, formatAge, keyboard, renderTerminalState } from "./helpers.js";

type K = typeof CardKind.Session;

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
			case "reset": {
				const sessionKey = card.state.sessionKey;
				if (sessionKey) {
					deleteSession(sessionKey);
					getSessionManager().clearSession(sessionKey);
					// W1 — session-scoped approvals must not outlive the session.
					revokeSessionAllowlist(sessionKey);
				}
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
			}

			case "view-history": {
				const sessionKey = card.state.sessionKey;
				if (!sessionKey) {
					return {
						state: { ...card.state, historyPreview: ["No active session"] },
						callbackText: "No session",
						rerender: true,
					};
				}
				const session = getSession(sessionKey);
				if (!session) {
					return {
						state: { ...card.state, historyPreview: ["Session not found"] },
						callbackText: "Session not found",
						rerender: true,
					};
				}
				const preview = [
					`Session ID: ${session.sessionId.slice(0, 8)}...`,
					`Last active: ${formatAge(session.updatedAt)}`,
					`System prompt sent: ${session.systemSent ? "yes" : "no"}`,
				];
				return {
					state: { ...card.state, historyPreview: preview },
					callbackText: "History loaded",
					rerender: true,
				};
			}

			case "refresh": {
				const sessionKey = card.state.sessionKey;
				if (!sessionKey) {
					return { callbackText: "No session key", rerender: true };
				}
				const session = getSession(sessionKey);
				const summary = session
					? `Active session (last used ${formatAge(session.updatedAt)})`
					: "No active session";
				return {
					state: { ...card.state, summary },
					callbackText: "Refreshed",
					rerender: true,
				};
			}
		}
	},
};
