import {
	openSocialQueueCard,
	runSocialHeartbeatCommand,
	sendSocialActivityLogCommand,
	startSocialAskWizard,
} from "../../control-command-actions.js";
import { buildSocialMenuState } from "../menu-state.js";
import type {
	CardExecutionContext,
	CardExecutionResult,
	CardInstance,
	CardKind,
	CardRenderer,
	CardRenderResult,
	SocialMenuCardAction,
	SocialMenuCardState,
} from "../types.js";
import { btn, esc, formatAge, keyboard, renderTerminalState } from "./helpers.js";

type K = typeof CardKind.SocialMenu;

export const socialMenuRenderer: CardRenderer<K> = {
	render(card: CardInstance<K>): CardRenderResult {
		const s = card.state;

		const terminal = renderTerminalState(card, s.title);
		if (terminal) return terminal;

		let text = `🌐 *${esc(s.title)}*\n\n`;
		if (s.services.length === 0) {
			text += esc("No social services configured");
		} else {
			text += `${esc(`${s.services.length} enabled service(s)`)}:`;
			for (const service of s.services) {
				text += `\n• ${esc(service.label)}`;
			}
		}

		if (s.adminControlsEnabled && s.queueCount !== undefined) {
			text += `\n\n${esc(`${s.queueCount} pending post(s) in queue`)}`;
		}

		if (s.lastRefreshedAt) {
			text += `\n\n_Updated ${esc(formatAge(s.lastRefreshedAt))}_`;
		}

		const kb = keyboard();
		if (s.adminControlsEnabled) {
			kb.text("📥 Queue", btn(card, "queue"))
				.text("🚀 Promote", btn(card, "promote"))
				.row()
				.text("💓 Run Now", btn(card, "run"))
				.text("📜 View Log", btn(card, "log"))
				.row()
				.text("💬 Ask", btn(card, "ask"));
		}
		kb.text("↻ Refresh", btn(card, "refresh"));

		return { text, parseMode: "MarkdownV2", keyboard: kb };
	},

	reduce(card: CardInstance<K>, _action: SocialMenuCardAction): SocialMenuCardState {
		return card.state;
	},

	async execute(context: CardExecutionContext<K>): Promise<CardExecutionResult<K>> {
		const { action, card } = context;

		switch (action.type) {
			case "queue":
			case "promote": {
				const result = await openSocialQueueCard(context.ctx.api, {
					chatId: card.chatId,
					actorScope: card.actorScope,
					threadId: card.threadId,
				});
				return {
					callbackText:
						action.type === "promote" && result.callbackText === "Opened pending queue"
							? "Open the queue to promote a post"
							: result.callbackText,
					callbackAlert: result.callbackAlert,
				};
			}

			case "run": {
				const result = await runSocialHeartbeatCommand(context.ctx.api, {
					chatId: card.chatId,
					threadId: card.threadId,
				});
				return {
					state: buildSocialMenuState(card.chatId),
					callbackText: result.callbackText,
					callbackAlert: result.callbackAlert,
					rerender: true,
				};
			}

			case "log": {
				const result = await sendSocialActivityLogCommand(context.ctx.api, {
					chatId: card.chatId,
					threadId: card.threadId,
					hours: 4,
				});
				return {
					callbackText: result.callbackText,
					callbackAlert: result.callbackAlert,
				};
			}

			case "ask": {
				const result = startSocialAskWizard(context.ctx.api, {
					chatId: card.chatId,
					threadId: card.threadId,
				});
				return {
					callbackText: result.callbackText,
					callbackAlert: result.callbackAlert,
				};
			}

			case "refresh":
				return {
					state: buildSocialMenuState(card.chatId),
					callbackText: "Social refreshed",
					rerender: true,
				};
		}
	},
};
