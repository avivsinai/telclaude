import {
	hasActiveSocialAskWizard,
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
				if (!card.state.adminControlsEnabled) {
					return {
						callbackText: "Only admin can manage social actions.",
						callbackAlert: true,
						rerender: false,
					};
				}
				if ((card.state.queueCount ?? 0) === 0) {
					return {
						callbackText: "No pending posts.",
						callbackAlert: true,
						rerender: false,
					};
				}
				return {
					callbackText:
						action.type === "promote"
							? "Open the queue to promote a post"
							: "Opening pending queue",
					rerender: false,
					afterCommit: async () => {
						await openSocialQueueCard(context.ctx.api, {
							chatId: card.chatId,
							actorScope: card.actorScope,
							threadId: card.threadId,
						});
					},
				};
			}

			case "run": {
				if (!card.state.adminControlsEnabled) {
					return {
						callbackText: "Only admin can trigger heartbeats.",
						callbackAlert: true,
						rerender: false,
					};
				}
				if (card.state.services.length === 0) {
					return {
						callbackText: "No social services are enabled.",
						callbackAlert: true,
						rerender: false,
					};
				}
				return {
					callbackText:
						card.state.services.length === 1
							? `Starting heartbeat for ${card.state.services[0].label}`
							: `Starting heartbeat for ${card.state.services.length} services`,
					rerender: false,
					afterCommit: async () => {
						await runSocialHeartbeatCommand(context.ctx.api, {
							chatId: card.chatId,
							threadId: card.threadId,
						});
					},
				};
			}

			case "log": {
				if (!card.state.adminControlsEnabled) {
					return {
						callbackText: "Only admin can view public activity.",
						callbackAlert: true,
						rerender: false,
					};
				}
				return {
					callbackText: "Sending activity log",
					rerender: false,
					afterCommit: async () => {
						await sendSocialActivityLogCommand(context.ctx.api, {
							chatId: card.chatId,
							threadId: card.threadId,
							hours: 4,
						});
					},
				};
			}

			case "ask": {
				if (!card.state.adminControlsEnabled) {
					return {
						callbackText: "Only admin can query the public persona.",
						callbackAlert: true,
						rerender: false,
					};
				}
				if (card.state.services.length === 0) {
					return {
						callbackText: "No social services are enabled.",
						callbackAlert: true,
						rerender: false,
					};
				}
				if (
					hasActiveSocialAskWizard({
						actorId: context.ctx.from.id,
						chatId: card.chatId,
						threadId: card.threadId,
					})
				) {
					return {
						callbackText: "Already waiting for your question.",
						callbackAlert: true,
						rerender: false,
					};
				}
				return {
					callbackText:
						card.state.services.length === 1
							? `Reply with a question for ${card.state.services[0].label}`
							: "Choose a service, then reply with your question",
					rerender: false,
					afterCommit: () => {
						startSocialAskWizard(context.ctx.api, {
							actorId: context.ctx.from.id,
							chatId: card.chatId,
							threadId: card.threadId,
						});
					},
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
