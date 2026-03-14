import { openSkillDraftCard, reloadSkillsSession } from "../../control-command-actions.js";
import { buildSkillsMenuState } from "../menu-state.js";
import type {
	CardExecutionContext,
	CardExecutionResult,
	CardInstance,
	CardKind,
	CardRenderer,
	CardRenderResult,
	SkillsMenuCardAction,
	SkillsMenuCardState,
} from "../types.js";
import { btn, esc, formatAge, keyboard, renderTerminalState } from "./helpers.js";

type K = typeof CardKind.SkillsMenu;

export const skillsMenuRenderer: CardRenderer<K> = {
	render(card: CardInstance<K>): CardRenderResult {
		const s = card.state;

		const terminal = renderTerminalState(card, s.title);
		if (terminal) return terminal;

		let text = `🧰 *${esc(s.title)}*\n\n${esc(`${s.activeSkills.length} active skill(s)`)}:`;
		if (s.activeSkills.length === 0) {
			text += `\n• ${esc("No active skills")}`;
		} else {
			for (const skill of s.activeSkills) {
				text += `\n• ${esc(skill.label)}`;
			}
		}

		if (s.adminControlsEnabled) {
			text += `\n\n${esc(`${s.draftCount} draft skill(s) awaiting promotion`)}`;
		}

		if (s.lastRefreshedAt) {
			text += `\n\n_Updated ${esc(formatAge(s.lastRefreshedAt))}_`;
		}

		const kb = keyboard();
		if (s.adminControlsEnabled) {
			kb.text("📄 Drafts", btn(card, "open-drafts"))
				.text("🚀 Promote", btn(card, "promote"))
				.row()
				.text("🔄 Reload", btn(card, "reload"));
		}
		kb.text("↻ Refresh", btn(card, "refresh"));

		return { text, parseMode: "MarkdownV2", keyboard: kb };
	},

	reduce(card: CardInstance<K>, _action: SkillsMenuCardAction): SkillsMenuCardState {
		return card.state;
	},

	async execute(context: CardExecutionContext<K>): Promise<CardExecutionResult<K>> {
		const { action, card } = context;

		switch (action.type) {
			case "open-drafts":
			case "promote": {
				if (!card.state.adminControlsEnabled) {
					return {
						callbackText: "Only admin can manage skill drafts.",
						callbackAlert: true,
						rerender: false,
					};
				}
				if (card.state.draftCount === 0) {
					return {
						callbackText: "No draft skills awaiting promotion.",
						callbackAlert: true,
						rerender: false,
					};
				}
				return {
					callbackText:
						action.type === "promote" ? "Select a draft to promote" : "Opening skill drafts",
					rerender: false,
					afterCommit: async () => {
						await openSkillDraftCard(context.ctx.api, {
							chatId: card.chatId,
							actorScope: card.actorScope,
							threadId: card.threadId,
						});
					},
				};
			}

			case "reload": {
				if (!card.state.adminControlsEnabled) {
					return {
						callbackText: "Only admin can reload skills.",
						callbackAlert: true,
						rerender: false,
					};
				}
				const result = reloadSkillsSession(card.state.sessionKey);
				return {
					state: buildSkillsMenuState(card.chatId, card.state.sessionKey),
					callbackText: result.callbackText,
					callbackAlert: result.callbackAlert,
					rerender: true,
				};
			}

			case "refresh":
				return {
					state: buildSkillsMenuState(card.chatId, card.state.sessionKey),
					callbackText: "Skills refreshed",
					rerender: true,
				};
		}
	},
};
