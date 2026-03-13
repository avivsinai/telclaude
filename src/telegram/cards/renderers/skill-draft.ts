import type {
	CardExecutionContext,
	CardExecutionResult,
	CardInstance,
	CardKind,
	CardRenderer,
	CardRenderResult,
	SkillDraftCardAction,
	SkillDraftCardState,
} from "../types.js";
import { btn, esc, keyboard, renderTerminalState } from "./helpers.js";

type K = typeof CardKind.SkillDraft;

const PAGE_SIZE = 4;

function pageSlice(drafts: { id: string; label: string; summary?: string }[], page: number) {
	const start = page * PAGE_SIZE;
	return drafts.slice(start, start + PAGE_SIZE);
}

function totalPages(count: number): number {
	return Math.max(1, Math.ceil(count / PAGE_SIZE));
}

export const skillDraftRenderer: CardRenderer<K> = {
	render(card: CardInstance<K>): CardRenderResult {
		const s = card.state;

		const terminal = renderTerminalState(card, s.title);
		if (terminal) return terminal;

		const page = s.page ?? 0;
		const pages = totalPages(s.drafts.length);
		const visible = pageSlice(s.drafts, page);

		let text = `\uD83D\uDCDD *${esc(s.title)}*\n`;

		if (visible.length === 0) {
			text += "\n_No draft skills_";
		} else {
			for (const draft of visible) {
				text += `\n\u2022 *${esc(draft.label)}*`;
				if (draft.summary) {
					text += `\n  ${esc(draft.summary)}`;
				}
			}
		}

		if (pages > 1) {
			text += `\n\n_Page ${page + 1}/${pages}_`;
		}

		const kb = keyboard();

		if (visible.length > 0) {
			kb.text("\u2705 Promote", btn(card, "promote")).text("\u274C Reject", btn(card, "reject"));
			kb.row();
		}

		kb.text("\uD83D\uDD04 Refresh", btn(card, "refresh"));

		return { text, parseMode: "MarkdownV2", keyboard: kb };
	},

	reduce(card: CardInstance<K>, action: SkillDraftCardAction): SkillDraftCardState {
		const s = { ...card.state };
		const page = s.page ?? 0;

		switch (action.type) {
			case "promote": {
				const visible = pageSlice(s.drafts, page);
				return { ...s, selectedDraftName: visible[0]?.id };
			}
			case "reject": {
				const visible = pageSlice(s.drafts, page);
				return { ...s, selectedDraftName: visible[0]?.id };
			}
			case "refresh":
				return s;
		}
	},

	async execute(context: CardExecutionContext<K>): Promise<CardExecutionResult<K>> {
		const { action, card } = context;
		const s = card.state;
		const page = s.page ?? 0;
		const visible = pageSlice(s.drafts, page);
		const targetName = s.selectedDraftName ?? visible[0]?.id;

		switch (action.type) {
			case "promote": {
				if (!targetName) {
					return { callbackText: "No draft to promote", callbackAlert: true };
				}
				// TODO: promote skill draft to active skill
				const remaining = s.drafts.filter((d) => d.id !== targetName);
				return {
					state: { ...s, drafts: remaining, selectedDraftName: undefined },
					callbackText: `Promoted: ${targetName}`,
					rerender: true,
				};
			}

			case "reject": {
				if (!targetName) {
					return { callbackText: "No draft to reject", callbackAlert: true };
				}
				// TODO: reject/dismiss skill draft
				const remaining = s.drafts.filter((d) => d.id !== targetName);
				return {
					state: { ...s, drafts: remaining, selectedDraftName: undefined },
					callbackText: `Rejected: ${targetName}`,
					rerender: true,
				};
			}

			case "refresh":
				// TODO: re-scan skill drafts directory
				return {
					callbackText: "Refreshed",
					rerender: true,
				};
		}
	},
};
