import { getEntries, promoteEntryTrust } from "../../../memory/store.js";
import type {
	CardExecutionContext,
	CardExecutionResult,
	CardInstance,
	CardKind,
	CardRenderer,
	CardRenderResult,
	PendingQueueCardAction,
	PendingQueueCardState,
} from "../types.js";
import { btn, esc, keyboard, renderTerminalState } from "./helpers.js";

type K = typeof CardKind.PendingQueue;

const PAGE_SIZE = 4;

function pageSlice(entries: { id: string; label: string; summary?: string }[], page: number) {
	const start = page * PAGE_SIZE;
	return entries.slice(start, start + PAGE_SIZE);
}

function totalPages(total: number): number {
	return Math.max(1, Math.ceil(total / PAGE_SIZE));
}

export const pendingQueueRenderer: CardRenderer<K> = {
	render(card: CardInstance<K>): CardRenderResult {
		const s = card.state;

		const terminal = renderTerminalState(card, s.title);
		if (terminal) return terminal;

		const page = s.page ?? 0;
		const entries = s.entries;
		const total = s.total ?? entries.length;
		const pages = totalPages(total);
		const visible = pageSlice(entries, page);

		let text = `\uD83D\uDCCB *${esc(s.title)}*\n`;

		if (visible.length === 0) {
			text += `\n_No pending entries_`;
		} else {
			for (const entry of visible) {
				text += `\n\u2022 *${esc(entry.label)}*`;
				if (entry.summary) {
					text += `\n  ${esc(entry.summary)}`;
				}
			}
		}

		if (pages > 1) {
			text += `\n\n_Page ${page + 1}/${pages}_`;
		}

		const kb = keyboard();

		// Action buttons (only if there are entries)
		if (visible.length > 0) {
			kb.text("\u2B06 Promote", btn(card, "promote")).text(
				"\uD83D\uDDD1 Dismiss",
				btn(card, "dismiss"),
			);
			kb.row();
		}

		// Pagination buttons
		if (page > 0) {
			kb.text("\u25C0 Prev", btn(card, "prev"));
		}
		if (page < pages - 1) {
			kb.text("Next \u25B6", btn(card, "next"));
		}

		// Refresh always available
		kb.row().text("\uD83D\uDD04 Refresh", btn(card, "refresh"));

		return { text, parseMode: "MarkdownV2", keyboard: kb };
	},

	reduce(card: CardInstance<K>, action: PendingQueueCardAction): PendingQueueCardState {
		const s = { ...card.state };
		const total = s.total ?? s.entries.length;
		const pages = totalPages(total);
		const currentPage = s.page ?? 0;

		switch (action.type) {
			case "next":
				return { ...s, page: Math.min(currentPage + 1, pages - 1), selectedEntryId: undefined };
			case "prev":
				return { ...s, page: Math.max(currentPage - 1, 0), selectedEntryId: undefined };
			case "promote": {
				// Select first visible entry if none selected
				const visible = pageSlice(s.entries, currentPage);
				return { ...s, selectedEntryId: visible[0]?.id };
			}
			case "dismiss": {
				const visible = pageSlice(s.entries, currentPage);
				return { ...s, selectedEntryId: visible[0]?.id };
			}
			case "refresh":
				return s;
		}
	},

	async execute(context: CardExecutionContext<K>): Promise<CardExecutionResult<K>> {
		const { action, card } = context;
		const s = card.state;
		const currentPage = s.page ?? 0;
		const visible = pageSlice(s.entries, currentPage);
		const targetId = s.selectedEntryId ?? visible[0]?.id;

		switch (action.type) {
			case "promote": {
				if (!targetId) {
					return { callbackText: "No entry to promote", callbackAlert: true };
				}
				const result = promoteEntryTrust(targetId, "card");
				if (!result.ok) {
					return { callbackText: result.reason, callbackAlert: true };
				}
				const remaining = s.entries.filter((e) => e.id !== targetId);
				return {
					state: {
						...s,
						entries: remaining,
						total: (s.total ?? s.entries.length) - 1,
						selectedEntryId: undefined,
					},
					callbackText: "Promoted",
					rerender: true,
				};
			}

			case "dismiss": {
				if (!targetId) {
					return { callbackText: "No entry to dismiss", callbackAlert: true };
				}
				// Dismiss is UI-only — just remove from the displayed list
				const remaining = s.entries.filter((e) => e.id !== targetId);
				return {
					state: {
						...s,
						entries: remaining,
						total: (s.total ?? s.entries.length) - 1,
						selectedEntryId: undefined,
					},
					callbackText: "Dismissed",
					rerender: true,
				};
			}

			case "next":
				return {
					state: {
						...s,
						page: Math.min(currentPage + 1, totalPages(s.total ?? s.entries.length) - 1),
						selectedEntryId: undefined,
					},
					callbackText: `Page ${Math.min(currentPage + 2, totalPages(s.total ?? s.entries.length))}`,
					rerender: true,
				};

			case "prev":
				return {
					state: {
						...s,
						page: Math.max(currentPage - 1, 0),
						selectedEntryId: undefined,
					},
					callbackText: `Page ${Math.max(currentPage, 1)}`,
					rerender: true,
				};

			case "refresh": {
				const quarantined = getEntries({ trust: ["quarantined"] });
				const refreshedEntries = quarantined.map((e) => ({
					id: e.id,
					label: e.content.slice(0, 60),
					summary: e._provenance.chatId ? `from chat ${e._provenance.chatId}` : undefined,
				}));
				return {
					state: {
						...s,
						entries: refreshedEntries,
						total: refreshedEntries.length,
						page: 0,
						selectedEntryId: undefined,
					},
					callbackText: "Refreshed",
					rerender: true,
				};
			}
		}
	},
};
