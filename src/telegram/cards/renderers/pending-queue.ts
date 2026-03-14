import { deleteEntry, getEntries, promoteEntryTrust } from "../../../memory/store.js";
import { parseSocialQuoteProposalMetadata } from "../../../social/proposal-metadata.js";
import type {
	CardExecutionContext,
	CardExecutionResult,
	CardInstance,
	CardKind,
	CardListEntry,
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

/** Clamp page index to valid range after entries change. */
function clampPage(page: number, total: number): number {
	const maxPage = Math.max(0, totalPages(total) - 1);
	return Math.min(page, maxPage);
}

/**
 * Load pending queue entries from memory store.
 * Shared between the initial `/social queue` command and the card's refresh action.
 */
export function loadPendingQueueEntries(chatId?: string): CardListEntry[] {
	const telegramPending = getEntries({
		categories: ["posts"],
		trust: ["quarantined"],
		sources: ["telegram"],
		...(chatId ? { chatId } : {}),
		limit: 20,
		order: "desc",
	});
	const socialPending = getEntries({
		categories: ["posts"],
		trust: ["untrusted"],
		sources: ["social"],
		limit: 20,
		order: "desc",
	});
	const merged = [...telegramPending, ...socialPending]
		.sort((a, b) => b._provenance.createdAt - a._provenance.createdAt)
		.slice(0, 20);

	return merged.map((entry) => {
		const age = Math.round((Date.now() - entry._provenance.createdAt) / 60000);
		const ageStr = age < 60 ? `${age}m ago` : `${Math.round(age / 60)}h ago`;
		const preview = entry.content.length > 60 ? `${entry.content.slice(0, 60)}...` : entry.content;
		const quoteMetadata = parseSocialQuoteProposalMetadata(entry.metadata);
		const summary = quoteMetadata
			? `quote${quoteMetadata.targetAuthor ? ` ${quoteMetadata.targetAuthor}` : ""}${
					quoteMetadata.targetExcerpt
						? `: "${quoteMetadata.targetExcerpt.slice(0, 40)}${quoteMetadata.targetExcerpt.length > 40 ? "..." : ""}"`
						: ""
				}`
			: undefined;
		return { id: entry.id, label: `"${preview}" — ${ageStr}`, summary };
	});
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
			for (let i = 0; i < visible.length; i++) {
				const entry = visible[i];
				const marker = i === 0 ? "\u25B6" : "\u2022";
				text += `\n${marker} *${esc(entry.label)}*`;
				if (entry.summary) {
					text += `\n  ${esc(entry.summary)}`;
				}
			}
		}

		if (pages > 1) {
			text += `\n\n_Page ${page + 1}/${pages}_`;
		}

		const kb = keyboard();

		// Action buttons act on ▶ marked entry (first on page)
		if (visible.length > 0) {
			kb.text("\u2B06 Promote \u25B6", btn(card, "promote")).text(
				"\uD83D\uDDD1 Dismiss \u25B6",
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
		const { action, card, ctx } = context;
		const s = card.state;
		const currentPage = s.page ?? 0;
		const visible = pageSlice(s.entries, currentPage);
		const targetId = s.selectedEntryId ?? visible[0]?.id;
		const promotedBy = `telegram:${card.chatId}:${ctx.from.id}`;

		switch (action.type) {
			case "promote": {
				if (!targetId) {
					return { callbackText: "No entry to promote", callbackAlert: true };
				}
				const result = promoteEntryTrust(targetId, promotedBy);
				if (!result.ok) {
					return { callbackText: result.reason, callbackAlert: true };
				}
				const remaining = s.entries.filter((e) => e.id !== targetId);
				const newTotal = (s.total ?? s.entries.length) - 1;
				return {
					state: {
						...s,
						entries: remaining,
						total: newTotal,
						page: clampPage(currentPage, newTotal),
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
				deleteEntry(targetId);
				const remaining = s.entries.filter((e) => e.id !== targetId);
				const newTotal = (s.total ?? s.entries.length) - 1;
				return {
					state: {
						...s,
						entries: remaining,
						total: newTotal,
						page: clampPage(currentPage, newTotal),
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
				const refreshedEntries = loadPendingQueueEntries(String(card.chatId));
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
