import { runCuratorScan } from "../../../curator/actions.js";
import { decideCuratorItem, getCuratorItem, listCuratorItems } from "../../../curator/store.js";
import type { CuratorItem } from "../../../curator/types.js";
import type {
	CardExecutionContext,
	CardExecutionResult,
	CardInstance,
	CardKind,
	CardRenderer,
	CardRenderResult,
	CuratorInboxCardAction,
	CuratorInboxCardState,
	CuratorInboxEntry,
} from "../types.js";
import { PICKER_PAGE_SIZE } from "../types.js";
import { btn, esc, formatAge, keyboard, renderTerminalState } from "./helpers.js";

type K = typeof CardKind.CuratorInbox;

function severityIcon(severity: CuratorInboxEntry["severity"]): string {
	switch (severity) {
		case "high":
			return "\u26A0\uFE0F";
		case "medium":
			return "\uD83D\uDD36";
		case "low":
			return "\uD83D\uDD39";
		case "info":
			return "\u2139\uFE0F";
	}
}

function totalPages(count: number): number {
	return Math.max(1, Math.ceil(count / PICKER_PAGE_SIZE));
}

function pageSlice<T>(items: T[], page: number): T[] {
	const start = page * PICKER_PAGE_SIZE;
	return items.slice(start, start + PICKER_PAGE_SIZE);
}

function clampPage(page: number, count: number): number {
	if (count <= 0) return 0;
	return Math.max(0, Math.min(page, totalPages(count) - 1));
}

function actionType(item: CuratorItem): string | undefined {
	const value = item.proposedAction.type;
	return typeof value === "string" ? value : undefined;
}

function toEntry(item: CuratorItem): CuratorInboxEntry {
	return {
		shortId: item.shortId,
		kind: item.kind,
		status: item.status,
		severity: item.severity,
		source: item.source,
		title: item.title,
		summary: item.summary,
		rationale: item.rationale ?? undefined,
		entityRef: item.entityRef,
		proposedActionType: actionType(item),
		updatedAtMs: item.updatedAtMs,
	};
}

export function loadCuratorInboxEntries(): CuratorInboxEntry[] {
	return listCuratorItems({ status: "open", limit: 50 }).map(toEntry);
}

function selectedEntry(state: CuratorInboxCardState): CuratorInboxEntry | undefined {
	if (!state.selectedShortId) return undefined;
	return state.entries.find((entry) => entry.shortId === state.selectedShortId);
}

function renderListView(card: CardInstance<K>): CardRenderResult {
	const s = card.state;
	const page = clampPage(s.page ?? 0, s.entries.length);
	const pages = totalPages(s.entries.length);
	const visible = pageSlice(s.entries, page);
	const lines: string[] = [`\uD83E\uDDED *${esc(s.title)}*`];

	if (s.entries.length === 0) {
		lines.push("", "_No open Curator suggestions._");
	} else {
		lines.push("", esc("Tap a suggestion for details. Accept/reject only records the decision."));
		for (const entry of visible) {
			lines.push(
				`\n${severityIcon(entry.severity)} \`${esc(entry.shortId)}\` *${esc(entry.title)}*`,
			);
			lines.push(
				`  _${esc(entry.kind)} · ${esc(entry.severity)} · ${esc(formatAge(entry.updatedAtMs))}_`,
			);
		}
	}
	if (s.lastScanSummary) {
		lines.push("", esc(s.lastScanSummary));
	}
	if (pages > 1) {
		lines.push("", `_Page ${page + 1}/${pages}_`);
	}
	if (s.lastRefreshedAtMs) {
		lines.push("", `_Updated ${esc(formatAge(s.lastRefreshedAtMs))}_`);
	}

	const kb = keyboard();
	visible.forEach((entry, idx) => {
		kb.text(`${severityIcon(entry.severity)} ${entry.shortId}`, btn(card, `select-${idx}`)).row();
	});
	if (page > 0) {
		kb.text("\u25C0 Prev", btn(card, "page-prev"));
	}
	if (page < pages - 1) {
		kb.text("Next \u25B6", btn(card, "page-next"));
	}
	if (pages > 1) kb.row();
	kb.text("\uD83D\uDD0E Scan", btn(card, "scan")).text(
		"\uD83D\uDD04 Refresh",
		btn(card, "refresh"),
	);

	return { text: lines.join("\n"), parseMode: "MarkdownV2", keyboard: kb };
}

function renderDetailView(card: CardInstance<K>): CardRenderResult {
	const s = card.state;
	const entry = selectedEntry(s);
	if (!entry) {
		return renderListView({
			...card,
			state: { ...s, view: "list", selectedShortId: undefined },
		});
	}

	const lines = [
		`\uD83E\uDDED *${esc(s.title)}* \u2014 \`${esc(entry.shortId)}\``,
		"",
		`${severityIcon(entry.severity)} *${esc(entry.title)}*`,
		`*Status:* ${esc(entry.status)}`,
		`*Kind:* ${esc(entry.kind)}`,
		`*Source:* ${esc(entry.source)}`,
		`*Entity:* \`${esc(entry.entityRef)}\``,
		"",
		esc(entry.summary),
	];
	if (entry.rationale) {
		lines.push("", `*Rationale:* ${esc(entry.rationale)}`);
	}
	if (entry.proposedActionType) {
		lines.push("", `*Next action:* ${esc(entry.proposedActionType)} \\(manual\\)`);
	}

	const kb = keyboard();
	if (entry.status === "open") {
		kb.text("\u2705 Accept", btn(card, "accept"))
			.text("\uD83D\uDEAB Reject", btn(card, "reject"))
			.row();
	}
	kb.text("\u21A9 Back", btn(card, "back"))
		.text("\uD83D\uDD0E Scan", btn(card, "scan"))
		.row()
		.text("\uD83D\uDD04 Refresh", btn(card, "refresh"));

	return { text: lines.join("\n"), parseMode: "MarkdownV2", keyboard: kb };
}

function refreshedState(state: CuratorInboxCardState): CuratorInboxCardState {
	const entries = loadCuratorInboxEntries();
	const selectedShortId = entries.some((entry) => entry.shortId === state.selectedShortId)
		? state.selectedShortId
		: undefined;
	return {
		...state,
		entries,
		selectedShortId,
		view: selectedShortId ? state.view : "list",
		page: clampPage(state.page ?? 0, entries.length),
		lastRefreshedAtMs: Date.now(),
	};
}

export const curatorInboxRenderer: CardRenderer<K> = {
	render(card: CardInstance<K>): CardRenderResult {
		const terminal = renderTerminalState(card, card.state.title);
		if (terminal) return terminal;
		return card.state.view === "detail" ? renderDetailView(card) : renderListView(card);
	},

	reduce(card: CardInstance<K>, _action: CuratorInboxCardAction): CuratorInboxCardState {
		return card.state;
	},

	async execute(context: CardExecutionContext<K>): Promise<CardExecutionResult<K>> {
		const { action, card } = context;
		const s = card.state;
		const page = clampPage(s.page ?? 0, s.entries.length);

		switch (action.type) {
			case "page-next":
			case "page-prev": {
				const delta = action.type === "page-next" ? 1 : -1;
				const nextPage = clampPage(page + delta, s.entries.length);
				return {
					state: { ...s, page: nextPage, lastRefreshedAtMs: Date.now() },
					callbackText: `Page ${nextPage + 1}`,
					rerender: true,
				};
			}
			case "back":
				return {
					state: { ...s, view: "list", selectedShortId: undefined, lastRefreshedAtMs: Date.now() },
					callbackText: "Back",
					rerender: true,
				};
			case "refresh":
				return {
					state: refreshedState(s),
					callbackText: "Refreshed",
					rerender: true,
				};
			case "scan": {
				const result = runCuratorScan({ producerKind: "system" });
				return {
					state: {
						...refreshedState(s),
						lastScanSummary: `Scan updated ${result.createdOrUpdated} item(s); ${result.openItems} open.`,
					},
					callbackText: `${result.openItems} open`,
					rerender: true,
				};
			}
			case "accept":
			case "reject": {
				const entry = selectedEntry(s);
				if (!entry) {
					return { callbackText: "Choose an item first.", callbackAlert: true };
				}
				const item = getCuratorItem(entry.shortId);
				if (!item) {
					return { state: refreshedState(s), callbackText: "Item missing", rerender: true };
				}
				const decided = decideCuratorItem({
					id: item.shortId,
					status: action.type === "accept" ? "accepted" : "rejected",
					actor: `telegram:${context.ctx.from.id}`,
				});
				if (!decided) {
					return { state: refreshedState(s), callbackText: "Item missing", rerender: true };
				}
				return {
					state: {
						...refreshedState(s),
						view: "list",
						selectedShortId: undefined,
					},
					callbackText: action.type === "accept" ? "Accepted" : "Rejected",
					rerender: true,
				};
			}
			case "select-0":
			case "select-1":
			case "select-2":
			case "select-3":
			case "select-4":
			case "select-5":
			case "select-6":
			case "select-7": {
				const idx = Number.parseInt(action.type.slice("select-".length), 10);
				const entry = pageSlice(s.entries, page)[idx];
				if (!entry) {
					return { callbackText: "Item not available", callbackAlert: true };
				}
				return {
					state: {
						...s,
						view: "detail",
						selectedShortId: entry.shortId,
						lastRefreshedAtMs: Date.now(),
					},
					callbackText: entry.shortId,
					rerender: true,
				};
			}
		}
	},
};
