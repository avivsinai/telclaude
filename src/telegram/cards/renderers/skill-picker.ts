import {
	listActiveSkills,
	listDraftSkills,
	promoteSkill,
} from "../../../commands/skills-promote.js";
import { deleteSession } from "../../../config/sessions.js";
import { getSessionManager } from "../../../sdk/session-manager.js";
import type {
	CardExecutionContext,
	CardExecutionResult,
	CardInstance,
	CardKind,
	CardRenderer,
	CardRenderResult,
	SkillPickerCardAction,
	SkillPickerCardState,
	SkillPickerEntry,
} from "../types.js";
import { PICKER_PAGE_SIZE } from "../types.js";
import { btn, esc, formatAge, keyboard, renderTerminalState } from "./helpers.js";

type K = typeof CardKind.SkillPicker;

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

export function loadSkillPickerEntries(): SkillPickerEntry[] {
	const drafts = listDraftSkills().map<SkillPickerEntry>((name) => ({
		id: name,
		label: name,
		status: "draft",
		summary: "Draft — tap to promote",
	}));
	const active = listActiveSkills().map<SkillPickerEntry>((name) => ({
		id: name,
		label: name,
		status: "active",
	}));
	// Drafts first so one-tap promote is prominent.
	return [...drafts, ...active];
}

function skillIcon(entry: SkillPickerEntry): string {
	return entry.status === "draft" ? "\uD83D\uDCDD" : "\u2713";
}

export const skillPickerRenderer: CardRenderer<K> = {
	render(card: CardInstance<K>): CardRenderResult {
		const s = card.state;
		const terminal = renderTerminalState(card, s.title);
		if (terminal) return terminal;

		const page = s.page ?? 0;
		const pages = totalPages(s.entries.length);
		const visible = pageSlice(s.entries, page);

		const draftCount = s.entries.filter((e) => e.status === "draft").length;
		const activeCount = s.entries.filter((e) => e.status === "active").length;

		const lines: string[] = [
			`\uD83E\uDDF0 *${esc(s.title)}*`,
			"",
			esc(`${activeCount} active · ${draftCount} draft`),
		];

		if (s.entries.length === 0) {
			lines.push("", "_No skills found._");
		}

		for (const entry of visible) {
			lines.push(`\n${skillIcon(entry)} *${esc(entry.label)}* _(${esc(entry.status)})_`);
			if (entry.summary) {
				lines.push(`  ${esc(entry.summary)}`);
			}
		}

		if (pages > 1) {
			lines.push("", `_Page ${page + 1}/${pages}_`);
		}
		if (s.lastRefreshedAtMs) {
			lines.push("", `_Updated ${esc(formatAge(s.lastRefreshedAtMs))}_`);
		}

		const kb = keyboard();

		if (s.adminControlsEnabled) {
			visible.forEach((entry, idx) => {
				if (entry.status === "draft") {
					kb.text(`\u2B06 Promote "${entry.label}"`, btn(card, `select-${idx}`)).row();
				} else {
					kb.text(`\u2713 ${entry.label}`, btn(card, `select-${idx}`)).row();
				}
			});
		}

		const pagerRow: Array<{ text: string; cb: string }> = [];
		if (page > 0) {
			pagerRow.push({ text: "\u25C0 Prev", cb: btn(card, "page-prev") });
		}
		if (page < pages - 1) {
			pagerRow.push({ text: "Next \u25B6", cb: btn(card, "page-next") });
		}
		for (const entry of pagerRow) {
			kb.text(entry.text, entry.cb);
		}
		if (pagerRow.length > 0) kb.row();

		if (s.adminControlsEnabled) {
			kb.text("\uD83D\uDD04 Reload", btn(card, "reload"))
				.text("\u2716 Cancel", btn(card, "cancel"))
				.row();
		}
		kb.text("\uD83D\uDD04 Refresh", btn(card, "refresh"));

		return { text: lines.join("\n"), parseMode: "MarkdownV2", keyboard: kb };
	},

	reduce(card: CardInstance<K>, _action: SkillPickerCardAction): SkillPickerCardState {
		return card.state;
	},

	async execute(context: CardExecutionContext<K>): Promise<CardExecutionResult<K>> {
		const { action, card } = context;
		const s = card.state;
		const page = s.page ?? 0;

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

			case "cancel": {
				return {
					status: "consumed",
					callbackText: "Cancelled",
					rerender: true,
				};
			}

			case "reload": {
				if (!s.adminControlsEnabled) {
					return {
						callbackText: "Only admin can reload skills.",
						callbackAlert: true,
					};
				}
				if (s.sessionKey) {
					deleteSession(s.sessionKey);
					getSessionManager().clearSession(s.sessionKey);
				}
				// Also refresh the entries list so any newly promoted skills show.
				const refreshed = loadSkillPickerEntries();
				return {
					state: {
						...s,
						entries: refreshed,
						page: clampPage(page, refreshed.length),
						lastRefreshedAtMs: Date.now(),
					},
					callbackText: s.sessionKey
						? "Skills reloaded. Next message starts fresh."
						: "Skills refreshed.",
					rerender: true,
				};
			}

			case "refresh": {
				const refreshed = loadSkillPickerEntries();
				return {
					state: {
						...s,
						entries: refreshed,
						page: clampPage(page, refreshed.length),
						lastRefreshedAtMs: Date.now(),
					},
					callbackText: "Refreshed",
					rerender: true,
				};
			}

			// `promote` is kept for symmetry but the picker uses `select-N` for
			// per-row tap-to-promote. If a caller wires a generic Promote button
			// we treat it the same as selecting the first visible draft.
			case "promote": {
				if (!s.adminControlsEnabled) {
					return { callbackText: "Only admin can promote.", callbackAlert: true };
				}
				const visible = pageSlice(s.entries, page);
				const firstDraft = visible.find((entry) => entry.status === "draft");
				if (!firstDraft) {
					return { callbackText: "No draft on this page.", callbackAlert: true };
				}
				return executePromote(card, firstDraft);
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
				const visible = pageSlice(s.entries, page);
				const entry = visible[idx];
				if (!entry) {
					return { callbackText: "Item not available", callbackAlert: true };
				}

				if (entry.status === "active") {
					return {
						callbackText: `${entry.label} is already active.`,
						callbackAlert: false,
					};
				}

				if (!s.adminControlsEnabled) {
					return {
						callbackText: "Only admin can promote skills.",
						callbackAlert: true,
					};
				}

				return executePromote(card, entry);
			}
		}
	},
};

function executePromote(card: CardInstance<K>, entry: SkillPickerEntry): CardExecutionResult<K> {
	const result = promoteSkill(entry.id);
	if (!result.success) {
		return {
			callbackText: result.error ?? "Promotion failed",
			callbackAlert: true,
		};
	}
	// Drop the now-active entry; keep it visible in active form for confirmation.
	const remaining = card.state.entries.filter((e) => !(e.id === entry.id && e.status === "draft"));
	remaining.push({
		id: entry.id,
		label: entry.label,
		status: "active",
	});
	// Re-sort: drafts first, then active.
	remaining.sort((a, b) => {
		if (a.status === b.status) return a.label.localeCompare(b.label);
		return a.status === "draft" ? -1 : 1;
	});
	const pageCount = Math.max(1, Math.ceil(remaining.length / PICKER_PAGE_SIZE));
	return {
		state: {
			...card.state,
			entries: remaining,
			page: Math.min(card.state.page ?? 0, pageCount - 1),
			lastRefreshedAtMs: Date.now(),
		},
		callbackText: `Promoted ${entry.label}`,
		rerender: true,
	};
}
