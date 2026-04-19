import {
	canActorManageProviders,
	startProviderAddWizard,
	startProviderEditWizard,
	startProviderRemoveWizard,
} from "../../control-command-actions.js";
import type {
	CardExecutionContext,
	CardExecutionResult,
	CardInstance,
	CardKind,
	CardRenderer,
	CardRenderResult,
	ProviderHealthIcon,
	ProviderListCardAction,
	ProviderListCardState,
	ProviderListEntry,
} from "../types.js";
import { PICKER_PAGE_SIZE } from "../types.js";
import { btn, esc, formatAge, keyboard, renderTerminalState } from "./helpers.js";

type K = typeof CardKind.ProviderList;

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

export function healthIcon(health: ProviderHealthIcon): string {
	switch (health) {
		case "ok":
			return "\u2705"; // check
		case "degraded":
			return "\u26A0\uFE0F"; // warning
		case "auth_expired":
			return "\uD83D\uDD10"; // lock
		default:
			return "\u2753"; // question mark
	}
}

function resolveSelected(state: ProviderListCardState): ProviderListEntry | undefined {
	if (!state.selectedProviderId) return undefined;
	return state.providers.find((p) => p.id === state.selectedProviderId);
}

function renderListView(card: CardInstance<K>): CardRenderResult {
	const s = card.state;
	const page = s.page ?? 0;
	const pages = totalPages(s.providers.length);
	const visible = pageSlice(s.providers, page);

	const lines: string[] = [`\uD83D\uDD0C *${esc(s.title)}*`];

	if (s.providers.length === 0) {
		lines.push("", "_No providers configured._");
	} else {
		lines.push("", esc("Tap a provider for details."));
		for (const entry of visible) {
			const icon = healthIcon(entry.health);
			lines.push(`\n${icon} *${esc(entry.label)}*`);
			if (entry.description) {
				lines.push(`  ${esc(entry.description)}`);
			}
		}
	}

	if (pages > 1) {
		lines.push("", `_Page ${page + 1}/${pages}_`);
	}
	if (s.lastRefreshedAtMs) {
		lines.push("", `_Updated ${esc(formatAge(s.lastRefreshedAtMs))}_`);
	}

	const kb = keyboard();

	visible.forEach((entry, idx) => {
		kb.text(`${healthIcon(entry.health)} ${entry.label}`, btn(card, `select-${idx}`)).row();
	});

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

	if (s.canMutate) {
		kb.text("\u2795 Add", btn(card, "add")).row();
	}

	kb.text("\u2716 Cancel", btn(card, "cancel")).text("\uD83D\uDD04 Refresh", btn(card, "refresh"));

	return { text: lines.join("\n"), parseMode: "MarkdownV2", keyboard: kb };
}

function renderDetailView(card: CardInstance<K>): CardRenderResult {
	const s = card.state;
	const entry = resolveSelected(s);
	if (!entry) {
		return renderListView({
			...card,
			state: { ...s, view: "list", selectedProviderId: undefined },
		});
	}

	const lines: string[] = [
		`\uD83D\uDD0C *${esc(s.title)}* \u2014 ${esc(entry.label)}`,
		"",
		`*Status:* ${healthIcon(entry.health)} ${esc(entry.health)}`,
	];
	if (entry.description) {
		lines.push("", esc(entry.description));
	}
	if (entry.detail) {
		lines.push("", `*Detail:* ${esc(entry.detail)}`);
	}
	if (entry.baseUrl) {
		lines.push(`*Base URL:* \`${esc(entry.baseUrl)}\``);
	}
	if (entry.oauthServiceId) {
		lines.push(`*OAuth:* ${esc(entry.oauthServiceId)}`);
	}
	if (entry.setupCommand) {
		lines.push("", `_Remediation:_ \`${esc(entry.setupCommand)}\``);
	}

	const kb = keyboard();
	if (s.canMutate) {
		kb.text("\u270F\uFE0F Edit", btn(card, "edit"))
			.text("\uD83D\uDDD1\uFE0F Remove", btn(card, "remove"))
			.row();
	}
	kb.text("\u21A9 Back", btn(card, "back"))
		.text("\u2716 Cancel", btn(card, "cancel"))
		.row()
		.text("\uD83D\uDD04 Refresh", btn(card, "refresh"));

	return { text: lines.join("\n"), parseMode: "MarkdownV2", keyboard: kb };
}

export const providerListRenderer: CardRenderer<K> = {
	render(card: CardInstance<K>): CardRenderResult {
		const terminal = renderTerminalState(card, card.state.title);
		if (terminal) return terminal;
		return card.state.view === "detail" ? renderDetailView(card) : renderListView(card);
	},

	reduce(card: CardInstance<K>, _action: ProviderListCardAction): ProviderListCardState {
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
				const nextPage = clampPage(page + delta, s.providers.length);
				return {
					state: { ...s, page: nextPage, lastRefreshedAtMs: Date.now() },
					callbackText: `Page ${nextPage + 1}`,
					rerender: true,
				};
			}

			case "back": {
				if (s.view !== "detail") {
					return { callbackText: "Already at top" };
				}
				return {
					state: {
						...s,
						view: "list",
						selectedProviderId: undefined,
						lastRefreshedAtMs: Date.now(),
					},
					callbackText: "Back",
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

			case "add": {
				if (!s.canMutate || !canActorManageProviders(card.chatId)) {
					return { callbackText: "Only admin can add providers.", callbackAlert: true };
				}
				return {
					callbackText: "Starting provider wizard",
					rerender: false,
					afterCommit: () => {
						startProviderAddWizard(context.ctx.api, {
							actorId: context.ctx.from.id,
							chatId: card.chatId,
							threadId: card.threadId,
						});
					},
				};
			}

			case "edit": {
				if (!s.canMutate || !canActorManageProviders(card.chatId)) {
					return { callbackText: "Only admin can edit providers.", callbackAlert: true };
				}
				const entry = resolveSelected(s);
				if (!entry) {
					return { callbackText: "Choose a provider first.", callbackAlert: true };
				}
				return {
					callbackText: `Editing ${entry.label}`,
					rerender: false,
					afterCommit: () => {
						startProviderEditWizard(context.ctx.api, {
							actorId: context.ctx.from.id,
							chatId: card.chatId,
							threadId: card.threadId,
							providerId: entry.id,
						});
					},
				};
			}

			case "remove": {
				if (!s.canMutate || !canActorManageProviders(card.chatId)) {
					return { callbackText: "Only admin can remove providers.", callbackAlert: true };
				}
				const entry = resolveSelected(s);
				if (!entry) {
					return { callbackText: "Choose a provider first.", callbackAlert: true };
				}
				return {
					callbackText: `Removing ${entry.label}`,
					rerender: false,
					afterCommit: () => {
						startProviderRemoveWizard(context.ctx.api, {
							actorId: context.ctx.from.id,
							chatId: card.chatId,
							threadId: card.threadId,
							providerId: entry.id,
						});
					},
				};
			}

			case "refresh": {
				// Refresh re-queries providers (health snapshot), but reuse existing list
				// when called from within a renderer unit-test (caller supplies data).
				// Intent-level refresh lives in the command helper; here we just timestamp.
				return {
					state: { ...s, lastRefreshedAtMs: Date.now() },
					callbackText: "Refreshed",
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
				const visible = pageSlice(s.providers, page);
				const entry = visible[idx];
				if (!entry) {
					return { callbackText: "Item not available", callbackAlert: true };
				}
				return {
					state: {
						...s,
						view: "detail",
						selectedProviderId: entry.id,
						lastRefreshedAtMs: Date.now(),
					},
					callbackText: entry.label,
					rerender: true,
				};
			}
		}
	},
};
