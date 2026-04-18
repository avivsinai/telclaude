import { setChatModelPreference } from "../../../config/model-preferences.js";
import type {
	CardExecutionContext,
	CardExecutionResult,
	CardInstance,
	CardKind,
	CardRenderer,
	CardRenderResult,
	ModelPickerCardAction,
	ModelPickerCardState,
	ModelPickerProvider,
} from "../types.js";
import { PICKER_PAGE_SIZE } from "../types.js";
import { btn, esc, formatAge, keyboard, renderTerminalState } from "./helpers.js";

type K = typeof CardKind.ModelPicker;

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

function resolveSelectedProvider(state: ModelPickerCardState): ModelPickerProvider | undefined {
	if (!state.selectedProviderId) return undefined;
	return state.providers.find((p) => p.id === state.selectedProviderId);
}

function renderProvidersView(card: CardInstance<K>): CardRenderResult {
	const s = card.state;
	const page = s.page ?? 0;
	const pages = totalPages(s.providers.length);
	const visible = pageSlice(s.providers, page);

	const lines: string[] = [`\uD83E\uDDE0 *${esc(s.title)}*`];

	if (s.currentModelId) {
		const providerLabel =
			s.providers.find((p) => p.id === s.currentProviderId)?.label ?? s.currentProviderId ?? "?";
		lines.push("", `*Current:* ${esc(s.currentModelId)} _(${esc(providerLabel)})_`);
	}
	if (s.viewerTier) {
		lines.push(`*Tier:* ${esc(s.viewerTier)}`);
	}
	if (s.fallbackState) {
		lines.push(`*Fallback:* ${esc(s.fallbackState)}`);
	}
	lines.push("", esc("Tap a provider to browse its models."));

	if (visible.length === 0) {
		lines.push("", "_No providers configured._");
	}

	if (pages > 1) {
		lines.push("", `_Page ${page + 1}/${pages}_`);
	}
	if (s.lastRefreshedAtMs) {
		lines.push("", `_Updated ${esc(formatAge(s.lastRefreshedAtMs))}_`);
	}

	const kb = keyboard();

	// Provider rows (one per row for readability)
	visible.forEach((provider, idx) => {
		const active = provider.id === s.currentProviderId ? " \u2605" : "";
		kb.text(
			`${provider.label} (${provider.models.length})${active}`,
			btn(card, `select-${idx}`),
		).row();
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

	kb.text("\u2716 Cancel", btn(card, "cancel")).text("\uD83D\uDD04 Refresh", btn(card, "refresh"));

	return { text: lines.join("\n"), parseMode: "MarkdownV2", keyboard: kb };
}

function renderModelsView(card: CardInstance<K>): CardRenderResult {
	const s = card.state;
	const provider = resolveSelectedProvider(s);
	if (!provider) {
		// Defensive: malformed state — show providers view instead.
		return renderProvidersView({
			...card,
			state: { ...s, view: "providers", selectedProviderId: undefined, page: 0 },
		});
	}

	const page = s.page ?? 0;
	const pages = totalPages(provider.models.length);
	const visible = pageSlice(provider.models, page);

	const lines: string[] = [`\uD83E\uDDE0 *${esc(s.title)}* \u2014 ${esc(provider.label)}`];
	if (s.currentModelId) {
		lines.push("", `*Current:* ${esc(s.currentModelId)}`);
	}
	lines.push("", esc("Tap a model to switch."));

	if (visible.length === 0) {
		lines.push("", "_No models for this provider._");
	}

	if (pages > 1) {
		lines.push("", `_Page ${page + 1}/${pages}_`);
	}

	const kb = keyboard();
	visible.forEach((model, idx) => {
		const active = model.id === s.currentModelId ? " \u2605" : "";
		kb.text(`${model.label}${active}`, btn(card, `select-${idx}`)).row();
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

	kb.text("\u21A9 Back", btn(card, "back"))
		.text("\u2716 Cancel", btn(card, "cancel"))
		.row()
		.text("\uD83D\uDD04 Refresh", btn(card, "refresh"));

	return { text: lines.join("\n"), parseMode: "MarkdownV2", keyboard: kb };
}

export const modelPickerRenderer: CardRenderer<K> = {
	render(card: CardInstance<K>): CardRenderResult {
		const terminal = renderTerminalState(card, card.state.title);
		if (terminal) return terminal;
		return card.state.view === "models" ? renderModelsView(card) : renderProvidersView(card);
	},

	reduce(card: CardInstance<K>, _action: ModelPickerCardAction): ModelPickerCardState {
		return card.state;
	},

	async execute(context: CardExecutionContext<K>): Promise<CardExecutionResult<K>> {
		const { action, card } = context;
		const s = card.state;
		const page = s.page ?? 0;

		switch (action.type) {
			case "page-next":
			case "page-prev": {
				const count =
					s.view === "models"
						? (resolveSelectedProvider(s)?.models.length ?? 0)
						: s.providers.length;
				const delta = action.type === "page-next" ? 1 : -1;
				const nextPage = clampPage(page + delta, count);
				return {
					state: { ...s, page: nextPage, lastRefreshedAtMs: Date.now() },
					callbackText: `Page ${nextPage + 1}`,
					rerender: true,
				};
			}

			case "back": {
				if (s.view !== "models") {
					return { callbackText: "Already at top" };
				}
				return {
					state: {
						...s,
						view: "providers",
						selectedProviderId: undefined,
						page: 0,
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

			case "refresh": {
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
				if (s.view === "providers") {
					const visible = pageSlice(s.providers, page);
					const provider = visible[idx];
					if (!provider) {
						return { callbackText: "Item not available", callbackAlert: true };
					}
					return {
						state: {
							...s,
							view: "models",
							selectedProviderId: provider.id,
							page: 0,
							lastRefreshedAtMs: Date.now(),
						},
						callbackText: `Opening ${provider.label}`,
						rerender: true,
					};
				}

				// models view
				const provider = resolveSelectedProvider(s);
				if (!provider) {
					return { callbackText: "Provider missing", callbackAlert: true };
				}
				const visible = pageSlice(provider.models, page);
				const model = visible[idx];
				if (!model) {
					return { callbackText: "Model not available", callbackAlert: true };
				}

				if (!s.canMutate) {
					return {
						callbackText: "Your tier cannot switch models.",
						callbackAlert: true,
					};
				}

				try {
					setChatModelPreference({
						chatId: card.chatId,
						providerId: provider.id,
						modelId: model.id,
					});
				} catch (err) {
					return {
						callbackText: `Switch failed: ${String(err).slice(0, 80)}`,
						callbackAlert: true,
					};
				}

				return {
					state: {
						...s,
						currentModelId: model.id,
						currentProviderId: provider.id,
						lastRefreshedAtMs: Date.now(),
					},
					status: "consumed",
					callbackText: `Switched to ${model.label}`,
					rerender: true,
				};
			}
		}
	},
};
