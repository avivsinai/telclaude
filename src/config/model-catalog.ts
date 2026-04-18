/**
 * Curated model catalog surfaced by the `/model` picker.
 *
 * This is the display catalog for the W2 picker, not an authoritative
 * routing table. The picker writes the chosen `modelId` into the per-chat
 * preference store; the SDK query path may consult it later.
 */

import type { ModelPickerProvider } from "../telegram/cards/types.js";

export const MODEL_CATALOG: ModelPickerProvider[] = [
	{
		id: "anthropic",
		label: "Anthropic",
		models: [
			{
				id: "claude-opus-4-5-20250929",
				label: "Claude Opus 4.5",
				tier: "frontier",
				summary: "Highest-capacity reasoning model",
			},
			{
				id: "claude-sonnet-4-5-20250929",
				label: "Claude Sonnet 4.5",
				tier: "balanced",
				summary: "Default for most sessions",
			},
			{
				id: "claude-haiku-4-5-20251001",
				label: "Claude Haiku 4.5",
				tier: "fast",
				summary: "Low-latency lightweight model",
			},
		],
	},
	{
		id: "openai",
		label: "OpenAI",
		models: [
			{
				id: "gpt-5",
				label: "GPT-5",
				tier: "frontier",
				summary: "Frontier general reasoning",
			},
			{
				id: "gpt-5-mini",
				label: "GPT-5 Mini",
				tier: "fast",
				summary: "Fast general responses",
			},
		],
	},
];

/**
 * Resolve a free-form token (e.g. "sonnet", "opus", "haiku") to the best
 * matching provider in the catalog. Used by intent-router to pre-filter
 * the picker to a provider.
 *
 * Returns `{ providerId, modelId? }` where `modelId` is optional — if the
 * token matches a specific model within the provider, we surface it so the
 * picker can open directly on the models view.
 */
export function resolveModelHint(token: string): {
	providerId: string;
	modelId?: string;
} | null {
	const needle = token.trim().toLowerCase();
	if (!needle) return null;

	for (const provider of MODEL_CATALOG) {
		if (provider.id.toLowerCase() === needle || provider.label.toLowerCase() === needle) {
			return { providerId: provider.id };
		}
		for (const model of provider.models) {
			if (
				model.id.toLowerCase() === needle ||
				model.label.toLowerCase() === needle ||
				model.id.toLowerCase().includes(needle) ||
				model.label.toLowerCase().includes(needle)
			) {
				return { providerId: provider.id, modelId: model.id };
			}
		}
	}

	// Fuzzy keywords
	if (needle.includes("sonnet")) {
		const anthropic = MODEL_CATALOG.find((p) => p.id === "anthropic");
		const sonnet = anthropic?.models.find((m) => m.label.toLowerCase().includes("sonnet"));
		if (anthropic && sonnet) return { providerId: anthropic.id, modelId: sonnet.id };
	}
	if (needle.includes("opus")) {
		const anthropic = MODEL_CATALOG.find((p) => p.id === "anthropic");
		const opus = anthropic?.models.find((m) => m.label.toLowerCase().includes("opus"));
		if (anthropic && opus) return { providerId: anthropic.id, modelId: opus.id };
	}
	if (needle.includes("haiku")) {
		const anthropic = MODEL_CATALOG.find((p) => p.id === "anthropic");
		const haiku = anthropic?.models.find((m) => m.label.toLowerCase().includes("haiku"));
		if (anthropic && haiku) return { providerId: anthropic.id, modelId: haiku.id };
	}
	if (needle.includes("gpt") || needle.includes("openai")) {
		const openai = MODEL_CATALOG.find((p) => p.id === "openai");
		if (openai) return { providerId: openai.id };
	}

	return null;
}

/**
 * Deep-clone the catalog so callers can mutate without leaking state back
 * into the module-level constant.
 */
export function cloneModelCatalog(): ModelPickerProvider[] {
	return MODEL_CATALOG.map((provider) => ({
		id: provider.id,
		label: provider.label,
		models: provider.models.map((model) => ({ ...model })),
	}));
}
