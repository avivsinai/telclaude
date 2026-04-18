import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

let modelPickerRenderer: typeof import("../../../src/telegram/cards/renderers/model-picker.js").modelPickerRenderer;
let CardKind: typeof import("../../../src/telegram/cards/types.js").CardKind;
let resetDatabase: typeof import("../../../src/storage/db.js").resetDatabase;
let getChatModelPreference: typeof import("../../../src/config/model-preferences.js").getChatModelPreference;
let cloneModelCatalog: typeof import("../../../src/config/model-catalog.js").cloneModelCatalog;

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

function baseCard(kind: typeof CardKind.ModelPicker) {
	return {
		cardId: "m-1",
		shortId: "abcdef12",
		kind,
		version: 1,
		chatId: 777,
		messageId: 9,
		actorScope: "user:101",
		entityRef: "model-picker",
		revision: 1,
		expiresAt: Date.now() + 60_000,
		status: "active" as const,
		createdAt: Date.now(),
		updatedAt: Date.now(),
	};
}

describe("model picker card", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-model-picker-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;

		const db = await import("../../../src/storage/db.js");
		resetDatabase = db.resetDatabase;
		resetDatabase();

		({ modelPickerRenderer } = await import(
			"../../../src/telegram/cards/renderers/model-picker.js"
		));
		({ CardKind } = await import("../../../src/telegram/cards/types.js"));
		({ getChatModelPreference } = await import("../../../src/config/model-preferences.js"));
		({ cloneModelCatalog } = await import("../../../src/config/model-catalog.js"));
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("renders providers view with counts, tier, and fallback state", () => {
		const providers = cloneModelCatalog();
		const card = {
			...baseCard(CardKind.ModelPicker),
			state: {
				kind: CardKind.ModelPicker,
				title: "Model",
				providers,
				page: 0,
				view: "providers" as const,
				viewerTier: "FULL_ACCESS",
				canMutate: true,
				fallbackState: "default",
				currentModelId: "claude-sonnet-4-5-20250929",
				currentProviderId: "anthropic",
			},
		} as any;

		const render = modelPickerRenderer.render(card);
		expect(render.text).toContain("Model");
		expect(render.text).toContain("Tier");
		// MarkdownV2 escapes underscores, so match the literal rendered form.
		expect(render.text).toContain("FULL\\_ACCESS");
		expect(render.text).toContain("Fallback");
		expect(render.text).toContain("Current");
		const buttons =
			render.keyboard?.inline_keyboard
				?.flat()
				.map((b) => ("text" in b ? b.text : "")) ?? [];
		expect(buttons.some((b) => b.includes("Anthropic"))).toBe(true);
		expect(buttons.some((b) => b.includes("OpenAI"))).toBe(true);
		// Pagination buttons absent when everything fits on one page
		expect(buttons.some((b) => /Next|Prev/.test(b))).toBe(false);
	});

	it("drills into the models view when a provider row is tapped", async () => {
		const providers = cloneModelCatalog();
		const card = {
			...baseCard(CardKind.ModelPicker),
			state: {
				kind: CardKind.ModelPicker,
				title: "Model",
				providers,
				page: 0,
				view: "providers" as const,
				canMutate: true,
			},
		} as any;

		const result = await modelPickerRenderer.execute({
			action: { type: "select-0" },
			card,
			ctx: { from: { id: 101 } } as any,
		});
		const state = result.state;
		expect(state).toEqual(
			expect.objectContaining({
				view: "models",
				selectedProviderId: "anthropic",
				page: 0,
			}),
		);
		expect(result.rerender).toBe(true);
	});

	it("persists the chosen model on select in the models view", async () => {
		const providers = cloneModelCatalog();
		const card = {
			...baseCard(CardKind.ModelPicker),
			state: {
				kind: CardKind.ModelPicker,
				title: "Model",
				providers,
				selectedProviderId: "anthropic",
				page: 0,
				view: "models" as const,
				canMutate: true,
			},
		} as any;

		// Pick the first model in the models view (Opus 4.5 per catalog order).
		const result = await modelPickerRenderer.execute({
			action: { type: "select-0" },
			card,
			ctx: { from: { id: 101 } } as any,
		});
		expect(result.status).toBe("consumed");
		const pref = getChatModelPreference(card.chatId);
		expect(pref).toEqual(
			expect.objectContaining({
				chatId: 777,
				providerId: "anthropic",
			}),
		);
	});

	it("blocks model selection when the viewer cannot mutate", async () => {
		const providers = cloneModelCatalog();
		const card = {
			...baseCard(CardKind.ModelPicker),
			state: {
				kind: CardKind.ModelPicker,
				title: "Model",
				providers,
				selectedProviderId: "anthropic",
				page: 0,
				view: "models" as const,
				canMutate: false,
			},
		} as any;

		const result = await modelPickerRenderer.execute({
			action: { type: "select-0" },
			card,
			ctx: { from: { id: 101 } } as any,
		});
		expect(result.callbackAlert).toBe(true);
		expect(result.callbackText).toContain("tier");
		expect(getChatModelPreference(card.chatId)).toBeNull();
	});

	it("navigates pages server-side on page-next / page-prev", async () => {
		const manyProviders = Array.from({ length: 20 }, (_, idx) => ({
			id: `prov-${idx}`,
			label: `Provider ${idx}`,
			models: [{ id: `m-${idx}`, label: `Model ${idx}` }],
		}));
		const card = {
			...baseCard(CardKind.ModelPicker),
			state: {
				kind: CardKind.ModelPicker,
				title: "Model",
				providers: manyProviders,
				page: 0,
				view: "providers" as const,
				canMutate: true,
			},
		} as any;

		const nextResult = await modelPickerRenderer.execute({
			action: { type: "page-next" },
			card,
			ctx: { from: { id: 101 } } as any,
		});
		expect(nextResult.state?.page).toBe(1);
		expect(nextResult.rerender).toBe(true);

		const card2 = { ...card, state: nextResult.state! } as any;
		const prevResult = await modelPickerRenderer.execute({
			action: { type: "page-prev" },
			card: card2,
			ctx: { from: { id: 101 } } as any,
		});
		expect(prevResult.state?.page).toBe(0);
	});

	it("returns to providers view on back action", async () => {
		const providers = cloneModelCatalog();
		const card = {
			...baseCard(CardKind.ModelPicker),
			state: {
				kind: CardKind.ModelPicker,
				title: "Model",
				providers,
				selectedProviderId: "anthropic",
				page: 0,
				view: "models" as const,
				canMutate: true,
			},
		} as any;

		const result = await modelPickerRenderer.execute({
			action: { type: "back" },
			card,
			ctx: { from: { id: 101 } } as any,
		});
		expect(result.state?.view).toBe("providers");
		expect(result.state?.selectedProviderId).toBeUndefined();
	});

	it("cancel marks the card consumed", async () => {
		const providers = cloneModelCatalog();
		const card = {
			...baseCard(CardKind.ModelPicker),
			state: {
				kind: CardKind.ModelPicker,
				title: "Model",
				providers,
				page: 0,
				view: "providers" as const,
				canMutate: true,
			},
		} as any;

		const result = await modelPickerRenderer.execute({
			action: { type: "cancel" },
			card,
			ctx: { from: { id: 101 } } as any,
		});
		expect(result.status).toBe("consumed");
	});
});
