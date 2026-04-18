import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let skillPickerRenderer: typeof import("../../../src/telegram/cards/renderers/skill-picker.js").skillPickerRenderer;
let CardKind: typeof import("../../../src/telegram/cards/types.js").CardKind;
let resetDatabase: typeof import("../../../src/storage/db.js").resetDatabase;

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

function baseCard(kind: typeof CardKind.SkillPicker) {
	return {
		cardId: "sp-1",
		shortId: "abcdef12",
		kind,
		version: 1,
		chatId: 777,
		messageId: 9,
		actorScope: "user:101",
		entityRef: "skill-picker",
		revision: 1,
		expiresAt: Date.now() + 60_000,
		status: "active" as const,
		createdAt: Date.now(),
		updatedAt: Date.now(),
	};
}

describe("skill picker card", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-skill-picker-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;

		vi.resetModules();
		const db = await import("../../../src/storage/db.js");
		resetDatabase = db.resetDatabase;
		resetDatabase();

		({ skillPickerRenderer } = await import(
			"../../../src/telegram/cards/renderers/skill-picker.js"
		));
		({ CardKind } = await import("../../../src/telegram/cards/types.js"));
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("shows per-row promote buttons only for drafts", () => {
		const card = {
			...baseCard(CardKind.SkillPicker),
			state: {
				kind: CardKind.SkillPicker,
				title: "Skills",
				entries: [
					{ id: "draft-one", label: "draft-one", status: "draft" as const },
					{ id: "active-one", label: "active-one", status: "active" as const },
				],
				page: 0,
				view: "list" as const,
				adminControlsEnabled: true,
			},
		} as any;

		const render = skillPickerRenderer.render(card);
		const labels =
			render.keyboard?.inline_keyboard
				?.flat()
				.map((b) => ("text" in b ? b.text : "")) ?? [];
		expect(labels.some((l) => l.includes("Promote") && l.includes("draft-one"))).toBe(
			true,
		);
		expect(labels.some((l) => l.includes("active-one"))).toBe(true);
		// Reload + Cancel visible for admin
		expect(labels.filter((l) => l.includes("Reload")).length).toBeGreaterThan(0);
		expect(labels.filter((l) => l.includes("Cancel")).length).toBeGreaterThan(0);
	});

	it("hides admin controls when adminControlsEnabled is false", () => {
		const card = {
			...baseCard(CardKind.SkillPicker),
			state: {
				kind: CardKind.SkillPicker,
				title: "Skills",
				entries: [
					{ id: "draft-one", label: "draft-one", status: "draft" as const },
				],
				page: 0,
				view: "list" as const,
				adminControlsEnabled: false,
			},
		} as any;

		const render = skillPickerRenderer.render(card);
		const labels =
			render.keyboard?.inline_keyboard
				?.flat()
				.map((b) => ("text" in b ? b.text : "")) ?? [];
		// Only Refresh should be visible to non-admins
		expect(labels.some((l) => l.includes("Promote"))).toBe(false);
		expect(labels.some((l) => l.includes("Reload"))).toBe(false);
	});

	it("rejects select on active entries with a friendly callback", async () => {
		const card = {
			...baseCard(CardKind.SkillPicker),
			state: {
				kind: CardKind.SkillPicker,
				title: "Skills",
				entries: [
					{ id: "already-live", label: "already-live", status: "active" as const },
				],
				page: 0,
				view: "list" as const,
				adminControlsEnabled: true,
			},
		} as any;

		const result = await skillPickerRenderer.execute({
			action: { type: "select-0" },
			card,
			ctx: { from: { id: 101 } } as any,
		});
		expect(result.callbackText).toContain("already active");
	});

	it("blocks promote when admin controls are off", async () => {
		const card = {
			...baseCard(CardKind.SkillPicker),
			state: {
				kind: CardKind.SkillPicker,
				title: "Skills",
				entries: [
					{ id: "draft-one", label: "draft-one", status: "draft" as const },
				],
				page: 0,
				view: "list" as const,
				adminControlsEnabled: false,
			},
		} as any;

		const result = await skillPickerRenderer.execute({
			action: { type: "select-0" },
			card,
			ctx: { from: { id: 101 } } as any,
		});
		expect(result.callbackAlert).toBe(true);
		expect(result.callbackText).toContain("Only admin");
	});

	it("paginates via page-next without leaking cursor into the token", async () => {
		const entries = Array.from({ length: 20 }, (_, idx) => ({
			id: `skill-${idx}`,
			label: `skill-${idx}`,
			status: "active" as const,
		}));
		const card = {
			...baseCard(CardKind.SkillPicker),
			state: {
				kind: CardKind.SkillPicker,
				title: "Skills",
				entries,
				page: 0,
				view: "list" as const,
				adminControlsEnabled: true,
			},
		} as any;

		const result = await skillPickerRenderer.execute({
			action: { type: "page-next" },
			card,
			ctx: { from: { id: 101 } } as any,
		});
		expect(result.state?.page).toBe(1);
		expect(result.rerender).toBe(true);
	});
});
