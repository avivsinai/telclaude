/**
 * W9 — SkillReview card renderer tests.
 *
 * Focus:
 *   - Render surfaces scanner counts, trust badge, and auto-install hits.
 *   - Promote/Reject buttons are gated on admin controls + scannerBlocked.
 *   - Reject transitions to consumed status without touching the draft.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let CardKind: typeof import("../../../src/telegram/cards/types.js").CardKind;
let skillReviewRenderer: typeof import(
	"../../../src/telegram/cards/renderers/skill-review.js"
).skillReviewRenderer;
let resetDatabase: typeof import("../../../src/storage/db.js").resetDatabase;

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

type SkillReviewCardState = import(
	"../../../src/telegram/cards/types.js"
).SkillReviewCardState;

function baseCard(state: SkillReviewCardState) {
	return {
		cardId: "sr-1",
		shortId: "abcdef12",
		kind: state.kind,
		version: 1,
		chatId: 777,
		messageId: 9,
		actorScope: "user:101" as const,
		entityRef: `skill-review:${state.skillName}`,
		revision: 1,
		expiresAt: Date.now() + 60_000,
		status: "active" as const,
		createdAt: Date.now(),
		updatedAt: Date.now(),
		state,
	};
}

describe("skill review card", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-skill-review-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;

		vi.resetModules();
		const db = await import("../../../src/storage/db.js");
		resetDatabase = db.resetDatabase;
		resetDatabase();

		({ CardKind } = await import("../../../src/telegram/cards/types.js"));
		({ skillReviewRenderer } = await import(
			"../../../src/telegram/cards/renderers/skill-review.js"
		));
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	function makeState(overrides: Partial<SkillReviewCardState> = {}): SkillReviewCardState {
		return {
			kind: CardKind.SkillReview,
			title: "Review Skill",
			skillName: "sample-skill",
			description: "Sample skill description.",
			findingSummary: [
				{ severity: "medium", count: 2 },
				{ severity: "info", count: 1 },
			],
			totalFindings: 3,
			scannerBlocked: false,
			topFindings: [],
			trust: "community",
			trustDetail: undefined,
			autoInstallPatterns: [],
			adminControlsEnabled: true,
			diffSummary: "+5 lines (draft 40, active 35)",
			...overrides,
		};
	}

	it("renders the community badge for unsigned skills without blocking promote", () => {
		const card = baseCard(makeState());
		const render = skillReviewRenderer.render(card);
		expect(render.text).toContain("community");
		const labels =
			render.keyboard?.inline_keyboard?.flat().map((b) => ("text" in b ? b.text : "")) ?? [];
		expect(labels.some((l) => l.includes("Promote"))).toBe(true);
		expect(labels.some((l) => l.includes("Reject"))).toBe(true);
	});

	it("renders the trusted badge when trust=trusted", () => {
		const card = baseCard(
			makeState({ trust: "trusted", trustDetail: "sha256:abcdef1234…" }),
		);
		const render = skillReviewRenderer.render(card);
		expect(render.text).toContain("trusted");
		expect(render.text).toContain("sha256:abcdef");
	});

	it("disables promote when the scanner blocks the skill", async () => {
		const card = baseCard(
			makeState({
				scannerBlocked: true,
				findingSummary: [
					{ severity: "high", count: 1 },
					{ severity: "medium", count: 1 },
				],
				topFindings: [
					{ severity: "high", message: "Shell exec directive", file: "SKILL.md" },
				],
			}),
		);
		const render = skillReviewRenderer.render(card);
		expect(render.text).toContain("Blocked by scanner");
		const labels =
			render.keyboard?.inline_keyboard?.flat().map((b) => ("text" in b ? b.text : "")) ?? [];
		expect(labels.some((l) => l.includes("Promote"))).toBe(false);
		// Reject is still allowed (admin can dismiss the review)
		expect(labels.some((l) => l.includes("Reject"))).toBe(true);

		const result = await skillReviewRenderer.execute({
			action: { type: "promote" },
			card,
			ctx: { from: { id: 101 } } as never,
		});
		expect(result.callbackAlert).toBe(true);
		expect(result.callbackText).toContain("blocked");
	});

	it("hides promote/reject when admin controls are off", () => {
		const card = baseCard(makeState({ adminControlsEnabled: false }));
		const render = skillReviewRenderer.render(card);
		const labels =
			render.keyboard?.inline_keyboard?.flat().map((b) => ("text" in b ? b.text : "")) ?? [];
		expect(labels.some((l) => l.includes("Promote"))).toBe(false);
		expect(labels.some((l) => l.includes("Reject"))).toBe(false);
	});

	it("reject marks the card consumed without calling promoteSkill", async () => {
		const card = baseCard(makeState());
		const result = await skillReviewRenderer.execute({
			action: { type: "reject" },
			card,
			ctx: { from: { id: 101 } } as never,
		});
		expect(result.status).toBe("consumed");
		expect(result.state?.decision).toBe("rejected");
		expect(result.callbackText).toContain("Rejected");
	});

	it("surfaces auto-install patterns in the rendered text", () => {
		const card = baseCard(
			makeState({ autoInstallPatterns: ["brew install jq", "npx foo"] }),
		);
		const render = skillReviewRenderer.render(card);
		expect(render.text).toContain("Auto-install");
		expect(render.text).toContain("brew install");
	});
});
