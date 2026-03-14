import { beforeEach, describe, expect, it, vi } from "vitest";

let CardKind: typeof import("../../src/telegram/cards/types.js").CardKind;
let skillsMenuRenderer: typeof import("../../src/telegram/cards/renderers/skills-menu.js").skillsMenuRenderer;
let socialMenuRenderer: typeof import("../../src/telegram/cards/renderers/social-menu.js").socialMenuRenderer;

function makeBaseCard(kind: string) {
	return {
		cardId: `${kind}-1`,
		shortId: "abcdef12",
		kind,
		version: 1,
		chatId: 777,
		messageId: 55,
		threadId: 9,
		actorScope: "user:101",
		entityRef: kind,
		revision: 1,
		expiresAt: Date.now() + 60_000,
		status: "active" as const,
		createdAt: Date.now(),
		updatedAt: Date.now(),
	};
}

describe("menu cards", () => {
	beforeEach(async () => {
		vi.resetModules();
		({ CardKind } = await import("../../src/telegram/cards/types.js"));
		({ skillsMenuRenderer } = await import("../../src/telegram/cards/renderers/skills-menu.js"));
		({ socialMenuRenderer } = await import("../../src/telegram/cards/renderers/social-menu.js"));
	});

	it("hides admin-only skills actions and rejects forged reload callbacks", async () => {
		const card = {
			...makeBaseCard(CardKind.SkillsMenu),
			state: {
				kind: CardKind.SkillsMenu,
				title: "Skills",
				activeSkills: [{ id: "browser-automation", label: "browser-automation" }],
				draftCount: 2,
				adminControlsEnabled: false,
				sessionKey: "tg:101",
				lastRefreshedAt: Date.now(),
			},
		} as any;

		const render = skillsMenuRenderer.render(card);
		const buttonLabels =
			render.keyboard?.inline_keyboard.flat().map((button) => ("text" in button ? button.text : "")) ?? [];
		expect(buttonLabels).toEqual(["↻ Refresh"]);

		const result = await skillsMenuRenderer.execute({
			action: { type: "reload" },
			card,
			ctx: { api: {}, from: { id: 101 } },
		} as any);
		expect(result.callbackAlert).toBe(true);
		expect(result.callbackText).toBe("Only admin can reload skills.");
		expect(result.afterCommit).toBeUndefined();
	});

	it("defers social run side effects until after the card commit", async () => {
		const sendMessage = vi.fn(async () => ({ message_id: 99 }));
		const card = {
			...makeBaseCard(CardKind.SocialMenu),
			state: {
				kind: CardKind.SocialMenu,
				title: "Social",
				services: [{ id: "xtwitter", label: "xtwitter" }],
				queueCount: 1,
				adminControlsEnabled: true,
				lastRefreshedAt: Date.now(),
			},
		} as any;

		const result = await socialMenuRenderer.execute({
			action: { type: "run" },
			card,
			ctx: { api: { sendMessage }, from: { id: 101 } },
		} as any);

		expect(sendMessage).not.toHaveBeenCalled();
		expect(result.callbackAlert).toBeUndefined();
		expect(result.callbackText).toBe("Starting heartbeat for xtwitter");
		expect(result.afterCommit).toEqual(expect.any(Function));
	});
});
