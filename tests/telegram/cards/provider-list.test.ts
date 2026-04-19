import { describe, expect, it } from "vitest";

import { providerListRenderer } from "../../../src/telegram/cards/renderers/provider-list.js";
import { CardKind } from "../../../src/telegram/cards/types.js";

function baseCard() {
	return {
		cardId: "p-1",
		shortId: "abcdef12",
		kind: CardKind.ProviderList,
		version: 1,
		chatId: 777,
		messageId: 9,
		actorScope: "user:101",
		entityRef: "provider-list",
		revision: 1,
		expiresAt: Date.now() + 60_000,
		status: "active" as const,
		createdAt: Date.now(),
		updatedAt: Date.now(),
	};
}

describe("provider list card", () => {
	it("renders list view with health icons", () => {
		const card = {
			...baseCard(),
			state: {
				kind: CardKind.ProviderList,
				title: "Providers",
				providers: [
					{
						id: "google",
						label: "Google Services",
						health: "ok" as const,
						description: "Gmail, Calendar, Drive, Contacts",
					},
					{
						id: "health-api",
						label: "Health API",
						health: "degraded" as const,
						detail: "3 failures in last hour",
					},
					{
						id: "bank-api",
						label: "Bank API",
						health: "auth_expired" as const,
					},
				],
				page: 0,
				view: "list" as const,
				canMutate: true,
			},
		} as any;

		const render = providerListRenderer.render(card);
		expect(render.text).toContain("Providers");
		expect(render.text).toContain("Google Services");
		expect(render.text).toContain("Health API");
		expect(render.text).toContain("Bank API");
		const kbFlat = render.keyboard?.inline_keyboard?.flat() ?? [];
		const labels = kbFlat.map((b) => ("text" in b ? b.text : ""));
		expect(labels.filter((l) => l.includes("Google")).length).toBeGreaterThan(0);
		expect(labels.filter((l) => l.includes("Add")).length).toBe(1);
		expect(labels.filter((l) => l.includes("Cancel")).length).toBe(1);
	});

	it("opens detail view with remediation command when selected", async () => {
		const card = {
			...baseCard(),
			state: {
				kind: CardKind.ProviderList,
				title: "Providers",
				providers: [
					{
						id: "google",
						label: "Google Services",
						health: "auth_expired" as const,
						detail: "auth expired: gmail",
						setupCommand: "providers setup google",
						oauthServiceId: "google",
					},
				],
				page: 0,
				view: "list" as const,
				canMutate: true,
			},
		} as any;

		const result = await providerListRenderer.execute({
			action: { type: "select-0" },
			card,
			ctx: { from: { id: 101 } } as any,
		});
		expect(result.state?.view).toBe("detail");
		expect(result.state?.selectedProviderId).toBe("google");

		const detailCard = { ...card, state: result.state! } as any;
		const render = providerListRenderer.render(detailCard);
		expect(render.text).toContain("Google Services");
		// MarkdownV2 escapes underscores, so the rendered form uses a backslash.
		expect(render.text).toContain("auth\\_expired");
		expect(render.text).toContain("providers setup google");
		const kbFlat = render.keyboard?.inline_keyboard?.flat() ?? [];
		const labels = kbFlat.map((b) => ("text" in b ? b.text : ""));
		expect(labels.filter((l) => l.includes("Edit")).length).toBe(1);
		expect(labels.filter((l) => l.includes("Remove")).length).toBe(1);
	});

	it("paginates server-side; token carries only the action verb", async () => {
		const providers = Array.from({ length: 20 }, (_, idx) => ({
			id: `p-${idx}`,
			label: `Provider ${idx}`,
			health: "ok" as const,
		}));
		const card = {
			...baseCard(),
			state: {
				kind: CardKind.ProviderList,
				title: "Providers",
				providers,
				page: 0,
				view: "list" as const,
				canMutate: true,
			},
		} as any;

		const nextResult = await providerListRenderer.execute({
			action: { type: "page-next" },
			card,
			ctx: { from: { id: 101 } } as any,
		});
		expect(nextResult.state?.page).toBe(1);
	});

	it("falls back to list view if the selected provider is missing", () => {
		const card = {
			...baseCard(),
			state: {
				kind: CardKind.ProviderList,
				title: "Providers",
				providers: [
					{
						id: "google",
						label: "Google",
						health: "ok" as const,
					},
				],
				selectedProviderId: "missing-id",
				page: 0,
				view: "detail" as const,
				canMutate: true,
			},
		} as any;

		const render = providerListRenderer.render(card);
		expect(render.text).toContain("Tap a provider");
	});

	it("does not expose provider mutation buttons to non-admin viewers", () => {
		const card = {
			...baseCard(),
			state: {
				kind: CardKind.ProviderList,
				title: "Providers",
				providers: [
					{
						id: "google",
						label: "Google Services",
						health: "ok" as const,
					},
				],
				selectedProviderId: "google",
				page: 0,
				view: "detail" as const,
				canMutate: false,
			},
		} as any;

		const render = providerListRenderer.render(card);
		const kbFlat = render.keyboard?.inline_keyboard?.flat() ?? [];
		const labels = kbFlat.map((b) => ("text" in b ? b.text : ""));
		expect(labels.some((label) => label.includes("Edit"))).toBe(false);
		expect(labels.some((label) => label.includes("Remove"))).toBe(false);
	});

	it("rejects provider mutation actions at handler time for non-admin viewers", async () => {
		for (const action of ["add", "edit", "remove"] as const) {
			const card = {
				...baseCard(),
				state: {
					kind: CardKind.ProviderList,
					title: "Providers",
					providers: [
						{
							id: "google",
							label: "Google Services",
							health: "ok" as const,
						},
					],
					selectedProviderId: action === "add" ? undefined : "google",
					page: 0,
					view: action === "add" ? ("list" as const) : ("detail" as const),
					canMutate: true,
				},
			} as any;

			const result = await providerListRenderer.execute({
				action: { type: action },
				card,
				ctx: { from: { id: 101 }, api: {} } as any,
			});

			expect(result.callbackAlert).toBe(true);
			expect(result.callbackText).toBe(
				action === "add"
					? "Only admin can add providers."
					: action === "edit"
						? "Only admin can edit providers."
						: "Only admin can remove providers.",
			);
		}
	});
});
