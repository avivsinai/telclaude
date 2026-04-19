import type { Api } from "grammy";
import type { CardInstance, CardKind, CardRenderer, CardRenderResult } from "./types.js";

export type CardRenderSnapshot = {
	text: string;
	parseMode: string | null;
	keyboard: string;
};

export function snapshotCardRender(render: CardRenderResult): CardRenderSnapshot {
	return {
		text: render.text,
		parseMode: render.parseMode ?? null,
		keyboard: JSON.stringify(render.keyboard?.inline_keyboard ?? null),
	};
}

export function renderCardSnapshot<K extends CardKind>(
	card: CardInstance<K>,
	renderer: CardRenderer<K>,
): {
	render: CardRenderResult;
	snapshot: CardRenderSnapshot;
} {
	const render = renderer.render(card);
	return {
		render,
		snapshot: snapshotCardRender(render),
	};
}

export function sameCardRender(a: CardRenderSnapshot, b: CardRenderSnapshot): boolean {
	return a.text === b.text && a.parseMode === b.parseMode && a.keyboard === b.keyboard;
}

export function isMessageNotModifiedError(error: unknown): boolean {
	return String(error).toLowerCase().includes("message is not modified");
}

export async function editCardMessage(
	api: Pick<Api, "editMessageText">,
	card: Pick<CardInstance, "chatId" | "messageId">,
	render: CardRenderResult,
): Promise<"updated" | "not_modified"> {
	try {
		await api.editMessageText(card.chatId, card.messageId, render.text, {
			parse_mode: render.parseMode,
			reply_markup: render.keyboard ?? undefined,
		});
		return "updated";
	} catch (error) {
		if (isMessageNotModifiedError(error)) {
			return "not_modified";
		}
		throw error;
	}
}
