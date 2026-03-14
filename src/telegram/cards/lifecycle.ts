import {
	type CreateCardInput,
	createCard,
	expireStaleCards,
	getActiveCardsByEntity,
	getExpiredActiveCards,
	supersedeActiveCards,
	updateCard,
} from "./store.js";
import type { CardInstance, CardKind } from "./types.js";

export function createActiveCard<K extends CardKind>(input: CreateCardInput<K>): CardInstance<K> {
	return createCard({
		...input,
		status: "active",
	});
}

export function createOrSupersedeCard<K extends CardKind>(
	input: CreateCardInput<K>,
	options?: { supersedeExisting?: boolean },
): { card: CardInstance<K>; supersededCount: number; supersededCards: CardInstance[] } {
	let supersededCards: CardInstance[] = [];
	if (options?.supersedeExisting !== false) {
		// Collect cards that will be superseded BEFORE marking them
		supersededCards = getActiveCardsByEntity({
			kind: input.kind,
			chatId: input.chatId,
			entityRef: input.entityRef,
		});
		supersedeActiveCards({
			kind: input.kind,
			chatId: input.chatId,
			entityRef: input.entityRef,
		});
	}
	const card = createActiveCard(input);
	return { card, supersededCount: supersededCards.length, supersededCards };
}

export function markCardConsumed<K extends CardKind>(
	card: CardInstance<K>,
	expectedRevision = card.revision,
): CardInstance<K> | null {
	return updateCard({
		cardId: card.cardId,
		expectedRevision,
		patch: { status: "consumed" },
	});
}

export function markCardExpired<K extends CardKind>(
	card: CardInstance<K>,
	expectedRevision = card.revision,
): CardInstance<K> | null {
	return updateCard({
		cardId: card.cardId,
		expectedRevision,
		patch: { status: "expired" },
	});
}

export function markCardSuperseded<K extends CardKind>(
	card: CardInstance<K>,
	expectedRevision = card.revision,
): CardInstance<K> | null {
	return updateCard({
		cardId: card.cardId,
		expectedRevision,
		patch: { status: "superseded" },
	});
}

export function supersedeCardsForEntity(params: {
	kind: CardKind;
	chatId: number;
	entityRef: string;
	excludeCardId?: string;
}): number {
	return supersedeActiveCards(params);
}

export function sweepExpiredCards(now = Date.now()): { count: number; cards: CardInstance[] } {
	const cards = getExpiredActiveCards(now);
	const count = expireStaleCards(now);
	return { count, cards };
}

export function isCardTerminal(card: CardInstance): boolean {
	return card.status !== "active";
}

export function hasCardExpired(card: CardInstance, now = Date.now()): boolean {
	return card.expiresAt <= now || card.status === "expired";
}
