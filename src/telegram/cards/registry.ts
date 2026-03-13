import type { CardKind, CardRenderer } from "./types.js";

export class CardRegistry {
	private readonly renderers = new Map<CardKind, CardRenderer<CardKind>>();

	register<K extends CardKind>(kind: K, renderer: CardRenderer<K>): void {
		this.renderers.set(kind, renderer as CardRenderer<CardKind>);
	}

	has(kind: CardKind): boolean {
		return this.renderers.has(kind);
	}

	get<K extends CardKind>(kind: K): CardRenderer<K> {
		const renderer = this.renderers.get(kind);
		if (!renderer) {
			throw new Error(`No card renderer registered for ${kind}`);
		}
		return renderer as CardRenderer<K>;
	}
}

export const cardRegistry = new CardRegistry();
