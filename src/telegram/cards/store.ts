import { randomBytes, randomUUID } from "node:crypto";
import { getChildLogger } from "../../logging.js";
import { getDb } from "../../storage/db.js";
import type { CardInstance, CardKind, CardState, CardStatus } from "./types.js";

const logger = getChildLogger({ module: "telegram-card-store" });

type CardInstanceRow = {
	card_id: string;
	short_id: string;
	kind: CardKind;
	version: number;
	chat_id: number;
	message_id: number;
	thread_id: number | null;
	actor_scope: string;
	entity_ref: string;
	revision: number;
	state: string;
	expires_at: number;
	status: CardStatus;
	created_at: number;
	updated_at: number;
};

export type CreateCardInput<K extends CardKind> = {
	cardId?: string;
	shortId?: string;
	kind: K;
	version?: number;
	chatId: number;
	messageId: number;
	threadId?: number;
	actorScope: string;
	entityRef: string;
	revision?: number;
	state: CardState<K>;
	expiresAt: number;
	status?: CardStatus;
	createdAt?: number;
	updatedAt?: number;
};

export type UpdateCardPatch<K extends CardKind> = Partial<
	Pick<
		CardInstance<K>,
		"messageId" | "threadId" | "actorScope" | "entityRef" | "state" | "expiresAt" | "status"
	>
>;

function generateShortId(): string {
	return randomBytes(4).toString("hex");
}

function isShortIdConflict(error: unknown): boolean {
	const message = String(error);
	return (
		message.includes("card_instances.short_id") ||
		message.includes("UNIQUE constraint failed: card_instances.short_id")
	);
}

function hydrateCardState<K extends CardKind>(kind: K, raw: string): CardState<K> {
	const parsed = JSON.parse(raw) as Record<string, unknown>;
	if (typeof parsed !== "object" || parsed === null) {
		throw new Error(`Invalid card state payload for ${kind}`);
	}
	if (parsed.kind !== kind) {
		return { ...parsed, kind } as CardState<K>;
	}
	return parsed as CardState<K>;
}

function rowToCard<K extends CardKind>(row: CardInstanceRow & { kind: K }): CardInstance<K> {
	return {
		cardId: row.card_id,
		shortId: row.short_id,
		kind: row.kind,
		version: row.version,
		chatId: row.chat_id,
		messageId: row.message_id,
		threadId: row.thread_id ?? undefined,
		actorScope: row.actor_scope,
		entityRef: row.entity_ref,
		revision: row.revision,
		state: hydrateCardState(row.kind, row.state),
		expiresAt: row.expires_at,
		status: row.status,
		createdAt: row.created_at,
		updatedAt: row.updated_at,
	};
}

export function createCard<K extends CardKind>(input: CreateCardInput<K>): CardInstance<K> {
	const db = getDb();
	const cardId = input.cardId ?? randomUUID();
	const version = input.version ?? 1;
	const revision = input.revision ?? 1;
	const status = input.status ?? "active";
	const createdAt = input.createdAt ?? Date.now();
	const updatedAt = input.updatedAt ?? createdAt;
	const insert = db.prepare(
		`INSERT INTO card_instances (
			card_id, short_id, kind, version, chat_id, message_id, thread_id,
			actor_scope, entity_ref, revision, state, expires_at, status, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	);

	for (let attempt = 0; attempt < 10; attempt++) {
		const shortId = input.shortId ?? generateShortId();
		const card: CardInstance<K> = {
			cardId,
			shortId,
			kind: input.kind,
			version,
			chatId: input.chatId,
			messageId: input.messageId,
			threadId: input.threadId,
			actorScope: input.actorScope,
			entityRef: input.entityRef,
			revision,
			state: input.state,
			expiresAt: input.expiresAt,
			status,
			createdAt,
			updatedAt,
		};

		try {
			insert.run(
				card.cardId,
				card.shortId,
				card.kind,
				card.version,
				card.chatId,
				card.messageId,
				card.threadId ?? null,
				card.actorScope,
				card.entityRef,
				card.revision,
				JSON.stringify(card.state),
				card.expiresAt,
				card.status,
				card.createdAt,
				card.updatedAt,
			);
			logger.debug({ cardId: card.cardId, shortId: card.shortId, kind: card.kind }, "card created");
			return card;
		} catch (error) {
			if (!input.shortId && isShortIdConflict(error)) {
				continue;
			}
			throw error;
		}
	}

	throw new Error("Failed to generate a collision-free card short ID");
}

export function getCard<K extends CardKind>(cardId: string): CardInstance<K> | null {
	const db = getDb();
	const row = db.prepare("SELECT * FROM card_instances WHERE card_id = ?").get(cardId) as
		| (CardInstanceRow & { kind: K })
		| undefined;
	return row ? rowToCard(row) : null;
}

export function getCardByShortId<K extends CardKind>(shortId: string): CardInstance<K> | null {
	const db = getDb();
	const row = db.prepare("SELECT * FROM card_instances WHERE short_id = ?").get(shortId) as
		| (CardInstanceRow & { kind: K })
		| undefined;
	return row ? rowToCard(row) : null;
}

export function updateCard<K extends CardKind>(params: {
	cardId: string;
	expectedRevision: number;
	patch?: UpdateCardPatch<K>;
}): CardInstance<K> | null {
	const db = getDb();
	const patch = params.patch ?? {};
	const sets: string[] = [];
	const values: unknown[] = [];

	if ("messageId" in patch) {
		sets.push("message_id = ?");
		values.push(patch.messageId);
	}
	if ("threadId" in patch) {
		sets.push("thread_id = ?");
		values.push(patch.threadId ?? null);
	}
	if ("actorScope" in patch) {
		sets.push("actor_scope = ?");
		values.push(patch.actorScope);
	}
	if ("entityRef" in patch) {
		sets.push("entity_ref = ?");
		values.push(patch.entityRef);
	}
	if ("state" in patch) {
		sets.push("state = ?");
		values.push(JSON.stringify(patch.state));
	}
	if ("expiresAt" in patch) {
		sets.push("expires_at = ?");
		values.push(patch.expiresAt);
	}
	if ("status" in patch) {
		sets.push("status = ?");
		values.push(patch.status);
	}

	const now = Date.now();
	sets.push("revision = revision + 1", "updated_at = ?");
	values.push(now, params.cardId, params.expectedRevision);

	const result = db
		.prepare(`UPDATE card_instances SET ${sets.join(", ")} WHERE card_id = ? AND revision = ?`)
		.run(...values);

	if (result.changes === 0) {
		return null;
	}

	return getCard<K>(params.cardId);
}

export function getActiveCardsByEntity(params: {
	kind: CardKind;
	chatId: number;
	entityRef: string;
	excludeCardId?: string;
}): CardInstance[] {
	const db = getDb();
	const query = params.excludeCardId
		? db.prepare(
				"SELECT * FROM card_instances WHERE kind = ? AND chat_id = ? AND entity_ref = ? AND status = 'active' AND card_id <> ? ORDER BY updated_at DESC",
			)
		: db.prepare(
				"SELECT * FROM card_instances WHERE kind = ? AND chat_id = ? AND entity_ref = ? AND status = 'active' ORDER BY updated_at DESC",
			);

	const rows = (
		params.excludeCardId
			? query.all(params.kind, params.chatId, params.entityRef, params.excludeCardId)
			: query.all(params.kind, params.chatId, params.entityRef)
	) as (CardInstanceRow & { kind: CardKind })[];

	return rows.map(rowToCard);
}

export function supersedeActiveCards(params: {
	kind: CardKind;
	chatId: number;
	entityRef: string;
	excludeCardId?: string;
}): number {
	const db = getDb();
	const now = Date.now();

	const result = params.excludeCardId
		? db
				.prepare(
					`UPDATE card_instances
					 SET status = 'superseded', revision = revision + 1, updated_at = ?
					 WHERE kind = ? AND chat_id = ? AND entity_ref = ? AND status = 'active' AND card_id <> ?`,
				)
				.run(now, params.kind, params.chatId, params.entityRef, params.excludeCardId)
		: db
				.prepare(
					`UPDATE card_instances
					 SET status = 'superseded', revision = revision + 1, updated_at = ?
					 WHERE kind = ? AND chat_id = ? AND entity_ref = ? AND status = 'active'`,
				)
				.run(now, params.kind, params.chatId, params.entityRef);

	if (result.changes > 0) {
		logger.debug(
			{
				kind: params.kind,
				chatId: params.chatId,
				entityRef: params.entityRef,
				changes: result.changes,
			},
			"active cards superseded",
		);
	}

	return result.changes;
}

/**
 * Update only the messageId without bumping revision.
 * Used after sending the Telegram message — this is bookkeeping,
 * not a state change, so it must not invalidate button callback tokens.
 */
export function patchMessageId(cardId: string, messageId: number): boolean {
	const db = getDb();
	const result = db
		.prepare("UPDATE card_instances SET message_id = ?, updated_at = ? WHERE card_id = ?")
		.run(messageId, Date.now(), cardId);
	return result.changes > 0;
}

export function getExpiredActiveCards(now = Date.now()): CardInstance[] {
	const db = getDb();
	const rows = db
		.prepare("SELECT * FROM card_instances WHERE status = 'active' AND expires_at <= ?")
		.all(now) as (CardInstanceRow & { kind: CardKind })[];
	return rows.map(rowToCard);
}

export function expireStaleCards(now = Date.now()): number {
	const db = getDb();
	const result = db
		.prepare(
			`UPDATE card_instances
			 SET status = 'expired', revision = revision + 1, updated_at = ?
			 WHERE status = 'active' AND expires_at <= ?`,
		)
		.run(now, now);

	if (result.changes > 0) {
		logger.debug({ expired: result.changes }, "stale cards expired");
	}

	return result.changes;
}
