/**
 * Card Creation Helpers
 *
 * Convenience functions that command handlers call to create and send cards.
 * Each helper:
 * 1. Supersedes any active card of the same kind/entity in the chat.
 * 2. Creates a CardInstance in the store.
 * 3. Renders it using the registry.
 * 4. Sends the Telegram message with text + keyboard.
 * 5. Updates the card with the actual messageId.
 * 6. Returns the card instance.
 */

import type { Api } from "grammy";
import { getChildLogger } from "../../logging.js";
import { createOrSupersedeCard } from "./lifecycle.js";
import { buildSkillsMenuState, buildSocialMenuState } from "./menu-state.js";
import { cardRegistry } from "./registry.js";
import { editCardMessage, renderCardSnapshot, sameCardRender } from "./rendering.js";
import {
	getActiveCardsByEntity,
	getCard,
	patchMessageId,
	supersedeActiveCards,
	touchCard,
	updateCard,
} from "./store.js";
import type {
	ApprovalCardState,
	ApprovalScopeCardState,
	AuthCardState,
	BackgroundJobCardState,
	BackgroundJobListCardState,
	CardActorScope,
	CardInstance,
	CardKind,
	CardListEntry,
	HeartbeatCardState,
	ModelPickerCardState,
	PendingQueueCardState,
	ProviderListCardState,
	SessionCardState,
	SkillDraftCardState,
	SkillPickerCardState,
	SkillReviewCardState,
	SkillsMenuCardState,
	SocialMenuCardState,
	StatusCardState,
	SystemHealthCardState,
} from "./types.js";
import { CardKind as CK } from "./types.js";

const logger = getChildLogger({ module: "telegram-card-helpers" });

/** Default card expiry: 30 minutes. */
const DEFAULT_EXPIRY_MS = 30 * 60 * 1000;

/**
 * Re-render a terminal card (superseded/expired) to remove stale buttons.
 * Re-fetches the card from DB to get the post-update status so
 * `renderTerminalState` sees the correct terminal state.
 * Best-effort — ignores failures since the message may have been deleted.
 */
export async function rerenderTerminalCard(api: Api, card: CardInstance): Promise<void> {
	try {
		// Re-fetch to get post-update status (the passed card may be a pre-update snapshot)
		const current = getCard(card.cardId) ?? card;
		const renderer = cardRegistry.get(current.kind);
		const render = renderer.render(current);
		await api.editMessageText(current.chatId, current.messageId, render.text, {
			parse_mode: render.parseMode,
			reply_markup: render.keyboard ?? undefined,
		});
	} catch {
		// Best effort — message may have been deleted or already modified
	}
}

/** Approval card expiry: 5 minutes (matches approval TTL). */
const APPROVAL_EXPIRY_MS = 5 * 60 * 1000;

type BaseCardOptions = {
	actorScope: CardActorScope;
	threadId?: number;
	expiryMs?: number;
	entityRef?: string;
};

/**
 * Internal: create or update a card, then send/edit the Telegram message.
 *
 * Upsert behaviour: if an active card with the same kind/chatId/entityRef
 * already exists and has a valid Telegram messageId, we update its state
 * in-place and edit the existing message.  This avoids superseding the old
 * card (which would orphan its buttons and cause "Card outdated" on click).
 *
 * For new cards we use patchMessageId (no revision bump) to record the
 * Telegram messageId — this is bookkeeping, not a state change, so it must
 * not invalidate the callback tokens baked into the just-sent buttons.
 */
async function createAndSendCard<K extends CardKind>(
	api: Api,
	chatId: number,
	kind: K,
	state: CardInstance<K>["state"],
	options: BaseCardOptions,
): Promise<CardInstance<K>> {
	const expiryMs = options.expiryMs ?? DEFAULT_EXPIRY_MS;
	const entityRef = options.entityRef ?? kind;

	// ── Upsert path: edit existing card in place ──────────────────────
	// Only reuse a card that matches thread and actor scope, AND whose
	// message was updated recently enough to still be visible in the chat.
	// Editing a message that's scrolled far up is invisible to the user.
	const UPSERT_MAX_AGE_MS = 5 * 60 * 1000; // 5 minutes
	const activeCards = getActiveCardsByEntity({ kind, chatId, entityRef });
	const now = Date.now();
	const existing = activeCards.find(
		(c) =>
			c.messageId > 0 &&
			c.actorScope === options.actorScope &&
			(c.threadId ?? undefined) === options.threadId &&
			now - c.updatedAt < UPSERT_MAX_AGE_MS,
	) as CardInstance<K> | undefined;

	if (existing) {
		const renderer = cardRegistry.get(kind);
		const nextExpiresAt = Date.now() + expiryMs;
		const currentRender = renderCardSnapshot(existing, renderer);
		const comparisonCard: CardInstance<K> = {
			...existing,
			state,
			expiresAt: nextExpiresAt,
			updatedAt: Date.now(),
		};
		const comparisonRender = renderCardSnapshot(comparisonCard, renderer);

		if (sameCardRender(currentRender.snapshot, comparisonRender.snapshot)) {
			const touched = touchCard<K>({
				cardId: existing.cardId,
				expectedRevision: existing.revision,
				patch: { expiresAt: nextExpiresAt },
			});
			if (touched) {
				logger.debug(
					{ cardId: touched.cardId, kind, chatId, messageId: touched.messageId },
					"card reused without visible Telegram diff",
				);
				return touched;
			}
		}

		const updated = updateCard<K>({
			cardId: existing.cardId,
			expectedRevision: existing.revision,
			patch: {
				state,
				expiresAt: nextExpiresAt,
			},
		});

		if (updated) {
			// Supersede any other active duplicates to restore single-live-card invariant
			if (activeCards.length > 1) {
				supersedeActiveCards({ kind, chatId, entityRef, excludeCardId: updated.cardId });
				for (const dup of activeCards) {
					if (dup.cardId !== updated.cardId && dup.messageId > 0) {
						rerenderTerminalCard(api, dup).catch(() => {});
					}
				}
			}

			try {
				const editResult = await editCardMessage(api, updated, renderer.render(updated));
				if (editResult === "not_modified") {
					logger.debug(
						{ cardId: updated.cardId, kind, chatId, messageId: updated.messageId },
						"in-place card edit produced no Telegram diff",
					);
					const current = getCard<K>(updated.cardId);
					return current ?? updated;
				}
				logger.debug(
					{ cardId: updated.cardId, kind, chatId, messageId: updated.messageId },
					"card updated in place",
				);
				return updated;
			} catch (editErr) {
				// Edit failed (message deleted, too old, etc.) — fall through to create new
				logger.debug(
					{ cardId: updated.cardId, error: String(editErr) },
					"in-place edit failed, falling through to new card",
				);
			}
		}
	}

	// ── Create path: new card + new Telegram message ─────────────────
	const { card, supersededCards } = createOrSupersedeCard<K>({
		kind,
		chatId,
		messageId: 0, // placeholder until we send
		threadId: options.threadId,
		actorScope: options.actorScope,
		entityRef,
		state,
		expiresAt: Date.now() + expiryMs,
	});

	// Re-render superseded cards to remove stale buttons
	for (const old of supersededCards) {
		if (old.messageId > 0) {
			rerenderTerminalCard(api, old).catch((err) => {
				logger.debug(
					{ cardId: old.cardId, error: String(err) },
					"failed to re-render superseded card",
				);
			});
		}
	}

	// Render and send
	const renderer = cardRegistry.get(kind);
	const render = renderer.render(card);

	try {
		const msg = await api.sendMessage(chatId, render.text, {
			parse_mode: render.parseMode,
			reply_markup: render.keyboard ?? undefined,
			message_thread_id: options.threadId,
		});

		// Record the real messageId WITHOUT bumping revision —
		// buttons already carry revision=1 and must stay valid.
		patchMessageId(card.cardId, msg.message_id);

		const finalCard = { ...card, messageId: msg.message_id };
		logger.debug({ cardId: card.cardId, kind, chatId, messageId: msg.message_id }, "card sent");
		return finalCard;
	} catch (err) {
		logger.error(
			{ cardId: card.cardId, kind, chatId, error: String(err) },
			"failed to send card message",
		);
		throw err;
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Public Helpers
// ═══════════════════════════════════════════════════════════════════════════════

export async function sendApprovalCard(
	api: Api,
	chatId: number,
	opts: {
		title: string;
		body: string;
		nonce: string;
		actorScope: CardActorScope;
		threadId?: number;
	},
): Promise<CardInstance<typeof CK.Approval>> {
	const state: ApprovalCardState = {
		kind: CK.Approval,
		title: opts.title,
		body: opts.body,
	};
	return createAndSendCard(api, chatId, CK.Approval, state, {
		actorScope: opts.actorScope,
		threadId: opts.threadId,
		expiryMs: APPROVAL_EXPIRY_MS,
		entityRef: `approval:${opts.nonce}`,
	});
}

/**
 * W1 — Graduated approval card. Offers once / session / always / deny buttons.
 *
 * `scopesEnabled` defaults to all three approve scopes; callers should trim
 * it to match the risk cap ("high" → ["once"] only).
 */
export async function sendApprovalScopeCard(
	api: Api,
	chatId: number,
	opts: {
		title: string;
		body: string;
		nonce: string;
		toolKey: string;
		riskTier: ApprovalScopeCardState["riskTier"];
		scopesEnabled?: ApprovalScopeCardState["scopesEnabled"];
		explanation?: string;
		actorScope: CardActorScope;
		threadId?: number;
	},
): Promise<CardInstance<typeof CK.ApprovalScope>> {
	const defaultScopes: ApprovalScopeCardState["scopesEnabled"] =
		opts.riskTier === "high" ? ["once"] : ["once", "session", "always"];
	const state: ApprovalScopeCardState = {
		kind: CK.ApprovalScope,
		title: opts.title,
		body: opts.body,
		toolKey: opts.toolKey,
		riskTier: opts.riskTier,
		scopesEnabled: opts.scopesEnabled ?? defaultScopes,
		explanation: opts.explanation,
	};
	return createAndSendCard(api, chatId, CK.ApprovalScope, state, {
		actorScope: opts.actorScope,
		threadId: opts.threadId,
		expiryMs: APPROVAL_EXPIRY_MS,
		entityRef: `approval:${opts.nonce}`,
	});
}

export async function sendPendingQueueCard(
	api: Api,
	chatId: number,
	opts: {
		entries: CardListEntry[];
		actorScope: CardActorScope;
		threadId?: number;
	},
): Promise<CardInstance<typeof CK.PendingQueue>> {
	const state: PendingQueueCardState = {
		kind: CK.PendingQueue,
		title: "Pending Queue",
		entries: opts.entries,
		total: opts.entries.length,
		page: 0,
	};
	return createAndSendCard(api, chatId, CK.PendingQueue, state, {
		actorScope: opts.actorScope,
		threadId: opts.threadId,
		entityRef: "pending-queue",
	});
}

export async function sendStatusCard(
	api: Api,
	chatId: number,
	opts: {
		title?: string;
		summary: string;
		details?: string[];
		actorScope: CardActorScope;
		threadId?: number;
		entityRef?: string;
		view?: StatusCardState["view"];
		sessionKey?: string;
	},
): Promise<CardInstance<typeof CK.Status>> {
	const state: StatusCardState = {
		kind: CK.Status,
		title: opts.title ?? "System Status",
		summary: opts.summary,
		details: opts.details,
		lastRefreshedAt: Date.now(),
		view: opts.view,
		sessionKey: opts.sessionKey,
	};
	return createAndSendCard(api, chatId, CK.Status, state, {
		actorScope: opts.actorScope,
		threadId: opts.threadId,
		entityRef: opts.entityRef ?? "system-status",
	});
}

export async function sendAuthCard(
	api: Api,
	chatId: number,
	opts: {
		step: AuthCardState["step"];
		summary?: string;
		localUserId?: string;
		actorScope: CardActorScope;
		threadId?: number;
	},
): Promise<CardInstance<typeof CK.Auth>> {
	const state: AuthCardState = {
		kind: CK.Auth,
		title: "Authentication",
		step: opts.step,
		summary: opts.summary,
		localUserId: opts.localUserId,
	};
	return createAndSendCard(api, chatId, CK.Auth, state, {
		actorScope: opts.actorScope,
		threadId: opts.threadId,
		entityRef: `auth:${opts.localUserId ?? chatId}`,
	});
}

export async function sendHeartbeatCard(
	api: Api,
	chatId: number,
	opts: {
		services: CardListEntry[];
		lastRunAt?: number;
		actorScope: CardActorScope;
		threadId?: number;
	},
): Promise<CardInstance<typeof CK.Heartbeat>> {
	const state: HeartbeatCardState = {
		kind: CK.Heartbeat,
		title: "Social Heartbeat",
		services: opts.services,
		lastRunAt: opts.lastRunAt,
	};
	return createAndSendCard(api, chatId, CK.Heartbeat, state, {
		actorScope: opts.actorScope,
		threadId: opts.threadId,
		entityRef: "heartbeat",
	});
}

export async function sendSkillDraftCard(
	api: Api,
	chatId: number,
	opts: {
		drafts: CardListEntry[];
		actorScope: CardActorScope;
		threadId?: number;
	},
): Promise<CardInstance<typeof CK.SkillDraft>> {
	const state: SkillDraftCardState = {
		kind: CK.SkillDraft,
		title: "Skill Drafts",
		drafts: opts.drafts,
		page: 0,
	};
	return createAndSendCard(api, chatId, CK.SkillDraft, state, {
		actorScope: opts.actorScope,
		threadId: opts.threadId,
		entityRef: "skill-drafts",
	});
}

export async function sendSkillsMenuCard(
	api: Api,
	chatId: number,
	opts: {
		actorScope: CardActorScope;
		threadId?: number;
		sessionKey?: string;
	},
): Promise<CardInstance<typeof CK.SkillsMenu>> {
	const state: SkillsMenuCardState = buildSkillsMenuState(chatId, opts.sessionKey);
	return createAndSendCard(api, chatId, CK.SkillsMenu, state, {
		actorScope: opts.actorScope,
		threadId: opts.threadId,
		entityRef: "skills-menu",
	});
}

export async function sendSocialMenuCard(
	api: Api,
	chatId: number,
	opts: {
		actorScope: CardActorScope;
		threadId?: number;
	},
): Promise<CardInstance<typeof CK.SocialMenu>> {
	const state: SocialMenuCardState = buildSocialMenuState(chatId);
	return createAndSendCard(api, chatId, CK.SocialMenu, state, {
		actorScope: opts.actorScope,
		threadId: opts.threadId,
		entityRef: "social-menu",
	});
}

export async function sendBackgroundJobCard(
	api: Api,
	chatId: number,
	opts: {
		state: BackgroundJobCardState;
		actorScope: CardActorScope;
		threadId?: number;
		/** Default 24h so terminal cards stay around for review. */
		expiryMs?: number;
	},
): Promise<CardInstance<typeof CK.BackgroundJob>> {
	return createAndSendCard(api, chatId, CK.BackgroundJob, opts.state, {
		actorScope: opts.actorScope,
		threadId: opts.threadId,
		expiryMs: opts.expiryMs ?? 24 * 60 * 60 * 1000,
		entityRef: `bg:${opts.state.shortId}`,
	});
}

export async function sendBackgroundJobListCard(
	api: Api,
	chatId: number,
	opts: {
		state: BackgroundJobListCardState;
		actorScope: CardActorScope;
		threadId?: number;
		expiryMs?: number;
	},
): Promise<CardInstance<typeof CK.BackgroundJobList>> {
	return createAndSendCard(api, chatId, CK.BackgroundJobList, opts.state, {
		actorScope: opts.actorScope,
		threadId: opts.threadId,
		expiryMs: opts.expiryMs ?? 30 * 60 * 1000,
		entityRef: "background-job-list",
	});
}

export async function sendSessionCard(
	api: Api,
	chatId: number,
	opts: {
		summary: string;
		sessionKey?: string;
		historyPreview?: string[];
		actorScope: CardActorScope;
		threadId?: number;
	},
): Promise<CardInstance<typeof CK.Session>> {
	const state: SessionCardState = {
		kind: CK.Session,
		title: "Session",
		summary: opts.summary,
		sessionKey: opts.sessionKey,
		historyPreview: opts.historyPreview,
	};
	return createAndSendCard(api, chatId, CK.Session, state, {
		actorScope: opts.actorScope,
		threadId: opts.threadId,
		entityRef: `session:${opts.sessionKey ?? chatId}`,
	});
}

/**
 * W10 — Send the `/system health` snapshot card.
 *
 * The caller builds a `SystemHealthCardState` (typically from
 * `collectSystemHealth()`) and this helper enforces a single live health
 * card per chat via the `system-health` entityRef.
 */
export async function sendSystemHealthCard(
	api: Api,
	chatId: number,
	opts: {
		state: SystemHealthCardState;
		actorScope: CardActorScope;
		threadId?: number;
		expiryMs?: number;
	},
): Promise<CardInstance<typeof CK.SystemHealth>> {
	return createAndSendCard(api, chatId, CK.SystemHealth, opts.state, {
		actorScope: opts.actorScope,
		threadId: opts.threadId,
		expiryMs: opts.expiryMs ?? 15 * 60 * 1000,
		entityRef: "system-health",
	});
}

export async function sendModelPickerCard(
	api: Api,
	chatId: number,
	opts: {
		state: ModelPickerCardState;
		actorScope: CardActorScope;
		threadId?: number;
		expiryMs?: number;
	},
): Promise<CardInstance<typeof CK.ModelPicker>> {
	return createAndSendCard(api, chatId, CK.ModelPicker, opts.state, {
		actorScope: opts.actorScope,
		threadId: opts.threadId,
		// 10-minute picker lifetime per W2 spec.
		expiryMs: opts.expiryMs ?? 10 * 60 * 1000,
		entityRef: "model-picker",
	});
}

export async function sendProviderListCard(
	api: Api,
	chatId: number,
	opts: {
		state: ProviderListCardState;
		actorScope: CardActorScope;
		threadId?: number;
		expiryMs?: number;
	},
): Promise<CardInstance<typeof CK.ProviderList>> {
	return createAndSendCard(api, chatId, CK.ProviderList, opts.state, {
		actorScope: opts.actorScope,
		threadId: opts.threadId,
		expiryMs: opts.expiryMs ?? 10 * 60 * 1000,
		entityRef: "provider-list",
	});
}

export async function sendSkillPickerCard(
	api: Api,
	chatId: number,
	opts: {
		state: SkillPickerCardState;
		actorScope: CardActorScope;
		threadId?: number;
		expiryMs?: number;
	},
): Promise<CardInstance<typeof CK.SkillPicker>> {
	return createAndSendCard(api, chatId, CK.SkillPicker, opts.state, {
		actorScope: opts.actorScope,
		threadId: opts.threadId,
		expiryMs: opts.expiryMs ?? 10 * 60 * 1000,
		entityRef: "skill-picker",
	});
}

/**
 * W9 — Send the skill draft-review card. The caller assembles
 * `SkillReviewCardState` via `buildSkillReviewState` (see
 * `src/commands/skills-promote.ts`). `entityRef` includes the skill name so
 * per-skill reviews don't supersede each other when multiple drafts are
 * being triaged in sequence.
 */
export async function sendSkillReviewCard(
	api: Api,
	chatId: number,
	opts: {
		state: SkillReviewCardState;
		actorScope: CardActorScope;
		threadId?: number;
		expiryMs?: number;
	},
): Promise<CardInstance<typeof CK.SkillReview>> {
	return createAndSendCard(api, chatId, CK.SkillReview, opts.state, {
		actorScope: opts.actorScope,
		threadId: opts.threadId,
		expiryMs: opts.expiryMs ?? 15 * 60 * 1000,
		entityRef: `skill-review:${opts.state.skillName}`,
	});
}
