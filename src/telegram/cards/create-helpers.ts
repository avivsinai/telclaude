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
import { updateCard } from "./store.js";
import type {
	ApprovalCardState,
	AuthCardState,
	CardActorScope,
	CardInstance,
	CardKind,
	CardListEntry,
	HeartbeatCardState,
	PendingQueueCardState,
	SessionCardState,
	SkillDraftCardState,
	SkillsMenuCardState,
	SocialMenuCardState,
	StatusCardState,
} from "./types.js";
import { CardKind as CK } from "./types.js";

const logger = getChildLogger({ module: "telegram-card-helpers" });

/** Default card expiry: 30 minutes. */
const DEFAULT_EXPIRY_MS = 30 * 60 * 1000;

/** Approval card expiry: 5 minutes (matches approval TTL). */
const APPROVAL_EXPIRY_MS = 5 * 60 * 1000;

type BaseCardOptions = {
	actorScope: CardActorScope;
	threadId?: number;
	expiryMs?: number;
	entityRef?: string;
};

/**
 * Internal: create a card, send the rendered message, update with messageId.
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

	// Create the card (supersedes any existing active card of same kind/entity)
	const { card } = createOrSupersedeCard<K>({
		kind,
		chatId,
		messageId: 0, // placeholder until we send
		threadId: options.threadId,
		actorScope: options.actorScope,
		entityRef,
		state,
		expiresAt: Date.now() + expiryMs,
	});

	// Render
	const renderer = cardRegistry.get(kind);
	const render = renderer.render(card);

	// Send Telegram message
	try {
		const msg = await api.sendMessage(chatId, render.text, {
			parse_mode: render.parseMode,
			reply_markup: render.keyboard ?? undefined,
			message_thread_id: options.threadId,
		});

		// Update card with the real message ID
		const updated = updateCard<K>({
			cardId: card.cardId,
			expectedRevision: card.revision,
			patch: { messageId: msg.message_id },
		});

		if (updated) {
			logger.debug(
				{ cardId: card.cardId, kind, chatId, messageId: msg.message_id },
				"card sent and updated with messageId",
			);
			return updated;
		}

		// Revision conflict (unlikely since we just created it)
		logger.warn({ cardId: card.cardId }, "revision conflict updating card messageId");
		return { ...card, messageId: msg.message_id };
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
	},
): Promise<CardInstance<typeof CK.Status>> {
	const state: StatusCardState = {
		kind: CK.Status,
		title: opts.title ?? "System Status",
		summary: opts.summary,
		details: opts.details,
		lastRefreshedAt: Date.now(),
		view: opts.view,
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
