import type { CallbackQueryContext, Context } from "grammy";
import type { PermissionTier } from "../../config/config.js";
import { getChildLogger } from "../../logging.js";
import type { AuditLogger } from "../../security/audit.js";
import { isAdmin } from "../../security/linking.js";
import { parseCallbackToken } from "./callback-tokens.js";
import { markCardExpired } from "./lifecycle.js";
import { type CardRegistry, cardRegistry } from "./registry.js";
import { editCardMessage, renderCardSnapshot, sameCardRender } from "./rendering.js";
import { getCard, getCardByShortId, touchCard, updateCard } from "./store.js";
import { type CardInstance, type CardKind, type CardRenderer, parseCardAction } from "./types.js";

const logger = getChildLogger({ module: "telegram-card-callbacks" });
const CALLBACK_ACK_TIMEOUT_MS = 1_500;

const CARD_KIND_TO_TIER: Record<CardKind, PermissionTier> = {
	Approval: "FULL_ACCESS",
	ApprovalScope: "FULL_ACCESS",
	PendingQueue: "SOCIAL",
	Status: "READ_ONLY",
	Auth: "WRITE_LOCAL",
	Heartbeat: "SOCIAL",
	SkillDraft: "WRITE_LOCAL",
	SkillsMenu: "READ_ONLY",
	SocialMenu: "SOCIAL",
	Session: "WRITE_LOCAL",
	BackgroundJob: "WRITE_LOCAL",
	BackgroundJobList: "READ_ONLY",
	SystemHealth: "READ_ONLY",
	ModelPicker: "READ_ONLY",
	ProviderList: "READ_ONLY",
	SkillPicker: "WRITE_LOCAL",
	SkillReview: "WRITE_LOCAL",
};

type CallbackHandlerOptions = {
	auditLogger?: AuditLogger;
	registry?: CardRegistry;
};

function resolveChatThreadId(ctx: CallbackQueryContext<Context>): number | undefined {
	const message = ctx.callbackQuery.message;
	if (!message || !("message_thread_id" in message)) {
		return undefined;
	}
	return message.message_thread_id;
}

function actorMatchesScope(scope: string, ctx: CallbackQueryContext<Context>): boolean {
	const chatId = ctx.chat?.id;
	const actorId = ctx.from.id;

	if (scope === "admin") {
		return chatId !== undefined && isAdmin(chatId);
	}
	if (scope.startsWith("user:")) {
		const scopedUserId = Number.parseInt(scope.slice(5), 10);
		return Number.isInteger(scopedUserId) && scopedUserId === actorId;
	}
	if (scope.startsWith("chat:")) {
		const scopedChatId = Number.parseInt(scope.slice(5), 10);
		return Number.isInteger(scopedChatId) && chatId === scopedChatId;
	}

	// Fail closed: unrecognized scope format rejects. All callers must use typed prefixes.
	return false;
}

function chatMatchesCard(ctx: CallbackQueryContext<Context>, card: CardInstance): boolean {
	return ctx.chat?.id === card.chatId;
}

function threadMatchesCard(ctx: CallbackQueryContext<Context>, card: CardInstance): boolean {
	if (card.threadId === undefined) {
		return true;
	}
	return resolveChatThreadId(ctx) === card.threadId;
}

async function renderCardMessage<K extends CardKind>(
	ctx: CallbackQueryContext<Context>,
	card: CardInstance<K>,
	renderer: CardRenderer<K>,
): Promise<void> {
	try {
		const result = await editCardMessage(ctx.api, card, renderer.render(card));
		if (result === "not_modified") {
			return;
		}
	} catch (error) {
		logger.warn(
			{ cardId: card.cardId, chatId: card.chatId, messageId: card.messageId, error: String(error) },
			"failed to re-render card message",
		);
	}
}

function createCallbackResponder(ctx: CallbackQueryContext<Context>) {
	let answered = false;
	const timer = setTimeout(() => {
		if (answered) {
			return;
		}
		answered = true;
		void ctx.answerCallbackQuery().catch((error) => {
			logger.debug({ error: String(error) }, "callback ack fallback failed");
		});
	}, CALLBACK_ACK_TIMEOUT_MS);

	return {
		async answer(params?: { text?: string; show_alert?: boolean }): Promise<void> {
			clearTimeout(timer);
			if (answered) {
				return;
			}
			answered = true;
			if (params) {
				await ctx.answerCallbackQuery(params);
				return;
			}
			await ctx.answerCallbackQuery();
		},
		cancel(): void {
			clearTimeout(timer);
		},
	};
}

async function logCallbackAudit(
	auditLogger: AuditLogger | undefined,
	params: {
		card?: CardInstance;
		shortId: string;
		action: string;
		chatId: number;
		actorId: number;
		username?: string;
		outcome: "success" | "blocked" | "error";
		errorType?: string;
	},
): Promise<void> {
	if (!auditLogger) {
		return;
	}

	await auditLogger.log({
		timestamp: new Date(),
		requestId: `cardcb_${params.shortId}_${Date.now()}`,
		telegramUserId: String(params.actorId),
		telegramUsername: params.username,
		chatId: params.chatId,
		messagePreview: params.card
			? `card:${params.card.kind}:${params.action}:${params.card.entityRef}`
			: `card:${params.shortId}:${params.action}`,
		permissionTier: params.card ? CARD_KIND_TO_TIER[params.card.kind] : "READ_ONLY",
		outcome: params.outcome,
		errorType: params.errorType,
	});
}

export async function handleCallback(
	ctx: CallbackQueryContext<Context>,
	options: CallbackHandlerOptions = {},
): Promise<void> {
	const rawData = ctx.callbackQuery.data;
	const token = parseCallbackToken(rawData);
	const registry = options.registry ?? cardRegistry;
	const actorId = ctx.from.id;
	const chatId = ctx.chat?.id ?? 0;

	if (!token) {
		await ctx.answerCallbackQuery({ text: "Invalid card action", show_alert: true });
		await logCallbackAudit(options.auditLogger, {
			shortId: "invalid",
			action: "invalid",
			chatId,
			actorId,
			username: ctx.from.username,
			outcome: "blocked",
			errorType: "invalid_callback_token",
		});
		return;
	}

	const card = getCardByShortId(token.shortId);
	if (!card) {
		await ctx.answerCallbackQuery({ text: "Card not found", show_alert: true });
		await logCallbackAudit(options.auditLogger, {
			shortId: token.shortId,
			action: token.action,
			chatId,
			actorId,
			username: ctx.from.username,
			outcome: "blocked",
			errorType: "card_not_found",
		});
		return;
	}

	const action = parseCardAction(card.kind, token.action);
	if (!action) {
		await ctx.answerCallbackQuery({ text: "Unknown card action", show_alert: true });
		await logCallbackAudit(options.auditLogger, {
			card,
			shortId: token.shortId,
			action: token.action,
			chatId: card.chatId,
			actorId,
			username: ctx.from.username,
			outcome: "blocked",
			errorType: "unknown_card_action",
		});
		return;
	}

	let renderer: CardRenderer<CardKind>;
	try {
		renderer = registry.get(card.kind);
	} catch (error) {
		logger.error(
			{ cardId: card.cardId, kind: card.kind, error: String(error) },
			"card renderer missing",
		);
		await ctx.answerCallbackQuery({ text: "Card type unavailable", show_alert: true });
		await logCallbackAudit(options.auditLogger, {
			card,
			shortId: token.shortId,
			action: token.action,
			chatId: card.chatId,
			actorId,
			username: ctx.from.username,
			outcome: "error",
			errorType: "renderer_missing",
		});
		return;
	}

	if (!actorMatchesScope(card.actorScope, ctx)) {
		await ctx.answerCallbackQuery({ text: "Not authorized for this card", show_alert: true });
		await logCallbackAudit(options.auditLogger, {
			card,
			shortId: token.shortId,
			action: token.action,
			chatId: card.chatId,
			actorId,
			username: ctx.from.username,
			outcome: "blocked",
			errorType: "actor_scope_mismatch",
		});
		return;
	}

	if (!chatMatchesCard(ctx, card) || !threadMatchesCard(ctx, card)) {
		await ctx.answerCallbackQuery({ text: "Card no longer matches this chat", show_alert: true });
		await logCallbackAudit(options.auditLogger, {
			card,
			shortId: token.shortId,
			action: token.action,
			chatId: card.chatId,
			actorId,
			username: ctx.from.username,
			outcome: "blocked",
			errorType: "chat_scope_mismatch",
		});
		return;
	}

	if (card.status === "consumed") {
		await renderCardMessage(ctx, card, renderer);
		await ctx.answerCallbackQuery({ text: "Already processed" });
		await logCallbackAudit(options.auditLogger, {
			card,
			shortId: token.shortId,
			action: token.action,
			chatId: card.chatId,
			actorId,
			username: ctx.from.username,
			outcome: "success",
			errorType: "already_consumed",
		});
		return;
	}

	if (card.expiresAt <= Date.now() || card.status === "expired") {
		const expiredCard =
			card.status === "expired" ? card : (markCardExpired(card) ?? getCard(card.cardId) ?? card);
		await renderCardMessage(ctx, expiredCard, renderer);
		await ctx.answerCallbackQuery({ text: "Card expired", show_alert: true });
		await logCallbackAudit(options.auditLogger, {
			card: expiredCard,
			shortId: token.shortId,
			action: token.action,
			chatId: expiredCard.chatId,
			actorId,
			username: ctx.from.username,
			outcome: "blocked",
			errorType: "card_expired",
		});
		return;
	}

	if (card.status === "superseded") {
		await renderCardMessage(ctx, card, renderer);
		await ctx.answerCallbackQuery({ text: "Card outdated", show_alert: true });
		await logCallbackAudit(options.auditLogger, {
			card,
			shortId: token.shortId,
			action: token.action,
			chatId: card.chatId,
			actorId,
			username: ctx.from.username,
			outcome: "blocked",
			errorType: "card_superseded",
		});
		return;
	}

	if (card.revision !== token.revision) {
		await renderCardMessage(ctx, card, renderer);
		await ctx.answerCallbackQuery({ text: "Card outdated", show_alert: true });
		await logCallbackAudit(options.auditLogger, {
			card,
			shortId: token.shortId,
			action: token.action,
			chatId: card.chatId,
			actorId,
			username: ctx.from.username,
			outcome: "blocked",
			errorType: "stale_revision",
		});
		return;
	}

	const responder = createCallbackResponder(ctx);

	try {
		const execution = await renderer.execute({ ctx, card, action });
		const currentCard = getCard(card.cardId) ?? card;
		if (currentCard.status === "consumed") {
			await renderCardMessage(ctx, currentCard, renderer);
			await responder.answer({ text: "Already processed" });
			await logCallbackAudit(options.auditLogger, {
				card: currentCard,
				shortId: token.shortId,
				action: token.action,
				chatId: currentCard.chatId,
				actorId,
				username: ctx.from.username,
				outcome: "success",
				errorType: "already_consumed",
			});
			return;
		}

		if (currentCard.status === "superseded" || currentCard.revision !== card.revision) {
			await renderCardMessage(ctx, currentCard, renderer);
			await responder.answer({ text: "Card outdated", show_alert: true });
			await logCallbackAudit(options.auditLogger, {
				card: currentCard,
				shortId: token.shortId,
				action: token.action,
				chatId: currentCard.chatId,
				actorId,
				username: ctx.from.username,
				outcome: "blocked",
				errorType: currentCard.status === "superseded" ? "card_superseded" : "revision_conflict",
			});
			return;
		}

		if (currentCard.expiresAt <= Date.now() || currentCard.status === "expired") {
			const expiredCard =
				currentCard.status === "expired"
					? currentCard
					: (markCardExpired(currentCard, currentCard.revision) ??
						getCard(currentCard.cardId) ??
						currentCard);
			await renderCardMessage(ctx, expiredCard, renderer);
			await responder.answer({ text: "Card expired", show_alert: true });
			await logCallbackAudit(options.auditLogger, {
				card: expiredCard,
				shortId: token.shortId,
				action: token.action,
				chatId: expiredCard.chatId,
				actorId,
				username: ctx.from.username,
				outcome: "blocked",
				errorType: "card_expired",
			});
			return;
		}

		const nextState = execution.state ?? renderer.reduce(currentCard, action);
		const nextStatus = execution.status ?? currentCard.status;
		const nextExpiresAt = execution.expiresAt ?? currentCard.expiresAt;
		const comparisonCurrent = renderCardSnapshot(currentCard, renderer);
		const comparisonCandidate = renderCardSnapshot(
			{
				...currentCard,
				state: nextState,
				status: nextStatus,
				expiresAt: nextExpiresAt,
			},
			renderer,
		);

		let finalCard = currentCard;
		const visibleChange = sameCardRender(comparisonCurrent.snapshot, comparisonCandidate.snapshot)
			? false
			: execution.rerender !== false;

		if (!visibleChange) {
			const touched = touchCard({
				cardId: currentCard.cardId,
				expectedRevision: currentCard.revision,
				patch: nextExpiresAt === currentCard.expiresAt ? undefined : { expiresAt: nextExpiresAt },
			});
			if (!touched) {
				const latestCard = getCard(card.cardId) ?? currentCard;
				await renderCardMessage(ctx, latestCard, renderer);
				await responder.answer({ text: "Card outdated", show_alert: true });
				await logCallbackAudit(options.auditLogger, {
					card: latestCard,
					shortId: token.shortId,
					action: token.action,
					chatId: latestCard.chatId,
					actorId,
					username: ctx.from.username,
					outcome: "blocked",
					errorType: "revision_conflict",
				});
				return;
			}
			finalCard = touched;
		} else {
			const updatedCard = updateCard({
				cardId: currentCard.cardId,
				expectedRevision: currentCard.revision,
				patch: {
					state: nextState,
					status: nextStatus,
					expiresAt: nextExpiresAt,
				},
			});

			if (!updatedCard) {
				const latestCard = getCard(card.cardId) ?? currentCard;
				await renderCardMessage(ctx, latestCard, renderer);
				await responder.answer({ text: "Card outdated", show_alert: true });
				await logCallbackAudit(options.auditLogger, {
					card: latestCard,
					shortId: token.shortId,
					action: token.action,
					chatId: latestCard.chatId,
					actorId,
					username: ctx.from.username,
					outcome: "blocked",
					errorType: "revision_conflict",
				});
				return;
			}

			finalCard = updatedCard;
			await renderCardMessage(ctx, updatedCard, renderer);
		}

		await responder.answer({
			text:
				execution.callbackText ?? (finalCard.status === "consumed" ? "Processed" : "Card updated"),
			show_alert: execution.callbackAlert ?? false,
		});

		await logCallbackAudit(options.auditLogger, {
			card: finalCard,
			shortId: token.shortId,
			action: token.action,
			chatId: finalCard.chatId,
			actorId,
			username: ctx.from.username,
			outcome: "success",
		});

		if (execution.afterCommit) {
			void Promise.resolve(execution.afterCommit()).catch((afterCommitError) => {
				logger.error(
					{
						cardId: finalCard.cardId,
						kind: finalCard.kind,
						action: token.action,
						error: String(afterCommitError),
					},
					"card post-commit action failed",
				);
			});
		}
	} catch (error) {
		logger.error(
			{ cardId: card.cardId, kind: card.kind, action: token.action, error: String(error) },
			"card callback execution failed",
		);
		await responder.answer({ text: "Card action failed", show_alert: true });
		await logCallbackAudit(options.auditLogger, {
			card,
			shortId: token.shortId,
			action: token.action,
			chatId: card.chatId,
			actorId,
			username: ctx.from.username,
			outcome: "error",
			errorType: "callback_execute_failed",
		});
	} finally {
		responder.cancel();
	}
}
