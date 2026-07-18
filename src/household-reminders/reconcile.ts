import type { TelclaudeConfig } from "../config/config.js";
import type {
	RelayConversation,
	RelayConversationStore,
} from "../hermes/relay-conversation-store.js";
import { getDb } from "../storage/db.js";
import {
	type HouseholdReminderBindingRevocationResult,
	revokeHouseholdReminderBindingState,
} from "./store.js";

export type HouseholdReminderReconciliationResult = HouseholdReminderBindingRevocationResult & {
	readonly bindingsRevoked: number;
	readonly conversationsRevoked: number;
	readonly turnsRevoked: number;
	readonly mediaConfirmationsRevoked: number;
	readonly mediaContentRowsDeleted: number;
	readonly mediaDerivationsDeleted: number;
};

function revokeConversations(
	store: RelayConversationStore,
	conversations: readonly RelayConversation[],
	nowMs: number,
): { readonly conversationsRevoked: number; readonly turnsRevoked: number } {
	const turnsRevoked = conversations.reduce((count, conversation) => {
		const pending = getDb()
			.prepare(
				`SELECT COUNT(*) AS count FROM hermes_relay_conversation_turns
				 WHERE conversation_token = ? AND revoked_at_ms IS NULL`,
			)
			.get(conversation.token) as { count: number };
		store.revoke(conversation.token, "household binding removed", nowMs);
		return count + pending.count;
	}, 0);
	return { conversationsRevoked: conversations.length, turnsRevoked };
}

export function revokeHouseholdBindingDurableState(input: {
	readonly bindingId: string;
	readonly nowMs?: number;
	readonly conversationStore?: RelayConversationStore;
}): Omit<HouseholdReminderReconciliationResult, "bindingsRevoked"> {
	const nowMs = input.nowMs ?? Date.now();
	const reminders = revokeHouseholdReminderBindingState({
		bindingId: input.bindingId,
		nowMs,
	});
	const media = getDb().transaction(() => {
		const confirmations = getDb()
			.prepare(
				`UPDATE household_media_action_confirmations
				 SET status = 'revoked', resolved_at_ms = ?
				 WHERE binding_id = ? AND status = 'pending'`,
			)
			.run(nowMs, input.bindingId);
		const content = getDb()
			.prepare(
				`DELETE FROM household_media_action_confirmation_content
				 WHERE confirmation_id IN (
				   SELECT confirmation_id FROM household_media_action_confirmations
				   WHERE binding_id = ? AND status = 'revoked'
				 )`,
			)
			.run(input.bindingId);
		const derivations = getDb()
			.prepare("DELETE FROM household_media_turn_derivations WHERE binding_id = ?")
			.run(input.bindingId);
		const leases = getDb()
			.prepare(
				`DELETE FROM household_interactive_choice_leases
				 WHERE binding_id = ? AND owner_kind = 'media_confirmation'`,
			)
			.run(input.bindingId);
		return {
			mediaConfirmationsRevoked: confirmations.changes,
			mediaContentRowsDeleted: content.changes,
			mediaDerivationsDeleted: derivations.changes,
			mediaLeasesReleased: leases.changes,
		};
	})();
	const conversations = input.conversationStore
		? input.conversationStore
				.list({ channel: "whatsapp", domain: "household" })
				.filter(
					(conversation) =>
						conversation.revokedAtMs === null &&
						conversation.conversationId === `whatsapp:household:${input.bindingId}`,
				)
		: [];
	const revokedConversations = input.conversationStore
		? revokeConversations(input.conversationStore, conversations, nowMs)
		: { conversationsRevoked: 0, turnsRevoked: 0 };
	return {
		...reminders,
		leasesReleased: reminders.leasesReleased + media.mediaLeasesReleased,
		mediaConfirmationsRevoked: media.mediaConfirmationsRevoked,
		mediaContentRowsDeleted: media.mediaContentRowsDeleted,
		mediaDerivationsDeleted: media.mediaDerivationsDeleted,
		...revokedConversations,
	};
}

export function reconcileHouseholdReminderBindings(
	config: Pick<TelclaudeConfig, "profiles">,
	nowMs = Date.now(),
	conversationStore?: RelayConversationStore,
): HouseholdReminderReconciliationResult {
	const liveBindingIds = new Set(
		(config.profiles ?? []).flatMap((profile) =>
			(profile.whatsappHouseholdBindings ?? []).map((binding) => binding.bindingId),
		),
	);
	const storedBindingIds = getDb()
		.prepare(
			`SELECT binding_id FROM household_reminders
			 WHERE status IN ('pending_confirmation','scheduled','paused_confirmation')
			 UNION SELECT binding_id FROM household_media_action_confirmations WHERE status = 'pending'
			 UNION SELECT binding_id FROM household_media_turn_derivations
			 UNION SELECT binding_id FROM household_interactive_choice_leases
			 ORDER BY binding_id`,
		)
		.all() as Array<{ binding_id: string }>;
	const revoked = storedBindingIds
		.map((row) => row.binding_id)
		.filter((bindingId) => !liveBindingIds.has(bindingId));
	const totals: HouseholdReminderReconciliationResult = {
		bindingsRevoked: revoked.length,
		conversationsRevoked: 0,
		turnsRevoked: 0,
		remindersCancelled: 0,
		firesDeadLettered: 0,
		proposalsExpired: 0,
		leasesReleased: 0,
		mediaConfirmationsRevoked: 0,
		mediaContentRowsDeleted: 0,
		mediaDerivationsDeleted: 0,
	};
	const reminderResult = revoked.reduce<HouseholdReminderReconciliationResult>(
		(result, bindingId) => {
			const next = revokeHouseholdBindingDurableState({ bindingId, nowMs, conversationStore });
			return {
				bindingsRevoked: result.bindingsRevoked,
				conversationsRevoked: result.conversationsRevoked + next.conversationsRevoked,
				turnsRevoked: result.turnsRevoked + next.turnsRevoked,
				remindersCancelled: result.remindersCancelled + next.remindersCancelled,
				firesDeadLettered: result.firesDeadLettered + next.firesDeadLettered,
				proposalsExpired: result.proposalsExpired + next.proposalsExpired,
				leasesReleased: result.leasesReleased + next.leasesReleased,
				mediaConfirmationsRevoked:
					result.mediaConfirmationsRevoked + next.mediaConfirmationsRevoked,
				mediaContentRowsDeleted: result.mediaContentRowsDeleted + next.mediaContentRowsDeleted,
				mediaDerivationsDeleted: result.mediaDerivationsDeleted + next.mediaDerivationsDeleted,
			};
		},
		totals,
	);
	if (!conversationStore) return reminderResult;
	const liveConversationIds = new Set(
		[...liveBindingIds].map((bindingId) => `whatsapp:household:${bindingId}`),
	);
	const removedConversations = conversationStore
		.list({ channel: "whatsapp", domain: "household" })
		.filter(
			(conversation) =>
				conversation.revokedAtMs === null && !liveConversationIds.has(conversation.conversationId),
		);
	const revokedConversations = revokeConversations(conversationStore, removedConversations, nowMs);
	return {
		...reminderResult,
		conversationsRevoked:
			reminderResult.conversationsRevoked + revokedConversations.conversationsRevoked,
		turnsRevoked: reminderResult.turnsRevoked + revokedConversations.turnsRevoked,
	};
}
