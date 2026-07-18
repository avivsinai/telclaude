import crypto from "node:crypto";
import type { TelclaudeConfig } from "../config/config.js";
import { resolveWhatsAppHouseholdBindingById } from "../config/profiles.js";
import type { CronActionResult } from "../cron/types.js";
import { sortKeysDeep } from "../crypto/canonical-hash.js";
import { EdgeAdapterSchemaVersions } from "../hermes/edge-adapter-contract.js";
import type { TelclaudeEdgeRuntime } from "../hermes/edge-adapter-runtime.js";
import type { TelclaudeMcpLedgerExecuteDependencies } from "../hermes/mcp/ledger-execute.js";
import type {
	TelclaudeMcpScheduledOutboundSideEffectPrepareInput,
	TelclaudeMcpScheduledOutboundSideEffectRecord,
	TelclaudeMcpSideEffectLedger,
	TelclaudeMcpSideEffectRecord,
} from "../hermes/mcp/side-effect-ledger.js";
import {
	type RelayConversation,
	type RelayConversationStore,
	relayAuthorityActorRefFor,
	relayConversationToConversationRef,
	targetableRelayConversationMembers,
} from "../hermes/relay-conversation-store.js";
import { recordHouseholdMetric } from "../household-metrics/store.js";
import type { OutboundDeliveryFailureClassifier } from "../relay/outbound-delivery-dispatcher.js";
import { type HouseholdReminderContext, resolveHouseholdReminderContext } from "./binding.js";
import { revokeHouseholdBindingDurableState } from "./reconcile.js";
import { householdReminderWhatsAppMessageId, renderHouseholdReminderBody } from "./render.js";
import {
	claimHouseholdReminderFire,
	completeHouseholdReminderFire,
	failHouseholdReminderFire,
	getHouseholdReminderPolicySnapshot,
	getHouseholdReminderRevisionForFire,
	householdReminderBindingFingerprint,
	householdReminderConsentHash,
	markHouseholdReminderFireDispatched,
	markHouseholdReminderFirePrepared,
} from "./store.js";
import {
	type HouseholdReminderSystemOriginDeliveryTarget,
	householdReminderScheduledOutboundIdempotencyKey,
} from "./system-origin-policy.js";
import type { HouseholdReminder, HouseholdReminderFire, Sha256Ref } from "./types.js";

const DEFAULT_LEASE_MS = 60_000;
const DEFAULT_MAX_ATTEMPTS = 3;
const RETRY_BACKOFF_MS = [30_000, 120_000, 600_000] as const;

export type HouseholdReminderPreparedFire = {
	readonly outboundRef: `scheduled-effect:${string}`;
	readonly edgePreparedHash: Sha256Ref;
	readonly idempotencyKey: string;
	readonly whatsappMessageId: string;
};

export type HouseholdReminderFireExecution =
	| {
			readonly ok: true;
			readonly receiptStatus: string;
			readonly platformMessageId?: string;
	  }
	| {
			readonly ok: false;
			readonly failureClass: string;
			readonly retryable: boolean;
	  };

export type HouseholdReminderFireExecutorDependencies = {
	readonly prepare: (input: {
		readonly reminder: HouseholdReminder;
		readonly fire: HouseholdReminderFire;
		readonly body: string;
	}) => Promise<HouseholdReminderPreparedFire>;
	readonly execute: (input: {
		readonly outboundRef: `scheduled-effect:${string}`;
		readonly beforeDispatch: () => boolean;
	}) => Promise<HouseholdReminderFireExecution>;
	readonly nowMs?: () => number;
	readonly leaseMs?: number;
	readonly maxAttempts?: number;
};

export type HouseholdReminderLiveDeliveryTarget = HouseholdReminderSystemOriginDeliveryTarget & {
	readonly conversation: RelayConversation;
};

export type HouseholdReminderFirePreparationDependencies = {
	readonly config: TelclaudeConfig;
	readonly conversationStore: RelayConversationStore;
	readonly edgeRuntime: TelclaudeEdgeRuntime;
	readonly ledger: TelclaudeMcpSideEffectLedger;
};

export function readHouseholdReminderKillSwitches(
	authority: HouseholdReminder["authority"],
	config: TelclaudeConfig,
	globalEnabled = process.env.TELCLAUDE_HOUSEHOLD_REMINDERS_ENABLED === "1",
): {
	readonly globalEnabled: boolean;
	readonly householdEnabled: boolean;
	readonly parentEnabled: boolean;
} {
	const context = resolveHouseholdReminderContext(authority, config);
	const binding = context
		? resolveWhatsAppHouseholdBindingById(context.binding.bindingId, config)
		: null;
	return {
		globalEnabled,
		householdEnabled: config.householdReminders.enabled,
		parentEnabled: binding?.remindersEnabled === true,
	};
}

export function resolveHouseholdReminderLiveDeliveryTarget(input: {
	readonly context: HouseholdReminderContext;
	readonly config: TelclaudeConfig;
	readonly conversationStore: RelayConversationStore;
}): HouseholdReminderLiveDeliveryTarget | null {
	const binding = resolveWhatsAppHouseholdBindingById(
		input.context.binding.bindingId,
		input.config,
	);
	if (
		!binding ||
		binding.actorId !== input.context.authority.actorId ||
		binding.subjectUserId !== input.context.authority.subjectUserId ||
		binding.profile.id !== input.context.authority.profileId
	) {
		return null;
	}
	const conversations = input.conversationStore
		.list({ channel: "whatsapp", domain: "household", authorizationState: "authorized" })
		.filter(
			(conversation) =>
				conversation.conversationId === input.context.binding.conversationId &&
				conversation.profileId === input.context.authority.profileId &&
				conversation.humanPairingProvenance,
		);
	if (conversations.length !== 1) return null;
	const conversation = conversations[0];
	const recipient = targetableRelayConversationMembers(conversation).find(
		(member) =>
			member.actorId === input.context.authority.actorId &&
			member.principalId === binding.replyAddress &&
			member.principalHash === input.context.binding.recipientPrincipalHash &&
			member.identityAssurance === "strong_link" &&
			member.scopes.includes("message:reply"),
	);
	if (!recipient) return null;
	return {
		destination: binding.replyAddress,
		resolvedDestination: {
			kind: "address",
			addressRef: binding.replyAddress,
			conversationId: conversation.conversationId,
		},
		conversationRef: conversation.conversationId,
		conversation,
	};
}

export function createHouseholdReminderFirePreparation(
	dependencies: HouseholdReminderFirePreparationDependencies,
): HouseholdReminderFireExecutorDependencies["prepare"] {
	return async ({ reminder, fire, body }) => {
		const snapshot = getHouseholdReminderPolicySnapshot(
			reminder.id,
			reminder.revision,
			reminder.authority,
		);
		if (
			snapshot?.reminder.status !== "scheduled" ||
			snapshot.reminder.schedule.resolvedAtMs !== fire.scheduledForMs ||
			body !== renderHouseholdReminderBody(snapshot.reminder)
		) {
			throw new Error("confirmed household reminder revision is unavailable");
		}
		const context = resolveHouseholdReminderContext(reminder.authority, dependencies.config);
		if (
			!context ||
			householdReminderBindingFingerprint(context.binding) !== reminder.bindingFingerprint ||
			householdReminderConsentHash(context.consent) !== reminder.consentHash
		) {
			if (!resolveWhatsAppHouseholdBindingById(reminder.binding.bindingId, dependencies.config)) {
				const revokedAtMs = Date.now();
				revokeHouseholdBindingDurableState({
					bindingId: reminder.binding.bindingId,
					nowMs: revokedAtMs,
					conversationStore: dependencies.conversationStore,
				});
			}
			throw new Error("household reminder context changed");
		}
		const target = resolveHouseholdReminderLiveDeliveryTarget({
			context,
			config: dependencies.config,
			conversationStore: dependencies.conversationStore,
		});
		if (!target) throw new Error("household reminder destination is unavailable");
		const prepared = dependencies.edgeRuntime.prepareOutbound({
			authorizingActor: relayAuthorityActorRefFor(target.conversation),
			request: {
				schemaVersion: EdgeAdapterSchemaVersions.outboundRequest,
				channel: "whatsapp",
				recipient: { kind: "address", addressRef: target.destination },
				requestedBody: body,
				mediaRefs: [],
				conversationRef: relayConversationToConversationRef(target.conversation),
				correlationId: `household-reminder-fire:${fire.fireId}`,
			},
		});
		if (
			prepared.resolvedDestination.kind !== "address" ||
			prepared.resolvedDestination.addressRef !== target.destination ||
			prepared.resolvedDestination.conversationId !== target.conversationRef
		) {
			throw new Error("household reminder edge destination changed");
		}
		const idempotencyKey = householdReminderScheduledOutboundIdempotencyKey({
			policyVersion: "phase0.v1",
			reminderId: reminder.id,
			revision: reminder.revision,
			scheduledForMs: reminder.schedule.resolvedAtMs,
			contentHash: reminder.contentHash,
			recipientPrincipalHash: context.binding.recipientPrincipalHash,
		});
		const outboundRef = `scheduled-effect:${fire.fireId}` as const;
		const input: TelclaudeMcpScheduledOutboundSideEffectPrepareInput = {
			kind: "scheduled-outbound",
			ref: outboundRef,
			source: "household-reminder-system.v1",
			actorId: reminder.authority.actorId,
			profileId: reminder.authority.profileId,
			domain: "household",
			subjectUserId: reminder.authority.subjectUserId,
			channel: "whatsapp",
			destination: target.destination,
			resolvedDestination: target.resolvedDestination,
			requestedBody: body,
			renderedBody: body,
			preparedMediaRefs: [],
			conversationRef: target.conversationRef,
			edgePreparedRef: prepared.outboundRef,
			edgePreparedHash: prepared.edgePreparedHash,
			idempotencyKey,
			householdReminderPolicy: {
				reminderId: reminder.id,
				fireId: fire.fireId,
				revision: reminder.revision,
				...(snapshot.authorization.kind === "parent-confirmed"
					? {
							authorizationKind: "parent-confirmed" as const,
							confirmedProposalHash: snapshot.authorization.proposalHash,
						}
					: {
							authorizationKind: "appointment-derived" as const,
							sourceObservationHash: snapshot.authorization.observationHash,
						}),
				scheduleHash: reminder.scheduleHash,
				contentHash: reminder.contentHash,
				bindingFingerprint: reminder.bindingFingerprint,
				actorId: reminder.authority.actorId,
				subjectUserId: reminder.authority.subjectUserId,
				profileId: reminder.authority.profileId,
				recipientPrincipalHash: context.binding.recipientPrincipalHash,
				systemPolicyPrincipal: "telclaude:household-reminder-system",
				systemPolicyVersion: "phase0.v1",
			},
		};
		const existing = dependencies.ledger.get(outboundRef);
		const record = existing
			? reusableScheduledRecord(existing, input)
			: dependencies.ledger.prepare(input);
		return {
			outboundRef,
			edgePreparedHash: record.edgePreparedHash as Sha256Ref,
			idempotencyKey: record.idempotencyKey,
			whatsappMessageId: householdReminderWhatsAppMessageId(record.idempotencyKey),
		};
	};
}

export function createHouseholdReminderScheduledExecution(input: {
	readonly execute: TelclaudeMcpLedgerExecuteDependencies["scheduledOutboundExecute"];
	readonly failureClassifier: OutboundDeliveryFailureClassifier;
}): HouseholdReminderFireExecutorDependencies["execute"] {
	return async ({ outboundRef, beforeDispatch }) => {
		input.failureClassifier.take(outboundRef);
		const result = await input.execute({ outboundRef, beforeDispatch });
		const classification = input.failureClassifier.take(outboundRef);
		if (!result.ok) {
			return {
				ok: false,
				failureClass: classification?.failureClass ?? result.code,
				retryable: classification?.retryable ?? result.retryable,
			};
		}
		return {
			ok: true,
			receiptStatus: result.receipt.deliveryStatus,
			...(result.receipt.platformMessageId
				? { platformMessageId: result.receipt.platformMessageId }
				: {}),
		};
	};
}

export function createHouseholdReminderFireExecutor(
	dependencies: HouseholdReminderFireExecutorDependencies,
): (
	input: { readonly reminderId: string; readonly revision: number },
	signal: AbortSignal,
) => Promise<CronActionResult> {
	const nowMs = dependencies.nowMs ?? Date.now;
	const leaseMs = dependencies.leaseMs ?? DEFAULT_LEASE_MS;
	const maxAttempts = dependencies.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
	return async (input, signal) => {
		if (signal.aborted) return { ok: false, message: "household reminder fire aborted" };
		const reminder = getHouseholdReminderRevisionForFire(input.reminderId, input.revision);
		if (reminder?.status !== "scheduled") {
			return { ok: true, message: "household reminder is no longer scheduled" };
		}
		const bindingKey = reminder.binding.bindingId;
		const now = nowMs();
		const claimed = claimHouseholdReminderFire({
			reminderId: reminder.id,
			revision: reminder.revision,
			scheduledForMs: reminder.schedule.resolvedAtMs,
			nowMs: now,
			leaseMs,
			maxAttempts,
		});
		if (!claimed.acquired) {
			if (claimed.fire.state === "delivered" || claimed.fire.state === "dead_lettered") {
				return { ok: true, message: `household reminder fire is ${claimed.fire.state}` };
			}
			if (claimed.fire.attemptCount >= maxAttempts && (claimed.fire.leaseExpiresAtMs ?? 0) < now) {
				return terminalFailure(
					claimed.fire,
					"reminder_attempts_exhausted",
					now,
					maxAttempts,
					bindingKey,
				);
			}
			const retryAtMs = Math.max(now + 1, (claimed.fire.leaseExpiresAtMs ?? now) + 1);
			return { ok: false, message: "household reminder fire lease is held", retryAtMs };
		}
		recordHouseholdMetric("fire_started", bindingKey, now);

		let prepared: HouseholdReminderPreparedFire;
		try {
			prepared = await dependencies.prepare({
				reminder,
				fire: claimed.fire,
				body: renderHouseholdReminderBody(reminder),
			});
		} catch {
			return terminalFailure(claimed.fire, "reminder_prepare_failed", now, maxAttempts, bindingKey);
		}
		const stored = markHouseholdReminderFirePrepared({
			fireId: claimed.fire.fireId,
			attemptCount: claimed.fire.attemptCount,
			...prepared,
			nowMs: nowMs(),
		});
		if (!stored)
			return terminalFailure(
				claimed.fire,
				"reminder_prepare_drift",
				nowMs(),
				maxAttempts,
				bindingKey,
			);

		let execution: HouseholdReminderFireExecution;
		try {
			execution = await dependencies.execute({
				outboundRef: prepared.outboundRef,
				beforeDispatch: () =>
					markHouseholdReminderFireDispatched({
						fireId: stored.fireId,
						attemptCount: stored.attemptCount,
						nowMs: nowMs(),
					}) !== null,
			});
		} catch {
			return terminalFailure(stored, "reminder_execute_failed", nowMs(), maxAttempts, bindingKey);
		}
		if (!execution.ok) {
			const failureNowMs = nowMs();
			const failed = failHouseholdReminderFire({
				fireId: stored.fireId,
				attemptCount: stored.attemptCount,
				failureClass: execution.failureClass,
				retryable: execution.retryable,
				maxAttempts,
				nowMs: failureNowMs,
			});
			recordHouseholdMetric("delivery_failed", bindingKey, failureNowMs);
			if (failed?.state === "retryable_failed") {
				return {
					ok: false,
					message: execution.failureClass,
					retryAtMs: nowMs() + retryBackoffMs(failed.attemptCount),
				};
			}
			return { ok: false, message: execution.failureClass };
		}
		const completionNowMs = nowMs();
		const completed = completeHouseholdReminderFire({
			fireId: stored.fireId,
			attemptCount: stored.attemptCount,
			receiptStatus: execution.receiptStatus,
			...(execution.platformMessageId
				? { platformMessageIdHash: digest(execution.platformMessageId) }
				: {}),
			nowMs: completionNowMs,
		});
		if (completed) {
			recordHouseholdMetric("delivery_succeeded", bindingKey, completionNowMs);
			return { ok: true, message: "household reminder delivered" };
		}
		const retryNowMs = nowMs();
		recordHouseholdMetric("delivery_failed", bindingKey, retryNowMs);
		return {
			ok: false,
			message: "household reminder receipt persistence failed",
			retryAtMs: Math.max(retryNowMs + 1, (stored.leaseExpiresAtMs ?? retryNowMs) + 1),
		};
	};
}

function terminalFailure(
	fire: HouseholdReminderFire,
	failureClass: string,
	nowMs: number,
	maxAttempts: number,
	bindingKey: string,
): CronActionResult {
	failHouseholdReminderFire({
		fireId: fire.fireId,
		attemptCount: fire.attemptCount,
		failureClass,
		retryable: false,
		maxAttempts,
		nowMs,
	});
	recordHouseholdMetric("delivery_failed", bindingKey, nowMs);
	return { ok: false, message: failureClass };
}

function retryBackoffMs(attemptCount: number): number {
	return RETRY_BACKOFF_MS[Math.min(attemptCount - 1, RETRY_BACKOFF_MS.length - 1)] ?? 600_000;
}

function digest(value: string): Sha256Ref {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function reusableScheduledRecord(
	record: TelclaudeMcpSideEffectRecord,
	input: TelclaudeMcpScheduledOutboundSideEffectPrepareInput,
): TelclaudeMcpScheduledOutboundSideEffectRecord {
	if (
		record.kind !== "scheduled-outbound" ||
		record.status !== "prepared" ||
		input.ref === undefined ||
		record.ref !== input.ref ||
		record.source !== input.source ||
		record.actorId !== input.actorId ||
		record.profileId !== input.profileId ||
		record.subjectUserId !== input.subjectUserId ||
		record.destination !== input.destination ||
		record.conversationRef !== input.conversationRef ||
		record.requestedBody !== input.requestedBody ||
		record.renderedBody !== input.renderedBody ||
		record.edgePreparedRef !== input.edgePreparedRef ||
		record.edgePreparedHash !== input.edgePreparedHash ||
		record.idempotencyKey !== input.idempotencyKey ||
		!sameJson(record.resolvedDestination, input.resolvedDestination) ||
		!sameJson(record.householdReminderPolicy, input.householdReminderPolicy)
	) {
		throw new Error("scheduled household reminder record changed");
	}
	return record;
}

function sameJson(left: unknown, right: unknown): boolean {
	return JSON.stringify(sortKeysDeep(left)) === JSON.stringify(sortKeysDeep(right));
}
