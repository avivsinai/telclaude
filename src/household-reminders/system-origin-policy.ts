import crypto from "node:crypto";
import { sortKeysDeep } from "../crypto/canonical-hash.js";
import { edgePreparedPayloadHash } from "../hermes/edge-adapter-runtime.js";
import type {
	TelclaudeMcpOutboundResolvedDestination,
	TelclaudeMcpScheduledOutboundSideEffectRecord,
} from "../hermes/mcp/side-effect-ledger.js";
import type { HouseholdReminderContext } from "./binding.js";
import {
	getConfirmedHouseholdReminderPolicySnapshot,
	type HouseholdReminderConfirmedPolicySnapshot,
	householdReminderBindingFingerprint,
	householdReminderConsentHash,
} from "./store.js";
import type { HouseholdReminderAuthority, HouseholdReminderFire, Sha256Ref } from "./types.js";

export type HouseholdReminderSystemOriginPolicyFailure = {
	readonly ok: false;
	readonly code: string;
	readonly reason: string;
	readonly retryable: false;
};

export type HouseholdReminderSystemOriginPolicyResult =
	| { readonly ok: true }
	| HouseholdReminderSystemOriginPolicyFailure;

export type HouseholdReminderSystemOriginDeliveryTarget = {
	readonly destination: string;
	readonly resolvedDestination: TelclaudeMcpOutboundResolvedDestination;
	readonly conversationRef: string;
};

export type HouseholdReminderSystemOriginPolicyDependencies = {
	readonly readConfirmedPolicySnapshot?: typeof getConfirmedHouseholdReminderPolicySnapshot;
	readonly readFire: (fireId: string) => HouseholdReminderFire | null;
	readonly resolveContext: (
		authority: HouseholdReminderAuthority,
	) => HouseholdReminderContext | null;
	readonly readKillSwitches: (authority: HouseholdReminderAuthority) => {
		readonly globalEnabled: boolean;
		readonly householdEnabled: boolean;
		readonly parentEnabled: boolean;
	};
	readonly resolveDeliveryTarget: (
		context: HouseholdReminderContext,
	) => HouseholdReminderSystemOriginDeliveryTarget | null;
	readonly renderReminderBody: (snapshot: HouseholdReminderConfirmedPolicySnapshot) => string;
};

export type HouseholdReminderSystemOriginPolicyRevalidator = (
	record: TelclaudeMcpScheduledOutboundSideEffectRecord,
) => HouseholdReminderSystemOriginPolicyResult | Promise<HouseholdReminderSystemOriginPolicyResult>;

export function householdReminderScheduledOutboundIdempotencyKey(input: {
	readonly policyVersion: "phase0.v1";
	readonly reminderId: string;
	readonly revision: number;
	readonly scheduledForMs: number;
	readonly contentHash: Sha256Ref;
	readonly recipientPrincipalHash: Sha256Ref;
}): Sha256Ref {
	return canonicalSha256({
		domain: "telclaude.household-reminder-scheduled-outbound-idempotency.v1",
		policyVersion: input.policyVersion,
		reminderId: input.reminderId,
		revision: input.revision,
		scheduledForMs: input.scheduledForMs,
		contentHash: input.contentHash,
		recipientPrincipalHash: input.recipientPrincipalHash,
	});
}

export function createHouseholdReminderSystemOriginPolicyRevalidator(
	dependencies: HouseholdReminderSystemOriginPolicyDependencies,
): HouseholdReminderSystemOriginPolicyRevalidator {
	const readSnapshot =
		dependencies.readConfirmedPolicySnapshot ?? getConfirmedHouseholdReminderPolicySnapshot;
	return async (record) => {
		const authority = authorityFromRecord(record);
		const switches = dependencies.readKillSwitches(authority);
		if (!switches.globalEnabled || !switches.householdEnabled || !switches.parentEnabled) {
			return failure("reminder_policy_disabled", "household reminder delivery policy is disabled");
		}

		const snapshot = readSnapshot(
			record.householdReminderPolicy.reminderId,
			record.householdReminderPolicy.revision,
			authority,
		);
		if (!snapshot) {
			return failure(
				"reminder_revision_not_authorized",
				"confirmed household reminder revision is unavailable",
			);
		}
		if (
			snapshot.confirmation.proposalHash !== record.householdReminderPolicy.confirmedProposalHash
		) {
			return failure(
				"reminder_confirmation_drift",
				"household reminder confirmation evidence changed",
			);
		}
		const reminder = snapshot.reminder;
		if (
			reminder.id !== record.householdReminderPolicy.reminderId ||
			reminder.revision !== record.householdReminderPolicy.revision ||
			reminder.status !== "scheduled" ||
			reminder.scheduleHash !== record.householdReminderPolicy.scheduleHash ||
			reminder.contentHash !== record.householdReminderPolicy.contentHash ||
			reminder.bindingFingerprint !== record.householdReminderPolicy.bindingFingerprint ||
			!sameAuthority(reminder.authority, authority)
		) {
			return failure("reminder_revision_drift", "household reminder revision changed");
		}

		const context = dependencies.resolveContext(authority);
		if (!context || !sameAuthority(context.authority, authority)) {
			return failure(
				"reminder_context_not_authorized",
				"current household reminder context is unavailable",
			);
		}
		if (
			householdReminderBindingFingerprint(context.binding) !== reminder.bindingFingerprint ||
			householdReminderConsentHash(context.consent) !== reminder.consentHash ||
			context.binding.recipientPrincipalHash !==
				record.householdReminderPolicy.recipientPrincipalHash
		) {
			return failure("reminder_binding_drift", "household reminder binding or consent changed");
		}

		const fire = dependencies.readFire(record.householdReminderPolicy.fireId);
		if (
			!fire ||
			fire.fireId !== record.householdReminderPolicy.fireId ||
			fire.reminderId !== reminder.id ||
			fire.revision !== reminder.revision ||
			fire.scheduledForMs !== reminder.schedule.resolvedAtMs ||
			fire.state !== "prepared" ||
			fire.outboundRef !== record.edgePreparedRef ||
			fire.edgePreparedHash !== record.edgePreparedHash ||
			fire.idempotencyKey !== record.idempotencyKey
		) {
			return failure("reminder_fire_not_authorized", "household reminder fire is not prepared");
		}

		const target = dependencies.resolveDeliveryTarget(context);
		const renderedBody = dependencies.renderReminderBody(snapshot);
		const expectedIdempotencyKey = householdReminderScheduledOutboundIdempotencyKey({
			policyVersion: record.householdReminderPolicy.systemPolicyVersion,
			reminderId: reminder.id,
			revision: reminder.revision,
			scheduledForMs: reminder.schedule.resolvedAtMs,
			contentHash: reminder.contentHash,
			recipientPrincipalHash: context.binding.recipientPrincipalHash,
		});
		if (
			!target ||
			record.source !== "household-reminder-system.v1" ||
			record.domain !== "household" ||
			record.channel !== "whatsapp" ||
			record.preparedMediaRefs.length !== 0 ||
			record.destination !== target.destination ||
			!sameJson(record.resolvedDestination, target.resolvedDestination) ||
			record.conversationRef !== target.conversationRef ||
			record.requestedBody !== renderedBody ||
			record.renderedBody !== renderedBody ||
			record.idempotencyKey !== expectedIdempotencyKey
		) {
			return failure("reminder_outbound_drift", "prepared reminder outbound changed");
		}
		const expectedEdgeHash = edgePreparedPayloadHash({
			channel: "whatsapp",
			resolvedDestination: target.resolvedDestination,
			body: renderedBody,
			mediaRefs: [],
		});
		if (record.edgePreparedHash !== expectedEdgeHash) {
			return failure("reminder_outbound_drift", "prepared reminder outbound hash changed");
		}
		return { ok: true };
	};
}

function authorityFromRecord(
	record: TelclaudeMcpScheduledOutboundSideEffectRecord,
): HouseholdReminderAuthority {
	return {
		actorId: record.actorId,
		subjectUserId: record.subjectUserId,
		profileId: record.profileId,
	};
}

function sameAuthority(
	left: HouseholdReminderAuthority,
	right: HouseholdReminderAuthority,
): boolean {
	return (
		left.actorId === right.actorId &&
		left.subjectUserId === right.subjectUserId &&
		left.profileId === right.profileId
	);
}

function sameJson(left: unknown, right: unknown): boolean {
	return JSON.stringify(sortKeysDeep(left)) === JSON.stringify(sortKeysDeep(right));
}

function canonicalSha256(value: unknown): Sha256Ref {
	return `sha256:${crypto
		.createHash("sha256")
		.update(JSON.stringify(sortKeysDeep(value)))
		.digest("hex")}`;
}

function failure(code: string, reason: string): HouseholdReminderSystemOriginPolicyFailure {
	return { ok: false, code, reason, retryable: false };
}
