import crypto from "node:crypto";
import {
	pauseHouseholdReminderCronWakeup,
	upsertHouseholdReminderCronWakeup,
} from "../cron/store.js";
import { sortKeysDeep } from "../crypto/canonical-hash.js";
import { recordHouseholdMetric } from "../household-metrics/store.js";
import {
	claimInteractiveChoiceLease,
	InteractiveChoiceBusyError,
	releaseInteractiveChoiceLease,
} from "../relay/interactive-choice-lease.js";
import { getDb } from "../storage/db.js";
import {
	type HouseholdReminderConfirmationTemplateId,
	householdAppointmentDerivedReminderNotice,
} from "./copy.js";
import { validateJerusalemOneShotSchedule } from "./time.js";
import type {
	HouseholdReminder,
	HouseholdReminderAuthority,
	HouseholdReminderBinding,
	HouseholdReminderConsentReceipt,
	HouseholdReminderFire,
	HouseholdReminderOneShotSchedule,
	HouseholdReminderProposal,
	HouseholdReminderProposalAction,
	HouseholdReminderSource,
	Sha256Ref,
} from "./types.js";

const DEFAULT_PROPOSAL_TTL_MS = 10 * 60 * 1_000;
const SHA256_REF_RE = /^sha256:[a-f0-9]{64}$/;

type HouseholdReminderAckTemplateId = HouseholdReminderConfirmationTemplateId;

type ReminderPayload = {
	readonly text: string;
	readonly label?: string;
	readonly source: HouseholdReminderSource;
	readonly schedule: HouseholdReminderOneShotSchedule;
	readonly contentHash: Sha256Ref;
	readonly scheduleHash: Sha256Ref;
};

type ReminderRow = {
	id: string;
	revision: number;
	actor_id: string;
	subject_user_id: string;
	profile_id: string;
	binding_id: string;
	conversation_id: string;
	sender_principal_hash: string;
	recipient_principal_hash: string;
	binding_fingerprint: string;
	consent_hash: string;
	text: string;
	label: string | null;
	locale: "he-IL";
	source_kind: "parent" | "clalit-appointment";
	source_observation_hash: string | null;
	time_zone: "Asia/Jerusalem";
	local_date_time: string;
	resolved_at_ms: number;
	resolved_at: string;
	offset_minutes: number;
	content_hash: string;
	schedule_hash: string;
	status: HouseholdReminder["status"];
	confirmed_at_ms: number | null;
	created_at_ms: number;
	updated_at_ms: number;
};

type ProposalRow = {
	ref: string;
	action: HouseholdReminderProposalAction;
	reminder_id: string;
	base_revision: number;
	proposed_revision: number;
	actor_id: string;
	subject_user_id: string;
	profile_id: string;
	binding_id: string;
	conversation_id: string;
	sender_principal_hash: string;
	recipient_principal_hash: string;
	binding_fingerprint: string;
	consent_hash: string;
	proposal_hash: string;
	proposed_payload_json: string | null;
	status: HouseholdReminderProposal["status"];
	created_at_ms: number;
	expires_at_ms: number;
};

type FireRow = {
	fire_id: string;
	reminder_id: string;
	revision: number;
	scheduled_for_ms: number;
	state: HouseholdReminderFire["state"];
	attempt_count: number;
	lease_expires_at_ms: number | null;
	outbound_ref: string | null;
	edge_prepared_hash: string | null;
	idempotency_key: string | null;
	whatsapp_message_id: string | null;
	receipt_status: string | null;
	platform_message_id_hash: string | null;
	failure_class: string | null;
	created_at_ms: number;
	updated_at_ms: number;
};

type InterceptionReceiptRow = {
	receipt_id: string;
	event_id_hash: string;
	message_id_hash: string;
	actor_id: string;
	subject_user_id: string;
	profile_id: string;
	binding_id: string;
	conversation_id: string;
	proposal_ref: string;
	proposal_hash: string;
	template_id: HouseholdReminderAckTemplateId;
	status: HouseholdReminderInterceptionReceipt["status"];
	created_at_ms: number;
	updated_at_ms: number;
};

export type HouseholdReminderProposalResolution =
	| { readonly ok: true; readonly reminder: HouseholdReminder }
	| {
			readonly ok: false;
			readonly code:
				| "proposal_not_found"
				| "proposal_expired"
				| "binding_changed"
				| "consent_changed"
				| "invalid_state";
	  };

export type HouseholdReminderConfirmedPolicySnapshot = {
	readonly reminder: HouseholdReminder;
	readonly confirmation: {
		readonly proposalRef: string;
		readonly proposalHash: Sha256Ref;
		readonly action: "create" | "update";
	};
};

export type HouseholdReminderPolicySnapshot = {
	readonly reminder: HouseholdReminder;
	readonly authorization:
		| {
				readonly kind: "parent-confirmed";
				readonly proposalHash: Sha256Ref;
		  }
		| {
				readonly kind: "appointment-derived";
				readonly observationHash: Sha256Ref;
		  };
};

export type HouseholdReminderInterceptionReceipt = {
	readonly receiptId: string;
	readonly eventIdHash: Sha256Ref;
	readonly messageIdHash: Sha256Ref;
	readonly proposalRef: string;
	readonly proposalHash: Sha256Ref;
	readonly templateId: HouseholdReminderAckTemplateId;
	readonly status: "pending_ack" | "acked";
	readonly createdAtMs: number;
	readonly updatedAtMs: number;
};

export function householdReminderBindingFingerprint(binding: HouseholdReminderBinding): Sha256Ref {
	const normalized = normalizeBinding(binding);
	return canonicalSha256({
		domain: "telclaude.household-reminder-binding.v1",
		...normalized,
	});
}

export function householdReminderConsentHash(consent: HouseholdReminderConsentReceipt): Sha256Ref {
	return canonicalSha256({
		domain: "telclaude.household-reminder-consent.v1",
		...normalizeConsent(consent),
	});
}

export function prepareHouseholdReminderCreate(input: {
	readonly authority: HouseholdReminderAuthority;
	readonly binding: HouseholdReminderBinding;
	readonly consent: HouseholdReminderConsentReceipt;
	readonly text: string;
	readonly label?: string;
	readonly source: HouseholdReminderSource;
	readonly schedule: HouseholdReminderOneShotSchedule;
	readonly nowMs?: number;
	readonly proposalTtlMs?: number;
}): { readonly reminder: HouseholdReminder; readonly proposal: HouseholdReminderProposal } {
	const { authority, binding, consentHash } = normalizeContext(input);
	const nowMs = normalizeNow(input.nowMs);
	const payload = normalizePayload({ ...input, nowMs });
	const reminderId = `reminder-${crypto.randomUUID()}`;
	const bindingFingerprint = householdReminderBindingFingerprint(binding);
	const proposal = makeProposal({
		action: "create",
		reminderId,
		baseRevision: 1,
		proposedRevision: 1,
		authority,
		binding,
		bindingFingerprint,
		consentHash,
		payload,
		nowMs,
		proposalTtlMs: input.proposalTtlMs,
	});

	const db = getDb();
	db.transaction(() => {
		insertReminder({
			id: reminderId,
			revision: 1,
			authority,
			binding,
			bindingFingerprint,
			consentHash,
			payload,
			status: "pending_confirmation",
			createdAtMs: nowMs,
			updatedAtMs: nowMs,
		});
		insertProposal(proposal, payload);
	})();

	return {
		reminder: requireReminder(reminderId, 1),
		proposal,
	};
}

export function createAppointmentDerivedHouseholdReminder(input: {
	readonly authority: HouseholdReminderAuthority;
	readonly binding: HouseholdReminderBinding;
	readonly consent: HouseholdReminderConsentReceipt;
	readonly text: string;
	readonly label?: string;
	readonly observationHash: Sha256Ref;
	readonly addresseeGender: "f" | "m";
	readonly schedule: HouseholdReminderOneShotSchedule;
	readonly nowMs?: number;
}): {
	readonly reminder: HouseholdReminder;
	readonly created: boolean;
	readonly notice?: string;
} {
	if (!input.consent) throw new Error("appointment-derived household reminder consent is required");
	const { authority, binding, consentHash } = normalizeContext(input);
	const nowMs = normalizeNow(input.nowMs);
	const payload = normalizePayload({
		...input,
		source: { kind: "clalit-appointment" as const, observationHash: input.observationHash },
		nowMs,
	});
	if (payload.source.kind !== "clalit-appointment") {
		throw new Error("appointment-derived household reminder source is invalid");
	}
	const observationHash = payload.source.observationHash;
	const reminderId = `reminder-derived-${canonicalSha256({
		domain: "telclaude.appointment-derived-reminder-id.v1",
		authority,
		observationHash,
	}).slice("sha256:".length)}`;
	const bindingFingerprint = householdReminderBindingFingerprint(binding);

	const created = getDb().transaction(() => {
		const existing = getReminderRevision(reminderId, 1);
		if (existing) {
			if (
				existing.source.kind !== "clalit-appointment" ||
				existing.source.observationHash !== observationHash ||
				existing.bindingFingerprint !== bindingFingerprint ||
				existing.consentHash !== consentHash ||
				existing.contentHash !== payload.contentHash ||
				existing.scheduleHash !== payload.scheduleHash
			) {
				throw new Error("appointment-derived household reminder observation changed");
			}
			return false;
		}
		insertReminder({
			id: reminderId,
			revision: 1,
			authority,
			binding,
			bindingFingerprint,
			consentHash,
			payload,
			status: "scheduled",
			createdAtMs: nowMs,
			updatedAtMs: nowMs,
		});
		upsertHouseholdReminderCronWakeup({
			reminderId,
			revision: 1,
			resolvedAtMs: payload.schedule.resolvedAtMs,
			nowMs,
		});
		return true;
	})();
	const reminder = requireReminder(reminderId, 1);
	return {
		reminder,
		created,
		...(created
			? { notice: householdAppointmentDerivedReminderNotice(input.addresseeGender) }
			: {}),
	};
}

export function cancelAppointmentDerivedHouseholdReminder(input: {
	readonly reminderId: string;
	readonly authority: HouseholdReminderAuthority;
	readonly binding: HouseholdReminderBinding;
	readonly consent: HouseholdReminderConsentReceipt;
	readonly nowMs?: number;
}): HouseholdReminder {
	const { authority, binding, consentHash } = normalizeContext(input);
	const current = getHouseholdReminderForAuthority(input.reminderId, authority);
	if (current?.status !== "scheduled" || current.source.kind !== "clalit-appointment") {
		throw new Error("appointment-derived household reminder not found");
	}
	assertCurrentBinding(current, binding);
	if (current.consentHash !== consentHash) throw new Error("household reminder consent changed");
	const nowMs = normalizeNow(input.nowMs);
	getDb().transaction(() => {
		if (!setReminderStatus(current.id, current.revision, "scheduled", "cancelled", nowMs)) {
			throw new Error("appointment-derived household reminder changed while cancelling");
		}
		pauseHouseholdReminderCronWakeup(current.id, nowMs);
	})();
	return requireReminder(current.id, current.revision);
}

export function prepareHouseholdReminderUpdate(input: {
	readonly reminderId: string;
	readonly authority: HouseholdReminderAuthority;
	readonly binding: HouseholdReminderBinding;
	readonly consent: HouseholdReminderConsentReceipt;
	readonly text: string;
	readonly label?: string;
	readonly schedule: HouseholdReminderOneShotSchedule;
	readonly nowMs?: number;
	readonly proposalTtlMs?: number;
}): { readonly reminder: HouseholdReminder; readonly proposal: HouseholdReminderProposal } {
	const { authority, binding, consentHash } = normalizeContext(input);
	const current = getHouseholdReminderForAuthority(input.reminderId, authority);
	if (current?.status !== "scheduled") throw new Error("household reminder not found");
	assertCurrentBinding(current, binding);
	const nowMs = normalizeNow(input.nowMs);
	const payload = normalizePayload({
		text: input.text,
		label: input.label,
		source: current.source,
		schedule: input.schedule,
		nowMs,
	});
	const proposal = makeProposal({
		action: "update",
		reminderId: current.id,
		baseRevision: current.revision,
		proposedRevision: current.revision + 1,
		authority,
		binding,
		bindingFingerprint: current.bindingFingerprint,
		consentHash,
		payload,
		nowMs,
		proposalTtlMs: input.proposalTtlMs,
	});

	getDb().transaction(() => {
		insertProposal(proposal, payload);
		if (
			!setReminderStatus(current.id, current.revision, "scheduled", "paused_confirmation", nowMs)
		) {
			throw new Error("household reminder changed while preparing update");
		}
		pauseHouseholdReminderCronWakeup(current.id, nowMs);
	})();
	return { reminder: requireReminder(current.id, current.revision), proposal };
}

export function prepareHouseholdReminderCancellation(input: {
	readonly reminderId: string;
	readonly authority: HouseholdReminderAuthority;
	readonly binding: HouseholdReminderBinding;
	readonly consent: HouseholdReminderConsentReceipt;
	readonly nowMs?: number;
	readonly proposalTtlMs?: number;
}): { readonly reminder: HouseholdReminder; readonly proposal: HouseholdReminderProposal } {
	const { authority, binding, consentHash } = normalizeContext(input);
	const current = getHouseholdReminderForAuthority(input.reminderId, authority);
	if (current?.status !== "scheduled") throw new Error("household reminder not found");
	assertCurrentBinding(current, binding);
	const nowMs = normalizeNow(input.nowMs);
	const proposal = makeProposal({
		action: "cancel",
		reminderId: current.id,
		baseRevision: current.revision,
		proposedRevision: current.revision,
		authority,
		binding,
		bindingFingerprint: current.bindingFingerprint,
		consentHash,
		payload: null,
		nowMs,
		proposalTtlMs: input.proposalTtlMs,
	});

	getDb().transaction(() => {
		insertProposal(proposal, null);
		if (
			!setReminderStatus(current.id, current.revision, "scheduled", "paused_confirmation", nowMs)
		) {
			throw new Error("household reminder changed while preparing cancellation");
		}
		pauseHouseholdReminderCronWakeup(current.id, nowMs);
	})();
	return { reminder: requireReminder(current.id, current.revision), proposal };
}

export function confirmHouseholdReminderProposal(input: {
	readonly proposalRef: string;
	readonly authority: HouseholdReminderAuthority;
	readonly binding: HouseholdReminderBinding;
	readonly consent: HouseholdReminderConsentReceipt;
	readonly nowMs?: number;
}): HouseholdReminderProposalResolution {
	const { authority, binding, consentHash } = normalizeContext(input);
	const nowMs = normalizeNow(input.nowMs);
	const db = getDb();
	return db.transaction(() => {
		const row = findPendingProposal(input.proposalRef, authority);
		if (!row) return { ok: false as const, code: "proposal_not_found" as const };
		const verifiedProposal = verifyProposalPayload(row);
		if (!verifiedProposal.ok) return { ok: false as const, code: "invalid_state" as const };
		if (
			verifiedProposal.payload &&
			!isScheduleWithinWindow(verifiedProposal.payload.schedule, nowMs)
		) {
			return { ok: false as const, code: "invalid_state" as const };
		}
		if (householdReminderBindingFingerprint(binding) !== row.binding_fingerprint) {
			return { ok: false as const, code: "binding_changed" as const };
		}
		if (consentHash !== row.consent_hash) {
			return { ok: false as const, code: "consent_changed" as const };
		}
		if (row.expires_at_ms < nowMs) {
			if (!expireProposal(row, nowMs)) {
				return { ok: false as const, code: "invalid_state" as const };
			}
			return { ok: false as const, code: "proposal_expired" as const };
		}

		let reminder: HouseholdReminder;
		if (row.action === "create") {
			const current = getReminderRevision(row.reminder_id, row.base_revision);
			if (
				!current ||
				!verifiedProposal.payload ||
				current.contentHash !== verifiedProposal.payload.contentHash ||
				current.scheduleHash !== verifiedProposal.payload.scheduleHash ||
				current.bindingFingerprint !== row.binding_fingerprint ||
				current.consentHash !== row.consent_hash ||
				!setReminderStatus(
					row.reminder_id,
					row.base_revision,
					"pending_confirmation",
					"scheduled",
					nowMs,
					nowMs,
				)
			) {
				return { ok: false as const, code: "invalid_state" as const };
			}
			reminder = requireReminder(row.reminder_id, row.base_revision);
		} else if (row.action === "update") {
			const current = getReminderRevision(row.reminder_id, row.base_revision);
			const payload = verifiedProposal.payload;
			if (
				!current ||
				!payload ||
				!setReminderStatus(
					row.reminder_id,
					row.base_revision,
					"paused_confirmation",
					"superseded",
					nowMs,
				)
			) {
				return { ok: false as const, code: "invalid_state" as const };
			}
			insertReminder({
				id: current.id,
				revision: row.proposed_revision,
				authority: current.authority,
				binding: current.binding,
				bindingFingerprint: current.bindingFingerprint,
				consentHash: row.consent_hash as Sha256Ref,
				payload,
				status: "scheduled",
				confirmedAtMs: nowMs,
				createdAtMs: current.createdAtMs,
				updatedAtMs: nowMs,
			});
			reminder = requireReminder(row.reminder_id, row.proposed_revision);
		} else {
			if (
				!setReminderStatus(
					row.reminder_id,
					row.base_revision,
					"paused_confirmation",
					"cancelled",
					nowMs,
				)
			) {
				return { ok: false as const, code: "invalid_state" as const };
			}
			reminder = requireReminder(row.reminder_id, row.base_revision);
		}
		resolveProposal(row, "confirmed", nowMs);
		if (reminder.status === "scheduled") {
			upsertHouseholdReminderCronWakeup({
				reminderId: reminder.id,
				revision: reminder.revision,
				resolvedAtMs: reminder.schedule.resolvedAtMs,
				nowMs,
			});
		} else {
			pauseHouseholdReminderCronWakeup(reminder.id, nowMs);
		}
		return { ok: true as const, reminder };
	})();
}

export function rejectHouseholdReminderProposal(input: {
	readonly proposalRef: string;
	readonly authority: HouseholdReminderAuthority;
	readonly binding: HouseholdReminderBinding;
	readonly consent: HouseholdReminderConsentReceipt;
	readonly nowMs?: number;
}): HouseholdReminderProposalResolution {
	const { authority, binding, consentHash } = normalizeContext(input);
	const nowMs = normalizeNow(input.nowMs);
	return getDb().transaction(() => {
		const row = findPendingProposal(input.proposalRef, authority);
		if (!row) return { ok: false as const, code: "proposal_not_found" as const };
		if (!verifyProposalPayload(row).ok) {
			return { ok: false as const, code: "invalid_state" as const };
		}
		if (householdReminderBindingFingerprint(binding) !== row.binding_fingerprint) {
			return { ok: false as const, code: "binding_changed" as const };
		}
		if (consentHash !== row.consent_hash) {
			return { ok: false as const, code: "consent_changed" as const };
		}
		if (row.expires_at_ms < nowMs) {
			if (!expireProposal(row, nowMs)) {
				return { ok: false as const, code: "invalid_state" as const };
			}
			return { ok: false as const, code: "proposal_expired" as const };
		}
		const restoredStatus = row.action === "create" ? "cancelled" : "scheduled";
		const expectedStatus = row.action === "create" ? "pending_confirmation" : "paused_confirmation";
		if (
			!setReminderStatus(row.reminder_id, row.base_revision, expectedStatus, restoredStatus, nowMs)
		) {
			return { ok: false as const, code: "invalid_state" as const };
		}
		resolveProposal(row, "rejected", nowMs);
		const reminder = requireReminder(row.reminder_id, row.base_revision);
		if (reminder.status === "scheduled") {
			upsertHouseholdReminderCronWakeup({
				reminderId: reminder.id,
				revision: reminder.revision,
				resolvedAtMs: reminder.schedule.resolvedAtMs,
				nowMs,
			});
		}
		return {
			ok: true as const,
			reminder,
		};
	})();
}

export function getHouseholdReminderInterceptionReceipt(input: {
	readonly eventId: string;
	readonly messageId: string;
	readonly authority: HouseholdReminderAuthority;
	readonly binding: HouseholdReminderBinding;
}): HouseholdReminderInterceptionReceipt | null {
	const authority = normalizeAuthority(input.authority);
	const binding = normalizeBinding(input.binding);
	const eventId = nonEmpty(input.eventId, "eventId");
	const messageId = nonEmpty(input.messageId, "messageId");
	const receiptId = interceptionReceiptId({
		eventId,
		messageId,
		authority,
		binding,
	});
	const row = getDb()
		.prepare(
			`SELECT * FROM household_reminder_interception_receipts
			 WHERE receipt_id = ? AND actor_id = ? AND subject_user_id = ? AND profile_id = ?
			 AND binding_id = ? AND conversation_id = ?`,
		)
		.get(
			receiptId,
			authority.actorId,
			authority.subjectUserId,
			authority.profileId,
			binding.bindingId,
			binding.conversationId,
		) as InterceptionReceiptRow | undefined;
	if (
		!row ||
		row.event_id_hash !== interceptionValueHash("event", eventId) ||
		row.message_id_hash !== interceptionValueHash("message", messageId)
	) {
		return null;
	}
	return rowToInterceptionReceipt(row);
}

export function resolveHouseholdReminderProposalWithInterceptionReceipt(input: {
	readonly eventId: string;
	readonly messageId: string;
	readonly proposalRef: string;
	readonly choice: "confirm" | "reject";
	readonly authority: HouseholdReminderAuthority;
	readonly binding: HouseholdReminderBinding;
	readonly consent: HouseholdReminderConsentReceipt;
	readonly nowMs?: number;
}): HouseholdReminderInterceptionReceipt | null {
	const { authority, binding } = normalizeContext(input);
	const eventId = nonEmpty(input.eventId, "eventId");
	const messageId = nonEmpty(input.messageId, "messageId");
	const nowMs = normalizeNow(input.nowMs);
	return getDb().transaction(() => {
		const existing = getHouseholdReminderInterceptionReceipt({
			eventId,
			messageId,
			authority,
			binding,
		});
		if (existing) return existing;
		const proposal = findPendingProposal(input.proposalRef, authority);
		if (!proposal) return null;
		const resolution =
			input.choice === "confirm"
				? confirmHouseholdReminderProposal({
						proposalRef: proposal.ref,
						authority: input.authority,
						binding: input.binding,
						consent: input.consent,
						nowMs,
					})
				: rejectHouseholdReminderProposal({
						proposalRef: proposal.ref,
						authority: input.authority,
						binding: input.binding,
						consent: input.consent,
						nowMs,
					});
		const receiptId = interceptionReceiptId({ eventId, messageId, authority, binding });
		getDb()
			.prepare(
				`INSERT INTO household_reminder_interception_receipts (
				 receipt_id, event_id_hash, message_id_hash,
				 actor_id, subject_user_id, profile_id, binding_id, conversation_id,
				 proposal_ref, proposal_hash, template_id, status, created_at_ms, updated_at_ms
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_ack', ?, ?)`,
			)
			.run(
				receiptId,
				interceptionValueHash("event", eventId),
				interceptionValueHash("message", messageId),
				authority.actorId,
				authority.subjectUserId,
				authority.profileId,
				binding.bindingId,
				binding.conversationId,
				proposal.ref,
				proposal.proposal_hash,
				interceptionResolutionTemplate(resolution, proposal.action, input.choice),
				nowMs,
				nowMs,
			);
		return requireInterceptionReceipt(receiptId);
	})();
}

export function markHouseholdReminderInterceptionReceiptAcked(
	receiptIdInput: string,
	nowMsInput?: number,
): HouseholdReminderInterceptionReceipt | null {
	const receiptId = nonEmpty(receiptIdInput, "receiptId");
	const nowMs = normalizeNow(nowMsInput);
	const changed = getDb()
		.prepare(
			`UPDATE household_reminder_interception_receipts
			 SET status = 'acked', updated_at_ms = ?
			 WHERE receipt_id = ? AND status = 'pending_ack'`,
		)
		.run(nowMs, receiptId);
	if (changed.changes === 0) {
		const existing = readInterceptionReceipt(receiptId);
		return existing?.status === "acked" ? existing : null;
	}
	return requireInterceptionReceipt(receiptId);
}

export function getHouseholdReminderForAuthority(
	reminderId: string,
	authorityInput: HouseholdReminderAuthority,
): HouseholdReminder | null {
	const authority = normalizeAuthority(authorityInput);
	const row = getDb()
		.prepare(
			`SELECT * FROM household_reminders
			 WHERE id = ? AND actor_id = ? AND subject_user_id = ? AND profile_id = ?
			 ORDER BY revision DESC LIMIT 1`,
		)
		.get(
			nonEmpty(reminderId, "reminderId"),
			authority.actorId,
			authority.subjectUserId,
			authority.profileId,
		) as ReminderRow | undefined;
	return row ? rowToReminder(row) : null;
}

/** Internal scheduler read. Never expose through MCP or caller-selected authority. */
export function getHouseholdReminderRevisionForFire(
	reminderId: string,
	revision: number,
): HouseholdReminder | null {
	return getReminderRevision(nonEmpty(reminderId, "reminderId"), positiveInt(revision, "revision"));
}

export function getConfirmedHouseholdReminderPolicySnapshot(
	reminderIdInput: string,
	revisionInput: number,
	authorityInput: HouseholdReminderAuthority,
): HouseholdReminderConfirmedPolicySnapshot | null {
	const reminderId = nonEmpty(reminderIdInput, "reminderId");
	const revision = positiveInt(revisionInput, "revision");
	const authority = normalizeAuthority(authorityInput);
	const db = getDb();
	const reminderRow = db
		.prepare(
			`SELECT * FROM household_reminders
			 WHERE id = ? AND revision = ?
			 AND actor_id = ? AND subject_user_id = ? AND profile_id = ?`,
		)
		.get(reminderId, revision, authority.actorId, authority.subjectUserId, authority.profileId) as
		| ReminderRow
		| undefined;
	if (!reminderRow) return null;
	const proposalRow = db
		.prepare(
			`SELECT * FROM household_reminder_proposals
			 WHERE reminder_id = ? AND proposed_revision = ?
			 AND actor_id = ? AND subject_user_id = ? AND profile_id = ?
			 AND status = 'confirmed' AND action IN ('create', 'update')
			 ORDER BY created_at_ms DESC LIMIT 1`,
		)
		.get(reminderId, revision, authority.actorId, authority.subjectUserId, authority.profileId) as
		| ProposalRow
		| undefined;
	if (!proposalRow) return null;
	// Fire-time authorization replays the exact tuple accepted at confirmation.
	// Do not reinterpret it through current tzdata: legislation/database updates
	// may change the wall-time mapping after the durable instant was frozen.
	const verified = verifyFrozenProposalPayload(proposalRow);
	if (
		!verified.ok ||
		!verified.payload ||
		verified.payload.contentHash !== reminderRow.content_hash ||
		verified.payload.scheduleHash !== reminderRow.schedule_hash ||
		proposalRow.binding_fingerprint !== reminderRow.binding_fingerprint ||
		proposalRow.consent_hash !== reminderRow.consent_hash
	) {
		return null;
	}
	return {
		reminder: rowToReminder(reminderRow),
		confirmation: {
			proposalRef: proposalRow.ref,
			proposalHash: proposalRow.proposal_hash as Sha256Ref,
			action: proposalRow.action as "create" | "update",
		},
	};
}

export function getHouseholdReminderPolicySnapshot(
	reminderIdInput: string,
	revisionInput: number,
	authorityInput: HouseholdReminderAuthority,
): HouseholdReminderPolicySnapshot | null {
	const reminderId = nonEmpty(reminderIdInput, "reminderId");
	const revision = positiveInt(revisionInput, "revision");
	const authority = normalizeAuthority(authorityInput);
	const reminder = getReminderRevision(reminderId, revision);
	if (
		!reminder ||
		reminder.authority.actorId !== authority.actorId ||
		reminder.authority.subjectUserId !== authority.subjectUserId ||
		reminder.authority.profileId !== authority.profileId
	) {
		return null;
	}
	if (reminder.source.kind === "clalit-appointment") {
		return {
			reminder,
			authorization: {
				kind: "appointment-derived",
				observationHash: reminder.source.observationHash,
			},
		};
	}
	const confirmed = getConfirmedHouseholdReminderPolicySnapshot(reminderId, revision, authority);
	return confirmed
		? {
				reminder: confirmed.reminder,
				authorization: {
					kind: "parent-confirmed",
					proposalHash: confirmed.confirmation.proposalHash,
				},
			}
		: null;
}

export function listHouseholdReminders(
	authorityInput: HouseholdReminderAuthority,
): HouseholdReminder[] {
	const authority = normalizeAuthority(authorityInput);
	const rows = getDb()
		.prepare(
			`SELECT r.*
			 FROM household_reminders r
			 JOIN (
				 SELECT id, MAX(revision) AS revision
				 FROM household_reminders
				 WHERE actor_id = ? AND subject_user_id = ? AND profile_id = ?
				 GROUP BY id
			 ) latest ON latest.id = r.id AND latest.revision = r.revision
			 ORDER BY r.created_at_ms DESC`,
		)
		.all(authority.actorId, authority.subjectUserId, authority.profileId) as ReminderRow[];
	return rows.map(rowToReminder);
}

export function getPendingHouseholdReminderProposal(
	authorityInput: HouseholdReminderAuthority,
	bindingInput: HouseholdReminderBinding,
): HouseholdReminderProposal | null {
	const authority = normalizeAuthority(authorityInput);
	const binding = normalizeBinding(bindingInput);
	const bindingFingerprint = householdReminderBindingFingerprint(binding);
	const row = getDb()
		.prepare(
			`SELECT * FROM household_reminder_proposals
			 WHERE actor_id = ? AND subject_user_id = ? AND profile_id = ?
			 AND conversation_id = ? AND binding_fingerprint = ? AND status = 'pending'
			 ORDER BY created_at_ms DESC LIMIT 1`,
		)
		.get(
			authority.actorId,
			authority.subjectUserId,
			authority.profileId,
			binding.conversationId,
			bindingFingerprint,
		) as ProposalRow | undefined;
	if (!row || !verifyProposalPayload(row).ok) return null;
	return rowToProposal(row);
}

export function claimHouseholdReminderFire(input: {
	readonly reminderId: string;
	readonly revision: number;
	readonly scheduledForMs: number;
	readonly nowMs?: number;
	readonly leaseMs?: number;
	readonly maxAttempts?: number;
}): {
	readonly created: boolean;
	readonly acquired: boolean;
	readonly fire: HouseholdReminderFire;
} {
	const reminderId = nonEmpty(input.reminderId, "reminderId");
	const revision = positiveInt(input.revision, "revision");
	const scheduledForMs = timestamp(input.scheduledForMs, "scheduledForMs");
	const nowMs = normalizeNow(input.nowMs);
	const leaseMs = positiveInt(input.leaseMs ?? 60_000, "leaseMs");
	const maxAttempts = positiveInt(input.maxAttempts ?? 3, "maxAttempts");
	const db = getDb();
	return db.transaction(() => {
		const reminder = getReminderRevision(reminderId, revision);
		if (reminder?.status !== "scheduled" || reminder.schedule.resolvedAtMs !== scheduledForMs) {
			throw new Error("household reminder occurrence is not schedulable");
		}
		const fireId = `reminder-fire-${canonicalSha256({
			domain: "telclaude.household-reminder-fire.v1",
			reminderId,
			revision,
			scheduledForMs,
		}).slice("sha256:".length, "sha256:".length + 32)}`;
		const result = db
			.prepare(
				`INSERT OR IGNORE INTO household_reminder_fires (
				 fire_id, reminder_id, revision, scheduled_for_ms, state,
				 attempt_count, lease_expires_at_ms, created_at_ms, updated_at_ms
			) VALUES (?, ?, ?, ?, 'claimed', 1, ?, ?, ?)`,
			)
			.run(fireId, reminderId, revision, scheduledForMs, nowMs + leaseMs, nowMs, nowMs);
		let row = db
			.prepare(
				`SELECT * FROM household_reminder_fires
				 WHERE reminder_id = ? AND revision = ? AND scheduled_for_ms = ?`,
			)
			.get(reminderId, revision, scheduledForMs) as FireRow;
		const created = result.changes === 1;
		let acquired = created;
		if (
			!created &&
			row.attempt_count < maxAttempts &&
			["claimed", "prepared", "dispatched", "retryable_failed"].includes(row.state) &&
			(row.lease_expires_at_ms === null || row.lease_expires_at_ms < nowMs)
		) {
			const resumed = db
				.prepare(
					`UPDATE household_reminder_fires
					 SET state = 'claimed', attempt_count = attempt_count + 1,
					     lease_expires_at_ms = ?, failure_class = NULL, updated_at_ms = ?
					 WHERE fire_id = ? AND attempt_count = ? AND state = ?`,
				)
				.run(nowMs + leaseMs, nowMs, row.fire_id, row.attempt_count, row.state);
			acquired = resumed.changes === 1;
			if (acquired) {
				row = db
					.prepare("SELECT * FROM household_reminder_fires WHERE fire_id = ?")
					.get(fireId) as FireRow;
			}
		}
		return { created, acquired, fire: rowToFire(row) };
	})();
}

export function getHouseholdReminderFire(fireId: string): HouseholdReminderFire | null {
	const row = getDb()
		.prepare("SELECT * FROM household_reminder_fires WHERE fire_id = ?")
		.get(nonEmpty(fireId, "fireId")) as FireRow | undefined;
	return row ? rowToFire(row) : null;
}

export function markHouseholdReminderFirePrepared(input: {
	readonly fireId: string;
	readonly attemptCount: number;
	readonly outboundRef: string;
	readonly edgePreparedHash: Sha256Ref;
	readonly idempotencyKey: string;
	readonly whatsappMessageId: string;
	readonly nowMs?: number;
}): HouseholdReminderFire | null {
	const nowMs = normalizeNow(input.nowMs);
	const current = getHouseholdReminderFire(input.fireId);
	if (
		current?.state !== "claimed" ||
		current.attemptCount !== positiveInt(input.attemptCount, "attemptCount") ||
		(current.leaseExpiresAtMs ?? 0) < nowMs
	)
		return null;
	for (const [existing, expected] of [
		[current.outboundRef, nonEmpty(input.outboundRef, "outboundRef")],
		[current.edgePreparedHash, sha256Ref(input.edgePreparedHash)],
		[current.idempotencyKey, nonEmpty(input.idempotencyKey, "idempotencyKey")],
		[current.whatsappMessageId, nonEmpty(input.whatsappMessageId, "whatsappMessageId")],
	] as const) {
		if (existing !== undefined && existing !== expected) return null;
	}
	const changed = getDb()
		.prepare(
			`UPDATE household_reminder_fires SET state = 'prepared',
			 outbound_ref = ?, edge_prepared_hash = ?, idempotency_key = ?, whatsapp_message_id = ?,
			 updated_at_ms = ? WHERE fire_id = ? AND state = 'claimed' AND attempt_count = ?`,
		)
		.run(
			input.outboundRef,
			input.edgePreparedHash,
			input.idempotencyKey,
			input.whatsappMessageId,
			nowMs,
			input.fireId,
			input.attemptCount,
		);
	return changed.changes === 1 ? getHouseholdReminderFire(input.fireId) : null;
}

export function markHouseholdReminderFireDispatched(input: {
	readonly fireId: string;
	readonly attemptCount: number;
	readonly nowMs?: number;
}): HouseholdReminderFire | null {
	const nowMs = normalizeNow(input.nowMs);
	const changed = getDb()
		.prepare(
			`UPDATE household_reminder_fires SET state = 'dispatched', updated_at_ms = ?
		 WHERE fire_id = ? AND state = 'prepared' AND attempt_count = ?
		 AND lease_expires_at_ms >= ?`,
		)
		.run(
			nowMs,
			nonEmpty(input.fireId, "fireId"),
			positiveInt(input.attemptCount, "attemptCount"),
			nowMs,
		);
	return changed.changes === 1 ? getHouseholdReminderFire(input.fireId) : null;
}

export function completeHouseholdReminderFire(input: {
	readonly fireId: string;
	readonly attemptCount: number;
	readonly receiptStatus: string;
	readonly platformMessageIdHash?: Sha256Ref;
	readonly nowMs?: number;
}): HouseholdReminderFire | null {
	const nowMs = normalizeNow(input.nowMs);
	return getDb().transaction(() => {
		const row = getDb()
			.prepare("SELECT * FROM household_reminder_fires WHERE fire_id = ?")
			.get(nonEmpty(input.fireId, "fireId")) as FireRow | undefined;
		if (row?.state !== "dispatched" || row.attempt_count !== input.attemptCount) return null;
		const changed = getDb()
			.prepare(
				`UPDATE household_reminder_fires SET state = 'delivered', lease_expires_at_ms = NULL,
			 receipt_status = ?, platform_message_id_hash = ?, updated_at_ms = ?
			 WHERE fire_id = ? AND state = 'dispatched' AND attempt_count = ?`,
			)
			.run(
				nonEmpty(input.receiptStatus, "receiptStatus"),
				input.platformMessageIdHash ?? null,
				nowMs,
				row.fire_id,
				input.attemptCount,
			);
		if (changed.changes !== 1) return null;
		setReminderStatus(row.reminder_id, row.revision, "scheduled", "completed", nowMs);
		pauseHouseholdReminderCronWakeup(row.reminder_id, nowMs);
		return getHouseholdReminderFire(row.fire_id);
	})();
}

export function failHouseholdReminderFire(input: {
	readonly fireId: string;
	readonly attemptCount: number;
	readonly failureClass: string;
	readonly retryable: boolean;
	readonly maxAttempts?: number;
	readonly nowMs?: number;
}): HouseholdReminderFire | null {
	const nowMs = normalizeNow(input.nowMs);
	const maxAttempts = positiveInt(input.maxAttempts ?? 3, "maxAttempts");
	const nextState =
		input.retryable && input.attemptCount < maxAttempts ? "retryable_failed" : "dead_lettered";
	return getDb().transaction(() => {
		const row = getDb()
			.prepare("SELECT * FROM household_reminder_fires WHERE fire_id = ?")
			.get(nonEmpty(input.fireId, "fireId")) as FireRow | undefined;
		if (
			!row ||
			!["claimed", "prepared", "dispatched"].includes(row.state) ||
			row.attempt_count !== positiveInt(input.attemptCount, "attemptCount")
		)
			return null;
		const changed = getDb()
			.prepare(
				`UPDATE household_reminder_fires SET state = ?, lease_expires_at_ms = NULL,
			 failure_class = ?, updated_at_ms = ?
			 WHERE fire_id = ? AND state = ? AND attempt_count = ?`,
			)
			.run(
				nextState,
				nonEmpty(input.failureClass, "failureClass"),
				nowMs,
				row.fire_id,
				row.state,
				input.attemptCount,
			);
		if (changed.changes !== 1) return null;
		if (nextState === "dead_lettered") {
			setReminderStatus(row.reminder_id, row.revision, "scheduled", "failed_terminal", nowMs);
			pauseHouseholdReminderCronWakeup(row.reminder_id, nowMs);
		}
		return getHouseholdReminderFire(row.fire_id);
	})();
}

function makeProposal(input: {
	action: HouseholdReminderProposalAction;
	reminderId: string;
	baseRevision: number;
	proposedRevision: number;
	authority: HouseholdReminderAuthority;
	binding: HouseholdReminderBinding;
	bindingFingerprint: Sha256Ref;
	consentHash: Sha256Ref;
	payload: ReminderPayload | null;
	nowMs: number;
	proposalTtlMs?: number;
}): HouseholdReminderProposal {
	const ttlMs = positiveInt(input.proposalTtlMs ?? DEFAULT_PROPOSAL_TTL_MS, "proposalTtlMs");
	const proposalHash = canonicalSha256({
		domain: "telclaude.household-reminder-proposal.v1",
		action: input.action,
		reminderId: input.reminderId,
		baseRevision: input.baseRevision,
		proposedRevision: input.proposedRevision,
		authority: input.authority,
		bindingFingerprint: input.bindingFingerprint,
		consentHash: input.consentHash,
		payload: input.payload,
	});
	return {
		ref: `reminder-proposal-${crypto.randomUUID()}`,
		action: input.action,
		reminderId: input.reminderId,
		baseRevision: input.baseRevision,
		proposedRevision: input.proposedRevision,
		authority: input.authority,
		binding: input.binding,
		bindingFingerprint: input.bindingFingerprint,
		consentHash: input.consentHash,
		proposalHash,
		status: "pending",
		createdAtMs: input.nowMs,
		expiresAtMs: input.nowMs + ttlMs,
	};
}

function insertProposal(
	proposal: HouseholdReminderProposal,
	payload: ReminderPayload | null,
): void {
	try {
		claimInteractiveChoiceLease({
			actorId: proposal.authority.actorId,
			subjectUserId: proposal.authority.subjectUserId,
			profileId: proposal.authority.profileId,
			bindingId: proposal.binding.bindingId,
			conversationId: proposal.binding.conversationId,
			kind: "reminder",
			ownerRef: proposal.ref,
			createdAtMs: proposal.createdAtMs,
			expiresAtMs: proposal.expiresAtMs,
		});
	} catch (error) {
		if (error instanceof InteractiveChoiceBusyError && error.incumbentKind === "reminder") {
			throw new Error("household reminder confirmation is already pending");
		}
		throw error;
	}
	const pending = getDb()
		.prepare(
			"SELECT 1 FROM household_reminder_proposals WHERE conversation_id = ? AND status = 'pending'",
		)
		.get(proposal.binding.conversationId);
	if (pending) throw new Error("household reminder confirmation is already pending");
	getDb()
		.prepare(
			`INSERT INTO household_reminder_proposals (
			 ref, action, reminder_id, base_revision, proposed_revision,
			 actor_id, subject_user_id, profile_id,
			 binding_id, conversation_id, sender_principal_hash, recipient_principal_hash,
			 binding_fingerprint, consent_hash, proposal_hash, proposed_payload_json,
			 status, created_at_ms, expires_at_ms
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`,
		)
		.run(
			proposal.ref,
			proposal.action,
			proposal.reminderId,
			proposal.baseRevision,
			proposal.proposedRevision,
			proposal.authority.actorId,
			proposal.authority.subjectUserId,
			proposal.authority.profileId,
			proposal.binding.bindingId,
			proposal.binding.conversationId,
			proposal.binding.senderPrincipalHash,
			proposal.binding.recipientPrincipalHash,
			proposal.bindingFingerprint,
			proposal.consentHash,
			proposal.proposalHash,
			payload ? JSON.stringify(sortKeysDeep(payload)) : null,
			proposal.createdAtMs,
			proposal.expiresAtMs,
		);
}

function insertReminder(input: {
	id: string;
	revision: number;
	authority: HouseholdReminderAuthority;
	binding: HouseholdReminderBinding;
	bindingFingerprint: Sha256Ref;
	consentHash: Sha256Ref;
	payload: ReminderPayload;
	status: HouseholdReminder["status"];
	confirmedAtMs?: number;
	createdAtMs: number;
	updatedAtMs: number;
}): void {
	getDb()
		.prepare(
			`INSERT INTO household_reminders (
			 id, revision, actor_id, subject_user_id, profile_id,
			 binding_id, conversation_id, sender_principal_hash, recipient_principal_hash,
			 binding_fingerprint, consent_hash, text, label, locale, source_kind, source_observation_hash,
			 time_zone, local_date_time, resolved_at_ms, resolved_at, offset_minutes,
			 content_hash, schedule_hash, status, confirmed_at_ms, created_at_ms, updated_at_ms
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'he-IL', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		)
		.run(
			input.id,
			input.revision,
			input.authority.actorId,
			input.authority.subjectUserId,
			input.authority.profileId,
			input.binding.bindingId,
			input.binding.conversationId,
			input.binding.senderPrincipalHash,
			input.binding.recipientPrincipalHash,
			input.bindingFingerprint,
			input.consentHash,
			input.payload.text,
			input.payload.label ?? null,
			input.payload.source.kind,
			input.payload.source.kind === "clalit-appointment"
				? input.payload.source.observationHash
				: null,
			input.payload.schedule.timeZone,
			input.payload.schedule.localDateTime,
			input.payload.schedule.resolvedAtMs,
			input.payload.schedule.resolvedAt,
			input.payload.schedule.offsetMinutes,
			input.payload.contentHash,
			input.payload.scheduleHash,
			input.status,
			input.confirmedAtMs ?? null,
			input.createdAtMs,
			input.updatedAtMs,
		);
}

function normalizePayload(input: {
	text: string;
	label?: string;
	source: HouseholdReminderSource;
	schedule: HouseholdReminderOneShotSchedule;
	nowMs?: number;
}): ReminderPayload {
	const text = normalizeReminderText(input.text);
	const label = input.label ? normalizeLabel(input.label) : undefined;
	const source = normalizeSource(input.source);
	const schedule = normalizeSchedule(input.schedule, input.nowMs);
	return {
		text,
		...(label ? { label } : {}),
		source,
		schedule,
		contentHash: canonicalSha256({
			domain: "telclaude.household-reminder-content.v1",
			text,
			label: label ?? null,
			source,
		}),
		scheduleHash: canonicalSha256({
			domain: "telclaude.household-reminder-schedule.v1",
			...schedule,
		}),
	};
}

export function normalizeReminderText(value: string): string {
	const normalized = value
		.normalize("NFC")
		.replace(/\r\n?/g, "\n")
		.split("")
		.filter((character) => {
			const codePoint = character.codePointAt(0) ?? 0;
			return codePoint === 9 || codePoint === 10 || (codePoint >= 32 && codePoint !== 127);
		})
		.join("")
		.split("\n")
		.map((line) => line.replace(/[\t ]+/g, " ").trim())
		.join("\n")
		.replace(/\n{3,}/g, "\n\n")
		.trim();
	if (!normalized) throw new Error("household reminder text is required");
	if (normalized.length > 500) throw new Error("household reminder text exceeds 500 characters");
	return normalized;
}

function normalizeLabel(value: string): string {
	const label = value.normalize("NFC").replace(/\s+/g, " ").trim();
	if (!label || label.length > 80) throw new Error("household reminder label is invalid");
	return label;
}

function normalizeSource(source: HouseholdReminderSource): HouseholdReminderSource {
	if (source.kind === "parent") return { kind: "parent" };
	return { kind: "clalit-appointment", observationHash: sha256Ref(source.observationHash) };
}

function normalizeSchedule(
	schedule: HouseholdReminderOneShotSchedule,
	nowMs?: number,
): HouseholdReminderOneShotSchedule {
	validateJerusalemOneShotSchedule(schedule, nowMs === undefined ? {} : { nowMs });
	const resolvedAtMs = timestamp(schedule.resolvedAtMs, "resolvedAtMs");
	return {
		timeZone: "Asia/Jerusalem",
		localDateTime: nonEmpty(schedule.localDateTime, "localDateTime"),
		resolvedAtMs,
		resolvedAt: schedule.resolvedAt,
		offsetMinutes: schedule.offsetMinutes,
	};
}

function normalizeAuthority(authority: HouseholdReminderAuthority): HouseholdReminderAuthority {
	return {
		actorId: nonEmpty(authority.actorId, "actorId"),
		subjectUserId: nonEmpty(authority.subjectUserId, "subjectUserId"),
		profileId: nonEmpty(authority.profileId, "profileId"),
	};
}

function normalizeContext(input: {
	authority: HouseholdReminderAuthority;
	binding: HouseholdReminderBinding;
	consent: HouseholdReminderConsentReceipt;
}): {
	authority: HouseholdReminderAuthority;
	binding: HouseholdReminderBinding;
	consentHash: Sha256Ref;
} {
	const authority = normalizeAuthority(input.authority);
	const binding = normalizeBinding(input.binding);
	const consent = normalizeConsent(input.consent);
	if (consent.verifiedChannelHash !== binding.senderPrincipalHash) {
		throw new Error("household reminder consent does not match the bound channel");
	}
	return {
		authority,
		binding,
		consentHash: householdReminderConsentHash(consent),
	};
}

function normalizeBinding(binding: HouseholdReminderBinding): HouseholdReminderBinding {
	const senderPrincipalHash = sha256Ref(binding.senderPrincipalHash);
	const recipientPrincipalHash = sha256Ref(binding.recipientPrincipalHash);
	if (senderPrincipalHash !== recipientPrincipalHash) {
		throw new Error("household reminder binding recipient must match the bound sender");
	}
	return {
		bindingId: nonEmpty(binding.bindingId, "bindingId"),
		conversationId: nonEmpty(binding.conversationId, "conversationId"),
		senderPrincipalHash,
		recipientPrincipalHash,
	};
}

function rowToReminder(row: ReminderRow): HouseholdReminder {
	return {
		id: row.id,
		revision: row.revision,
		authority: {
			actorId: row.actor_id,
			subjectUserId: row.subject_user_id,
			profileId: row.profile_id,
		},
		binding: {
			bindingId: row.binding_id,
			conversationId: row.conversation_id,
			senderPrincipalHash: sha256Ref(row.sender_principal_hash),
			recipientPrincipalHash: sha256Ref(row.recipient_principal_hash),
		},
		bindingFingerprint: sha256Ref(row.binding_fingerprint),
		consentHash: sha256Ref(row.consent_hash),
		text: row.text,
		...(row.label ? { label: row.label } : {}),
		locale: row.locale,
		source:
			row.source_kind === "parent"
				? { kind: "parent" }
				: {
						kind: "clalit-appointment",
						observationHash: sha256Ref(row.source_observation_hash ?? ""),
					},
		schedule: {
			timeZone: row.time_zone,
			localDateTime: row.local_date_time,
			resolvedAtMs: row.resolved_at_ms,
			resolvedAt: row.resolved_at,
			offsetMinutes: row.offset_minutes,
		},
		contentHash: sha256Ref(row.content_hash),
		scheduleHash: sha256Ref(row.schedule_hash),
		status: row.status,
		...(row.confirmed_at_ms === null ? {} : { confirmedAtMs: row.confirmed_at_ms }),
		createdAtMs: row.created_at_ms,
		updatedAtMs: row.updated_at_ms,
	};
}

function rowToFire(row: FireRow): HouseholdReminderFire {
	return {
		fireId: row.fire_id,
		reminderId: row.reminder_id,
		revision: row.revision,
		scheduledForMs: row.scheduled_for_ms,
		state: row.state,
		attemptCount: row.attempt_count,
		...(row.lease_expires_at_ms === null ? {} : { leaseExpiresAtMs: row.lease_expires_at_ms }),
		...(row.outbound_ref ? { outboundRef: row.outbound_ref } : {}),
		...(row.edge_prepared_hash ? { edgePreparedHash: row.edge_prepared_hash } : {}),
		...(row.idempotency_key ? { idempotencyKey: row.idempotency_key } : {}),
		...(row.whatsapp_message_id ? { whatsappMessageId: row.whatsapp_message_id } : {}),
		...(row.receipt_status ? { receiptStatus: row.receipt_status } : {}),
		...(row.platform_message_id_hash
			? { platformMessageIdHash: sha256Ref(row.platform_message_id_hash) }
			: {}),
		...(row.failure_class ? { failureClass: row.failure_class } : {}),
		createdAtMs: row.created_at_ms,
		updatedAtMs: row.updated_at_ms,
	};
}

function rowToInterceptionReceipt(
	row: InterceptionReceiptRow,
): HouseholdReminderInterceptionReceipt {
	return {
		receiptId: row.receipt_id,
		eventIdHash: sha256Ref(row.event_id_hash),
		messageIdHash: sha256Ref(row.message_id_hash),
		proposalRef: row.proposal_ref,
		proposalHash: sha256Ref(row.proposal_hash),
		templateId: row.template_id,
		status: row.status,
		createdAtMs: row.created_at_ms,
		updatedAtMs: row.updated_at_ms,
	};
}

function rowToProposal(row: ProposalRow): HouseholdReminderProposal {
	return {
		ref: row.ref,
		action: row.action,
		reminderId: row.reminder_id,
		baseRevision: row.base_revision,
		proposedRevision: row.proposed_revision,
		authority: {
			actorId: row.actor_id,
			subjectUserId: row.subject_user_id,
			profileId: row.profile_id,
		},
		binding: {
			bindingId: row.binding_id,
			conversationId: row.conversation_id,
			senderPrincipalHash: sha256Ref(row.sender_principal_hash),
			recipientPrincipalHash: sha256Ref(row.recipient_principal_hash),
		},
		bindingFingerprint: sha256Ref(row.binding_fingerprint),
		consentHash: sha256Ref(row.consent_hash),
		proposalHash: sha256Ref(row.proposal_hash),
		status: row.status,
		createdAtMs: row.created_at_ms,
		expiresAtMs: row.expires_at_ms,
	};
}

function findPendingProposal(
	proposalRef: string,
	authority: HouseholdReminderAuthority,
): ProposalRow | null {
	return (
		(getDb()
			.prepare(
				`SELECT * FROM household_reminder_proposals
				 WHERE ref = ? AND actor_id = ? AND subject_user_id = ? AND profile_id = ?
				 AND status = 'pending'`,
			)
			.get(
				nonEmpty(proposalRef, "proposalRef"),
				authority.actorId,
				authority.subjectUserId,
				authority.profileId,
			) as ProposalRow | undefined) ?? null
	);
}

function readInterceptionReceipt(receiptId: string): HouseholdReminderInterceptionReceipt | null {
	const row = getDb()
		.prepare("SELECT * FROM household_reminder_interception_receipts WHERE receipt_id = ?")
		.get(receiptId) as InterceptionReceiptRow | undefined;
	return row ? rowToInterceptionReceipt(row) : null;
}

function requireInterceptionReceipt(receiptId: string): HouseholdReminderInterceptionReceipt {
	const receipt = readInterceptionReceipt(receiptId);
	if (!receipt) throw new Error("household reminder interception receipt persistence failure");
	return receipt;
}

function interceptionReceiptId(input: {
	readonly eventId: string;
	readonly messageId: string;
	readonly authority: HouseholdReminderAuthority;
	readonly binding: HouseholdReminderBinding;
}): string {
	const digest = canonicalSha256({
		domain: "telclaude.household-reminder-interception-receipt.v1",
		eventId: nonEmpty(input.eventId, "eventId"),
		messageId: nonEmpty(input.messageId, "messageId"),
		authority: input.authority,
		bindingId: input.binding.bindingId,
		conversationId: input.binding.conversationId,
	});
	return `reminder-interception:${digest.slice("sha256:".length)}`;
}

function interceptionValueHash(kind: "event" | "message", value: string): Sha256Ref {
	return canonicalSha256({
		domain: `telclaude.household-reminder-interception-${kind}.v1`,
		value,
	});
}

function interceptionResolutionTemplate(
	resolution: HouseholdReminderProposalResolution,
	action: HouseholdReminderProposalAction,
	choice: "confirm" | "reject",
): HouseholdReminderAckTemplateId {
	if (!resolution.ok) {
		return resolution.code === "proposal_expired" ? "proposal_expired" : "failed";
	}
	if (resolution.reminder.status === "cancelled") return "rejected";
	if (choice === "reject" && action !== "create") return "unchanged";
	return "confirmed";
}

function getReminderRevision(reminderId: string, revision: number): HouseholdReminder | null {
	const row = getDb()
		.prepare("SELECT * FROM household_reminders WHERE id = ? AND revision = ?")
		.get(reminderId, revision) as ReminderRow | undefined;
	return row ? rowToReminder(row) : null;
}

function requireReminder(reminderId: string, revision: number): HouseholdReminder {
	const reminder = getReminderRevision(reminderId, revision);
	if (!reminder) throw new Error("household reminder persistence failure");
	return reminder;
}

function setReminderStatus(
	reminderId: string,
	revision: number,
	expected: HouseholdReminder["status"],
	next: HouseholdReminder["status"],
	nowMs: number,
	confirmedAtMs?: number,
): boolean {
	const result = getDb()
		.prepare(
			`UPDATE household_reminders
			 SET status = ?, updated_at_ms = ?, confirmed_at_ms = COALESCE(?, confirmed_at_ms)
			 WHERE id = ? AND revision = ? AND status = ?`,
		)
		.run(next, nowMs, confirmedAtMs ?? null, reminderId, revision, expected);
	return result.changes === 1;
}

function resolveProposal(
	row: ProposalRow,
	status: "confirmed" | "rejected" | "expired",
	nowMs: number,
): void {
	const resolved = getDb()
		.prepare(
			`UPDATE household_reminder_proposals
			 SET status = ?, resolved_at_ms = ? WHERE ref = ? AND status = 'pending'`,
		)
		.run(status, nowMs, row.ref);
	if (resolved.changes !== 1) throw new Error("household reminder proposal resolution failed");
	recordHouseholdMetric(
		status === "confirmed"
			? "proposal_confirmed"
			: status === "rejected"
				? "proposal_rejected"
				: "proposal_expired",
		row.binding_id,
		nowMs,
	);
	if (
		!releaseInteractiveChoiceLease({
			actorId: row.actor_id,
			subjectUserId: row.subject_user_id,
			profileId: row.profile_id,
			bindingId: row.binding_id,
			conversationId: row.conversation_id,
			kind: "reminder",
			ownerRef: row.ref,
		})
	) {
		throw new Error("household reminder interactive choice lease release failed");
	}
}

function expireProposal(row: ProposalRow, nowMs: number): boolean {
	const expected = row.action === "create" ? "pending_confirmation" : "paused_confirmation";
	const next = row.action === "create" ? "cancelled" : "scheduled";
	if (!setReminderStatus(row.reminder_id, row.base_revision, expected, next, nowMs)) return false;
	resolveProposal(row, "expired", nowMs);
	const reminder = requireReminder(row.reminder_id, row.base_revision);
	if (reminder.status === "scheduled") {
		upsertHouseholdReminderCronWakeup({
			reminderId: reminder.id,
			revision: reminder.revision,
			resolvedAtMs: reminder.schedule.resolvedAtMs,
			nowMs,
		});
	}
	return true;
}

function verifyProposalPayload(
	row: ProposalRow,
): { readonly ok: true; readonly payload: ReminderPayload | null } | { readonly ok: false } {
	try {
		const payload = row.proposed_payload_json
			? normalizePayload(JSON.parse(row.proposed_payload_json) as ReminderPayload)
			: null;
		if ((row.action === "cancel") !== (payload === null)) return { ok: false };
		const proposalHash = canonicalSha256({
			domain: "telclaude.household-reminder-proposal.v1",
			action: row.action,
			reminderId: row.reminder_id,
			baseRevision: row.base_revision,
			proposedRevision: row.proposed_revision,
			authority: {
				actorId: row.actor_id,
				subjectUserId: row.subject_user_id,
				profileId: row.profile_id,
			},
			bindingFingerprint: row.binding_fingerprint,
			consentHash: row.consent_hash,
			payload,
		});
		return proposalHash === row.proposal_hash ? { ok: true, payload } : { ok: false };
	} catch {
		return { ok: false };
	}
}

function verifyFrozenProposalPayload(
	row: ProposalRow,
): { readonly ok: true; readonly payload: ReminderPayload } | { readonly ok: false } {
	try {
		if (!row.proposed_payload_json || row.action === "cancel") return { ok: false };
		const stored = JSON.parse(row.proposed_payload_json) as ReminderPayload;
		const text = normalizeReminderText(stored.text);
		const label = stored.label ? normalizeLabel(stored.label) : undefined;
		const source = normalizeSource(stored.source);
		const schedule = normalizeFrozenSchedule(stored.schedule);
		const payload: ReminderPayload = {
			text,
			...(label ? { label } : {}),
			source,
			schedule,
			contentHash: canonicalSha256({
				domain: "telclaude.household-reminder-content.v1",
				text,
				label: label ?? null,
				source,
			}),
			scheduleHash: canonicalSha256({
				domain: "telclaude.household-reminder-schedule.v1",
				...schedule,
			}),
		};
		const proposalHash = canonicalSha256({
			domain: "telclaude.household-reminder-proposal.v1",
			action: row.action,
			reminderId: row.reminder_id,
			baseRevision: row.base_revision,
			proposedRevision: row.proposed_revision,
			authority: {
				actorId: row.actor_id,
				subjectUserId: row.subject_user_id,
				profileId: row.profile_id,
			},
			bindingFingerprint: row.binding_fingerprint,
			consentHash: row.consent_hash,
			payload,
		});
		return proposalHash === row.proposal_hash ? { ok: true, payload } : { ok: false };
	} catch {
		return { ok: false };
	}
}

function normalizeFrozenSchedule(
	schedule: HouseholdReminderOneShotSchedule,
): HouseholdReminderOneShotSchedule {
	if (
		schedule.timeZone !== "Asia/Jerusalem" ||
		!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(schedule.localDateTime) ||
		!Number.isInteger(schedule.offsetMinutes) ||
		Math.abs(schedule.offsetMinutes) > 24 * 60
	) {
		throw new Error("stored household reminder schedule is invalid");
	}
	const resolvedAtMs = timestamp(schedule.resolvedAtMs, "resolvedAtMs");
	if (schedule.resolvedAt !== new Date(resolvedAtMs).toISOString()) {
		throw new Error("stored household reminder instant is invalid");
	}
	return {
		timeZone: "Asia/Jerusalem",
		localDateTime: schedule.localDateTime,
		resolvedAtMs,
		resolvedAt: schedule.resolvedAt,
		offsetMinutes: schedule.offsetMinutes,
	};
}

function isScheduleWithinWindow(
	schedule: HouseholdReminderOneShotSchedule,
	nowMs: number,
): boolean {
	try {
		validateJerusalemOneShotSchedule(schedule, { nowMs });
		return true;
	} catch {
		return false;
	}
}

function assertCurrentBinding(
	reminder: HouseholdReminder,
	binding: HouseholdReminderBinding,
): void {
	if (householdReminderBindingFingerprint(binding) !== reminder.bindingFingerprint) {
		throw new Error("household reminder binding changed");
	}
}

function normalizeConsent(
	consent: HouseholdReminderConsentReceipt,
): HouseholdReminderConsentReceipt {
	if (consent.state !== "granted" || consent.ceremonyVersion !== "phase0.v1") {
		throw new Error("household reminder consent is not granted");
	}
	if (
		consent.categories.proactiveDelivery !== true ||
		consent.categories.scheduleManagement !== true ||
		consent.categories.retentionDisclosure !== true
	) {
		throw new Error("household reminder consent categories are incomplete");
	}
	const recordedAtMs = Date.parse(consent.recordedAt);
	if (
		!Number.isFinite(recordedAtMs) ||
		new Date(recordedAtMs).toISOString() !== consent.recordedAt
	) {
		throw new Error("household reminder consent timestamp is invalid");
	}
	if (!/^operator:[a-z0-9-]{1,64}$/.test(consent.operatorId)) {
		throw new Error("household reminder consent operator is invalid");
	}
	return {
		state: "granted",
		ceremonyVersion: "phase0.v1",
		ceremonyHash: sha256Ref(consent.ceremonyHash),
		verifiedChannelHash: sha256Ref(consent.verifiedChannelHash),
		categories: {
			proactiveDelivery: true,
			scheduleManagement: true,
			retentionDisclosure: true,
		},
		recordedAt: consent.recordedAt,
		operatorId: consent.operatorId,
	};
}

function canonicalSha256(value: unknown): Sha256Ref {
	return `sha256:${crypto
		.createHash("sha256")
		.update(JSON.stringify(sortKeysDeep(value)))
		.digest("hex")}`;
}

function sha256Ref(value: string): Sha256Ref {
	if (!SHA256_REF_RE.test(value)) throw new Error("invalid sha256 reference");
	return value as Sha256Ref;
}

function nonEmpty(value: string, field: string): string {
	const normalized = value.trim();
	if (!normalized) throw new Error(`${field} is required`);
	return normalized;
}

function positiveInt(value: number, field: string): number {
	if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${field} must be positive`);
	return value;
}

function timestamp(value: number, field: string): number {
	if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${field} is invalid`);
	return value;
}

function normalizeNow(value: number | undefined): number {
	return timestamp(value ?? Date.now(), "nowMs");
}
