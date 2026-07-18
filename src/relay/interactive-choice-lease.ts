import { getDb } from "../storage/db.js";

export type InteractiveChoiceKind = "reminder" | "media_confirmation";

export type InteractiveChoiceLease = {
	readonly actorId: string;
	readonly subjectUserId: string;
	readonly profileId: string;
	readonly bindingId: string;
	readonly conversationId: string;
	readonly kind: InteractiveChoiceKind;
	readonly ownerRef: string;
	readonly createdAtMs: number;
	readonly expiresAtMs: number;
};

type InteractiveChoiceLeaseRow = {
	actor_id: string;
	subject_user_id: string;
	profile_id: string;
	binding_id: string;
	conversation_id: string;
	owner_kind: InteractiveChoiceKind;
	owner_ref: string;
	created_at_ms: number;
	expires_at_ms: number;
};

export class InteractiveChoiceBusyError extends Error {
	readonly code = "interactive_choice_busy";

	constructor(readonly incumbentKind: InteractiveChoiceKind) {
		super("another interactive choice is already pending");
		this.name = "InteractiveChoiceBusyError";
	}
}

export function claimInteractiveChoiceLease(input: InteractiveChoiceLease): InteractiveChoiceLease {
	const lease = normalizeLease(input);
	return getDb().transaction(() => {
		getDb()
			.prepare(
				"DELETE FROM household_interactive_choice_leases WHERE conversation_id = ? AND expires_at_ms <= ?",
			)
			.run(lease.conversationId, lease.createdAtMs);
		getDb()
			.prepare(
				`INSERT INTO household_interactive_choice_leases (
				 actor_id, subject_user_id, profile_id, binding_id, conversation_id,
				 owner_kind, owner_ref, created_at_ms, expires_at_ms
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT(conversation_id) DO NOTHING`,
			)
			.run(
				lease.actorId,
				lease.subjectUserId,
				lease.profileId,
				lease.bindingId,
				lease.conversationId,
				lease.kind,
				lease.ownerRef,
				lease.createdAtMs,
				lease.expiresAtMs,
			);
		const current = readLease(lease.conversationId);
		if (!current) throw new Error("interactive choice lease persistence failed");
		if (sameClaim(current, lease)) return current;
		throw new InteractiveChoiceBusyError(current.kind);
	})();
}

export function getInteractiveChoiceLease(
	conversationIdInput: string,
	nowMsInput = Date.now(),
): InteractiveChoiceLease | null {
	const conversationId = required(conversationIdInput, "conversationId");
	const nowMs = timestamp(nowMsInput, "nowMs");
	const lease = readLease(conversationId);
	return lease && lease.expiresAtMs > nowMs ? lease : null;
}

export function releaseInteractiveChoiceLease(input: {
	readonly actorId: string;
	readonly subjectUserId: string;
	readonly profileId: string;
	readonly bindingId: string;
	readonly conversationId: string;
	readonly kind: InteractiveChoiceKind;
	readonly ownerRef: string;
}): boolean {
	const owner = {
		actorId: required(input.actorId, "actorId"),
		subjectUserId: required(input.subjectUserId, "subjectUserId"),
		profileId: required(input.profileId, "profileId"),
		bindingId: required(input.bindingId, "bindingId"),
		conversationId: required(input.conversationId, "conversationId"),
		kind: input.kind,
		ownerRef: required(input.ownerRef, "ownerRef"),
	};
	const result = getDb()
		.prepare(
			`DELETE FROM household_interactive_choice_leases
			 WHERE conversation_id = ? AND owner_kind = ? AND owner_ref = ?
			 AND actor_id = ? AND subject_user_id = ? AND profile_id = ? AND binding_id = ?`,
		)
		.run(
			owner.conversationId,
			owner.kind,
			owner.ownerRef,
			owner.actorId,
			owner.subjectUserId,
			owner.profileId,
			owner.bindingId,
		);
	return result.changes === 1;
}

function readLease(conversationId: string): InteractiveChoiceLease | null {
	const row = getDb()
		.prepare("SELECT * FROM household_interactive_choice_leases WHERE conversation_id = ?")
		.get(conversationId) as InteractiveChoiceLeaseRow | undefined;
	return row
		? {
				actorId: row.actor_id,
				subjectUserId: row.subject_user_id,
				profileId: row.profile_id,
				bindingId: row.binding_id,
				conversationId: row.conversation_id,
				kind: row.owner_kind,
				ownerRef: row.owner_ref,
				createdAtMs: row.created_at_ms,
				expiresAtMs: row.expires_at_ms,
			}
		: null;
}

function normalizeLease(input: InteractiveChoiceLease): InteractiveChoiceLease {
	const createdAtMs = timestamp(input.createdAtMs, "createdAtMs");
	const expiresAtMs = timestamp(input.expiresAtMs, "expiresAtMs");
	if (expiresAtMs <= createdAtMs)
		throw new Error("interactive choice lease must expire in the future");
	if (input.kind !== "reminder" && input.kind !== "media_confirmation") {
		throw new Error("interactive choice lease kind is invalid");
	}
	return {
		actorId: required(input.actorId, "actorId"),
		subjectUserId: required(input.subjectUserId, "subjectUserId"),
		profileId: required(input.profileId, "profileId"),
		bindingId: required(input.bindingId, "bindingId"),
		conversationId: required(input.conversationId, "conversationId"),
		kind: input.kind,
		ownerRef: required(input.ownerRef, "ownerRef"),
		createdAtMs,
		expiresAtMs,
	};
}

function sameClaim(left: InteractiveChoiceLease, right: InteractiveChoiceLease): boolean {
	return (
		left.actorId === right.actorId &&
		left.subjectUserId === right.subjectUserId &&
		left.profileId === right.profileId &&
		left.bindingId === right.bindingId &&
		left.conversationId === right.conversationId &&
		left.kind === right.kind &&
		left.ownerRef === right.ownerRef &&
		left.createdAtMs === right.createdAtMs &&
		left.expiresAtMs === right.expiresAtMs
	);
}

function required(value: string, field: string): string {
	const normalized = value.trim();
	if (!normalized) throw new Error(`interactive choice ${field} is required`);
	return normalized;
}

function timestamp(value: number, field: string): number {
	if (!Number.isSafeInteger(value) || value < 0) {
		throw new Error(`interactive choice ${field} must be a non-negative safe integer`);
	}
	return value;
}
