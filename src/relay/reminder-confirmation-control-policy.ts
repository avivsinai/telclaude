import crypto from "node:crypto";
import { type PreparedOutbound, PreparedOutboundSchema } from "../hermes/edge-adapter-contract.js";
import type { RelayConversationStore } from "../hermes/relay-conversation-store.js";
import {
	HOUSEHOLD_REMINDER_CONFIRMATION_COPY,
	type HouseholdReminderConfirmationTemplateId,
} from "../household-reminders/copy.js";
import type { OutboundConversationContext } from "./outbound-delivery-dispatcher.js";

const RECORD_TTL_MS = 5 * 60 * 1_000;

export type ReminderConfirmationControlPolicyRecord = {
	readonly ref: string;
	readonly origin: "relay_system_reminder_confirmation_control";
	readonly templateId: HouseholdReminderConfirmationTemplateId;
	readonly bindingId: string;
	readonly conversationToken: string;
	readonly preparedOutboundRef: string;
	readonly preparedOutboundHash: string;
	readonly idempotencyKey: string;
	readonly bodyHash: `sha256:${string}`;
	readonly destinationHash: `sha256:${string}`;
	readonly status: "authorized" | "executing" | "sent" | "failed";
	readonly createdAtMs: number;
	readonly expiresAtMs: number;
};

export type ReminderConfirmationControlPolicyStore = {
	authorize(input: {
		readonly prepared: PreparedOutbound;
		readonly templateId: HouseholdReminderConfirmationTemplateId;
		readonly bindingId: string;
		readonly conversationToken: string;
		readonly expectedAddress: string;
	}): PreparedOutbound;
	claim(prepared: PreparedOutbound): boolean;
	complete(prepared: PreparedOutbound, sent: boolean): void;
	resolveConversation(prepared: PreparedOutbound): Promise<OutboundConversationContext | null>;
	list(): readonly ReminderConfirmationControlPolicyRecord[];
};

export function createReminderConfirmationControlPolicyStore(options: {
	readonly conversationStore: RelayConversationStore;
	readonly nowMs?: () => number;
	readonly makeRef?: () => string;
}): ReminderConfirmationControlPolicyStore {
	const records = new Map<string, ReminderConfirmationControlPolicyRecord>();
	const nowMs = options.nowMs ?? Date.now;
	const makeRef =
		options.makeRef ??
		(() => `reminder-confirmation-${crypto.randomBytes(18).toString("base64url")}`);

	function validRecord(prepared: PreparedOutbound): ReminderConfirmationControlPolicyRecord | null {
		const record = records.get(prepared.sideEffectLedgerRef);
		if (!record || record.expiresAtMs <= nowMs()) return null;
		if (
			record.preparedOutboundRef !== prepared.outboundRef ||
			record.preparedOutboundHash !== prepared.edgePreparedHash ||
			record.idempotencyKey !== prepared.idempotencyKey ||
			record.bodyHash !== digest(prepared.finalRenderedBody) ||
			record.destinationHash !== digest(JSON.stringify(prepared.resolvedDestination)) ||
			HOUSEHOLD_REMINDER_CONFIRMATION_COPY[record.templateId] !== prepared.finalRenderedBody
		) {
			return null;
		}
		return record;
	}

	return {
		authorize(input) {
			const prepared = PreparedOutboundSchema.parse(input.prepared);
			if (prepared.channel !== "whatsapp") throw new Error("reminder control channel denied");
			if (prepared.finalRenderedBody !== HOUSEHOLD_REMINDER_CONFIRMATION_COPY[input.templateId]) {
				throw new Error("reminder control body is not the fixed template");
			}
			if (
				prepared.resolvedDestination.kind !== "address" ||
				prepared.resolvedDestination.addressRef !== input.expectedAddress
			) {
				throw new Error("reminder control destination is not binding-owned");
			}
			const ref = `${required(input.bindingId, "bindingId")}:${required(makeRef(), "ref")}`;
			const now = nowMs();
			const authorized = PreparedOutboundSchema.parse({
				...prepared,
				outboundRef: `reminder-confirmation-out:${ref}`,
				idempotencyKey: `reminder-confirmation-idem:${ref}`,
				sideEffectLedgerRef: ref,
			});
			records.set(ref, {
				ref,
				origin: "relay_system_reminder_confirmation_control",
				templateId: input.templateId,
				bindingId: input.bindingId,
				conversationToken: required(input.conversationToken, "conversationToken"),
				preparedOutboundRef: authorized.outboundRef,
				preparedOutboundHash: authorized.edgePreparedHash,
				idempotencyKey: authorized.idempotencyKey,
				bodyHash: digest(authorized.finalRenderedBody),
				destinationHash: digest(JSON.stringify(authorized.resolvedDestination)),
				status: "authorized",
				createdAtMs: now,
				expiresAtMs: now + RECORD_TTL_MS,
			});
			return authorized;
		},

		claim(prepared) {
			const record = validRecord(prepared);
			if (record?.status !== "authorized") return false;
			records.set(record.ref, { ...record, status: "executing" });
			return true;
		},

		complete(prepared, sent) {
			const record = validRecord(prepared);
			if (record?.status !== "executing") return;
			records.set(record.ref, { ...record, status: sent ? "sent" : "failed" });
		},

		async resolveConversation(prepared) {
			const record = validRecord(prepared);
			if (record?.status !== "executing") return null;
			const conversation = options.conversationStore.resolveAuthorized(record.conversationToken);
			if (
				conversation?.channel !== "whatsapp" ||
				conversation.domain !== "household" ||
				conversation.conversationId !== `whatsapp:household:${record.bindingId}`
			) {
				return null;
			}
			return {
				conversationToken: conversation.token,
				threadMessageIds: conversation.threadMessageIds,
			};
		},

		list() {
			return [...records.values()].map((record) => ({ ...record }));
		},
	};
}

function digest(value: string): `sha256:${string}` {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function required(value: string, field: string): string {
	const trimmed = value.trim();
	if (!trimmed) throw new Error(`reminder control policy ${field} is missing`);
	return trimmed;
}
