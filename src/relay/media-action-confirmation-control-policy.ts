import crypto from "node:crypto";
import { type PreparedOutbound, PreparedOutboundSchema } from "../hermes/edge-adapter-contract.js";
import type { RelayConversationStore } from "../hermes/relay-conversation-store.js";
import {
	type MediaActionConfirmationTemplateId,
	mediaActionConfirmationCopy,
} from "./media-action-confirmation-copy.js";
import type { OutboundConversationContext } from "./outbound-delivery-dispatcher.js";

const RECORD_TTL_MS = 5 * 60_000;

export type MediaActionConfirmationControlPolicyRecord = {
	readonly ref: string;
	readonly origin: "relay_system_media_action_confirmation_control";
	readonly templateId: MediaActionConfirmationTemplateId;
	readonly bindingId: string;
	readonly addresseeGender: "f" | "m";
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

export type MediaActionConfirmationControlPolicyStore = {
	authorize(input: {
		readonly prepared: PreparedOutbound;
		readonly templateId: MediaActionConfirmationTemplateId;
		readonly bindingId: string;
		readonly addresseeGender: "f" | "m";
		readonly conversationToken: string;
		readonly expectedAddress: string;
		readonly deliveryRef: string;
	}): PreparedOutbound;
	claim(prepared: PreparedOutbound): boolean;
	complete(prepared: PreparedOutbound, sent: boolean): void;
	resolveConversation(prepared: PreparedOutbound): Promise<OutboundConversationContext | null>;
	list(): readonly MediaActionConfirmationControlPolicyRecord[];
};

export function createMediaActionConfirmationControlPolicyStore(options: {
	readonly conversationStore: RelayConversationStore;
	readonly nowMs?: () => number;
}): MediaActionConfirmationControlPolicyStore {
	const records = new Map<string, MediaActionConfirmationControlPolicyRecord>();
	const nowMs = options.nowMs ?? Date.now;

	function validRecord(
		prepared: PreparedOutbound,
	): MediaActionConfirmationControlPolicyRecord | null {
		const record = records.get(prepared.sideEffectLedgerRef);
		if (!record || record.expiresAtMs <= nowMs()) return null;
		if (
			record.preparedOutboundRef !== prepared.outboundRef ||
			record.preparedOutboundHash !== prepared.edgePreparedHash ||
			record.idempotencyKey !== prepared.idempotencyKey ||
			record.bodyHash !== digest(prepared.finalRenderedBody) ||
			record.destinationHash !== digest(JSON.stringify(prepared.resolvedDestination)) ||
			mediaActionConfirmationCopy(record.templateId, record.addresseeGender) !==
				prepared.finalRenderedBody
		) {
			return null;
		}
		return record;
	}

	return {
		authorize(input) {
			const prepared = PreparedOutboundSchema.parse(input.prepared);
			if (prepared.channel !== "whatsapp") throw new Error("media control channel denied");
			if (
				prepared.finalRenderedBody !==
				mediaActionConfirmationCopy(input.templateId, input.addresseeGender)
			) {
				throw new Error("media control body is not the fixed template");
			}
			if (
				prepared.resolvedDestination.kind !== "address" ||
				prepared.resolvedDestination.addressRef !== input.expectedAddress
			) {
				throw new Error("media control destination is not binding-owned");
			}
			const ref = `${required(input.bindingId, "bindingId")}:${deliveryRef(input.deliveryRef)}`;
			const now = nowMs();
			const authorized = PreparedOutboundSchema.parse({
				...prepared,
				outboundRef: `media-confirmation-out:${ref}`,
				idempotencyKey: `media-confirmation-idem:${ref}`,
				sideEffectLedgerRef: ref,
			});
			records.set(ref, {
				ref,
				origin: "relay_system_media_action_confirmation_control",
				templateId: input.templateId,
				bindingId: input.bindingId,
				addresseeGender: input.addresseeGender,
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
			return { conversationToken: conversation.token, threadMessageIds: [] };
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
	const normalized = value.trim();
	if (!normalized) throw new Error(`media control policy ${field} is missing`);
	return normalized;
}

function deliveryRef(value: string): string {
	const normalized = required(value, "deliveryRef");
	if (!/^[A-Za-z0-9:_-]{1,240}$/u.test(normalized)) {
		throw new Error("media control policy deliveryRef is invalid");
	}
	return normalized;
}
