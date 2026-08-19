import crypto from "node:crypto";
import {
	type DeliveryReceipt,
	EdgeAdapterSchemaVersions,
	type PreparedOutbound,
	PreparedOutboundSchema,
} from "../hermes/edge-adapter-contract.js";
import type { TelclaudeEdgeRuntime } from "../hermes/edge-adapter-runtime.js";
import {
	type RelayConversation,
	type RelayConversationStore,
	relayAuthorityActorRefFor,
	relayConversationToConversationRef,
} from "../hermes/relay-conversation-store.js";
import { classifyHouseholdOutboundSafetyV1 } from "../security/household-outbound-safety.js";
import type {
	OutboundConversationContext,
	OutboundDeliveryDispatcher,
} from "./outbound-delivery-dispatcher.js";

const RECORD_TTL_MS = 5 * 60 * 1_000;

export class WhatsAppInboundReplyError extends Error {
	readonly code: string;

	constructor(code: string) {
		super(code);
		this.name = "WhatsAppInboundReplyError";
		this.code = code;
	}
}

export type WhatsAppInboundReplySenderInput = {
	readonly conversation: RelayConversation;
	readonly recipientAddressRef: string;
	readonly body: string;
	readonly turnRef: string;
};

export type WhatsAppInboundReplySender = (
	input: WhatsAppInboundReplySenderInput,
) => Promise<DeliveryReceipt>;

export type WhatsAppInboundReplyOutcome =
	| { readonly kind: "reply_sent" }
	| { readonly kind: "reply_skipped_empty" }
	| { readonly kind: "reply_failed"; readonly code: string };

export type WhatsAppInboundReplyLogSink = {
	info(bindings: Record<string, unknown>, msg: string): void;
	warn(bindings: Record<string, unknown>, msg: string): void;
};

type WhatsAppInboundReplyPolicyRecord = {
	readonly ref: string;
	readonly origin: "relay_system_whatsapp_inbound_reply";
	readonly conversationToken: string;
	readonly turnRef: string;
	readonly preparedOutboundRef: string;
	readonly preparedOutboundHash: string;
	readonly idempotencyKey: string;
	readonly bodyHash: `sha256:${string}`;
	readonly destinationHash: `sha256:${string}`;
	readonly status: "authorized" | "executing" | "sent" | "failed";
	readonly createdAtMs: number;
	readonly expiresAtMs: number;
};

export type WhatsAppInboundReplyPolicyStore = {
	authorize(input: {
		readonly prepared: PreparedOutbound;
		readonly conversationToken: string;
		readonly turnRef: string;
		readonly expectedAddress: string;
	}): PreparedOutbound;
	claim(prepared: PreparedOutbound): boolean;
	complete(prepared: PreparedOutbound, sent: boolean): void;
	resolveConversation(prepared: PreparedOutbound): Promise<OutboundConversationContext | null>;
	list(): readonly WhatsAppInboundReplyPolicyRecord[];
};

export function logWhatsAppInboundReplyOutcome(
	sink: WhatsAppInboundReplyLogSink,
	outcome: WhatsAppInboundReplyOutcome,
): void {
	if (outcome.kind === "reply_failed") {
		sink.warn({ outcome: outcome.kind, code: outcome.code }, "WhatsApp inbound reply");
		return;
	}
	sink.info({ outcome: outcome.kind }, "WhatsApp inbound reply");
}

export function createWhatsAppInboundReplyPolicyStore(options: {
	readonly conversationStore: RelayConversationStore;
	readonly nowMs?: () => number;
	readonly makeRef?: (turnRef: string) => string;
}): WhatsAppInboundReplyPolicyStore {
	const records = new Map<string, WhatsAppInboundReplyPolicyRecord>();
	const nowMs = options.nowMs ?? Date.now;
	const makeRef =
		options.makeRef ??
		((turnRef: string) => `whatsapp-inbound-reply:${required(turnRef, "turnRef")}`);

	function validRecord(prepared: PreparedOutbound): WhatsAppInboundReplyPolicyRecord | null {
		const record = records.get(prepared.sideEffectLedgerRef);
		if (!record || record.expiresAtMs <= nowMs()) return null;
		if (
			record.preparedOutboundRef !== prepared.outboundRef ||
			record.preparedOutboundHash !== prepared.edgePreparedHash ||
			record.idempotencyKey !== prepared.idempotencyKey ||
			record.bodyHash !== digest(prepared.finalRenderedBody) ||
			record.destinationHash !== digest(JSON.stringify(prepared.resolvedDestination))
		) {
			return null;
		}
		return record;
	}

	return {
		authorize(input) {
			const prepared = PreparedOutboundSchema.parse(input.prepared);
			if (prepared.channel !== "whatsapp") {
				throw new WhatsAppInboundReplyError("whatsapp_inbound_reply_channel_denied");
			}
			if (prepared.mediaRefs.length > 0) {
				throw new WhatsAppInboundReplyError("whatsapp_inbound_reply_media_denied");
			}
			if (
				prepared.resolvedDestination.kind !== "address" ||
				prepared.resolvedDestination.addressRef !== input.expectedAddress
			) {
				throw new WhatsAppInboundReplyError("whatsapp_inbound_reply_destination_denied");
			}
			const ref = makeRef(input.turnRef);
			const now = nowMs();
			const authorized = PreparedOutboundSchema.parse({
				...prepared,
				outboundRef: `whatsapp-inbound-reply-out:${ref}`,
				idempotencyKey: `whatsapp-inbound-reply-idem:${ref}`,
				sideEffectLedgerRef: ref,
			});
			records.set(ref, {
				ref,
				origin: "relay_system_whatsapp_inbound_reply",
				conversationToken: required(input.conversationToken, "conversationToken"),
				turnRef: required(input.turnRef, "turnRef"),
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
			if (conversation?.channel !== "whatsapp") return null;
			return {
				conversationToken: conversation.token,
				threadMessageIds: [],
			};
		},

		list() {
			return [...records.values()].map((record) => ({ ...record }));
		},
	};
}

export function createWhatsAppInboundReplySender(options: {
	readonly edgeRuntime: TelclaudeEdgeRuntime;
	readonly dispatch: OutboundDeliveryDispatcher;
	readonly policyStore: WhatsAppInboundReplyPolicyStore;
	readonly classifyHouseholdOutboundSafety?: typeof classifyHouseholdOutboundSafetyV1;
}): WhatsAppInboundReplySender {
	const classifyHouseholdOutboundSafety =
		options.classifyHouseholdOutboundSafety ?? classifyHouseholdOutboundSafetyV1;
	return async (input) => {
		const body = input.body.trim();
		if (!body) throw new WhatsAppInboundReplyError("whatsapp_inbound_reply_empty");
		if (
			input.conversation.domain === "household" &&
			!classifyHouseholdOutboundSafety(body).safeForAutoGrant
		) {
			throw new WhatsAppInboundReplyError("whatsapp_inbound_reply_not_auto_grant_safe");
		}
		const prepared = options.edgeRuntime.prepareOutbound({
			authorizingActor: relayAuthorityActorRefFor(input.conversation),
			request: {
				schemaVersion: EdgeAdapterSchemaVersions.outboundRequest,
				channel: "whatsapp",
				recipient: { kind: "address", addressRef: input.recipientAddressRef },
				requestedBody: body,
				mediaRefs: [],
				conversationRef: relayConversationToConversationRef(input.conversation),
				correlationId: `whatsapp-inbound-reply:${input.turnRef}`,
			},
		});
		const authorized = options.policyStore.authorize({
			prepared,
			conversationToken: input.conversation.token,
			turnRef: input.turnRef,
			expectedAddress: input.recipientAddressRef,
		});
		if (!options.policyStore.claim(authorized)) {
			throw new WhatsAppInboundReplyError("whatsapp_inbound_reply_replay_denied");
		}
		let sent = false;
		try {
			const receipt = await options.dispatch(authorized);
			sent = receipt.deliveryStatus !== "failed" && receipt.deliveryStatus !== "dead_lettered";
			if (!sent) throw new WhatsAppInboundReplyError("whatsapp_inbound_reply_delivery_failed");
			return receipt;
		} finally {
			options.policyStore.complete(authorized, sent);
		}
	};
}

function digest(value: string): `sha256:${string}` {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function required(value: string, field: string): string {
	const trimmed = value.trim();
	if (!trimmed) throw new WhatsAppInboundReplyError(`whatsapp_inbound_reply_${field}_missing`);
	return trimmed;
}
