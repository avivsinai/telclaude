import crypto from "node:crypto";
import type { TelclaudeConfig } from "../config/config.js";
import { resolveWhatsAppHouseholdBindingById } from "../config/profiles.js";
import {
	EdgeAdapterSchemaVersions,
	type PreparedOutbound,
	PreparedOutboundSchema,
} from "../hermes/edge-adapter-contract.js";
import type { TelclaudeEdgeRuntime } from "../hermes/edge-adapter-runtime.js";
import {
	type RelayConversationStore,
	relayAuthorityActorRefFor,
	relayConversationToConversationRef,
} from "../hermes/relay-conversation-store.js";
import type {
	OutboundConversationContext,
	OutboundDeliveryDispatcher,
} from "./outbound-delivery-dispatcher.js";
import {
	type WhatsAppProviderChallengeControlSender,
	type WhatsAppProviderChallengeTemplateId,
	whatsAppProviderChallengeCopy,
} from "./whatsapp-provider-challenge-interceptor.js";

const RECORD_TTL_MS = 5 * 60 * 1_000;

export type ProviderChallengeControlPolicyRecord = {
	readonly ref: string;
	readonly origin: "relay_system_provider_challenge_control";
	readonly templateId: WhatsAppProviderChallengeTemplateId;
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

export type ProviderChallengeControlPolicyStore = {
	authorize(input: {
		readonly prepared: PreparedOutbound;
		readonly templateId: WhatsAppProviderChallengeTemplateId;
		readonly bindingId: string;
		readonly addresseeGender: "f" | "m";
		readonly conversationToken: string;
		readonly expectedAddress: string;
	}): PreparedOutbound;
	claim(prepared: PreparedOutbound): boolean;
	complete(prepared: PreparedOutbound, sent: boolean): void;
	resolveConversation(prepared: PreparedOutbound): Promise<OutboundConversationContext | null>;
	list(): readonly ProviderChallengeControlPolicyRecord[];
};

export function createProviderChallengeControlPolicyStore(options: {
	readonly conversationStore: RelayConversationStore;
	readonly nowMs?: () => number;
	readonly makeRef?: () => string;
}): ProviderChallengeControlPolicyStore {
	const records = new Map<string, ProviderChallengeControlPolicyRecord>();
	const nowMs = options.nowMs ?? Date.now;
	const makeRef =
		options.makeRef ?? (() => `system-control-${crypto.randomBytes(18).toString("base64url")}`);

	function validRecord(prepared: PreparedOutbound): ProviderChallengeControlPolicyRecord | null {
		const record = records.get(prepared.sideEffectLedgerRef);
		if (!record || record.expiresAtMs <= nowMs()) return null;
		if (
			record.preparedOutboundRef !== prepared.outboundRef ||
			record.preparedOutboundHash !== prepared.edgePreparedHash ||
			record.idempotencyKey !== prepared.idempotencyKey ||
			record.bodyHash !== digest(prepared.finalRenderedBody) ||
			record.destinationHash !== digest(JSON.stringify(prepared.resolvedDestination)) ||
			whatsAppProviderChallengeCopy(record.templateId, record.addresseeGender) !==
				prepared.finalRenderedBody
		) {
			return null;
		}
		return record;
	}

	return {
		authorize(input) {
			const prepared = PreparedOutboundSchema.parse(input.prepared);
			if (prepared.channel !== "whatsapp") throw new Error("provider control channel denied");
			if (
				prepared.finalRenderedBody !==
				whatsAppProviderChallengeCopy(input.templateId, input.addresseeGender)
			) {
				throw new Error("provider control body is not the fixed template");
			}
			if (
				prepared.resolvedDestination.kind !== "address" ||
				prepared.resolvedDestination.addressRef !== input.expectedAddress
			) {
				throw new Error("provider control destination is not binding-owned");
			}
			const ref = required(makeRef());
			const now = nowMs();
			const authorized = PreparedOutboundSchema.parse({
				...prepared,
				outboundRef: `system-control-out:${ref}`,
				idempotencyKey: `system-control-idem:${ref}`,
				sideEffectLedgerRef: ref,
			});
			records.set(ref, {
				ref,
				origin: "relay_system_provider_challenge_control",
				templateId: input.templateId,
				bindingId: required(input.bindingId),
				addresseeGender: input.addresseeGender,
				conversationToken: required(input.conversationToken),
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

export function createProviderChallengeControlSender(options: {
	readonly config: TelclaudeConfig;
	readonly conversationStore: RelayConversationStore;
	readonly edgeRuntime: TelclaudeEdgeRuntime;
	readonly dispatch: OutboundDeliveryDispatcher;
	readonly policyStore: ProviderChallengeControlPolicyStore;
}): WhatsAppProviderChallengeControlSender {
	return async (input) => {
		const binding = resolveWhatsAppHouseholdBindingById(input.bindingId, options.config);
		if (!binding || binding.replyAddress !== input.replyAddressRef) {
			throw new Error("provider control binding is unavailable");
		}
		if (input.body !== whatsAppProviderChallengeCopy(input.templateId, binding.addresseeGender)) {
			throw new Error("provider control body is not relay-owned");
		}
		const conversations = options.conversationStore
			.list({ channel: "whatsapp", domain: "household", authorizationState: "authorized" })
			.filter(
				(conversation) =>
					conversation.conversationId === `whatsapp:household:${binding.bindingId}` &&
					conversation.profileId === binding.profile.id,
			);
		if (conversations.length !== 1) throw new Error("provider control conversation is ambiguous");
		const conversation = conversations[0];
		const prepared = options.edgeRuntime.prepareOutbound({
			authorizingActor: relayAuthorityActorRefFor(conversation),
			request: {
				schemaVersion: EdgeAdapterSchemaVersions.outboundRequest,
				channel: "whatsapp",
				recipient: { kind: "address", addressRef: binding.replyAddress },
				requestedBody: input.body,
				mediaRefs: [],
				conversationRef: relayConversationToConversationRef(conversation),
				correlationId: `provider-control:${input.bindingId}:${input.templateId}`,
			},
		});
		const authorized = options.policyStore.authorize({
			prepared,
			templateId: input.templateId,
			bindingId: binding.bindingId,
			addresseeGender: binding.addresseeGender,
			conversationToken: conversation.token,
			expectedAddress: binding.replyAddress,
		});
		if (!options.policyStore.claim(authorized)) throw new Error("provider control replay denied");
		let sent = false;
		try {
			const receipt = await options.dispatch(authorized);
			sent = receipt.deliveryStatus !== "failed" && receipt.deliveryStatus !== "dead_lettered";
			if (!sent) throw new Error("provider control delivery failed");
		} finally {
			options.policyStore.complete(authorized, sent);
		}
	};
}

function digest(value: string): `sha256:${string}` {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function required(value: string): string {
	const trimmed = value.trim();
	if (!trimmed) throw new Error("provider control policy field is missing");
	return trimmed;
}
