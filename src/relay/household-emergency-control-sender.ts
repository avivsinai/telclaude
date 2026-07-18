import type { TelclaudeConfig } from "../config/config.js";
import { resolveWhatsAppHouseholdBindingById } from "../config/profiles.js";
import { EdgeAdapterSchemaVersions } from "../hermes/edge-adapter-contract.js";
import type { TelclaudeEdgeRuntime } from "../hermes/edge-adapter-runtime.js";
import {
	type RelayConversationStore,
	relayAuthorityActorRefFor,
	relayConversationToConversationRef,
} from "../hermes/relay-conversation-store.js";
import type { HouseholdEmergencyControlPolicyStore } from "./household-emergency-control-policy.js";
import { householdEmergencyCopy } from "./household-emergency-copy.js";
import type { OutboundDeliveryDispatcher } from "./outbound-delivery-dispatcher.js";

export type HouseholdEmergencyControlSender = (input: {
	readonly bindingId: string;
	readonly replyAddressRef: string;
	readonly body: string;
	readonly eventMessageId: string;
}) => Promise<boolean>;

export function createHouseholdEmergencyControlSender(options: {
	readonly config: TelclaudeConfig;
	readonly conversationStore: RelayConversationStore;
	readonly edgeRuntime: TelclaudeEdgeRuntime;
	readonly dispatch: OutboundDeliveryDispatcher;
	readonly policyStore: HouseholdEmergencyControlPolicyStore;
}): HouseholdEmergencyControlSender {
	return async (input) => {
		const binding = resolveWhatsAppHouseholdBindingById(input.bindingId, options.config);
		if (
			!options.config.householdEmergency?.enabled ||
			!binding?.emergencyEnabled ||
			binding.replyAddress !== input.replyAddressRef
		)
			throw new Error("emergency control binding is unavailable");
		if (input.body !== householdEmergencyCopy(binding.addresseeGender)) {
			throw new Error("emergency control body is not fixed emergency copy");
		}
		const conversations = options.conversationStore
			.list({ channel: "whatsapp", domain: "household", authorizationState: "authorized" })
			.filter(
				(conversation) =>
					conversation.conversationId === `whatsapp:household:${binding.bindingId}` &&
					conversation.profileId === binding.profile.id,
			);
		if (conversations.length !== 1) throw new Error("emergency control conversation is ambiguous");
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
				correlationId: `household-emergency:${input.bindingId}:${input.eventMessageId}`,
			},
		});
		const authorized = options.policyStore.authorize({
			prepared,
			bindingId: binding.bindingId,
			addresseeGender: binding.addresseeGender,
			conversationToken: conversation.token,
			eventMessageId: input.eventMessageId,
			expectedAddress: binding.replyAddress,
		});
		if (!options.policyStore.claim(authorized)) return false;
		let sent = false;
		try {
			const receipt = await options.dispatch(authorized);
			sent = receipt.deliveryStatus !== "failed" && receipt.deliveryStatus !== "dead_lettered";
			return sent;
		} finally {
			options.policyStore.complete(authorized, sent);
		}
	};
}
