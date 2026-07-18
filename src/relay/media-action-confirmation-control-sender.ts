import type { TelclaudeConfig } from "../config/config.js";
import { resolveWhatsAppHouseholdBindingById } from "../config/profiles.js";
import { EdgeAdapterSchemaVersions } from "../hermes/edge-adapter-contract.js";
import type { TelclaudeEdgeRuntime } from "../hermes/edge-adapter-runtime.js";
import {
	type RelayConversationStore,
	relayAuthorityActorRefFor,
	relayConversationToConversationRef,
} from "../hermes/relay-conversation-store.js";
import type { MediaActionConfirmationControlPolicyStore } from "./media-action-confirmation-control-policy.js";
import {
	type MediaActionConfirmationTemplateId,
	mediaActionConfirmationCopy,
} from "./media-action-confirmation-copy.js";
import type { OutboundDeliveryDispatcher } from "./outbound-delivery-dispatcher.js";

export type WhatsAppMediaActionConfirmationControlSender = (input: {
	readonly templateId: MediaActionConfirmationTemplateId;
	readonly body: string;
	readonly bindingId: string;
	readonly deliveryRef: string;
}) => Promise<void>;

export function createMediaActionConfirmationControlSender(options: {
	readonly config: TelclaudeConfig;
	readonly conversationStore: RelayConversationStore;
	readonly edgeRuntime: TelclaudeEdgeRuntime;
	readonly dispatch: OutboundDeliveryDispatcher;
	readonly policyStore: MediaActionConfirmationControlPolicyStore;
}): WhatsAppMediaActionConfirmationControlSender {
	return async (input) => {
		const binding = resolveWhatsAppHouseholdBindingById(input.bindingId, options.config);
		if (!binding) throw new Error("media control binding is unavailable");
		if (input.body !== mediaActionConfirmationCopy(input.templateId, binding.addresseeGender)) {
			throw new Error("media control body is not relay-owned");
		}
		const conversations = options.conversationStore
			.list({ channel: "whatsapp", domain: "household", authorizationState: "authorized" })
			.filter(
				(conversation) =>
					conversation.conversationId === `whatsapp:household:${binding.bindingId}` &&
					conversation.profileId === binding.profile.id,
			);
		if (conversations.length !== 1) throw new Error("media control conversation is ambiguous");
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
				correlationId: `media-confirmation:${input.bindingId}:${input.templateId}`,
			},
		});
		const authorized = options.policyStore.authorize({
			prepared,
			templateId: input.templateId,
			bindingId: binding.bindingId,
			addresseeGender: binding.addresseeGender,
			conversationToken: conversation.token,
			expectedAddress: binding.replyAddress,
			deliveryRef: input.deliveryRef,
		});
		if (!options.policyStore.claim(authorized)) throw new Error("media control replay denied");
		let sent = false;
		try {
			const receipt = await options.dispatch(authorized);
			sent = receipt.deliveryStatus !== "failed" && receipt.deliveryStatus !== "dead_lettered";
			if (!sent) throw new Error("media control delivery failed");
		} finally {
			options.policyStore.complete(authorized, sent);
		}
	};
}
