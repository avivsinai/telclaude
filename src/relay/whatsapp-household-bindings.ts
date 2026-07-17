import type { TelclaudeConfig } from "../config/config.js";
import { resolveWhatsAppHouseholdBinding } from "../config/profiles.js";
import type { WhatsAppIdentityResolver } from "./whatsapp-inbound-cl1.js";

export function createWhatsAppHouseholdIdentityResolver(
	config: TelclaudeConfig,
): WhatsAppIdentityResolver {
	return ({ senderAddressRef }) => {
		const resolved = resolveWhatsAppHouseholdBinding(senderAddressRef, config);
		if (!resolved) return null;
		// Static config is the Phase 0 pairing attestation; this epoch is not a live grant timestamp.
		const grantedAt = new Date(0).toISOString();
		return {
			bindingId: resolved.bindingId,
			actorId: resolved.actorId,
			subjectUserId: resolved.subjectUserId,
			profileId: resolved.profile.id,
			domain: "household",
			principalId: resolved.address,
			displayName: resolved.displayName,
			memorySource: resolved.memorySource as `household:${string}`,
			writableNamespace: resolved.writableNamespace as `household:${string}`,
			replyAddressRef: resolved.replyAddress,
			expectedConversationKey: resolved.expectedConversationKey,
			conversationId: `whatsapp:household:${resolved.bindingId}`,
			identityAssurance: "strong_link",
			authorizationScopes: ["message:read", "message:reply"],
			actorScopes: [
				{ scope: "message:read", actions: ["read"], grantedAt },
				{ scope: "message:reply", actions: ["reply"], grantedAt },
			],
			humanPairingProvenance: true,
		};
	};
}

export function combineWhatsAppIdentityResolvers(
	...resolvers: readonly WhatsAppIdentityResolver[]
): WhatsAppIdentityResolver {
	return (input) => {
		for (const resolver of resolvers) {
			const resolved = resolver(input);
			if (resolved) return resolved;
		}
		return null;
	};
}
