import type { TelclaudeConfig } from "../config/config.js";
import { resolveWhatsAppHouseholdBinding } from "../config/profiles.js";
import type { WhatsAppIdentityResolver } from "./whatsapp-inbound-cl1.js";

export type WhatsAppHouseholdReplyBindingLookup = {
	readonly actorId: string;
	readonly subjectUserId: string;
	readonly profileId: string;
};

export type ResolvedWhatsAppHouseholdReplyBinding = {
	readonly bindingId: string;
	readonly actorId: string;
	readonly subjectUserId: string;
	readonly profileId: string;
	readonly principalId: string;
	readonly replyPrincipalId: string;
	readonly identityAssurance: "strong_link";
	readonly pairingAttested: boolean;
	readonly revoked: boolean;
};

export type WhatsAppHouseholdReplyBindingResolver = (
	input: WhatsAppHouseholdReplyBindingLookup,
) =>
	| ResolvedWhatsAppHouseholdReplyBinding
	| null
	| Promise<ResolvedWhatsAppHouseholdReplyBinding | null>;

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

export function createWhatsAppHouseholdReplyBindingResolver(
	config: TelclaudeConfig,
): WhatsAppHouseholdReplyBindingResolver {
	return (input) => {
		for (const profile of config.profiles ?? []) {
			if (profile.id !== input.profileId) continue;
			for (const binding of profile.whatsappHouseholdBindings ?? []) {
				const resolved = resolveWhatsAppHouseholdBinding(binding.address, config);
				if (
					!resolved ||
					resolved.actorId !== input.actorId ||
					resolved.subjectUserId !== input.subjectUserId ||
					resolved.profile.id !== input.profileId
				) {
					continue;
				}
				return {
					bindingId: resolved.bindingId,
					actorId: resolved.actorId,
					subjectUserId: resolved.subjectUserId,
					profileId: resolved.profile.id,
					principalId: resolved.address,
					replyPrincipalId: resolved.replyAddress,
					identityAssurance: "strong_link",
					// Static config is the Phase 0 pairing attestation; removal is revocation.
					pairingAttested: true,
					revoked: false,
				};
			}
		}
		return null;
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
