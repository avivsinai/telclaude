import crypto from "node:crypto";
import type { TelclaudeConfig } from "../config/config.js";
import { resolveWhatsAppHouseholdBindingById } from "../config/profiles.js";
import type { RelayConversationStore } from "../hermes/relay-conversation-store.js";
import type { PendingProviderChallengeRegistry } from "./pending-provider-challenge.js";
import { pendingProviderChallengeRegistry } from "./pending-provider-challenge.js";
import type { ProviderChallengeSidecar } from "./provider-challenge-sidecar.js";
import {
	WHATSAPP_PROVIDER_CHALLENGE_COPY,
	type WhatsAppProviderChallengeControlSender,
} from "./whatsapp-provider-challenge-interceptor.js";

const CHALLENGE_TTL_MS = 3 * 60 * 1_000;

export type ProviderLoginCoordinator = {
	start(input: {
		readonly origin: "relay_login_coordinator";
		readonly bindingId: string;
		readonly initiatingTurnRef: string;
	}): Promise<
		| {
				readonly status: "provider_challenge_armed";
				readonly initiationRef: string;
				readonly expiresAtMs: number;
		  }
		| { readonly status: "denied" | "error" }
	>;
};

let configuredProviderLoginCoordinator: ProviderLoginCoordinator | null = null;

export function setConfiguredProviderLoginCoordinator(
	coordinator: ProviderLoginCoordinator | null,
): void {
	configuredProviderLoginCoordinator = coordinator;
}

export function startConfiguredProviderLogin(
	input: Parameters<ProviderLoginCoordinator["start"]>[0],
): ReturnType<ProviderLoginCoordinator["start"]> {
	if (!configuredProviderLoginCoordinator) {
		return Promise.resolve({ status: "error" });
	}
	return configuredProviderLoginCoordinator.start(input);
}

export function createProviderLoginCoordinator(options: {
	readonly config: TelclaudeConfig;
	readonly conversationStore: RelayConversationStore;
	readonly sidecar: ProviderChallengeSidecar;
	readonly sendControl: WhatsAppProviderChallengeControlSender;
	readonly registry?: PendingProviderChallengeRegistry;
	readonly nowMs?: () => number;
	readonly makeInitiationRef?: () => string;
}): ProviderLoginCoordinator {
	const registry = options.registry ?? pendingProviderChallengeRegistry;
	const nowMs = options.nowMs ?? Date.now;
	const makeInitiationRef =
		options.makeInitiationRef ??
		(() => `provider_login_${crypto.randomBytes(24).toString("base64url")}`);

	return {
		async start(input) {
			if (input.origin !== "relay_login_coordinator") return { status: "denied" };
			const now = nowMs();
			const binding = resolveWhatsAppHouseholdBindingById(input.bindingId, options.config);
			if (!binding || !hasCurrentConsent(binding, now)) return { status: "denied" };
			const turn = options.conversationStore.resolveInboundTurn(input.initiatingTurnRef, now);
			if (!turn) return { status: "denied" };
			const conversation = options.conversationStore.resolveAuthorized(turn.conversationToken, now);
			if (!conversation || !matchesAuthority(binding, turn, conversation)) {
				return { status: "denied" };
			}

			const initiationRef = requiredRef(makeInitiationRef());
			const initiated = await options.sidecar.initiate({
				actorUserId: binding.actorId,
				subjectUserId: binding.subjectUserId,
			});
			if (initiated.status !== "challenge") return { status: "error" };
			const armed = registry.arm({
				origin: "relay_login_coordinator",
				binding: {
					bindingId: binding.bindingId,
					actorId: binding.actorId,
					subjectUserId: binding.subjectUserId,
					profileId: binding.profile.id,
					conversationToken: conversation.token,
					conversationId: conversation.conversationId,
					senderPrincipalHash: digest(binding.address),
				},
				service: "clalit",
				providerChallengeId: initiated.challengeId,
				challengeType: initiated.challengeType,
				initiationRef,
				initiatingTurnRef: turn.ref,
				sidecarExpiresAtMs: now + CHALLENGE_TTL_MS,
				nowMs: now,
			});
			try {
				await options.sendControl({
					templateId: "challenge_sent",
					body: WHATSAPP_PROVIDER_CHALLENGE_COPY.challenge_sent,
					replyAddressRef: binding.replyAddress,
					bindingId: binding.bindingId,
				});
			} catch {
				registry.cancel(binding.bindingId);
				return { status: "error" };
			}
			return {
				status: "provider_challenge_armed",
				initiationRef,
				expiresAtMs: armed.expiresAtMs,
			};
		},
	};
}

function hasCurrentConsent(
	binding: NonNullable<ReturnType<typeof resolveWhatsAppHouseholdBindingById>>,
	nowMs: number,
): boolean {
	const consent = binding.providerConsent;
	const recordedAtMs = consent ? Date.parse(consent.recordedAt) : Number.NaN;
	return Boolean(
		consent &&
			consent.service === "clalit" &&
			consent.state === "granted" &&
			!consent.revokedAt &&
			Number.isFinite(recordedAtMs) &&
			recordedAtMs <= nowMs &&
			consent.verifiedChannelHash === digest(binding.address) &&
			consent.categories.otpRelay &&
			consent.categories.subjectOwnership &&
			consent.categories.retentionDisclosure &&
			consent.categories.emergencyUnderstanding,
	);
}

function matchesAuthority(
	binding: NonNullable<ReturnType<typeof resolveWhatsAppHouseholdBindingById>>,
	turn: NonNullable<ReturnType<RelayConversationStore["resolveInboundTurn"]>>,
	conversation: NonNullable<ReturnType<RelayConversationStore["resolveAuthorized"]>>,
): boolean {
	return (
		turn.senderActorId === binding.actorId &&
		turn.senderPrincipalId === binding.address &&
		turn.channel === "whatsapp" &&
		turn.domain === "household" &&
		turn.profileId === binding.profile.id &&
		turn.conversationId === `whatsapp:household:${binding.bindingId}` &&
		conversation.channel === "whatsapp" &&
		conversation.domain === "household" &&
		conversation.profileId === binding.profile.id &&
		conversation.conversationId === turn.conversationId &&
		conversation.humanPairingProvenance &&
		conversation.revokedAtMs === null &&
		conversation.members.some(
			(member) =>
				member.actorId === binding.actorId &&
				member.principalId === binding.address &&
				member.principalHash === digest(binding.address) &&
				!member.revoked,
		)
	);
}

function digest(value: string): `sha256:${string}` {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function requiredRef(value: string): string {
	const trimmed = value.trim();
	if (!trimmed) throw new Error("provider login initiation ref is missing");
	return trimmed;
}
