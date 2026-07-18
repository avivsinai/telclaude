import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { TelclaudeConfig } from "../../src/config/config.js";
import type { EffectiveOperatorProfile } from "../../src/config/profiles.js";
import { createRelayConversationStore } from "../../src/hermes/relay-conversation-store.js";
import { createMediaActionConfirmationDispatcher } from "../../src/relay/media-action-confirmation-dispatcher.js";
import type { WhatsAppIdentityResolution } from "../../src/relay/whatsapp-inbound-cl1.js";
import { closeDb, resetDatabase } from "../../src/storage/db.js";

const NOW = Date.parse("2026-07-18T12:00:00.000Z");
const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("media action confirmation dispatcher", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-media-dispatch-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		resetDatabase();
	});

	afterEach(() => {
		closeDb();
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) delete process.env.TELCLAUDE_DATA_DIR;
		else process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
	});

	it("mints a fresh turn and dispatches only the bound action plus quoted derivation", async () => {
		const conversationStore = createRelayConversationStore({ nowMs: () => NOW });
		const { conversation } = conversationStore.mint({
			channel: "whatsapp",
			conversationId: "whatsapp:household:parent-a",
			threadId: identity.expectedConversationKey,
			profileId: "parent-a",
			domain: "household",
			authorizationState: "authorized",
			humanPairingProvenance: true,
			authorizationScopes: ["message:read", "message:reply"],
			members: [
				{
					actorId: identity.actorId,
					principalId: identity.principalId,
					role: "sender",
					identityAssurance: "strong_link",
					scopes: ["message:read", "message:reply"],
				},
			],
			nowMs: NOW,
		});
		const dispatch = vi.fn(async () => ({
			ok: true as const,
			response: "ok",
			success: true,
			toolUses: 1,
			toolResults: 1,
		}));
		const dispatcher = createMediaActionConfirmationDispatcher({
			conversationStore,
			dispatch,
			nowMs: () => NOW,
		});
		const confirmation = {
			confirmationId: "media-confirmation-private-id",
			status: "pending" as const,
			actorId: identity.actorId,
			subjectUserId: identity.subjectUserId,
			profileId: identity.profileId,
			bindingId: identity.bindingId,
			conversationId: identity.conversationId,
			senderPrincipalHash: `sha256:${"a".repeat(64)}` as const,
			originalTurnRef: `turn_${"1".repeat(32)}`,
			ownerScopeHash: `sha256:${"b".repeat(64)}` as const,
			sourceDigest: `sha256:${"c".repeat(64)}` as const,
			derivedDigest: `sha256:${"d".repeat(64)}` as const,
			actionDigest: `sha256:${"e".repeat(64)}` as const,
			actionToolName: "tc_provider_prepare_write" as const,
			jtiHash: `sha256:${"f".repeat(64)}` as const,
			createdAtMs: NOW,
			expiresAtMs: NOW + 60_000,
		};
		const turn = dispatcher.mintFreshTurn({
			confirmation,
			eventId: "event-confirm",
			messageId: "message-confirm",
			identity,
			conversation,
		});

		await dispatcher.dispatch({
			freshTurnRef: turn.ref,
			payload,
			confirmation,
			identity,
			conversation,
			config: { hermes: {} as TelclaudeConfig["hermes"] },
			profile,
		});

		expect(turn.ref).toMatch(/^turn_[a-f0-9]{32}$/u);
		expect(turn.ref).not.toBe(confirmation.originalTurnRef);
		expect(dispatch).toHaveBeenCalledTimes(1);
		const dispatched = dispatch.mock.calls[0]?.[0];
		expect(dispatched?.turn.ref).toBe(turn.ref);
		expect(dispatched?.event.normalized.text).toContain("tc_provider_prepare_write");
		expect(dispatched?.event.normalized.text).toContain("prescription_renewal");
		expect(dispatched?.event.normalized.text).toContain("[FORWARDED CONTENT");
		expect(dispatched?.event.normalized.text).toContain("נא לחדש את המרשם");
		expect(dispatched?.event.normalized.text).not.toContain(confirmation.confirmationId);
		expect(dispatched?.event.normalized.mediaRefs).toEqual([]);
	});
});

const identity = {
	domain: "household",
	actorId: "household:whatsapp:parent-a",
	subjectUserId: "household:parent-a",
	profileId: "parent-a",
	bindingId: "parent-a",
	principalId: "whatsapp:+15551234567",
	displayName: "Parent A",
	addresseeGender: "f",
	memorySource: "household:parent-a",
	writableNamespace: "household:parent-a",
	replyAddressRef: "whatsapp:+15551234567",
	expectedConversationKey: "whatsapp:15551234567@s.whatsapp.net",
	conversationId: "whatsapp:household:parent-a",
	identityAssurance: "strong_link",
	authorizationScopes: ["message:read", "message:reply"],
	actorScopes: [
		{
			scope: "message:read",
			actions: ["read"],
			grantedAt: new Date(0).toISOString(),
		},
	],
	humanPairingProvenance: true,
} as const satisfies WhatsAppIdentityResolution;

const profile = {
	id: "parent-a",
	label: "Parent A",
	allowedSkills: [],
	providerScopes: ["clalit"],
	capabilityScopes: ["schedule.read", "schedule.write"],
	outboundChannels: ["whatsapp"],
	implicit: false,
} as EffectiveOperatorProfile;

const payload = {
	envelopes: [
		{
			kind: "document_extract" as const,
			text: "נא לחדש את המרשם",
			sourceSha256: "1".repeat(64),
			sourceMediaType: "image/jpeg" as const,
			sourcePageCount: 1,
			extractor: "openai_responses_document_extract_v1" as const,
			confidenceSource: "document_confidence_unavailable_v1" as const,
			confirmed: false as const,
			confidencePolicyVersion: "media_confidence_policy_v1" as const,
			lowConfidence: true as const,
			lowConfidenceReasonCodes: ["document_confidence_unavailable" as const],
			classifierVersion: "derived_media_action_classifier_v1" as const,
			actionBearing: true,
			actionBearingReasonCodes: ["explicit_action_verb" as const],
		},
	],
	action: {
		toolName: "tc_provider_prepare_write" as const,
		params: {
			providerId: "clalit",
			service: "clalit",
			action: "prescription_renewal",
			params: { prescriptionId: "synthetic-rx" },
		},
	},
};
