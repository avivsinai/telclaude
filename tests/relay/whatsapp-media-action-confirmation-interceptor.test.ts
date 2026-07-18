import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { EffectiveOperatorProfile } from "../../src/config/profiles.js";
import type { MediaActionConfirmationDispatcher } from "../../src/relay/media-action-confirmation-dispatcher.js";
import { createMediaActionConfirmationStore } from "../../src/relay/media-action-confirmation-store.js";
import type { WhatsAppIdentityResolution } from "../../src/relay/whatsapp-inbound-cl1.js";
import {
	createWhatsAppMediaActionConfirmationInterceptor,
	parseWhatsAppMediaActionChoice,
} from "../../src/relay/whatsapp-media-action-confirmation-interceptor.js";
import { closeDb, resetDatabase } from "../../src/storage/db.js";

const NOW = Date.parse("2026-07-18T12:00:00.000Z");
const KEY = "media-confirmation-interceptor-test-key-32chars";
const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("WhatsApp media action confirmation interceptor", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-media-interceptor-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		resetDatabase();
	});

	afterEach(() => {
		closeDb();
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) delete process.env.TELCLAUDE_DATA_DIR;
		else process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
	});

	it.each([
		["1", "confirm"],
		["כן", "confirm"],
		["אישור", "confirm"],
		["2", "reject"],
		["לא", "reject"],
		["ביטול", "reject"],
	] as const)("parses canonical choice %s", (text, expected) => {
		expect(parseWhatsAppMediaActionChoice(text)).toBe(expected);
	});

	it("confirms once, dispatches one fresh turn, and replays only the fixed ACK", async () => {
		const fixture = armedFixture();
		const input = { event: inbound("אישור"), identity, conversation };

		expect(await fixture.intercept(input)).toEqual({ handled: true, templateId: "confirmed" });
		expect(await fixture.intercept(input)).toEqual({ handled: true, templateId: "confirmed" });

		expect(fixture.dispatcher.mintFreshTurn).toHaveBeenCalledTimes(1);
		expect(fixture.dispatcher.dispatch).toHaveBeenCalledTimes(1);
		expect(fixture.sendControl).toHaveBeenCalledTimes(2);
		expect(fixture.sendControl).toHaveBeenLastCalledWith(
			expect.objectContaining({ templateId: "confirmed", bindingId: "parent-a" }),
		);
	});

	it("rejects without minting or dispatching an action turn", async () => {
		const fixture = armedFixture();

		expect(await fixture.intercept({ event: inbound("ביטול"), identity, conversation })).toEqual({
			handled: true,
			templateId: "rejected",
		});
		expect(fixture.dispatcher.mintFreshTurn).not.toHaveBeenCalled();
		expect(fixture.dispatcher.dispatch).not.toHaveBeenCalled();
	});

	it("passes unrelated text and attachments without changing the pending TTL", async () => {
		const fixture = armedFixture();
		const before = fixture.store.peekPendingForOwner({ owner, nowMs: NOW + 2 });

		expect(
			await fixture.intercept({ event: inbound("מה מזג האוויר?"), identity, conversation }),
		).toEqual({ handled: false });
		expect(
			await fixture.intercept({
				event: { ...inbound("1"), attachments: [{ mediaType: "image/jpeg" }] as never },
				identity,
				conversation,
			}),
		).toEqual({ handled: false });
		const after = fixture.store.peekPendingForOwner({ owner, nowMs: NOW + 3 });
		expect(after?.confirmationId).toBe(before?.confirmationId);
		expect(after?.expiresAtMs).toBe(before?.expiresAtMs);
		expect(fixture.sendControl).not.toHaveBeenCalled();
	});

	it("swallows a choice-like near miss with fixed retry copy and leaves state pending", async () => {
		const fixture = armedFixture();

		expect(await fixture.intercept({ event: inbound("confirm"), identity, conversation })).toEqual({
			handled: true,
			templateId: "choice_required",
		});
		expect(fixture.store.peekPendingForOwner({ owner, nowMs: NOW + 2 })).not.toBeNull();
		expect(fixture.dispatcher.dispatch).not.toHaveBeenCalled();
	});

	it("fails closed for a different sender without consuming the pending action", async () => {
		const fixture = armedFixture();
		const wrongIdentity = { ...identity, principalId: "whatsapp:+15550000000" };

		expect(
			await fixture.intercept({
				event: inbound("1"),
				identity: wrongIdentity,
				conversation,
			}),
		).toEqual({ handled: false });
		expect(fixture.store.peekPendingForOwner({ owner, nowMs: NOW + 2 })).not.toBeNull();
	});

	it("consumes an expired choice with fixed expiry copy and no dispatch", async () => {
		const fixture = armedFixture({ confirmationTtlMs: 2, interceptNowMs: NOW + 3 });
		expect(fixture.store.inspectConfirmation("media-confirmation-interceptor")).toMatchObject({
			status: "pending",
			expiresAtMs: NOW + 3,
		});

		expect(await fixture.intercept({ event: inbound("1"), identity, conversation })).toEqual({
			handled: true,
			templateId: "expired",
		});
		expect(fixture.dispatcher.mintFreshTurn).not.toHaveBeenCalled();
		expect(fixture.dispatcher.dispatch).not.toHaveBeenCalled();
	});
});

function armedFixture(options: { confirmationTtlMs?: number; interceptNowMs?: number } = {}) {
	const store = createMediaActionConfirmationStore({
		encryptionKey: KEY,
		nowMs: () => NOW + 1,
		makeConfirmationId: () => "media-confirmation-interceptor",
		makeJti: () => "interceptor-jti",
		...(options.confirmationTtlMs ? { confirmationTtlMs: options.confirmationTtlMs } : {}),
	});
	store.registerTurnDerivation({
		owner,
		turnRef: `turn_${"1".repeat(32)}`,
		envelopes: [documentEnvelope()],
		createdAtMs: NOW,
	});
	store.guardConsequentialAction({
		turnRef: `turn_${"1".repeat(32)}`,
		authority: {
			actorId: owner.actorId,
			subjectUserId: owner.subjectUserId,
			profileId: owner.profileId,
		},
		action: {
			toolName: "tc_provider_prepare_write",
			params: { action: "prescription_renewal" },
		},
		nowMs: NOW + 1,
	});
	const dispatcher = {
		mintFreshTurn: vi.fn(() => ({ ref: `turn_${"2".repeat(32)}` }) as never),
		dispatch: vi.fn(async () => ({
			ok: true as const,
			response: "done",
			success: true,
			toolUses: 1,
			toolResults: 1,
		})),
	} satisfies MediaActionConfirmationDispatcher;
	const sendControl = vi.fn(async () => undefined);
	const intercept = createWhatsAppMediaActionConfirmationInterceptor({
		store,
		dispatcher,
		sendControl,
		config: { hermes: {} as never },
		resolveProfile: () => profile,
		nowMs: () => options.interceptNowMs ?? NOW + 2,
	});
	return { store, dispatcher, sendControl, intercept };
}

function inbound(text: string) {
	return {
		eventId: "event-choice",
		messageId: "message-choice",
		text,
		attachments: [],
	} as never;
}

function documentEnvelope() {
	return {
		kind: "document_extract" as const,
		text: "נא לחדש מרשם",
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
	};
}

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
	actorScopes: [],
	humanPairingProvenance: true,
} as const satisfies WhatsAppIdentityResolution;

const conversation = {
	channel: "whatsapp",
	domain: "household",
	authorizationState: "authorized",
	revokedAtMs: null,
	humanPairingProvenance: true,
	conversationId: identity.conversationId,
	profileId: identity.profileId,
	token: `conv_${"1".repeat(32)}`,
} as never;

const owner = {
	actorId: identity.actorId,
	subjectUserId: identity.subjectUserId,
	profileId: identity.profileId,
	bindingId: identity.bindingId,
	conversationId: identity.conversationId,
	senderPrincipalHash: `sha256:${crypto
		.createHash("sha256")
		.update(identity.principalId)
		.digest("hex")}` as const,
};

const profile = {
	id: "parent-a",
	label: "Parent A",
	allowedSkills: [],
	providerScopes: ["clalit"],
	capabilityScopes: ["schedule.read", "schedule.write"],
	outboundChannels: ["whatsapp"],
	implicit: false,
} as EffectiveOperatorProfile;
