import crypto from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import type { RelayConversation } from "../../src/hermes/relay-conversation-store.js";
import { createPendingProviderChallengeRegistry } from "../../src/relay/pending-provider-challenge.js";
import type {
	WhatsAppIdentityResolution,
	WhatsAppInboundBridgeEvent,
} from "../../src/relay/whatsapp-inbound-cl1.js";
import {
	createWhatsAppProviderChallengeInterceptor,
	parseWhatsAppOtp,
	WHATSAPP_PROVIDER_CHALLENGE_COPY,
} from "../../src/relay/whatsapp-provider-challenge-interceptor.js";

describe("WhatsApp provider challenge interceptor", () => {
	it("keeps an armed challenge pending for audio without decoding or responding", async () => {
		const fixture = challengeFixture();
		fixture.arm();
		const result = await fixture.intercept({
			event: inbound({
				text: undefined,
				attachments: [{ mediaType: "audio/ogg", bytesBase64: "not-base64" }],
			}),
			identity: fixture.identity,
			conversation: fixture.conversation,
		});

		expect(result).toEqual({ handled: true, templateId: "challenge_type_digits" });
		expect(fixture.respondToChallenge).not.toHaveBeenCalled();
		expect(fixture.sendControl).toHaveBeenCalledWith(
			expect.objectContaining({ body: "תכתבי את המספרים בהודעה" }),
		);
		expect(fixture.registry.peekForInbound(fixture.binding)).toMatchObject({ status: "armed" });
	});

	it("keeps an armed challenge pending after invalid text, then claims a valid code once", async () => {
		const fixture = challengeFixture();
		fixture.arm();

		expect(
			await fixture.intercept({
				event: inbound({ text: "הקוד הוא 246810 ועוד משהו" }),
				identity: fixture.identity,
				conversation: fixture.conversation,
			}),
		).toEqual({ handled: true, templateId: "challenge_invalid_format" });
		expect(fixture.registry.peekForInbound(fixture.binding)).toMatchObject({ status: "armed" });

		expect(
			await fixture.intercept({
				event: inbound({ text: "קוד אימות: 246810" }),
				identity: fixture.identity,
				conversation: fixture.conversation,
			}),
		).toEqual({ handled: true, templateId: "challenge_success_repeat_request" });
		expect(fixture.respondToChallenge).toHaveBeenCalledWith(
			expect.objectContaining({ code: "246810" }),
		);
		expect(fixture.registry.peekForInbound(fixture.binding)).toEqual({ status: "none" });

		expect(
			await fixture.intercept({
				event: inbound({ text: "246810" }),
				identity: fixture.identity,
				conversation: fixture.conversation,
			}),
		).toEqual({ handled: true, templateId: "challenge_unarmed_safety" });
		expect(fixture.respondToChallenge).toHaveBeenCalledTimes(1);
	});

	it("spends a claim before a provider error and never retries", async () => {
		const fixture = challengeFixture({ responseStatus: "error" });
		fixture.arm();

		expect(
			await fixture.intercept({
				event: inbound({ text: "246810" }),
				identity: fixture.identity,
				conversation: fixture.conversation,
			}),
		).toEqual({ handled: true, templateId: "challenge_failed_restart" });
		expect(fixture.registry.peekForInbound(fixture.binding)).toEqual({ status: "none" });
	});

	it("isolates a wrong household while preserving the intended parent's challenge", async () => {
		const fixture = challengeFixture();
		fixture.arm();
		const other = householdIdentity("parent-b", "+15550000002");

		expect(
			await fixture.intercept({
				event: inbound({ senderAddressRef: other.principalId, text: "246810" }),
				identity: other,
				conversation: householdConversation(other, "b"),
			}),
		).toEqual({ handled: true, templateId: "challenge_unarmed_safety" });
		expect(fixture.registry.peekForInbound(fixture.binding)).toMatchObject({ status: "armed" });
	});

	it("returns fixed expired copy and never invokes the provider", async () => {
		let nowMs = 100_000;
		const fixture = challengeFixture({ nowMs: () => nowMs, sidecarExpiresAtMs: 100_001 });
		fixture.arm();
		nowMs = 100_001;

		expect(
			await fixture.intercept({
				event: inbound({ text: "246810" }),
				identity: fixture.identity,
				conversation: fixture.conversation,
			}),
		).toEqual({ handled: true, templateId: "challenge_expired_restart" });
		expect(fixture.respondToChallenge).not.toHaveBeenCalled();
	});

	it("will not claim against a revoked household conversation", async () => {
		const fixture = challengeFixture();
		fixture.arm();

		expect(
			await fixture.intercept({
				event: inbound({ text: "246810" }),
				identity: fixture.identity,
				conversation: {
					...fixture.conversation,
					authorizationState: "revoked",
					revokedAtMs: 100_000,
					revokeReason: "pairing removed",
				},
			}),
		).toEqual({ handled: true, templateId: "challenge_unarmed_safety" });
		expect(fixture.respondToChallenge).not.toHaveBeenCalled();
		expect(fixture.registry.peekForInbound(fixture.binding)).toMatchObject({ status: "armed" });
	});

	it("passes ordinary household and private text through but intercepts an unarmed OTP", async () => {
		const fixture = challengeFixture();
		const privateIdentity = { ...fixture.identity, domain: "private" as const };
		for (const [identity, text, handled] of [
			[fixture.identity, "מה נשמע?", false],
			[privateIdentity, "246810", false],
			[fixture.identity, "246810", true],
		] as const) {
			const result = await fixture.intercept({
				event: inbound({ text }),
				identity,
				conversation: fixture.conversation,
			});
			expect(result.handled).toBe(handled);
		}
	});

	it("keeps code and provider challenge id out of public results and control copy", async () => {
		const fixture = challengeFixture();
		fixture.arm("provider-secret-never-serialize");
		const result = await fixture.intercept({
			event: inbound({ text: "864209" }),
			identity: fixture.identity,
			conversation: fixture.conversation,
		});
		const publicSurfaces = JSON.stringify({ result, controls: fixture.sendControl.mock.calls });

		expect(publicSurfaces).not.toContain("864209");
		expect(publicSurfaces).not.toContain("provider-secret-never-serialize");
		expect(Object.values(WHATSAPP_PROVIDER_CHALLENGE_COPY).join(" ")).not.toMatch(/[0-9]{4,8}/);
	});
});

describe("parseWhatsAppOtp", () => {
	it.each([
		["1234", "1234"],
		["OTP: 12345678!", "12345678"],
		["קוד האימות 123456", "123456"],
		["123", null],
		["123456789", null],
		["my code is 1234", null],
		["１２３４", null],
		[`1234${" ".repeat(61)}`, null],
	] as const)("parses only bounded ASCII OTP input: %s", (text, expected) => {
		expect(parseWhatsAppOtp(text)).toBe(expected);
	});
});

function challengeFixture(
	options: {
		readonly nowMs?: () => number;
		readonly sidecarExpiresAtMs?: number;
		readonly responseStatus?: "success" | "rejected" | "error";
	} = {},
) {
	const nowMs = options.nowMs ?? (() => 100_000);
	const registry = createPendingProviderChallengeRegistry({ nowMs });
	const identity = householdIdentity("parent-a", "+15550000001");
	const conversation = householdConversation(identity, "a");
	const binding = {
		bindingId: identity.bindingId,
		actorId: identity.actorId,
		subjectUserId: identity.subjectUserId,
		profileId: identity.profileId,
		conversationToken: conversation.token,
		conversationId: conversation.conversationId,
		senderPrincipalHash: digest(identity.principalId),
	};
	const respondToChallenge = vi.fn(async () => ({ status: options.responseStatus ?? "success" }));
	const sendControl = vi.fn(async () => undefined);
	return {
		registry,
		identity,
		conversation,
		binding,
		respondToChallenge,
		sendControl,
		intercept: createWhatsAppProviderChallengeInterceptor({
			registry,
			nowMs,
			respondToChallenge,
			sendControl,
		}),
		arm(providerChallengeId = "synthetic-provider-secret") {
			registry.arm({
				origin: "relay_login_coordinator",
				initiationRef: "provider_login_parent_a_12345678",
				initiatingTurnRef: `turn_${"f".repeat(32)}`,
				binding,
				service: "clalit",
				providerChallengeId,
				challengeType: "sms_otp",
				sidecarExpiresAtMs: options.sidecarExpiresAtMs ?? 200_000,
				nowMs: nowMs(),
			});
		},
	};
}

function householdIdentity(
	bindingId: string,
	phone: string,
): Extract<WhatsAppIdentityResolution, { domain: "household" }> {
	return {
		domain: "household",
		bindingId,
		actorId: `household:whatsapp:${bindingId}`,
		subjectUserId: `household:${bindingId}`,
		profileId: bindingId,
		principalId: `whatsapp:${phone}`,
		identityAssurance: "strong_link",
		authorizationScopes: ["message:read", "message:reply"],
		actorScopes: [],
		humanPairingProvenance: true,
		memorySource: `household:${bindingId}`,
		writableNamespace: `household:${bindingId}`,
		replyAddressRef: `whatsapp:${phone}`,
		expectedConversationKey: `whatsapp:${phone}`,
		conversationId: `whatsapp:household:${bindingId}`,
	};
}

function householdConversation(
	identity: Extract<WhatsAppIdentityResolution, { domain: "household" }>,
	hex: string,
): RelayConversation {
	return {
		token: `conv_${hex.repeat(32)}`,
		channel: "whatsapp",
		conversationId: identity.conversationId,
		threadId: identity.replyAddressRef,
		profileId: identity.profileId,
		domain: "household",
		mcpDomain: "household",
		edgeDomain: "household",
		routingSession: { sessionId: "test", routeKey: "test" },
		authorizationState: "authorized",
		humanPairingProvenance: true,
		authorizationScopes: [],
		members: [],
		threadMessageIds: [],
		inboundCursor: null,
		auditIds: [],
		createdAtMs: 1,
		expiresAtMs: null,
		revokedAtMs: null,
		revokeReason: null,
		updatedAtMs: 1,
	};
}

function inbound(overrides: Partial<WhatsAppInboundBridgeEvent> = {}): WhatsAppInboundBridgeEvent {
	return {
		schemaVersion: "telclaude.edge.whatsapp.inbound.v1",
		eventId: "event-1",
		messageId: "message-1",
		cursorSequence: 1,
		chatKind: "direct",
		senderAddressRef: "whatsapp:+15550000001",
		conversationKey: "whatsapp:+15550000001",
		text: "hello",
		attachments: [],
		receivedAtMs: 100_000,
		...overrides,
	};
}

function digest(value: string): `sha256:${string}` {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}
