import { describe, expect, it, vi } from "vitest";
import { createHouseholdEmergencyNotifier } from "../../src/relay/household-emergency-notifier.js";

const NOW = Date.parse("2026-07-18T12:00:00.000Z");

describe("household emergency notifier", () => {
	it("sends the fixed reply for every match but rate-limits redacted alerts per binding and class", async () => {
		let now = NOW;
		const sendControl = vi.fn(async () => true);
		const sendAdminAlert = vi.fn(async () => undefined);
		const ensureConversation = vi.fn(() => undefined);
		const notify = createHouseholdEmergencyNotifier({
			sendControl,
			sendAdminAlert,
			nowMs: () => now,
		});
		const event = householdEvent("כאב בחזה, קוד 123456 ות.ז. 123456782");
		const identity = householdIdentity("parent-a", "f");

		expect(await notify({ event, identity, ensureConversation })).toMatchObject({
			matched: true,
			class: "cardiac",
			replySent: true,
		});
		now += 60_000;
		await notify({ event: { ...event, messageId: "wa-msg-2" }, identity, ensureConversation });

		expect(ensureConversation).toHaveBeenCalledTimes(2);
		expect(sendControl).toHaveBeenCalledTimes(2);
		expect(sendAdminAlert).toHaveBeenCalledTimes(1);
		const alertText = sendAdminAlert.mock.calls[0]?.[0]?.message ?? "";
		expect(alertText).toContain("cardiac");
		expect(alertText).toContain("Parent A");
		expect(alertText).toContain(new Date(NOW).toISOString());
		expect(alertText).toContain("reply_sent=true");
		expect(alertText).not.toContain("123456");
		expect(alertText).not.toContain("123456782");
		expect(alertText).toContain("[REDACTED:");

		await notify({
			event: { ...event, messageId: "wa-msg-3", text: "דימום חזק" },
			identity,
			ensureConversation,
		});
		await notify({
			event: { ...event, messageId: "wa-msg-4" },
			identity: { ...identity, bindingId: "parent-b", displayName: "Parent B" },
			ensureConversation,
		});
		expect(sendAdminAlert).toHaveBeenCalledTimes(3);
	});

	it("isolates reply and alert failures and never absorbs the matched event", async () => {
		const sendAdminAlert = vi.fn(async () => {
			throw new Error("alert offline");
		});
		const notify = createHouseholdEmergencyNotifier({
			sendControl: vi.fn(async () => {
				throw new Error("bridge offline");
			}),
			sendAdminAlert,
			nowMs: () => NOW,
		});

		await expect(
			notify({
				event: householdEvent("אני לא יכולה לנשום"),
				identity: householdIdentity("parent-a", "f"),
				ensureConversation: () => undefined,
			}),
		).resolves.toMatchObject({ matched: true, class: "breathing", replySent: false });
		expect(sendAdminAlert).toHaveBeenCalledWith(
			expect.objectContaining({ message: expect.stringContaining("reply_sent=false") }),
		);
		await notify({
			event: { ...householdEvent("אני לא יכולה לנשום"), messageId: "wa-msg-retry" },
			identity: householdIdentity("parent-a", "f"),
			ensureConversation: () => undefined,
		});
		expect(sendAdminAlert).toHaveBeenCalledTimes(2);
	});

	it("does not classify OTP-shaped or media-derived text", async () => {
		const sendControl = vi.fn(async () => true);
		const sendAdminAlert = vi.fn(async () => undefined);
		const notify = createHouseholdEmergencyNotifier({
			sendControl,
			sendAdminAlert,
			nowMs: () => NOW,
		});
		const identity = householdIdentity("parent-a", "f");

		expect(
			await notify({
				event: householdEvent("123456"),
				identity,
				ensureConversation: () => undefined,
			}),
		).toEqual({ matched: false });
		expect(
			await notify({
				event: {
					...householdEvent(undefined),
					attachments: [{ mediaType: "audio/ogg", bytesBase64: "YQ==" }],
				},
				identity,
				ensureConversation: () => undefined,
			}),
		).toEqual({ matched: false });
		expect(sendControl).not.toHaveBeenCalled();
		expect(sendAdminAlert).not.toHaveBeenCalled();
	});

	it("bounds the redacted trigger preview below Telegram's message limit", async () => {
		const sendAdminAlert = vi.fn(async () => undefined);
		const notify = createHouseholdEmergencyNotifier({
			sendControl: vi.fn(async () => true),
			sendAdminAlert,
			nowMs: () => NOW,
		});
		await notify({
			event: householdEvent(`כאב בחזה ${"פרטים ".repeat(1_000)}`),
			identity: householdIdentity("parent-a", "f"),
			ensureConversation: () => undefined,
		});
		const message = sendAdminAlert.mock.calls[0]?.[0]?.message ?? "";
		expect(Array.from(message).length).toBeLessThan(1_200);
		expect(message).toContain("…");
	});
});

function householdEvent(text: string | undefined) {
	return {
		schemaVersion: "telclaude.edge.whatsapp.inbound.v1" as const,
		eventId: "wa-event-1",
		messageId: "wa-msg-1",
		cursorSequence: 1,
		chatKind: "direct" as const,
		senderAddressRef: "whatsapp:+15551234567",
		conversationKey: "15551234567@s.whatsapp.net",
		...(text === undefined ? {} : { text }),
		attachments: [],
		receivedAtMs: NOW,
	};
}

function householdIdentity(bindingId: string, addresseeGender: "f" | "m") {
	return {
		actorId: `household:whatsapp:${bindingId}`,
		profileId: bindingId,
		principalId: "whatsapp:+15551234567",
		displayName: "Parent A",
		identityAssurance: "strong_link" as const,
		authorizationScopes: ["message:read", "message:reply"],
		actorScopes: [
			{ scope: "message:reply", actions: ["reply"], grantedAt: new Date(0).toISOString() },
		],
		humanPairingProvenance: true as const,
		domain: "household" as const,
		bindingId,
		addresseeGender,
		subjectUserId: `household:${bindingId}`,
		memorySource: `household:${bindingId}` as const,
		writableNamespace: `household:${bindingId}` as const,
		replyAddressRef: "whatsapp:+15551234567",
		expectedConversationKey: "15551234567@s.whatsapp.net",
		conversationId: `whatsapp:household:${bindingId}`,
	};
}
