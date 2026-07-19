import { describe, expect, it, vi } from "vitest";
import { createHouseholdEmergencyNotifier } from "../../src/relay/household-emergency-notifier.js";

const NOW = Date.parse("2026-07-18T12:00:00.000Z");

describe("household emergency notifier", () => {
	it("escalates every same-class repeat and resets after five minutes of silence", async () => {
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
		now += 3 * 60_000;
		await notify({ event: { ...event, messageId: "wa-msg-2" }, identity, ensureConversation });
		now += 3 * 60_000;
		await notify({ event: { ...event, messageId: "wa-msg-3" }, identity, ensureConversation });

		expect(ensureConversation).toHaveBeenCalledTimes(3);
		expect(sendControl).toHaveBeenCalledTimes(3);
		expect(sendAdminAlert).toHaveBeenCalledTimes(3);
		expect(sendAdminAlert.mock.calls.map(([alert]) => alert.title)).toEqual([
			"Household emergency signal",
			"REPEATED household emergency signal — escalating (2×)",
			"REPEATED household emergency signal — escalating (3×)",
		]);
		const firstAlertText = sendAdminAlert.mock.calls[0]?.[0]?.message ?? "";
		expect(firstAlertText).toContain("cardiac");
		expect(firstAlertText).toContain("Parent A");
		expect(firstAlertText).toContain(new Date(NOW).toISOString());
		expect(firstAlertText).toContain("reply_sent=true");
		const repeatedAlertText = sendAdminAlert.mock.calls[1]?.[0]?.message ?? "";
		expect(repeatedAlertText).toContain("repeat_count=2");
		expect(repeatedAlertText).toContain("seconds_since_previous=180");
		expect(repeatedAlertText).not.toContain("123456");
		expect(repeatedAlertText).not.toContain("123456782");
		expect(repeatedAlertText).toContain("[REDACTED:");
		expect(Array.from(repeatedAlertText).length).toBeLessThan(1_200);

		now += 5 * 60_000;
		await notify({
			event: { ...event, messageId: "wa-msg-4" },
			identity,
			ensureConversation,
		});
		expect(sendAdminAlert.mock.calls[3]?.[0]?.title).toBe("Household emergency signal");
		expect(sendAdminAlert.mock.calls[3]?.[0]?.message).not.toContain("repeat_count=");
		expect(sendControl).toHaveBeenCalledTimes(4);
	});

	it("tracks repeat incidents independently per binding and emergency class", async () => {
		let now = NOW;
		const sendAdminAlert = vi.fn(async () => undefined);
		const notify = createHouseholdEmergencyNotifier({
			sendControl: vi.fn(async () => true),
			sendAdminAlert,
			nowMs: () => now,
		});
		const cardiac = householdEvent("כאב בחזה");
		const parentA = householdIdentity("parent-a", "f");

		await notify({ event: cardiac, identity: parentA, ensureConversation: () => undefined });
		now += 60_000;
		await notify({
			event: { ...cardiac, messageId: "wa-msg-2", text: "דימום חזק" },
			identity: parentA,
			ensureConversation: () => undefined,
		});
		await notify({
			event: { ...cardiac, messageId: "wa-msg-3" },
			identity: { ...parentA, bindingId: "parent-b", displayName: "Parent B" },
			ensureConversation: () => undefined,
		});
		await notify({
			event: { ...cardiac, messageId: "wa-msg-4" },
			identity: parentA,
			ensureConversation: () => undefined,
		});

		expect(sendAdminAlert.mock.calls.map(([alert]) => alert.title)).toEqual([
			"Household emergency signal",
			"Household emergency signal",
			"Household emergency signal",
			"REPEATED household emergency signal — escalating (2×)",
		]);
	});

	it("rolls failed first and repeated alerts back so the next event retries the same count", async () => {
		let now = NOW;
		const sendAdminAlert = vi
			.fn<(alert: { title: string; message: string }) => Promise<void>>()
			.mockRejectedValueOnce(new Error("first alert offline"))
			.mockResolvedValueOnce(undefined)
			.mockResolvedValueOnce(undefined)
			.mockRejectedValueOnce(new Error("repeat alert offline"))
			.mockResolvedValueOnce(undefined);
		const notify = createHouseholdEmergencyNotifier({
			sendControl: vi.fn(async () => {
				throw new Error("bridge offline");
			}),
			sendAdminAlert,
			nowMs: () => now,
		});
		const event = householdEvent("אני לא יכולה לנשום");
		const identity = householdIdentity("parent-a", "f");

		for (let index = 0; index < 5; index += 1) {
			await expect(
				notify({
					event: { ...event, messageId: `wa-msg-${index + 1}` },
					identity,
					ensureConversation: () => undefined,
				}),
			).resolves.toMatchObject({ matched: true, class: "breathing", replySent: false });
			now += 60_000;
		}

		expect(sendAdminAlert.mock.calls.map(([alert]) => alert.title)).toEqual([
			"Household emergency signal",
			"Household emergency signal",
			"REPEATED household emergency signal — escalating (2×)",
			"REPEATED household emergency signal — escalating (3×)",
			"REPEATED household emergency signal — escalating (3×)",
		]);
		expect(sendAdminAlert.mock.calls[4]?.[0]?.message).toContain("repeat_count=3");
		expect(sendAdminAlert.mock.calls[4]?.[0]?.message).toContain("reply_sent=false");
	});

	it("does not let a failed older alert roll back a newer successful reservation", async () => {
		let rejectFirstAlert: ((error: Error) => void) | undefined;
		const sendAdminAlert = vi
			.fn<(alert: { title: string; message: string }) => Promise<void>>()
			.mockImplementationOnce(
				() =>
					new Promise((_resolve, reject) => {
						rejectFirstAlert = reject;
					}),
			)
			.mockResolvedValue(undefined);
		let now = NOW;
		const notify = createHouseholdEmergencyNotifier({
			sendControl: vi.fn(async () => true),
			sendAdminAlert,
			nowMs: () => now,
		});
		const event = householdEvent("כאב בחזה");
		const identity = householdIdentity("parent-a", "f");

		const first = notify({ event, identity, ensureConversation: () => undefined });
		await vi.waitFor(() => expect(sendAdminAlert).toHaveBeenCalledTimes(1));
		now += 60_000;
		await notify({
			event: { ...event, messageId: "wa-msg-2" },
			identity,
			ensureConversation: () => undefined,
		});
		rejectFirstAlert?.(new Error("first alert finished late"));
		await first;
		now += 60_000;
		await notify({
			event: { ...event, messageId: "wa-msg-3" },
			identity,
			ensureConversation: () => undefined,
		});

		expect(sendAdminAlert.mock.calls.map(([alert]) => alert.title)).toEqual([
			"Household emergency signal",
			"REPEATED household emergency signal — escalating (2×)",
			"REPEATED household emergency signal — escalating (3×)",
		]);
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
