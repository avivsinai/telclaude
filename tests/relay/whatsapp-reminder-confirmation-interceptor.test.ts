import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { TelclaudeConfig } from "../../src/config/config.js";
import type { RelayConversation } from "../../src/hermes/relay-conversation-store.js";
import { resolveHouseholdReminderContext } from "../../src/household-reminders/binding.js";
import { householdReminderConfirmationCopy } from "../../src/household-reminders/copy.js";
import {
	confirmHouseholdReminderProposal,
	getHouseholdReminderForAuthority,
	getHouseholdReminderInterceptionReceipt,
	getPendingHouseholdReminderProposal,
	prepareHouseholdReminderCancellation,
	prepareHouseholdReminderCreate,
	prepareHouseholdReminderUpdate,
	resolveHouseholdReminderProposalWithInterceptionReceipt,
} from "../../src/household-reminders/store.js";
import { createPendingProviderChallengeRegistry } from "../../src/relay/pending-provider-challenge.js";
import type {
	WhatsAppIdentityResolution,
	WhatsAppInboundBridgeEvent,
} from "../../src/relay/whatsapp-inbound-cl1.js";
import { composeWhatsAppInboundInterceptors } from "../../src/relay/whatsapp-inbound-http.js";
import { createWhatsAppProviderChallengeInterceptor } from "../../src/relay/whatsapp-provider-challenge-interceptor.js";
import {
	createWhatsAppReminderConfirmationInterceptor,
	parseWhatsAppReminderChoice,
} from "../../src/relay/whatsapp-reminder-confirmation-interceptor.js";
import { closeDb, resetDatabase } from "../../src/storage/db.js";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;
const NOW_MS = Date.parse("2026-07-17T12:00:00.000Z");
const ADDRESS = "whatsapp:+15550000001";

describe("WhatsApp reminder confirmation interceptor", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-reminder-interceptor-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		resetDatabase();
	});

	afterEach(() => {
		closeDb();
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) delete process.env.TELCLAUDE_DATA_DIR;
		else process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
	});

	it("accepts only exact 1/2 input and spends the proposal once", async () => {
		const fixture = reminderFixture();
		const reminder = fixture.arm();

		expect(
			await fixture.intercept({
				event: inbound({ text: "כן" }),
				identity: fixture.identity,
				conversation: fixture.conversation,
			}),
		).toEqual({ handled: true, templateId: "choice_required" });
		expect(fixture.sendControl).toHaveBeenLastCalledWith(
			expect.objectContaining({ body: householdReminderConfirmationCopy("choice_required", "f") }),
		);
		expect(householdReminderConfirmationCopy("choice_required", "f")).toContain("1. אישור");
		expect(householdReminderConfirmationCopy("choice_required", "f")).toContain("2. ביטול");

		expect(
			await fixture.intercept({
				event: inbound({ text: "1" }),
				identity: fixture.identity,
				conversation: fixture.conversation,
			}),
		).toEqual({ handled: true, templateId: "confirmed" });
		expect(getHouseholdReminderForAuthority(reminder.id, fixture.context.authority)?.status).toBe(
			"scheduled",
		);
		expect(
			getPendingHouseholdReminderProposal(fixture.context.authority, fixture.context.binding),
		).toBeNull();
		const afterConfirmation = getHouseholdReminderForAuthority(
			reminder.id,
			fixture.context.authority,
		);
		const sentCount = fixture.sendControl.mock.calls.length;

		expect(
			await fixture.intercept({
				event: inbound({ text: "1" }),
				identity: fixture.identity,
				conversation: fixture.conversation,
			}),
		).toEqual({ handled: true, templateId: "confirmed" });
		expect(getHouseholdReminderForAuthority(reminder.id, fixture.context.authority)).toEqual(
			afterConfirmation,
		);
		expect(fixture.sendControl).toHaveBeenCalledTimes(sentCount);
	});

	it("recovers a crash before ACK completion without a second proposal mutation", async () => {
		const fixture = reminderFixture();
		const reminder = fixture.arm();
		fixture.sendControl.mockRejectedValueOnce(new Error("simulated crash before ack completion"));
		const event = inbound({ eventId: "event-crash", messageId: "message-crash", text: "1" });

		await expect(
			fixture.intercept({ event, identity: fixture.identity, conversation: fixture.conversation }),
		).rejects.toThrow(/simulated crash/);
		expect(getHouseholdReminderForAuthority(reminder.id, fixture.context.authority)?.status).toBe(
			"scheduled",
		);
		const receipt = getHouseholdReminderInterceptionReceipt({
			eventId: event.eventId,
			messageId: event.messageId,
			authority: fixture.context.authority,
			binding: fixture.context.binding,
		});
		expect(receipt).toMatchObject({ status: "pending_ack", templateId: "confirmed" });
		expect(fixture.sendControl).toHaveBeenCalledTimes(1);
		const firstSend = fixture.sendControl.mock.calls[0]?.[0];

		await expect(
			fixture.intercept({ event, identity: fixture.identity, conversation: fixture.conversation }),
		).resolves.toEqual({ handled: true, templateId: "confirmed" });
		expect(fixture.sendControl).toHaveBeenCalledTimes(2);
		expect(fixture.sendControl.mock.calls[1]?.[0]).toEqual(firstSend);
		expect(
			getHouseholdReminderInterceptionReceipt({
				eventId: event.eventId,
				messageId: event.messageId,
				authority: fixture.context.authority,
				binding: fixture.context.binding,
			}),
		).toMatchObject({ status: "acked" });

		await fixture.intercept({
			event,
			identity: fixture.identity,
			conversation: fixture.conversation,
		});
		expect(fixture.sendControl).toHaveBeenCalledTimes(2);
	});

	it("retries the same delivery ref after send-before-ACK without mutating twice", async () => {
		const fixture = reminderFixture();
		const reminder = fixture.arm();
		const proposal = getPendingHouseholdReminderProposal(
			fixture.context.authority,
			fixture.context.binding,
		);
		if (!proposal) throw new Error("test proposal missing");
		const event = inbound({
			eventId: "event-after-send",
			messageId: "message-after-send",
			text: "1",
		});
		const receipt = resolveHouseholdReminderProposalWithInterceptionReceipt({
			eventId: event.eventId,
			messageId: event.messageId,
			proposalRef: proposal.ref,
			choice: "confirm",
			...fixture.context,
			nowMs: NOW_MS,
		});
		if (!receipt) throw new Error("test receipt missing");
		const delivery = {
			templateId: receipt.templateId,
			body: householdReminderConfirmationCopy(receipt.templateId, "f"),
			replyAddressRef: fixture.identity.replyAddressRef,
			bindingId: fixture.identity.bindingId,
			deliveryRef: receipt.receiptId,
		};
		await fixture.sendControl(delivery);
		// Simulate process death after the bridge accepted the send but before the
		// relay could mark the durable receipt acked.
		expect(receipt.status).toBe("pending_ack");

		await expect(
			fixture.intercept({ event, identity: fixture.identity, conversation: fixture.conversation }),
		).resolves.toEqual({ handled: true, templateId: "confirmed" });
		expect(fixture.sendControl.mock.calls).toEqual([[delivery], [delivery]]);
		expect(getHouseholdReminderForAuthority(reminder.id, fixture.context.authority)?.status).toBe(
			"scheduled",
		);
		expect(
			getHouseholdReminderInterceptionReceipt({
				eventId: event.eventId,
				messageId: event.messageId,
				authority: fixture.context.authority,
				binding: fixture.context.binding,
			}),
		).toMatchObject({ status: "acked" });
	});

	it("rejects with 2 and never accepts whitespace or non-ASCII lookalikes", async () => {
		const fixture = reminderFixture();
		const reminder = fixture.arm();
		for (const text of [" 1", "1 ", "１", "אישור"]) {
			expect(
				await fixture.intercept({
					event: inbound({ text }),
					identity: fixture.identity,
					conversation: fixture.conversation,
				}),
			).toEqual({ handled: true, templateId: "choice_required" });
		}
		expect(
			await fixture.intercept({
				event: inbound({ text: "2" }),
				identity: fixture.identity,
				conversation: fixture.conversation,
			}),
		).toEqual({ handled: true, templateId: "rejected" });
		expect(getHouseholdReminderForAuthority(reminder.id, fixture.context.authority)?.status).toBe(
			"cancelled",
		);
	});

	it("lets unrelated input continue to Hermes without spending the pending proposal", async () => {
		const fixture = reminderFixture();
		fixture.arm();

		expect(
			await fixture.intercept({
				event: inbound({ text: "מה מזג האוויר?" }),
				identity: fixture.identity,
				conversation: fixture.conversation,
			}),
		).toEqual({ handled: false });
		expect(fixture.sendControl).not.toHaveBeenCalled();
		expect(
			getPendingHouseholdReminderProposal(fixture.context.authority, fixture.context.binding),
		).not.toBeNull();
	});

	it("acknowledges a confirmed cancellation as cancelled", async () => {
		const fixture = reminderFixture();
		const reminder = scheduleReminder(fixture);
		prepareFollowUpProposal(fixture, reminder.id, "cancel");

		expect(
			await fixture.intercept({
				event: inbound({ text: "1" }),
				identity: fixture.identity,
				conversation: fixture.conversation,
			}),
		).toEqual({ handled: true, templateId: "rejected" });
		expect(getHouseholdReminderForAuthority(reminder.id, fixture.context.authority)?.status).toBe(
			"cancelled",
		);
	});

	it.each([
		"update",
		"cancel",
	] as const)("uses unambiguous unchanged copy when rejecting a pending %s", async (action) => {
		const fixture = reminderFixture();
		const reminder = scheduleReminder(fixture);
		prepareFollowUpProposal(fixture, reminder.id, action);

		expect(
			await fixture.intercept({
				event: inbound({ text: "2" }),
				identity: fixture.identity,
				conversation: fixture.conversation,
			}),
		).toEqual({ handled: true, templateId: "unchanged" });
		expect(fixture.sendControl).toHaveBeenLastCalledWith(
			expect.objectContaining({ body: householdReminderConfirmationCopy("unchanged", "f") }),
		);
		expect(getHouseholdReminderForAuthority(reminder.id, fixture.context.authority)?.status).toBe(
			"scheduled",
		);
	});

	it.each([
		"update",
		"cancel",
	] as const)("reports an expired %s proposal without claiming the reminder was cancelled", async (action) => {
		const fixture = reminderFixture(NOW_MS + 2);
		const reminder = scheduleReminder(fixture);
		prepareFollowUpProposal(fixture, reminder.id, action, 1);

		expect(
			await fixture.intercept({
				event: inbound({ text: "1" }),
				identity: fixture.identity,
				conversation: fixture.conversation,
			}),
		).toEqual({ handled: true, templateId: "proposal_expired" });
		expect(fixture.sendControl).toHaveBeenLastCalledWith(
			expect.objectContaining({
				body: householdReminderConfirmationCopy("proposal_expired", "f"),
			}),
		);
		expect(householdReminderConfirmationCopy("proposal_expired", "f")).not.toBe(
			householdReminderConfirmationCopy("rejected", "f"),
		);
		expect(getHouseholdReminderForAuthority(reminder.id, fixture.context.authority)?.status).toBe(
			"scheduled",
		);
	});

	it("uses fixed failure copy when live consent no longer matches the proposal", async () => {
		const changedConfig = structuredClone(config);
		const consent = changedConfig.profiles?.[0]?.whatsappHouseholdBindings?.[0]?.reminderConsent;
		if (!consent) throw new Error("test reminder consent missing");
		consent.ceremonyHash = `sha256:${"b".repeat(64)}`;
		const fixture = reminderFixture(NOW_MS, changedConfig);
		fixture.arm();

		expect(
			await fixture.intercept({
				event: inbound({ text: "1" }),
				identity: fixture.identity,
				conversation: fixture.conversation,
			}),
		).toEqual({ handled: true, templateId: "failed" });
		expect(fixture.sendControl).toHaveBeenLastCalledWith(
			expect.objectContaining({ body: householdReminderConfirmationCopy("failed", "f") }),
		);
	});

	it("gives an armed provider OTP challenge precedence over a simultaneous reminder proposal", async () => {
		const fixture = reminderFixture();
		fixture.arm();
		const registry = createPendingProviderChallengeRegistry({ nowMs: () => NOW_MS });
		const providerSend = vi.fn(async () => undefined);
		const providerRespond = vi.fn(async () => ({ status: "success" as const }));
		registry.arm({
			origin: "relay_login_coordinator",
			initiationRef: "provider_login_parent_a_12345678",
			initiatingTurnRef: `turn_${"f".repeat(32)}`,
			binding: {
				bindingId: fixture.identity.bindingId,
				actorId: fixture.identity.actorId,
				subjectUserId: fixture.identity.subjectUserId,
				profileId: fixture.identity.profileId,
				conversationToken: fixture.conversation.token,
				conversationId: fixture.conversation.conversationId,
				senderPrincipalHash: digest(fixture.identity.principalId),
			},
			service: "clalit",
			providerChallengeId: "provider-secret",
			challengeType: "sms_otp",
			sidecarExpiresAtMs: NOW_MS + 60_000,
			nowMs: NOW_MS,
		});
		const provider = createWhatsAppProviderChallengeInterceptor({
			registry,
			nowMs: () => NOW_MS,
			respondToChallenge: providerRespond,
			sendControl: providerSend,
		});
		const composed = composeWhatsAppInboundInterceptors({
			providerChallenge: provider,
			reminderConfirmation: fixture.intercept,
		});
		if (!composed) throw new Error("test interceptor composition missing");

		expect(
			await composed({
				event: inbound({ text: "1" }),
				identity: fixture.identity,
				conversation: fixture.conversation,
			}),
		).toEqual({ handled: true, templateId: "challenge_invalid_format" });
		expect(fixture.sendControl).not.toHaveBeenCalled();
		expect(
			getPendingHouseholdReminderProposal(fixture.context.authority, fixture.context.binding),
		).not.toBeNull();

		await composed({
			event: inbound({ text: "246810" }),
			identity: fixture.identity,
			conversation: fixture.conversation,
		});
		expect(providerRespond).toHaveBeenCalledTimes(1);
		expect(
			await composed({
				event: inbound({ text: "1" }),
				identity: fixture.identity,
				conversation: fixture.conversation,
			}),
		).toEqual({ handled: true, templateId: "confirmed" });
	});
});

describe("parseWhatsAppReminderChoice", () => {
	it.each([
		["1", "confirm"],
		["2", "reject"],
		[" 1", null],
		["１", null],
		[undefined, null],
	] as const)("parses exact ASCII choices only: %s", (text, expected) => {
		expect(parseWhatsAppReminderChoice(text)).toBe(expected);
	});
});

function reminderFixture(interceptorNowMs = NOW_MS, interceptorConfig = config) {
	const identity = householdIdentity();
	const conversation = householdConversation(identity);
	const context = resolveHouseholdReminderContext(
		{
			actorId: identity.actorId,
			subjectUserId: identity.subjectUserId,
			profileId: identity.profileId,
		},
		config,
	);
	if (!context) throw new Error("test reminder context missing");
	const sendControl = vi.fn(async () => undefined);
	return {
		identity,
		conversation,
		context,
		sendControl,
		intercept: createWhatsAppReminderConfirmationInterceptor({
			config: interceptorConfig,
			sendControl,
			nowMs: () => interceptorNowMs,
		}),
		arm() {
			return prepareHouseholdReminderCreate({
				...context,
				text: "להביא מסמכים",
				source: { kind: "parent" },
				schedule: {
					timeZone: "Asia/Jerusalem",
					localDateTime: "2026-08-01T09:00",
					resolvedAtMs: Date.parse("2026-08-01T06:00:00.000Z"),
					resolvedAt: "2026-08-01T06:00:00.000Z",
					offsetMinutes: 180,
				},
				nowMs: NOW_MS,
			}).reminder;
		},
	};
}

function scheduleReminder(fixture: ReturnType<typeof reminderFixture>) {
	const reminder = fixture.arm();
	const proposal = getPendingHouseholdReminderProposal(
		fixture.context.authority,
		fixture.context.binding,
	);
	if (!proposal) throw new Error("test create proposal missing");
	const confirmed = confirmHouseholdReminderProposal({
		proposalRef: proposal.ref,
		...fixture.context,
		nowMs: NOW_MS,
	});
	if (!confirmed.ok) throw new Error("test create confirmation failed");
	return reminder;
}

function prepareFollowUpProposal(
	fixture: ReturnType<typeof reminderFixture>,
	reminderId: string,
	action: "update" | "cancel",
	proposalTtlMs?: number,
): void {
	const input = {
		reminderId,
		...fixture.context,
		nowMs: NOW_MS,
		...(proposalTtlMs === undefined ? {} : { proposalTtlMs }),
	};
	if (action === "cancel") {
		prepareHouseholdReminderCancellation(input);
		return;
	}
	prepareHouseholdReminderUpdate({
		...input,
		text: "להביא מסמכים והפניה",
		schedule: {
			timeZone: "Asia/Jerusalem",
			localDateTime: "2026-08-02T09:00",
			resolvedAtMs: Date.parse("2026-08-02T06:00:00.000Z"),
			resolvedAt: "2026-08-02T06:00:00.000Z",
			offsetMinutes: 180,
		},
	});
}

function householdIdentity(): Extract<WhatsAppIdentityResolution, { domain: "household" }> {
	return {
		domain: "household",
		bindingId: "parent-a",
		addresseeGender: "f",
		actorId: "household:whatsapp:parent-a",
		subjectUserId: "household:parent-a",
		profileId: "parent-a",
		principalId: ADDRESS,
		identityAssurance: "strong_link",
		authorizationScopes: ["message:read", "message:reply"],
		actorScopes: [],
		humanPairingProvenance: true,
		memorySource: "household:parent-a",
		writableNamespace: "household:parent-a",
		replyAddressRef: ADDRESS,
		expectedConversationKey: ADDRESS,
		conversationId: "whatsapp:household:parent-a",
	};
}

function householdConversation(
	identity: Extract<WhatsAppIdentityResolution, { domain: "household" }>,
): RelayConversation {
	return {
		token: `conv_${"a".repeat(32)}`,
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
		senderAddressRef: ADDRESS,
		conversationKey: ADDRESS,
		text: "hello",
		attachments: [],
		receivedAtMs: NOW_MS,
		...overrides,
	};
}

function digest(value: string): `sha256:${string}` {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

const config = {
	profiles: [
		{
			id: "parent-a",
			label: "Parent A",
			allowedSkills: [],
			providerScopes: ["clalit"],
			capabilityScopes: ["schedule.read", "schedule.write"],
			outboundChannels: ["whatsapp"],
			whatsappHouseholdBindings: [
				{
					bindingId: "parent-a",
					addresseeGender: "f",
					address: ADDRESS,
					replyAddress: ADDRESS,
					displayName: "Parent A",
					subjectUserId: "household:parent-a",
					reminderConsent: {
						state: "granted",
						ceremonyVersion: "phase0.v1",
						ceremonyHash: `sha256:${"a".repeat(64)}`,
						verifiedChannelHash: digest(ADDRESS),
						categories: {
							proactiveDelivery: true,
							scheduleManagement: true,
							retentionDisclosure: true,
						},
						recordedAt: "2026-07-17T09:00:00.000Z",
						operatorId: "operator:phase0-admin",
					},
				},
			],
		},
	],
} as TelclaudeConfig;
