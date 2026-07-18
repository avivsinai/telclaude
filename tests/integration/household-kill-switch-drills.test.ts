import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { TelclaudeConfig } from "../../src/config/config.js";
import {
	resolveHouseholdEmergencyActivation,
	resolveHouseholdMediaActivation,
} from "../../src/config/profiles.js";
import {
	createTelclaudeMcpBridge,
	type TelclaudeMcpAuthority,
	type TelclaudeMcpBridgeDependencies,
} from "../../src/hermes/mcp/bridge.js";
import { createTelclaudeLiveMcpRelayClients } from "../../src/hermes/mcp/live-relay-clients.js";
import { createTelclaudeMcpSideEffectLedger } from "../../src/hermes/mcp/side-effect-ledger.js";
import { createRelayConversationStore } from "../../src/hermes/relay-conversation-store.js";
import { resolveHouseholdReminderContext } from "../../src/household-reminders/binding.js";
import { readHouseholdReminderKillSwitches } from "../../src/household-reminders/fire-executor.js";
import {
	getPendingHouseholdReminderProposal,
	prepareHouseholdReminderCreate,
} from "../../src/household-reminders/store.js";
import { resolveJerusalemOneShot } from "../../src/household-reminders/time.js";
import { createAttachmentQuarantineStore } from "../../src/relay/attachment-quarantine-store.js";
import { createHouseholdEmergencyNotifier } from "../../src/relay/household-emergency-notifier.js";
import type { MediaActionConfirmationDispatcher } from "../../src/relay/media-action-confirmation-dispatcher.js";
import { createMediaActionConfirmationStore } from "../../src/relay/media-action-confirmation-store.js";
import { createWhatsAppHouseholdIdentityResolver } from "../../src/relay/whatsapp-household-bindings.js";
import {
	createWhatsAppInboundCl1Pipeline,
	signWhatsAppInboundBridgeEvent,
} from "../../src/relay/whatsapp-inbound-cl1.js";
import { createWhatsAppMediaActionConfirmationInterceptor } from "../../src/relay/whatsapp-media-action-confirmation-interceptor.js";
import { createWhatsAppReminderConfirmationInterceptor } from "../../src/relay/whatsapp-reminder-confirmation-interceptor.js";
import { closeDb, getDb, resetDatabase } from "../../src/storage/db.js";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("household kill-switch drills", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-household-switch-drill-"));
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
		["global", householdConfig({ remindersGlobal: false, parentAReminders: true })],
		["binding", householdConfig({ remindersGlobal: true, parentAReminders: false })],
		["omitted binding", householdConfig({ remindersGlobal: true })],
	] as const)("keeps reminder creation inert when the %s switch is off", async (_switch, config) => {
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger: createTelclaudeMcpSideEffectLedger({
				verifyApproval: async () => ({
					ok: false,
					code: "approval_required",
					reason: "unused in reminder drill",
				}),
			}),
			householdReminderConfig: config,
		});

		await expect(
			clients.scheduleCreate({
				...householdAuthority("parent-a"),
				schedule: { kind: "at", at: futureJerusalemMinute(60) },
				prompt: "לקחת מסמכים",
			}),
		).rejects.toThrow(/reminder.*disabled/i);
		expect(getDb().prepare("SELECT COUNT(*) AS count FROM household_reminders").get()).toEqual({
			count: 0,
		});
	});

	it("keeps every reminder entry point inert after the binding switch is omitted", async () => {
		const activeConfig = householdConfig({ remindersGlobal: true, parentAReminders: true });
		const disabledConfig = householdConfig({ remindersGlobal: true });
		const authority = householdAuthority("parent-a");
		const activeContext = resolveHouseholdReminderContext(authority, activeConfig);
		if (!activeContext) throw new Error("active household reminder context missing");
		const proposal = prepareHouseholdReminderCreate({
			...activeContext,
			text: "לקחת מסמכים",
			source: { kind: "parent" },
			schedule: resolveJerusalemOneShot(futureJerusalemMinute(60)),
		}).reminder;
		const disabledClients = createTelclaudeLiveMcpRelayClients({
			ledger: testLedger(),
			householdReminderConfig: disabledConfig,
		});

		await expect(disabledClients.scheduleList({ ...authority, limit: 20 })).rejects.toThrow(
			/reminder.*disabled/i,
		);
		await expect(
			disabledClients.scheduleUpdate({
				...authority,
				jobId: proposal.id,
				schedule: { kind: "at", at: futureJerusalemMinute(120) },
				prompt: "לקחת מסמכים והפניה",
			}),
		).rejects.toThrow(/reminder.*disabled/i);
		await expect(
			disabledClients.scheduleCancel({ ...authority, jobId: proposal.id }),
		).rejects.toThrow(/reminder.*disabled/i);

		const sendControl = vi.fn(async () => undefined);
		const intercept = createWhatsAppReminderConfirmationInterceptor({
			config: disabledConfig,
			sendControl,
		});
		await expect(
			intercept({
				event: { eventId: "event-1", messageId: "message-1", text: "1", attachments: [] } as never,
				identity: householdIdentity("parent-a"),
				conversation: householdConversation("parent-a"),
			}),
		).resolves.toEqual({ handled: false });
		expect(sendControl).not.toHaveBeenCalled();
		expect(
			getPendingHouseholdReminderProposal(activeContext.authority, activeContext.binding),
		).not.toBeNull();
		expect(resolveHouseholdReminderContext(authority, disabledConfig)).toBeNull();
		expect(readHouseholdReminderKillSwitches(authority, disabledConfig, true)).toEqual({
			globalEnabled: true,
			householdEnabled: true,
			parentEnabled: false,
		});
	});

	it("denies Clalit read and prepare-write when the household profile omits the scope", async () => {
		const providerRead = vi.fn();
		const providerPrepareWrite = vi.fn();
		const bridge = createTelclaudeMcpBridge(
			{ ...householdAuthority("parent-a"), providerScopes: [] },
			{ providerRead, providerPrepareWrite } as unknown as TelclaudeMcpBridgeDependencies,
		);

		await expect(
			bridge.tc_provider_read({ service: "clalit", action: "appointments.list", params: {} }),
		).rejects.toThrow("provider scope denied: clalit");
		await expect(
			bridge.tc_provider_prepare_write({
				service: "clalit",
				action: "prescription_renewal",
				params: { medicationId: "medication-1" },
			}),
		).rejects.toThrow("provider scope denied: clalit");
		expect(providerRead).not.toHaveBeenCalled();
		expect(providerPrepareWrite).not.toHaveBeenCalled();
	});

	it("keeps media and emergency activation fail-closed globally and per binding", () => {
		const globallyDisabled = householdConfig({
			remindersGlobal: true,
			parentAReminders: true,
			mediaGlobal: false,
			parentAMedia: true,
			emergencyGlobal: false,
			parentAEmergency: true,
		});
		expect(resolveHouseholdMediaActivation(globallyDisabled, "x".repeat(32))).toEqual({
			enabled: false,
			reason: "global_disabled",
		});
		expect(resolveHouseholdEmergencyActivation(globallyDisabled)).toEqual({
			enabled: false,
			reason: "global_disabled",
		});

		const perBindingDisabled = householdConfig({
			remindersGlobal: true,
			parentAReminders: true,
			mediaGlobal: true,
			parentAMedia: false,
			emergencyGlobal: true,
			parentAEmergency: false,
		});
		expect(resolveHouseholdMediaActivation(perBindingDisabled, "x".repeat(32))).toEqual({
			enabled: false,
			reason: "binding_disabled",
		});
		expect(resolveHouseholdEmergencyActivation(perBindingDisabled)).toEqual({
			enabled: false,
			reason: "binding_disabled",
		});
	});

	it("bypasses emergency control for a disabled parent while another parent stays live", async () => {
		const config = withLiveParentB(
			householdConfig({
				remindersGlobal: true,
				parentAReminders: true,
				emergencyGlobal: true,
				parentAEmergency: false,
			}),
		);
		const activation = resolveHouseholdEmergencyActivation(config);
		if (!activation.enabled) throw new Error(`emergency activation missing: ${activation.reason}`);
		const sendControl = vi.fn(async () => true);
		const sendAdminAlert = vi.fn(async () => undefined);
		const delivered = vi.fn(async () => undefined);
		const pipeline = createWhatsAppInboundCl1Pipeline({
			signatureSecret: "household-kill-switch-drill-secret",
			conversationStore: createRelayConversationStore(),
			quarantineStore: createAttachmentQuarantineStore(),
			resolveIdentity: createWhatsAppHouseholdIdentityResolver(config),
			handleHouseholdEmergency: createHouseholdEmergencyNotifier({
				sendControl,
				sendAdminAlert,
				eligibleBindingIds: activation.eligibleBindingIds,
			}),
			onInboundEvent: delivered,
		});

		const parentAEvent = householdInboundEvent({
			eventId: "event-parent-a",
			messageId: "message-parent-a",
			senderAddressRef: "whatsapp:+15557654321",
			conversationKey: "whatsapp:15557654321@s.whatsapp.net",
		});
		const parentAResult = await pipeline.ingest({
			event: parentAEvent,
			signature: signWhatsAppInboundBridgeEvent(parentAEvent, "household-kill-switch-drill-secret"),
		});
		if (!parentAResult.ok) throw new Error(JSON.stringify(parentAResult));
		expect(parentAResult).toMatchObject({ ok: true, intercepted: false });
		expect(sendControl).not.toHaveBeenCalled();
		expect(sendAdminAlert).not.toHaveBeenCalled();
		expect(delivered).toHaveBeenCalledTimes(1);

		const parentBEvent = householdInboundEvent({
			eventId: "event-parent-b",
			messageId: "message-parent-b",
			cursorSequence: 2,
			senderAddressRef: "whatsapp:+15557654322",
			conversationKey: "whatsapp:15557654322@s.whatsapp.net",
		});
		const parentBResult = await pipeline.ingest({
			event: parentBEvent,
			signature: signWhatsAppInboundBridgeEvent(parentBEvent, "household-kill-switch-drill-secret"),
		});
		if (!parentBResult.ok) throw new Error(JSON.stringify(parentBResult));
		expect(parentBResult).toMatchObject({ ok: true, intercepted: false });
		expect(sendControl).toHaveBeenCalledTimes(1);
		expect(sendControl).toHaveBeenCalledWith(expect.objectContaining({ bindingId: "parent-b" }));
		expect(sendAdminAlert).toHaveBeenCalledTimes(1);
		expect(delivered).toHaveBeenCalledTimes(2);
	});

	it("routes an emergency phrase normally when the global emergency switch is off", async () => {
		const config = householdConfig({
			remindersGlobal: true,
			parentAReminders: true,
			emergencyGlobal: false,
			parentAEmergency: true,
		});
		const activation = resolveHouseholdEmergencyActivation(config);
		if (activation.enabled) throw new Error("global emergency switch unexpectedly enabled");
		const sendControl = vi.fn();
		const sendAdminAlert = vi.fn();
		const delivered = vi.fn(async () => undefined);
		const pipeline = createWhatsAppInboundCl1Pipeline({
			signatureSecret: "household-global-emergency-drill-secret",
			conversationStore: createRelayConversationStore(),
			quarantineStore: createAttachmentQuarantineStore(),
			resolveIdentity: createWhatsAppHouseholdIdentityResolver(config),
			onInboundEvent: delivered,
		});
		const event = householdInboundEvent({
			eventId: "event-emergency-global-off",
			messageId: "message-emergency-global-off",
			senderAddressRef: "whatsapp:+15557654321",
			conversationKey: "whatsapp:15557654321@s.whatsapp.net",
		});

		await expect(
			pipeline.ingest({
				event,
				signature: signWhatsAppInboundBridgeEvent(event, "household-global-emergency-drill-secret"),
			}),
		).resolves.toMatchObject({ ok: true, intercepted: false });
		expect(sendControl).not.toHaveBeenCalled();
		expect(sendAdminAlert).not.toHaveBeenCalled();
		expect(delivered).toHaveBeenCalledTimes(1);
	});

	it("keeps disabled media confirmations inert while another parent can confirm", async () => {
		const globallyDisabled = householdConfig({
			remindersGlobal: true,
			parentAReminders: true,
			mediaGlobal: false,
			parentAMedia: true,
		});
		expect(configuredMediaInterceptor(globallyDisabled)).toBeNull();

		const config = withLiveParentB(
			householdConfig({
				remindersGlobal: true,
				parentAReminders: true,
				mediaGlobal: true,
				parentAMedia: false,
			}),
		);
		const fixture = configuredMediaInterceptor(config);
		if (!fixture) throw new Error("media confirmation interceptor missing");
		const parentA = mediaOwner("parent-a", "whatsapp:+15557654321");
		const parentB = mediaOwner("parent-b", "whatsapp:+15557654322");
		armMediaConfirmation(fixture.store, parentA, `turn_${"1".repeat(32)}`);
		armMediaConfirmation(fixture.store, parentB, `turn_${"2".repeat(32)}`);

		await expect(
			fixture.intercept({
				event: {
					eventId: "event-media-a",
					messageId: "message-media-a",
					text: "1",
					attachments: [],
				} as never,
				identity: householdIdentity("parent-a"),
				conversation: householdConversation("parent-a"),
			}),
		).resolves.toEqual({ handled: false });
		expect(fixture.store.peekPendingForOwner({ owner: parentA })).not.toBeNull();
		expect(fixture.sendControl).not.toHaveBeenCalled();
		expect(fixture.dispatcher.dispatch).not.toHaveBeenCalled();

		await expect(
			fixture.intercept({
				event: {
					eventId: "event-media-b",
					messageId: "message-media-b",
					text: "1",
					attachments: [],
				} as never,
				identity: householdIdentity("parent-b", "whatsapp:+15557654322", "m"),
				conversation: householdConversation("parent-b"),
			}),
		).resolves.toEqual({ handled: true, templateId: "confirmed" });
		expect(fixture.sendControl).toHaveBeenCalledWith(
			expect.objectContaining({ bindingId: "parent-b", templateId: "confirmed" }),
		);
		expect(fixture.dispatcher.dispatch).toHaveBeenCalledTimes(1);
	});
});

function testLedger() {
	return createTelclaudeMcpSideEffectLedger({
		verifyApproval: async () => ({
			ok: false,
			code: "approval_required",
			reason: "unused in kill-switch drill",
		}),
	});
}

function householdAuthority(bindingId: string): TelclaudeMcpAuthority {
	return {
		actorId: `household:whatsapp:${bindingId}`,
		subjectUserId: `household:${bindingId}`,
		profileId: bindingId,
		domain: "household" as const,
		memorySource: `household:${bindingId}`,
		writableNamespace: `household:${bindingId}`,
		providerScopes: ["clalit"],
		capabilityScopes: ["schedule.read", "schedule.write"],
		outboundChannels: ["whatsapp"],
		endpointId: "endpoint-household",
		networkNamespace: "netns-household",
	};
}

function householdIdentity(
	bindingId: string,
	principalId = "whatsapp:+15557654321",
	addresseeGender: "f" | "m" = "f",
) {
	const digits = principalId.slice("whatsapp:+".length);
	return {
		domain: "household",
		actorId: `household:whatsapp:${bindingId}`,
		subjectUserId: `household:${bindingId}`,
		profileId: bindingId,
		bindingId,
		principalId,
		displayName: "Parent A",
		addresseeGender,
		memorySource: `household:${bindingId}`,
		writableNamespace: `household:${bindingId}`,
		replyAddressRef: principalId,
		expectedConversationKey: `whatsapp:${digits}@s.whatsapp.net`,
		conversationId: `whatsapp:household:${bindingId}`,
		identityAssurance: "strong_link",
		authorizationScopes: ["message:read", "message:reply"],
		actorScopes: [],
		humanPairingProvenance: true,
	} as never;
}

function configuredMediaInterceptor(config: TelclaudeConfig) {
	const activation = resolveHouseholdMediaActivation(config, "x".repeat(32));
	if (!activation.enabled) return null;
	let sequence = 0;
	const store = createMediaActionConfirmationStore({
		encryptionKey: activation.encryptionKey,
		makeConfirmationId: () => `media-confirmation-${++sequence}`,
		makeJti: () => `media-confirmation-jti-${sequence}`,
	});
	const dispatcher = {
		mintFreshTurn: vi.fn(() => ({ ref: `turn_${"9".repeat(32)}` }) as never),
		dispatch: vi.fn(async () => ({
			ok: true as const,
			response: "done",
			success: true,
			toolUses: 1,
			toolResults: 1,
		})),
	} satisfies MediaActionConfirmationDispatcher;
	const sendControl = vi.fn(async () => undefined);
	return {
		store,
		dispatcher,
		sendControl,
		intercept: createWhatsAppMediaActionConfirmationInterceptor({
			store,
			dispatcher,
			sendControl,
			config: { hermes: {} as never },
			eligibleBindingIds: activation.eligibleBindingIds,
			resolveProfile: (identity) => ({
				id: identity.profileId,
				label: identity.displayName ?? identity.bindingId,
				allowedSkills: [],
				providerScopes: ["clalit"],
				capabilityScopes: ["schedule.read", "schedule.write"],
				outboundChannels: ["whatsapp"],
				implicit: false,
			}),
		}),
	};
}

function mediaOwner(bindingId: string, principalId: string) {
	return {
		actorId: `household:whatsapp:${bindingId}`,
		subjectUserId: `household:${bindingId}`,
		profileId: bindingId,
		bindingId,
		conversationId: `whatsapp:household:${bindingId}`,
		senderPrincipalHash: `sha256:${cryptoHash(principalId)}` as const,
	};
}

function armMediaConfirmation(
	store: ReturnType<typeof createMediaActionConfirmationStore>,
	owner: ReturnType<typeof mediaOwner>,
	turnRef: string,
) {
	store.registerTurnDerivation({
		owner,
		turnRef,
		envelopes: [
			{
				kind: "document_extract",
				text: "נא לחדש מרשם",
				sourceSha256: "1".repeat(64),
				sourceMediaType: "image/jpeg",
				sourcePageCount: 1,
				extractor: "openai_responses_document_extract_v1",
				confidenceSource: "document_confidence_unavailable_v1",
				confirmed: false,
				confidencePolicyVersion: "media_confidence_policy_v1",
				lowConfidence: true,
				lowConfidenceReasonCodes: ["document_confidence_unavailable"],
				classifierVersion: "derived_media_action_classifier_v1",
				actionBearing: true,
				actionBearingReasonCodes: ["explicit_action_verb"],
			},
		],
	});
	store.guardConsequentialAction({
		turnRef,
		authority: {
			actorId: owner.actorId,
			subjectUserId: owner.subjectUserId,
			profileId: owner.profileId,
		},
		action: {
			toolName: "tc_provider_prepare_write",
			params: { action: "prescription_renewal" },
		},
	});
}

function cryptoHash(value: string): string {
	return crypto.createHash("sha256").update(value).digest("hex");
}

function householdConversation(bindingId: string) {
	return {
		channel: "whatsapp",
		domain: "household",
		authorizationState: "authorized",
		revokedAtMs: null,
		humanPairingProvenance: true,
		conversationId: `whatsapp:household:${bindingId}`,
		profileId: bindingId,
		token: `conv_${"1".repeat(32)}`,
	} as never;
}

function householdInboundEvent(overrides: {
	readonly eventId: string;
	readonly messageId: string;
	readonly cursorSequence?: number;
	readonly senderAddressRef: string;
	readonly conversationKey: string;
}) {
	return {
		schemaVersion: "telclaude.edge.whatsapp.inbound.v1" as const,
		eventId: overrides.eventId,
		messageId: overrides.messageId,
		cursorSequence: overrides.cursorSequence ?? 1,
		chatKind: "direct" as const,
		senderAddressRef: overrides.senderAddressRef,
		conversationKey: overrides.conversationKey,
		text: "יש לי כאב בחזה",
		attachments: [],
		receivedAtMs: Date.now(),
	};
}

function futureJerusalemMinute(minutesFromNow: number): string {
	const parts = new Intl.DateTimeFormat("en-CA", {
		timeZone: "Asia/Jerusalem",
		year: "numeric",
		month: "2-digit",
		day: "2-digit",
		hour: "2-digit",
		minute: "2-digit",
		hourCycle: "h23",
	}).formatToParts(Date.now() + minutesFromNow * 60_000);
	const value = (name: string) => parts.find((part) => part.type === name)?.value;
	return `${value("year")}-${value("month")}-${value("day")}T${value("hour")}:${value("minute")}`;
}

function householdConfig(input: {
	readonly remindersGlobal: boolean;
	readonly parentAReminders?: boolean;
	readonly mediaGlobal?: boolean;
	readonly parentAMedia?: boolean;
	readonly emergencyGlobal?: boolean;
	readonly parentAEmergency?: boolean;
}): TelclaudeConfig {
	return {
		householdReminders: { enabled: input.remindersGlobal },
		householdMedia: { enabled: input.mediaGlobal ?? false },
		householdEmergency: { enabled: input.emergencyGlobal ?? false },
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
						address: "whatsapp:+15557654321",
						replyAddress: "whatsapp:+15557654321",
						displayName: "Parent A",
						subjectUserId: "household:parent-a",
						...(input.parentAReminders === undefined
							? {}
							: { remindersEnabled: input.parentAReminders }),
						...(input.parentAMedia === undefined ? {} : { mediaEnabled: input.parentAMedia }),
						...(input.parentAEmergency === undefined
							? {}
							: { emergencyEnabled: input.parentAEmergency }),
						reminderConsent: {
							state: "granted",
							ceremonyVersion: "phase0.v1",
							ceremonyHash: `sha256:${"a".repeat(64)}`,
							verifiedChannelHash:
								"sha256:a0237ae1db3c517ae525a8b60cb1b956bf87d4369f0b7533204cd7706236bce6",
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
}

function withLiveParentB(config: TelclaudeConfig): TelclaudeConfig {
	return {
		...config,
		profiles: [
			...(config.profiles ?? []),
			{
				id: "parent-b",
				label: "Parent B",
				allowedSkills: [],
				providerScopes: ["clalit"],
				capabilityScopes: ["schedule.read", "schedule.write"],
				outboundChannels: ["whatsapp"],
				whatsappHouseholdBindings: [
					{
						bindingId: "parent-b",
						addresseeGender: "m",
						address: "whatsapp:+15557654322",
						replyAddress: "whatsapp:+15557654322",
						displayName: "Parent B",
						subjectUserId: "household:parent-b",
						remindersEnabled: true,
						mediaEnabled: true,
						emergencyEnabled: true,
					},
				],
			},
		],
	} as TelclaudeConfig;
}
