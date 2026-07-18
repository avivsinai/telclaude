import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { TelclaudeConfig } from "../../src/config/config.js";
import { getCronJob } from "../../src/cron/store.js";
import { createRelayConversationStore } from "../../src/hermes/relay-conversation-store.js";
import { resolveHouseholdReminderContext } from "../../src/household-reminders/binding.js";
import { createHouseholdReminderFirePreparation } from "../../src/household-reminders/fire-executor.js";
import { reconcileHouseholdReminderBindings } from "../../src/household-reminders/reconcile.js";
import { renderHouseholdReminderBody } from "../../src/household-reminders/render.js";
import {
	claimHouseholdReminderFire,
	createAppointmentDerivedHouseholdReminder,
	getHouseholdReminderFire,
	getHouseholdReminderForAuthority,
	prepareHouseholdReminderCreate,
} from "../../src/household-reminders/store.js";
import { resolveJerusalemOneShot } from "../../src/household-reminders/time.js";
import { createMediaActionConfirmationStore } from "../../src/relay/media-action-confirmation-store.js";
import { createWhatsAppHouseholdIdentityResolver } from "../../src/relay/whatsapp-household-bindings.js";
import { closeDb, getDb, resetDatabase } from "../../src/storage/db.js";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;
const ADDRESS = "whatsapp:+15557654321";

describe("household binding revocation drill", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-household-revocation-drill-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		resetDatabase();
	});

	afterEach(() => {
		closeDb();
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) delete process.env.TELCLAUDE_DATA_DIR;
		else process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
	});

	it("cancels scheduled reminders and unfired claims when the binding disappears", async () => {
		const activeConfig = householdConfig();
		const authority = {
			actorId: "household:whatsapp:parent-a",
			subjectUserId: "household:parent-a",
			profileId: "parent-a",
		};
		const context = resolveHouseholdReminderContext(authority, activeConfig);
		if (!context) throw new Error("active reminder context missing");
		const schedule = resolveJerusalemOneShot(futureJerusalemMinute(60));
		const { reminder } = createAppointmentDerivedHouseholdReminder({
			...context,
			text: "תור אצל רופאת המשפחה",
			observationHash: `sha256:${"9".repeat(64)}`,
			addresseeGender: context.addresseeGender,
			schedule,
		});
		const claimed = claimHouseholdReminderFire({
			reminderId: reminder.id,
			revision: reminder.revision,
			scheduledForMs: reminder.schedule.resolvedAtMs,
		});
		const identity = createWhatsAppHouseholdIdentityResolver(activeConfig)({
			senderAddressRef: ADDRESS,
		});
		if (identity?.domain !== "household") throw new Error("active household identity missing");
		const conversationStore = createRelayConversationStore();
		const conversation = conversationStore.mint({
			channel: "whatsapp",
			conversationId: identity.conversationId,
			threadId: identity.expectedConversationKey,
			profileId: identity.profileId,
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
		});
		const revokedConfig = { ...activeConfig, profiles: [] } as TelclaudeConfig;
		expect(resolveHouseholdReminderContext(authority, revokedConfig)).toBeNull();
		const prepare = createHouseholdReminderFirePreparation({
			config: revokedConfig,
			conversationStore,
			edgeRuntime: {} as never,
			ledger: {} as never,
		});

		await expect(
			prepare({
				reminder,
				fire: claimed.fire,
				body: "תזכורת: תור אצל רופאת המשפחה",
			}),
		).rejects.toThrow("household reminder context changed");
		expect(getHouseholdReminderForAuthority(reminder.id, authority)?.status).toBe("cancelled");
		expect(getHouseholdReminderFire(claimed.fire.fireId)).toMatchObject({
			state: "dead_lettered",
			failureClass: "binding_revoked",
		});
		expect(conversationStore.resolveAuthorized(conversation.token)).toBeNull();
	});

	it.each([
		[
			"per-binding switch",
			() => householdConfig([householdProfile("parent-a", ADDRESS, "f", false)]),
		],
		[
			"global switch",
			() => ({ ...householdConfig(), householdReminders: { enabled: false } }) as TelclaudeConfig,
		],
	] as const)("denies on %s off without revoking durable binding state", async (_name, disabled) => {
		const activeConfig = householdConfig();
		const disabledConfig = disabled();
		const targeted = scheduledReminder(activeConfig, "parent-a", "7", 60);
		const other = scheduledReminder(activeConfig, "parent-a", "6", 120);
		const claimed = claimHouseholdReminderFire({
			reminderId: targeted.id,
			revision: targeted.revision,
			scheduledForMs: targeted.schedule.resolvedAtMs,
		}).fire;
		const conversationStore = createRelayConversationStore();
		const conversation = mintHouseholdConversation(
			conversationStore,
			activeConfig,
			ADDRESS,
			`flag-off-${targeted.id}`,
		);
		const conversationBefore = conversationStore.inspect(conversation.conversation.token);
		const owner = mediaOwner("parent-a", ADDRESS);
		const mediaStore = createMediaActionConfirmationStore({
			encryptionKey: "household-flag-off-media-key-32-characters",
			makeConfirmationId: () => `flag-off-media-${targeted.id}`,
			makeJti: () => `flag-off-media-jti-${targeted.id}`,
		});
		const media = seedMediaConfirmation(mediaStore, owner, `turn_${"5".repeat(32)}`);
		const prepare = createHouseholdReminderFirePreparation({
			config: disabledConfig,
			conversationStore,
			edgeRuntime: {} as never,
			ledger: {} as never,
		});

		expect(resolveHouseholdReminderContext(targeted.authority, disabledConfig)).toBeNull();
		await expect(
			prepare({ reminder: targeted, fire: claimed, body: renderHouseholdReminderBody(targeted) }),
		).rejects.toThrow("household reminder context changed");
		expect(getHouseholdReminderForAuthority(targeted.id, targeted.authority)?.status).toBe(
			"scheduled",
		);
		expect(getHouseholdReminderForAuthority(other.id, other.authority)?.status).toBe("scheduled");
		expect(getHouseholdReminderFire(claimed.fireId)?.state).toBe("claimed");
		expect(conversationStore.inspect(conversation.conversation.token)).toEqual(conversationBefore);
		expect(conversationStore.resolveAuthorized(conversation.conversation.token)).toEqual(
			conversationBefore,
		);
		expect(
			mediaStore.readPendingPayload({
				confirmationId: media.confirmation.confirmationId,
				owner,
			}),
		).not.toBeNull();
		expect(
			getDb()
				.prepare(
					"SELECT COUNT(*) AS count FROM household_media_action_confirmation_content WHERE confirmation_id = ?",
				)
				.get(media.confirmation.confirmationId),
		).toEqual({ count: 1 });
	});

	it("reconciles only removed bindings at startup and is idempotent", () => {
		const parentBAddress = "whatsapp:+15557654322";
		const activeConfig = householdConfig([
			householdProfile("parent-a", ADDRESS, "f"),
			householdProfile("parent-b", parentBAddress, "m"),
		]);
		const parentA = scheduledReminder(activeConfig, "parent-a", "9", 60);
		const parentB = scheduledReminder(activeConfig, "parent-b", "8", 120);
		const parentAFire = claimHouseholdReminderFire({
			reminderId: parentA.id,
			revision: parentA.revision,
			scheduledForMs: parentA.schedule.resolvedAtMs,
		}).fire;
		const parentBFire = claimHouseholdReminderFire({
			reminderId: parentB.id,
			revision: parentB.revision,
			scheduledForMs: parentB.schedule.resolvedAtMs,
		}).fire;
		const parentAContext = resolveHouseholdReminderContext(parentA.authority, activeConfig);
		if (!parentAContext) throw new Error("active parent A context missing");
		const pending = prepareHouseholdReminderCreate({
			...parentAContext,
			text: "לקחת מסמכים",
			source: { kind: "parent" },
			schedule: resolveJerusalemOneShot(futureJerusalemMinute(180)),
		});
		const currentConfig = householdConfig([householdProfile("parent-b", parentBAddress, "m")]);

		expect(reconcileHouseholdReminderBindings(currentConfig, Date.now())).toMatchObject({
			bindingsRevoked: 1,
			remindersCancelled: 2,
			firesDeadLettered: 1,
			proposalsExpired: 1,
			leasesReleased: 1,
		});
		expect(getHouseholdReminderForAuthority(parentA.id, parentA.authority)?.status).toBe(
			"cancelled",
		);
		expect(getHouseholdReminderFire(parentAFire.fireId)).toMatchObject({
			state: "dead_lettered",
			failureClass: "binding_revoked",
		});
		expect(getCronJob(`household-reminder:${parentA.id}`)).toMatchObject({
			enabled: false,
			nextRunAtMs: null,
		});
		expect(
			getDb()
				.prepare("SELECT status FROM household_reminder_proposals WHERE ref = ?")
				.get(pending.proposal.ref),
		).toEqual({ status: "expired" });
		expect(
			getDb()
				.prepare(
					"SELECT COUNT(*) AS count FROM household_interactive_choice_leases WHERE binding_id = ? AND owner_kind = 'reminder'",
				)
				.get(parentA.binding.bindingId),
		).toEqual({ count: 0 });
		expect(getHouseholdReminderForAuthority(parentB.id, parentB.authority)?.status).toBe(
			"scheduled",
		);
		expect(getHouseholdReminderFire(parentBFire.fireId)?.state).toBe("claimed");
		expect(reconcileHouseholdReminderBindings(currentConfig, Date.now())).toEqual({
			bindingsRevoked: 0,
			conversationsRevoked: 0,
			turnsRevoked: 0,
			remindersCancelled: 0,
			firesDeadLettered: 0,
			proposalsExpired: 0,
			leasesReleased: 0,
			mediaConfirmationsRevoked: 0,
			mediaContentRowsDeleted: 0,
			mediaDerivationsDeleted: 0,
		});
	});

	it("revokes a removed binding's persisted conversation and in-flight turn", () => {
		const activeConfig = householdConfig();
		const identity = createWhatsAppHouseholdIdentityResolver(activeConfig)({
			senderAddressRef: ADDRESS,
		});
		if (identity?.domain !== "household") {
			throw new Error("active household identity missing");
		}
		const store = createRelayConversationStore();
		const minted = store.mint({
			channel: "whatsapp",
			conversationId: identity.conversationId,
			threadId: identity.expectedConversationKey,
			profileId: identity.profileId,
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
		});
		const turn = store.mintInboundTurn({
			conversationToken: minted.token,
			inboundMessageId: "message-before-revocation",
			senderActorId: identity.actorId,
		});
		const revokedConfig = { ...activeConfig, profiles: [] } as TelclaudeConfig;
		reconcileHouseholdReminderBindings(revokedConfig, Date.now(), store);

		expect(
			createWhatsAppHouseholdIdentityResolver(revokedConfig)({ senderAddressRef: ADDRESS }),
		).toBeNull();
		expect(store.resolveAuthorized(minted.token)).toBeNull();
		expect(store.resolveAuthorizedInboundTurn(turn.turnRef, minted.token)).toBeNull();
		const restartedStore = createRelayConversationStore();
		expect(restartedStore.resolveAuthorized(minted.token)).toBeNull();
		expect(restartedStore.resolveAuthorizedInboundTurn(turn.turnRef, minted.token)).toBeNull();
		const revokedConversation = store.inspect(minted.token);
		const revokedTurn = store.inspectInboundTurn(turn.turnRef);
		expect(reconcileHouseholdReminderBindings(revokedConfig, Date.now(), store)).toMatchObject({
			conversationsRevoked: 0,
			turnsRevoked: 0,
		});
		expect(store.inspect(minted.token)).toEqual(revokedConversation);
		expect(store.inspectInboundTurn(turn.turnRef)).toEqual(revokedTurn);
	});

	it("leaves a live household conversation byte-unchanged", () => {
		const config = householdConfig();
		const identity = createWhatsAppHouseholdIdentityResolver(config)({
			senderAddressRef: ADDRESS,
		});
		if (identity?.domain !== "household") throw new Error("active household identity missing");
		const store = createRelayConversationStore();
		const minted = store.mint({
			channel: "whatsapp",
			conversationId: identity.conversationId,
			threadId: identity.expectedConversationKey,
			profileId: identity.profileId,
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
		});
		const before = store.inspect(minted.token);

		expect(reconcileHouseholdReminderBindings(config, Date.now(), store)).toMatchObject({
			conversationsRevoked: 0,
			turnsRevoked: 0,
		});
		expect(store.inspect(minted.token)).toEqual(before);
		expect(store.resolveAuthorized(minted.token)).toEqual(before);
	});

	it("revokes removed A while live B conversation and turn remain byte-unchanged", () => {
		const parentBAddress = "whatsapp:+15557654322";
		const activeConfig = householdConfig([
			householdProfile("parent-a", ADDRESS, "f"),
			householdProfile("parent-b", parentBAddress, "m"),
		]);
		const store = createRelayConversationStore();
		const parentA = mintHouseholdConversation(store, activeConfig, ADDRESS, "mixed-parent-a");
		const parentB = mintHouseholdConversation(
			store,
			activeConfig,
			parentBAddress,
			"mixed-parent-b",
		);
		const parentBBefore = store.inspect(parentB.conversation.token);
		const parentBTurnBefore = store.inspectInboundTurn(parentB.turn.turnRef);
		const currentConfig = householdConfig([householdProfile("parent-b", parentBAddress, "m")]);

		expect(reconcileHouseholdReminderBindings(currentConfig, Date.now(), store)).toMatchObject({
			conversationsRevoked: 1,
			turnsRevoked: 1,
		});
		expect(store.resolveAuthorized(parentA.conversation.token)).toBeNull();
		expect(
			store.resolveAuthorizedInboundTurn(parentA.turn.turnRef, parentA.conversation.token),
		).toBeNull();
		expect(store.inspect(parentB.conversation.token)).toEqual(parentBBefore);
		expect(store.inspectInboundTurn(parentB.turn.turnRef)).toEqual(parentBTurnBefore);
		expect(store.resolveAuthorized(parentB.conversation.token)).toEqual(parentBBefore);
		expect(
			store.resolveAuthorizedInboundTurn(parentB.turn.turnRef, parentB.conversation.token),
		).toEqual(parentBTurnBefore);
	});

	it("revokes pending media confirmation state and its interactive lease", () => {
		const activeConfig = householdConfig();
		const owner = mediaOwner("parent-a", ADDRESS);
		const mediaStore = createMediaActionConfirmationStore({
			encryptionKey: "household-revocation-media-key-32-characters",
			makeConfirmationId: () => "media-confirmation-before-revocation",
			makeJti: () => "media-confirmation-jti-before-revocation",
		});
		const turnRef = `turn_${"7".repeat(32)}`;
		const guarded = seedMediaConfirmation(mediaStore, owner, turnRef);
		expect(
			mediaStore.readPendingPayload({
				confirmationId: guarded.confirmation.confirmationId,
				owner,
			}),
		).not.toBeNull();
		expect(
			getDb()
				.prepare(
					"SELECT COUNT(*) AS count FROM household_media_action_confirmation_content WHERE confirmation_id = ?",
				)
				.get(guarded.confirmation.confirmationId),
		).toEqual({ count: 1 });
		const revokedConfig = { ...activeConfig, profiles: [] } as TelclaudeConfig;

		expect(reconcileHouseholdReminderBindings(revokedConfig)).toMatchObject({
			bindingsRevoked: 1,
			mediaConfirmationsRevoked: 1,
			mediaContentRowsDeleted: 1,
			mediaDerivationsDeleted: 1,
			leasesReleased: 1,
		});
		expect(mediaStore.inspectConfirmation("media-confirmation-before-revocation")?.status).toBe(
			"revoked",
		);
		expect(mediaStore.peekPendingForOwner({ owner })).toBeNull();
		expect(
			mediaStore.readPendingPayload({
				confirmationId: guarded.confirmation.confirmationId,
				owner,
			}),
		).toBeNull();
		expect(
			getDb()
				.prepare(
					"SELECT COUNT(*) AS count FROM household_media_action_confirmation_content WHERE confirmation_id = ?",
				)
				.get(guarded.confirmation.confirmationId),
		).toEqual({ count: 0 });
		expect(
			getDb()
				.prepare(
					"SELECT COUNT(*) AS count FROM household_media_turn_derivations WHERE binding_id = ?",
				)
				.get(owner.bindingId),
		).toEqual({ count: 0 });
	});
});

function mintHouseholdConversation(
	store: ReturnType<typeof createRelayConversationStore>,
	config: TelclaudeConfig,
	address: string,
	inboundMessageId: string,
) {
	const identity = createWhatsAppHouseholdIdentityResolver(config)({ senderAddressRef: address });
	if (identity?.domain !== "household") throw new Error("active household identity missing");
	const conversation = store.mint({
		channel: "whatsapp",
		conversationId: identity.conversationId,
		threadId: identity.expectedConversationKey,
		profileId: identity.profileId,
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
	});
	const turn = store.mintInboundTurn({
		conversationToken: conversation.token,
		inboundMessageId,
		senderActorId: identity.actorId,
	});
	return { conversation, turn };
}

function mediaOwner(bindingId: string, address: string) {
	return {
		actorId: `household:whatsapp:${bindingId}`,
		subjectUserId: `household:${bindingId}`,
		profileId: bindingId,
		bindingId,
		conversationId: `whatsapp:household:${bindingId}`,
		senderPrincipalHash:
			`sha256:${crypto.createHash("sha256").update(address).digest("hex")}` as const,
	};
}

function seedMediaConfirmation(
	store: ReturnType<typeof createMediaActionConfirmationStore>,
	owner: ReturnType<typeof mediaOwner>,
	turnRef: string,
) {
	store.registerTurnDerivation({ owner, turnRef, envelopes: [documentEnvelope()] });
	const guarded = store.guardConsequentialAction({
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
	if (!guarded.required) throw new Error("media confirmation was not created");
	return guarded;
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

function scheduledReminder(
	config: TelclaudeConfig,
	bindingId: string,
	observationChar: string,
	minutesFromNow: number,
) {
	const authority = {
		actorId: `household:whatsapp:${bindingId}`,
		subjectUserId: `household:${bindingId}`,
		profileId: bindingId,
	};
	const context = resolveHouseholdReminderContext(authority, config);
	if (!context) throw new Error(`active reminder context missing: ${bindingId}`);
	return createAppointmentDerivedHouseholdReminder({
		...context,
		text: "תור אצל רופאת המשפחה",
		observationHash: `sha256:${observationChar.repeat(64)}`,
		addresseeGender: context.addresseeGender,
		schedule: resolveJerusalemOneShot(futureJerusalemMinute(minutesFromNow)),
	}).reminder;
}

function householdConfig(profiles = [householdProfile("parent-a", ADDRESS, "f")]): TelclaudeConfig {
	return {
		householdReminders: { enabled: true },
		profiles,
	} as TelclaudeConfig;
}

function householdProfile(
	bindingId: string,
	address: string,
	addresseeGender: "f" | "m",
	remindersEnabled = true,
) {
	return {
		id: bindingId,
		label: bindingId === "parent-a" ? "Parent A" : "Parent B",
		allowedSkills: [],
		providerScopes: ["clalit"],
		capabilityScopes: ["schedule.read", "schedule.write"],
		outboundChannels: ["whatsapp"],
		whatsappHouseholdBindings: [
			{
				bindingId,
				addresseeGender,
				address,
				replyAddress: address,
				displayName: bindingId === "parent-a" ? "Parent A" : "Parent B",
				subjectUserId: `household:${bindingId}`,
				remindersEnabled,
				reminderConsent: {
					state: "granted",
					ceremonyVersion: "phase0.v1",
					ceremonyHash: `sha256:${"a".repeat(64)}`,
					verifiedChannelHash: `sha256:${crypto.createHash("sha256").update(address).digest("hex")}`,
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
	};
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
