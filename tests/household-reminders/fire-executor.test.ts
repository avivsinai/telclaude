import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { TelclaudeConfig } from "../../src/config/config.js";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;
const NOW_MS = Date.parse("2026-07-17T00:00:00.000Z");
const HASH = (char: string) => `sha256:${char.repeat(64)}` as `sha256:${string}`;
const ADDRESS = "whatsapp:+15557654321";
const AUTHORITY = {
	actorId: "household:whatsapp:parent-a",
	subjectUserId: "household:parent-a",
	profileId: "parent-a",
};
const BINDING = {
	bindingId: "parent-a",
	conversationId: "whatsapp:household:parent-a",
	senderPrincipalHash: HASH("a"),
	recipientPrincipalHash: HASH("a"),
};
const CONSENT = {
	state: "granted",
	ceremonyVersion: "phase0.v1",
	ceremonyHash: HASH("b"),
	verifiedChannelHash: HASH("a"),
	categories: {
		proactiveDelivery: true,
		scheduleManagement: true,
		retentionDisclosure: true,
	},
	recordedAt: "2026-07-17T09:00:00.000Z",
	operatorId: "operator:phase0-admin",
} as const;

describe("household reminder fire executor", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-reminder-fire-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		vi.resetModules();
		const { resetDatabase } = await import("../../src/storage/db.js");
		resetDatabase();
	});

	afterEach(async () => {
		const { closeDb } = await import("../../src/storage/db.js");
		closeDb();
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) delete process.env.TELCLAUDE_DATA_DIR;
		else process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
	});

	it("renders fixed Hebrew copy and completes one durable fire at the frozen instant", async () => {
		const store = await import("../../src/household-reminders/store.js");
		const { createHouseholdReminderFireExecutor } = await import(
			"../../src/household-reminders/fire-executor.js"
		);
		const reminder = confirmedReminder(store);
		const time = await import("../../src/household-reminders/time.js");
		const currentTzdataValidation = vi
			.spyOn(time, "validateJerusalemOneShotSchedule")
			.mockImplementation(() => {
				throw new Error("simulated current-tzdata drift");
			});
		const prepare = vi.fn(async ({ fire, body }) => ({
			outboundRef: `scheduled-effect:${fire.fireId}` as const,
			edgePreparedHash: HASH("c"),
			idempotencyKey: HASH("d"),
			whatsappMessageId: "TCREMINDER0123456789abcdef0123456789abcdef",
			body,
		}));
		const execute = vi.fn(async ({ beforeDispatch }) => {
			expect(beforeDispatch()).toBe(true);
			return {
				ok: true as const,
				receiptStatus: "sent",
				platformMessageId: "wa-platform-1",
			};
		});
		const executor = createHouseholdReminderFireExecutor({
			prepare,
			execute,
			nowMs: () => NOW_MS + 10_000,
		});

		await expect(
			executor(
				{ reminderId: reminder.id, revision: reminder.revision },
				new AbortController().signal,
			),
		).resolves.toEqual({ ok: true, message: "household reminder delivered" });
		expect(prepare).toHaveBeenCalledWith(
			expect.objectContaining({
				reminder: expect.objectContaining({
					id: reminder.id,
					schedule: expect.objectContaining({
						localDateTime: "2026-08-01T09:00",
						resolvedAtMs: reminder.schedule.resolvedAtMs,
					}),
				}),
				body: "תזכורת: להביא מסמכים",
			}),
		);
		const fire = store.getHouseholdReminderFire(
			prepare.mock.calls[0]?.[0].fire.fireId ?? "missing",
		);
		expect(fire).toMatchObject({
			state: "delivered",
			attemptCount: 1,
			receiptStatus: "sent",
			platformMessageIdHash: expect.stringMatching(/^sha256:/),
		});
		expect(JSON.stringify(fire)).not.toContain("wa-platform-1");
		expect(store.getHouseholdReminderForAuthority(reminder.id, AUTHORITY)?.status).toBe(
			"completed",
		);
		expect(execute).toHaveBeenCalledTimes(1);
		expect(currentTzdataValidation).not.toHaveBeenCalled();
	});

	it("reuses exact prepared identifiers across a bounded transient retry", async () => {
		const store = await import("../../src/household-reminders/store.js");
		const { createHouseholdReminderFireExecutor } = await import(
			"../../src/household-reminders/fire-executor.js"
		);
		const reminder = confirmedReminder(store);
		let nowMs = NOW_MS + 10_000;
		const preparedInputs: unknown[] = [];
		const prepare = vi.fn(async ({ fire }) => {
			const prepared = {
				outboundRef: `scheduled-effect:${fire.fireId}` as const,
				edgePreparedHash: HASH("c"),
				idempotencyKey: HASH("d"),
				whatsappMessageId: "TCREMINDER0123456789abcdef0123456789abcdef",
			};
			preparedInputs.push(prepared);
			return prepared;
		});
		let executionAttempt = 0;
		const executor = createHouseholdReminderFireExecutor({
			prepare,
			execute: async ({ beforeDispatch }) => {
				expect(beforeDispatch()).toBe(true);
				executionAttempt += 1;
				return executionAttempt === 1
					? {
							ok: false as const,
							failureClass: "whatsapp_transport_timeout",
							retryable: true,
						}
					: { ok: true as const, receiptStatus: "sent" };
			},
			nowMs: () => nowMs,
		});

		const first = await executor(
			{ reminderId: reminder.id, revision: reminder.revision },
			new AbortController().signal,
		);
		expect(first).toMatchObject({
			ok: false,
			message: "whatsapp_transport_timeout",
			retryAtMs: NOW_MS + 40_000,
		});
		if (!first.retryAtMs) throw new Error("retry time missing");
		nowMs = first.retryAtMs;
		await expect(
			executor(
				{ reminderId: reminder.id, revision: reminder.revision },
				new AbortController().signal,
			),
		).resolves.toMatchObject({ ok: true });
		expect(preparedInputs).toHaveLength(2);
		expect(preparedInputs[1]).toEqual(preparedInputs[0]);
		expect(prepare.mock.calls[1]?.[0].fire).toMatchObject({ attemptCount: 2 });
	});

	it("dead-letters an expired final lease instead of rescheduling forever", async () => {
		const store = await import("../../src/household-reminders/store.js");
		const { createHouseholdReminderFireExecutor } = await import(
			"../../src/household-reminders/fire-executor.js"
		);
		const reminder = confirmedReminder(store);
		store.claimHouseholdReminderFire({
			reminderId: reminder.id,
			revision: reminder.revision,
			scheduledForMs: reminder.schedule.resolvedAtMs,
			nowMs: NOW_MS + 10_000,
			leaseMs: 1_000,
			maxAttempts: 1,
		});
		const prepare = vi.fn();
		const execute = vi.fn();
		const executor = createHouseholdReminderFireExecutor({
			prepare,
			execute,
			nowMs: () => NOW_MS + 11_001,
			leaseMs: 1_000,
			maxAttempts: 1,
		});

		await expect(
			executor(
				{ reminderId: reminder.id, revision: reminder.revision },
				new AbortController().signal,
			),
		).resolves.toEqual({ ok: false, message: "reminder_attempts_exhausted" });
		expect(prepare).not.toHaveBeenCalled();
		expect(execute).not.toHaveBeenCalled();
		expect(store.getHouseholdReminderForAuthority(reminder.id, AUTHORITY)?.status).toBe(
			"failed_terminal",
		);
	});

	it("prepares parent-confirmed and appointment-derived records from bound authority", async () => {
		const store = await import("../../src/household-reminders/store.js");
		const { resolveHouseholdReminderContext } = await import(
			"../../src/household-reminders/binding.js"
		);
		const { createHouseholdReminderFirePreparation } = await import(
			"../../src/household-reminders/fire-executor.js"
		);
		const { TelclaudeEdgeRuntime } = await import("../../src/hermes/edge-adapter-runtime.js");
		const { createRelayConversationStore } = await import(
			"../../src/hermes/relay-conversation-store.js"
		);
		const { createTelclaudeMcpSideEffectLedger } = await import(
			"../../src/hermes/mcp/side-effect-ledger.js"
		);
		const context = resolveHouseholdReminderContext(AUTHORITY, LIVE_CONFIG);
		if (!context) throw new Error("household context missing");
		const created = store.prepareHouseholdReminderCreate({
			...context,
			text: "להביא מסמכים",
			schedule: {
				timeZone: "Asia/Jerusalem",
				localDateTime: "2026-08-01T09:00",
				resolvedAtMs: Date.parse("2026-08-01T06:00:00.000Z"),
				resolvedAt: "2026-08-01T06:00:00.000Z",
				offsetMinutes: 180,
			},
			source: { kind: "parent" },
			nowMs: NOW_MS,
		});
		const confirmed = store.confirmHouseholdReminderProposal({
			proposalRef: created.proposal.ref,
			...context,
			nowMs: NOW_MS + 1_000,
		});
		if (!confirmed.ok) throw new Error(confirmed.code);
		const claimed = store.claimHouseholdReminderFire({
			reminderId: confirmed.reminder.id,
			revision: confirmed.reminder.revision,
			scheduledForMs: confirmed.reminder.schedule.resolvedAtMs,
			nowMs: NOW_MS + 10_000,
		});
		const conversationStore = createRelayConversationStore({ nowMs: () => NOW_MS + 10_000 });
		conversationStore.mint({
			channel: "whatsapp",
			conversationId: context.binding.conversationId,
			threadId: "whatsapp:15557654321@s.whatsapp.net",
			profileId: AUTHORITY.profileId,
			domain: "household",
			authorizationState: "authorized",
			humanPairingProvenance: true,
			authorizationScopes: ["message:read", "message:reply"],
			members: [
				{
					actorId: AUTHORITY.actorId,
					principalId: ADDRESS,
					role: "sender",
					identityAssurance: "strong_link",
					scopes: ["message:read", "message:reply"],
				},
			],
			nowMs: NOW_MS,
		});
		const ledger = createTelclaudeMcpSideEffectLedger({
			verifyApproval: async () => ({ ok: false, code: "unused", reason: "unused" }),
			nowMs: () => NOW_MS + 10_000,
			makeRef: () => "effect-standard-ref",
		});
		const prepare = createHouseholdReminderFirePreparation({
			config: LIVE_CONFIG,
			conversationStore,
			edgeRuntime: new TelclaudeEdgeRuntime({
				now: () => new Date(NOW_MS + 10_000).toISOString(),
			}),
			ledger,
		});
		const observationHash = HASH("9");
		const { reminder: derived } = store.createAppointmentDerivedHouseholdReminder({
			...context,
			text: "תור אצל רופאת המשפחה",
			schedule: {
				timeZone: "Asia/Jerusalem",
				localDateTime: "2026-08-02T09:00",
				resolvedAtMs: Date.parse("2026-08-02T06:00:00.000Z"),
				resolvedAt: "2026-08-02T06:00:00.000Z",
				offsetMinutes: 180,
			},
			observationHash,
			addresseeGender: context.addresseeGender,
			nowMs: NOW_MS,
		});
		const time = await import("../../src/household-reminders/time.js");
		const currentTzdataValidation = vi
			.spyOn(time, "validateJerusalemOneShotSchedule")
			.mockImplementation(() => {
				throw new Error("simulated current-tzdata drift");
			});

		const prepared = await prepare({
			reminder: confirmed.reminder,
			fire: claimed.fire,
			body: "תזכורת: להביא מסמכים",
		});
		expect(prepared).toMatchObject({
			outboundRef: `scheduled-effect:${claimed.fire.fireId}`,
			idempotencyKey: expect.stringMatching(/^sha256:/),
			whatsappMessageId: expect.stringMatching(/^TCREMINDER[a-f0-9]{32}$/),
		});
		expect(ledger.get(prepared.outboundRef)).toMatchObject({
			kind: "scheduled-outbound",
			source: "household-reminder-system.v1",
			actorId: AUTHORITY.actorId,
			subjectUserId: AUTHORITY.subjectUserId,
			profileId: AUTHORITY.profileId,
			destination: ADDRESS,
			requestedBody: "תזכורת: להביא מסמכים",
			preparedMediaRefs: [],
			householdReminderPolicy: {
				fireId: claimed.fire.fireId,
				authorizationKind: "parent-confirmed",
				recipientPrincipalHash: context.binding.recipientPrincipalHash,
			},
		});
		expect(
			await prepare({
				reminder: confirmed.reminder,
				fire: claimed.fire,
				body: "תזכורת: להביא מסמכים",
			}),
		).toEqual(prepared);

		const derivedClaim = store.claimHouseholdReminderFire({
			reminderId: derived.id,
			revision: derived.revision,
			scheduledForMs: derived.schedule.resolvedAtMs,
			nowMs: NOW_MS + 10_000,
		});
		const derivedPrepared = await prepare({
			reminder: derived,
			fire: derivedClaim.fire,
			body: "תזכורת: תור אצל רופאת המשפחה",
		});
		expect(ledger.get(derivedPrepared.outboundRef)).toMatchObject({
			householdReminderPolicy: {
				authorizationKind: "appointment-derived",
				sourceObservationHash: observationHash,
			},
		});
		expect(currentTzdataValidation).not.toHaveBeenCalled();
	});

	it("requires all three independently dark delivery switches", async () => {
		const { readHouseholdReminderKillSwitches } = await import(
			"../../src/household-reminders/fire-executor.js"
		);
		expect(readHouseholdReminderKillSwitches(AUTHORITY, LIVE_CONFIG, false)).toEqual({
			globalEnabled: false,
			householdEnabled: true,
			parentEnabled: true,
		});
		expect(readHouseholdReminderKillSwitches(AUTHORITY, LIVE_CONFIG, true)).toEqual({
			globalEnabled: true,
			householdEnabled: true,
			parentEnabled: true,
		});
	});

	it("uses connector classification only to decide a typed transient retry", async () => {
		const { createHouseholdReminderScheduledExecution } = await import(
			"../../src/household-reminders/fire-executor.js"
		);
		const { createOutboundDeliveryFailureClassifier } = await import(
			"../../src/relay/outbound-delivery-dispatcher.js"
		);
		const failureClassifier = createOutboundDeliveryFailureClassifier();
		const outboundRef = "scheduled-effect:reminder-fire-1" as const;
		const execute = createHouseholdReminderScheduledExecution({
			failureClassifier,
			execute: (async (request) => {
				expect(await request.beforeDispatch()).toBe(true);
				failureClassifier.record(
					{
						kind: "prepared_outbound",
						channel: "whatsapp",
						outboundRef: "edge-reminder-fire-1",
						idempotencyKey: HASH("d"),
						sideEffectLedgerRef: request.outboundRef,
						maxAttempts: 3,
					},
					{
						ok: false,
						code: "whatsapp_transport_timeout",
						reason: "timed out",
						retryable: true,
					},
				);
				return {
					ok: false,
					code: "outbound_delivery_failed",
					reason: "dispatcher returned failed",
					retryable: false,
				};
			}) as Parameters<typeof createHouseholdReminderScheduledExecution>[0]["execute"],
		});

		await expect(execute({ outboundRef, beforeDispatch: () => true })).resolves.toEqual({
			ok: false,
			failureClass: "whatsapp_transport_timeout",
			retryable: true,
		});
	});

	it("derives a stable Baileys-safe message id from the system idempotency key", async () => {
		const { householdReminderWhatsAppMessageId } = await import(
			"../../src/household-reminders/render.js"
		);
		const first = householdReminderWhatsAppMessageId(HASH("d"));
		expect(first).toMatch(/^TCREMINDER[a-f0-9]{32}$/);
		expect(householdReminderWhatsAppMessageId(HASH("d"))).toBe(first);
		expect(householdReminderWhatsAppMessageId(HASH("e"))).not.toBe(first);
	});
});

function confirmedReminder(
	store: typeof import("../../src/household-reminders/store.js"),
	schedule = {
		localDateTime: "2026-08-01T09:00",
		resolvedAtMs: Date.parse("2026-08-01T06:00:00.000Z"),
		resolvedAt: "2026-08-01T06:00:00.000Z",
		offsetMinutes: 180,
	},
) {
	const created = store.prepareHouseholdReminderCreate({
		authority: AUTHORITY,
		binding: BINDING,
		consent: CONSENT,
		text: "להביא מסמכים",
		schedule: { timeZone: "Asia/Jerusalem", ...schedule },
		source: { kind: "parent" },
		nowMs: NOW_MS,
	});
	const confirmed = store.confirmHouseholdReminderProposal({
		proposalRef: created.proposal.ref,
		authority: AUTHORITY,
		binding: BINDING,
		consent: CONSENT,
		nowMs: NOW_MS + 1_000,
	});
	if (!confirmed.ok) throw new Error(confirmed.code);
	return confirmed.reminder;
}

const LIVE_CONFIG = {
	householdReminders: { enabled: true },
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
					address: ADDRESS,
					replyAddress: ADDRESS,
					displayName: "Parent A",
					subjectUserId: "household:parent-a",
					remindersEnabled: true,
					reminderConsent: {
						state: "granted",
						ceremonyVersion: "phase0.v1",
						ceremonyHash: HASH("b"),
						verifiedChannelHash: `sha256:${crypto
							.createHash("sha256")
							.update(ADDRESS)
							.digest("hex")}`,
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
