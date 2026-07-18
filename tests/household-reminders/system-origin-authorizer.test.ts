import { describe, expect, it } from "vitest";
import { edgePreparedPayloadHash } from "../../src/hermes/edge-adapter-runtime.js";
import {
	createTelclaudeMcpSideEffectLedger,
	getTelclaudeMcpSideEffectApprovalBinding,
	type TelclaudeMcpScheduledOutboundSideEffectPrepareInput,
} from "../../src/hermes/mcp/side-effect-ledger.js";
import type { HouseholdReminderContext } from "../../src/household-reminders/binding.js";
import {
	householdReminderBindingFingerprint,
	householdReminderConsentHash,
} from "../../src/household-reminders/store.js";
import { createHouseholdReminderSystemOriginAuthorizer } from "../../src/household-reminders/system-origin-authorizer.js";
import {
	createHouseholdReminderSystemOriginPolicyRevalidator,
	householdReminderScheduledOutboundIdempotencyKey,
} from "../../src/household-reminders/system-origin-policy.js";
import type { HouseholdReminder } from "../../src/household-reminders/types.js";

const HASH = (char: string) => `sha256:${char.repeat(64)}` as `sha256:${string}`;
const BODY = "תזכורת: להביא מסמכים";
const DESTINATION = "+972501234567";
const CONVERSATION_REF = "whatsapp:household:parent-a";

describe("household reminder system-origin authorization", () => {
	it("revalidates live policy and mints a short-lived unique-JTI token for the exact record", async () => {
		const fixture = makeFixture();
		const vault = new MockVaultClient();
		let nextJti = 0;
		const authorize = createHouseholdReminderSystemOriginAuthorizer({
			revalidate: fixture.revalidate,
			vaultClient: vault,
			nowSeconds: () => 100,
			ttlSeconds: 30,
			makeJti: () => `reminder-system-${++nextJti}`,
		});

		const first = await authorize(fixture.record);
		const second = await authorize(fixture.record);

		expect(first).toMatchObject({ ok: true, approvalId: "reminder-system-1" });
		expect(second).toMatchObject({ ok: true, approvalId: "reminder-system-2" });
		if (!first.ok || !second.ok) throw new Error("authorization unexpectedly failed");
		const firstClaims = decodeClaims(first.approvalToken);
		expect(firstClaims).toMatchObject({
			iat: 100,
			exp: 130,
			jti: "reminder-system-1",
			binding: getTelclaudeMcpSideEffectApprovalBinding(fixture.record),
		});
		expect(second.approvalToken).not.toBe(first.approvalToken);
		expect(vault.signCalls).toHaveLength(2);
	});

	it("authorizes an appointment-derived fire from exact stored observation evidence", async () => {
		const fixture = makeFixture({ authorizationKind: "appointment-derived" });
		const vault = new MockVaultClient();
		const authorize = createHouseholdReminderSystemOriginAuthorizer({
			revalidate: fixture.revalidate,
			vaultClient: vault,
			nowSeconds: () => 100,
			makeJti: () => "derived-reminder-system",
		});

		await expect(authorize(fixture.record)).resolves.toMatchObject({
			ok: true,
			approvalId: "derived-reminder-system",
		});
		expect(fixture.record.householdReminderPolicy).toMatchObject({
			authorizationKind: "appointment-derived",
			sourceObservationHash: HASH("6"),
		});
		expect(vault.signCalls).toHaveLength(1);
	});

	it.each([
		["global kill switch", { switches: { globalEnabled: false } }, "reminder_policy_disabled"],
		[
			"household kill switch",
			{ switches: { householdEnabled: false } },
			"reminder_policy_disabled",
		],
		["parent kill switch", { switches: { parentEnabled: false } }, "reminder_policy_disabled"],
		["missing fire", { fire: null }, "reminder_fire_not_authorized"],
		["wrong fire state", { fire: { state: "claimed" } }, "reminder_fire_not_authorized"],
		["revoked consent", { context: null }, "reminder_context_not_authorized"],
		[
			"changed recipient",
			{ context: { recipientPrincipalHash: HASH("9") } },
			"reminder_binding_drift",
		],
		["changed body", { renderedBody: "תזכורת: תוכן אחר" }, "reminder_outbound_drift"],
		["changed destination", { destination: "+972509999999" }, "reminder_outbound_drift"],
		["changed confirmation", { confirmedProposalHash: HASH("8") }, "reminder_confirmation_drift"],
		[
			"changed derived observation",
			{ authorizationKind: "appointment-derived", snapshotObservationHash: HASH("8") },
			"reminder_source_observation_drift",
		],
		["changed schedule", { scheduleHash: HASH("7") }, "reminder_revision_drift"],
	] as const)("fails closed on %s without signing", async (_label, mutation, expectedCode) => {
		const fixture = makeFixture(mutation);
		const vault = new MockVaultClient();
		const authorize = createHouseholdReminderSystemOriginAuthorizer({
			revalidate: fixture.revalidate,
			vaultClient: vault,
			nowSeconds: () => 100,
			makeJti: () => "must-not-mint",
		});

		await expect(authorize(fixture.record)).resolves.toMatchObject({
			ok: false,
			code: expectedCode,
		});
		expect(vault.signCalls).toEqual([]);
	});

	it("refuses authorizer TTLs beyond the global 60-second approval-token ceiling", () => {
		const fixture = makeFixture();
		expect(() =>
			createHouseholdReminderSystemOriginAuthorizer({
				revalidate: fixture.revalidate,
				vaultClient: new MockVaultClient(),
				ttlSeconds: 61,
			}),
		).toThrow(/60/);
	});
});

type FixtureMutation = {
	readonly switches?: Partial<{
		readonly globalEnabled: boolean;
		readonly householdEnabled: boolean;
		readonly parentEnabled: boolean;
	}>;
	readonly fire?: null | { readonly state: "claimed" | "prepared" };
	readonly context?: null | { readonly recipientPrincipalHash: `sha256:${string}` };
	readonly renderedBody?: string;
	readonly destination?: string;
	readonly confirmedProposalHash?: `sha256:${string}`;
	readonly authorizationKind?: "parent-confirmed" | "appointment-derived";
	readonly snapshotObservationHash?: `sha256:${string}`;
	readonly scheduleHash?: `sha256:${string}`;
};

function makeFixture(mutation: FixtureMutation = {}) {
	const baselineContext = contextFixture(HASH("5"));
	const authorizationKind = mutation.authorizationKind ?? "parent-confirmed";
	const reminder = reminderFixture({
		scheduleHash: mutation.scheduleHash,
		bindingFingerprint: householdReminderBindingFingerprint(baselineContext.binding),
		consentHash: householdReminderConsentHash(baselineContext.consent),
		source:
			authorizationKind === "appointment-derived"
				? { kind: "clalit-appointment", observationHash: HASH("6") }
				: { kind: "parent" },
	});
	const context =
		mutation.context === null
			? null
			: mutation.context
				? contextFixture(mutation.context.recipientPrincipalHash)
				: baselineContext;
	const destination = mutation.destination ?? DESTINATION;
	const renderedBody = mutation.renderedBody ?? BODY;
	const idempotencyKey = householdReminderScheduledOutboundIdempotencyKey({
		policyVersion: "phase0.v1",
		reminderId: reminder.id,
		revision: reminder.revision,
		scheduledForMs: reminder.schedule.resolvedAtMs,
		contentHash: reminder.contentHash,
		recipientPrincipalHash: HASH("5"),
	});
	const resolvedDestination = {
		kind: "address" as const,
		addressRef: DESTINATION,
		conversationId: CONVERSATION_REF,
	};
	const edgePreparedHash = edgePreparedPayloadHash({
		channel: "whatsapp",
		resolvedDestination,
		body: BODY,
		mediaRefs: [],
	});
	const fire =
		mutation.fire === null
			? null
			: {
					fireId: "reminder-fire-1",
					reminderId: reminder.id,
					revision: reminder.revision,
					scheduledForMs: reminder.schedule.resolvedAtMs,
					state: mutation.fire?.state ?? ("prepared" as const),
					attemptCount: 1,
					outboundRef: "edge-reminder-fire-1",
					edgePreparedHash,
					idempotencyKey,
					createdAtMs: 90_000,
					updatedAtMs: 95_000,
				};
	const input: TelclaudeMcpScheduledOutboundSideEffectPrepareInput = {
		kind: "scheduled-outbound",
		source: "household-reminder-system.v1",
		actorId: reminder.authority.actorId,
		profileId: reminder.authority.profileId,
		domain: "household",
		subjectUserId: reminder.authority.subjectUserId,
		channel: "whatsapp",
		destination: DESTINATION,
		resolvedDestination,
		requestedBody: BODY,
		renderedBody: BODY,
		preparedMediaRefs: [],
		conversationRef: CONVERSATION_REF,
		edgePreparedRef: "edge-reminder-fire-1",
		edgePreparedHash,
		idempotencyKey,
		householdReminderPolicy: {
			reminderId: reminder.id,
			fireId: "reminder-fire-1",
			revision: reminder.revision,
			...(authorizationKind === "parent-confirmed"
				? { authorizationKind, confirmedProposalHash: HASH("1") }
				: { authorizationKind, sourceObservationHash: HASH("6") }),
			scheduleHash: HASH("2"),
			contentHash: reminder.contentHash,
			bindingFingerprint: reminder.bindingFingerprint,
			actorId: reminder.authority.actorId,
			subjectUserId: reminder.authority.subjectUserId,
			profileId: reminder.authority.profileId,
			recipientPrincipalHash: HASH("5"),
			systemPolicyPrincipal: "telclaude:household-reminder-system",
			systemPolicyVersion: "phase0.v1",
		},
	};
	const ledger = createTelclaudeMcpSideEffectLedger({
		verifyApproval: async () => ({ ok: false, code: "unused", reason: "unused" }),
		nowMs: () => 100_000,
		makeRef: () => "effect-reminder-fire-1",
		defaultTtlMs: 60_000,
	});
	const record = ledger.prepare(input);
	const revalidate = createHouseholdReminderSystemOriginPolicyRevalidator({
		readPolicySnapshot: () => ({
			reminder,
			authorization:
				authorizationKind === "parent-confirmed"
					? {
							kind: "parent-confirmed" as const,
							proposalHash: mutation.confirmedProposalHash ?? HASH("1"),
						}
					: {
							kind: "appointment-derived" as const,
							observationHash: mutation.snapshotObservationHash ?? HASH("6"),
						},
		}),
		readFire: () => fire,
		resolveContext: () => context,
		readKillSwitches: () => ({
			globalEnabled: mutation.switches?.globalEnabled ?? true,
			householdEnabled: mutation.switches?.householdEnabled ?? true,
			parentEnabled: mutation.switches?.parentEnabled ?? true,
		}),
		resolveDeliveryTarget: () => ({
			destination,
			resolvedDestination: {
				...resolvedDestination,
				addressRef: destination,
			},
			conversationRef: CONVERSATION_REF,
		}),
		renderReminderBody: () => renderedBody,
	});
	return { record, revalidate };
}

function reminderFixture(
	overrides: {
		readonly scheduleHash?: `sha256:${string}`;
		readonly bindingFingerprint?: `sha256:${string}`;
		readonly consentHash?: `sha256:${string}`;
		readonly source?: HouseholdReminder["source"];
	} = {},
) {
	return {
		id: "reminder-1",
		revision: 1,
		authority: {
			actorId: "household:whatsapp:parent-a",
			subjectUserId: "household:parent-a",
			profileId: "parent-a",
		},
		binding: {
			bindingId: "parent-a",
			conversationId: CONVERSATION_REF,
			senderPrincipalHash: HASH("5"),
			recipientPrincipalHash: HASH("5"),
		},
		bindingFingerprint: overrides.bindingFingerprint ?? HASH("4"),
		consentHash: overrides.consentHash ?? HASH("6"),
		text: "להביא מסמכים",
		locale: "he-IL",
		source: overrides.source ?? { kind: "parent" },
		schedule: {
			timeZone: "Asia/Jerusalem",
			localDateTime: "2026-08-01T09:00",
			resolvedAtMs: Date.parse("2026-08-01T06:00:00.000Z"),
			resolvedAt: "2026-08-01T06:00:00.000Z",
			offsetMinutes: 180,
		},
		contentHash: HASH("3"),
		scheduleHash: overrides.scheduleHash ?? HASH("2"),
		status: "scheduled",
		confirmedAtMs: 90_000,
		createdAtMs: 80_000,
		updatedAtMs: 90_000,
	} satisfies HouseholdReminder;
}

function contextFixture(recipientPrincipalHash: `sha256:${string}`): HouseholdReminderContext {
	return {
		authority: {
			actorId: "household:whatsapp:parent-a",
			subjectUserId: "household:parent-a",
			profileId: "parent-a",
		},
		binding: {
			bindingId: "parent-a",
			conversationId: CONVERSATION_REF,
			senderPrincipalHash: recipientPrincipalHash,
			recipientPrincipalHash,
		},
		consent: {
			state: "granted",
			ceremonyVersion: "phase0.v1",
			ceremonyHash: HASH("a"),
			verifiedChannelHash: recipientPrincipalHash,
			categories: {
				proactiveDelivery: true,
				scheduleManagement: true,
				retentionDisclosure: true,
			},
			recordedAt: "2026-07-17T09:00:00.000Z",
			operatorId: "operator:phase0-admin",
		},
	};
}

class MockVaultClient {
	readonly signCalls: Array<{ payload: string; prefix: string }> = [];
	async signPayload(payload: string, prefix: string) {
		this.signCalls.push({ payload, prefix });
		return {
			type: "sign-payload",
			signature: Buffer.from(`${prefix}\n${payload}`, "utf8").toString("base64url"),
		};
	}
}

function decodeClaims(token: string): Record<string, unknown> {
	const [, claims] = token.split(".");
	return JSON.parse(Buffer.from(claims ?? "", "base64url").toString("utf8"));
}
