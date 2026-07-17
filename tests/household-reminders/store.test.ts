import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;
const NOW_MS = Date.parse("2026-07-17T00:00:00.000Z");
const HASH_A = `sha256:${"a".repeat(64)}` as const;
const HASH_B = `sha256:${"b".repeat(64)}` as const;

const AUTHORITY_A = {
	actorId: "household:whatsapp:parent-a",
	subjectUserId: "household:parent-a",
	profileId: "parent-a",
};
const AUTHORITY_B = {
	actorId: "household:whatsapp:parent-b",
	subjectUserId: "household:parent-b",
	profileId: "parent-b",
};
const BINDING_A = {
	bindingId: "parent-a",
	conversationId: "whatsapp:household:parent-a",
	senderPrincipalHash: HASH_A,
	recipientPrincipalHash: HASH_A,
};
const BINDING_B = {
	bindingId: "parent-b",
	conversationId: "whatsapp:household:parent-b",
	senderPrincipalHash: HASH_B,
	recipientPrincipalHash: HASH_B,
};
const CONSENT_A = {
	state: "granted",
	ceremonyVersion: "phase0.v1",
	ceremonyHash: `sha256:${"c".repeat(64)}`,
	verifiedChannelHash: HASH_A,
	categories: {
		proactiveDelivery: true,
		scheduleManagement: true,
		retentionDisclosure: true,
	},
	recordedAt: "2026-07-17T09:00:00.000Z",
	operatorId: "operator:phase0-admin",
} as const;
const CONSENT_B = {
	...CONSENT_A,
	ceremonyHash: `sha256:${"e".repeat(64)}` as const,
	verifiedChannelHash: HASH_B,
};
const CONSENT_A_CHANGED = {
	...CONSENT_A,
	ceremonyHash: `sha256:${"f".repeat(64)}` as const,
};

describe("household reminder store", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-household-reminders-"));
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

	it("creates a pending proposal and schedules only after same-binding confirmation", async () => {
		const store = await import("../../src/household-reminders/store.js");
		const created = store.prepareHouseholdReminderCreate({
			authority: AUTHORITY_A,
			binding: BINDING_A,
			consent: CONSENT_A,
			text: "  לקחת\r\nמסמכים  ",
			schedule: schedule("2026-08-01T09:00", "2026-08-01T06:00:00.000Z", 180),
			source: { kind: "parent" },
			nowMs: NOW_MS,
		});

		expect(created.reminder).toMatchObject({
			revision: 1,
			status: "pending_confirmation",
			text: "לקחת\nמסמכים",
			authority: AUTHORITY_A,
			consentHash: created.proposal.consentHash,
		});
		expect(store.listHouseholdReminders(AUTHORITY_A)).toHaveLength(1);
		expect(store.listHouseholdReminders(AUTHORITY_B)).toEqual([]);

		expect(
			store.confirmHouseholdReminderProposal({
				proposalRef: created.proposal.ref,
				authority: AUTHORITY_B,
				binding: BINDING_B,
				consent: CONSENT_B,
				nowMs: NOW_MS + 1_000,
			}),
		).toEqual({ ok: false, code: "proposal_not_found" });
		expect(
			store.confirmHouseholdReminderProposal({
				proposalRef: created.proposal.ref,
				authority: AUTHORITY_A,
				binding: BINDING_A,
				consent: CONSENT_A_CHANGED,
				nowMs: NOW_MS + 200,
			}),
		).toEqual({ ok: false, code: "consent_changed" });

		const confirmed = store.confirmHouseholdReminderProposal({
			proposalRef: created.proposal.ref,
			authority: AUTHORITY_A,
			binding: BINDING_A,
			consent: CONSENT_A,
			nowMs: NOW_MS + 1_000,
		});
		expect(confirmed).toMatchObject({
			ok: true,
			reminder: { revision: 1, status: "scheduled", confirmedAtMs: NOW_MS + 1_000 },
		});
		expect(
			store.confirmHouseholdReminderProposal({
				proposalRef: created.proposal.ref,
				authority: AUTHORITY_A,
				binding: BINDING_A,
				consent: CONSENT_A,
				nowMs: NOW_MS + 1_001,
			}),
		).toEqual({ ok: false, code: "proposal_not_found" });
	});

	it("requires reminder consent to match the bound WhatsApp channel", async () => {
		const store = await import("../../src/household-reminders/store.js");
		expect(() =>
			store.prepareHouseholdReminderCreate({
				authority: AUTHORITY_A,
				binding: BINDING_A,
				consent: CONSENT_B,
				text: "להביא מסמכים",
				schedule: schedule("2026-08-01T09:00", "2026-08-01T06:00:00.000Z", 180),
				source: { kind: "parent" },
				nowMs: NOW_MS,
			}),
		).toThrow(/consent does not match/i);
	});

	it("reads an authority-scoped confirmed revision and its confirmation evidence", async () => {
		const store = await import("../../src/household-reminders/store.js");
		const created = store.prepareHouseholdReminderCreate({
			authority: AUTHORITY_A,
			binding: BINDING_A,
			consent: CONSENT_A,
			text: "להביא מסמכים",
			schedule: schedule("2026-08-01T09:00", "2026-08-01T06:00:00.000Z", 180),
			source: { kind: "parent" },
			nowMs: NOW_MS,
		});
		const confirmed = store.confirmHouseholdReminderProposal({
			proposalRef: created.proposal.ref,
			authority: AUTHORITY_A,
			binding: BINDING_A,
			consent: CONSENT_A,
			nowMs: NOW_MS + 1_000,
		});
		if (!confirmed.ok) throw new Error(confirmed.code);

		expect(
			store.getConfirmedHouseholdReminderPolicySnapshot(
				confirmed.reminder.id,
				confirmed.reminder.revision,
				AUTHORITY_A,
			),
		).toEqual({
			reminder: confirmed.reminder,
			confirmation: {
				proposalRef: created.proposal.ref,
				proposalHash: created.proposal.proposalHash,
				action: "create",
			},
		});
		expect(
			store.getConfirmedHouseholdReminderPolicySnapshot(
				confirmed.reminder.id,
				confirmed.reminder.revision,
				AUTHORITY_B,
			),
		).toBeNull();
		expect(
			store.getConfirmedHouseholdReminderPolicySnapshot(
				"reminder-absent",
				confirmed.reminder.revision,
				AUTHORITY_A,
			),
		).toBeNull();
	});

	it("rejects schedules that are already due at prepare or confirmation time", async () => {
		const store = await import("../../src/household-reminders/store.js");
		const reminderSchedule = schedule("2026-08-01T09:00", "2026-08-01T06:00:00.000Z", 180);
		expect(() =>
			store.prepareHouseholdReminderCreate({
				authority: AUTHORITY_A,
				binding: BINDING_A,
				consent: CONSENT_A,
				text: "להביא מסמכים",
				schedule: reminderSchedule,
				source: { kind: "parent" },
				nowMs: reminderSchedule.resolvedAtMs,
			}),
		).toThrow(/future/i);

		const created = store.prepareHouseholdReminderCreate({
			authority: AUTHORITY_A,
			binding: BINDING_A,
			consent: CONSENT_A,
			text: "להביא מסמכים",
			schedule: reminderSchedule,
			source: { kind: "parent" },
			nowMs: NOW_MS,
		});
		expect(
			store.confirmHouseholdReminderProposal({
				proposalRef: created.proposal.ref,
				authority: AUTHORITY_A,
				binding: BINDING_A,
				consent: CONSENT_A,
				nowMs: reminderSchedule.resolvedAtMs,
			}),
		).toEqual({ ok: false, code: "invalid_state" });
	});

	it("rejects confirmation after binding drift or expiry", async () => {
		const store = await import("../../src/household-reminders/store.js");
		const drifted = { ...BINDING_A, conversationId: "whatsapp:household:changed" };
		const created = store.prepareHouseholdReminderCreate({
			authority: AUTHORITY_A,
			binding: BINDING_A,
			consent: CONSENT_A,
			text: "להביא מסמכים",
			schedule: schedule("2026-08-01T09:00", "2026-08-01T06:00:00.000Z", 180),
			source: { kind: "parent" },
			nowMs: NOW_MS,
			proposalTtlMs: 500,
		});

		expect(
			store.confirmHouseholdReminderProposal({
				proposalRef: created.proposal.ref,
				authority: AUTHORITY_A,
				binding: drifted,
				consent: CONSENT_A,
				nowMs: NOW_MS + 100,
			}),
		).toEqual({ ok: false, code: "binding_changed" });
		expect(
			store.confirmHouseholdReminderProposal({
				proposalRef: created.proposal.ref,
				authority: AUTHORITY_A,
				binding: BINDING_A,
				consent: CONSENT_A,
				nowMs: NOW_MS + 501,
			}),
		).toEqual({ ok: false, code: "proposal_expired" });
		expect(store.getHouseholdReminderForAuthority(created.reminder.id, AUTHORITY_A)?.status).toBe(
			"cancelled",
		);
	});

	it("allows only one pending confirmation per conversation and rejects forged schedule tuples", async () => {
		const store = await import("../../src/household-reminders/store.js");
		store.prepareHouseholdReminderCreate({
			authority: AUTHORITY_A,
			binding: BINDING_A,
			consent: CONSENT_A,
			text: "להביא מסמכים",
			schedule: schedule("2026-08-01T09:00", "2026-08-01T06:00:00.000Z", 180),
			source: { kind: "parent" },
			nowMs: NOW_MS,
		});
		expect(() =>
			store.prepareHouseholdReminderCreate({
				authority: AUTHORITY_A,
				binding: BINDING_A,
				consent: CONSENT_A,
				text: "תזכורת שנייה",
				schedule: schedule("2026-08-02T09:00", "2026-08-02T06:00:00.000Z", 180),
				source: { kind: "parent" },
				nowMs: NOW_MS + 100,
			}),
		).toThrow(/already pending/i);

		expect(() =>
			store.prepareHouseholdReminderCreate({
				authority: AUTHORITY_B,
				binding: BINDING_B,
				consent: CONSENT_B,
				text: "תזכורת נפרדת",
				schedule: schedule("2026-08-01T09:00", "2026-08-01T07:00:00.000Z", 180),
				source: { kind: "parent" },
				nowMs: NOW_MS + 100,
			}),
		).toThrow(/do not match/i);
	});

	it("pauses updates/cancellations and restores or supersedes atomically", async () => {
		const store = await import("../../src/household-reminders/store.js");
		const initial = confirmedReminder(store);
		const update = store.prepareHouseholdReminderUpdate({
			reminderId: initial.id,
			authority: AUTHORITY_A,
			binding: BINDING_A,
			consent: CONSENT_A,
			text: "להביא גם הפניה",
			schedule: schedule("2026-08-01T10:00", "2026-08-01T07:00:00.000Z", 180),
			nowMs: NOW_MS + 2_000,
		});
		expect(store.getHouseholdReminderForAuthority(initial.id, AUTHORITY_A)?.status).toBe(
			"paused_confirmation",
		);
		expect(
			store.rejectHouseholdReminderProposal({
				proposalRef: update.proposal.ref,
				authority: AUTHORITY_A,
				binding: BINDING_A,
				consent: CONSENT_A,
				nowMs: NOW_MS + 2_100,
			}),
		).toMatchObject({ ok: true, reminder: { revision: 1, status: "scheduled" } });

		const secondUpdate = store.prepareHouseholdReminderUpdate({
			reminderId: initial.id,
			authority: AUTHORITY_A,
			binding: BINDING_A,
			consent: CONSENT_A,
			text: "להביא גם הפניה",
			schedule: schedule("2026-08-01T10:00", "2026-08-01T07:00:00.000Z", 180),
			nowMs: NOW_MS + 3_000,
		});
		const updated = store.confirmHouseholdReminderProposal({
			proposalRef: secondUpdate.proposal.ref,
			authority: AUTHORITY_A,
			binding: BINDING_A,
			consent: CONSENT_A,
			nowMs: NOW_MS + 3_100,
		});
		expect(updated).toMatchObject({
			ok: true,
			reminder: { revision: 2, text: "להביא גם הפניה", status: "scheduled" },
		});

		const cancellation = store.prepareHouseholdReminderCancellation({
			reminderId: initial.id,
			authority: AUTHORITY_A,
			binding: BINDING_A,
			consent: CONSENT_A,
			nowMs: NOW_MS + 4_000,
		});
		expect(store.getHouseholdReminderForAuthority(initial.id, AUTHORITY_A)?.status).toBe(
			"paused_confirmation",
		);
		expect(
			store.confirmHouseholdReminderProposal({
				proposalRef: cancellation.proposal.ref,
				authority: AUTHORITY_A,
				binding: BINDING_A,
				consent: CONSENT_A,
				nowMs: NOW_MS + 4_100,
			}),
		).toMatchObject({ ok: true, reminder: { revision: 2, status: "cancelled" } });
	});

	it("claims each scheduled occurrence with one durable deterministic fire", async () => {
		const store = await import("../../src/household-reminders/store.js");
		const reminder = confirmedReminder(store);
		const first = store.claimHouseholdReminderFire({
			reminderId: reminder.id,
			revision: reminder.revision,
			scheduledForMs: reminder.schedule.resolvedAtMs,
			nowMs: NOW_MS + 10_000,
		});
		const duplicate = store.claimHouseholdReminderFire({
			reminderId: reminder.id,
			revision: reminder.revision,
			scheduledForMs: reminder.schedule.resolvedAtMs,
			nowMs: NOW_MS + 11_000,
		});

		expect(first.created).toBe(true);
		expect(duplicate.created).toBe(false);
		expect(duplicate.fire).toEqual(first.fire);
		expect(first.fire).toMatchObject({ state: "claimed", attemptCount: 1 });
	});

	it("adds consent and fire-ledger columns to an earlier Wave 1 database", async () => {
		const { closeDb, getDb } = await import("../../src/storage/db.js");
		closeDb();
		const databasePath = path.join(tempDir, "telclaude.db");
		const legacyDb = new Database(databasePath);
		legacyDb.exec(`
			DROP INDEX idx_household_reminder_fires_idempotency;
			ALTER TABLE household_reminders DROP COLUMN consent_hash;
			ALTER TABLE household_reminder_proposals DROP COLUMN consent_hash;
			ALTER TABLE household_reminder_fires DROP COLUMN lease_expires_at_ms;
			ALTER TABLE household_reminder_fires DROP COLUMN outbound_ref;
			ALTER TABLE household_reminder_fires DROP COLUMN edge_prepared_hash;
			ALTER TABLE household_reminder_fires DROP COLUMN idempotency_key;
			ALTER TABLE household_reminder_fires DROP COLUMN whatsapp_message_id;
			ALTER TABLE household_reminder_fires DROP COLUMN receipt_status;
			ALTER TABLE household_reminder_fires DROP COLUMN platform_message_id_hash;
			ALTER TABLE household_reminder_fires DROP COLUMN failure_class;
		`);
		legacyDb.close();

		const migratedDb = getDb();
		const reminderColumns = migratedDb
			.prepare("PRAGMA table_info(household_reminders)")
			.all() as Array<{ name: string }>;
		const proposalColumns = migratedDb
			.prepare("PRAGMA table_info(household_reminder_proposals)")
			.all() as Array<{ name: string }>;
		const fireColumns = migratedDb
			.prepare("PRAGMA table_info(household_reminder_fires)")
			.all() as Array<{ name: string }>;

		expect(reminderColumns.map(({ name }) => name)).toContain("consent_hash");
		expect(proposalColumns.map(({ name }) => name)).toContain("consent_hash");
		expect(fireColumns.map(({ name }) => name)).toEqual(
			expect.arrayContaining([
				"lease_expires_at_ms",
				"outbound_ref",
				"edge_prepared_hash",
				"idempotency_key",
				"whatsapp_message_id",
				"receipt_status",
				"platform_message_id_hash",
				"failure_class",
			]),
		);
		expect(
			migratedDb
				.prepare(
					"SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'idx_household_reminder_fires_idempotency'",
				)
				.get(),
		).toEqual({ name: "idx_household_reminder_fires_idempotency" });
	});
});

function schedule(localDateTime: string, resolvedAt: string, offsetMinutes: number) {
	return {
		timeZone: "Asia/Jerusalem" as const,
		localDateTime,
		resolvedAtMs: Date.parse(resolvedAt),
		resolvedAt,
		offsetMinutes,
	};
}

function confirmedReminder(store: typeof import("../../src/household-reminders/store.js")) {
	const created = store.prepareHouseholdReminderCreate({
		authority: AUTHORITY_A,
		binding: BINDING_A,
		consent: CONSENT_A,
		text: "להביא מסמכים",
		schedule: schedule("2026-08-01T09:00", "2026-08-01T06:00:00.000Z", 180),
		source: { kind: "parent" },
		nowMs: NOW_MS,
	});
	const confirmed = store.confirmHouseholdReminderProposal({
		proposalRef: created.proposal.ref,
		authority: AUTHORITY_A,
		binding: BINDING_A,
		consent: CONSENT_A,
		nowMs: NOW_MS + 1_000,
	});
	if (!confirmed.ok) throw new Error(confirmed.code);
	return confirmed.reminder;
}
