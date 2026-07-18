import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { MediaActionConfirmationStore } from "../../src/relay/media-action-confirmation-store.js";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;
const NOW_MS = Date.parse("2026-07-18T12:00:00.000Z");
const ENCRYPTION_KEY = "phase0-test-media-confirmation-key-material-32chars";
const OWNER_A = {
	actorId: "household:whatsapp:parent-a",
	subjectUserId: "household:parent-a",
	profileId: "parent-a",
	bindingId: "parent-a",
	conversationId: "whatsapp:household:parent-a",
	senderPrincipalHash: `sha256:${"a".repeat(64)}`,
} as const;
const OWNER_B = {
	actorId: "household:whatsapp:parent-b",
	subjectUserId: "household:parent-b",
	profileId: "parent-b",
	bindingId: "parent-b",
	conversationId: "whatsapp:household:parent-b",
	senderPrincipalHash: `sha256:${"b".repeat(64)}`,
} as const;

describe("media action confirmation store", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-media-confirmation-"));
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

	it("requires a stable injected key of at least 32 characters", async () => {
		const { createMediaActionConfirmationStore } = await import(
			"../../src/relay/media-action-confirmation-store.js"
		);

		expect(() => createMediaActionConfirmationStore({ encryptionKey: undefined })).toThrowError(
			expect.objectContaining({ code: "media_confirmation_key_unavailable" }),
		);
		expect(() => createMediaActionConfirmationStore({ encryptionKey: "short" })).toThrowError(
			expect.objectContaining({ code: "media_confirmation_key_unavailable" }),
		);
	});

	it("encrypts the derivation and exact action while exposing content-free control metadata", async () => {
		const { createMediaActionConfirmationStore } = await import(
			"../../src/relay/media-action-confirmation-store.js"
		);
		const { getDb } = await import("../../src/storage/db.js");
		const store = createMediaActionConfirmationStore({
			encryptionKey: ENCRYPTION_KEY,
			nowMs: () => NOW_MS,
			makeConfirmationId: () => "media-confirmation-a",
			makeJti: () => "one-shot-jti-a",
		});
		store.registerTurnDerivation({
			owner: OWNER_A,
			turnRef: `turn_${"1".repeat(32)}`,
			envelopes: [documentEnvelope("צריך לשלוח את הטופס למרפאה")],
			createdAtMs: NOW_MS,
		});

		const guarded = store.guardConsequentialAction({
			turnRef: `turn_${"1".repeat(32)}`,
			authority: {
				actorId: OWNER_A.actorId,
				subjectUserId: OWNER_A.subjectUserId,
				profileId: OWNER_A.profileId,
			},
			action: {
				toolName: "tc_provider_prepare_write",
				params: {
					providerId: "clalit",
					service: "clalit",
					action: "prescription_renewal",
					params: { prescriptionId: "synthetic-rx" },
				},
			},
			nowMs: NOW_MS + 1,
		});

		expect(guarded).toMatchObject({
			required: true,
			confirmation: {
				confirmationId: "media-confirmation-a",
				status: "pending",
				actionToolName: "tc_provider_prepare_write",
				sourceDigest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
				derivedDigest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
				actionDigest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
				jtiHash: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
			},
		});
		if (!guarded.required) throw new Error("test confirmation was not required");
		expect(store.inspectConfirmation(guarded.confirmation.confirmationId)).toEqual(
			guarded.confirmation,
		);
		expect(
			store.readPendingPayload({
				confirmationId: guarded.confirmation.confirmationId,
				owner: OWNER_A,
				nowMs: NOW_MS + 2,
			}),
		).toEqual({
			envelopes: [documentEnvelope("צריך לשלוח את הטופס למרפאה")],
			action: {
				toolName: "tc_provider_prepare_write",
				params: {
					providerId: "clalit",
					service: "clalit",
					action: "prescription_renewal",
					params: { prescriptionId: "synthetic-rx" },
				},
			},
		});
		for (const file of fs.readdirSync(tempDir).filter((name) => name.startsWith("telclaude.db"))) {
			const rawDb = fs.readFileSync(path.join(tempDir, file));
			expect(rawDb.includes(Buffer.from("צריך לשלוח")), file).toBe(false);
			expect(rawDb.includes(Buffer.from("synthetic-rx")), file).toBe(false);
		}
		const controlRow = getDb()
			.prepare("SELECT * FROM household_media_action_confirmations WHERE confirmation_id = ?")
			.get("media-confirmation-a") as Record<string, unknown>;
		expect(JSON.stringify(controlRow)).not.toMatch(/צריך|synthetic-rx|params_json|text|ciphertext/);
	});

	it("fails decryption when ciphertext rows are swapped between parents", async () => {
		const { createMediaActionConfirmationStore } = await import(
			"../../src/relay/media-action-confirmation-store.js"
		);
		const { getDb } = await import("../../src/storage/db.js");
		let nextId = 0;
		const store = createMediaActionConfirmationStore({
			encryptionKey: ENCRYPTION_KEY,
			makeConfirmationId: () => `media-confirmation-${++nextId}`,
			makeJti: () => `one-shot-jti-${nextId}`,
		});
		for (const [owner, suffix] of [
			[OWNER_A, "a"],
			[OWNER_B, "b"],
		] as const) {
			store.registerTurnDerivation({
				owner,
				turnRef: `turn_${suffix.repeat(32)}`,
				envelopes: [documentEnvelope(`private-${suffix}`)],
				createdAtMs: NOW_MS,
			});
			store.guardConsequentialAction({
				turnRef: `turn_${suffix.repeat(32)}`,
				authority: {
					actorId: owner.actorId,
					subjectUserId: owner.subjectUserId,
					profileId: owner.profileId,
				},
				action: { toolName: "tc_schedule_create", params: { prompt: `private-${suffix}` } },
				nowMs: NOW_MS + 1,
			});
		}
		getDb().exec(`
			CREATE TEMP TABLE swapped AS
			SELECT confirmation_id, ciphertext FROM household_media_action_confirmation_content;
			UPDATE household_media_action_confirmation_content
			SET ciphertext = (SELECT ciphertext FROM swapped
			                  WHERE confirmation_id != household_media_action_confirmation_content.confirmation_id);
		`);

		expect(
			store.readPendingPayload({
				confirmationId: "media-confirmation-1",
				owner: OWNER_A,
				nowMs: NOW_MS + 2,
			}),
		).toBeNull();
		expect(
			store.readPendingPayload({
				confirmationId: "media-confirmation-2",
				owner: OWNER_B,
				nowMs: NOW_MS + 2,
			}),
		).toBeNull();
	});

	it("rolls media arming back behind a reminder and cascades encrypted content on expiry", async () => {
		const metrics = await import("../../src/household-metrics/store.js");
		metrics.configureHouseholdMetrics({ enabled: true });
		const { claimInteractiveChoiceLease } = await import(
			"../../src/relay/interactive-choice-lease.js"
		);
		const { createMediaActionConfirmationStore } = await import(
			"../../src/relay/media-action-confirmation-store.js"
		);
		const { getDb } = await import("../../src/storage/db.js");
		const store = createMediaActionConfirmationStore({
			encryptionKey: ENCRYPTION_KEY,
			makeConfirmationId: () => "media-confirmation-expiring",
			makeJti: () => "one-shot-jti-expiring",
		});
		claimInteractiveChoiceLease({
			...OWNER_A,
			kind: "reminder",
			ownerRef: "reminder-proposal-1",
			createdAtMs: NOW_MS,
			expiresAtMs: NOW_MS + 100,
		});
		store.registerTurnDerivation({
			owner: OWNER_A,
			turnRef: `turn_${"1".repeat(32)}`,
			envelopes: [documentEnvelope("blocked by reminder")],
			createdAtMs: NOW_MS,
		});
		expect(() =>
			store.guardConsequentialAction({
				turnRef: `turn_${"1".repeat(32)}`,
				authority: {
					actorId: OWNER_A.actorId,
					subjectUserId: OWNER_A.subjectUserId,
					profileId: OWNER_A.profileId,
				},
				action: { toolName: "tc_schedule_create", params: { prompt: "blocked" } },
				nowMs: NOW_MS + 1,
			}),
		).toThrowError(
			expect.objectContaining({
				code: "interactive_choice_busy",
				incumbentKind: "reminder",
			}),
		);
		expect(
			getDb().prepare("SELECT COUNT(*) AS count FROM household_media_action_confirmations").get(),
		).toEqual({ count: 0 });

		const armed = store.guardConsequentialAction({
			turnRef: `turn_${"1".repeat(32)}`,
			authority: {
				actorId: OWNER_A.actorId,
				subjectUserId: OWNER_A.subjectUserId,
				profileId: OWNER_A.profileId,
			},
			action: { toolName: "tc_schedule_create", params: { prompt: "now arm" } },
			nowMs: NOW_MS + 101,
		});
		expect(armed).toMatchObject({ required: true });

		claimInteractiveChoiceLease({
			...OWNER_A,
			kind: "reminder",
			ownerRef: "reminder-after-expiry",
			createdAtMs: NOW_MS + 10 * 60_000 + 102,
			expiresAtMs: NOW_MS + 10 * 60_000 + 202,
		});
		expect(store.inspectConfirmation("media-confirmation-expiring")).toMatchObject({
			status: "expired",
		});
		expect(
			getDb()
				.prepare("SELECT COUNT(*) AS count FROM household_media_action_confirmation_content")
				.get(),
		).toEqual({ count: 0 });
		expect(metrics.collectHouseholdMetricRollups()).toEqual([
			{ bindingKey: "parent-a", metricKind: "confirmation_expired", count: 1 },
			{ bindingKey: "parent-a", metricKind: "confirmation_shown", count: 1 },
		]);
	});

	it("does not recount store-owned expiry when the released lease is replaced", async () => {
		const metrics = await import("../../src/household-metrics/store.js");
		const { claimInteractiveChoiceLease } = await import(
			"../../src/relay/interactive-choice-lease.js"
		);
		const { createMediaActionConfirmationStore } = await import(
			"../../src/relay/media-action-confirmation-store.js"
		);
		metrics.configureHouseholdMetrics({ enabled: true });
		const store = createMediaActionConfirmationStore({
			encryptionKey: ENCRYPTION_KEY,
			makeConfirmationId: () => "media-confirmation-store-expiry",
			makeJti: () => "store-expiry-jti",
		});
		armProviderAction(store, `turn_${"2".repeat(32)}`);

		expect(
			store.peekPendingForOwner({ owner: OWNER_A, nowMs: NOW_MS + 10 * 60_000 + 1 }),
		).toBeNull();
		claimInteractiveChoiceLease({
			...OWNER_A,
			kind: "reminder",
			ownerRef: "reminder-after-store-expiry",
			createdAtMs: NOW_MS + 10 * 60_000 + 2,
			expiresAtMs: NOW_MS + 20 * 60_000,
		});
		expect(metrics.collectHouseholdMetricRollups()).toEqual([
			{ bindingKey: "parent-a", metricKind: "confirmation_expired", count: 1 },
			{ bindingKey: "parent-a", metricKind: "confirmation_shown", count: 1 },
		]);
	});

	it("confirms once into an exact fresh-turn capability and replays only the durable receipt", async () => {
		const metrics = await import("../../src/household-metrics/store.js");
		metrics.configureHouseholdMetrics({ enabled: true });
		const { createMediaActionConfirmationStore } = await import(
			"../../src/relay/media-action-confirmation-store.js"
		);
		const { getDb } = await import("../../src/storage/db.js");
		const store = createMediaActionConfirmationStore({
			encryptionKey: ENCRYPTION_KEY,
			nowMs: () => NOW_MS,
			makeConfirmationId: () => "media-confirmation-fresh",
			makeJti: () => "fresh-action-jti",
		});
		armProviderAction(store, `turn_${"3".repeat(32)}`);
		const mintFreshTurn = vi.fn(() => ({ ref: `turn_${"4".repeat(32)}` }));

		const confirmed = store.resolveChoice({
			owner: OWNER_A,
			eventId: "event-confirm-once",
			messageId: "message-confirm-once",
			choice: "confirm",
			mintFreshTurn,
			nowMs: NOW_MS + 10,
		});

		expect(confirmed).toMatchObject({
			status: "confirmed",
			templateId: "confirmed",
			newlyResolved: true,
			freshTurnRef: `turn_${"4".repeat(32)}`,
			payload: {
				envelopes: [expect.objectContaining({ kind: "document_extract" })],
				action: expect.objectContaining({ toolName: "tc_provider_prepare_write" }),
			},
		});
		expect(mintFreshTurn).toHaveBeenCalledTimes(1);
		expect(
			getDb().prepare("SELECT COUNT(*) AS count FROM household_interactive_choice_leases").get(),
		).toEqual({ count: 0 });
		expect(
			getDb()
				.prepare("SELECT COUNT(*) AS count FROM household_media_action_confirmation_content")
				.get(),
		).toEqual({ count: 0 });

		expect(
			store.resolveChoice({
				owner: OWNER_A,
				eventId: "event-confirm-once",
				messageId: "message-confirm-once",
				choice: "confirm",
				mintFreshTurn,
				nowMs: NOW_MS + 11,
			}),
		).toMatchObject({
			status: "confirmed",
			templateId: "confirmed",
			newlyResolved: false,
			freshTurnRef: `turn_${"4".repeat(32)}`,
		});
		expect(mintFreshTurn).toHaveBeenCalledTimes(1);
		expect(metrics.collectHouseholdMetricRollups()).toEqual([
			{ bindingKey: "parent-a", metricKind: "confirmation_confirmed", count: 1 },
			{ bindingKey: "parent-a", metricKind: "confirmation_shown", count: 1 },
		]);

		getDb().exec("DROP TABLE household_metrics");
		const failingMetricsStore = createMediaActionConfirmationStore({
			encryptionKey: ENCRYPTION_KEY,
			nowMs: () => NOW_MS + 20,
			makeConfirmationId: () => "media-confirmation-metrics-fail",
			makeJti: () => "metrics-fail-action-jti",
		});
		armProviderAction(failingMetricsStore, `turn_${"8".repeat(32)}`);
		expect(
			failingMetricsStore.resolveChoice({
				owner: OWNER_A,
				eventId: "event-metrics-fail",
				messageId: "message-metrics-fail",
				choice: "confirm",
				mintFreshTurn: () => ({ ref: `turn_${"9".repeat(32)}` }),
				nowMs: NOW_MS + 21,
			}),
		).toMatchObject({ status: "confirmed", newlyResolved: true });
	});

	it("allows exactly one exact action on the fresh turn and denies changes or replay", async () => {
		const { createMediaActionConfirmationStore } = await import(
			"../../src/relay/media-action-confirmation-store.js"
		);
		let confirmationId = 0;
		let jti = 0;
		const store = createMediaActionConfirmationStore({
			encryptionKey: ENCRYPTION_KEY,
			makeConfirmationId: () => `media-confirmation-capability-${++confirmationId}`,
			makeJti: () => `capability-jti-${++jti}`,
		});
		const action = armProviderAction(store, `turn_${"5".repeat(32)}`);
		const freshTurnRef = `turn_${"6".repeat(32)}`;
		store.resolveChoice({
			owner: OWNER_A,
			eventId: "event-capability",
			messageId: "message-capability",
			choice: "confirm",
			mintFreshTurn: () => ({ ref: freshTurnRef }),
			nowMs: NOW_MS + 10,
		});

		expect(() =>
			store.guardConsequentialAction({
				turnRef: freshTurnRef,
				authority: mediaAuthority(OWNER_A),
				action: {
					...action,
					params: { ...action.params, action: "appointment_booking" },
				},
				nowMs: NOW_MS + 11,
			}),
		).toThrowError(expect.objectContaining({ code: "media_confirmed_action_denied" }));
		expect(
			store.guardConsequentialAction({
				turnRef: freshTurnRef,
				authority: mediaAuthority(OWNER_A),
				action,
				nowMs: NOW_MS + 12,
			}),
		).toEqual({ required: false });
		expect(() =>
			store.guardConsequentialAction({
				turnRef: freshTurnRef,
				authority: mediaAuthority(OWNER_A),
				action,
				nowMs: NOW_MS + 13,
			}),
		).toThrowError(expect.objectContaining({ code: "media_confirmed_action_denied" }));

		const laterTurnRef = `turn_${"a".repeat(32)}`;
		store.registerTurnDerivation({
			owner: OWNER_A,
			turnRef: laterTurnRef,
			envelopes: [documentEnvelope("בקשה חדשה מאותו מסמך")],
			createdAtMs: NOW_MS + 14,
		});
		expect(
			store.guardConsequentialAction({
				turnRef: laterTurnRef,
				authority: mediaAuthority(OWNER_A),
				action,
				nowMs: NOW_MS + 15,
			}),
		).toMatchObject({ required: true });
	});

	it("rejects durably without minting or dispatch payload and re-gates a later derived turn", async () => {
		const metrics = await import("../../src/household-metrics/store.js");
		metrics.configureHouseholdMetrics({ enabled: true });
		const { createMediaActionConfirmationStore } = await import(
			"../../src/relay/media-action-confirmation-store.js"
		);
		let confirmationId = 0;
		let jti = 0;
		const store = createMediaActionConfirmationStore({
			encryptionKey: ENCRYPTION_KEY,
			makeConfirmationId: () => `media-confirmation-${++confirmationId}`,
			makeJti: () => `reject-jti-${++jti}`,
		});
		armProviderAction(store, `turn_${"7".repeat(32)}`);
		const mintFreshTurn = vi.fn(() => ({ ref: `turn_${"8".repeat(32)}` }));

		expect(
			store.resolveChoice({
				owner: OWNER_A,
				eventId: "event-reject",
				messageId: "message-reject",
				choice: "reject",
				mintFreshTurn,
				nowMs: NOW_MS + 10,
			}),
		).toMatchObject({
			status: "rejected",
			templateId: "rejected",
			newlyResolved: true,
		});
		expect(mintFreshTurn).not.toHaveBeenCalled();
		expect(
			metrics
				.collectHouseholdMetricRollups()
				.find((metric) => metric.metricKind === "confirmation_rejected"),
		).toEqual({ bindingKey: "parent-a", metricKind: "confirmation_rejected", count: 1 });

		const laterTurnRef = `turn_${"9".repeat(32)}`;
		const action = armProviderAction(store, laterTurnRef, "media-confirmation-later");
		expect(
			store.guardConsequentialAction({
				turnRef: laterTurnRef,
				authority: mediaAuthority(OWNER_A),
				action,
				nowMs: NOW_MS + 11,
			}),
		).toMatchObject({ required: true });
	});

	it("resolves a pending confirmation after the store is reopened with the same key", async () => {
		const { createMediaActionConfirmationStore } = await import(
			"../../src/relay/media-action-confirmation-store.js"
		);
		const first = createMediaActionConfirmationStore({
			encryptionKey: ENCRYPTION_KEY,
			makeConfirmationId: () => "media-confirmation-restart",
			makeJti: () => "restart-jti",
		});
		armProviderAction(first, `turn_${"b".repeat(32)}`);
		const { closeDb } = await import("../../src/storage/db.js");
		closeDb();
		const reopened = createMediaActionConfirmationStore({ encryptionKey: ENCRYPTION_KEY });

		expect(
			reopened.resolveChoice({
				owner: OWNER_A,
				eventId: "event-after-restart",
				messageId: "message-after-restart",
				choice: "confirm",
				mintFreshTurn: () => ({ ref: `turn_${"c".repeat(32)}` }),
				nowMs: NOW_MS + 10,
			}),
		).toMatchObject({
			status: "confirmed",
			newlyResolved: true,
			freshTurnRef: `turn_${"c".repeat(32)}`,
		});
	});
});

function armProviderAction(
	store: MediaActionConfirmationStore,
	turnRef: string,
	confirmationId?: string,
) {
	const action = {
		toolName: "tc_provider_prepare_write" as const,
		params: {
			providerId: "clalit",
			service: "clalit",
			action: "prescription_renewal",
			params: { prescriptionId: confirmationId ?? "synthetic-rx" },
		},
	};
	store.registerTurnDerivation({
		owner: OWNER_A,
		turnRef,
		envelopes: [documentEnvelope("נא לחדש את המרשם")],
		createdAtMs: NOW_MS,
	});
	store.guardConsequentialAction({
		turnRef,
		authority: mediaAuthority(OWNER_A),
		action,
		nowMs: NOW_MS + 1,
	});
	return action;
}

function mediaAuthority(owner: typeof OWNER_A | typeof OWNER_B) {
	return {
		actorId: owner.actorId,
		subjectUserId: owner.subjectUserId,
		profileId: owner.profileId,
	};
}

function documentEnvelope(text: string) {
	return {
		kind: "document_extract" as const,
		text,
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
