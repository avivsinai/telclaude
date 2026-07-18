import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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
	});
});

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
