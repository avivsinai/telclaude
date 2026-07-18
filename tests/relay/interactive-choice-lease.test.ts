import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;
const NOW_MS = Date.parse("2026-07-18T12:00:00.000Z");
const OWNER = {
	actorId: "household:whatsapp:parent-a",
	subjectUserId: "household:parent-a",
	profileId: "parent-a",
	bindingId: "parent-a",
	conversationId: "whatsapp:household:parent-a",
} as const;

describe("interactive-choice lease", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-interactive-choice-"));
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

	it("allows only the first durable claimant and preserves its exact owner", async () => {
		const leaseStore = await import("../../src/relay/interactive-choice-lease.js");
		const reminder = leaseStore.claimInteractiveChoiceLease({
			...OWNER,
			kind: "reminder",
			ownerRef: "reminder-proposal-1",
			createdAtMs: NOW_MS,
			expiresAtMs: NOW_MS + 10 * 60_000,
		});

		expect(reminder).toEqual({
			...OWNER,
			kind: "reminder",
			ownerRef: "reminder-proposal-1",
			createdAtMs: NOW_MS,
			expiresAtMs: NOW_MS + 10 * 60_000,
		});
		expect(() =>
			leaseStore.claimInteractiveChoiceLease({
				...OWNER,
				kind: "media_confirmation",
				ownerRef: "media-confirmation-1",
				createdAtMs: NOW_MS + 1,
				expiresAtMs: NOW_MS + 10 * 60_000,
			}),
		).toThrowError(
			expect.objectContaining({
				code: "interactive_choice_busy",
				incumbentKind: "reminder",
			}),
		);
		expect(leaseStore.getInteractiveChoiceLease(OWNER.conversationId, NOW_MS + 1)).toEqual(
			reminder,
		);
	});

	it("is idempotent for the same claimant but rejects a changed owner tuple", async () => {
		const leaseStore = await import("../../src/relay/interactive-choice-lease.js");
		const input = {
			...OWNER,
			kind: "media_confirmation" as const,
			ownerRef: "media-confirmation-1",
			createdAtMs: NOW_MS,
			expiresAtMs: NOW_MS + 10 * 60_000,
		};
		const first = leaseStore.claimInteractiveChoiceLease(input);

		expect(leaseStore.claimInteractiveChoiceLease(input)).toEqual(first);
		expect(() =>
			leaseStore.claimInteractiveChoiceLease({
				...input,
				actorId: "household:whatsapp:parent-b",
			}),
		).toThrowError(expect.objectContaining({ code: "interactive_choice_busy" }));
	});

	it("reclaims expired state and releases only for the exact owner", async () => {
		const leaseStore = await import("../../src/relay/interactive-choice-lease.js");
		leaseStore.claimInteractiveChoiceLease({
			...OWNER,
			kind: "reminder",
			ownerRef: "reminder-proposal-expiring",
			createdAtMs: NOW_MS,
			expiresAtMs: NOW_MS + 1,
		});
		const replacement = leaseStore.claimInteractiveChoiceLease({
			...OWNER,
			kind: "media_confirmation",
			ownerRef: "media-confirmation-replacement",
			createdAtMs: NOW_MS + 2,
			expiresAtMs: NOW_MS + 10 * 60_000,
		});

		expect(
			leaseStore.releaseInteractiveChoiceLease({
				...OWNER,
				kind: "reminder",
				ownerRef: "reminder-proposal-expiring",
			}),
		).toBe(false);
		expect(leaseStore.getInteractiveChoiceLease(OWNER.conversationId, NOW_MS + 2)).toEqual(
			replacement,
		);
		expect(
			leaseStore.releaseInteractiveChoiceLease({
				...OWNER,
				kind: "media_confirmation",
				ownerRef: "media-confirmation-replacement",
			}),
		).toBe(true);
		expect(leaseStore.getInteractiveChoiceLease(OWNER.conversationId, NOW_MS + 2)).toBeNull();
	});

	it("keeps lease reclaim independent from a failing expiry metric write", async () => {
		const metrics = await import("../../src/household-metrics/store.js");
		const { getDb } = await import("../../src/storage/db.js");
		const leaseStore = await import("../../src/relay/interactive-choice-lease.js");
		metrics.configureHouseholdMetrics({ enabled: true });
		leaseStore.claimInteractiveChoiceLease({
			...OWNER,
			kind: "media_confirmation",
			ownerRef: "media-confirmation-expiring",
			createdAtMs: NOW_MS,
			expiresAtMs: NOW_MS + 1,
		});
		getDb().exec("DROP TABLE household_metrics");

		expect(
			leaseStore.claimInteractiveChoiceLease({
				...OWNER,
				kind: "reminder",
				ownerRef: "reminder-replacement",
				createdAtMs: NOW_MS + 2,
				expiresAtMs: NOW_MS + 10 * 60_000,
			}),
		).toMatchObject({ kind: "reminder", ownerRef: "reminder-replacement" });
	});
});
