import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { z } from "zod";
import type { TelclaudeConfig } from "../config/config.js";
import { resolveHouseholdReminderContext } from "../household-reminders/binding.js";
import { createHouseholdReminderFireExecutor } from "../household-reminders/fire-executor.js";
import {
	confirmHouseholdReminderProposal,
	getHouseholdReminderForAuthority,
	getHouseholdReminderInterceptionReceipt,
	listHouseholdReminders,
	markHouseholdReminderInterceptionReceiptAcked,
	prepareHouseholdReminderCancellation,
	prepareHouseholdReminderCreate,
	prepareHouseholdReminderUpdate,
	resolveHouseholdReminderProposalWithInterceptionReceipt,
} from "../household-reminders/store.js";
import { resolveJerusalemOneShot } from "../household-reminders/time.js";
import type {
	HouseholdReminderAuthority,
	HouseholdReminderBinding,
	HouseholdReminderConsentReceipt,
	HouseholdReminderOneShotSchedule,
	Sha256Ref,
} from "../household-reminders/types.js";
import { closeDb, resetDatabase } from "../storage/db.js";
import { WhatsAppBridgeIdempotencyJournal } from "../whatsapp-bridge/idempotency-journal.js";
import {
	type HermesSignedEvidenceValidationOptions,
	hermesAllowsStaleAttestations,
	hermesAttestationFreshnessFailure,
} from "./attestation-validation.js";
import { type HermesArtifactWriteOptions, writeHermesJsonArtifact } from "./foundation.js";
import {
	HOUSEHOLD_REMINDER_ATTESTATION_RUNNER,
	HOUSEHOLD_REMINDER_ATTESTATION_SCHEMA_VERSION,
	HOUSEHOLD_REMINDER_ATTESTATION_SOURCE,
	type HouseholdReminderAttestation,
	householdReminderAttestationFieldsForEvidence,
	householdReminderAttestationSignatureFailure,
	signHouseholdReminderAttestation,
} from "./household-reminder-attestation.js";

export const HOUSEHOLD_REMINDER_PROBE_ID = "household.reminders";
export const HOUSEHOLD_REMINDER_PROBE_SCHEMA_VERSION =
	"telclaude.hermes.household-reminder-probe.v1";
export const HOUSEHOLD_REMINDER_PROBE_SOURCE = "telclaude-household-reminder-acceptance-harness";
export const DEFAULT_HOUSEHOLD_REMINDER_EVIDENCE_PATH =
	"artifacts/hermes/probes/household-reminders.json";

const NonEmptyString = z.string().trim().min(1);
const Sha256Digest = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const HexSha256Digest = z.string().regex(/^[a-f0-9]{64}$/);
const SCENARIO_NOW_MS = Date.parse("2026-07-18T09:00:00.000Z");
const FORBIDDEN_EVIDENCE =
	/תזכורת|מסמכים|"(?:body|destination|recipient|address|actorId|subjectUserId|reminderText)"\s*:/i;
const EXPECTED_DST_ADJACENT_INSTANT_HASHES = [
	digest("2026-03-26T23:59:00.000Z"),
	digest("2026-03-27T00:00:00.000Z"),
	digest("2026-10-24T21:59:00.000Z"),
	digest("2026-10-25T00:00:00.000Z"),
] as const;
const EXPECTED_FROZEN_INSTANT_HASH = digest(String(Date.parse("2026-08-02T06:00:00.000Z")));

const REQUIRED_CHECKS = [
	"household-reminder.parents-isolated",
	"household-reminder.create-confirm-edit-confirm-fire-receipt",
	"household-reminder.cancel-confirm",
	"household-reminder.revoke-before-fire",
	"household-reminder.dst-adjacent-instants",
	"household-reminder.dst-gap-overlap-rejected",
	"household-reminder.frozen-instant",
	"household-reminder.channel-routing",
	"household-reminder.restart-pending-receipt-mismatch",
	"household-reminder.artifact-sanitized",
] as const;

const CheckSchema = z
	.object({
		name: z.enum(REQUIRED_CHECKS),
		status: z.enum(["pass", "fail"]),
		detail: NonEmptyString,
	})
	.strict();

const ObservationsSchema = z
	.object({
		parentCount: z.number().int().nonnegative(),
		createdCount: z.number().int().nonnegative(),
		updatedCount: z.number().int().nonnegative(),
		cancelledCount: z.number().int().nonnegative(),
		revokedBeforeFireCount: z.number().int().nonnegative(),
		deliveredCount: z.number().int().nonnegative(),
		whatsappSendCount: z.number().int().nonnegative(),
		telegramSendCount: z.number().int().nonnegative(),
		hermesSendCount: z.number().int().nonnegative(),
		receiptPendingRestartRecovered: z.boolean(),
		receiptMismatchDenied: z.boolean(),
		journalPendingRestartRecovered: z.boolean(),
		journalCompletedReplaySwallowed: z.boolean(),
		journalDigestMismatchDenied: z.boolean(),
		dstGapRejected: z.boolean(),
		dstOverlapRejected: z.boolean(),
		currentTzdataDriftRejected: z.boolean(),
		fireIdHash: Sha256Digest,
		receiptIdHash: Sha256Digest,
		restartMessageIdHash: Sha256Digest,
		dstAdjacentInstantHashes: z.array(Sha256Digest).length(4),
		frozenInstantHash: Sha256Digest,
	})
	.strict();

const InternalResponseProofSchema = z
	.object({
		version: z.literal("v1"),
		scope: NonEmptyString,
		timestamp: NonEmptyString,
		nonce: NonEmptyString,
		method: NonEmptyString,
		path: NonEmptyString,
		requestBodySha256: HexSha256Digest,
		responseBodySha256: HexSha256Digest,
		signature: NonEmptyString,
	})
	.strict();

const AttestationSchema = z
	.object({
		schemaVersion: z.literal(HOUSEHOLD_REMINDER_ATTESTATION_SCHEMA_VERSION),
		source: z.literal(HOUSEHOLD_REMINDER_ATTESTATION_SOURCE),
		runner: z.literal(HOUSEHOLD_REMINDER_ATTESTATION_RUNNER),
		probeEvidenceSchemaVersion: z.literal(HOUSEHOLD_REMINDER_PROBE_SCHEMA_VERSION),
		probeId: z.literal(HOUSEHOLD_REMINDER_PROBE_ID),
		status: z.enum(["pass", "fail"]),
		ran: z.boolean(),
		observedAt: NonEmptyString,
		checksSha256: Sha256Digest,
		observationsSha256: Sha256Digest,
		evidenceSha256: Sha256Digest,
		signature: InternalResponseProofSchema,
	})
	.strict();

export const HouseholdReminderProbeEvidenceSchema = z
	.object({
		schemaVersion: z.literal(HOUSEHOLD_REMINDER_PROBE_SCHEMA_VERSION),
		probeId: z.literal(HOUSEHOLD_REMINDER_PROBE_ID),
		status: z.enum(["pass", "fail"]),
		ran: z.boolean(),
		observedAt: NonEmptyString,
		source: z.literal(HOUSEHOLD_REMINDER_PROBE_SOURCE),
		summary: NonEmptyString,
		checks: z.array(CheckSchema).min(1),
		observations: ObservationsSchema,
		runnerAttestation: AttestationSchema.optional(),
	})
	.strict();

export type HouseholdReminderProbeEvidence = z.infer<typeof HouseholdReminderProbeEvidenceSchema>;
export type HouseholdReminderPhase0AcceptanceObservations = z.infer<typeof ObservationsSchema>;

export async function runHouseholdReminderProbe(input: {
	readonly allowRun: boolean;
	readonly observedAt?: string;
}): Promise<HouseholdReminderProbeEvidence> {
	const observedAt = input.observedAt ?? new Date().toISOString();
	if (!input.allowRun) return pendingEvidence(observedAt);
	let observations: HouseholdReminderPhase0AcceptanceObservations;
	try {
		observations = await runHouseholdReminderPhase0AcceptanceScenario();
	} catch {
		observations = emptyObservations();
	}
	const checks = buildChecks(observations);
	const status = checks.every((check) => check.status === "pass") ? "pass" : "fail";
	const evidence: Omit<HouseholdReminderProbeEvidence, "runnerAttestation"> = {
		schemaVersion: HOUSEHOLD_REMINDER_PROBE_SCHEMA_VERSION,
		probeId: HOUSEHOLD_REMINDER_PROBE_ID,
		status,
		ran: true,
		observedAt,
		source: HOUSEHOLD_REMINDER_PROBE_SOURCE,
		summary:
			status === "pass"
				? "Household reminder Phase 0 acceptance probe passed"
				: "Household reminder Phase 0 acceptance probe failed",
		checks,
		observations,
	};
	return { ...evidence, runnerAttestation: signHouseholdReminderAttestation(evidence) };
}

export async function runHouseholdReminderPhase0AcceptanceScenario(
	input: {
		readonly currentTzdataValidator?: (schedule: HouseholdReminderOneShotSchedule) => void;
	} = {},
): Promise<HouseholdReminderPhase0AcceptanceObservations> {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-household-reminder-probe-"));
	const originalDataDir = process.env.TELCLAUDE_DATA_DIR;
	closeDb();
	process.env.TELCLAUDE_DATA_DIR = path.join(tempDir, "relay-data");
	resetDatabase();
	try {
		return await executeAcceptanceScenario(tempDir, input.currentTzdataValidator);
	} finally {
		closeDb();
		if (originalDataDir === undefined) delete process.env.TELCLAUDE_DATA_DIR;
		else process.env.TELCLAUDE_DATA_DIR = originalDataDir;
		fs.rmSync(tempDir, { recursive: true, force: true });
	}
}

export function householdReminderProbeEvidenceFailure(
	evidence: unknown,
	options: HermesSignedEvidenceValidationOptions = {},
): string | null {
	const parsed = HouseholdReminderProbeEvidenceSchema.safeParse(evidence);
	if (!parsed.success) return `invalid household reminder evidence: ${flatten(parsed.error)}`;
	const data = parsed.data;
	const failures: string[] = [];
	const attestationFailure = verifyAttestation(data, options);
	if (attestationFailure) failures.push(attestationFailure);
	if (data.status !== "pass") failures.push(`status is ${data.status}`);
	if (!data.ran) failures.push("harness did not run");
	const freshnessFailure = hermesAttestationFreshnessFailure(
		"household reminder observedAt",
		data.observedAt,
		options,
	);
	if (freshnessFailure) failures.push(freshnessFailure);
	for (const duplicate of duplicates(data.checks.map((check) => check.name))) {
		failures.push(`duplicate check ${duplicate}`);
	}
	const checks = new Map(data.checks.map((check) => [check.name, check]));
	for (const name of REQUIRED_CHECKS) {
		const check = checks.get(name);
		if (!check) failures.push(`check ${name} is missing`);
		else if (check.status !== "pass") failures.push(`check ${name} is ${check.status}`);
	}
	// Keep relay-signed crypto metadata outside the content/custody scan after
	// its authenticity is checked. Only the evidence body can carry reminder or
	// routing content.
	const evidenceBody = JSON.stringify({ ...data, runnerAttestation: undefined });
	if (FORBIDDEN_EVIDENCE.test(evidenceBody)) {
		failures.push("artifact contains non-sanitized reminder or routing content");
	}
	failures.push(...observationFailures(data.observations));
	return failures.length > 0 ? failures.join("; ") : null;
}

export function writeHouseholdReminderProbeEvidence(
	evidence: HouseholdReminderProbeEvidence,
	filePath: string,
	options: HermesArtifactWriteOptions = {},
): void {
	writeHermesJsonArtifact(filePath, evidence, options);
}

async function executeAcceptanceScenario(
	tempDir: string,
	currentTzdataValidator: ((schedule: HouseholdReminderOneShotSchedule) => void) | undefined,
): Promise<HouseholdReminderPhase0AcceptanceObservations> {
	const parentA = context("parent-a", "a");
	const parentB = context("parent-b", "b");
	let whatsappSendCount = 0;
	const telegramSendCount = 0;
	const hermesSendCount = 0;

	const createdA = prepareHouseholdReminderCreate({
		...parentA,
		text: "להביא מסמכים",
		schedule: schedule("2026-08-01T09:00", "2026-08-01T06:00:00.000Z", 180),
		source: { kind: "parent" },
		nowMs: SCENARIO_NOW_MS,
	});
	requireResolved(
		confirmHouseholdReminderProposal({
			proposalRef: createdA.proposal.ref,
			...parentA,
			nowMs: SCENARIO_NOW_MS + 1_000,
		}),
	);
	const updatedA = prepareHouseholdReminderUpdate({
		reminderId: createdA.reminder.id,
		...parentA,
		text: "להביא מסמכים מעודכנים",
		schedule: schedule("2026-08-02T09:00", "2026-08-02T06:00:00.000Z", 180),
		nowMs: SCENARIO_NOW_MS + 2_000,
	});
	const updateReceipt = resolveHouseholdReminderProposalWithInterceptionReceipt({
		eventId: "probe-event-parent-a-update",
		messageId: "probe-message-parent-a-update",
		proposalRef: updatedA.proposal.ref,
		choice: "confirm",
		...parentA,
		nowMs: SCENARIO_NOW_MS + 3_000,
	});
	if (!updateReceipt) throw new Error("acceptance update receipt missing");
	closeDb();
	const receiptPendingRestartRecovered =
		getHouseholdReminderInterceptionReceipt({
			eventId: "probe-event-parent-a-update",
			messageId: "probe-message-parent-a-update",
			authority: parentA.authority,
			binding: parentA.binding,
		})?.status === "pending_ack";
	const receiptMismatchDenied =
		getHouseholdReminderInterceptionReceipt({
			eventId: "probe-event-parent-a-update",
			messageId: "probe-message-parent-a-mismatch",
			authority: parentA.authority,
			binding: parentA.binding,
		}) === null;
	if (!markHouseholdReminderInterceptionReceiptAcked(updateReceipt.receiptId)) {
		throw new Error("acceptance update receipt ACK failed");
	}
	const confirmedA = getHouseholdReminderForAuthority(createdA.reminder.id, parentA.authority);
	if (confirmedA?.revision !== 2 || confirmedA.status !== "scheduled") {
		throw new Error("acceptance updated reminder missing");
	}

	let currentTzdataDriftRejected = false;
	try {
		(
			currentTzdataValidator ??
			(() => {
				throw new Error("simulated current-tzdata drift");
			})
		)(confirmedA.schedule);
	} catch {
		currentTzdataDriftRejected = true;
	}
	let fireId = "";
	const fireExecutor = createHouseholdReminderFireExecutor({
		nowMs: () => confirmedA.schedule.resolvedAtMs + 1_000,
		prepare: async ({ fire }) => {
			fireId = fire.fireId;
			return {
				outboundRef: `scheduled-effect:${fire.fireId}`,
				edgePreparedHash: digest("probe-edge-prepared"),
				idempotencyKey: digest("probe-reminder-delivery"),
				whatsappMessageId: `TCREMINDER${"1".repeat(32)}`,
			};
		},
		execute: async ({ beforeDispatch }) => {
			if (!beforeDispatch()) throw new Error("acceptance dispatch was not authorized");
			whatsappSendCount += 1;
			return { ok: true, receiptStatus: "sent", platformMessageId: "probe-platform-message" };
		},
	});
	const delivered = await fireExecutor(
		{ reminderId: confirmedA.id, revision: confirmedA.revision },
		new AbortController().signal,
	);
	await fireExecutor(
		{ reminderId: confirmedA.id, revision: confirmedA.revision },
		new AbortController().signal,
	);

	const createdB = prepareHouseholdReminderCreate({
		...parentB,
		text: "בדיקת ביטול",
		schedule: schedule("2026-08-03T09:00", "2026-08-03T06:00:00.000Z", 180),
		source: { kind: "parent" },
		nowMs: SCENARIO_NOW_MS + 4_000,
	});
	requireResolved(
		confirmHouseholdReminderProposal({
			proposalRef: createdB.proposal.ref,
			...parentB,
			nowMs: SCENARIO_NOW_MS + 5_000,
		}),
	);
	const cancellation = prepareHouseholdReminderCancellation({
		reminderId: createdB.reminder.id,
		...parentB,
		nowMs: SCENARIO_NOW_MS + 6_000,
	});
	const cancellationReceipt = resolveHouseholdReminderProposalWithInterceptionReceipt({
		eventId: "probe-event-parent-b-cancel",
		messageId: "probe-message-parent-b-cancel",
		proposalRef: cancellation.proposal.ref,
		choice: "confirm",
		...parentB,
		nowMs: SCENARIO_NOW_MS + 7_000,
	});
	if (!cancellationReceipt) throw new Error("acceptance cancellation receipt missing");
	markHouseholdReminderInterceptionReceiptAcked(cancellationReceipt.receiptId);

	const revoked = prepareHouseholdReminderCreate({
		...parentB,
		text: "בדיקת ביטול הסכמה",
		schedule: schedule("2026-08-04T09:00", "2026-08-04T06:00:00.000Z", 180),
		source: { kind: "parent" },
		nowMs: SCENARIO_NOW_MS + 8_000,
	});
	const confirmedRevoked = requireResolved(
		confirmHouseholdReminderProposal({
			proposalRef: revoked.proposal.ref,
			...parentB,
			nowMs: SCENARIO_NOW_MS + 9_000,
		}),
	).reminder;
	let revokedContextDenied = false;
	const revokedExecutor = createHouseholdReminderFireExecutor({
		nowMs: () => confirmedRevoked.schedule.resolvedAtMs + 1_000,
		prepare: async () => {
			revokedContextDenied =
				resolveHouseholdReminderContext(parentB.authority, revokedReminderConfig(parentB)) === null;
			if (!revokedContextDenied) throw new Error("revoked reminder context remained authorized");
			throw new Error("consent revoked before fire");
		},
		execute: async () => {
			whatsappSendCount += 1;
			return { ok: true, receiptStatus: "sent" };
		},
	});
	const revokeResult = await revokedExecutor(
		{ reminderId: confirmedRevoked.id, revision: confirmedRevoked.revision },
		new AbortController().signal,
	);

	const dst = dstObservations();
	const journal = await journalObservations(path.join(tempDir, "bridge-data"));
	const parentAVisible = listHouseholdReminders(parentA.authority);
	const parentBVisible = listHouseholdReminders(parentB.authority);
	const parentsIsolated =
		parentAVisible.length === 1 &&
		parentBVisible.length === 2 &&
		getHouseholdReminderForAuthority(createdA.reminder.id, parentB.authority) === null &&
		getHouseholdReminderForAuthority(createdB.reminder.id, parentA.authority) === null;
	if (!parentsIsolated) throw new Error("acceptance parent isolation failed");

	return {
		parentCount: 2,
		createdCount: 3,
		updatedCount: 1,
		cancelledCount:
			getHouseholdReminderForAuthority(createdB.reminder.id, parentB.authority)?.status ===
			"cancelled"
				? 1
				: 0,
		revokedBeforeFireCount:
			!revokeResult.ok && revokedContextDenied && whatsappSendCount === 1 ? 1 : 0,
		deliveredCount: delivered.ok ? 1 : 0,
		whatsappSendCount,
		telegramSendCount,
		hermesSendCount,
		receiptPendingRestartRecovered,
		receiptMismatchDenied,
		...journal,
		...dst,
		currentTzdataDriftRejected,
		fireIdHash: digest(fireId),
		receiptIdHash: digest(updateReceipt.receiptId),
		frozenInstantHash: digest(String(confirmedA.schedule.resolvedAtMs)),
	};
}

async function journalObservations(
	dataDir: string,
): Promise<
	Pick<
		HouseholdReminderPhase0AcceptanceObservations,
		| "journalPendingRestartRecovered"
		| "journalCompletedReplaySwallowed"
		| "journalDigestMismatchDenied"
		| "restartMessageIdHash"
	>
> {
	const input = {
		idempotencyKey: "household-reminder-probe-pending",
		requestDigest: digest("household-reminder-probe-request"),
		messageCount: 1,
	};
	let firstMessageIds: readonly string[] = [];
	const first = new WhatsAppBridgeIdempotencyJournal({ dataDir });
	await first.execute(input, async (messageIds) => {
		firstMessageIds = [...messageIds];
		return { ok: false, code: "simulated_retry", retryable: true };
	});
	let restartedIds: readonly string[] = [];
	const restarted = new WhatsAppBridgeIdempotencyJournal({ dataDir });
	await restarted.execute(input, async (messageIds) => {
		restartedIds = [...messageIds];
		return { ok: true, platformMessageId: messageIds[0] };
	});
	let completedReplayCalls = 0;
	await new WhatsAppBridgeIdempotencyJournal({ dataDir }).execute(input, async () => {
		completedReplayCalls += 1;
		return { ok: true };
	});
	const mismatch = await restarted.execute(
		{ ...input, requestDigest: digest("household-reminder-probe-mismatch") },
		async () => ({ ok: true }),
	);
	return {
		journalPendingRestartRecovered:
			firstMessageIds.length === 1 &&
			JSON.stringify(firstMessageIds) === JSON.stringify(restartedIds),
		journalCompletedReplaySwallowed: completedReplayCalls === 0,
		journalDigestMismatchDenied:
			!mismatch.ok && mismatch.code === "whatsapp_bridge_idempotency_mismatch",
		restartMessageIdHash: digest(firstMessageIds[0] ?? "missing"),
	};
}

function dstObservations(): Pick<
	HouseholdReminderPhase0AcceptanceObservations,
	"dstAdjacentInstantHashes" | "dstGapRejected" | "dstOverlapRejected"
> {
	const adjacent = [
		resolveJerusalemOneShot("2026-03-27T01:59", {
			nowMs: Date.parse("2026-03-25T00:00:00.000Z"),
		}),
		resolveJerusalemOneShot("2026-03-27T03:00", {
			nowMs: Date.parse("2026-03-25T00:00:00.000Z"),
		}),
		resolveJerusalemOneShot("2026-10-25T00:59", {
			nowMs: Date.parse("2026-10-23T00:00:00.000Z"),
		}),
		resolveJerusalemOneShot("2026-10-25T02:00", {
			nowMs: Date.parse("2026-10-23T00:00:00.000Z"),
		}),
	];
	return {
		dstAdjacentInstantHashes: adjacent.map((entry) => digest(entry.resolvedAt)),
		dstGapRejected: throws(() =>
			resolveJerusalemOneShot("2026-03-27T02:30", {
				nowMs: Date.parse("2026-03-25T00:00:00.000Z"),
			}),
		),
		dstOverlapRejected: throws(() =>
			resolveJerusalemOneShot("2026-10-25T01:30", {
				nowMs: Date.parse("2026-10-23T00:00:00.000Z"),
			}),
		),
	};
}

function buildChecks(
	observations: HouseholdReminderPhase0AcceptanceObservations,
): HouseholdReminderProbeEvidence["checks"] {
	return [
		check("household-reminder.parents-isolated", observations.parentCount === 2),
		check(
			"household-reminder.create-confirm-edit-confirm-fire-receipt",
			observations.createdCount === 3 &&
				observations.updatedCount === 1 &&
				observations.deliveredCount === 1 &&
				observations.fireIdHash.startsWith("sha256:") &&
				observations.receiptIdHash.startsWith("sha256:"),
		),
		check("household-reminder.cancel-confirm", observations.cancelledCount === 1),
		check("household-reminder.revoke-before-fire", observations.revokedBeforeFireCount === 1),
		check(
			"household-reminder.dst-adjacent-instants",
			JSON.stringify(observations.dstAdjacentInstantHashes) ===
				JSON.stringify(EXPECTED_DST_ADJACENT_INSTANT_HASHES),
		),
		check(
			"household-reminder.dst-gap-overlap-rejected",
			observations.dstGapRejected && observations.dstOverlapRejected,
		),
		check(
			"household-reminder.frozen-instant",
			observations.currentTzdataDriftRejected &&
				observations.frozenInstantHash === EXPECTED_FROZEN_INSTANT_HASH &&
				observations.deliveredCount === 1,
		),
		check(
			"household-reminder.channel-routing",
			observations.whatsappSendCount === 1 &&
				observations.telegramSendCount === 0 &&
				observations.hermesSendCount === 0,
		),
		check(
			"household-reminder.restart-pending-receipt-mismatch",
			observations.receiptMismatchDenied &&
				observations.receiptPendingRestartRecovered &&
				observations.journalPendingRestartRecovered &&
				observations.journalCompletedReplaySwallowed &&
				observations.journalDigestMismatchDenied,
		),
		check(
			"household-reminder.artifact-sanitized",
			!FORBIDDEN_EVIDENCE.test(JSON.stringify(observations)),
		),
	];
}

function check(
	name: (typeof REQUIRED_CHECKS)[number],
	passed: boolean,
): HouseholdReminderProbeEvidence["checks"][number] {
	return {
		name,
		status: passed ? "pass" : "fail",
		detail: passed ? "acceptance condition observed" : "acceptance condition failed",
	};
}

function observationFailures(
	observations: HouseholdReminderPhase0AcceptanceObservations,
): string[] {
	const checks = buildChecks(observations);
	return checks
		.filter((check) => check.status === "fail")
		.map((check) => `${check.name} observation mismatch`);
}

function verifyAttestation(
	evidence: HouseholdReminderProbeEvidence,
	options: HermesSignedEvidenceValidationOptions,
): string | null {
	const attestation = evidence.runnerAttestation as HouseholdReminderAttestation | undefined;
	if (!attestation) return "runnerAttestation is missing";
	const signatureFailure = householdReminderAttestationSignatureFailure(attestation, {
		allowStale: hermesAllowsStaleAttestations(options),
		relayPublicKey: options.relayPublicKey,
	});
	if (signatureFailure) return `runnerAttestation signature is invalid: ${signatureFailure}`;
	const expected = householdReminderAttestationFieldsForEvidence(evidence);
	for (const field of [
		"probeEvidenceSchemaVersion",
		"probeId",
		"status",
		"ran",
		"observedAt",
		"checksSha256",
		"observationsSha256",
		"evidenceSha256",
	] as const) {
		if (attestation[field] !== expected[field]) return `runnerAttestation ${field} mismatch`;
	}
	return null;
}

function pendingEvidence(observedAt: string): HouseholdReminderProbeEvidence {
	return {
		schemaVersion: HOUSEHOLD_REMINDER_PROBE_SCHEMA_VERSION,
		probeId: HOUSEHOLD_REMINDER_PROBE_ID,
		status: "fail",
		ran: false,
		observedAt,
		source: HOUSEHOLD_REMINDER_PROBE_SOURCE,
		summary: "household reminder harness requires --allow-run",
		checks: [check("household-reminder.parents-isolated", false)],
		observations: emptyObservations(),
	};
}

function emptyObservations(): HouseholdReminderPhase0AcceptanceObservations {
	const zeroHash = digest("not-run");
	return {
		parentCount: 0,
		createdCount: 0,
		updatedCount: 0,
		cancelledCount: 0,
		revokedBeforeFireCount: 0,
		deliveredCount: 0,
		whatsappSendCount: 0,
		telegramSendCount: 0,
		hermesSendCount: 0,
		receiptPendingRestartRecovered: false,
		receiptMismatchDenied: false,
		journalPendingRestartRecovered: false,
		journalCompletedReplaySwallowed: false,
		journalDigestMismatchDenied: false,
		dstGapRejected: false,
		dstOverlapRejected: false,
		currentTzdataDriftRejected: false,
		fireIdHash: zeroHash,
		receiptIdHash: zeroHash,
		restartMessageIdHash: zeroHash,
		dstAdjacentInstantHashes: [zeroHash, zeroHash, zeroHash, zeroHash],
		frozenInstantHash: zeroHash,
	};
}

type ScenarioContext = {
	readonly authority: HouseholdReminderAuthority;
	readonly binding: HouseholdReminderBinding;
	readonly consent: HouseholdReminderConsentReceipt;
};

function context(label: string, hashChar: string): ScenarioContext {
	const address = `whatsapp:+1555000000${hashChar === "a" ? "1" : "2"}`;
	const principalHash = digest(address);
	return {
		authority: {
			actorId: `household:whatsapp:${label}`,
			subjectUserId: `household:${label}`,
			profileId: label,
		},
		binding: {
			bindingId: label,
			conversationId: `whatsapp:household:${label}`,
			senderPrincipalHash: principalHash,
			recipientPrincipalHash: principalHash,
		},
		consent: {
			state: "granted",
			ceremonyVersion: "phase0.v1",
			ceremonyHash: digest(`ceremony-${label}`),
			verifiedChannelHash: principalHash,
			categories: {
				proactiveDelivery: true,
				scheduleManagement: true,
				retentionDisclosure: true,
			},
			recordedAt: new Date(SCENARIO_NOW_MS).toISOString(),
			operatorId: "operator:probe",
		},
	};
}

function revokedReminderConfig(householdContext: ScenarioContext): TelclaudeConfig {
	const address =
		householdContext.binding.bindingId === "parent-a"
			? "whatsapp:+15550000001"
			: "whatsapp:+15550000002";
	const partial: Pick<TelclaudeConfig, "householdReminders" | "profiles"> = {
		householdReminders: { enabled: true },
		profiles: [
			{
				id: householdContext.authority.profileId,
				label: "Household probe profile",
				allowedSkills: [],
				providerScopes: ["clalit"],
				capabilityScopes: ["schedule.read", "schedule.write"],
				outboundChannels: ["whatsapp"],
				whatsappHouseholdBindings: [
					{
						bindingId: householdContext.binding.bindingId,
						addresseeGender: householdContext.binding.bindingId === "parent-a" ? "f" : "m",
						address,
						replyAddress: address,
						displayName: "Household probe parent",
						subjectUserId: householdContext.authority.subjectUserId,
						remindersEnabled: true,
						reminderConsent: {
							state: "revoked",
							ceremonyVersion: householdContext.consent.ceremonyVersion,
							ceremonyHash: householdContext.consent.ceremonyHash,
							verifiedChannelHash: householdContext.consent.verifiedChannelHash,
							categories: householdContext.consent.categories,
							recordedAt: householdContext.consent.recordedAt,
							operatorId: householdContext.consent.operatorId,
							revokedAt: new Date(SCENARIO_NOW_MS + 10_000).toISOString(),
						},
					},
				],
			},
		],
	};
	return partial as TelclaudeConfig;
}

function schedule(
	localDateTime: string,
	resolvedAt: string,
	offsetMinutes: number,
): HouseholdReminderOneShotSchedule {
	return {
		timeZone: "Asia/Jerusalem",
		localDateTime,
		resolvedAt,
		resolvedAtMs: Date.parse(resolvedAt),
		offsetMinutes,
	};
}

function requireResolved<T extends { readonly ok: boolean }>(
	resolution: T,
): Extract<T, { readonly ok: true }> {
	if (!resolution.ok) throw new Error("acceptance proposal resolution failed");
	return resolution as Extract<T, { readonly ok: true }>;
}

function digest(value: string): Sha256Ref {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function throws(operation: () => unknown): boolean {
	try {
		operation();
		return false;
	} catch {
		return true;
	}
}

function duplicates(values: readonly string[]): string[] {
	const seen = new Set<string>();
	const duplicates = new Set<string>();
	for (const value of values) {
		if (seen.has(value)) duplicates.add(value);
		else seen.add(value);
	}
	return [...duplicates];
}

function flatten(error: z.ZodError): string {
	return error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`).join("; ");
}
