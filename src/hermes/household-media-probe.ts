import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { z } from "zod";
import type { TelclaudeConfig } from "../config/config.js";
import { resolveHouseholdMediaActivation } from "../config/profiles.js";
import {
	createAttachmentProcessorCapability,
	createAttachmentQuarantineStore,
	type QuarantineOwnerBinding,
} from "../relay/attachment-quarantine-store.js";
import { createDocumentUnderstandingAdapter } from "../relay/document-understanding-adapter.js";
import { createEdgeOutboundExecutorRegistry } from "../relay/edge-outbound-executor-registry.js";
import { createInboundMediaProcessor } from "../relay/inbound-media-processor.js";
import {
	createMediaActionConfirmationStore,
	type MediaConfirmationOwner,
	type MediaConsequentialAction,
} from "../relay/media-action-confirmation-store.js";
import { evaluateVoiceConfidenceV1 } from "../relay/media-confidence-policy.js";
import { createOutboundDeliveryDispatcher } from "../relay/outbound-delivery-dispatcher.js";
import {
	createWhatsAppEdgeChannelConnector,
	type WhatsAppSidecarSendRequest,
} from "../relay/whatsapp-edge-channel-connector.js";
import { closeDb, resetDatabase } from "../storage/db.js";
import { whatsappBridgeContentForAttachment } from "../whatsapp-bridge/contract.js";
import {
	type HermesSignedEvidenceValidationOptions,
	hermesAllowsStaleAttestations,
	hermesAttestationFreshnessFailure,
} from "./attestation-validation.js";
import {
	EdgeAdapterSchemaVersions,
	type PreparedOutbound,
	PreparedOutboundSchema,
} from "./edge-adapter-contract.js";
import { type HermesArtifactWriteOptions, writeHermesJsonArtifact } from "./foundation.js";
import {
	HOUSEHOLD_MEDIA_ATTESTATION_RUNNER,
	HOUSEHOLD_MEDIA_ATTESTATION_SCHEMA_VERSION,
	HOUSEHOLD_MEDIA_ATTESTATION_SOURCE,
	type HouseholdMediaAttestation,
	householdMediaAttestationFieldsForEvidence,
	householdMediaAttestationSignatureFailure,
	signHouseholdMediaAttestation,
} from "./household-media-attestation.js";

export const HOUSEHOLD_MEDIA_PROBE_ID = "household.media";
export const HOUSEHOLD_MEDIA_PROBE_SCHEMA_VERSION = "telclaude.hermes.household-media-probe.v1";
export const HOUSEHOLD_MEDIA_PROBE_SOURCE = "telclaude-household-media-acceptance-harness";
export const DEFAULT_HOUSEHOLD_MEDIA_EVIDENCE_PATH = "artifacts/hermes/probes/household-media.json";

export const HOUSEHOLD_MEDIA_PROBE_REQUIRED_CHECKS = [
	"media.parents-isolated",
	"media.quarantine-bounded",
	"media.voice-confidence-weighted",
	"media.document-static-bounded",
	"media.action-classified",
	"media.confirmation-bound-once",
	"media.execution-fresh-turn-bound",
	"media.outbound-named-pdf-bound",
	"media.denials-fail-closed",
	"media.artifact-sanitized",
] as const;

const NonEmptyString = z.string().trim().min(1);
const Sha256Digest = z.string().regex(/^sha256:[a-f0-9]{64}$/u);
const HexSha256Digest = z.string().regex(/^[a-f0-9]{64}$/u);
const SCENARIO_NOW_MS = Date.parse("2026-07-18T12:00:00.000Z");
const ZERO_HASH = digest("not-run");
const FORBIDDEN_EVIDENCE =
	/OpusHead|raw-parent|private\/tmp|quarantineId|providerId|EXIF|filename|bytes|actorId|subjectUserId|conversationId/i;

const CheckSchema = z
	.object({
		name: z.enum(HOUSEHOLD_MEDIA_PROBE_REQUIRED_CHECKS),
		status: z.enum(["pass", "fail"]),
		detail: NonEmptyString,
	})
	.strict();

const ObservationsSchema = z
	.object({
		parentCount: z.number().int().nonnegative(),
		voiceDerivationCount: z.number().int().nonnegative(),
		documentDerivationCount: z.number().int().nonnegative(),
		confirmedActionCount: z.number().int().nonnegative(),
		executedActionCount: z.number().int().nonnegative(),
		namedPdfDeliveryCount: z.number().int().nonnegative(),
		deletionReceiptCount: z.number().int().nonnegative(),
		denialCount: z.number().int().nonnegative(),
		parentsIsolated: z.boolean(),
		quarantineBounded: z.boolean(),
		voiceConfidenceWeighted: z.boolean(),
		documentStaticBounded: z.boolean(),
		actionClassified: z.boolean(),
		confirmationBoundOnce: z.boolean(),
		freshTurnExecutionBound: z.boolean(),
		namedPdfBound: z.boolean(),
		denialsFailClosed: z.boolean(),
		artifactSanitized: z.boolean(),
		parentChainHashes: z.array(Sha256Digest).length(2),
		namedPdfHashes: z.array(Sha256Digest).length(2),
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
		schemaVersion: z.literal(HOUSEHOLD_MEDIA_ATTESTATION_SCHEMA_VERSION),
		source: z.literal(HOUSEHOLD_MEDIA_ATTESTATION_SOURCE),
		runner: z.literal(HOUSEHOLD_MEDIA_ATTESTATION_RUNNER),
		probeEvidenceSchemaVersion: z.literal(HOUSEHOLD_MEDIA_PROBE_SCHEMA_VERSION),
		probeId: z.literal(HOUSEHOLD_MEDIA_PROBE_ID),
		status: z.enum(["pass", "fail"]),
		ran: z.boolean(),
		observedAt: NonEmptyString,
		checksSha256: Sha256Digest,
		observationsSha256: Sha256Digest,
		evidenceSha256: Sha256Digest,
		signature: InternalResponseProofSchema,
	})
	.strict();

export const HouseholdMediaProbeEvidenceSchema = z
	.object({
		schemaVersion: z.literal(HOUSEHOLD_MEDIA_PROBE_SCHEMA_VERSION),
		probeId: z.literal(HOUSEHOLD_MEDIA_PROBE_ID),
		status: z.enum(["pass", "fail"]),
		ran: z.boolean(),
		observedAt: NonEmptyString,
		source: z.literal(HOUSEHOLD_MEDIA_PROBE_SOURCE),
		summary: NonEmptyString,
		checks: z.array(CheckSchema).min(1),
		observations: ObservationsSchema,
		runnerAttestation: AttestationSchema.optional(),
	})
	.strict();

export type HouseholdMediaProbeEvidence = z.infer<typeof HouseholdMediaProbeEvidenceSchema>;
export type HouseholdMediaPhase0AcceptanceObservations = z.infer<typeof ObservationsSchema>;

export async function runHouseholdMediaProbe(input: {
	readonly allowRun: boolean;
	readonly observedAt?: string;
}): Promise<HouseholdMediaProbeEvidence> {
	const observedAt = input.observedAt ?? new Date().toISOString();
	if (!input.allowRun) return pendingEvidence(observedAt);
	let observations: HouseholdMediaPhase0AcceptanceObservations;
	try {
		observations = await runHouseholdMediaPhase0AcceptanceScenario();
	} catch {
		observations = emptyObservations();
	}
	const checks = buildChecks(observations);
	const status = checks.every((item) => item.status === "pass") ? "pass" : "fail";
	const evidence: Omit<HouseholdMediaProbeEvidence, "runnerAttestation"> = {
		schemaVersion: HOUSEHOLD_MEDIA_PROBE_SCHEMA_VERSION,
		probeId: HOUSEHOLD_MEDIA_PROBE_ID,
		status,
		ran: true,
		observedAt,
		source: HOUSEHOLD_MEDIA_PROBE_SOURCE,
		summary:
			status === "pass"
				? "Household media Phase 0 acceptance probe passed"
				: "Household media Phase 0 acceptance probe failed",
		checks,
		observations,
	};
	return { ...evidence, runnerAttestation: signHouseholdMediaAttestation(evidence) };
}

export async function runHouseholdMediaPhase0AcceptanceScenario(): Promise<HouseholdMediaPhase0AcceptanceObservations> {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-household-media-probe-"));
	const originalDataDir = process.env.TELCLAUDE_DATA_DIR;
	closeDb();
	process.env.TELCLAUDE_DATA_DIR = path.join(tempDir, "relay-data");
	resetDatabase();
	try {
		return await executeAcceptanceScenario(tempDir);
	} finally {
		closeDb();
		if (originalDataDir === undefined) delete process.env.TELCLAUDE_DATA_DIR;
		else process.env.TELCLAUDE_DATA_DIR = originalDataDir;
		fs.rmSync(tempDir, { recursive: true, force: true });
	}
}

export function householdMediaProbeEvidenceFailure(
	evidence: unknown,
	options: HermesSignedEvidenceValidationOptions = {},
): string | null {
	const parsed = HouseholdMediaProbeEvidenceSchema.safeParse(evidence);
	if (!parsed.success) return `invalid household media evidence: ${flatten(parsed.error)}`;
	const data = parsed.data;
	const failures: string[] = [];
	if (data.status !== "pass") failures.push(`status is ${data.status}`);
	if (!data.ran) failures.push("harness did not run");
	const freshnessFailure = hermesAttestationFreshnessFailure(
		"household media observedAt",
		data.observedAt,
		options,
	);
	if (freshnessFailure) failures.push(freshnessFailure);
	for (const duplicate of duplicates(data.checks.map((item) => item.name))) {
		failures.push(`duplicate check ${duplicate}`);
	}
	const checks = new Map(data.checks.map((item) => [item.name, item]));
	for (const name of HOUSEHOLD_MEDIA_PROBE_REQUIRED_CHECKS) {
		const item = checks.get(name);
		if (!item) failures.push(`check ${name} is missing`);
		else if (item.status !== "pass") failures.push(`check ${name} is ${item.status}`);
	}
	if (FORBIDDEN_EVIDENCE.test(JSON.stringify(data))) {
		failures.push("artifact contains non-sanitized media content or custody metadata");
	}
	failures.push(...observationFailures(data.observations));
	const attestationFailure = verifyAttestation(data, options);
	if (attestationFailure) failures.push(attestationFailure);
	return failures.length > 0 ? failures.join("; ") : null;
}

export function writeHouseholdMediaProbeEvidence(
	evidence: HouseholdMediaProbeEvidence,
	filePath: string,
	options: HermesArtifactWriteOptions = {},
): void {
	writeHermesJsonArtifact(filePath, evidence, options);
}

async function executeAcceptanceScenario(
	tempDir: string,
): Promise<HouseholdMediaPhase0AcceptanceObservations> {
	const parents = [parent("a"), parent("b")] as const;
	const capability = createAttachmentProcessorCapability();
	const quarantineStore = createAttachmentQuarantineStore({
		processorCapability: capability,
		quarantineDir: path.join(tempDir, "processor-quarantine"),
		now: () => SCENARIO_NOW_MS,
	});
	let denialCount = 0;

	const voiceRef = quarantineStore.store({
		bytes: Buffer.concat([Buffer.from("OggS"), Buffer.alloc(24), Buffer.from("OpusHead")]),
		mediaType: "audio/ogg",
		conversationToken: parents[0].quarantine.conversationToken,
		owner: parents[0].quarantine,
		accessClass: "media-processor",
		receivedAtMs: SCENARIO_NOW_MS,
	});
	const cleanVoice = quarantineStore.recordScanResult(
		voiceRef.quarantineId,
		parents[0].quarantine,
		"clean",
	);
	if (!cleanVoice) throw new Error("voice fixture did not become clean");
	if (
		quarantineStore.leaseForProcessing(
			cleanVoice.quarantineId,
			parents[1].quarantine,
			capability,
		) === null
	) {
		denialCount += 1;
	}

	const staticPdf = Buffer.from(
		"%PDF-1.4\n1 0 obj << /Type /Page /MediaBox [0 0 612 792] >> endobj\n%%EOF",
	);
	const documentRef = quarantineStore.store({
		bytes: staticPdf,
		mediaType: "application/pdf",
		conversationToken: parents[1].quarantine.conversationToken,
		owner: parents[1].quarantine,
		accessClass: "media-processor",
		receivedAtMs: SCENARIO_NOW_MS,
	});
	const cleanDocument = quarantineStore.recordScanResult(
		documentRef.quarantineId,
		parents[1].quarantine,
		"clean",
	);
	if (!cleanDocument) throw new Error("document fixture did not become clean");

	let documentRequest: unknown;
	const documentAdapter = createDocumentUnderstandingAdapter({
		createResponse: async (request) => {
			documentRequest = request;
			return {
				output_text: JSON.stringify({
					text: "נא לשלוח את סיכום הביקור",
					blocks: [{ page: 1, block: 0, text: "נא לשלוח את סיכום הביקור" }],
				}),
			};
		},
	});
	const processor = createInboundMediaProcessor({
		quarantineStore,
		processorCapability: capability,
		runFfmpeg: async (_inputPath, outputPath) => {
			fs.writeFileSync(outputPath, "derived-audio", { mode: 0o600 });
		},
		transcribe: async () => ({
			text: "תזכירי לי לקבוע תור",
			language: "he",
			durationSeconds: 4,
			confidenceSource: "openai_whisper_verbose_segments_v1",
			segments: [
				{ durationSeconds: 1, avgLogprob: -0.1, noSpeechProbability: 0.01 },
				{ durationSeconds: 3, avgLogprob: -0.2, noSpeechProbability: 0.02 },
			],
		}),
		documentAdapter,
	});
	const voiceEnvelope = await processor.processVoice({
		ref: cleanVoice,
		owner: parents[0].quarantine,
	});
	const documentEnvelope = await processor.processDocument({
		ref: cleanDocument,
		owner: parents[1].quarantine,
	});
	const lowVoiceConfidence = evaluateVoiceConfidenceV1({
		confidenceSource: "openai_whisper_verbose_segments_v1",
		language: "he",
		durationSeconds: 4,
		segments: [{ durationSeconds: 4, avgLogprob: -0.3, noSpeechProbability: 0.01 }],
	});

	const activeDocumentRejected = await rejects(async () => {
		await documentAdapter.extract({
			bytes: Buffer.from(
				"%PDF-1.4\n1 0 obj << /Type /Page /MediaBox [0 0 612 792] /OpenAction 2 0 R >> endobj\n%%EOF",
			),
			mediaType: "application/pdf",
		});
	});
	if (activeDocumentRejected) denialCount += 1;
	const oversizedDocumentRejected = await rejects(async () => {
		await documentAdapter.extract({
			bytes: Buffer.from(
				`%PDF-1.4\n${Array.from(
					{ length: 21 },
					(_, index) => `${index + 1} 0 obj << /Type /Page /MediaBox [0 0 612 792] >> endobj`,
				).join("\n")}\n%%EOF`,
			),
			mediaType: "application/pdf",
		});
	});
	if (oversizedDocumentRejected) denialCount += 1;
	const blocked = quarantineStore.store({
		bytes: Buffer.from("raw-parent-unsupported"),
		mediaType: "application/pdf",
		conversationToken: parents[0].quarantine.conversationToken,
		owner: parents[0].quarantine,
		accessClass: "media-processor",
		receivedAtMs: SCENARIO_NOW_MS,
	});
	if (blocked.scanState === "blocked" && quarantineStore.getDeletionReceipt(blocked.quarantineId)) {
		denialCount += 1;
	}

	const mediaStore = createMediaActionConfirmationStore({
		encryptionKey: "household-media-probe-encryption-key-v1",
		nowMs: () => SCENARIO_NOW_MS,
		makeConfirmationId: sequence("media-confirmation"),
		makeJti: sequence("media-action-jti"),
	});
	const envelopes = [voiceEnvelope, documentEnvelope] as const;
	const actions = [providerAction("a"), providerAction("b")] as const;
	const originalTurns = [`turn_${"a".repeat(32)}`, `turn_${"b".repeat(32)}`] as const;
	const freshTurns = [`turn_${"c".repeat(32)}`, `turn_${"d".repeat(32)}`] as const;
	const parentChainHashes: `sha256:${string}`[] = [];
	let confirmedActionCount = 0;
	let executedActionCount = 0;
	let confirmationBoundOnce = true;
	let freshTurnExecutionBound = true;

	for (const [index, current] of parents.entries()) {
		const envelope = envelopes[index];
		const action = actions[index];
		const originalTurn = originalTurns[index];
		const freshTurn = freshTurns[index];
		if (!envelope || !action || !originalTurn || !freshTurn) {
			throw new Error("media acceptance chain fixture is incomplete");
		}
		mediaStore.registerTurnDerivation({
			owner: current.confirmation,
			turnRef: originalTurn,
			envelopes: [envelope],
			createdAtMs: SCENARIO_NOW_MS,
		});
		const guarded = mediaStore.guardConsequentialAction({
			turnRef: originalTurn,
			authority: current.confirmation,
			action,
			nowMs: SCENARIO_NOW_MS + 1,
		});
		if (!guarded.required) throw new Error("media confirmation was not required");
		if (index === 0) {
			const wrongParent = mediaStore.resolveChoice({
				owner: parents[1].confirmation,
				eventId: "wrong-parent-event",
				messageId: "wrong-parent-message",
				choice: "confirm",
				mintFreshTurn: () => ({ ref: freshTurn }),
				nowMs: SCENARIO_NOW_MS + 2,
			});
			if (wrongParent === null) denialCount += 1;
		}
		const receipt = mediaStore.resolveChoice({
			owner: current.confirmation,
			eventId: `confirm-event-${index}`,
			messageId: `confirm-message-${index}`,
			choice: "confirm",
			mintFreshTurn: () => ({ ref: freshTurn }),
			nowMs: SCENARIO_NOW_MS + 3,
		});
		if (!receipt?.newlyResolved || receipt.status !== "confirmed") {
			throw new Error("media confirmation did not resolve");
		}
		confirmedActionCount += 1;
		const replay = mediaStore.resolveChoice({
			owner: current.confirmation,
			eventId: `confirm-event-${index}`,
			messageId: `confirm-message-${index}`,
			choice: "confirm",
			mintFreshTurn: () => ({ ref: `turn_${"e".repeat(32)}` }),
			nowMs: SCENARIO_NOW_MS + 4,
		});
		if (replay?.newlyResolved === false) denialCount += 1;
		else confirmationBoundOnce = false;

		const mutatedDenied = throws(() =>
			mediaStore.guardConsequentialAction({
				turnRef: freshTurn,
				authority: current.confirmation,
				action: { ...action, params: { ...action.params, changed: true } },
				nowMs: SCENARIO_NOW_MS + 5,
			}),
		);
		if (mutatedDenied) denialCount += 1;
		const execution = mediaStore.guardConsequentialAction({
			turnRef: freshTurn,
			authority: current.confirmation,
			action,
			nowMs: SCENARIO_NOW_MS + 6,
		});
		if (execution.required) throw new Error("confirmed exact action was re-gated");
		executedActionCount += 1;
		const replayDenied = throws(() =>
			mediaStore.guardConsequentialAction({
				turnRef: freshTurn,
				authority: current.confirmation,
				action,
				nowMs: SCENARIO_NOW_MS + 7,
			}),
		);
		if (replayDenied) denialCount += 1;
		else freshTurnExecutionBound = false;
		parentChainHashes.push(
			digest(`${guarded.confirmation.sourceDigest}\n${guarded.confirmation.actionDigest}`),
		);
	}

	const outboundStore = createAttachmentQuarantineStore({
		quarantineDir: path.join(tempDir, "outbound-quarantine"),
		now: () => SCENARIO_NOW_MS,
	});
	const sentRequests: WhatsAppSidecarSendRequest[] = [];
	const allowedRecipients = parents.map((item) => item.addressRef);
	const connector = createWhatsAppEdgeChannelConnector({
		allowedRecipientAddressRefs: allowedRecipients,
		sendToSidecar: async (request) => {
			sentRequests.push(request);
			return { ok: true, platformMessageId: `sent-${sentRequests.length}` };
		},
	});
	const dispatch = createOutboundDeliveryDispatcher({
		registry: createEdgeOutboundExecutorRegistry([connector]),
		resolveConversation: async (prepared) => ({
			conversationToken: prepared.resolvedDestination.conversationId ?? "",
			threadMessageIds: [],
		}),
		quarantineStore: outboundStore,
		now: () => SCENARIO_NOW_MS,
	});
	const namedPdfHashes: `sha256:${string}`[] = [];
	const outboundRefs: Array<ReturnType<typeof outboundStore.store>> = [];
	for (const [index, current] of parents.entries()) {
		const name = `Provider_Statement_${index === 0 ? "A" : "B"}.pdf`;
		const stored = outboundStore.store({
			bytes: Buffer.from(`%PDF-1.4\nstatement-${index}\n%%EOF`),
			mediaType: "application/pdf",
			conversationToken: current.quarantine.conversationToken,
			scanState: "clean",
		});
		outboundRefs.push(stored);
		const receipt = await dispatch(
			preparedOutbound(index, current, { ...stored, redactedFilename: name }),
		);
		if (receipt.deliveryStatus !== "sent") throw new Error("named PDF delivery failed");
		const attachment = sentRequests[index]?.attachments[0];
		if (!attachment) throw new Error("named PDF sidecar attachment missing");
		const content = whatsappBridgeContentForAttachment(attachment, "");
		if (content.fileName !== name) throw new Error("named PDF did not reach the bridge");
		namedPdfHashes.push(digest(name));
	}
	const firstOutbound = outboundRefs[0];
	if (!firstOutbound) throw new Error("outbound fixture missing");
	const driftReceipt = await dispatch(
		preparedOutbound(99, parents[0], {
			...firstOutbound,
			redactedFilename: "Provider_Statement_A.pdf",
			sizeBytes: firstOutbound.sizeBytes + 1,
		}),
	);
	if (driftReceipt.deliveryStatus === "failed" && sentRequests.length === 2) denialCount += 1;

	const configFor = (globalEnabled: boolean, bindingEnabled: boolean) =>
		({
			householdMedia: { enabled: globalEnabled },
			profiles: [
				{
					whatsappHouseholdBindings: [{ bindingId: "parent-a", mediaEnabled: bindingEnabled }],
				},
			],
		}) as Pick<TelclaudeConfig, "householdMedia" | "profiles">;
	for (const dark of [
		resolveHouseholdMediaActivation(configFor(false, true), "x".repeat(32)),
		resolveHouseholdMediaActivation(configFor(true, false), "x".repeat(32)),
		resolveHouseholdMediaActivation(configFor(true, true), undefined),
	]) {
		if (!dark.enabled) denialCount += 1;
	}

	const deletionReceiptCount = [
		cleanVoice.quarantineId,
		cleanDocument.quarantineId,
		blocked.quarantineId,
	].filter((id) => quarantineStore.getDeletionReceipt(id) !== null).length;
	const documentRequestText = JSON.stringify(documentRequest);
	const observationsWithoutPrivacy = {
		parentCount: parents.length,
		voiceDerivationCount: voiceEnvelope.kind === "voice_transcript" ? 1 : 0,
		documentDerivationCount: documentEnvelope.kind === "document_extract" ? 1 : 0,
		confirmedActionCount,
		executedActionCount,
		namedPdfDeliveryCount: sentRequests.length,
		deletionReceiptCount,
		denialCount,
		parentsIsolated: new Set(parentChainHashes).size === parents.length,
		quarantineBounded:
			deletionReceiptCount === 3 &&
			quarantineStore.inspect(cleanVoice.quarantineId, parents[0].quarantine)?.state ===
				"deleted" &&
			quarantineStore.inspect(cleanDocument.quarantineId, parents[1].quarantine)?.state ===
				"deleted",
		voiceConfidenceWeighted:
			voiceEnvelope.confidence !== undefined &&
			voiceEnvelope.confidence >= 0.82 &&
			!voiceEnvelope.lowConfidence &&
			lowVoiceConfidence.lowConfidence &&
			lowVoiceConfidence.reasonCodes.includes("confidence_below_threshold"),
		documentStaticBounded:
			documentEnvelope.sourcePageCount === 1 &&
			documentRequestText.includes('"store":false') &&
			documentRequestText.includes("data:application/pdf;base64,") &&
			activeDocumentRejected &&
			oversizedDocumentRejected,
		actionClassified: voiceEnvelope.actionBearing && documentEnvelope.actionBearing,
		confirmationBoundOnce,
		freshTurnExecutionBound,
		namedPdfBound: sentRequests.length === 2 && namedPdfHashes.length === 2,
		denialsFailClosed: denialCount >= 10,
		parentChainHashes,
		namedPdfHashes,
	};
	const artifactSanitized = !FORBIDDEN_EVIDENCE.test(JSON.stringify(observationsWithoutPrivacy));
	return { ...observationsWithoutPrivacy, artifactSanitized };
}

function buildChecks(
	observations: HouseholdMediaPhase0AcceptanceObservations,
): HouseholdMediaProbeEvidence["checks"] {
	const conditions: Record<(typeof HOUSEHOLD_MEDIA_PROBE_REQUIRED_CHECKS)[number], boolean> = {
		"media.parents-isolated": observations.parentsIsolated && observations.parentCount === 2,
		"media.quarantine-bounded":
			observations.quarantineBounded && observations.deletionReceiptCount === 3,
		"media.voice-confidence-weighted":
			observations.voiceConfidenceWeighted && observations.voiceDerivationCount === 1,
		"media.document-static-bounded":
			observations.documentStaticBounded && observations.documentDerivationCount === 1,
		"media.action-classified": observations.actionClassified,
		"media.confirmation-bound-once":
			observations.confirmationBoundOnce && observations.confirmedActionCount === 2,
		"media.execution-fresh-turn-bound":
			observations.freshTurnExecutionBound && observations.executedActionCount === 2,
		"media.outbound-named-pdf-bound":
			observations.namedPdfBound && observations.namedPdfDeliveryCount === 2,
		"media.denials-fail-closed": observations.denialsFailClosed && observations.denialCount >= 10,
		"media.artifact-sanitized": observations.artifactSanitized,
	};
	return HOUSEHOLD_MEDIA_PROBE_REQUIRED_CHECKS.map((name) => check(name, conditions[name]));
}

function check(
	name: (typeof HOUSEHOLD_MEDIA_PROBE_REQUIRED_CHECKS)[number],
	passed: boolean,
): HouseholdMediaProbeEvidence["checks"][number] {
	return {
		name,
		status: passed ? "pass" : "fail",
		detail: passed ? "acceptance condition observed" : "acceptance condition failed",
	};
}

function observationFailures(observations: HouseholdMediaPhase0AcceptanceObservations): string[] {
	return buildChecks(observations)
		.filter((item) => item.status === "fail")
		.map((item) => `${item.name} observation mismatch`);
}

function verifyAttestation(
	evidence: HouseholdMediaProbeEvidence,
	options: HermesSignedEvidenceValidationOptions,
): string | null {
	const attestation = evidence.runnerAttestation as HouseholdMediaAttestation | undefined;
	if (!attestation) return "runnerAttestation is missing";
	const signatureFailure = householdMediaAttestationSignatureFailure(attestation, {
		allowStale: hermesAllowsStaleAttestations(options),
		relayPublicKey: options.relayPublicKey,
	});
	if (signatureFailure) return `runnerAttestation signature is invalid: ${signatureFailure}`;
	const expected = householdMediaAttestationFieldsForEvidence(evidence);
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

function pendingEvidence(observedAt: string): HouseholdMediaProbeEvidence {
	return {
		schemaVersion: HOUSEHOLD_MEDIA_PROBE_SCHEMA_VERSION,
		probeId: HOUSEHOLD_MEDIA_PROBE_ID,
		status: "fail",
		ran: false,
		observedAt,
		source: HOUSEHOLD_MEDIA_PROBE_SOURCE,
		summary: "household media harness requires --allow-run",
		checks: [check(HOUSEHOLD_MEDIA_PROBE_REQUIRED_CHECKS[0], false)],
		observations: emptyObservations(),
	};
}

function emptyObservations(): HouseholdMediaPhase0AcceptanceObservations {
	return {
		parentCount: 0,
		voiceDerivationCount: 0,
		documentDerivationCount: 0,
		confirmedActionCount: 0,
		executedActionCount: 0,
		namedPdfDeliveryCount: 0,
		deletionReceiptCount: 0,
		denialCount: 0,
		parentsIsolated: false,
		quarantineBounded: false,
		voiceConfidenceWeighted: false,
		documentStaticBounded: false,
		actionClassified: false,
		confirmationBoundOnce: false,
		freshTurnExecutionBound: false,
		namedPdfBound: false,
		denialsFailClosed: false,
		artifactSanitized: false,
		parentChainHashes: [ZERO_HASH, ZERO_HASH],
		namedPdfHashes: [ZERO_HASH, ZERO_HASH],
	};
}

type ScenarioParent = {
	readonly quarantine: QuarantineOwnerBinding;
	readonly confirmation: MediaConfirmationOwner;
	readonly addressRef: string;
};

function parent(suffix: "a" | "b"): ScenarioParent {
	const principal = `whatsapp:+1555000000${suffix === "a" ? "1" : "2"}`;
	const bindingId = `parent-${suffix}`;
	const conversationId = `whatsapp:household:${bindingId}`;
	return {
		quarantine: {
			actorId: `household:whatsapp:${bindingId}`,
			subjectUserId: `household:${bindingId}`,
			bindingId,
			senderPrincipalId: principal,
			conversationId,
			conversationToken: `conversation-token-${suffix}`,
		},
		confirmation: {
			actorId: `household:whatsapp:${bindingId}`,
			subjectUserId: `household:${bindingId}`,
			profileId: bindingId,
			bindingId,
			conversationId,
			senderPrincipalHash: digest(principal),
		},
		addressRef: principal,
	};
}

function providerAction(suffix: "a" | "b"): MediaConsequentialAction {
	return {
		toolName: "tc_provider_prepare_write",
		params: {
			providerId: "clalit",
			service: "clalit",
			action: "prescription_renewal",
			params: { prescriptionRef: `synthetic-${suffix}` },
		},
	};
}

function preparedOutbound(
	index: number,
	parentFixture: ScenarioParent,
	mediaRef: PreparedOutbound["mediaRefs"][number],
): PreparedOutbound {
	return PreparedOutboundSchema.parse({
		schemaVersion: EdgeAdapterSchemaVersions.preparedOutbound,
		outboundRef: `edge-out:household-media-${index}`,
		channel: "whatsapp",
		resolvedDestination: {
			kind: "address",
			addressRef: parentFixture.addressRef,
			conversationId: parentFixture.quarantine.conversationToken,
		},
		finalRenderedBody: "",
		mediaRefs: [mediaRef],
		authorizingActor: {
			schemaVersion: EdgeAdapterSchemaVersions.actorRef,
			actorId: parentFixture.confirmation.actorId,
			channelIdentity: { channel: "whatsapp", principalId: parentFixture.addressRef },
			identityAssurance: "strong_link",
			scopes: [],
			revocation: { revoked: false },
		},
		edgePreparedHash: crypto.createHash("sha256").update(`prepared-${index}`).digest("hex"),
		policyResult: { decision: "allowed", reason: "confirmed exact media action" },
		approvalRequirement: { required: false },
		idempotencyKey: `edge-idem:household-media-${index}`,
		sideEffectLedgerRef: `edge-ledger:household-media-${index}`,
		createdAt: new Date(SCENARIO_NOW_MS).toISOString(),
		retryPolicy: { maxAttempts: 1, backoff: "none", deadLetterAfterAttempts: 1 },
	});
}

function sequence(prefix: string): () => string {
	let value = 0;
	return () => `${prefix}-${++value}`;
}

function throws(callback: () => unknown): boolean {
	try {
		callback();
		return false;
	} catch {
		return true;
	}
}

async function rejects(callback: () => Promise<unknown>): Promise<boolean> {
	try {
		await callback();
		return false;
	} catch {
		return true;
	}
}

function digest(value: string): `sha256:${string}` {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function duplicates(values: readonly string[]): string[] {
	const seen = new Set<string>();
	const duplicates = new Set<string>();
	for (const value of values) {
		if (seen.has(value)) duplicates.add(value);
		seen.add(value);
	}
	return [...duplicates];
}

function flatten(error: z.ZodError): string {
	return error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`).join("; ");
}
