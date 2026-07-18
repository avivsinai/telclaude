import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import type { InboundEvent } from "../hermes/edge-adapter-contract.js";
import type { RelayConversation } from "../hermes/relay-conversation-store.js";
import { getChildLogger } from "../logging.js";
import { wrapExternalContent } from "../security/external-content.js";
import { type TranscriptionResult, transcribeAudio } from "../services/transcription.js";
import type {
	AttachmentProcessorCapability,
	AttachmentProcessorTempDirectory,
	AttachmentQuarantineStore,
	QuarantineOwnerBinding,
} from "./attachment-quarantine-store.js";
import {
	classifyDerivedMediaActionV1,
	type DERIVED_MEDIA_ACTION_CLASSIFIER_VERSION,
	type DerivedMediaActionReasonCode,
} from "./derived-media-action-classifier.js";
import {
	DOCUMENT_EXTRACTOR_ID,
	type DocumentMediaTypeV1,
	type DocumentUnderstandingAdapter,
} from "./document-understanding-adapter.js";
import {
	evaluateVoiceConfidenceV1,
	MEDIA_CONFIDENCE_POLICY_VERSION,
	VOICE_DURATION_CAP_SECONDS,
	type VoiceLowConfidenceReasonCode,
} from "./media-confidence-policy.js";
import type { WhatsAppIdentityResolution } from "./whatsapp-inbound-cl1.js";

const logger = getChildLogger({ module: "inbound-media-processor" });

export const DERIVED_MEDIA_MAX_SCALARS = 8_000;
export const DERIVED_MEDIA_MAX_DURATION_SECONDS = VOICE_DURATION_CAP_SECONDS;
export const VOICE_EXTRACTOR_ID = "ffmpeg_ogg_opus_wav16k_transcription_v1";
export const DOCUMENT_CONFIDENCE_SOURCE = "document_confidence_unavailable_v1";

export type DocumentLowConfidenceReasonCode = "document_confidence_unavailable";

export type DerivedVoiceEnvelopeV1 = {
	readonly kind: "voice_transcript";
	readonly text: string;
	readonly sourceSha256: string;
	readonly sourceMediaType: "audio/ogg";
	readonly sourceDurationSeconds?: number;
	readonly extractor: typeof VOICE_EXTRACTOR_ID;
	readonly confidenceSource: TranscriptionResult["confidenceSource"];
	readonly confidence?: number;
	readonly confirmed: false;
	readonly confidencePolicyVersion: typeof MEDIA_CONFIDENCE_POLICY_VERSION;
	readonly lowConfidence: boolean;
	readonly lowConfidenceReasonCodes: readonly VoiceLowConfidenceReasonCode[];
	readonly classifierVersion: typeof DERIVED_MEDIA_ACTION_CLASSIFIER_VERSION;
	readonly actionBearing: boolean;
	readonly actionBearingReasonCodes: readonly DerivedMediaActionReasonCode[];
};

export type DerivedDocumentEnvelopeV1 = {
	readonly kind: "document_extract";
	readonly text: string;
	readonly sourceSha256: string;
	readonly sourceMediaType: DocumentMediaTypeV1;
	readonly sourcePageCount: number;
	readonly extractor: typeof DOCUMENT_EXTRACTOR_ID;
	readonly confidenceSource: typeof DOCUMENT_CONFIDENCE_SOURCE;
	readonly confirmed: false;
	readonly confidencePolicyVersion: typeof MEDIA_CONFIDENCE_POLICY_VERSION;
	readonly lowConfidence: true;
	readonly lowConfidenceReasonCodes: readonly DocumentLowConfidenceReasonCode[];
	readonly classifierVersion: typeof DERIVED_MEDIA_ACTION_CLASSIFIER_VERSION;
	readonly actionBearing: boolean;
	readonly actionBearingReasonCodes: readonly DerivedMediaActionReasonCode[];
};

export type DerivedMediaEnvelopeV1 = DerivedVoiceEnvelopeV1 | DerivedDocumentEnvelopeV1;

export type InboundMediaProcessingInput = {
	readonly event: InboundEvent;
	readonly identity: WhatsAppIdentityResolution;
	readonly conversation: RelayConversation;
};

export type VoiceFfmpegInvocation = {
	readonly command: "ffmpeg";
	readonly args: readonly string[];
	readonly options: {
		readonly shell: false;
		readonly stdio: ["ignore", "ignore", "pipe"];
	};
};

export type InboundMediaProcessor = {
	processVoice(input: {
		readonly ref: InboundEvent["normalized"]["mediaRefs"][number];
		readonly owner: QuarantineOwnerBinding;
	}): Promise<DerivedVoiceEnvelopeV1>;
	processDocument(input: {
		readonly ref: InboundEvent["normalized"]["mediaRefs"][number];
		readonly owner: QuarantineOwnerBinding;
	}): Promise<DerivedDocumentEnvelopeV1>;
	processInbound(input: InboundMediaProcessingInput): Promise<InboundEvent>;
	ownerFor(input: InboundMediaProcessingInput): QuarantineOwnerBinding;
};

export type InboundVoiceMediaProcessor = InboundMediaProcessor;

export type CreateInboundMediaProcessorOptions = {
	readonly quarantineStore: AttachmentQuarantineStore;
	readonly processorCapability: AttachmentProcessorCapability;
	readonly runFfmpeg?: (inputPath: string, outputPath: string) => Promise<void>;
	readonly transcribe?: (wavPath: string) => Promise<TranscriptionResult>;
	readonly documentAdapter?: DocumentUnderstandingAdapter;
};

export type CreateInboundVoiceMediaProcessorOptions = CreateInboundMediaProcessorOptions;

export function buildVoiceFfmpegInvocation(
	inputPath: string,
	outputPath: string,
): VoiceFfmpegInvocation {
	return {
		command: "ffmpeg",
		args: [
			"-nostdin",
			"-hide_banner",
			"-loglevel",
			"error",
			"-i",
			inputPath,
			"-vn",
			"-ac",
			"1",
			"-ar",
			"16000",
			"-c:a",
			"pcm_s16le",
			"-y",
			outputPath,
		],
		options: { shell: false, stdio: ["ignore", "ignore", "pipe"] },
	};
}

export function createInboundVoiceMediaProcessor(
	options: CreateInboundVoiceMediaProcessorOptions,
): InboundVoiceMediaProcessor {
	return createInboundMediaProcessor(options);
}

export function createInboundMediaProcessor(
	options: CreateInboundMediaProcessorOptions,
): InboundMediaProcessor {
	const runFfmpeg = options.runFfmpeg ?? runVoiceFfmpeg;
	const transcribe = options.transcribe ?? ((wavPath) => transcribeAudio(wavPath));

	function ownerFor(input: InboundMediaProcessingInput): QuarantineOwnerBinding {
		if (input.identity.domain !== "household") {
			throw new Error("voice_media_household_only");
		}
		return {
			actorId: input.identity.actorId,
			subjectUserId: input.identity.subjectUserId,
			bindingId: input.identity.bindingId,
			senderPrincipalId: input.identity.principalId,
			conversationId: input.conversation.conversationId,
			conversationToken: input.conversation.token,
		};
	}

	async function processVoice(input: {
		readonly ref: InboundEvent["normalized"]["mediaRefs"][number];
		readonly owner: QuarantineOwnerBinding;
	}): Promise<DerivedVoiceEnvelopeV1> {
		if (input.ref.mediaType !== "audio/ogg") {
			options.quarantineStore.deleteForOwner(input.ref.quarantineId, input.owner);
			throw new Error("voice_media_type_unsupported");
		}
		const lease = options.quarantineStore.leaseForProcessing(
			input.ref.quarantineId,
			input.owner,
			options.processorCapability,
		);
		if (lease?.mediaType !== "audio/ogg") {
			options.quarantineStore.deleteForOwner(input.ref.quarantineId, input.owner);
			throw new Error("voice_media_not_clean_or_owner_mismatch");
		}
		if (!containsOpusHead(lease.bytes)) {
			options.quarantineStore.deleteForOwner(lease.quarantineId, input.owner);
			throw new Error("voice_media_codec_unsupported");
		}
		let workspace: AttachmentProcessorTempDirectory | null;
		try {
			workspace = options.quarantineStore.createProcessorTempDirectory(options.processorCapability);
		} catch {
			options.quarantineStore.deleteForOwner(lease.quarantineId, input.owner);
			throw new Error("voice_media_workspace_failed");
		}
		if (!workspace) {
			options.quarantineStore.deleteForOwner(lease.quarantineId, input.owner);
			throw new Error("voice_media_workspace_denied");
		}
		const workDir = workspace.directoryPath;
		const inputPath = path.join(workDir, "source");
		const outputPath = path.join(workDir, "derived");
		let processingCompleted = false;
		let phase: "conversion" | "transcription" | "envelope" = "conversion";

		try {
			fs.writeFileSync(inputPath, lease.bytes, { flag: "wx", mode: 0o600 });
			await runFfmpeg(inputPath, outputPath);
			phase = "transcription";
			const transcription = await transcribe(outputPath);
			phase = "envelope";
			const bounded = boundScalars(transcription.text, DERIVED_MEDIA_MAX_SCALARS);
			const confidence = evaluateVoiceConfidenceV1({
				confidenceSource: transcription.confidenceSource,
				language: transcription.language,
				durationSeconds: transcription.durationSeconds,
				segments: transcription.segments,
				truncated: bounded.truncated,
			});
			const classification = classifyDerivedMediaActionV1(bounded.text, transcription.language, {
				truncated: bounded.truncated,
			});
			const sourceDurationSeconds = boundedDuration(transcription.durationSeconds);
			const envelope: DerivedMediaEnvelopeV1 = {
				kind: "voice_transcript",
				text: bounded.text,
				sourceSha256: lease.contentHash.replace(/^sha256:/u, ""),
				sourceMediaType: "audio/ogg",
				...(sourceDurationSeconds === undefined ? {} : { sourceDurationSeconds }),
				extractor: VOICE_EXTRACTOR_ID,
				confidenceSource: transcription.confidenceSource,
				...(confidence.confidence === undefined ? {} : { confidence: confidence.confidence }),
				confirmed: false,
				confidencePolicyVersion: confidence.policyVersion,
				lowConfidence: confidence.lowConfidence,
				lowConfidenceReasonCodes: confidence.reasonCodes,
				classifierVersion: classification.classifierVersion,
				actionBearing: classification.actionBearing,
				actionBearingReasonCodes: classification.reasonCodes,
			};
			if (
				!options.quarantineStore.completeProcessing(lease, input.owner, options.processorCapability)
			) {
				throw new Error("voice_media_completion_failed");
			}
			processingCompleted = true;
			logger.info(
				{
					contentDigestPrefix: envelope.sourceSha256.slice(0, 12),
					durationBucket: durationBucket(transcription.durationSeconds),
					providerId: transcription.confidenceSource,
					resultLength: Array.from(envelope.text).length,
					reasonCode: envelope.lowConfidence ? "low_confidence" : "derived",
				},
				"voice attachment derived",
			);
			return envelope;
		} catch {
			logger.warn(
				{
					contentDigestPrefix: lease.contentHash.replace(/^sha256:/u, "").slice(0, 12),
					reasonCode: `voice_${phase}_failed`,
				},
				"voice attachment processing failed",
			);
			throw new Error(`voice_${phase}_failed`);
		} finally {
			if (!processingCompleted) {
				options.quarantineStore.deleteForOwner(lease.quarantineId, input.owner);
			}
			workspace.cleanup();
		}
	}

	async function processDocument(input: {
		readonly ref: InboundEvent["normalized"]["mediaRefs"][number];
		readonly owner: QuarantineOwnerBinding;
	}): Promise<DerivedDocumentEnvelopeV1> {
		const mediaType = asDocumentMediaType(input.ref.mediaType);
		if (!mediaType || !options.documentAdapter) {
			options.quarantineStore.deleteForOwner(input.ref.quarantineId, input.owner);
			throw new Error("document_media_type_unsupported");
		}
		const lease = options.quarantineStore.leaseForProcessing(
			input.ref.quarantineId,
			input.owner,
			options.processorCapability,
		);
		if (lease?.mediaType !== mediaType) {
			options.quarantineStore.deleteForOwner(input.ref.quarantineId, input.owner);
			throw new Error("document_media_not_clean_or_owner_mismatch");
		}
		let processingCompleted = false;
		let phase: "extraction" | "envelope" | "completion" = "extraction";
		try {
			const extraction = await options.documentAdapter.extract({
				bytes: lease.bytes,
				mediaType,
			});
			phase = "envelope";
			const bounded = boundScalars(extraction.text, DERIVED_MEDIA_MAX_SCALARS);
			if (bounded.truncated) throw new Error("document_output_exceeded");
			const classification = classifyDerivedMediaActionV1(bounded.text, undefined, {
				truncated: false,
			});
			const envelope: DerivedDocumentEnvelopeV1 = {
				kind: "document_extract",
				text: bounded.text,
				sourceSha256: lease.contentHash.replace(/^sha256:/u, ""),
				sourceMediaType: mediaType,
				sourcePageCount: extraction.pageCount,
				extractor: DOCUMENT_EXTRACTOR_ID,
				confidenceSource: DOCUMENT_CONFIDENCE_SOURCE,
				confirmed: false,
				confidencePolicyVersion: MEDIA_CONFIDENCE_POLICY_VERSION,
				lowConfidence: true,
				lowConfidenceReasonCodes: ["document_confidence_unavailable"],
				classifierVersion: classification.classifierVersion,
				actionBearing: classification.actionBearing,
				actionBearingReasonCodes: classification.reasonCodes,
			};
			phase = "completion";
			if (
				!options.quarantineStore.completeProcessing(lease, input.owner, options.processorCapability)
			) {
				throw new Error("document_media_completion_failed");
			}
			processingCompleted = true;
			logger.info(
				{
					contentDigestPrefix: envelope.sourceSha256.slice(0, 12),
					pageCountBucket: documentPageCountBucket(envelope.sourcePageCount),
					providerId: envelope.extractor,
					resultLength: Array.from(envelope.text).length,
					reasonCode: "low_confidence",
				},
				"document attachment derived",
			);
			return envelope;
		} catch {
			logger.warn(
				{
					contentDigestPrefix: lease.contentHash.replace(/^sha256:/u, "").slice(0, 12),
					reasonCode: `document_${phase}_failed`,
				},
				"document attachment processing failed",
			);
			throw new Error(`document_${phase}_failed`);
		} finally {
			if (!processingCompleted) {
				options.quarantineStore.deleteForOwner(lease.quarantineId, input.owner);
			}
		}
	}

	async function processInbound(input: InboundMediaProcessingInput): Promise<InboundEvent> {
		if (input.identity.domain !== "household") return input.event;
		const owner = ownerFor(input);
		const retainedRefs: InboundEvent["normalized"]["mediaRefs"][number][] = [];
		const envelopes: DerivedMediaEnvelopeV1[] = [];
		for (const ref of input.event.normalized.mediaRefs) {
			const isVoice = ref.mediaType === "audio/ogg";
			const isDocument = asDocumentMediaType(ref.mediaType) !== null;
			if (!isVoice && !isDocument) {
				retainedRefs.push(ref);
				continue;
			}
			if (isDocument && !options.documentAdapter) {
				options.quarantineStore.deleteForOwner(ref.quarantineId, owner);
				continue;
			}
			try {
				envelopes.push(
					isVoice ? await processVoice({ ref, owner }) : await processDocument({ ref, owner }),
				);
			} catch {
				// Media failure is terminal for the raw item but does not block ordinary conversation.
			}
		}
		if (envelopes.length === 0 && retainedRefs.length === input.event.normalized.mediaRefs.length) {
			return input.event;
		}
		const derivedText = envelopes
			.map((envelope) =>
				wrapExternalContent(envelope.text, {
					source: "user-forwarded",
					serviceId:
						envelope.kind === "voice_transcript"
							? "whatsapp-voice-transcript"
							: "whatsapp-document-extract",
					foldHomoglyphs: false,
					maxLength: DERIVED_MEDIA_MAX_SCALARS * 2,
				}),
			)
			.join("\n\n");
		const combinedText = joinText(input.event.normalized.text, derivedText);
		return {
			...input.event,
			normalized: {
				...(combinedText ? { text: combinedText } : {}),
				mediaRefs: retainedRefs,
			},
			riskLabels: [
				...input.event.riskLabels,
				...(envelopes.length > 0 ? ["media-derived-untrusted"] : []),
			],
		};
	}

	return { processVoice, processDocument, processInbound, ownerFor };
}

async function runVoiceFfmpeg(inputPath: string, outputPath: string): Promise<void> {
	const invocation = buildVoiceFfmpegInvocation(inputPath, outputPath);
	await new Promise<void>((resolve, reject) => {
		const child = spawn(invocation.command, [...invocation.args], {
			shell: false,
			stdio: ["ignore", "ignore", "pipe"],
		});
		child.stderr.on("data", () => {});
		child.once("error", () => reject(new Error("ffmpeg_spawn_failed")));
		child.once("close", (code) => {
			if (code === 0) resolve();
			else reject(new Error("ffmpeg_nonzero_exit"));
		});
	});
}

function boundScalars(
	text: string,
	maxScalars: number,
): { readonly text: string; truncated: boolean } {
	const scalars = Array.from(text);
	return scalars.length <= maxScalars
		? { text, truncated: false }
		: { text: scalars.slice(0, maxScalars).join(""), truncated: true };
}

function joinText(existing: string | undefined, derived: string): string {
	return [existing, derived].filter((value) => value && value.length > 0).join("\n\n");
}

function durationBucket(seconds: number | undefined): string {
	if (seconds === undefined) return "unknown";
	if (seconds < 30) return "lt_30s";
	if (seconds < 120) return "30s_2m";
	if (seconds <= DERIVED_MEDIA_MAX_DURATION_SECONDS) return "2m_10m";
	return "gt_10m";
}

function boundedDuration(seconds: number | undefined): number | undefined {
	if (seconds === undefined || !Number.isFinite(seconds) || seconds < 0) return undefined;
	return Math.min(seconds, DERIVED_MEDIA_MAX_DURATION_SECONDS);
}

function containsOpusHead(bytes: Uint8Array): boolean {
	const header = Buffer.from("OpusHead");
	return Buffer.from(bytes.subarray(0, 512)).includes(header);
}

function asDocumentMediaType(mediaType: string): DocumentMediaTypeV1 | null {
	return mediaType === "application/pdf" || mediaType === "image/jpeg" || mediaType === "image/png"
		? mediaType
		: null;
}

function documentPageCountBucket(pageCount: number): string {
	if (pageCount <= 1) return "1";
	if (pageCount <= 5) return "2_5";
	if (pageCount <= 10) return "6_10";
	return "11_20";
}
