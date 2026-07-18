import type { TranscriptionEvidenceSegment } from "../services/transcription.js";

export const MEDIA_CONFIDENCE_POLICY_VERSION = "media_confidence_policy_v1";
export const VOICE_CONFIDENCE_THRESHOLD = 0.82;
export const NO_SPEECH_PROBABILITY_THRESHOLD = 0.5;
export const VOICE_DURATION_CAP_SECONDS = 600;

export type VoiceLowConfidenceReasonCode =
	| "metrics_unavailable"
	| "metrics_malformed"
	| "confidence_below_threshold"
	| "no_speech_threshold"
	| "language_unsupported"
	| "transcript_truncated"
	| "resample_error"
	| "duration_exceeded";

export type VoiceConfidenceInput = {
	readonly confidenceSource: "openai_whisper_verbose_segments_v1" | "unavailable";
	readonly language?: string;
	readonly durationSeconds?: number;
	readonly segments?: readonly TranscriptionEvidenceSegment[];
	readonly truncated?: boolean;
	readonly resampleError?: boolean;
};

export type VoiceConfidencePolicyResult = {
	readonly policyVersion: typeof MEDIA_CONFIDENCE_POLICY_VERSION;
	readonly confidence?: number;
	readonly lowConfidence: boolean;
	readonly reasonCodes: readonly VoiceLowConfidenceReasonCode[];
};

export function evaluateVoiceConfidenceV1(
	input: VoiceConfidenceInput,
): VoiceConfidencePolicyResult {
	const reasons: VoiceLowConfidenceReasonCode[] = [];
	let confidence: number | undefined;

	if (input.confidenceSource === "unavailable") {
		reasons.push("metrics_unavailable");
	} else if (!validSegments(input.segments)) {
		reasons.push("metrics_malformed");
	} else {
		const duration = input.segments.reduce((sum, segment) => sum + segment.durationSeconds, 0);
		const weightedLogprob = input.segments.reduce(
			(sum, segment) => sum + segment.durationSeconds * segment.avgLogprob,
			0,
		);
		confidence = clamp(Math.exp(weightedLogprob / duration));
		if (confidence < VOICE_CONFIDENCE_THRESHOLD) reasons.push("confidence_below_threshold");
		if (
			input.segments.some(
				(segment) => segment.noSpeechProbability >= NO_SPEECH_PROBABILITY_THRESHOLD,
			)
		) {
			reasons.push("no_speech_threshold");
		}
	}

	if (!input.language || !["he", "en"].includes(input.language.trim().toLowerCase())) {
		reasons.push("language_unsupported");
	}
	if (input.truncated) reasons.push("transcript_truncated");
	if (input.resampleError) reasons.push("resample_error");
	if (
		input.durationSeconds !== undefined &&
		(!Number.isFinite(input.durationSeconds) ||
			input.durationSeconds < 0 ||
			input.durationSeconds > VOICE_DURATION_CAP_SECONDS)
	) {
		reasons.push("duration_exceeded");
	}

	return {
		policyVersion: MEDIA_CONFIDENCE_POLICY_VERSION,
		...(confidence === undefined ? {} : { confidence }),
		lowConfidence: reasons.length > 0,
		reasonCodes: reasons,
	};
}

function validSegments(
	segments: readonly TranscriptionEvidenceSegment[] | undefined,
): segments is readonly TranscriptionEvidenceSegment[] {
	return (
		Array.isArray(segments) &&
		segments.length > 0 &&
		segments.every(
			(segment) =>
				Number.isFinite(segment.durationSeconds) &&
				segment.durationSeconds > 0 &&
				Number.isFinite(segment.avgLogprob) &&
				Number.isFinite(segment.noSpeechProbability) &&
				segment.noSpeechProbability >= 0 &&
				segment.noSpeechProbability <= 1,
		)
	);
}

function clamp(value: number): number {
	return Math.max(0, Math.min(1, value));
}
