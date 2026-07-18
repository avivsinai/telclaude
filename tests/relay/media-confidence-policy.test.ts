import { describe, expect, it } from "vitest";
import {
	evaluateVoiceConfidenceV1,
	MEDIA_CONFIDENCE_POLICY_VERSION,
	NO_SPEECH_PROBABILITY_THRESHOLD,
	VOICE_CONFIDENCE_THRESHOLD,
} from "../../src/relay/media-confidence-policy.js";

describe("media_confidence_policy_v1", () => {
	it("pins the policy identifiers and thresholds", () => {
		expect(MEDIA_CONFIDENCE_POLICY_VERSION).toBe("media_confidence_policy_v1");
		expect(VOICE_CONFIDENCE_THRESHOLD).toBe(0.82);
		expect(NO_SPEECH_PROBABILITY_THRESHOLD).toBe(0.5);
	});

	it("computes duration-weighted exponential confidence", () => {
		const result = evaluateVoiceConfidenceV1({
			confidenceSource: "openai_whisper_verbose_segments_v1",
			language: "he",
			durationSeconds: 4,
			segments: [
				{ durationSeconds: 1, avgLogprob: Math.log(0.9), noSpeechProbability: 0.1 },
				{ durationSeconds: 3, avgLogprob: Math.log(0.8), noSpeechProbability: 0.1 },
			],
		});

		expect(result.confidence).toBeCloseTo(Math.exp((Math.log(0.9) + 3 * Math.log(0.8)) / 4));
		expect(result.lowConfidence).toBe(false);
		expect(result.reasonCodes).toEqual([]);
	});

	it("treats exactly 0.82 as sufficient and values immediately below it as low", () => {
		const atThreshold = evaluateVoiceConfidenceV1(voiceAtLogprob(Math.log(0.82)));
		const belowThreshold = evaluateVoiceConfidenceV1(voiceAtLogprob(Math.log(0.82) - 1e-9));

		expect(atThreshold.confidence).toBeCloseTo(0.82, 12);
		expect(atThreshold.reasonCodes).not.toContain("confidence_below_threshold");
		expect(belowThreshold.confidence).toBeLessThan(0.82);
		expect(belowThreshold.reasonCodes).toContain("confidence_below_threshold");
	});

	it("treats exactly 0.50 no-speech probability as low", () => {
		const below = evaluateVoiceConfidenceV1(voiceAtLogprob(Math.log(0.9), 0.499999));
		const at = evaluateVoiceConfidenceV1(voiceAtLogprob(Math.log(0.9), 0.5));

		expect(below.reasonCodes).not.toContain("no_speech_threshold");
		expect(at.reasonCodes).toContain("no_speech_threshold");
	});

	it.each([
		[
			"unavailable evidence",
			{ confidenceSource: "unavailable", language: "he" },
			"metrics_unavailable",
		],
		[
			"empty segments",
			{
				confidenceSource: "openai_whisper_verbose_segments_v1",
				language: "he",
				segments: [],
			},
			"metrics_malformed",
		],
		[
			"non-finite metrics",
			{
				confidenceSource: "openai_whisper_verbose_segments_v1",
				language: "he",
				segments: [{ durationSeconds: 1, avgLogprob: Number.NaN, noSpeechProbability: 0 }],
			},
			"metrics_malformed",
		],
		[
			"missing language",
			{
				confidenceSource: "openai_whisper_verbose_segments_v1",
				durationSeconds: 1,
				segments: [{ durationSeconds: 1, avgLogprob: Math.log(0.9), noSpeechProbability: 0.1 }],
			},
			"language_unsupported",
		],
		["unsupported language", voiceAtLogprob(Math.log(0.9), 0.1, "fr"), "language_unsupported"],
	] as const)("fails closed for %s", (_name, input, reason) => {
		const result = evaluateVoiceConfidenceV1(input);
		expect(result.lowConfidence).toBe(true);
		expect(result.reasonCodes).toContain(reason);
	});

	it("fails closed for truncation, resample error, and duration over the cap", () => {
		expect(
			evaluateVoiceConfidenceV1({ ...voiceAtLogprob(Math.log(0.9)), truncated: true }).reasonCodes,
		).toContain("transcript_truncated");
		expect(
			evaluateVoiceConfidenceV1({ ...voiceAtLogprob(Math.log(0.9)), resampleError: true })
				.reasonCodes,
		).toContain("resample_error");
		expect(
			evaluateVoiceConfidenceV1({ ...voiceAtLogprob(Math.log(0.9)), durationSeconds: 600.001 })
				.reasonCodes,
		).toContain("duration_exceeded");
	});
});

function voiceAtLogprob(
	avgLogprob: number,
	noSpeechProbability = 0.1,
	language: string | undefined = "en",
) {
	return {
		confidenceSource: "openai_whisper_verbose_segments_v1" as const,
		...(language === undefined ? {} : { language }),
		durationSeconds: 1,
		segments: [{ durationSeconds: 1, avgLogprob, noSpeechProbability }],
	};
}
