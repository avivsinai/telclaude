/**
 * CLI command for text-to-speech generation.
 * Used by Claude via the text-to-speech skill.
 */

import type { Command } from "commander";
import { getChildLogger } from "../logging.js";
import { relayTextToSpeech } from "../relay/capabilities-client.js";
import { initializeOpenAIKey } from "../services/openai-client.js";
import { getEstimatedTTSCost, isTTSAvailable, textToSpeech } from "../services/tts.js";

const logger = getChildLogger({ module: "cmd-tts" });

export type TextToSpeechOptions = {
	voice?: "alloy" | "echo" | "fable" | "onyx" | "nova" | "shimmer";
	speed?: string;
	model?: "tts-1" | "tts-1-hd";
	format?: "mp3" | "opus" | "aac" | "flac" | "wav";
	voiceMessage?: boolean;
	verbose?: boolean;
	userId?: string;
};

export function registerTextToSpeechCommand(program: Command): void {
	program
		.command("text-to-speech")
		.alias("tts")
		.description("Convert text to speech using OpenAI TTS API")
		.argument("<text>", "Text to convert to speech")
		.option("-v, --voice <voice>", "Voice: alloy, echo, fable, onyx, nova, shimmer", "alloy")
		.option("-s, --speed <speed>", "Speed: 0.25 to 4.0", "1.0")
		.option("-m, --model <model>", "Model: tts-1, tts-1-hd", "tts-1")
		.option("-f, --format <format>", "Format: mp3, opus, aac, flac, wav", "mp3")
		.option("--voice-message", "Output as Telegram voice message (OGG/Opus with waveform)")
		.option("--user-id <id>", "User ID for rate limiting (optional)")
		.action(async (text: string, opts: TextToSpeechOptions) => {
			const verbose = program.opts().verbose || opts.verbose;

			try {
				const useRelay = Boolean(process.env.TELCLAUDE_CAPABILITIES_URL);
				const voice = validateVoice(opts.voice);
				const speed = validateSpeed(opts.speed);
				const model = validateModel(opts.model);
				const format = validateFormat(opts.format);
				const voiceMessage = opts.voiceMessage ?? false;
				const requestUserId = opts.userId ?? process.env.TELCLAUDE_REQUEST_USER_ID;

				if (useRelay) {
					const result = await relayTextToSpeech({
						text,
						voice,
						speed,
						voiceMessage,
						userId: requestUserId,
					});

					console.log(`Generated audio saved to: ${result.path}`);
					console.log(`Size: ${(result.bytes / 1024).toFixed(1)} KB`);
					console.log(`Format: ${result.format}`);
					console.log(`Voice: ${result.voice}`);
					return;
				}

				// Initialize keychain lookup so isTTSAvailable() works correctly
				await initializeOpenAIKey();

				if (!isTTSAvailable()) {
					console.error(
						"Error: Text-to-speech not available.\n" +
							"Run: telclaude setup-openai\n" +
							"Or set OPENAI_API_KEY environment variable.",
					);
					process.exit(1);
				}

				if (verbose) {
					const cost = getEstimatedTTSCost(text.length, model);
					console.log(`Generating speech with ${voice} voice at ${speed}x speed...`);
					console.log(`Estimated cost: $${cost.toFixed(4)}`);
					if (voiceMessage) {
						console.log("Output: Telegram voice message (OGG/Opus)");
					}
				}

				const result = await textToSpeech(text, {
					voice,
					speed,
					model,
					responseFormat: format,
					voiceMessage,
					userId: requestUserId,
				});

				// Output in a format that's easy to parse
				console.log(`Generated audio saved to: ${result.path}`);
				console.log(`Size: ${(result.sizeBytes / 1024).toFixed(1)} KB`);
				console.log(`Format: ${result.format}`);
				console.log(`Voice: ${result.voice}`);
				console.log(`Estimated duration: ${result.estimatedDurationSeconds.toFixed(1)}s`);
			} catch (err) {
				logger.error({ error: String(err) }, "text-to-speech command failed");
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exit(1);
			}
		});
}

function validateVoice(voice?: string): "alloy" | "echo" | "fable" | "onyx" | "nova" | "shimmer" {
	const valid = ["alloy", "echo", "fable", "onyx", "nova", "shimmer"];
	if (voice && valid.includes(voice)) {
		return voice as "alloy" | "echo" | "fable" | "onyx" | "nova" | "shimmer";
	}
	return "alloy";
}

function validateSpeed(speed?: string): number {
	const parsed = Number.parseFloat(speed ?? "1.0");
	if (Number.isNaN(parsed) || parsed < 0.25 || parsed > 4.0) {
		return 1.0;
	}
	return parsed;
}

function validateModel(model?: string): "tts-1" | "tts-1-hd" {
	if (model === "tts-1-hd") {
		return "tts-1-hd";
	}
	return "tts-1";
}

function validateFormat(format?: string): "mp3" | "opus" | "aac" | "flac" | "wav" {
	const valid = ["mp3", "opus", "aac", "flac", "wav"];
	if (format && valid.includes(format)) {
		return format as "mp3" | "opus" | "aac" | "flac" | "wav";
	}
	return "mp3";
}
