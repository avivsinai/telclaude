/**
 * Text-to-speech service using OpenAI TTS API.
 * Generates speech audio from text for voice message responses.
 */

import { spawn } from "node:child_process";
import fs from "node:fs";

import { loadConfig, type TTSConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { saveMediaBuffer } from "../media/store.js";
import { relayTextToSpeech } from "../relay/capabilities-client.js";
import { getMultimediaRateLimiter } from "./multimedia-rate-limit.js";
import { getOpenAIClient, isOpenAIConfigured, isOpenAIConfiguredSync } from "./openai-client.js";

const logger = getChildLogger({ module: "tts" });

/**
 * Convert audio buffer to OGG/Opus format using ffmpeg.
 * This format is required for proper Telegram voice message display (waveform).
 *
 * @param inputBuffer - Input audio buffer (any format ffmpeg supports)
 * @returns OGG/Opus encoded buffer
 */
async function convertToOggOpus(inputBuffer: Buffer): Promise<Buffer> {
	return new Promise((resolve, reject) => {
		const ffmpeg = spawn("ffmpeg", [
			"-i",
			"pipe:0", // Read from stdin
			"-c:a",
			"libopus", // Opus codec
			"-b:a",
			"32k", // 32kbps - good for voice, keeps file small
			"-ar",
			"48000", // 48kHz sample rate (Opus standard)
			"-ac",
			"1", // Mono (required for Telegram voice)
			"-f",
			"ogg", // OGG container
			"pipe:1", // Write to stdout
		]);

		const chunks: Buffer[] = [];
		let stderr = "";

		ffmpeg.stdout.on("data", (chunk: Buffer) => {
			chunks.push(chunk);
		});

		ffmpeg.stderr.on("data", (data: Buffer) => {
			stderr += data.toString();
		});

		ffmpeg.on("close", (code) => {
			if (code === 0) {
				resolve(Buffer.concat(chunks));
			} else {
				reject(new Error(`ffmpeg exited with code ${code}: ${stderr}`));
			}
		});

		ffmpeg.on("error", (err) => {
			reject(new Error(`ffmpeg spawn error: ${err.message}`));
		});

		// Write input buffer to ffmpeg stdin
		ffmpeg.stdin.write(inputBuffer);
		ffmpeg.stdin.end();
	});
}

/**
 * TTS generation options.
 */
export type TTSOptions = {
	/** Voice to use. Default: alloy */
	voice?: "alloy" | "echo" | "fable" | "onyx" | "nova" | "shimmer";
	/** Speech speed (0.25 to 4.0). Default: 1.0 */
	speed?: number;
	/** Output format. Default: mp3 */
	responseFormat?: "mp3" | "opus" | "aac" | "flac" | "wav" | "pcm";
	/** Model to use. Default: tts-1 */
	model?: "tts-1" | "tts-1-hd";
	/** User ID for rate limiting (chat_id or local_user_id) */
	userId?: string;
	/** Skip internal rate limiting checks (relay handles this). */
	skipRateLimit?: boolean;
	/**
	 * Output as Telegram voice message format (OGG/Opus).
	 * When true, converts output to OGG container with Opus codec,
	 * which displays as a voice message waveform in Telegram.
	 */
	voiceMessage?: boolean;
};

/**
 * Generated speech result.
 */
export type GeneratedSpeech = {
	/** Local file path to the saved audio */
	path: string;
	/** Audio format */
	format: string;
	/** Audio size in bytes */
	sizeBytes: number;
	/** Voice used */
	voice: string;
	/** Speed used */
	speed: number;
	/** Duration estimate in seconds (based on text length) */
	estimatedDurationSeconds: number;
};

/**
 * Default TTS config.
 */
const DEFAULT_CONFIG: TTSConfig = {
	provider: "openai",
	voice: "alloy",
	speed: 1.0,
	autoReadResponses: false,
	maxPerHourPerUser: 30,
	maxPerDayPerUser: 100,
};

/**
 * Generate speech from text.
 *
 * @param text - Text to convert to speech
 * @param options - TTS options (include userId for rate limiting)
 * @returns Generated audio with local path and metadata
 * @throws Error if rate limited or generation fails
 */
export async function textToSpeech(text: string, options?: TTSOptions): Promise<GeneratedSpeech> {
	// Route through relay when running on agent container
	if (process.env.TELCLAUDE_CAPABILITIES_URL) {
		const voice = options?.voice ?? "alloy";
		const speed = options?.speed ?? 1.0;
		const voiceMessage = options?.voiceMessage ?? false;
		const userId = options?.userId;
		logger.debug({ textLength: text.length, userId }, "routing TTS through relay");
		const result = await relayTextToSpeech({ text, voice, speed, voiceMessage, userId });
		const wordCount = text.split(/\s+/).length;
		const estimatedDurationSeconds = (wordCount / (150 * speed)) * 60;
		return {
			path: result.path,
			format: result.format,
			sizeBytes: result.bytes,
			voice: result.voice,
			speed: result.speed,
			estimatedDurationSeconds,
		};
	}

	if (!(await isOpenAIConfigured())) {
		throw new Error("OpenAI API key not configured for text-to-speech");
	}

	const config = loadConfig();
	const ttsConfig = {
		...DEFAULT_CONFIG,
		...config.tts,
	};

	if (ttsConfig.provider === "disabled") {
		throw new Error("Text-to-speech is disabled in config");
	}

	// Currently only OpenAI is implemented
	if (ttsConfig.provider !== "openai") {
		throw new Error(
			`TTS provider '${ttsConfig.provider}' is not yet implemented. Only 'openai' is currently supported.`,
		);
	}

	// Rate limiting check (if userId provided)
	const userId = options?.userId;
	if (userId && !options?.skipRateLimit) {
		const rateLimiter = getMultimediaRateLimiter();
		const rateLimitConfig = {
			maxPerHourPerUser: ttsConfig.maxPerHourPerUser,
			maxPerDayPerUser: ttsConfig.maxPerDayPerUser,
		};
		const limitResult = rateLimiter.checkLimit("tts", userId, rateLimitConfig);

		if (!limitResult.allowed) {
			logger.warn({ userId, remaining: limitResult.remaining }, "TTS rate limited");
			throw new Error(limitResult.reason ?? "Text-to-speech rate limit exceeded");
		}
	}

	const client = await getOpenAIClient();
	const voice = options?.voice ?? ttsConfig.voice ?? "alloy";
	const speed = options?.speed ?? ttsConfig.speed ?? 1.0;
	const model = options?.model ?? "tts-1";
	const voiceMessage = options?.voiceMessage ?? false;

	// For voice messages, we'll get opus from OpenAI and convert to OGG container
	// For regular audio, use the requested format
	const responseFormat = voiceMessage ? "opus" : (options?.responseFormat ?? "mp3");

	// Truncate very long text (OpenAI has a 4096 character limit)
	const maxLength = 4096;
	const truncatedText = text.length > maxLength ? text.slice(0, maxLength) : text;

	logger.info(
		{
			textLength: truncatedText.length,
			voice,
			speed,
			model,
			voiceMessage,
		},
		"generating speech",
	);

	const startTime = Date.now();

	try {
		const response = await client.audio.speech.create({
			model,
			voice,
			input: truncatedText,
			speed,
			response_format: responseFormat,
		});

		const durationMs = Date.now() - startTime;

		// Convert response to buffer
		const arrayBuffer = await response.arrayBuffer();
		let buffer = Buffer.from(arrayBuffer);

		// For voice messages, convert to OGG/Opus format for proper Telegram display
		let finalFormat: string = responseFormat;
		let finalMimeType = `audio/${responseFormat === "mp3" ? "mpeg" : responseFormat}`;

		if (voiceMessage) {
			logger.debug("converting to OGG/Opus for Telegram voice message");
			buffer = Buffer.from(await convertToOggOpus(buffer));
			finalFormat = "ogg";
			finalMimeType = "audio/ogg";
		}

		// Save using centralized media store
		// Use "voice" category for voice messages so media detection can identify them
		const saved = await saveMediaBuffer(buffer, {
			mimeType: finalMimeType,
			category: voiceMessage ? "voice" : "tts",
			extension: `.${finalFormat}`,
		});

		const stat = await fs.promises.stat(saved.path);

		// Estimate duration based on text length and speed
		// Average speaking rate is ~150 words per minute, ~5 chars per word
		const wordsPerMinute = 150 * speed;
		const wordCount = truncatedText.split(/\s+/).length;
		const estimatedDurationSeconds = (wordCount / wordsPerMinute) * 60;

		logger.info(
			{
				voice,
				speed,
				model,
				voiceMessage,
				format: finalFormat,
				durationMs,
				sizeBytes: stat.size,
				estimatedDurationSeconds,
			},
			"speech generated successfully",
		);

		// Consume rate limit point after successful generation
		if (userId && !options?.skipRateLimit) {
			const rateLimiter = getMultimediaRateLimiter();
			rateLimiter.consume("tts", userId);
		}

		return {
			path: saved.path,
			format: finalFormat,
			sizeBytes: stat.size,
			voice,
			speed,
			estimatedDurationSeconds,
		};
	} catch (error) {
		logger.error({ textLength: truncatedText.length, error }, "speech generation failed");
		throw error;
	}
}

/**
 * Check if TTS is available.
 * Uses sync check for env/config; keychain key will be found at runtime.
 */
export function isTTSAvailable(): boolean {
	// Available via relay when TELCLAUDE_CAPABILITIES_URL is set
	if (process.env.TELCLAUDE_CAPABILITIES_URL) {
		return Boolean(
			process.env.TELEGRAM_RPC_PUBLIC_KEY ??
				process.env.TELEGRAM_RPC_PRIVATE_KEY ??
				process.env.TELCLAUDE_SESSION_TOKEN,
		);
	}

	const config = loadConfig();

	if (config.tts?.provider === "disabled") {
		return false;
	}

	return isOpenAIConfiguredSync();
}

/**
 * Get estimated cost for TTS generation.
 * Based on OpenAI TTS pricing (December 2025).
 */
export function getEstimatedTTSCost(
	textLength: number,
	model: "tts-1" | "tts-1-hd" = "tts-1",
): number {
	// OpenAI charges per 1000 characters
	// tts-1: $0.015 per 1000 chars
	// tts-1-hd: $0.030 per 1000 chars
	const pricePerKChars = model === "tts-1-hd" ? 0.03 : 0.015;
	return (textLength / 1000) * pricePerKChars;
}
