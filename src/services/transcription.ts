/**
 * Audio transcription service.
 * Supports OpenAI Whisper API and CLI command fallback.
 */

import { spawn } from "node:child_process";
import fs from "node:fs";

import { type TranscriptionConfig, loadConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { getOpenAIClient, isOpenAIConfigured, isOpenAIConfiguredSync } from "./openai-client.js";

const logger = getChildLogger({ module: "transcription" });

/**
 * Transcription result.
 */
export type TranscriptionResult = {
	text: string;
	language?: string;
	durationSeconds?: number;
};

/**
 * Default transcription config.
 */
const DEFAULT_CONFIG: TranscriptionConfig = {
	provider: "openai",
	model: "whisper-1",
	timeoutSeconds: 60,
};

/**
 * Transcribe audio file to text.
 *
 * @param filePath - Path to audio file (supports mp3, mp4, mpeg, mpga, m4a, wav, webm, ogg)
 * @param options - Optional config overrides
 * @returns Transcription result
 */
export async function transcribeAudio(
	filePath: string,
	options?: Partial<TranscriptionConfig>,
): Promise<TranscriptionResult> {
	const config = loadConfig();
	const transcriptionConfig = {
		...DEFAULT_CONFIG,
		...config.transcription,
		...options,
	};

	logger.debug({ filePath, provider: transcriptionConfig.provider }, "starting transcription");

	// Verify file exists
	try {
		await fs.promises.access(filePath, fs.constants.R_OK);
	} catch {
		throw new Error(`Audio file not found or not readable: ${filePath}`);
	}

	switch (transcriptionConfig.provider) {
		case "openai":
			return transcribeWithOpenAI(filePath, transcriptionConfig);
		case "command":
			return transcribeWithCommand(filePath, transcriptionConfig);
		case "deepgram":
			// Deepgram integration can be added later
			throw new Error("Deepgram transcription not yet implemented");
		default:
			throw new Error(`Unknown transcription provider: ${transcriptionConfig.provider}`);
	}
}

/**
 * Transcribe using OpenAI Whisper API.
 */
async function transcribeWithOpenAI(
	filePath: string,
	config: TranscriptionConfig,
): Promise<TranscriptionResult> {
	if (!(await isOpenAIConfigured())) {
		throw new Error("OpenAI API key not configured for transcription");
	}

	const client = await getOpenAIClient();
	const fileStream = fs.createReadStream(filePath);

	const startTime = Date.now();

	try {
		const response = await client.audio.transcriptions.create({
			file: fileStream,
			model: config.model ?? "whisper-1",
			language: config.language,
			response_format: "verbose_json",
		});

		const durationMs = Date.now() - startTime;
		logger.info(
			{
				filePath,
				model: config.model,
				durationMs,
				textLength: response.text.length,
				language: response.language,
			},
			"transcription complete",
		);

		return {
			text: response.text,
			language: response.language,
			durationSeconds: response.duration,
		};
	} catch (error) {
		logger.error({ filePath, error }, "OpenAI transcription failed");
		throw error;
	} finally {
		fileStream.destroy();
	}
}

/**
 * Transcribe using a CLI command (like clawdis approach).
 * Command should output plain text to stdout.
 */
async function transcribeWithCommand(
	filePath: string,
	config: TranscriptionConfig,
): Promise<TranscriptionResult> {
	if (!config.command?.length) {
		throw new Error("No transcription command configured");
	}

	// Replace {{file}} placeholder in command
	const command = config.command.map((arg) => arg.replace("{{file}}", filePath));
	const [cmd, ...args] = command;

	const timeoutMs = (config.timeoutSeconds ?? 60) * 1000;

	return new Promise((resolve, reject) => {
		let settled = false;
		let timeoutId: ReturnType<typeof setTimeout> | null = null;

		const proc = spawn(cmd, args, {
			stdio: ["ignore", "pipe", "pipe"],
		});

		let stdout = "";
		let stderr = "";

		proc.stdout.on("data", (data) => {
			stdout += data.toString();
		});

		proc.stderr.on("data", (data) => {
			stderr += data.toString();
		});

		proc.on("error", (error) => {
			if (settled) return;
			settled = true;
			if (timeoutId) clearTimeout(timeoutId);
			logger.error({ command, error }, "transcription command failed to start");
			reject(new Error(`Transcription command failed: ${error.message}`));
		});

		proc.on("close", (code) => {
			if (settled) return;
			settled = true;
			if (timeoutId) clearTimeout(timeoutId);

			if (code === 0) {
				const text = stdout.trim();
				logger.info({ command: cmd, textLength: text.length }, "command transcription complete");
				resolve({ text });
			} else {
				logger.error({ command, code, stderr }, "transcription command exited with error");
				reject(new Error(`Transcription command failed with code ${code}: ${stderr}`));
			}
		});

		// Handle timeout manually (spawn's timeout option doesn't reject the promise)
		timeoutId = setTimeout(() => {
			if (settled) return;
			settled = true;
			proc.kill("SIGTERM");
			reject(new Error(`Transcription command timed out after ${config.timeoutSeconds}s`));
		}, timeoutMs);
	});
}

/**
 * Check if transcription is available.
 * Uses sync check for env/config; keychain key will be found at runtime.
 */
export function isTranscriptionAvailable(): boolean {
	const config = loadConfig();
	const provider = config.transcription?.provider ?? "openai";

	switch (provider) {
		case "openai":
			// Use sync check for quick availability; actual key from keychain is checked at call time
			return isOpenAIConfiguredSync();
		case "command":
			return !!config.transcription?.command?.length;
		case "deepgram":
			return false; // Not yet implemented
		default:
			return false;
	}
}

/**
 * Get supported audio formats for transcription.
 */
export function getSupportedAudioFormats(): string[] {
	return ["mp3", "mp4", "mpeg", "mpga", "m4a", "wav", "webm", "ogg"];
}

/**
 * Check if a MIME type is supported for transcription.
 */
export function isTranscribableMime(mime?: string): boolean {
	if (!mime) return false;
	const supported = [
		"audio/mpeg",
		"audio/mp3",
		"audio/mp4",
		"audio/m4a",
		"audio/wav",
		"audio/x-wav",
		"audio/webm",
		"audio/ogg",
		"video/mp4", // Can extract audio from video
		"video/webm",
	];
	return supported.includes(mime);
}
