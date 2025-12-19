/**
 * Video processing service.
 * Extracts frames and audio from video files for multimodal analysis.
 */

import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { type VideoProcessingConfig, loadConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { cleanupOldMedia, createMediaSubdir } from "../media/store.js";
import { isTranscriptionAvailable, transcribeAudio } from "./transcription.js";

const logger = getChildLogger({ module: "video-processor" });

/**
 * Video processing options.
 */
export type VideoProcessingOptions = {
	/** Seconds between frame extractions. Default: 1 */
	frameInterval?: number;
	/** Maximum frames to extract. Default: 30 */
	maxFrames?: number;
	/** Maximum video duration to process in seconds. Default: 300 */
	maxDurationSeconds?: number;
	/** Whether to extract and transcribe audio. Default: true */
	extractAudio?: boolean;
};

/**
 * Processed video result.
 */
export type ProcessedVideo = {
	/** Paths to extracted frame images */
	framePaths: string[];
	/** Audio transcript if extracted */
	transcript?: string;
	/** Detected language from audio */
	language?: string;
	/** Video duration in seconds */
	durationSeconds?: number;
	/** Video hash for deduplication */
	hash: string;
};

/**
 * Default video processing config.
 */
const DEFAULT_CONFIG: VideoProcessingConfig = {
	enabled: true,
	frameInterval: 1,
	maxFrames: 30,
	maxDurationSeconds: 300,
	extractAudio: true,
};

/**
 * Check if FFmpeg is available.
 */
export async function isFFmpegAvailable(): Promise<boolean> {
	return new Promise((resolve) => {
		const proc = spawn("ffmpeg", ["-version"], {
			stdio: ["ignore", "ignore", "ignore"],
		});
		proc.on("error", () => resolve(false));
		proc.on("close", (code) => resolve(code === 0));
	});
}

/**
 * Process a video file - extract frames and optionally transcribe audio.
 *
 * @param videoPath - Path to the video file
 * @param options - Processing options
 * @returns Processed video with frame paths and transcript
 */
export async function processVideo(
	videoPath: string,
	options?: VideoProcessingOptions,
): Promise<ProcessedVideo> {
	const config = loadConfig();
	const videoConfig = {
		...DEFAULT_CONFIG,
		...config.videoProcessing,
		...options,
	};

	if (!videoConfig.enabled) {
		throw new Error("Video processing is disabled in config");
	}

	// Verify video file exists
	try {
		await fs.promises.access(videoPath, fs.constants.R_OK);
	} catch {
		throw new Error(`Video file not found or not readable: ${videoPath}`);
	}

	// Check FFmpeg availability
	if (!(await isFFmpegAvailable())) {
		throw new Error("FFmpeg not available. Install ffmpeg to process videos.");
	}

	// Create unique output directory based on video hash
	const videoBuffer = await fs.promises.readFile(videoPath);
	const hash = crypto.createHash("sha256").update(videoBuffer).digest("hex").slice(0, 16);
	const outputDir = await createMediaSubdir("video-frames", hash);

	logger.info({ videoPath, hash, outputDir }, "processing video");

	try {
		// Get video duration
		const duration = await getVideoDuration(videoPath);
		const effectiveDuration = Math.min(duration, videoConfig.maxDurationSeconds ?? 300);

		logger.debug({ duration, effectiveDuration }, "video duration");

		// Calculate frame extraction params
		const frameInterval = videoConfig.frameInterval ?? 1;
		const maxFrames = videoConfig.maxFrames ?? 30;
		const totalPossibleFrames = Math.floor(effectiveDuration / frameInterval);
		const framesToExtract = Math.min(totalPossibleFrames, maxFrames);

		// Extract frames
		const framePaths = await extractFrames(
			videoPath,
			outputDir,
			frameInterval,
			framesToExtract,
			effectiveDuration,
		);

		logger.info({ frameCount: framePaths.length, hash }, "frames extracted");

		// Extract and transcribe audio if enabled
		let transcript: string | undefined;
		let language: string | undefined;

		if (videoConfig.extractAudio && isTranscriptionAvailable()) {
			try {
				const audioPath = path.join(outputDir, "audio.mp3");
				await extractAudio(videoPath, audioPath, effectiveDuration);

				const transcription = await transcribeAudio(audioPath);
				transcript = transcription.text;
				language = transcription.language;

				logger.info({ transcriptLength: transcript.length, language }, "audio transcribed");

				// Clean up audio file
				await fs.promises.unlink(audioPath).catch(() => {});
			} catch (error) {
				logger.warn(
					{ error },
					"audio extraction/transcription failed, continuing with frames only",
				);
			}
		}

		return {
			framePaths,
			transcript,
			language,
			durationSeconds: effectiveDuration,
			hash,
		};
	} catch (error) {
		// Clean up on error
		await fs.promises.rm(outputDir, { recursive: true, force: true }).catch(() => {});
		throw error;
	}
}

/**
 * Get video duration using FFprobe.
 */
async function getVideoDuration(videoPath: string): Promise<number> {
	return new Promise((resolve, reject) => {
		const proc = spawn("ffprobe", [
			"-v",
			"error",
			"-show_entries",
			"format=duration",
			"-of",
			"default=noprint_wrappers=1:nokey=1",
			videoPath,
		]);

		let stdout = "";
		let stderr = "";

		proc.stdout.on("data", (data) => {
			stdout += data.toString();
		});
		proc.stderr.on("data", (data) => {
			stderr += data.toString();
		});

		proc.on("error", (error) => {
			reject(new Error(`FFprobe failed: ${error.message}`));
		});

		proc.on("close", (code) => {
			if (code === 0) {
				const duration = Number.parseFloat(stdout.trim());
				if (Number.isNaN(duration)) {
					reject(new Error("Could not parse video duration"));
				} else {
					resolve(duration);
				}
			} else {
				reject(new Error(`FFprobe failed with code ${code}: ${stderr}`));
			}
		});
	});
}

/**
 * Extract frames from video at specified intervals.
 */
async function extractFrames(
	videoPath: string,
	outputDir: string,
	interval: number,
	maxFrames: number,
	maxDuration: number,
): Promise<string[]> {
	return new Promise((resolve, reject) => {
		const outputPattern = path.join(outputDir, "frame_%04d.jpg");

		// FFmpeg command to extract frames at interval
		const args = [
			"-i",
			videoPath,
			"-vf",
			`fps=1/${interval}`,
			"-frames:v",
			String(maxFrames),
			"-t",
			String(maxDuration),
			"-q:v",
			"3", // JPEG quality (2-31, lower is better)
			outputPattern,
		];

		const proc = spawn("ffmpeg", args, {
			stdio: ["ignore", "pipe", "pipe"],
		});

		let stderr = "";
		proc.stderr.on("data", (data) => {
			stderr += data.toString();
		});

		proc.on("error", (error) => {
			reject(new Error(`FFmpeg failed: ${error.message}`));
		});

		proc.on("close", async (code) => {
			if (code === 0) {
				// List extracted frames
				try {
					const files = await fs.promises.readdir(outputDir);
					const framePaths = files
						.filter((f) => f.startsWith("frame_") && f.endsWith(".jpg"))
						.sort()
						.map((f) => path.join(outputDir, f));
					resolve(framePaths);
				} catch (error) {
					reject(error);
				}
			} else {
				reject(new Error(`FFmpeg failed with code ${code}: ${stderr}`));
			}
		});
	});
}

/**
 * Extract audio track from video.
 */
async function extractAudio(
	videoPath: string,
	audioPath: string,
	maxDuration: number,
): Promise<void> {
	return new Promise((resolve, reject) => {
		const args = [
			"-i",
			videoPath,
			"-vn", // No video
			"-t",
			String(maxDuration),
			"-acodec",
			"libmp3lame",
			"-ab",
			"128k",
			"-ar",
			"44100",
			"-y", // Overwrite output
			audioPath,
		];

		const proc = spawn("ffmpeg", args, {
			stdio: ["ignore", "pipe", "pipe"],
		});

		let stderr = "";
		proc.stderr.on("data", (data) => {
			stderr += data.toString();
		});

		proc.on("error", (error) => {
			reject(new Error(`FFmpeg audio extraction failed: ${error.message}`));
		});

		proc.on("close", (code) => {
			if (code === 0) {
				resolve();
			} else {
				reject(new Error(`FFmpeg audio extraction failed with code ${code}: ${stderr}`));
			}
		});
	});
}

/**
 * Check if video processing is available.
 */
export async function isVideoProcessingAvailable(): Promise<boolean> {
	const config = loadConfig();
	if (config.videoProcessing?.enabled === false) {
		return false;
	}
	return isFFmpegAvailable();
}

/**
 * Clean up old extracted frames.
 * Delegates to centralized media cleanup.
 */
export async function cleanupVideoFrames(maxAgeMs: number = 24 * 60 * 60 * 1000): Promise<number> {
	return cleanupOldMedia(maxAgeMs, "video-frames");
}
