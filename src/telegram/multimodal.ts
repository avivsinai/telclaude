/**
 * Multimodal message handling for Telegram → Claude.
 *
 * Claude can read images and documents via the Read tool.
 * Audio/voice messages are transcribed via OpenAI Whisper.
 * Video is processed via frame extraction + audio transcription.
 */

import { getChildLogger } from "../logging.js";
import { isTranscriptionAvailable, transcribeAudio } from "../services/transcription.js";
import { isVideoProcessingAvailable, processVideo } from "../services/video-processor.js";
import type { TelegramMediaType } from "./types.js";

const logger = getChildLogger({ module: "multimodal" });

export type MultimodalContext = {
	body: string;
	mediaPath?: string;
	mediaType?: TelegramMediaType;
	mimeType?: string;
	/** Pre-computed transcript (if already transcribed) */
	transcript?: string;
	/** Extracted video frame paths (if video processed) */
	framePaths?: string[];
};

/**
 * Media types that require transcription/conversion (not directly readable).
 */
const AUDIO_MEDIA_TYPES: TelegramMediaType[] = ["voice", "audio"];
const VIDEO_MEDIA_TYPES: TelegramMediaType[] = ["video", "animation"];

/**
 * Image MIME types that Claude can view.
 */
const IMAGE_MIME_TYPES = ["image/jpeg", "image/png", "image/gif", "image/webp", "image/svg+xml"];

/**
 * Document MIME types that Claude can read as text.
 */
const TEXT_DOCUMENT_MIME_TYPES = [
	"text/plain",
	"text/markdown",
	"text/csv",
	"text/html",
	"text/css",
	"text/javascript",
	"application/json",
	"application/xml",
	"application/javascript",
];

/**
 * Process media context and transcribe audio if needed.
 * Call this before buildMultimodalPrompt to handle async transcription.
 *
 * @param ctx - Multimodal context with media info
 * @returns Context with transcript populated if audio was transcribed
 */
export async function processMultimodalContext(ctx: MultimodalContext): Promise<MultimodalContext> {
	const { mediaPath, mediaType, transcript, framePaths } = ctx;

	// Skip if no media or already processed
	if (!mediaPath || !mediaType) {
		return ctx;
	}

	// Check if this is transcribable audio/voice
	if (AUDIO_MEDIA_TYPES.includes(mediaType) && !transcript && isTranscriptionAvailable()) {
		try {
			logger.info({ mediaPath, mediaType }, "transcribing audio");
			const result = await transcribeAudio(mediaPath);

			logger.info(
				{
					mediaPath,
					textLength: result.text.length,
					language: result.language,
					durationSeconds: result.durationSeconds,
				},
				"audio transcribed successfully",
			);

			return {
				...ctx,
				transcript: result.text,
			};
		} catch (error) {
			logger.error({ mediaPath, error }, "audio transcription failed");
			// Continue without transcript - will fall back to "cannot listen" message
		}
	}

	// Check if this is a video that needs processing
	if (
		VIDEO_MEDIA_TYPES.includes(mediaType) &&
		!framePaths &&
		(await isVideoProcessingAvailable())
	) {
		try {
			logger.info({ mediaPath, mediaType }, "processing video");
			const result = await processVideo(mediaPath);

			logger.info(
				{
					mediaPath,
					frameCount: result.framePaths.length,
					hasTranscript: !!result.transcript,
					durationSeconds: result.durationSeconds,
				},
				"video processed successfully",
			);

			return {
				...ctx,
				framePaths: result.framePaths,
				transcript: result.transcript,
			};
		} catch (error) {
			logger.error({ mediaPath, error }, "video processing failed");
			// Continue without frames - will fall back to "cannot watch" message
		}
	}

	return ctx;
}

/**
 * Build a prompt that includes multimodal context.
 *
 * If the user sends media without text, this creates a prompt describing the media.
 * If the user sends media with text, this augments the text with media context.
 *
 * NOTE: Call processMultimodalContext first to transcribe audio.
 */
export function buildMultimodalPrompt(ctx: MultimodalContext): string {
	const { body, mediaPath, mediaType, mimeType, transcript, framePaths } = ctx;
	const trimmedBody = body.trim();

	// No media - just return the body (or a default if empty)
	if (!mediaPath || !mediaType) {
		if (!trimmedBody) {
			// Empty message with no media - shouldn't happen but handle gracefully
			return "Hello";
		}
		return trimmedBody;
	}

	// Has media - build appropriate prompt
	const mediaDescription = getMediaDescription(mediaType, mimeType);
	const mediaInstruction = getMediaInstruction(
		mediaType,
		mimeType,
		mediaPath,
		transcript,
		framePaths,
	);

	if (!trimmedBody) {
		// Media only, no text caption
		return `The user sent ${mediaDescription}.\n\n${mediaInstruction}`;
	}

	// Media with text caption
	return `${trimmedBody}\n\n[Attached: ${mediaDescription}]\n${mediaInstruction}`;
}

/**
 * Get a human-readable description of the media type.
 */
function getMediaDescription(mediaType: TelegramMediaType, mimeType?: string): string {
	switch (mediaType) {
		case "photo":
			return "an image";
		case "document":
			if (mimeType) {
				if (IMAGE_MIME_TYPES.includes(mimeType)) {
					return "an image file";
				}
				if (mimeType === "application/pdf") {
					return "a PDF document";
				}
				if (TEXT_DOCUMENT_MIME_TYPES.includes(mimeType)) {
					return "a text document";
				}
			}
			return "a document";
		case "voice":
			return "a voice message";
		case "audio":
			return "an audio file";
		case "video":
			return "a video";
		case "animation":
			return "an animated GIF/video";
		case "sticker":
			return "a sticker";
		default:
			return "a file";
	}
}

/**
 * Get instructions for Claude on how to handle the media.
 */
function getMediaInstruction(
	mediaType: TelegramMediaType,
	mimeType: string | undefined,
	mediaPath: string,
	transcript?: string,
	framePaths?: string[],
): string {
	// Images - Claude can view directly
	if (mediaType === "photo" || (mimeType && IMAGE_MIME_TYPES.includes(mimeType))) {
		return `To view this image, use the Read tool on: ${mediaPath}`;
	}

	// Text documents - Claude can read directly
	if (mimeType && TEXT_DOCUMENT_MIME_TYPES.includes(mimeType)) {
		return `To read this document, use the Read tool on: ${mediaPath}`;
	}

	// PDF - Claude can read
	if (mimeType === "application/pdf") {
		return `To read this PDF, use the Read tool on: ${mediaPath}`;
	}

	// Documents with unknown type - try to read
	if (mediaType === "document") {
		return `To view this file, try using the Read tool on: ${mediaPath}`;
	}

	// Audio/voice - show transcript if available
	if (AUDIO_MEDIA_TYPES.includes(mediaType)) {
		if (transcript) {
			return `[Voice/Audio Transcript]\n${transcript}`;
		}
		return `Audio file saved at: ${mediaPath}\nNote: I cannot directly listen to audio. If you need the content transcribed, please describe what you'd like me to help with.`;
	}

	// Video - show frames and/or transcript if available
	if (VIDEO_MEDIA_TYPES.includes(mediaType)) {
		const parts: string[] = [];

		// Add frame paths if available
		if (framePaths && framePaths.length > 0) {
			parts.push(`[Video Frames Extracted: ${framePaths.length} frames]`);
			parts.push("To analyze the video visually, use the Read tool on these frames:");
			parts.push(framePaths.map((fp, i) => `  Frame ${i + 1}: ${fp}`).join("\n"));
		}

		// Add transcript if available
		if (transcript) {
			parts.push(`[Video Audio Transcript]\n${transcript}`);
		}

		// If we have either frames or transcript, return them
		if (parts.length > 0) {
			return parts.join("\n\n");
		}

		// Fallback if no processing was done
		return `Video file saved at: ${mediaPath}\nNote: I cannot directly watch videos. If you need help with the video content, please describe what you'd like me to do.`;
	}

	// Fallback
	return `File saved at: ${mediaPath}`;
}

/**
 * Check if media type is directly viewable by Claude.
 */
export function isMediaViewable(mediaType?: TelegramMediaType, mimeType?: string): boolean {
	if (!mediaType) return false;

	if (mediaType === "photo") return true;
	if (mimeType && IMAGE_MIME_TYPES.includes(mimeType)) return true;
	if (mimeType && TEXT_DOCUMENT_MIME_TYPES.includes(mimeType)) return true;
	if (mimeType === "application/pdf") return true;

	return false;
}

/**
 * Check if media type requires transcription.
 */
export function requiresTranscription(mediaType?: TelegramMediaType): boolean {
	if (!mediaType) return false;
	return AUDIO_MEDIA_TYPES.includes(mediaType) || VIDEO_MEDIA_TYPES.includes(mediaType);
}
