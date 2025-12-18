/**
 * Multimodal message handling for Telegram → Claude.
 *
 * Claude can read images and documents via the Read tool.
 * Audio/video require transcription (not yet implemented).
 */

import type { TelegramMediaType } from "./types.js";

export type MultimodalContext = {
	body: string;
	mediaPath?: string;
	mediaType?: TelegramMediaType;
	mimeType?: string;
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
 * Build a prompt that includes multimodal context.
 *
 * If the user sends media without text, this creates a prompt describing the media.
 * If the user sends media with text, this augments the text with media context.
 */
export function buildMultimodalPrompt(ctx: MultimodalContext): string {
	const { body, mediaPath, mediaType, mimeType } = ctx;
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
	const mediaInstruction = getMediaInstruction(mediaType, mimeType, mediaPath);

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

	// Audio/voice - can't process directly yet
	if (AUDIO_MEDIA_TYPES.includes(mediaType)) {
		return `Audio file saved at: ${mediaPath}\nNote: I cannot directly listen to audio. If you need the content transcribed, please describe what you'd like me to help with.`;
	}

	// Video - can't process directly yet
	if (VIDEO_MEDIA_TYPES.includes(mediaType)) {
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
