/**
 * Provider-agnostic media types.
 *
 * These types are used across the security and storage layers,
 * independent of the specific messaging provider (Telegram, etc.).
 */

/**
 * Supported media types for message attachments.
 */
export type MediaType =
	| "photo"
	| "document"
	| "voice"
	| "video"
	| "audio"
	| "sticker"
	| "animation";
