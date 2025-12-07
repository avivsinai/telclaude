import type { Message, User } from "grammy/types";
import type { MediaType } from "../types/media.js";

/**
 * Telegram chat identifier - can be user_id, group chat_id, or channel chat_id
 */
export type TelegramChatId = number | string;

/**
 * Media types supported by Telegram.
 * Alias for the provider-agnostic MediaType.
 */
export type TelegramMediaType = MediaType;

/**
 * Media payload for outbound messages
 */
export type TelegramMediaPayload =
	| { type: "photo"; source: Buffer | string; caption?: string }
	| { type: "document"; source: Buffer | string; filename?: string; caption?: string }
	| { type: "voice"; source: Buffer | string; caption?: string }
	| { type: "video"; source: Buffer | string; caption?: string }
	| { type: "audio"; source: Buffer | string; caption?: string; title?: string; performer?: string }
	| { type: "sticker"; source: Buffer | string }
	| { type: "animation"; source: Buffer | string; caption?: string };

/**
 * Unified inbound message format
 */
export type TelegramInboundMessage = {
	id: string;
	chatId: number;
	senderId?: number; // User ID of the sender (distinct from chatId in groups)
	from: string; // Normalized sender ID (tg:123456)
	to: string; // Bot's ID
	body: string; // Text content or caption
	pushName?: string; // User's display name
	username?: string; // @username if available
	chatType?: "private" | "group" | "supergroup" | "channel"; // Chat type for security checks
	timestamp?: number; // Unix timestamp in ms
	isEdited?: boolean;
	editedTimestamp?: number;
	replyToMessageId?: number;

	// Media info (if present)
	mediaPath?: string;
	mediaType?: TelegramMediaType;
	mediaFilePath?: string;
	mediaFileId?: string;
	mimeType?: string;

	// Callbacks for responding
	sendComposing: () => Promise<void>;
	/** Reply to the message. Uses plain text by default for safety.
	 *  Set useMarkdown: true only for trusted system messages. */
	reply: (text: string, options?: { useMarkdown?: boolean }) => Promise<void>;
	sendMedia: (payload: TelegramMediaPayload) => Promise<void>;

	// Raw message for advanced use
	raw?: Message;
};

/**
 * Close reason for the listener
 */
export type TelegramListenerCloseReason = {
	status?: number;
	isTokenRevoked: boolean;
	error?: unknown;
};

/**
 * Connection state
 */
export type TelegramConnectionState = {
	connected: boolean;
	botInfo?: {
		id: number;
		firstName: string;
		username?: string;
	};
	lastPollAt?: number;
	updatesProcessed: number;
};

/**
 * Bot info type
 */
export type BotInfo = {
	id: number;
	is_bot: boolean;
	first_name: string;
	username?: string;
	can_join_groups?: boolean;
	can_read_all_group_messages?: boolean;
	supports_inline_queries?: boolean;
};

/**
 * Build display name from Telegram user info
 */
export function buildPushName(user: User): string {
	const parts = [user.first_name];
	if (user.last_name) parts.push(user.last_name);
	return parts.join(" ");
}

/**
 * Media info extracted from a message
 */
export type MediaInfo = {
	fileId: string;
	type: TelegramMediaType;
	mimeType: string;
};

/**
 * Extract all media info from a message in a single pass.
 */
export function getMediaInfo(message: Message): MediaInfo | undefined {
	if (message.photo?.length) {
		return {
			fileId: message.photo[message.photo.length - 1].file_id,
			type: "photo",
			mimeType: "image/jpeg",
		};
	}
	if (message.document) {
		return {
			fileId: message.document.file_id,
			type: "document",
			mimeType: message.document.mime_type ?? "application/octet-stream",
		};
	}
	if (message.voice) {
		return {
			fileId: message.voice.file_id,
			type: "voice",
			mimeType: message.voice.mime_type ?? "audio/ogg",
		};
	}
	if (message.audio) {
		return {
			fileId: message.audio.file_id,
			type: "audio",
			mimeType: message.audio.mime_type ?? "audio/mpeg",
		};
	}
	if (message.video) {
		return {
			fileId: message.video.file_id,
			type: "video",
			mimeType: message.video.mime_type ?? "video/mp4",
		};
	}
	if (message.sticker) {
		return {
			fileId: message.sticker.file_id,
			type: "sticker",
			mimeType: "image/webp",
		};
	}
	if (message.animation) {
		return {
			fileId: message.animation.file_id,
			type: "animation",
			mimeType: message.animation.mime_type ?? "video/mp4",
		};
	}
	if (message.video_note) {
		return {
			fileId: message.video_note.file_id,
			type: "video",
			mimeType: "video/mp4",
		};
	}
	return undefined;
}

/**
 * Get file ID from various message types
 */
export function getFileIdFromMessage(message: Message): string | undefined {
	return getMediaInfo(message)?.fileId;
}

/**
 * Get media type from message
 */
export function getMediaTypeFromMessage(message: Message): TelegramMediaType | undefined {
	return getMediaInfo(message)?.type;
}

/**
 * Get MIME type from message
 */
export function getMimeTypeFromMessage(message: Message): string | undefined {
	return getMediaInfo(message)?.mimeType;
}
