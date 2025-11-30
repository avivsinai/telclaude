import type { Message, User } from "grammy/types";

/**
 * Telegram chat identifier - can be user_id, group chat_id, or channel chat_id
 */
export type TelegramChatId = number | string;

/**
 * Media types supported by Telegram
 */
export type TelegramMediaType =
	| "photo"
	| "document"
	| "voice"
	| "video"
	| "audio"
	| "sticker"
	| "animation";

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
	from: string; // Normalized sender ID (tg:123456)
	to: string; // Bot's ID
	body: string; // Text content or caption
	pushName?: string; // User's display name
	username?: string; // @username if available
	timestamp?: number; // Unix timestamp in ms
	isEdited?: boolean;
	editedTimestamp?: number;
	replyToMessageId?: number;

	// Media info (if present)
	mediaPath?: string;
	mediaType?: TelegramMediaType;
	mediaUrl?: string;
	mimeType?: string;

	// Callbacks for responding
	sendComposing: () => Promise<void>;
	reply: (text: string) => Promise<void>;
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
 * Get file ID from various message types
 */
export function getFileIdFromMessage(message: Message): string | undefined {
	if (message.photo?.length) {
		// Get the largest photo
		return message.photo[message.photo.length - 1].file_id;
	}
	if (message.document) return message.document.file_id;
	if (message.voice) return message.voice.file_id;
	if (message.audio) return message.audio.file_id;
	if (message.video) return message.video.file_id;
	if (message.sticker) return message.sticker.file_id;
	if (message.animation) return message.animation.file_id;
	if (message.video_note) return message.video_note.file_id;
	return undefined;
}

/**
 * Get media type from message
 */
export function getMediaTypeFromMessage(message: Message): TelegramMediaType | undefined {
	if (message.photo?.length) return "photo";
	if (message.document) return "document";
	if (message.voice) return "voice";
	if (message.audio) return "audio";
	if (message.video) return "video";
	if (message.sticker) return "sticker";
	if (message.animation) return "animation";
	return undefined;
}

/**
 * Get MIME type from message
 */
export function getMimeTypeFromMessage(message: Message): string | undefined {
	if (message.photo?.length) return "image/jpeg";
	if (message.document) return message.document.mime_type;
	if (message.voice) return message.voice.mime_type ?? "audio/ogg";
	if (message.audio) return message.audio.mime_type;
	if (message.video) return message.video.mime_type;
	if (message.sticker) return "image/webp";
	if (message.animation) return message.animation.mime_type ?? "video/mp4";
	return undefined;
}
