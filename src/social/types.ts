/**
 * Service-agnostic types for social backend integrations.
 *
 * These types abstract over specific backends (X/Twitter, Moltbook, Bluesky, etc.)
 * so the handler, scheduler, and context logic can work with any social service.
 */

export type SocialNotification = {
	id: string;
	type?: string;
	postId?: string;
	post?: {
		id?: string;
		content?: string;
		author?: { name?: string; handle?: string };
	};
	comment?: {
		id?: string;
		postId?: string;
		content?: string;
		author?: { name?: string; handle?: string };
	};
	actor?: { name?: string; handle?: string };
	message?: string;
	content?: string;
	createdAt?: string;
};

export type SocialReplyResult = {
	ok: boolean;
	status: number;
	error?: string;
	rateLimited?: boolean;
};

export type SocialPostResult = {
	ok: boolean;
	status: number;
	postId?: string;
	error?: string;
	rateLimited?: boolean;
};

export type SocialTimelinePost = {
	id: string;
	text: string;
	authorName?: string;
	authorHandle?: string;
	createdAt?: string;
	metrics?: { likes?: number; retweets?: number; replies?: number };
};

export type SocialHeartbeatPayload = {
	serviceId?: string;
	timestamp?: number;
	eventId?: string;
};

export type SocialHandlerResult = {
	ok: boolean;
	message?: string;
};

export type SocialPromptBundle = {
	prompt: string;
	systemPromptAppend: string;
};
