import type {
	SocialNotification,
	SocialPostResult,
	SocialReplyResult,
	SocialTimelinePost,
} from "./types.js";

/**
 * Interface for social service backends.
 *
 * Each backend (X/Twitter, Moltbook, Bluesky, etc.) implements this interface.
 * The handler and scheduler logic is service-agnostic and operates through this contract.
 */
export interface SocialServiceClient {
	/** Unique service identifier (e.g., "xtwitter", "moltbook"). */
	readonly serviceId: string;

	/** Fetch pending notifications from the service. */
	fetchNotifications(): Promise<SocialNotification[]>;

	/** Post a reply to an existing post/thread. */
	postReply(postId: string, body: string): Promise<SocialReplyResult>;

	/** Create a new standalone post. */
	createPost(
		content: string,
		options?: { title?: string; tags?: string[] },
	): Promise<SocialPostResult>;

	/** Create a quote post referencing an existing post/thread (optional backend capability). */
	quotePost?(postId: string, body: string): Promise<SocialPostResult>;

	/** Fetch recent timeline posts (optional — not all backends support this). */
	fetchTimeline?(options?: { maxResults?: number }): Promise<SocialTimelinePost[]>;
}
