import type { SocialServiceConfig } from "../config/config.js";
import { createMoltbookClient } from "./backends/moltbook.js";
import { createXTwitterClient } from "./backends/xtwitter.js";
import type { SocialServiceClient } from "./client.js";

export type { SocialServiceClient } from "./client.js";
export { handleSocialHeartbeat, handleSocialNotification, queryPublicPersona } from "./handler.js";
export { type SocialScheduler, startSocialScheduler } from "./scheduler.js";
export type {
	SocialHandlerResult,
	SocialHeartbeatPayload,
	SocialNotification,
	SocialPostResult,
	SocialPromptBundle,
	SocialReplyResult,
} from "./types.js";

/**
 * Factory: create a SocialServiceClient from config.
 * Dispatches by the `type` field to the appropriate backend.
 *
 * Returns null if the backend type is unknown or credentials are missing.
 */
export async function createSocialClient(
	config: SocialServiceConfig,
): Promise<SocialServiceClient | null> {
	switch (config.type) {
		case "moltbook":
			return createMoltbookClient(config);
		case "xtwitter":
			return createXTwitterClient(config);
		default:
			return null;
	}
}
