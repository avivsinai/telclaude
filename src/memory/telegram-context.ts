import { buildTelegramMemoryBundle } from "./telegram-memory.js";

/**
 * Backward-compatible thin wrapper around the richer telegram memory bundle.
 */
export function buildTelegramMemoryContext(
	chatId?: string,
	query?: string,
	profileId?: string,
): string | null {
	return buildTelegramMemoryBundle({
		chatId,
		query,
		profileId,
		includeRecentHistory: true,
	}).promptContext;
}
