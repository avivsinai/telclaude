import { getChildLogger } from "../logging.js";
import { recordEpisode, summarizeEpisode } from "./archive.js";
import { extractExplicitMemoryEntries } from "./extractor.js";
import { telegramMemorySource } from "./source.js";
import { createEntries } from "./store.js";

const logger = getChildLogger({ module: "telegram-memory-capture" });

export function captureTelegramTurnMemory(input: {
	chatId: string;
	sessionKey: string;
	sessionId: string;
	userText: string;
	assistantText: string;
	profileId?: string;
	createdAt?: number;
}): void {
	const chatId = input.chatId.trim();
	if (!chatId) return;
	const memorySource = telegramMemorySource(input.profileId);

	recordEpisode({
		source: memorySource,
		scopeKey: `tg:${chatId}`,
		chatId,
		sessionKey: input.sessionKey,
		sessionId: input.sessionId,
		userText: input.userText,
		assistantText: input.assistantText,
		summary: summarizeEpisode(input.userText, input.assistantText),
		createdAt: input.createdAt,
	});

	const extracted = extractExplicitMemoryEntries(input.userText, { chatId });
	for (const entry of extracted) {
		try {
			createEntries([entry], memorySource, input.createdAt ?? Date.now());
		} catch (error) {
			if (!String(error).includes("already exists")) {
				logger.warn({ error: String(error), entryId: entry.id }, "auto memory extraction failed");
			}
		}
	}
}
