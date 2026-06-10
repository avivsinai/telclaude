/**
 * Memory service — relay-local access layer.
 */

import { loadConfig } from "../config/config.js";
import { getOperatorProfile } from "../config/profiles.js";
import { getChatActiveProfileId } from "../config/sessions.js";
import {
	handleMemoryPropose,
	handleMemoryQuarantine,
	handleMemorySnapshot,
	type MemorySnapshotRequest,
	type MemorySnapshotResponse,
} from "../memory/rpc.js";
import { telegramMemorySource } from "../memory/source.js";
import type { MemoryEntryInput } from "../memory/store.js";
import type { MemoryEntry, MemorySource } from "../memory/types.js";

export function resolveLocalTelegramMemoryProfileId(chatId?: string): string {
	if (!chatId || !/^-?\d+$/.test(chatId.trim())) {
		return "default";
	}
	const numericChatId = Number(chatId.trim());
	if (!Number.isSafeInteger(numericChatId)) {
		return "default";
	}
	const activeProfileId = getChatActiveProfileId(numericChatId);
	if (!activeProfileId) {
		return "default";
	}
	const profile = getOperatorProfile(activeProfileId, loadConfig());
	if (!profile) {
		throw new Error(`unknown-profile-id: ${activeProfileId}`);
	}
	return profile.id;
}

function resolveLocalTelegramMemorySource(chatId?: string): MemorySource {
	return telegramMemorySource(resolveLocalTelegramMemoryProfileId(chatId));
}

/** Read memory entries from the relay-local SQLite store. */
export async function readMemory(query?: MemorySnapshotRequest): Promise<MemorySnapshotResponse> {
	const effectiveQuery =
		query?.chatId && !query.sources?.length && !query.sourceFamilies?.length
			? {
					...query,
					sources: [resolveLocalTelegramMemorySource(query.chatId)],
					sourceFamilies: undefined,
				}
			: (query ?? {});
	const result = handleMemorySnapshot(effectiveQuery);
	if (!result.ok) {
		throw new Error(result.error);
	}
	return result.value;
}

/** Write memory entries to the relay-local SQLite store. */
export async function writeMemory(
	entries: MemoryEntryInput[],
	options?: { userId?: string; chatId?: string },
): Promise<{ accepted: number }> {
	const result = handleMemoryPropose(
		{ entries, userId: options?.userId, chatId: options?.chatId },
		{ source: resolveLocalTelegramMemorySource(options?.chatId), userId: options?.userId },
	);
	if (!result.ok) {
		throw new Error(result.error);
	}
	return result.value;
}

/** Quarantine a post idea in the relay-local SQLite store. */
export async function quarantineIdea(
	id: string,
	content: string,
	options?: { userId?: string; chatId?: string },
): Promise<{ entry: MemoryEntry }> {
	const result = handleMemoryQuarantine(
		{ id, content, userId: options?.userId, chatId: options?.chatId },
		{ source: resolveLocalTelegramMemorySource(options?.chatId), userId: options?.userId },
	);
	if (!result.ok) {
		throw new Error(result.error);
	}
	return result.value;
}
