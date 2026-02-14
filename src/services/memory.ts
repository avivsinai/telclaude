/**
 * Memory service — dual-mode access layer.
 * Relay-side: reads/writes SQLite directly via store.ts + rpc.ts handlers.
 * Agent-side: routes through relay HTTP via memory-client.ts.
 */

import { fetchMemorySnapshot, proposeMemory, quarantineMemory } from "../agent/memory-client.js";
import { getChildLogger } from "../logging.js";
import {
	handleMemoryPropose,
	handleMemoryQuarantine,
	handleMemorySnapshot,
	type MemorySnapshotRequest,
	type MemorySnapshotResponse,
} from "../memory/rpc.js";
import type { MemoryEntryInput } from "../memory/store.js";
import type { MemoryEntry } from "../memory/types.js";

const logger = getChildLogger({ module: "memory-service" });

function isAgentSide(): boolean {
	return Boolean(process.env.TELCLAUDE_CAPABILITIES_URL);
}

/**
 * Read memory entries. Dual-mode: agent routes through relay, relay reads SQLite directly.
 */
export async function readMemory(query?: MemorySnapshotRequest): Promise<MemorySnapshotResponse> {
	if (isAgentSide()) {
		logger.debug("routing memory read through relay");
		return fetchMemorySnapshot(query ?? {});
	}

	const result = handleMemorySnapshot(query ?? {});
	if (!result.ok) {
		throw new Error(result.error);
	}
	return result.value;
}

/**
 * Write memory entries. Dual-mode: agent routes through relay, relay writes SQLite directly.
 */
export async function writeMemory(
	entries: MemoryEntryInput[],
	options?: { userId?: string; chatId?: string },
): Promise<{ accepted: number }> {
	if (isAgentSide()) {
		logger.debug("routing memory write through relay");
		return proposeMemory(entries, options);
	}

	const result = handleMemoryPropose(
		{ entries, userId: options?.userId, chatId: options?.chatId },
		{ source: "telegram", userId: options?.userId },
	);
	if (!result.ok) {
		throw new Error(result.error);
	}
	return result.value;
}

/**
 * Quarantine a post idea. Dual-mode: agent routes through relay, relay writes SQLite directly.
 */
export async function quarantineIdea(
	id: string,
	content: string,
	options?: { userId?: string; chatId?: string },
): Promise<{ entry: MemoryEntry }> {
	if (isAgentSide()) {
		logger.debug("routing memory quarantine through relay");
		return quarantineMemory(id, content, options);
	}

	const result = handleMemoryQuarantine(
		{ id, content, userId: options?.userId, chatId: options?.chatId },
		{ source: "telegram", userId: options?.userId },
	);
	if (!result.ok) {
		throw new Error(result.error);
	}
	return result.value;
}
