import { buildRpcAuthHeaders } from "../agent/token-client.js";
import type { InternalAuthScope } from "../internal-auth.js";
import { getChildLogger } from "../logging.js";
import type { MemorySnapshotRequest, MemorySnapshotResponse } from "../memory/rpc.js";
import type { MemoryEntryInput } from "../memory/store.js";

const logger = getChildLogger({ module: "agent-memory-client" });

function getCapabilitiesUrl(): string {
	const url = process.env.TELCLAUDE_CAPABILITIES_URL;
	if (!url) {
		throw new Error("TELCLAUDE_CAPABILITIES_URL is not configured");
	}
	return url.replace(/\/+$/, "");
}

function resolveScope(explicit?: InternalAuthScope): InternalAuthScope {
	if (explicit) return explicit;
	// Check for asymmetric keys (new) or symmetric secret (legacy)
	const hasMoltbookPrivate = Boolean(process.env.MOLTBOOK_RPC_PRIVATE_KEY);
	const hasMoltbookPublic = Boolean(process.env.MOLTBOOK_RPC_PUBLIC_KEY);
	const hasMoltbookSecret = Boolean(process.env.MOLTBOOK_RPC_SECRET);
	const hasTelegram = Boolean(process.env.TELEGRAM_RPC_SECRET);
	// Moltbook scope if we have asymmetric keys or legacy secret (and no telegram)
	if ((hasMoltbookPrivate || hasMoltbookPublic || hasMoltbookSecret) && !hasTelegram) {
		return "moltbook";
	}
	return "telegram";
}

async function postJson<T>(path: string, body: unknown, scope?: InternalAuthScope): Promise<T> {
	const baseUrl = getCapabilitiesUrl();
	const payload = JSON.stringify(body);
	const effectiveScope = resolveScope(scope);
	const response = await fetch(`${baseUrl}${path}`, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			...buildRpcAuthHeaders("POST", path, payload, effectiveScope),
		},
		body: payload,
	});

	if (!response.ok) {
		const text = await response.text();
		let detail = text;
		try {
			const parsed = JSON.parse(text) as { error?: string };
			if (parsed?.error) {
				detail = parsed.error;
			}
		} catch {
			// ignore parse failures
		}
		logger.warn({ path, status: response.status, body: text }, "memory request failed");
		const suffix = detail ? ` - ${detail}` : "";
		throw new Error(`Memory request failed: ${response.status} ${response.statusText}${suffix}`);
	}

	return (await response.json()) as T;
}

export async function proposeMemory(
	entries: MemoryEntryInput[],
	options?: { userId?: string; scope?: InternalAuthScope },
): Promise<{ accepted: number }> {
	return postJson("/v1/memory.propose", { entries, userId: options?.userId }, options?.scope);
}

export async function fetchMemorySnapshot(
	request: MemorySnapshotRequest = {},
	options?: { scope?: InternalAuthScope },
): Promise<MemorySnapshotResponse> {
	return postJson("/v1/memory.snapshot", request, options?.scope);
}
