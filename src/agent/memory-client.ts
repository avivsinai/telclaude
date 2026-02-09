import { buildRpcAuthHeaders } from "../agent/token-client.js";
import type { InternalAuthScope } from "../internal-auth.js";
import { getChildLogger } from "../logging.js";
import type { MemorySnapshotRequest, MemorySnapshotResponse } from "../memory/rpc.js";
import type { MemoryEntryInput } from "../memory/store.js";
import type { MemoryEntry } from "../memory/types.js";

const logger = getChildLogger({ module: "agent-memory-client" });

function getCapabilitiesUrl(): string {
	const url = process.env.TELCLAUDE_CAPABILITIES_URL;
	if (!url) {
		throw new Error("TELCLAUDE_CAPABILITIES_URL is not configured");
	}
	return url.replace(/\/+$/, "");
}

/**
 * Resolve the agent's auth scope from environment variables.
 *
 * M1 fix: Check TELCLAUDE_INTERNAL_AUTH_SCOPE first for explicit override.
 * Fail closed if both secrets are present and no explicit scope is set.
 */
function resolveScope(explicit?: InternalAuthScope): InternalAuthScope {
	if (explicit) return explicit;

	// M1: Explicit scope env var takes precedence
	const explicitScope = process.env.TELCLAUDE_INTERNAL_AUTH_SCOPE;
	if (explicitScope === "telegram" || explicitScope === "moltbook") {
		return explicitScope;
	}

	const hasMoltbook =
		Boolean(process.env.MOLTBOOK_RPC_AGENT_PRIVATE_KEY) ||
		Boolean(process.env.MOLTBOOK_RPC_RELAY_PRIVATE_KEY) ||
		Boolean(process.env.MOLTBOOK_RPC_AGENT_PUBLIC_KEY) ||
		Boolean(process.env.MOLTBOOK_RPC_RELAY_PUBLIC_KEY);
	const hasTelegram =
		Boolean(process.env.TELEGRAM_RPC_AGENT_PRIVATE_KEY) ||
		Boolean(process.env.TELEGRAM_RPC_RELAY_PRIVATE_KEY) ||
		Boolean(process.env.TELEGRAM_RPC_AGENT_PUBLIC_KEY) ||
		Boolean(process.env.TELEGRAM_RPC_RELAY_PUBLIC_KEY);

	// M1: Fail closed if both scopes have credentials — ambiguous
	if (hasMoltbook && hasTelegram) {
		throw new Error(
			"Ambiguous auth scope: both TELEGRAM_RPC_* and MOLTBOOK_RPC_* are set without TELCLAUDE_INTERNAL_AUTH_SCOPE. Set TELCLAUDE_INTERNAL_AUTH_SCOPE=telegram or TELCLAUDE_INTERNAL_AUTH_SCOPE=moltbook explicitly.",
		);
	}

	if (hasMoltbook && !hasTelegram) {
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
	options?: { userId?: string; chatId?: string; scope?: InternalAuthScope },
): Promise<{ accepted: number }> {
	return postJson(
		"/v1/memory.propose",
		{ entries, userId: options?.userId, chatId: options?.chatId },
		options?.scope,
	);
}

export async function fetchMemorySnapshot(
	request: MemorySnapshotRequest = {},
	options?: { scope?: InternalAuthScope },
): Promise<MemorySnapshotResponse> {
	return postJson("/v1/memory.snapshot", request, options?.scope);
}

export async function quarantineMemory(
	id: string,
	content: string,
	options?: { userId?: string; chatId?: string; scope?: InternalAuthScope },
): Promise<{ entry: MemoryEntry }> {
	return postJson(
		"/v1/memory.quarantine",
		{ id, content, userId: options?.userId, chatId: options?.chatId },
		options?.scope,
	);
}
