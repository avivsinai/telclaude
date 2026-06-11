import crypto from "node:crypto";
import {
	isSocialMemorySource,
	isTelegramMemorySource,
	telegramMemorySource,
	validateMemorySource,
} from "../../memory/source.js";
import type { MemorySource } from "../../memory/types.js";
import { isRelayConversationTurnRef } from "../relay-conversation-store.js";
import {
	createTelclaudeMcpBridge,
	type TelclaudeMcpAuthority,
	type TelclaudeMcpBridge,
	type TelclaudeMcpBridgeDependencies,
	type TelclaudeMcpDomain,
} from "./bridge.js";

export const TELCLAUDE_MCP_AUTHORITY_HEADER = "X-Telclaude-MCP-Authority";
export const TELCLAUDE_MCP_AUTHORITY_SESSION_KEY_HEADER = "X-Telclaude-MCP-Session-Key";
export const TELCLAUDE_MCP_AUTHORITY_PROFILE_HEADER = "X-Telclaude-MCP-Profile";
export const TELCLAUDE_MCP_AUTHORITY_ENDPOINT_HEADER = "X-Telclaude-MCP-Endpoint";
export const TELCLAUDE_MCP_AUTHORITY_NETWORK_NAMESPACE_HEADER = "X-Telclaude-MCP-Network-Namespace";
export const DEFAULT_MCP_AUTHORITY_TTL_MS = 15 * 60 * 1_000;

export type TelclaudeMcpAuthorityConnection = {
	readonly sessionKey: string;
	readonly profileId: string;
	readonly endpointId: string;
	readonly networkNamespace: string;
};

export type TelclaudeMcpAuthorityGrant = {
	readonly handle: string;
	readonly issuedAtMs: number;
	readonly expiresAtMs: number;
};

export type TelclaudeMcpAuthorityFailure = {
	readonly ok: false;
	readonly code: string;
	readonly reason: string;
	readonly retryable: false;
};

export type TelclaudeMcpAuthorityResolveResult =
	| {
			readonly ok: true;
			readonly authority: TelclaudeMcpAuthority;
			readonly issuedAtMs: number;
			readonly expiresAtMs: number;
	  }
	| TelclaudeMcpAuthorityFailure;

export type TelclaudeMcpRegisteredBridgeResult =
	| {
			readonly ok: true;
			readonly bridge: TelclaudeMcpBridge;
			readonly authority: TelclaudeMcpAuthority;
	  }
	| TelclaudeMcpAuthorityFailure;

export type TelclaudeMcpAuthorityRegistry = {
	register(input: {
		readonly connection: TelclaudeMcpAuthorityConnection;
		readonly authority: TelclaudeMcpAuthority;
		readonly nowMs?: number;
		readonly ttlMs?: number;
	}): TelclaudeMcpAuthorityGrant;
	resolve(input: {
		readonly handle: string;
		readonly connection: TelclaudeMcpAuthorityConnection;
		readonly nowMs?: number;
	}): TelclaudeMcpAuthorityResolveResult;
	revoke(handle: string, reason?: string, nowMs?: number): boolean;
	revokeConnection(
		connection: TelclaudeMcpAuthorityConnection,
		reason?: string,
		nowMs?: number,
	): number;
	cleanupExpired(nowMs?: number): number;
	clear(): void;
};

type AuthorityRecord = {
	readonly handleHash: string;
	readonly connection: TelclaudeMcpAuthorityConnection;
	readonly authority: TelclaudeMcpAuthority;
	readonly issuedAtMs: number;
	readonly expiresAtMs: number;
	revokedAtMs?: number;
	revokeReason?: string;
};

export function createTelclaudeMcpAuthorityRegistry(): TelclaudeMcpAuthorityRegistry {
	const records = new Map<string, AuthorityRecord>();

	return {
		register(input) {
			const nowMs = normalizeNowMs(input.nowMs ?? Date.now());
			const ttlMs = normalizeTtlMs(input.ttlMs ?? DEFAULT_MCP_AUTHORITY_TTL_MS);
			const connection = normalizeConnection(input.connection);
			const authority = normalizeAuthority(input.authority);
			assertAuthorityMatchesConnection(authority, connection);
			assertAuthorityMemoryBoundary(authority);

			const handle = `tc_mcp_${crypto.randomBytes(32).toString("base64url")}`;
			const handleHash = hashHandle(handle);
			records.set(handleHash, {
				handleHash,
				connection,
				authority,
				issuedAtMs: nowMs,
				expiresAtMs: nowMs + ttlMs,
			});
			return { handle, issuedAtMs: nowMs, expiresAtMs: nowMs + ttlMs };
		},

		resolve(input) {
			const nowMs = normalizeNowMs(input.nowMs ?? Date.now());
			const connection = normalizeConnection(input.connection);
			const record = records.get(hashHandle(input.handle));
			if (!record) {
				return failure("mcp_authority_unknown", "MCP authority is not registered");
			}
			if (record.revokedAtMs !== undefined) {
				return failure("mcp_authority_revoked", "MCP authority was revoked");
			}
			if (record.expiresAtMs <= nowMs) {
				return failure("mcp_authority_expired", "MCP authority expired");
			}
			if (!sameConnection(record.connection, connection)) {
				return failure("mcp_authority_connection_mismatch", "MCP authority connection mismatch");
			}
			return {
				ok: true,
				authority: cloneAuthority(record.authority),
				issuedAtMs: record.issuedAtMs,
				expiresAtMs: record.expiresAtMs,
			};
		},

		revoke(handle, reason, nowMs = Date.now()) {
			const record = records.get(hashHandle(handle));
			if (!record || record.revokedAtMs !== undefined) return false;
			record.revokedAtMs = normalizeNowMs(nowMs);
			if (reason?.trim()) record.revokeReason = reason.trim();
			return true;
		},

		revokeConnection(connection, reason, nowMs = Date.now()) {
			const normalized = normalizeConnection(connection);
			let revoked = 0;
			for (const record of records.values()) {
				if (record.revokedAtMs === undefined && sameConnection(record.connection, normalized)) {
					record.revokedAtMs = normalizeNowMs(nowMs);
					if (reason?.trim()) record.revokeReason = reason.trim();
					revoked += 1;
				}
			}
			return revoked;
		},

		cleanupExpired(nowMs = Date.now()) {
			const normalizedNow = normalizeNowMs(nowMs);
			let removed = 0;
			for (const [handleHash, record] of records) {
				if (record.expiresAtMs <= normalizedNow) {
					records.delete(handleHash);
					removed += 1;
				}
			}
			return removed;
		},

		clear() {
			records.clear();
		},
	};
}

export function createTelclaudeMcpBridgeForRegisteredConnection(input: {
	readonly registry: TelclaudeMcpAuthorityRegistry;
	readonly handle: string;
	readonly connection: TelclaudeMcpAuthorityConnection;
	readonly dependencies: TelclaudeMcpBridgeDependencies;
	readonly nowMs?: number;
}): TelclaudeMcpRegisteredBridgeResult {
	const resolved = input.registry.resolve({
		handle: input.handle,
		connection: input.connection,
		nowMs: input.nowMs,
	});
	if (!resolved.ok) return resolved;
	return {
		ok: true,
		authority: resolved.authority,
		bridge: createTelclaudeMcpBridge(resolved.authority, input.dependencies),
	};
}

export const hermesMcpAuthorityRegistry = createTelclaudeMcpAuthorityRegistry();

function normalizeAuthority(authority: TelclaudeMcpAuthority): TelclaudeMcpAuthority {
	const memorySourceError = validateMemorySource(authority.memorySource);
	if (memorySourceError) {
		throw new Error(memorySourceError);
	}
	return {
		actorId: requiredTrimmed(authority.actorId, "actorId"),
		profileId: requiredTrimmed(authority.profileId, "profileId"),
		domain: authority.domain,
		memorySource: authority.memorySource,
		writableNamespace: requiredTrimmed(authority.writableNamespace, "writableNamespace"),
		providerScopes: uniqueTrimmed(authority.providerScopes),
		outboundChannels: uniqueTrimmed(authority.outboundChannels),
		...(authority.capabilityScopes
			? { capabilityScopes: uniqueTrimmed(authority.capabilityScopes) }
			: {}),
		endpointId: requiredTrimmed(authority.endpointId, "endpointId"),
		networkNamespace: requiredTrimmed(authority.networkNamespace, "networkNamespace"),
		...(authority.turnConversationRef
			? { turnConversationRef: normalizeTurnConversationRef(authority.turnConversationRef) }
			: {}),
	};
}

function normalizeConnection(
	connection: TelclaudeMcpAuthorityConnection,
): TelclaudeMcpAuthorityConnection {
	return {
		sessionKey: requiredTrimmed(connection.sessionKey, "sessionKey"),
		profileId: requiredTrimmed(connection.profileId, "profileId"),
		endpointId: requiredTrimmed(connection.endpointId, "endpointId"),
		networkNamespace: requiredTrimmed(connection.networkNamespace, "networkNamespace"),
	};
}

function assertAuthorityMatchesConnection(
	authority: TelclaudeMcpAuthority,
	connection: TelclaudeMcpAuthorityConnection,
): void {
	if (authority.profileId !== connection.profileId) {
		throw new Error("MCP authority profileId must match the connection profileId");
	}
	if (authority.endpointId !== connection.endpointId) {
		throw new Error("MCP authority endpointId must match the connection endpointId");
	}
	if (authority.networkNamespace !== connection.networkNamespace) {
		throw new Error("MCP authority networkNamespace must match the connection networkNamespace");
	}
}

function assertAuthorityMemoryBoundary(authority: TelclaudeMcpAuthority): void {
	if (usesSocialMemory(authority.domain)) {
		if (!isSocialMemorySource(authority.memorySource)) {
			throw new Error("social MCP authority must use social memory source");
		}
		return;
	}

	if (!isTelegramMemorySource(authority.memorySource)) {
		throw new Error("private MCP authority must use telegram profile memory source");
	}
	const expected = telegramMemorySource(authority.profileId);
	if (authority.memorySource !== expected) {
		throw new Error(`private MCP authority memory source must be ${expected}`);
	}
}

function usesSocialMemory(domain: TelclaudeMcpDomain): boolean {
	return domain === "social" || domain === "public";
}

function sameConnection(
	left: TelclaudeMcpAuthorityConnection,
	right: TelclaudeMcpAuthorityConnection,
): boolean {
	return (
		left.sessionKey === right.sessionKey &&
		left.profileId === right.profileId &&
		left.endpointId === right.endpointId &&
		left.networkNamespace === right.networkNamespace
	);
}

function cloneAuthority(authority: TelclaudeMcpAuthority): TelclaudeMcpAuthority {
	return {
		...authority,
		memorySource: authority.memorySource as MemorySource,
		providerScopes: [...authority.providerScopes],
		outboundChannels: [...authority.outboundChannels],
		...(authority.capabilityScopes ? { capabilityScopes: [...authority.capabilityScopes] } : {}),
	};
}

function hashHandle(handle: string): string {
	return `sha256:${crypto.createHash("sha256").update(requiredTrimmed(handle, "handle")).digest("hex")}`;
}

function uniqueTrimmed(values: readonly string[]): string[] {
	return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

function requiredTrimmed(value: string, field: string): string {
	const trimmed = value.trim();
	if (!trimmed) {
		throw new Error(`MCP authority ${field} is required`);
	}
	return trimmed;
}

function normalizeTurnConversationRef(value: string): string {
	const ref = value.trim();
	if (!isRelayConversationTurnRef(ref)) {
		throw new Error("MCP authority turnConversationRef must be a relay turn ref");
	}
	return ref;
}

function normalizeNowMs(value: number): number {
	if (!Number.isFinite(value) || value < 0) {
		throw new Error("MCP authority nowMs must be a non-negative finite timestamp");
	}
	return value;
}

function normalizeTtlMs(value: number): number {
	if (!Number.isFinite(value) || value <= 0) {
		throw new Error("MCP authority ttlMs must be a positive finite duration");
	}
	return value;
}

function failure(code: string, reason: string): TelclaudeMcpAuthorityFailure {
	return { ok: false, code, reason, retryable: false };
}
