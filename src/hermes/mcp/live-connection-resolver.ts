import crypto from "node:crypto";
import type http from "node:http";
import net from "node:net";
import type {
	TelclaudeMcpAuthorityConnection,
	TelclaudeMcpAuthorityRegistry,
} from "./authority-registry.js";
import type { TelclaudeLiveMcpConnectionContext } from "./live-server.js";

export const TELCLAUDE_LIVE_MCP_CONNECTION_TOKEN_PREFIX = "tc_mcp_conn_";
export const DEFAULT_LIVE_MCP_CONNECTION_TTL_MS = 15 * 60 * 1_000;

export type TelclaudeLiveMcpConnectionGrant = {
	readonly token: string;
	readonly authorityHandle: string;
	readonly connection: TelclaudeMcpAuthorityConnection;
	readonly issuedAtMs: number;
	readonly expiresAtMs: number;
	readonly peerAddress?: string;
};

export type TelclaudeLiveMcpRuntimeAuthorityActivation = {
	readonly id: string;
	readonly authorityHandle: string;
	readonly connection: TelclaudeMcpAuthorityConnection;
	readonly issuedAtMs: number;
	readonly expiresAtMs: number;
	readonly peerAddress?: string;
};

export type TelclaudeLiveMcpConnectionIssueInput = {
	readonly authorityHandle: string;
	readonly connection: TelclaudeMcpAuthorityConnection;
	readonly nowMs?: number;
	readonly ttlMs?: number;
	readonly peerAddress?: string;
};

export type TelclaudeLiveMcpProbePeerBypassIssueInput = TelclaudeLiveMcpConnectionIssueInput & {
	readonly peerAddress: string;
	readonly probePurpose: "off-domain-peer-negative-control";
};

export type TelclaudeLiveMcpRuntimeAuthorityActivationInput = {
	readonly authorityHandle: string;
	readonly connection: TelclaudeMcpAuthorityConnection;
	readonly nowMs?: number;
	readonly ttlMs?: number;
	readonly peerAddress?: string;
};

export type TelclaudeLiveMcpConnectionResolver = {
	issue(input: TelclaudeLiveMcpConnectionIssueInput): TelclaudeLiveMcpConnectionGrant;
	issueProbePeerBypass(
		input: TelclaudeLiveMcpProbePeerBypassIssueInput,
	): TelclaudeLiveMcpConnectionGrant;
	activateRuntimeAuthority(
		input: TelclaudeLiveMcpRuntimeAuthorityActivationInput,
	): TelclaudeLiveMcpRuntimeAuthorityActivation;
	revokeRuntimeAuthority(id: string, reason?: string, nowMs?: number): boolean;
	resolveConnection(request: http.IncomingMessage): TelclaudeLiveMcpConnectionContext | null;
	revoke(token: string, reason?: string, nowMs?: number): boolean;
	revokeConnection(
		connection: TelclaudeMcpAuthorityConnection,
		reason?: string,
		nowMs?: number,
	): number;
	cleanupExpired(nowMs?: number): number;
	clear(): void;
};

export type CreateTelclaudeLiveMcpConnectionResolverOptions = {
	readonly registry: TelclaudeMcpAuthorityRegistry;
	readonly nowMs?: () => number;
	readonly allowedPeerAddresses?: readonly string[];
	readonly runtimeTransportToken?: string;
};

type ConnectionTokenRecord = {
	readonly tokenHash: string;
	readonly authorityHandle: string;
	readonly connection: TelclaudeMcpAuthorityConnection;
	readonly issuedAtMs: number;
	readonly expiresAtMs: number;
	readonly peerAddress?: string;
	revokedAtMs?: number;
	revokeReason?: string;
};

type RuntimeAuthorityActivationRecord = {
	readonly id: string;
	readonly authorityHandle: string;
	readonly connection: TelclaudeMcpAuthorityConnection;
	readonly issuedAtMs: number;
	readonly expiresAtMs: number;
	readonly peerAddress?: string;
	revokedAtMs?: number;
	revokeReason?: string;
};

export function createTelclaudeLiveMcpConnectionResolver(
	options: CreateTelclaudeLiveMcpConnectionResolverOptions,
): TelclaudeLiveMcpConnectionResolver {
	const records = new Map<string, ConnectionTokenRecord>();
	const runtimeAuthorityActivations = new Map<string, RuntimeAuthorityActivationRecord>();
	const allowedPeers = normalizedPeerSet(options.allowedPeerAddresses);
	const runtimeTransportTokenHash = normalizeRuntimeTransportTokenHash(
		options.runtimeTransportToken,
	);
	const now = () => normalizeNowMs(options.nowMs?.() ?? Date.now());

	function issueConnectionGrant(
		input: TelclaudeLiveMcpConnectionIssueInput,
		allowDisallowedPeer: boolean,
	): TelclaudeLiveMcpConnectionGrant {
		const issuedAtMs = normalizeNowMs(input.nowMs ?? now());
		const ttlMs = normalizeTtlMs(input.ttlMs ?? DEFAULT_LIVE_MCP_CONNECTION_TTL_MS);
		const token = createConnectionToken();
		const tokenHash = hashToken(token);
		const connection = normalizeConnection(input.connection);
		const authorityHandle = requiredTrimmed(input.authorityHandle, "authorityHandle");
		const peerAddress = normalizeOptionalIssuePeerAddress(input.peerAddress);
		if (peerAddress && allowedPeers && !allowedPeers.has(peerAddress) && !allowDisallowedPeer) {
			throw new Error("live MCP peerAddress is not in allowedPeerAddresses");
		}
		records.set(tokenHash, {
			tokenHash,
			authorityHandle,
			connection,
			issuedAtMs,
			expiresAtMs: issuedAtMs + ttlMs,
			...(peerAddress ? { peerAddress } : {}),
		});
		return {
			token,
			authorityHandle,
			connection,
			issuedAtMs,
			expiresAtMs: issuedAtMs + ttlMs,
			...(peerAddress ? { peerAddress } : {}),
		};
	}

	return {
		issue(input) {
			return issueConnectionGrant(input, false);
		},

		issueProbePeerBypass(input) {
			if (input.probePurpose !== "off-domain-peer-negative-control") {
				throw new Error("live MCP probe peer bypass requires off-domain negative-control purpose");
			}
			return issueConnectionGrant(input, true);
		},

		activateRuntimeAuthority(input) {
			if (!runtimeTransportTokenHash) {
				throw new Error("live MCP runtime transport token is not configured");
			}
			const issuedAtMs = normalizeNowMs(input.nowMs ?? now());
			const ttlMs = normalizeTtlMs(input.ttlMs ?? DEFAULT_LIVE_MCP_CONNECTION_TTL_MS);
			const token = `tc_mcp_active_${crypto.randomBytes(18).toString("base64url")}`;
			const connection = normalizeConnection(input.connection);
			const authorityHandle = requiredTrimmed(input.authorityHandle, "authorityHandle");
			const peerAddress = normalizeOptionalIssuePeerAddress(input.peerAddress);
			if (peerAddress && allowedPeers && !allowedPeers.has(peerAddress)) {
				throw new Error("live MCP runtime peerAddress is not in allowedPeerAddresses");
			}
			const record: RuntimeAuthorityActivationRecord = {
				id: token,
				authorityHandle,
				connection,
				issuedAtMs,
				expiresAtMs: issuedAtMs + ttlMs,
				...(peerAddress ? { peerAddress } : {}),
			};
			runtimeAuthorityActivations.set(token, record);
			return {
				id: token,
				authorityHandle,
				connection,
				issuedAtMs,
				expiresAtMs: issuedAtMs + ttlMs,
				...(peerAddress ? { peerAddress } : {}),
			};
		},

		revokeRuntimeAuthority(id, reason, nowMs = now()) {
			const record = runtimeAuthorityActivations.get(id.trim());
			if (!record || record.revokedAtMs !== undefined) return false;
			record.revokedAtMs = normalizeNowMs(nowMs);
			if (reason?.trim()) record.revokeReason = reason.trim();
			return true;
		},

		resolveConnection(request) {
			const peerAddress = normalizeOptionalPeerAddress(request.socket.remoteAddress);
			const token = extractBearerToken(request.headers.authorization);
			if (!token) return null;

			if (runtimeTransportTokenHash && hashToken(token) === runtimeTransportTokenHash) {
				return resolveRuntimeTransportAuthority(peerAddress);
			}
			if (!token.startsWith(TELCLAUDE_LIVE_MCP_CONNECTION_TOKEN_PREFIX)) return null;

			const record = records.get(hashToken(token));
			if (!record) return null;

			const resolvedNow = now();
			if (record.revokedAtMs !== undefined || record.expiresAtMs <= resolvedNow) return null;
			if (record.peerAddress) {
				if (record.peerAddress !== peerAddress) return null;
			} else if (!peerAllowed(peerAddress, allowedPeers)) {
				return null;
			}

			const authority = options.registry.resolve({
				handle: record.authorityHandle,
				connection: record.connection,
				nowMs: resolvedNow,
			});
			if (!authority.ok) return null;

			return {
				authorityHandle: record.authorityHandle,
				connection: { ...record.connection },
				authority: authority.authority,
			};
		},

		revoke(token, reason, nowMs = now()) {
			const record = records.get(hashToken(token));
			if (!record || record.revokedAtMs !== undefined) return false;
			record.revokedAtMs = normalizeNowMs(nowMs);
			if (reason?.trim()) record.revokeReason = reason.trim();
			options.registry.revoke(record.authorityHandle, reason, record.revokedAtMs);
			return true;
		},

		revokeConnection(connection, reason, nowMs = now()) {
			const normalized = normalizeConnection(connection);
			const revokedAtMs = normalizeNowMs(nowMs);
			let revoked = 0;
			for (const record of records.values()) {
				if (record.revokedAtMs === undefined && sameConnection(record.connection, normalized)) {
					record.revokedAtMs = revokedAtMs;
					if (reason?.trim()) record.revokeReason = reason.trim();
					revoked += 1;
				}
			}
			options.registry.revokeConnection(normalized, reason, revokedAtMs);
			return revoked;
		},

		cleanupExpired(nowMs = now()) {
			const resolvedNow = normalizeNowMs(nowMs);
			let removed = 0;
			for (const [tokenHash, record] of records) {
				if (record.expiresAtMs <= resolvedNow) {
					records.delete(tokenHash);
					removed += 1;
				}
			}
			for (const [id, record] of runtimeAuthorityActivations) {
				if (record.expiresAtMs <= resolvedNow) {
					runtimeAuthorityActivations.delete(id);
					removed += 1;
				}
			}
			return removed;
		},

		clear() {
			records.clear();
			runtimeAuthorityActivations.clear();
		},
	};

	function resolveRuntimeTransportAuthority(
		peerAddress: string | undefined,
	): TelclaudeLiveMcpConnectionContext | null {
		const resolvedNow = now();
		if (!peerAllowed(peerAddress, allowedPeers)) return null;
		const active = [...runtimeAuthorityActivations.values()].filter((record) => {
			if (record.revokedAtMs !== undefined || record.expiresAtMs <= resolvedNow) return false;
			return record.peerAddress ? record.peerAddress === peerAddress : true;
		});
		if (active.length !== 1) {
			return {
				...(peerAddress ? { observedPeerAddress: peerAddress } : {}),
			};
		}
		const record = active[0];
		if (!record) return null;

		const authority = options.registry.resolve({
			handle: record.authorityHandle,
			connection: record.connection,
			nowMs: resolvedNow,
		});
		if (!authority.ok) return null;

		return {
			authorityHandle: record.authorityHandle,
			connection: { ...record.connection },
			authority: authority.authority,
			...(peerAddress ? { observedPeerAddress: peerAddress } : {}),
		};
	}
}

function createConnectionToken(): string {
	return `${TELCLAUDE_LIVE_MCP_CONNECTION_TOKEN_PREFIX}${crypto.randomBytes(32).toString("base64url")}`;
}

function extractBearerToken(headerValue: string | string[] | undefined): string | null {
	if (typeof headerValue !== "string") return null;
	const match = headerValue.trim().match(/^Bearer\s+(.+)$/i);
	if (!match) return null;
	const token = match[1]?.trim();
	return token && token.length > 0 ? token : null;
}

function hashToken(token: string): string {
	return crypto.createHash("sha256").update(token).digest("hex");
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

function normalizeTtlMs(ttlMs: number): number {
	if (!Number.isFinite(ttlMs) || ttlMs <= 0)
		throw new Error("live MCP token ttlMs must be positive");
	return Math.trunc(ttlMs);
}

function normalizeNowMs(nowMs: number): number {
	if (!Number.isFinite(nowMs) || nowMs < 0) throw new Error("live MCP nowMs must be non-negative");
	return Math.trunc(nowMs);
}

function normalizeOptionalPeerAddress(value: string | undefined): string | undefined {
	const trimmed = value?.trim();
	if (!trimmed) return undefined;
	if (trimmed.startsWith("::ffff:")) return trimmed.slice("::ffff:".length);
	if (trimmed === "::1") return "127.0.0.1";
	return trimmed;
}

function normalizedPeerSet(values: readonly string[] | undefined): Set<string> | null {
	if (!values || values.length === 0) return null;
	return new Set(values.map((value) => normalizeRequiredIpAddress(value, "allowedPeerAddresses")));
}

function normalizeOptionalIssuePeerAddress(value: string | undefined): string | undefined {
	const normalized = normalizeOptionalPeerAddress(value);
	return normalized ? normalizeRequiredIpAddress(normalized, "peerAddress") : undefined;
}

function normalizeRequiredIpAddress(value: string, field: string): string {
	const normalized = normalizeOptionalPeerAddress(value);
	if (!normalized || net.isIP(normalized) === 0) {
		throw new Error(`live MCP ${field} must be an IP address`);
	}
	return normalized;
}

function peerAllowed(peerAddress: string | undefined, allowedPeers: Set<string> | null): boolean {
	if (!peerAddress) return false;
	if (allowedPeers) return allowedPeers.has(peerAddress);
	return isLoopbackIp(peerAddress);
}

function isLoopbackIp(peerAddress: string): boolean {
	return peerAddress === "::1" || peerAddress === "127.0.0.1" || /^127\./.test(peerAddress);
}

function normalizeRuntimeTransportTokenHash(token: string | undefined): string | null {
	const trimmed = token?.trim();
	return trimmed ? hashToken(trimmed) : null;
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

function requiredTrimmed(value: string, field: string): string {
	const trimmed = value.trim();
	if (!trimmed) throw new Error(`live MCP ${field} is required`);
	return trimmed;
}
