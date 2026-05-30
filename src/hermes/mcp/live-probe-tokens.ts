import crypto from "node:crypto";
import type {
	TelclaudeMcpAuthorityConnection,
	TelclaudeMcpAuthorityRegistry,
} from "./authority-registry.js";
import type { TelclaudeMcpAuthority } from "./bridge.js";
import {
	DEFAULT_LIVE_MCP_CONNECTION_TTL_MS,
	TELCLAUDE_LIVE_MCP_CONNECTION_TOKEN_PREFIX,
	type TelclaudeLiveMcpConnectionGrant,
	type TelclaudeLiveMcpConnectionResolver,
} from "./live-connection-resolver.js";

export const TELCLAUDE_LIVE_MCP_PROBE_TOKEN_METADATA_SCHEMA_VERSION =
	"telclaude.hermes.live-mcp.probe-token-metadata.v1";

export type TelclaudeLiveMcpProbeTokenSecret = {
	readonly token: string;
	readonly authorizationHeader: string;
	readonly issuedAtMs: number;
	readonly expiresAtMs: number;
};

export type TelclaudeLiveMcpProbeTokenMetadata = {
	readonly schemaVersion: typeof TELCLAUDE_LIVE_MCP_PROBE_TOKEN_METADATA_SCHEMA_VERSION;
	readonly issuedAtMs: number;
	readonly expiresAtMs: number;
	readonly ttlMs: number;
	readonly tokenPrefix: typeof TELCLAUDE_LIVE_MCP_CONNECTION_TOKEN_PREFIX;
	readonly tokenMaterial: "omitted";
	readonly peerBound: boolean;
	readonly offDomainPeerBound: boolean;
	readonly privateConnection: TelclaudeLiveMcpProbeConnectionMetadata;
	readonly wrongConnection: TelclaudeLiveMcpProbeConnectionMetadata;
};

export type TelclaudeLiveMcpProbeConnectionMetadata = {
	readonly profileId: string;
	readonly endpointId: string;
	readonly networkNamespace: string;
};

export type TelclaudeLiveMcpProbeTokenBundle = {
	readonly allowed: TelclaudeLiveMcpProbeTokenSecret;
	readonly offDomainPeer: TelclaudeLiveMcpProbeTokenSecret;
	readonly wrongConnection: TelclaudeLiveMcpProbeTokenSecret;
	readonly forged: TelclaudeLiveMcpProbeTokenSecret;
	readonly metadata: TelclaudeLiveMcpProbeTokenMetadata;
};

export type CreateTelclaudeLiveMcpProbeTokenBundleOptions = {
	readonly registry: TelclaudeMcpAuthorityRegistry;
	readonly resolver: TelclaudeLiveMcpConnectionResolver;
	readonly privateConnection: TelclaudeMcpAuthorityConnection;
	readonly wrongConnection: TelclaudeMcpAuthorityConnection;
	readonly privateAuthority: TelclaudeMcpAuthority;
	readonly nowMs?: number;
	readonly ttlMs?: number;
	readonly peerAddress?: string;
	readonly offDomainPeerAddress?: string;
	readonly randomBytes?: (size: number) => Buffer;
};

export function createTelclaudeLiveMcpProbeTokenBundle(
	options: CreateTelclaudeLiveMcpProbeTokenBundleOptions,
): TelclaudeLiveMcpProbeTokenBundle {
	const nowMs = normalizeNowMs(options.nowMs ?? Date.now());
	const ttlMs = normalizeTtlMs(options.ttlMs ?? DEFAULT_LIVE_MCP_CONNECTION_TTL_MS);
	const privateConnection = normalizeConnection(options.privateConnection);
	const wrongConnection = normalizeConnection(options.wrongConnection);
	if (sameConnection(privateConnection, wrongConnection)) {
		throw new Error("live MCP probe wrongConnection must differ from privateConnection");
	}
	const offDomainPeerAddress = options.offDomainPeerAddress ?? "10.255.255.254";

	const privateGrant = options.registry.register({
		connection: privateConnection,
		authority: options.privateAuthority,
		nowMs,
		ttlMs,
	});
	const allowed = options.resolver.issue({
		authorityHandle: privateGrant.handle,
		connection: privateConnection,
		nowMs,
		ttlMs,
		...(options.peerAddress ? { peerAddress: options.peerAddress } : {}),
	});
	const offDomainPeer = options.resolver.issueProbePeerBypass({
		authorityHandle: privateGrant.handle,
		connection: privateConnection,
		nowMs,
		ttlMs,
		peerAddress: offDomainPeerAddress,
		probePurpose: "off-domain-peer-negative-control",
	});
	const wrong = options.resolver.issue({
		authorityHandle: privateGrant.handle,
		connection: wrongConnection,
		nowMs,
		ttlMs,
		...(options.peerAddress ? { peerAddress: options.peerAddress } : {}),
	});
	const forgedToken = createForgedToken(options.randomBytes ?? crypto.randomBytes);
	const expiresAtMs = nowMs + ttlMs;

	return {
		allowed: tokenSecret(allowed),
		offDomainPeer: tokenSecret(offDomainPeer),
		wrongConnection: tokenSecret(wrong),
		forged: {
			token: forgedToken,
			authorizationHeader: `Bearer ${forgedToken}`,
			issuedAtMs: nowMs,
			expiresAtMs,
		},
		metadata: {
			schemaVersion: TELCLAUDE_LIVE_MCP_PROBE_TOKEN_METADATA_SCHEMA_VERSION,
			issuedAtMs: nowMs,
			expiresAtMs,
			ttlMs,
			tokenPrefix: TELCLAUDE_LIVE_MCP_CONNECTION_TOKEN_PREFIX,
			tokenMaterial: "omitted",
			peerBound: Boolean(options.peerAddress?.trim()),
			offDomainPeerBound: true,
			privateConnection: connectionMetadata(privateConnection),
			wrongConnection: connectionMetadata(wrongConnection),
		},
	};
}

function tokenSecret(grant: TelclaudeLiveMcpConnectionGrant): TelclaudeLiveMcpProbeTokenSecret {
	return {
		token: grant.token,
		authorizationHeader: `Bearer ${grant.token}`,
		issuedAtMs: grant.issuedAtMs,
		expiresAtMs: grant.expiresAtMs,
	};
}

function createForgedToken(randomBytes: (size: number) => Buffer): string {
	return `${TELCLAUDE_LIVE_MCP_CONNECTION_TOKEN_PREFIX}${randomBytes(32).toString("base64url")}`;
}

function connectionMetadata(
	connection: TelclaudeMcpAuthorityConnection,
): TelclaudeLiveMcpProbeConnectionMetadata {
	return {
		profileId: connection.profileId,
		endpointId: connection.endpointId,
		networkNamespace: connection.networkNamespace,
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

function normalizeNowMs(nowMs: number): number {
	if (!Number.isFinite(nowMs) || nowMs < 0) {
		throw new Error("live MCP probe token nowMs must be non-negative");
	}
	return Math.trunc(nowMs);
}

function normalizeTtlMs(ttlMs: number): number {
	if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
		throw new Error("live MCP probe token ttlMs must be positive");
	}
	return Math.trunc(ttlMs);
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
	if (!trimmed) throw new Error(`live MCP probe token ${field} is required`);
	return trimmed;
}
