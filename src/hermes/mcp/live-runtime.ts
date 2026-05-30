import net from "node:net";
import type {
	TelclaudeMcpAuthorityConnection,
	TelclaudeMcpAuthorityRegistry,
} from "./authority-registry.js";
import { createTelclaudeMcpAuthorityRegistry } from "./authority-registry.js";
import type { TelclaudeMcpAuthority } from "./bridge.js";
import { createTelclaudeLiveMcpConnectionResolver } from "./live-connection-resolver.js";
import {
	listenTelclaudeLiveMcpRelayHttpServer,
	type TelclaudeLiveMcpListenEndpoint,
} from "./live-listen.js";
import {
	createTelclaudeLiveMcpProbeTokenBundle,
	type TelclaudeLiveMcpProbeTokenBundle,
} from "./live-probe-tokens.js";
import {
	createTelclaudeLiveMcpNodeHttpServer,
	createTelclaudeLiveMcpRelayHttpServer,
	type TelclaudeLiveMcpRelayClients,
} from "./live-server.js";
import {
	createTelclaudeMcpSideEffectLedger,
	type TelclaudeMcpSideEffectApprovalVerifier,
	type TelclaudeMcpSideEffectLedger,
} from "./side-effect-ledger.js";

export const DEFAULT_TELCLAUDE_LIVE_MCP_HOST = "127.0.0.1";
export const DEFAULT_TELCLAUDE_LIVE_MCP_PORT = 8793;
export const DEFAULT_TELCLAUDE_LIVE_MCP_PATH = "/mcp";
export const DEFAULT_TELCLAUDE_LIVE_MCP_NETWORK = "telclaude-hermes-relay";

export type TelclaudeLiveMcpRuntimeConfig = {
	readonly enabled: boolean;
	readonly host: string;
	readonly port: number;
	readonly path: string;
	readonly networkName: string;
	readonly allowedPeerAddresses?: readonly string[];
};

export type TelclaudeLiveMcpRuntime = {
	readonly enabled: boolean;
	readonly endpoint: TelclaudeLiveMcpListenEndpoint | null;
	readonly registry: TelclaudeMcpAuthorityRegistry | null;
	readonly ledger: TelclaudeMcpSideEffectLedger | null;
	issueProbeTokenBundle(
		input: TelclaudeLiveMcpRuntimeProbeTokenInput,
	): TelclaudeLiveMcpProbeTokenBundle;
	stop(): Promise<void>;
};

export type TelclaudeLiveMcpRuntimeProbeTokenInput = {
	readonly privateConnection: TelclaudeMcpAuthorityConnection;
	readonly wrongConnection: TelclaudeMcpAuthorityConnection;
	readonly privateAuthority: TelclaudeMcpAuthority;
	readonly nowMs?: number;
	readonly ttlMs?: number;
	readonly peerAddress?: string;
};

export type TelclaudeLiveMcpRuntimeAdminHandle = {
	stop(): void | Promise<void>;
};

export type TelclaudeLiveMcpRuntimeAdminStarter = {
	start(context: {
		readonly endpoint: TelclaudeLiveMcpListenEndpoint;
		issueProbeTokenBundle(
			input: TelclaudeLiveMcpRuntimeProbeTokenInput,
		): TelclaudeLiveMcpProbeTokenBundle;
	}): TelclaudeLiveMcpRuntimeAdminHandle | Promise<TelclaudeLiveMcpRuntimeAdminHandle>;
};

export type StartTelclaudeLiveMcpRuntimeOptions = {
	readonly config: TelclaudeLiveMcpRuntimeConfig;
	readonly relayClients?: TelclaudeLiveMcpRelayClients;
	readonly createRelayClients?: (context: {
		readonly ledger: TelclaudeMcpSideEffectLedger;
	}) => TelclaudeLiveMcpRelayClients;
	readonly registry?: TelclaudeMcpAuthorityRegistry;
	readonly ledger?: TelclaudeMcpSideEffectLedger;
	readonly verifyApproval?: TelclaudeMcpSideEffectApprovalVerifier;
	readonly nowMs?: () => number;
	readonly admin?: TelclaudeLiveMcpRuntimeAdminStarter;
};

export function readTelclaudeLiveMcpRuntimeConfig(
	env: NodeJS.ProcessEnv = process.env,
): TelclaudeLiveMcpRuntimeConfig {
	const enabled = env.TELCLAUDE_HERMES_LIVE_MCP_ENABLED === "1";
	if (!enabled) {
		return {
			enabled: false,
			host: DEFAULT_TELCLAUDE_LIVE_MCP_HOST,
			port: DEFAULT_TELCLAUDE_LIVE_MCP_PORT,
			path: DEFAULT_TELCLAUDE_LIVE_MCP_PATH,
			networkName: DEFAULT_TELCLAUDE_LIVE_MCP_NETWORK,
			allowedPeerAddresses: undefined,
		};
	}
	const config = {
		enabled,
		host: nonEmptyEnv(env.TELCLAUDE_HERMES_LIVE_MCP_HOST, DEFAULT_TELCLAUDE_LIVE_MCP_HOST),
		port: parsePort(env.TELCLAUDE_HERMES_LIVE_MCP_PORT, DEFAULT_TELCLAUDE_LIVE_MCP_PORT),
		path: normalizePath(env.TELCLAUDE_HERMES_LIVE_MCP_PATH, DEFAULT_TELCLAUDE_LIVE_MCP_PATH),
		networkName: nonEmptyEnv(
			env.TELCLAUDE_HERMES_LIVE_MCP_NETWORK,
			DEFAULT_TELCLAUDE_LIVE_MCP_NETWORK,
		),
		allowedPeerAddresses: parsePeerAllowlist(env.TELCLAUDE_HERMES_LIVE_MCP_ALLOWED_PEERS),
	};
	assertPeerAllowlistForBindHost(config);
	return config;
}

export async function startTelclaudeLiveMcpRuntime(
	options: StartTelclaudeLiveMcpRuntimeOptions,
): Promise<TelclaudeLiveMcpRuntime> {
	if (!options.config.enabled) return disabledRuntime();

	const registry = options.registry ?? createTelclaudeMcpAuthorityRegistry();
	const resolver = createTelclaudeLiveMcpConnectionResolver({
		registry,
		nowMs: options.nowMs,
		allowedPeerAddresses: options.config.allowedPeerAddresses,
	});
	const ledger =
		options.ledger ??
		createTelclaudeMcpSideEffectLedger({
			verifyApproval: options.verifyApproval ?? denyLiveMcpApproval,
			nowMs: options.nowMs,
		});
	const relayClients =
		options.relayClients ??
		options.createRelayClients?.({ ledger }) ??
		createFailClosedTelclaudeLiveMcpRelayClients();
	const liveServer = createTelclaudeLiveMcpRelayHttpServer({
		registry,
		ledger,
		relayClients,
		bindHost: options.config.host,
		networkName: options.config.networkName,
		nowMs: options.nowMs,
	});
	const nodeServer = createTelclaudeLiveMcpNodeHttpServer(liveServer, {
		path: options.config.path,
		resolveConnection: (request) => resolver.resolveConnection(request),
	});
	const endpoint = await listenTelclaudeLiveMcpRelayHttpServer(liveServer, nodeServer, {
		host: options.config.host,
		port: options.config.port,
		path: options.config.path,
	});

	let adminHandle: TelclaudeLiveMcpRuntimeAdminHandle | null = null;
	let stopped = false;
	const issueProbeTokenBundle = (input: TelclaudeLiveMcpRuntimeProbeTokenInput) => {
		if (stopped) throw new Error("live MCP runtime is stopped");
		return createTelclaudeLiveMcpProbeTokenBundle({
			registry,
			resolver,
			...input,
		});
	};

	try {
		adminHandle = options.admin
			? await options.admin.start({ endpoint, issueProbeTokenBundle })
			: null;
	} catch (error) {
		await endpoint.close();
		resolver.clear();
		registry.clear();
		throw error;
	}

	return {
		enabled: true,
		endpoint,
		registry,
		ledger,
		issueProbeTokenBundle,
		async stop() {
			if (stopped) return;
			stopped = true;
			try {
				await adminHandle?.stop();
			} finally {
				try {
					await endpoint.close();
				} finally {
					resolver.clear();
					registry.clear();
				}
			}
		},
	};
}

export function createFailClosedTelclaudeLiveMcpRelayClients(
	reason = "live MCP relay client adapter is not configured",
): TelclaudeLiveMcpRelayClients {
	const fail = async () => {
		throw new Error(reason);
	};
	return {
		providerRead: fail,
		providerPrepareWrite: fail,
		memorySearch: fail,
		memoryWrite: fail,
		attachmentGet: fail,
		outboundPrepare: fail,
		auditNote: fail,
	};
}

async function denyLiveMcpApproval() {
	return {
		ok: false as const,
		code: "approval_required",
		reason: "live MCP side-effect approval verifier is not configured",
	};
}

function disabledRuntime(): TelclaudeLiveMcpRuntime {
	return {
		enabled: false,
		endpoint: null,
		registry: null,
		ledger: null,
		issueProbeTokenBundle() {
			throw new Error("live MCP runtime is disabled");
		},
		async stop() {
			// no-op
		},
	};
}

function parsePort(value: string | undefined, fallback: number): number {
	if (!value?.trim()) return fallback;
	const trimmed = value.trim();
	if (!/^\d+$/.test(trimmed)) {
		throw new Error(`Invalid TELCLAUDE_HERMES_LIVE_MCP_PORT: ${value}`);
	}
	const parsed = Number.parseInt(trimmed, 10);
	if (!Number.isInteger(parsed) || parsed <= 0 || parsed > 65535) {
		throw new Error(`Invalid TELCLAUDE_HERMES_LIVE_MCP_PORT: ${value}`);
	}
	return parsed;
}

function normalizePath(value: string | undefined, fallback: string): string {
	const path = nonEmptyEnv(value, fallback);
	return path.startsWith("/") ? path : `/${path}`;
}

function nonEmptyEnv(value: string | undefined, fallback: string): string {
	const trimmed = value?.trim();
	return trimmed && trimmed.length > 0 ? trimmed : fallback;
}

function csv(value: string | undefined): string[] | undefined {
	const entries = (value ?? "")
		.split(",")
		.map((entry) => entry.trim())
		.filter((entry) => entry.length > 0);
	return entries.length > 0 ? entries : undefined;
}

function parsePeerAllowlist(value: string | undefined): string[] | undefined {
	const entries = csv(value);
	if (!entries) return undefined;
	return entries.map((entry) => {
		const peerAddress = normalizePeerAddress(entry);
		if (net.isIP(peerAddress) === 0) {
			throw new Error("TELCLAUDE_HERMES_LIVE_MCP_ALLOWED_PEERS must contain IP addresses");
		}
		return peerAddress;
	});
}

function assertPeerAllowlistForBindHost(config: TelclaudeLiveMcpRuntimeConfig): void {
	if (!config.enabled || !requiresPeerAllowlist(config.host)) return;
	if (config.allowedPeerAddresses && config.allowedPeerAddresses.length > 0) return;
	throw new Error(
		"TELCLAUDE_HERMES_LIVE_MCP_ALLOWED_PEERS is required when live MCP binds outside loopback",
	);
}

function requiresPeerAllowlist(host: string): boolean {
	const normalized = normalizeHostAddress(host);
	if (normalized === "localhost") return false;
	if (normalized === "0.0.0.0" || normalized === "::" || normalized === "") return false;
	if (normalized === "127.0.0.1" || normalized === "::1") return false;
	if (/^127\./.test(normalized)) return false;
	return true;
}

function normalizeHostAddress(host: string): string {
	return normalizePeerAddress(host.trim().replace(/^\[(.*)\]$/, "$1"));
}

function normalizePeerAddress(value: string): string {
	const trimmed = value.trim();
	if (trimmed.startsWith("::ffff:")) return trimmed.slice("::ffff:".length);
	if (trimmed === "::1") return "127.0.0.1";
	return trimmed;
}
