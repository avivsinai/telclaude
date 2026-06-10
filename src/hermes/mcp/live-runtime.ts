import crypto from "node:crypto";
import net from "node:net";
import type { OutboundDeliveryDispatcher } from "../../relay/outbound-delivery-dispatcher.js";
import type {
	TelclaudeMcpAuthorityConnection,
	TelclaudeMcpAuthorityRegistry,
} from "./authority-registry.js";
import { createTelclaudeMcpAuthorityRegistry } from "./authority-registry.js";
import type { TelclaudeMcpAuthority } from "./bridge.js";
import type {
	TelclaudeMcpInboundTurnAuthorityResolver,
	TelclaudeMcpOutboundConversationResolver,
	TelclaudeMcpProviderSidecarApprovalTokenIssuer,
	TelclaudeMcpSideEffectApprovalTokenResolver,
} from "./ledger-execute.js";
import {
	createTelclaudeLiveMcpConnectionResolver,
	type TelclaudeLiveMcpRuntimeAuthorityActivation,
	type TelclaudeLiveMcpRuntimeAuthorityActivationInput,
} from "./live-connection-resolver.js";
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
export const DEFAULT_TELCLAUDE_LIVE_MCP_NETWORK = "telclaude-hermes-private";

export type TelclaudeLiveMcpRuntimeConfig = {
	readonly enabled: boolean;
	readonly host: string;
	readonly port: number;
	readonly path: string;
	readonly networkName: string;
	readonly additionalBinds?: readonly TelclaudeLiveMcpBindConfig[];
	readonly allowedPeerAddresses?: readonly string[];
	readonly runtimeTransportToken?: string;
};

export type TelclaudeLiveMcpBindConfig = {
	readonly host: string;
	readonly networkName: string;
};

export type TelclaudeLiveMcpRuntime = {
	readonly enabled: boolean;
	readonly endpoint: TelclaudeLiveMcpListenEndpoint | null;
	readonly endpoints: readonly TelclaudeLiveMcpListenEndpoint[];
	readonly registry: TelclaudeMcpAuthorityRegistry | null;
	readonly ledger: TelclaudeMcpSideEffectLedger | null;
	issueProbeTokenBundle(
		input: TelclaudeLiveMcpRuntimeProbeTokenInput,
	): TelclaudeLiveMcpProbeTokenBundle;
	activateRuntimeAuthority(
		input: Omit<TelclaudeLiveMcpRuntimeAuthorityActivationInput, "peerAddress"> & {
			readonly peerAddress?: string;
		},
	): TelclaudeLiveMcpRuntimeAuthorityActivation;
	revokeRuntimeAuthority(id: string, reason?: string, nowMs?: number): boolean;
	openCanaryWindow(input?: TelclaudeLiveMcpCanaryWindowInput): TelclaudeLiveMcpCanaryWindow;
	closeCanaryWindow(
		input: TelclaudeLiveMcpCanaryWindowCloseInput,
	): TelclaudeLiveMcpCanaryWindowCloseResult;
	stop(): Promise<void>;
};

/**
 * A canary window is a scoped, short-lived runtime-authority activation used
 * by `hermes verify-live` to prove the served-MCP path with a real turn. It is
 * never long-lived or global: it registers a minimal private-domain grant in
 * an inert memory namespace, refuses to open while any other runtime
 * authority is active (so it can never degrade a live user turn), and the
 * grant + activation are revoked together on close, with the activation TTL
 * as the fail-safe.
 */
export type TelclaudeLiveMcpCanaryWindowInput = {
	readonly profileId?: string;
	readonly providerScopes?: readonly string[];
	readonly ttlMs?: number;
	readonly nowMs?: number;
};

export type TelclaudeLiveMcpCanaryWindow = {
	readonly activationId: string;
	readonly authorityHandle: string;
	readonly issuedAtMs: number;
	readonly expiresAtMs: number;
};

export type TelclaudeLiveMcpCanaryWindowCloseInput = {
	readonly activationId: string;
	readonly authorityHandle: string;
	readonly reason?: string;
	readonly nowMs?: number;
};

export type TelclaudeLiveMcpCanaryWindowCloseResult = {
	readonly revokedActivation: boolean;
	readonly revokedAuthority: boolean;
};

export class TelclaudeLiveMcpCanaryWindowBusyError extends Error {
	constructor() {
		super("live MCP canary window refused: another runtime authority is active");
	}
}

const DEFAULT_CANARY_WINDOW_TTL_MS = 240_000;
const MAX_CANARY_WINDOW_TTL_MS = 15 * 60 * 1_000;

export type TelclaudeLiveMcpRuntimeProbeTokenInput = {
	readonly privateConnection: TelclaudeMcpAuthorityConnection;
	readonly offDomainConnection?: TelclaudeMcpAuthorityConnection;
	readonly wrongConnection: TelclaudeMcpAuthorityConnection;
	readonly privateAuthority: TelclaudeMcpAuthority;
	readonly offDomainAuthority?: TelclaudeMcpAuthority;
	readonly nowMs?: number;
	readonly ttlMs?: number;
	readonly peerAddress?: string;
	readonly offDomainPeerAddress?: string;
};

export type TelclaudeLiveMcpRuntimeAdminHandle = {
	stop(): void | Promise<void>;
};

export type TelclaudeLiveMcpRuntimeAdminStarter = {
	start(context: {
		readonly endpoint: TelclaudeLiveMcpListenEndpoint;
		readonly endpoints: readonly TelclaudeLiveMcpListenEndpoint[];
		issueProbeTokenBundle(
			input: TelclaudeLiveMcpRuntimeProbeTokenInput,
		): TelclaudeLiveMcpProbeTokenBundle;
		openCanaryWindow(input?: TelclaudeLiveMcpCanaryWindowInput): TelclaudeLiveMcpCanaryWindow;
		closeCanaryWindow(
			input: TelclaudeLiveMcpCanaryWindowCloseInput,
		): TelclaudeLiveMcpCanaryWindowCloseResult;
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
	readonly sideEffectApprovalTokenResolver?: TelclaudeMcpSideEffectApprovalTokenResolver;
	readonly resolveAuthorizedOutboundConversation?: TelclaudeMcpOutboundConversationResolver;
	readonly resolveAuthorizedInboundTurn?: TelclaudeMcpInboundTurnAuthorityResolver;
	readonly outboundDeliveryDispatcher?: OutboundDeliveryDispatcher;
	readonly providerApprovalTokenIssuer?: TelclaudeMcpProviderSidecarApprovalTokenIssuer;
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
			additionalBinds: undefined,
			allowedPeerAddresses: undefined,
			runtimeTransportToken: undefined,
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
		additionalBinds: parseAdditionalBinds(env.TELCLAUDE_HERMES_LIVE_MCP_ADDITIONAL_BINDS),
		allowedPeerAddresses: parsePeerAllowlist(env.TELCLAUDE_HERMES_LIVE_MCP_ALLOWED_PEERS),
		runtimeTransportToken: requiredLiveMcpRelayToken(env.TELCLAUDE_HERMES_MCP_RELAY_TOKEN),
	};
	assertLiveMcpRuntimeConfig(config);
	return config;
}

export async function startTelclaudeLiveMcpRuntime(
	options: StartTelclaudeLiveMcpRuntimeOptions,
): Promise<TelclaudeLiveMcpRuntime> {
	if (!options.config.enabled) return disabledRuntime();
	assertLiveMcpRuntimeConfig(options.config);

	const registry = options.registry ?? createTelclaudeMcpAuthorityRegistry();
	const resolver = createTelclaudeLiveMcpConnectionResolver({
		registry,
		nowMs: options.nowMs,
		allowedPeerAddresses: options.config.allowedPeerAddresses,
		runtimeTransportToken: options.config.runtimeTransportToken,
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
	const bindConfigs = liveMcpBindConfigs(options.config);
	const endpoints: TelclaudeLiveMcpListenEndpoint[] = [];
	try {
		for (const bind of bindConfigs) {
			const liveServer = createTelclaudeLiveMcpRelayHttpServer({
				registry,
				ledger,
				relayClients,
				bindHost: bind.host,
				networkName: bind.networkName,
				sideEffectApprovalTokenResolver: options.sideEffectApprovalTokenResolver,
				resolveAuthorizedOutboundConversation: options.resolveAuthorizedOutboundConversation,
				resolveAuthorizedInboundTurn: options.resolveAuthorizedInboundTurn,
				outboundDeliveryDispatcher: options.outboundDeliveryDispatcher,
				providerApprovalTokenIssuer: options.providerApprovalTokenIssuer,
				nowMs: options.nowMs,
			});
			const nodeServer = createTelclaudeLiveMcpNodeHttpServer(liveServer, {
				path: options.config.path,
				resolveConnection: (request) => resolver.resolveConnection(request),
			});
			endpoints.push(
				await listenTelclaudeLiveMcpRelayHttpServer(liveServer, nodeServer, {
					host: bind.host,
					port: options.config.port,
					path: options.config.path,
				}),
			);
		}
	} catch (error) {
		await closeEndpoints(endpoints);
		resolver.clear();
		registry.clear();
		throw error;
	}
	const [endpoint] = endpoints;
	if (!endpoint) {
		resolver.clear();
		registry.clear();
		throw new Error("live MCP runtime did not create a listen endpoint");
	}

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

	const openCanaryWindow = (
		input: TelclaudeLiveMcpCanaryWindowInput = {},
	): TelclaudeLiveMcpCanaryWindow => {
		if (stopped) throw new Error("live MCP runtime is stopped");
		const nowMs = input.nowMs ?? options.nowMs?.() ?? Date.now();
		if (resolver.hasActiveRuntimeAuthority(nowMs)) {
			throw new TelclaudeLiveMcpCanaryWindowBusyError();
		}
		const profileId = input.profileId?.trim() || "verify-live";
		const ttlMs = Math.min(
			input.ttlMs && input.ttlMs > 0 ? Math.trunc(input.ttlMs) : DEFAULT_CANARY_WINDOW_TTL_MS,
			MAX_CANARY_WINDOW_TTL_MS,
		);
		const connection: TelclaudeMcpAuthorityConnection = {
			sessionKey: `canary-${crypto.randomUUID()}`,
			profileId,
			endpointId: "tc-hermes-private",
			networkNamespace: options.config.networkName,
		};
		const authority: TelclaudeMcpAuthority = {
			actorId: "verify-live-canary",
			profileId,
			domain: "private",
			memorySource: `telegram:${profileId}`,
			writableNamespace: `telegram:${profileId}`,
			providerScopes: [...(input.providerScopes ?? [])],
			outboundChannels: [],
			endpointId: connection.endpointId,
			networkNamespace: connection.networkNamespace,
		};
		const grant = registry.register({ connection, authority, nowMs, ttlMs });
		try {
			const activation = resolver.activateRuntimeAuthority({
				authorityHandle: grant.handle,
				connection,
				nowMs,
				ttlMs,
				peerAddress: singleAllowedPeerAddress(options.config.allowedPeerAddresses),
			});
			return {
				activationId: activation.id,
				authorityHandle: grant.handle,
				issuedAtMs: activation.issuedAtMs,
				expiresAtMs: activation.expiresAtMs,
			};
		} catch (error) {
			registry.revoke(grant.handle, "canary window activation failed", nowMs);
			throw error;
		}
	};

	const closeCanaryWindow = (
		input: TelclaudeLiveMcpCanaryWindowCloseInput,
	): TelclaudeLiveMcpCanaryWindowCloseResult => {
		const nowMs = input.nowMs ?? options.nowMs?.() ?? Date.now();
		const reason = input.reason?.trim() || "canary window closed";
		const revokedActivation = resolver.revokeRuntimeAuthority(input.activationId, reason, nowMs);
		const revokedAuthority = registry.revoke(input.authorityHandle, reason, nowMs);
		return { revokedActivation, revokedAuthority };
	};

	try {
		adminHandle = options.admin
			? await options.admin.start({
					endpoint,
					endpoints,
					issueProbeTokenBundle,
					openCanaryWindow,
					closeCanaryWindow,
				})
			: null;
	} catch (error) {
		await closeEndpoints(endpoints);
		resolver.clear();
		registry.clear();
		throw error;
	}

	return {
		enabled: true,
		endpoint,
		endpoints,
		registry,
		ledger,
		issueProbeTokenBundle,
		activateRuntimeAuthority(input) {
			if (stopped) throw new Error("live MCP runtime is stopped");
			return resolver.activateRuntimeAuthority({
				...input,
				peerAddress:
					input.peerAddress ?? singleAllowedPeerAddress(options.config.allowedPeerAddresses),
			});
		},
		revokeRuntimeAuthority(id, reason, nowMs) {
			return resolver.revokeRuntimeAuthority(id, reason, nowMs);
		},
		openCanaryWindow,
		closeCanaryWindow,
		async stop() {
			if (stopped) return;
			stopped = true;
			try {
				await adminHandle?.stop();
			} finally {
				try {
					await closeEndpoints(endpoints);
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
		endpoints: [],
		registry: null,
		ledger: null,
		issueProbeTokenBundle() {
			throw new Error("live MCP runtime is disabled");
		},
		activateRuntimeAuthority() {
			throw new Error("live MCP runtime is disabled");
		},
		revokeRuntimeAuthority() {
			return false;
		},
		openCanaryWindow() {
			throw new Error("live MCP runtime is disabled");
		},
		closeCanaryWindow() {
			return { revokedActivation: false, revokedAuthority: false };
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

function requiredLiveMcpRelayToken(value: string | undefined): string {
	const trimmed = value?.trim();
	if (!trimmed) {
		throw new Error("TELCLAUDE_HERMES_MCP_RELAY_TOKEN is required when live MCP is enabled");
	}
	return trimmed;
}

function csv(value: string | undefined): string[] | undefined {
	const entries = (value ?? "")
		.split(",")
		.map((entry) => entry.trim())
		.filter((entry) => entry.length > 0);
	return entries.length > 0 ? entries : undefined;
}

function parseAdditionalBinds(value: string | undefined): TelclaudeLiveMcpBindConfig[] | undefined {
	const entries = csv(value);
	if (!entries) return undefined;
	return entries.map((entry) => {
		const separator = entry.lastIndexOf("@");
		if (separator <= 0 || separator >= entry.length - 1) {
			throw new Error("TELCLAUDE_HERMES_LIVE_MCP_ADDITIONAL_BINDS entries must use host@network");
		}
		return {
			host: nonEmptyEnv(entry.slice(0, separator), ""),
			networkName: nonEmptyEnv(entry.slice(separator + 1), ""),
		};
	});
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

function assertLiveMcpRuntimeConfig(config: TelclaudeLiveMcpRuntimeConfig): void {
	for (const bind of liveMcpBindConfigs(config)) {
		assertLiveMcpBindHost(bind.host);
	}
	assertPeerAllowlistForBindHost(config);
	if (config.enabled && !config.runtimeTransportToken?.trim()) {
		throw new Error("TELCLAUDE_HERMES_MCP_RELAY_TOKEN is required when live MCP is enabled");
	}
}

function liveMcpBindConfigs(config: TelclaudeLiveMcpRuntimeConfig): TelclaudeLiveMcpBindConfig[] {
	return [
		{ host: config.host, networkName: config.networkName },
		...(config.additionalBinds ?? []),
	];
}

function assertLiveMcpBindHost(host: string): void {
	const normalized = normalizeHostAddress(host);
	if (normalized === "0.0.0.0" || normalized === "::" || normalized === "") {
		throw new Error("TELCLAUDE_HERMES_LIVE_MCP_HOST must not bind an unspecified interface");
	}
	if (normalized === "localhost") {
		throw new Error("TELCLAUDE_HERMES_LIVE_MCP_HOST must be explicit, not localhost");
	}
}

function assertPeerAllowlistForBindHost(config: TelclaudeLiveMcpRuntimeConfig): void {
	if (
		!config.enabled ||
		!liveMcpBindConfigs(config).some((bind) => requiresPeerAllowlist(bind.host))
	) {
		return;
	}
	if (config.allowedPeerAddresses && config.allowedPeerAddresses.length > 0) return;
	throw new Error(
		"TELCLAUDE_HERMES_LIVE_MCP_ALLOWED_PEERS is required when live MCP binds outside loopback",
	);
}

function requiresPeerAllowlist(host: string): boolean {
	const normalized = normalizeHostAddress(host);
	if (normalized === "localhost") return false;
	if (normalized === "0.0.0.0" || normalized === "::" || normalized === "") return true;
	if (normalized === "127.0.0.1" || normalized === "::1") return false;
	if (/^127\./.test(normalized)) return false;
	return true;
}

function normalizeHostAddress(host: string): string {
	return normalizePeerAddress(host.trim().replace(/^\[(.*)\]$/, "$1"));
}

function singleAllowedPeerAddress(values: readonly string[] | undefined): string | undefined {
	return values?.length === 1 ? values[0] : undefined;
}

function normalizePeerAddress(value: string): string {
	const trimmed = value.trim();
	if (trimmed.startsWith("::ffff:")) return trimmed.slice("::ffff:".length);
	if (trimmed === "::1") return "127.0.0.1";
	return trimmed;
}

async function closeEndpoints(endpoints: readonly TelclaudeLiveMcpListenEndpoint[]): Promise<void> {
	const errors: unknown[] = [];
	for (const endpoint of [...endpoints].reverse()) {
		try {
			await endpoint.close();
		} catch (error) {
			errors.push(error);
		}
	}
	if (errors.length > 0) {
		throw errors[0];
	}
}
