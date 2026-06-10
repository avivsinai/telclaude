import fs from "node:fs";
import http from "node:http";
import type { Socket } from "node:net";
import path from "node:path";
import { z } from "zod";
import { buildInternalAuthHeaders, verifyInternalAuth } from "../../internal-auth.js";
import { getChildLogger } from "../../logging.js";
import { CONFIG_DIR } from "../../utils.js";
import type { TelclaudeMcpDomain } from "./bridge.js";
import type { TelclaudeLiveMcpProbeTokenBundle } from "./live-probe-tokens.js";
import {
	type TelclaudeLiveMcpCanaryWindow,
	TelclaudeLiveMcpCanaryWindowBusyError,
	type TelclaudeLiveMcpCanaryWindowCloseInput,
	type TelclaudeLiveMcpCanaryWindowCloseResult,
	type TelclaudeLiveMcpCanaryWindowInput,
	type TelclaudeLiveMcpRuntimeAdminStarter,
	type TelclaudeLiveMcpRuntimeProbeTokenInput,
} from "./live-runtime.js";

export const TELCLAUDE_LIVE_MCP_ADMIN_PROBE_TOKENS_PATH = "/v1/probe-tokens";
export const TELCLAUDE_LIVE_MCP_ADMIN_CANARY_OPEN_PATH = "/v1/canary-window/open";
export const TELCLAUDE_LIVE_MCP_ADMIN_CANARY_CLOSE_PATH = "/v1/canary-window/close";
export const TELCLAUDE_LIVE_MCP_ADMIN_SOCKET_ENV = "TELCLAUDE_HERMES_LIVE_MCP_ADMIN_SOCKET";
export const DEFAULT_TELCLAUDE_LIVE_MCP_ADMIN_SOCKET = path.join(
	CONFIG_DIR,
	"run",
	"hermes-live-mcp-admin.sock",
);

const MAX_ADMIN_BODY_BYTES = 64 * 1024;
const OPERATOR_SCOPE = "operator";

const logger = getChildLogger({ module: "hermes-live-mcp-admin" });

type LiveMcpAdminLogger = {
	info(...args: unknown[]): void;
	warn(...args: unknown[]): void;
	error(...args: unknown[]): void;
	debug(...args: unknown[]): void;
};

export type TelclaudeLiveMcpAdminServerHandle = {
	readonly transport: "unix";
	readonly socketPath: string;
	stop(): Promise<void>;
};

export type TelclaudeLiveMcpAdminConfig = {
	readonly enabled: boolean;
	readonly socketPath: string;
};

export type StartTelclaudeLiveMcpAdminServerOptions = {
	readonly socketPath?: string;
	readonly issueProbeTokenBundle: (
		input: TelclaudeLiveMcpRuntimeProbeTokenInput,
	) => TelclaudeLiveMcpProbeTokenBundle;
	readonly openCanaryWindow?: (
		input?: TelclaudeLiveMcpCanaryWindowInput,
	) => TelclaudeLiveMcpCanaryWindow;
	readonly closeCanaryWindow?: (
		input: TelclaudeLiveMcpCanaryWindowCloseInput,
	) => TelclaudeLiveMcpCanaryWindowCloseResult;
	readonly logger?: LiveMcpAdminLogger;
};

export type RequestTelclaudeLiveMcpProbeTokensOptions = {
	readonly socketPath?: string;
	readonly input: TelclaudeLiveMcpRuntimeProbeTokenInput;
	readonly timeoutMs?: number;
};

export type RequestTelclaudeLiveMcpCanaryWindowOpenOptions = {
	readonly socketPath?: string;
	readonly input?: TelclaudeLiveMcpCanaryWindowInput;
	readonly timeoutMs?: number;
};

export type RequestTelclaudeLiveMcpCanaryWindowCloseOptions = {
	readonly socketPath?: string;
	readonly input: TelclaudeLiveMcpCanaryWindowCloseInput;
	readonly timeoutMs?: number;
};

const NonEmptyString = z.string().trim().min(1);
const ConnectionSchema = z
	.object({
		sessionKey: NonEmptyString,
		profileId: NonEmptyString,
		endpointId: NonEmptyString,
		networkNamespace: NonEmptyString,
	})
	.strip();
const AuthoritySchema = z
	.object({
		actorId: NonEmptyString,
		profileId: NonEmptyString,
		domain: z.enum(["private", "social", "household", "public", "specialist"]),
		memorySource: NonEmptyString,
		writableNamespace: NonEmptyString,
		providerScopes: z.array(NonEmptyString),
		outboundChannels: z.array(NonEmptyString),
		endpointId: NonEmptyString,
		networkNamespace: NonEmptyString,
	})
	.strip();
const ProbeTokensRequestSchema = z
	.object({
		privateConnection: ConnectionSchema,
		offDomainConnection: ConnectionSchema.optional(),
		wrongConnection: ConnectionSchema,
		privateAuthority: AuthoritySchema,
		offDomainAuthority: AuthoritySchema.optional(),
		nowMs: z.number().finite().nonnegative().optional(),
		ttlMs: z.number().finite().positive().optional(),
		peerAddress: NonEmptyString.optional(),
		offDomainPeerAddress: NonEmptyString.optional(),
	})
	.strip();
const CanaryWindowOpenRequestSchema = z
	.object({
		profileId: NonEmptyString.optional(),
		providerScopes: z.array(NonEmptyString).max(8).optional(),
		ttlMs: z.number().finite().positive().optional(),
	})
	.strip();
const CanaryWindowCloseRequestSchema = z
	.object({
		activationId: NonEmptyString,
		authorityHandle: NonEmptyString,
		reason: NonEmptyString.optional(),
	})
	.strip();

export function readTelclaudeLiveMcpAdminSocketPath(env: NodeJS.ProcessEnv = process.env): string {
	const configured = env[TELCLAUDE_LIVE_MCP_ADMIN_SOCKET_ENV]?.trim();
	return normalizeAbsoluteSocketPath(configured || DEFAULT_TELCLAUDE_LIVE_MCP_ADMIN_SOCKET);
}

export function readTelclaudeLiveMcpAdminConfig(
	env: NodeJS.ProcessEnv = process.env,
): TelclaudeLiveMcpAdminConfig {
	const enabled = env.TELCLAUDE_HERMES_LIVE_MCP_ADMIN_ENABLED === "1";
	return {
		enabled,
		socketPath: enabled
			? readTelclaudeLiveMcpAdminSocketPath(env)
			: DEFAULT_TELCLAUDE_LIVE_MCP_ADMIN_SOCKET,
	};
}

export function createTelclaudeLiveMcpProbeAdminStarter(
	config: TelclaudeLiveMcpAdminConfig,
	options: { readonly logger?: LiveMcpAdminLogger } = {},
): TelclaudeLiveMcpRuntimeAdminStarter {
	return {
		start(context) {
			if (!config.enabled) {
				return { stop: () => undefined };
			}
			return startTelclaudeLiveMcpAdminServer({
				socketPath: config.socketPath,
				logger: options.logger,
				issueProbeTokenBundle: context.issueProbeTokenBundle,
				openCanaryWindow: context.openCanaryWindow,
				closeCanaryWindow: context.closeCanaryWindow,
			});
		},
	};
}

export async function startTelclaudeLiveMcpAdminServer(
	options: StartTelclaudeLiveMcpAdminServerOptions,
): Promise<TelclaudeLiveMcpAdminServerHandle> {
	const socketPath = normalizeAbsoluteSocketPath(
		options.socketPath ?? readTelclaudeLiveMcpAdminSocketPath(),
	);
	const log = options.logger ?? logger;
	prepareSocketPath(socketPath);

	const sockets = new Set<Socket>();
	const server = http.createServer((request, response) => {
		handleAdminRequest(request, response, options, log).catch((error) => {
			log.warn({ error: errorMessage(error) }, "Hermes live MCP admin request failed");
			writeJson(response, 500, { error: "Internal server error." });
		});
	});
	server.on("connection", (socket) => {
		sockets.add(socket);
		socket.on("close", () => sockets.delete(socket));
	});

	await new Promise<void>((resolve, reject) => {
		const onError = (error: Error) => {
			server.off("listening", onListening);
			reject(error);
		};
		const onListening = () => {
			server.off("error", onError);
			try {
				fs.chmodSync(socketPath, 0o600);
				const mode = fs.statSync(socketPath).mode & 0o777;
				if (mode !== 0o600) {
					throw new Error(`socket mode is ${mode.toString(8)}, expected 600`);
				}
				log.info({ socketPath }, "Hermes live MCP admin UDS listening");
				resolve();
			} catch (error) {
				server.close();
				reject(error);
			}
		};
		server.once("error", onError);
		server.once("listening", onListening);
		server.listen(socketPath);
	});

	return {
		transport: "unix",
		socketPath,
		stop: () => closeAdminServer(server, socketPath, sockets),
	};
}

export async function requestTelclaudeLiveMcpProbeTokens(
	options: RequestTelclaudeLiveMcpProbeTokensOptions,
): Promise<TelclaudeLiveMcpProbeTokenBundle> {
	const body = await postAdminJson(
		TELCLAUDE_LIVE_MCP_ADMIN_PROBE_TOKENS_PATH,
		options.input,
		options.socketPath,
		options.timeoutMs,
	);
	return body as TelclaudeLiveMcpProbeTokenBundle;
}

export async function requestTelclaudeLiveMcpCanaryWindowOpen(
	options: RequestTelclaudeLiveMcpCanaryWindowOpenOptions = {},
): Promise<TelclaudeLiveMcpCanaryWindow> {
	const body = await postAdminJson(
		TELCLAUDE_LIVE_MCP_ADMIN_CANARY_OPEN_PATH,
		options.input ?? {},
		options.socketPath,
		options.timeoutMs,
	);
	return body as TelclaudeLiveMcpCanaryWindow;
}

export async function requestTelclaudeLiveMcpCanaryWindowClose(
	options: RequestTelclaudeLiveMcpCanaryWindowCloseOptions,
): Promise<TelclaudeLiveMcpCanaryWindowCloseResult> {
	const body = await postAdminJson(
		TELCLAUDE_LIVE_MCP_ADMIN_CANARY_CLOSE_PATH,
		options.input,
		options.socketPath,
		options.timeoutMs,
	);
	return body as TelclaudeLiveMcpCanaryWindowCloseResult;
}

async function postAdminJson(
	path: string,
	input: unknown,
	socketPath?: string,
	timeoutMs?: number,
): Promise<unknown> {
	const resolvedSocketPath = normalizeAbsoluteSocketPath(
		socketPath ?? readTelclaudeLiveMcpAdminSocketPath(),
	);
	const body = JSON.stringify(input);
	const authHeaders = buildInternalAuthHeaders("POST", path, body, { scope: OPERATOR_SCOPE });
	const response = await postJsonOverUnixSocket({
		socketPath: resolvedSocketPath,
		path,
		body,
		headers: authHeaders,
		timeoutMs,
	});
	if (response.statusCode !== 200) {
		const reason = responseJsonReason(response.body);
		throw new Error(
			`Hermes live MCP admin request failed (${response.statusCode})${reason ? `: ${reason}` : ""}`,
		);
	}
	return response.body;
}

const ADMIN_PATHS = new Set([
	TELCLAUDE_LIVE_MCP_ADMIN_PROBE_TOKENS_PATH,
	TELCLAUDE_LIVE_MCP_ADMIN_CANARY_OPEN_PATH,
	TELCLAUDE_LIVE_MCP_ADMIN_CANARY_CLOSE_PATH,
]);

async function handleAdminRequest(
	request: http.IncomingMessage,
	response: http.ServerResponse,
	options: StartTelclaudeLiveMcpAdminServerOptions,
	log: LiveMcpAdminLogger,
): Promise<void> {
	const url = request.url ?? "";
	if (request.method !== "POST" || !ADMIN_PATHS.has(url)) {
		writeJson(response, 404, { error: "Not found." });
		return;
	}

	let body: string;
	try {
		body = await readBody(request);
	} catch (error) {
		writeJson(response, 413, { error: errorMessage(error) });
		return;
	}

	const auth = verifyInternalAuth(request, body);
	if (!auth.ok) {
		writeJson(response, auth.status, { error: auth.error, reason: auth.reason });
		return;
	}
	if (auth.scope !== OPERATOR_SCOPE) {
		writeJson(response, 403, { error: "Forbidden.", reason: "operator scope required." });
		return;
	}

	let parsedJson: unknown;
	try {
		parsedJson = JSON.parse(body);
	} catch {
		writeJson(response, 400, { error: "Invalid JSON body." });
		return;
	}

	if (url === TELCLAUDE_LIVE_MCP_ADMIN_CANARY_OPEN_PATH) {
		if (!options.openCanaryWindow) {
			writeJson(response, 501, { error: "Canary window is not supported by this relay." });
			return;
		}
		const parsed = CanaryWindowOpenRequestSchema.safeParse(parsedJson);
		if (!parsed.success) {
			writeJson(response, 400, { error: "Invalid canary window open request." });
			return;
		}
		try {
			const window = options.openCanaryWindow(parsed.data);
			log.info(
				{
					issuedAtMs: window.issuedAtMs,
					expiresAtMs: window.expiresAtMs,
					profileId: parsed.data.profileId ?? "verify-live",
				},
				"Hermes live MCP canary window opened",
			);
			writeJson(response, 200, window);
		} catch (error) {
			if (error instanceof TelclaudeLiveMcpCanaryWindowBusyError) {
				writeJson(response, 409, { error: "Busy.", reason: error.message });
				return;
			}
			throw error;
		}
		return;
	}

	if (url === TELCLAUDE_LIVE_MCP_ADMIN_CANARY_CLOSE_PATH) {
		if (!options.closeCanaryWindow) {
			writeJson(response, 501, { error: "Canary window is not supported by this relay." });
			return;
		}
		const parsed = CanaryWindowCloseRequestSchema.safeParse(parsedJson);
		if (!parsed.success) {
			writeJson(response, 400, { error: "Invalid canary window close request." });
			return;
		}
		const result = options.closeCanaryWindow(parsed.data);
		log.info(result, "Hermes live MCP canary window closed");
		writeJson(response, 200, result);
		return;
	}

	const parsed = ProbeTokensRequestSchema.safeParse(parsedJson);
	if (!parsed.success) {
		writeJson(response, 400, { error: "Invalid probe token request." });
		return;
	}

	const bundle = options.issueProbeTokenBundle(toProbeTokenInput(parsed.data));
	log.info(
		{
			issuedAtMs: bundle.metadata.issuedAtMs,
			expiresAtMs: bundle.metadata.expiresAtMs,
			peerBound: bundle.metadata.peerBound,
			privateEndpointId: bundle.metadata.privateConnection.endpointId,
			wrongEndpointId: bundle.metadata.wrongConnection.endpointId,
		},
		"Hermes live MCP probe token bundle issued",
	);
	writeJson(response, 200, bundle);
}

function toProbeTokenInput(
	input: z.infer<typeof ProbeTokensRequestSchema>,
): TelclaudeLiveMcpRuntimeProbeTokenInput {
	return {
		privateConnection: input.privateConnection,
		...(input.offDomainConnection ? { offDomainConnection: input.offDomainConnection } : {}),
		wrongConnection: input.wrongConnection,
		privateAuthority: {
			...input.privateAuthority,
			domain: input.privateAuthority.domain as TelclaudeMcpDomain,
		},
		...(input.offDomainAuthority
			? {
					offDomainAuthority: {
						...input.offDomainAuthority,
						domain: input.offDomainAuthority.domain as TelclaudeMcpDomain,
					},
				}
			: {}),
		...(input.nowMs !== undefined ? { nowMs: input.nowMs } : {}),
		...(input.ttlMs !== undefined ? { ttlMs: input.ttlMs } : {}),
		...(input.peerAddress ? { peerAddress: input.peerAddress } : {}),
		...(input.offDomainPeerAddress ? { offDomainPeerAddress: input.offDomainPeerAddress } : {}),
	};
}

async function postJsonOverUnixSocket(options: {
	readonly socketPath: string;
	readonly path: string;
	readonly body: string;
	readonly headers: Record<string, string>;
	readonly timeoutMs?: number;
}): Promise<{ statusCode: number; body: unknown }> {
	return new Promise((resolve, reject) => {
		const request = http.request(
			{
				socketPath: options.socketPath,
				path: options.path,
				method: "POST",
				timeout: options.timeoutMs ?? 5_000,
				headers: {
					"Content-Type": "application/json",
					"Content-Length": Buffer.byteLength(options.body),
					...options.headers,
				},
			},
			(response) => {
				const chunks: Buffer[] = [];
				response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
				response.on("end", () => {
					const raw = Buffer.concat(chunks).toString("utf8");
					try {
						resolve({ statusCode: response.statusCode ?? 0, body: JSON.parse(raw) });
					} catch {
						resolve({ statusCode: response.statusCode ?? 0, body: { error: raw } });
					}
				});
			},
		);
		request.on("timeout", () => {
			request.destroy(new Error("Hermes live MCP admin socket request timed out"));
		});
		request.on("error", (error: NodeJS.ErrnoException) => {
			if (error.code === "ENOENT" || error.code === "ECONNREFUSED") {
				reject(
					new Error(
						`Hermes live MCP admin socket is not active at ${options.socketPath}. Start the relay with live MCP enabled and retry.`,
					),
				);
				return;
			}
			reject(error);
		});
		request.end(options.body);
	});
}

async function readBody(request: http.IncomingMessage): Promise<string> {
	const chunks: Buffer[] = [];
	let total = 0;
	for await (const chunk of request) {
		const buffer = Buffer.from(chunk);
		total += buffer.length;
		if (total > MAX_ADMIN_BODY_BYTES) {
			throw new Error("Request body too large.");
		}
		chunks.push(buffer);
	}
	return Buffer.concat(chunks).toString("utf8");
}

function writeJson(response: http.ServerResponse, status: number, payload: unknown): void {
	if (response.headersSent) return;
	const body = JSON.stringify(payload);
	response.writeHead(status, {
		"Content-Type": "application/json; charset=utf-8",
		"Content-Length": Buffer.byteLength(body),
	});
	response.end(body);
}

function prepareSocketPath(socketPath: string): void {
	const socketDir = path.dirname(socketPath);
	fs.mkdirSync(socketDir, { recursive: true, mode: 0o700 });
	fs.chmodSync(socketDir, 0o700);
	if (!fs.existsSync(socketPath)) return;
	const stat = fs.lstatSync(socketPath);
	if (!stat.isSocket()) {
		throw new Error(
			`Hermes live MCP admin socket path already exists and is not a socket: ${socketPath}`,
		);
	}
	fs.unlinkSync(socketPath);
}

function closeAdminServer(
	server: http.Server,
	socketPath: string,
	sockets: Set<Socket>,
): Promise<void> {
	for (const socket of sockets) socket.destroy();
	return new Promise((resolve, reject) => {
		server.close((error) => {
			try {
				if (fs.existsSync(socketPath)) fs.unlinkSync(socketPath);
			} catch {
				// best effort cleanup
			}
			if (error) reject(error);
			else resolve();
		});
	});
}

function normalizeAbsoluteSocketPath(socketPath: string): string {
	const trimmed = socketPath.trim();
	if (!trimmed) throw new Error("Hermes live MCP admin socket path is required");
	if (!path.isAbsolute(trimmed)) {
		throw new Error(`Hermes live MCP admin socket path must be absolute: ${socketPath}`);
	}
	return path.resolve(trimmed);
}

function responseJsonReason(body: unknown): string | null {
	if (!body || typeof body !== "object") return null;
	const record = body as Record<string, unknown>;
	const reason = record.reason ?? record.error;
	return typeof reason === "string" ? reason : null;
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}
