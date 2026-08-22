import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import pino from "pino";
import qrcode from "qrcode-terminal";
import {
	createWhatsAppAuthWriteTracker,
	type WhatsAppAuthWriteSnapshot,
} from "./auth-observe.js";
import {
	digestWhatsAppBridgeSendRequest,
	isWhatsAppGroupJid,
	jidToWhatsAppAddressRef,
	parseWhatsAppBridgeAttachments,
	parseWhatsAppDestinationJid,
	signWhatsAppInboundBridgeEvent,
	validateWhatsAppBridgeSend,
	WHATSAPP_BRIDGE_HEALTH_PATH,
	WHATSAPP_BRIDGE_SEND_PATH,
	WHATSAPP_BRIDGE_STATUS_PATH,
	WHATSAPP_INBOUND_BRIDGE_SCHEMA_VERSION,
	WHATSAPP_INBOUND_SIGNATURE_HEADER,
	type WhatsAppBridgeHeaders,
	type WhatsAppBridgeSendRequest,
	type WhatsAppInboundBridgeEvent,
	whatsappBridgeContentForAttachment,
	whatsappInboundBridgeBody,
} from "./contract.js";
import {
	WhatsAppBridgeIdempotencyJournal,
	type WhatsAppBridgeJournalResponse,
} from "./idempotency-journal.js";
import {
	contentFreeWhatsAppErrorClass,
	createContentFreeBaileysLogger,
	createRecentInboundMessageStore,
	logWhatsAppInboundForwardOutcome,
	summarizeWhatsAppUpsert,
} from "./inbound-observe.js";
import {
	isStaleWhatsAppBridgeGeneration,
	shouldCreateWhatsAppBridgeSocket,
	whatsappBridgeReconnectDelayMs,
} from "./reconnect.js";

const logger = pino({
	level: process.env.LOG_LEVEL ?? process.env.TELCLAUDE_LOG_LEVEL ?? "info",
	name: "whatsapp-bridge",
});

const PORT = Number(process.env.WHATSAPP_BRIDGE_PORT ?? 3004);
const DATA_DIR = process.env.WHATSAPP_BRIDGE_DATA_DIR ?? "/data";
const RELAY_INBOUND_URL =
	process.env.TELCLAUDE_RELAY_INBOUND_URL ?? "http://telclaude:8790/v1/whatsapp/inbound";
const INBOUND_SECRET = process.env.TELCLAUDE_WHATSAPP_INBOUND_SECRET?.trim();
const BRIDGE_SECRET = process.env.TELCLAUDE_WHATSAPP_BRIDGE_SECRET?.trim();
const MAX_BODY_BYTES = 30 * 1024 * 1024;
export const WHATSAPP_INBOUND_FORWARD_TIMEOUT_MS = 30_000;

export type WhatsAppBridgeBaileysSender = {
	sendMessage(
		jid: string,
		content: Record<string, unknown>,
		options: { readonly messageId: string },
	): Promise<{ key?: { id?: string } }>;
};

type BaileysSocket = WhatsAppBridgeBaileysSender & {
	readonly ev: {
		on(event: string, handler: (...args: unknown[]) => void): void;
	};
	readonly signalRepository: {
		readonly lidMapping: {
			getPNForLID(lid: string): Promise<string | null>;
		};
	};
	end?(error: Error | undefined): void;
};

type BaileysApi = {
	readonly default: (options: Record<string, unknown>) => BaileysSocket;
	readonly Browsers: {
		readonly macOS: (browser: string) => readonly [string, string, string];
	};
	readonly DisconnectReason: { readonly loggedOut: number };
	readonly fetchLatestBaileysVersion: () => Promise<{ readonly version: readonly number[] }>;
	readonly isHostedLidUser: (jid: string | undefined) => boolean | undefined;
	readonly isHostedPnUser: (jid: string | undefined) => boolean | undefined;
	readonly isLidUser: (jid: string | undefined) => boolean | undefined;
	readonly isPnUser: (jid: string | undefined) => boolean | undefined;
	readonly makeCacheableSignalKeyStore: (keys: unknown, logger: unknown) => unknown;
	readonly useMultiFileAuthState: (
		folder: string,
	) => Promise<{ readonly state: unknown; readonly saveCreds: () => Promise<void> }>;
	readonly downloadMediaMessage?: (
		message: unknown,
		type: "buffer",
		options: Record<string, unknown>,
		context: Record<string, unknown>,
	) => Promise<Buffer | Uint8Array>;
};

type BridgeStatus = {
	connected: boolean;
	state: "starting" | "waiting_for_pairing" | "connected" | "disconnected" | "logged_out";
	stopping: boolean;
	lastQrAtMs?: number;
	lastConnectionAtMs?: number;
	lastDisconnectAtMs?: number;
	lastDisconnectReason?: string;
	outboundAuthConfigured: boolean;
	inboundForwardingConfigured: boolean;
};

class WhatsAppBridgeRuntime {
	private socket: BaileysSocket | null = null;
	private starting: Promise<void> | null = null;
	private shutdownPromise: Promise<void> | null = null;
	private stopping = false;
	private generation = 0;
	private reconnectAttempt = 0;
	private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
	private readonly authDir: string;
	private readonly authWriteTracker = createWhatsAppAuthWriteTracker();
	private readonly idempotencyJournal: WhatsAppBridgeIdempotencyJournal;
	private readonly recentMessages = createRecentInboundMessageStore();
	private readonly sequenceByConversation = new Map<string, number>();
	private status: BridgeStatus = {
		connected: false,
		state: "starting",
		stopping: false,
		outboundAuthConfigured: Boolean(BRIDGE_SECRET),
		inboundForwardingConfigured: Boolean(INBOUND_SECRET),
	};

	constructor(dataDir: string) {
		this.authDir = path.join(dataDir, "auth");
		this.idempotencyJournal = new WhatsAppBridgeIdempotencyJournal({ dataDir });
	}

	snapshot(): BridgeStatus & WhatsAppAuthWriteSnapshot {
		return {
			...this.status,
			stopping: this.stopping,
			...this.authWriteTracker.snapshot(),
		};
	}

	start(): Promise<void> {
		if (this.stopping) return Promise.resolve();
		if (
			!shouldCreateWhatsAppBridgeSocket({
				connected: this.status.connected,
				hasSocket: this.socket !== null,
			})
		) {
			return Promise.resolve();
		}
		if (this.starting) return this.starting;
		this.starting = this.connect().finally(() => {
			this.starting = null;
		});
		return this.starting;
	}

	async send(
		request: WhatsAppBridgeSendRequest,
		requestDigest: `sha256:${string}`,
	): Promise<Record<string, unknown>> {
		if (this.stopping) {
			return {
				ok: false,
				code: "whatsapp_bridge_shutting_down",
				reason: "WhatsApp bridge is shutting down.",
				retryable: true,
			};
		}
		if (this.reconnectTimer && !this.status.connected) {
			return {
				ok: false,
				code: "whatsapp_bridge_not_connected",
				reason: "WhatsApp bridge is not paired or not connected.",
				retryable: true,
			};
		}
		await this.start();
		if (!this.socket || !this.status.connected) {
			return {
				ok: false,
				code: "whatsapp_bridge_not_connected",
				reason: "WhatsApp bridge is not paired or not connected.",
				retryable: true,
			};
		}

		const destination = parseWhatsAppDestinationJid(request);
		if (!destination.ok) {
			return { ok: false, code: destination.code, reason: destination.reason, retryable: false };
		}

		const socket = this.socket;
		const messageCount = Math.max(1, request.attachments?.length ?? 0);
		return this.idempotencyJournal.execute(
			{
				idempotencyKey: request.idempotencyKey,
				requestDigest,
				messageCount,
			},
			(messageIds) => sendWhatsAppBridgeRequest(socket, destination.jid, request, messageIds),
		);
	}

	private async connect(): Promise<void> {
		this.clearReconnectTimer();
		this.generation += 1;
		const generation = this.generation;
		this.endSocket(this.socket);
		this.socket = null;

		fs.mkdirSync(this.authDir, { recursive: true });
		const api = (await import("@whiskeysockets/baileys")) as unknown as BaileysApi;
		if (this.stopping || isStaleWhatsAppBridgeGeneration(generation, this.generation)) return;
		const { state, saveCreds } = await api.useMultiFileAuthState(this.authDir);
		if (this.stopping || isStaleWhatsAppBridgeGeneration(generation, this.generation)) return;
		if (!isRecord(state) || !("creds" in state) || !("keys" in state)) {
			throw new Error("WhatsApp auth state is missing creds or keys");
		}
		const { version } = await api.fetchLatestBaileysVersion();
		if (this.stopping || isStaleWhatsAppBridgeGeneration(generation, this.generation)) return;
		const baileysLogger = createContentFreeBaileysLogger(logger);
		const socket = api.default({
			auth: {
				creds: state.creds,
				keys: api.makeCacheableSignalKeyStore(state.keys, baileysLogger),
			},
			version,
			browser: api.Browsers.macOS("Chrome"),
			logger: baileysLogger,
			syncFullHistory: false,
			getMessage: (key: { readonly remoteJid?: string; readonly id?: string }) =>
				this.recentMessages.getMessage(key),
		});

		this.socket = socket;
		socket.ev.on("creds.update", () => {
			if (this.stopping || isStaleWhatsAppBridgeGeneration(generation, this.generation)) return;
			void this.authWriteTracker
				.enqueue(saveCreds)
				.catch((err) =>
					logger.warn(
						{ errorClass: contentFreeWhatsAppErrorClass(err) },
						"WhatsApp auth write failed",
					),
				);
		});
		socket.ev.on("connection.update", (update) => {
			if (isStaleWhatsAppBridgeGeneration(generation, this.generation)) return;
			this.handleConnectionUpdate(api, socket, generation, update);
		});
		socket.ev.on("messages.upsert", (event) => {
			if (isStaleWhatsAppBridgeGeneration(generation, this.generation)) return;
			void this.handleMessages(api, socket, event).catch((err) =>
				logWhatsAppInboundForwardOutcome(logger, {
					kind: "failed",
					error: err,
				}),
			);
		});
	}

	stop(): Promise<void> {
		if (this.shutdownPromise) return this.shutdownPromise;
		this.stopping = true;
		this.clearReconnectTimer();
		this.generation += 1;
		const socket = this.socket;
		this.socket = null;
		this.status = {
			...this.status,
			connected: false,
			state: "disconnected",
			lastDisconnectAtMs: Date.now(),
			lastDisconnectReason: "shutdown",
		};
		this.endSocket(socket);

		const starting = this.starting;
		this.shutdownPromise = (async () => {
			await starting?.catch(() => undefined);
			await this.authWriteTracker.drain();
		})();
		return this.shutdownPromise;
	}

	private handleConnectionUpdate(
		api: BaileysApi,
		socket: BaileysSocket,
		generation: number,
		update: unknown,
	): void {
		if (isStaleWhatsAppBridgeGeneration(generation, this.generation)) return;
		const record = isRecord(update) ? update : {};
		const qr = typeof record.qr === "string" ? record.qr : undefined;
		if (qr) {
			this.status = {
				...this.status,
				connected: false,
				state: "waiting_for_pairing",
				lastQrAtMs: Date.now(),
			};
			logger.info("WhatsApp pairing QR received; scan it with the operator device.");
			qrcode.generate(qr, { small: true });
		}

		const connection = typeof record.connection === "string" ? record.connection : undefined;
		if (connection === "open") {
			this.reconnectAttempt = 0;
			this.clearReconnectTimer();
			this.status = {
				...this.status,
				connected: true,
				state: "connected",
				lastConnectionAtMs: Date.now(),
				lastDisconnectReason: undefined,
			};
			logger.info("WhatsApp bridge connected.");
			return;
		}
		if (connection !== "close") return;

		const statusCode = readDisconnectStatusCode(record.lastDisconnect);
		const loggedOut = statusCode === api.DisconnectReason.loggedOut;
		this.generation += 1;
		this.endSocket(socket);
		if (this.socket === socket) this.socket = null;
		this.status = {
			...this.status,
			connected: false,
			state: loggedOut ? "logged_out" : "disconnected",
			lastDisconnectAtMs: Date.now(),
			lastDisconnectReason: statusCode ? `status=${statusCode}` : "unknown",
		};
		logger.warn(
			{ statusCode, loggedOut },
			loggedOut ? "WhatsApp bridge logged out." : "WhatsApp bridge disconnected.",
		);
		this.scheduleReconnect(statusCode, loggedOut);
	}

	private scheduleReconnect(statusCode: number | null, loggedOut: boolean): void {
		this.clearReconnectTimer();
		const delayMs = whatsappBridgeReconnectDelayMs({
			loggedOut,
			statusCode,
			attempt: this.reconnectAttempt,
		});
		if (delayMs === null) return;
		this.reconnectAttempt += 1;
		logger.info(
			{ delayMs, statusCode, attempt: this.reconnectAttempt },
			"WhatsApp bridge reconnect scheduled",
		);
		this.reconnectTimer = setTimeout(() => {
			this.reconnectTimer = null;
			void this.start().catch((err) =>
				logger.warn({ err: errorMessage(err) }, "WhatsApp bridge reconnect failed"),
			);
		}, delayMs);
		this.reconnectTimer.unref();
	}

	private clearReconnectTimer(): void {
		if (!this.reconnectTimer) return;
		clearTimeout(this.reconnectTimer);
		this.reconnectTimer = null;
	}

	private endSocket(socket: BaileysSocket | null): void {
		if (!socket) return;
		try {
			socket.end?.(undefined);
		} catch {
			// already closed
		}
	}

	private async handleMessages(
		api: BaileysApi,
		socket: BaileysSocket,
		event: unknown,
	): Promise<void> {
		logger.info(summarizeWhatsAppUpsert(event), "WhatsApp inbound upsert");
		const record = isRecord(event) ? event : {};
		const messages = Array.isArray(record.messages) ? record.messages : [];
		for (const message of messages) {
			if (isRecord(message) && isRecord(message.key)) {
				this.recentMessages.remember(message.key, message.message);
			}
		}
		if (!INBOUND_SECRET) {
			logWhatsAppInboundForwardOutcome(logger, {
				kind: "skipped",
				reason: "inbound_unconfigured",
			});
			return;
		}
		for (const message of messages) {
			await this.forwardMessage(api, socket, message);
		}
	}

	private async forwardMessage(
		api: BaileysApi,
		socket: BaileysSocket,
		message: unknown,
	): Promise<void> {
		const inboundSecret = INBOUND_SECRET;
		if (!inboundSecret) return;

		if (!isRecord(message)) {
			logWhatsAppInboundForwardOutcome(logger, { kind: "skipped", reason: "missing_id" });
			return;
		}
		const key = isRecord(message.key) ? message.key : {};
		if (key.fromMe === true) {
			logWhatsAppInboundForwardOutcome(logger, { kind: "skipped", reason: "from_me" });
			return;
		}
		const remoteJid = typeof key.remoteJid === "string" ? key.remoteJid : undefined;
		const messageId = typeof key.id === "string" ? key.id : undefined;
		if (!remoteJid || !messageId) {
			logWhatsAppInboundForwardOutcome(logger, { kind: "skipped", reason: "missing_id" });
			return;
		}

		const chatKind = isWhatsAppGroupJid(remoteJid) ? "group" : "direct";
		if (chatKind === "group") {
			logWhatsAppInboundForwardOutcome(logger, { kind: "skipped", reason: "group" });
			return;
		}

		const identity = await resolveWhatsAppInboundDirectIdentity(key, {
			isPhoneJid: (jid) => api.isPnUser(jid) === true || api.isHostedPnUser(jid) === true,
			isLidJid: (jid) => api.isLidUser(jid) === true || api.isHostedLidUser(jid) === true,
			getPhoneJidForLid: (lid) => socket.signalRepository.lidMapping.getPNForLID(lid),
		});
		if (!identity) {
			logWhatsAppInboundForwardOutcome(logger, {
				kind: "skipped",
				reason: "unresolved_sender",
			});
			return;
		}

		const receivedAtMs = Date.now();
		const relayConversationId = identity.conversationKey;
		const eventPayload: WhatsAppInboundBridgeEvent = {
			schemaVersion: WHATSAPP_INBOUND_BRIDGE_SCHEMA_VERSION,
			eventId: `wa:${remoteJid}:${messageId}`,
			messageId,
			cursorSequence: this.nextSequence(relayConversationId, receivedAtMs),
			chatKind,
			senderAddressRef: identity.senderAddressRef,
			conversationKey: relayConversationId,
			...extractText(message.message),
			attachments: await extractAttachments(api, message),
			receivedAtMs,
		};

		const body = whatsappInboundBridgeBody(eventPayload);
		try {
			const response = await fetch(RELAY_INBOUND_URL, {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					Accept: "application/json",
					[WHATSAPP_INBOUND_SIGNATURE_HEADER]: signWhatsAppInboundBridgeEvent(
						eventPayload,
						inboundSecret,
					),
				},
				body,
				signal: AbortSignal.timeout(WHATSAPP_INBOUND_FORWARD_TIMEOUT_MS),
			});
			if (!response.ok) {
				logWhatsAppInboundForwardOutcome(logger, {
					kind: "rejected",
					status: response.status,
				});
				return;
			}
			logWhatsAppInboundForwardOutcome(logger, {
				kind: "forwarded",
				status: response.status,
			});
		} catch (error) {
			logWhatsAppInboundForwardOutcome(logger, {
				kind: "failed",
				error,
			});
		}
	}

	private nextSequence(conversationKey: string, receivedAtMs: number): number {
		const previous = this.sequenceByConversation.get(conversationKey) ?? 0;
		const next = Math.max(Math.floor(receivedAtMs), previous + 1);
		this.sequenceByConversation.set(conversationKey, next);
		return next;
	}
}

export type WhatsAppInboundDirectIdentity = {
	readonly senderAddressRef: string;
	readonly conversationKey: string;
};

export async function resolveWhatsAppInboundDirectIdentity(
	key: Record<string, unknown>,
	options: {
		readonly isPhoneJid: (jid: string) => boolean;
		readonly isLidJid: (jid: string) => boolean;
		readonly getPhoneJidForLid: (lid: string) => Promise<string | null>;
	},
): Promise<WhatsAppInboundDirectIdentity | null> {
	const primaryJid = typeof key.remoteJid === "string" ? key.remoteJid : null;
	if (!primaryJid) return null;
	const alternateJid = typeof key.remoteJidAlt === "string" ? key.remoteJidAlt : null;

	let phoneJid = [primaryJid, alternateJid].find((candidate): candidate is string =>
		Boolean(candidate && options.isPhoneJid(candidate)),
	);
	if (!phoneJid && options.isLidJid(primaryJid)) {
		try {
			phoneJid = (await options.getPhoneJidForLid(primaryJid)) ?? undefined;
		} catch {
			return null;
		}
	}
	if (!phoneJid || !options.isPhoneJid(phoneJid)) return null;

	const senderAddressRef = jidToWhatsAppAddressRef(phoneJid);
	if (!senderAddressRef) return null;
	const phoneDigits = senderAddressRef.slice("whatsapp:+".length);
	return {
		senderAddressRef,
		conversationKey: `whatsapp:${phoneDigits}@s.whatsapp.net`,
	};
}

export async function sendWhatsAppBridgeRequest(
	socket: WhatsAppBridgeBaileysSender,
	destinationJid: string,
	request: WhatsAppBridgeSendRequest,
	messageIds: readonly string[],
): Promise<WhatsAppBridgeJournalResponse> {
	try {
		const sentIds: string[] = [];
		const attachments = request.attachments ?? [];
		if (attachments.length === 0) {
			const messageId = requireMessageId(messageIds, 0);
			const sent = await socket.sendMessage(
				destinationJid,
				{ text: request.body.trim() || " " },
				{ messageId },
			);
			sentIds.push(sent.key?.id ?? messageId);
		} else {
			for (const [index, attachment] of attachments.entries()) {
				const content = whatsappBridgeContentForAttachment(
					attachment,
					index === 0 ? request.body : "",
				);
				const messageId = requireMessageId(messageIds, index);
				const sent = await socket.sendMessage(destinationJid, content, { messageId });
				sentIds.push(sent.key?.id ?? messageId);
			}
		}
		return {
			ok: true,
			...(sentIds[0] ? { platformMessageId: sentIds[0] } : {}),
			...(sentIds.at(-1) ? { observedThreadMessageId: sentIds.at(-1) } : {}),
		};
	} catch (err) {
		logger.warn({ err: errorMessage(err), outboundRef: request.outboundRef }, "send failed");
		return {
			ok: false,
			code: "whatsapp_bridge_send_failed",
			reason: "WhatsApp bridge send failed.",
			retryable: true,
		};
	}
}

function requireMessageId(messageIds: readonly string[], index: number): string {
	const messageId = messageIds[index];
	if (!messageId) throw new Error(`missing deterministic WhatsApp message id for part ${index}`);
	return messageId;
}

async function main(): Promise<void> {
	const runtime = new WhatsAppBridgeRuntime(DATA_DIR);
	void runtime
		.start()
		.catch((err) =>
			logger.warn({ err: errorMessage(err) }, "initial WhatsApp bridge start failed"),
		);

	const server = http.createServer((req, res) => {
		void handleRequest(runtime, req, res).catch((err) => {
			logger.error({ err: errorMessage(err) }, "request failed");
			writeJson(res, 500, { ok: false, code: "internal_error", reason: "Internal error." });
		});
	});

	server.listen(PORT, "0.0.0.0", () => {
		logger.info({ port: PORT, dataDir: DATA_DIR }, "WhatsApp bridge listening");
	});

	let shutdownPromise: Promise<void> | null = null;
	const requestShutdown = (signal: string): void => {
		if (shutdownPromise) return;
		shutdownPromise = (async () => {
			logger.info({ signal }, "WhatsApp bridge shutting down");
			await runtime.stop();
			await new Promise<void>((resolve) => {
				server.close((error) => {
					if (error) {
						logger.warn(
							{ errorClass: contentFreeWhatsAppErrorClass(error) },
							"WhatsApp bridge HTTP server close failed",
						);
					}
					resolve();
				});
			});
			process.exit(0);
		})();
		void shutdownPromise.catch((error) => {
			logger.error(
				{ errorClass: contentFreeWhatsAppErrorClass(error) },
				"WhatsApp bridge shutdown failed",
			);
			process.exit(1);
		});
	};
	process.on("SIGTERM", () => requestShutdown("SIGTERM"));
	process.on("SIGINT", () => requestShutdown("SIGINT"));
}

async function handleRequest(
	runtime: WhatsAppBridgeRuntime,
	req: http.IncomingMessage,
	res: http.ServerResponse,
): Promise<void> {
	const pathName = new URL(req.url ?? "/", "http://whatsapp-bridge").pathname;
	if (req.method === "GET" && pathName === WHATSAPP_BRIDGE_HEALTH_PATH) {
		writeJson(res, 200, { ok: true, ...runtime.snapshot() });
		return;
	}
	if (req.method === "GET" && pathName === WHATSAPP_BRIDGE_STATUS_PATH) {
		writeJson(res, 200, { ok: true, ...runtime.snapshot() });
		return;
	}
	if (req.method !== "POST" || pathName !== WHATSAPP_BRIDGE_SEND_PATH) {
		writeJson(res, 404, { ok: false, code: "not_found" });
		return;
	}

	const body = await readBody(req, MAX_BODY_BYTES);
	let parsed: unknown;
	try {
		parsed = JSON.parse(body);
	} catch {
		writeJson(res, 400, { ok: false, code: "invalid_json", reason: "Body must be JSON." });
		return;
	}

	const validation = validateWhatsAppBridgeSend(
		parsed,
		req.headers as WhatsAppBridgeHeaders,
		BRIDGE_SECRET ?? "",
	);
	if (!validation.ok) {
		writeJson(res, validation.status, {
			ok: false,
			code: validation.code,
			reason: validation.reason,
			retryable: false,
		});
		return;
	}

	const request = parseSendRequest(parsed);
	if (!request.ok) {
		writeJson(res, 400, {
			ok: false,
			code: request.code,
			reason: request.reason,
			retryable: false,
		});
		return;
	}

	writeJson(res, 200, await runtime.send(request.request, digestWhatsAppBridgeSendRequest(parsed)));
}

function parseSendRequest(
	value: unknown,
):
	| { readonly ok: true; readonly request: WhatsAppBridgeSendRequest }
	| { readonly ok: false; readonly code: string; readonly reason: string } {
	if (!isRecord(value)) {
		return { ok: false, code: "invalid_request", reason: "Request must be an object." };
	}
	const destination = isRecord(value.destination) ? value.destination : null;
	if (!destination) {
		return { ok: false, code: "invalid_request", reason: "destination is required." };
	}
	const request: WhatsAppBridgeSendRequest = {
		schemaVersion: String(value.schemaVersion ?? ""),
		outboundRef: String(value.outboundRef ?? ""),
		idempotencyKey: String(value.idempotencyKey ?? ""),
		destination: {
			kind: String(destination.kind ?? ""),
			...(typeof destination.addressRef === "string" ? { addressRef: destination.addressRef } : {}),
		},
		body: typeof value.body === "string" ? value.body : "",
		attachments: parseWhatsAppBridgeAttachments(value.attachments),
	};
	return { ok: true, request };
}

function extractText(message: unknown): { readonly text?: string } {
	const text = extractTextValue(message);
	return text ? { text } : {};
}

function extractTextValue(message: unknown): string | undefined {
	if (!isRecord(message)) return undefined;
	if (typeof message.conversation === "string") return message.conversation;
	if (
		isRecord(message.extendedTextMessage) &&
		typeof message.extendedTextMessage.text === "string"
	) {
		return message.extendedTextMessage.text;
	}
	for (const key of ["imageMessage", "videoMessage", "documentMessage"] as const) {
		const entry = message[key];
		if (isRecord(entry) && typeof entry.caption === "string") return entry.caption;
	}
	for (const key of ["ephemeralMessage", "viewOnceMessage", "viewOnceMessageV2"] as const) {
		const nested = message[key];
		if (isRecord(nested)) {
			const found = extractTextValue(nested.message);
			if (found) return found;
		}
	}
	if (isRecord(message.documentWithCaptionMessage)) {
		return extractTextValue(message.documentWithCaptionMessage.message);
	}
	return undefined;
}

async function extractAttachments(
	api: BaileysApi,
	message: unknown,
): Promise<WhatsAppInboundBridgeEvent["attachments"]> {
	const mediaType = mediaTypeForMessage(isRecord(message) ? message.message : undefined);
	if (!mediaType || !api.downloadMediaMessage) return [];
	try {
		const downloaded = await api.downloadMediaMessage(
			message,
			"buffer",
			{},
			{ logger: pino({ level: "silent" }) },
		);
		const bytes = Buffer.from(downloaded);
		if (bytes.byteLength === 0) return [];
		return [{ mediaType, bytesBase64: bytes.toString("base64"), scanState: "pending" }];
	} catch (err) {
		logger.warn({ err: errorMessage(err) }, "media download failed; forwarding text only");
		return [];
	}
}

function mediaTypeForMessage(message: unknown): string | null {
	const unwrapped = unwrapMessage(message);
	if (!isRecord(unwrapped)) return null;
	for (const key of [
		"imageMessage",
		"videoMessage",
		"audioMessage",
		"documentMessage",
		"stickerMessage",
	]) {
		const entry = unwrapped[key];
		if (isRecord(entry) && typeof entry.mimetype === "string") return entry.mimetype;
	}
	return null;
}

function unwrapMessage(message: unknown): unknown {
	if (!isRecord(message)) return message;
	for (const key of ["ephemeralMessage", "viewOnceMessage", "viewOnceMessageV2"] as const) {
		const nested = message[key];
		if (isRecord(nested) && nested.message) return unwrapMessage(nested.message);
	}
	if (isRecord(message.documentWithCaptionMessage)) {
		return unwrapMessage(message.documentWithCaptionMessage.message);
	}
	return message;
}

function readDisconnectStatusCode(value: unknown): number | null {
	if (!isRecord(value)) return null;
	const error = isRecord(value.error) ? value.error : {};
	const output = isRecord(error.output) ? error.output : {};
	const statusCode = output.statusCode ?? error.statusCode;
	return typeof statusCode === "number" ? statusCode : null;
}

function readBody(req: http.IncomingMessage, limit: number): Promise<string> {
	return new Promise((resolve, reject) => {
		let size = 0;
		const chunks: Buffer[] = [];
		req.on("data", (chunk: Buffer) => {
			size += chunk.byteLength;
			if (size > limit) {
				reject(new Error("request body too large"));
				req.destroy();
				return;
			}
			chunks.push(chunk);
		});
		req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
		req.on("error", reject);
	});
}

function writeJson(
	res: http.ServerResponse,
	status: number,
	payload: Record<string, unknown>,
): void {
	if (res.headersSent) return;
	res.writeHead(status, { "Content-Type": "application/json" });
	res.end(JSON.stringify(payload));
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function errorMessage(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	void main().catch((err) => {
		logger.error({ err: errorMessage(err) }, "WhatsApp bridge failed to start");
		process.exit(1);
	});
}
