import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import pino from "pino";
import qrcode from "qrcode-terminal";
import {
	isWhatsAppGroupJid,
	jidToWhatsAppAddressRef,
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
	whatsappInboundBridgeBody,
} from "./contract.js";

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

type BaileysSocket = {
	readonly ev: {
		on(event: string, handler: (...args: unknown[]) => void): void;
	};
	sendMessage(jid: string, content: Record<string, unknown>): Promise<{ key?: { id?: string } }>;
};

type BaileysApi = {
	readonly default: (options: Record<string, unknown>) => BaileysSocket;
	readonly DisconnectReason: { readonly loggedOut: number };
	readonly fetchLatestBaileysVersion: () => Promise<{ readonly version: readonly number[] }>;
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
	lastQrAtMs?: number;
	lastConnectionAtMs?: number;
	lastDisconnectAtMs?: number;
	lastDisconnectReason?: string;
	outboundAuthConfigured: boolean;
	inboundForwardingConfigured: boolean;
};

type WhatsAppBridgeRequestAttachment = NonNullable<
	WhatsAppBridgeSendRequest["attachments"]
>[number];

class WhatsAppBridgeRuntime {
	private socket: BaileysSocket | null = null;
	private starting: Promise<void> | null = null;
	private readonly authDir: string;
	private readonly sequenceByConversation = new Map<string, number>();
	private status: BridgeStatus = {
		connected: false,
		state: "starting",
		outboundAuthConfigured: Boolean(BRIDGE_SECRET),
		inboundForwardingConfigured: Boolean(INBOUND_SECRET),
	};

	constructor(dataDir: string) {
		this.authDir = path.join(dataDir, "auth");
	}

	snapshot(): BridgeStatus {
		return { ...this.status };
	}

	start(): Promise<void> {
		if (this.starting) return this.starting;
		this.starting = this.connect().finally(() => {
			this.starting = null;
		});
		return this.starting;
	}

	async send(request: WhatsAppBridgeSendRequest): Promise<Record<string, unknown>> {
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

		try {
			const sentIds: string[] = [];
			const attachments = request.attachments ?? [];
			if (attachments.length === 0) {
				const sent = await this.socket.sendMessage(destination.jid, {
					text: request.body.trim() || " ",
				});
				if (sent.key?.id) sentIds.push(sent.key.id);
			} else {
				for (const [index, attachment] of attachments.entries()) {
					const content = contentForAttachment(attachment, index === 0 ? request.body : "");
					const sent = await this.socket.sendMessage(destination.jid, content);
					if (sent.key?.id) sentIds.push(sent.key.id);
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
				reason: errorMessage(err),
				retryable: true,
			};
		}
	}

	private async connect(): Promise<void> {
		fs.mkdirSync(this.authDir, { recursive: true });
		const api = (await import("@whiskeysockets/baileys")) as unknown as BaileysApi;
		const { state, saveCreds } = await api.useMultiFileAuthState(this.authDir);
		const { version } = await api.fetchLatestBaileysVersion();
		const socket = api.default({
			auth: state,
			version,
			browser: ["Telclaude", "Chrome", "1.0"],
			logger: pino({ level: "silent" }),
			syncFullHistory: false,
		});

		this.socket = socket;
		socket.ev.on("creds.update", () => {
			void saveCreds().catch((err) => logger.warn({ err: errorMessage(err) }, "save creds failed"));
		});
		socket.ev.on("connection.update", (update) => this.handleConnectionUpdate(api, update));
		socket.ev.on("messages.upsert", (event) => {
			void this.handleMessages(api, event).catch((err) =>
				logger.warn({ err: errorMessage(err) }, "inbound forwarding failed"),
			);
		});
	}

	private handleConnectionUpdate(api: BaileysApi, update: unknown): void {
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
		this.status = {
			...this.status,
			connected: false,
			state: loggedOut ? "logged_out" : "disconnected",
			lastDisconnectAtMs: Date.now(),
			lastDisconnectReason: statusCode ? `status=${statusCode}` : "unknown",
		};
		this.socket = null;
		logger.warn(
			{ statusCode, loggedOut },
			loggedOut ? "WhatsApp bridge logged out." : "WhatsApp bridge disconnected.",
		);
		if (!loggedOut) {
			setTimeout(() => {
				void this.start().catch((err) =>
					logger.warn({ err: errorMessage(err) }, "WhatsApp bridge reconnect failed"),
				);
			}, 5_000).unref();
		}
	}

	private async handleMessages(api: BaileysApi, event: unknown): Promise<void> {
		if (!INBOUND_SECRET) return;
		const record = isRecord(event) ? event : {};
		const messages = Array.isArray(record.messages) ? record.messages : [];
		for (const message of messages) {
			await this.forwardMessage(api, message);
		}
	}

	private async forwardMessage(api: BaileysApi, message: unknown): Promise<void> {
		const inboundSecret = INBOUND_SECRET;
		if (!inboundSecret) return;

		if (!isRecord(message)) return;
		const key = isRecord(message.key) ? message.key : {};
		if (key.fromMe === true) return;
		const remoteJid = typeof key.remoteJid === "string" ? key.remoteJid : undefined;
		const messageId = typeof key.id === "string" ? key.id : undefined;
		if (!remoteJid || !messageId) return;

		const chatKind = isWhatsAppGroupJid(remoteJid) ? "group" : "direct";
		if (chatKind === "group") {
			logger.info({ remoteJid, messageId }, "skipping WhatsApp group inbound event");
			return;
		}

		const senderJid =
			typeof key.participant === "string" && key.participant ? key.participant : remoteJid;
		const senderAddressRef = jidToWhatsAppAddressRef(senderJid);
		if (!senderAddressRef) {
			logger.warn({ senderJid }, "skipping inbound message with non-phone sender JID");
			return;
		}

		const receivedAtMs = Date.now();
		const relayConversationId = ["whatsapp", remoteJid].join(":");
		const eventPayload: WhatsAppInboundBridgeEvent = {
			schemaVersion: WHATSAPP_INBOUND_BRIDGE_SCHEMA_VERSION,
			eventId: `wa:${remoteJid}:${messageId}`,
			messageId,
			cursorSequence: this.nextSequence(relayConversationId, receivedAtMs),
			chatKind,
			senderAddressRef,
			conversationKey: relayConversationId,
			...extractText(message.message),
			attachments: await extractAttachments(api, message),
			receivedAtMs,
		};

		const body = whatsappInboundBridgeBody(eventPayload);
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
		});
		if (!response.ok) {
			const text = await response.text().catch(() => "");
			logger.warn(
				{ status: response.status, messageId, text: text.slice(0, 300) },
				"inbound relay rejected WhatsApp event",
			);
		}
	}

	private nextSequence(conversationKey: string, receivedAtMs: number): number {
		const previous = this.sequenceByConversation.get(conversationKey) ?? 0;
		const next = Math.max(Math.floor(receivedAtMs), previous + 1);
		this.sequenceByConversation.set(conversationKey, next);
		return next;
	}
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

	process.on("SIGTERM", () => server.close(() => process.exit(0)));
	process.on("SIGINT", () => server.close(() => process.exit(0)));
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

	writeJson(res, 200, await runtime.send(request.request));
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
		attachments: Array.isArray(value.attachments)
			? value.attachments.filter(isBridgeAttachment)
			: [],
	};
	return { ok: true, request };
}

function isBridgeAttachment(value: unknown): value is WhatsAppBridgeRequestAttachment {
	return (
		isRecord(value) && typeof value.mediaType === "string" && typeof value.bytesBase64 === "string"
	);
}

function contentForAttachment(
	attachment: WhatsAppBridgeRequestAttachment,
	caption: string,
): Record<string, unknown> {
	const buffer = Buffer.from(attachment.bytesBase64, "base64");
	const mimetype = attachment.mediaType;
	const captionValue = caption.trim();
	if (mimetype.startsWith("image/")) {
		return { image: buffer, ...(captionValue ? { caption: captionValue } : {}) };
	}
	if (mimetype.startsWith("video/")) {
		return { video: buffer, mimetype, ...(captionValue ? { caption: captionValue } : {}) };
	}
	if (mimetype.startsWith("audio/")) {
		return { audio: buffer, mimetype };
	}
	return {
		document: buffer,
		mimetype,
		fileName: attachment.quarantineId ?? "attachment",
		...(captionValue ? { caption: captionValue } : {}),
	};
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

void main().catch((err) => {
	logger.error({ err: errorMessage(err) }, "WhatsApp bridge failed to start");
	process.exit(1);
});
