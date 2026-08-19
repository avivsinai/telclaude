const BAILEYS_LOG_KINDS: ReadonlyArray<readonly [needle: string, kind: string]> = [
	["failed to decrypt", "decrypt_failed"],
	["placeholder", "placeholder_resend"],
	["unavailable", "unavailable_skipped"],
	["missing keys", "missing_keys"],
	["no session", "no_session"],
	["ciphertext", "ciphertext"],
	["decrypt", "decrypt_failed"],
	["retry", "retry"],
];

export type WhatsAppUpsertSummary = {
	readonly type: string;
	readonly count: number;
	readonly fromMe: number;
	readonly missingId: number;
	readonly hasContent: number;
	readonly ciphertextStub: number;
};

export type ContentFreeLogSink = {
	debug?(bindings: { readonly component: "baileys" }, msg: string): void;
	info(bindings: { readonly component: "baileys" }, msg: string): void;
	warn(bindings: { readonly component: "baileys" }, msg: string): void;
	error(bindings: { readonly component: "baileys" }, msg: string): void;
};

export type ContentFreeBaileysLogger = {
	level: string;
	child(bindings: Record<string, unknown>): ContentFreeBaileysLogger;
	trace(obj: unknown, msg?: string): void;
	debug(obj: unknown, msg?: string): void;
	info(obj: unknown, msg?: string): void;
	warn(obj: unknown, msg?: string): void;
	error(obj: unknown, msg?: string): void;
};

export type RecentInboundMessageStore = {
	remember(key: Record<string, unknown>, content: unknown): void;
	getMessage(key: { readonly remoteJid?: string; readonly id?: string }): Promise<unknown>;
};

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function rawBaileysLogText(obj: unknown, msg?: string): string {
	if (typeof msg === "string" && msg.trim()) return msg;
	if (typeof obj === "string" && obj.trim()) return obj;
	if (isRecord(obj) && typeof obj.msg === "string" && obj.msg.trim()) return obj.msg;
	return "";
}

export function classifyBaileysLogKind(text: string): string {
	const lower = text.toLowerCase();
	for (const [needle, kind] of BAILEYS_LOG_KINDS) {
		if (lower.includes(needle)) return kind;
	}
	return "baileys";
}

export function extractContentFreeBaileysLogText(obj: unknown, msg?: string): string {
	return classifyBaileysLogKind(rawBaileysLogText(obj, msg));
}

export function summarizeWhatsAppUpsert(event: unknown): WhatsAppUpsertSummary {
	const record = isRecord(event) ? event : {};
	const type = typeof record.type === "string" && record.type.trim() ? record.type : "unknown";
	const messages = Array.isArray(record.messages) ? record.messages : [];
	let fromMe = 0;
	let missingId = 0;
	let hasContent = 0;
	let ciphertextStub = 0;
	for (const message of messages) {
		if (!isRecord(message)) {
			missingId += 1;
			continue;
		}
		const key = isRecord(message.key) ? message.key : {};
		if (key.fromMe === true) fromMe += 1;
		const messageId = typeof key.id === "string" ? key.id : undefined;
		if (!messageId) missingId += 1;
		if (isRecord(message.message)) {
			hasContent += 1;
		} else if (typeof message.messageStubType === "number") {
			ciphertextStub += 1;
		}
	}
	return {
		type,
		count: messages.length,
		fromMe,
		missingId,
		hasContent,
		ciphertextStub,
	};
}

export function createContentFreeBaileysLogger(sink: ContentFreeLogSink): ContentFreeBaileysLogger {
	const log = (level: "info" | "warn" | "error", obj: unknown, msg?: string): void => {
		const kind = extractContentFreeBaileysLogText(obj, msg);
		if (level === "info" && kind === "baileys") return;
		sink[level]({ component: "baileys" }, kind);
	};
	const logger: ContentFreeBaileysLogger = {
		level: "debug",
		child() {
			return logger;
		},
		trace() {},
		debug(obj, msg) {
			log("info", obj, msg);
		},
		info(obj, msg) {
			log("info", obj, msg);
		},
		warn(obj, msg) {
			log("warn", obj, msg);
		},
		error(obj, msg) {
			log("error", obj, msg);
		},
	};
	return logger;
}

export function createRecentInboundMessageStore(maxEntries = 64): RecentInboundMessageStore {
	const cache = new Map<string, unknown>();
	return {
		remember(key, content) {
			const remoteJid = typeof key.remoteJid === "string" ? key.remoteJid : undefined;
			const id = typeof key.id === "string" ? key.id : undefined;
			if (!remoteJid || !id || content === undefined) return;
			const cacheId = `${remoteJid}:${id}`;
			if (cache.has(cacheId)) cache.delete(cacheId);
			cache.set(cacheId, content);
			while (cache.size > maxEntries) {
				const oldest = cache.keys().next().value;
				if (typeof oldest !== "string") break;
				cache.delete(oldest);
			}
		},
		async getMessage(key) {
			if (!key.remoteJid || !key.id) return undefined;
			const cacheId = `${key.remoteJid}:${key.id}`;
			const content = cache.get(cacheId);
			if (content === undefined) return undefined;
			cache.delete(cacheId);
			cache.set(cacheId, content);
			return content;
		},
	};
}
