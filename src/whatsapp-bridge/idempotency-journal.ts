import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { deterministicWhatsAppBridgeMessageId } from "./contract.js";

export const WHATSAPP_BRIDGE_JOURNAL_RETENTION_MS = 30 * 24 * 60 * 60 * 1_000;

const JOURNAL_VERSION = 1;
const JOURNAL_DIRECTORY = "idempotency-journal";
const JOURNAL_FILE_MODE = 0o600;
const JOURNAL_DIRECTORY_MODE = 0o700;

export type WhatsAppBridgeJournalResponse =
	| {
			readonly ok: true;
			readonly platformMessageId?: string;
			readonly observedThreadMessageId?: string;
	  }
	| {
			readonly ok: false;
			readonly code: string;
			readonly reason?: string;
			readonly retryable: boolean;
	  };

export type WhatsAppBridgeJournalExecuteInput = {
	readonly idempotencyKey: string;
	readonly requestDigest: `sha256:${string}`;
	readonly messageCount: number;
};

type PendingJournalRecord = {
	readonly version: typeof JOURNAL_VERSION;
	readonly state: "pending";
	readonly idempotencyKey: string;
	readonly requestDigest: `sha256:${string}`;
	readonly messageIds: readonly string[];
	readonly createdAtMs: number;
	readonly updatedAtMs: number;
};

type CompletedJournalRecord = Omit<PendingJournalRecord, "state"> & {
	readonly state: "completed";
	readonly response: WhatsAppBridgeJournalResponse;
};

type JournalRecord = PendingJournalRecord | CompletedJournalRecord;

export type WhatsAppBridgeIdempotencyJournalOptions = {
	readonly dataDir: string;
	readonly nowMs?: () => number;
};

/**
 * Durable bridge-local dedupe. Pending rows are never aged out: an ambiguous
 * transport attempt must retain its deterministic Baileys IDs until resolved.
 * Completed rows outlive the relay retry horizon and are retained for 30 days.
 */
export class WhatsAppBridgeIdempotencyJournal {
	private readonly directory: string;
	private readonly nowMs: () => number;
	private readonly inFlight = new Map<string, Promise<void>>();

	constructor(options: WhatsAppBridgeIdempotencyJournalOptions) {
		const dataDir = path.resolve(options.dataDir);
		this.directory = path.join(dataDir, JOURNAL_DIRECTORY);
		this.nowMs = options.nowMs ?? Date.now;
		fs.mkdirSync(this.directory, { recursive: true, mode: JOURNAL_DIRECTORY_MODE });
		fs.chmodSync(this.directory, JOURNAL_DIRECTORY_MODE);
		this.cleanup();
	}

	execute(
		input: WhatsAppBridgeJournalExecuteInput,
		send: (messageIds: readonly string[]) => Promise<WhatsAppBridgeJournalResponse>,
	): Promise<WhatsAppBridgeJournalResponse> {
		const normalized = normalizeExecuteInput(input);
		const lockKey = journalFileName(normalized.idempotencyKey);
		return this.serialize(lockKey, async () => {
			const existing = this.read(normalized.idempotencyKey);
			if (existing && existing.requestDigest !== normalized.requestDigest) {
				return {
					ok: false,
					code: "whatsapp_bridge_idempotency_mismatch",
					reason: "Idempotency key was already used for a different request.",
					retryable: false,
				};
			}
			if (existing?.state === "completed") return existing.response;

			const messageIds = existing
				? validatePendingMessageIds(existing, normalized)
				: Array.from({ length: normalized.messageCount }, (_, index) =>
						deterministicWhatsAppBridgeMessageId(normalized.idempotencyKey, index),
					);
			const pending =
				existing ??
				this.writePending({
					idempotencyKey: normalized.idempotencyKey,
					requestDigest: normalized.requestDigest,
					messageIds,
				});
			const response = await send(messageIds);
			if (!response.ok && response.retryable) return response;

			const completed: CompletedJournalRecord = {
				...pending,
				state: "completed",
				response: sanitizeTerminalResponse(response),
				updatedAtMs: this.nowMs(),
			};
			this.atomicWrite(completed);
			return completed.response;
		});
	}

	cleanup(): number {
		const cutoffMs = this.nowMs() - WHATSAPP_BRIDGE_JOURNAL_RETENTION_MS;
		let removed = 0;
		for (const entry of fs.readdirSync(this.directory, { withFileTypes: true })) {
			if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
			const filePath = path.join(this.directory, entry.name);
			fs.chmodSync(filePath, JOURNAL_FILE_MODE);
			let record: JournalRecord;
			try {
				record = parseJournalRecord(fs.readFileSync(filePath, "utf8"));
			} catch {
				continue;
			}
			if (record.state !== "completed" || record.updatedAtMs > cutoffMs) continue;
			fs.unlinkSync(filePath);
			removed += 1;
		}
		if (removed > 0) fsyncDirectory(this.directory);
		return removed;
	}

	private writePending(input: {
		readonly idempotencyKey: string;
		readonly requestDigest: `sha256:${string}`;
		readonly messageIds: readonly string[];
	}): PendingJournalRecord {
		const nowMs = this.nowMs();
		const pending: PendingJournalRecord = {
			version: JOURNAL_VERSION,
			state: "pending",
			...input,
			createdAtMs: nowMs,
			updatedAtMs: nowMs,
		};
		this.atomicWrite(pending);
		return pending;
	}

	private read(idempotencyKey: string): JournalRecord | null {
		const filePath = this.filePath(idempotencyKey);
		if (!fs.existsSync(filePath)) return null;
		fs.chmodSync(filePath, JOURNAL_FILE_MODE);
		const record = parseJournalRecord(fs.readFileSync(filePath, "utf8"));
		if (record.idempotencyKey !== idempotencyKey) {
			throw new Error("WhatsApp bridge journal key does not match its file");
		}
		return record;
	}

	private atomicWrite(record: JournalRecord): void {
		const target = this.filePath(record.idempotencyKey);
		const temporary = path.join(
			this.directory,
			`.${path.basename(target)}.${process.pid}.${crypto.randomUUID()}.tmp`,
		);
		let fd: number | null = null;
		try {
			fd = fs.openSync(temporary, "wx", JOURNAL_FILE_MODE);
			fs.writeFileSync(fd, `${JSON.stringify(record)}\n`, "utf8");
			fs.fsyncSync(fd);
			fs.closeSync(fd);
			fd = null;
			fs.renameSync(temporary, target);
			fs.chmodSync(target, JOURNAL_FILE_MODE);
			fsyncDirectory(this.directory);
		} finally {
			if (fd !== null) fs.closeSync(fd);
			if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
		}
	}

	private filePath(idempotencyKey: string): string {
		return path.join(this.directory, journalFileName(idempotencyKey));
	}

	private async serialize<T>(key: string, operation: () => Promise<T>): Promise<T> {
		const previous = this.inFlight.get(key) ?? Promise.resolve();
		let release: (() => void) | undefined;
		const turn = new Promise<void>((resolve) => {
			release = resolve;
		});
		const tail = previous.then(() => turn);
		this.inFlight.set(key, tail);
		await previous;
		try {
			return await operation();
		} finally {
			release?.();
			if (this.inFlight.get(key) === tail) this.inFlight.delete(key);
		}
	}
}

function normalizeExecuteInput(
	input: WhatsAppBridgeJournalExecuteInput,
): WhatsAppBridgeJournalExecuteInput {
	const idempotencyKey = input.idempotencyKey.trim();
	if (!idempotencyKey) throw new Error("WhatsApp bridge idempotency key is required");
	if (!/^sha256:[a-f0-9]{64}$/.test(input.requestDigest)) {
		throw new Error("WhatsApp bridge request digest is invalid");
	}
	return {
		idempotencyKey,
		requestDigest: input.requestDigest,
		messageCount: positiveInteger(input.messageCount, "messageCount"),
	};
}

function validatePendingMessageIds(
	record: PendingJournalRecord,
	input: WhatsAppBridgeJournalExecuteInput,
): readonly string[] {
	const expected = Array.from({ length: input.messageCount }, (_, index) =>
		deterministicWhatsAppBridgeMessageId(input.idempotencyKey, index),
	);
	if (
		record.messageIds.length !== expected.length ||
		record.messageIds.some((messageId, index) => messageId !== expected[index])
	) {
		throw new Error("WhatsApp bridge pending message IDs changed");
	}
	return record.messageIds;
}

function sanitizeTerminalResponse(
	response: WhatsAppBridgeJournalResponse,
): WhatsAppBridgeJournalResponse {
	if (response.ok) {
		return {
			ok: true,
			...(response.platformMessageId
				? { platformMessageId: response.platformMessageId.trim() }
				: {}),
			...(response.observedThreadMessageId
				? { observedThreadMessageId: response.observedThreadMessageId.trim() }
				: {}),
		};
	}
	return {
		ok: false,
		code: response.code.trim() || "whatsapp_bridge_terminal_failure",
		reason: "WhatsApp bridge request failed.",
		retryable: false,
	};
}

function parseJournalRecord(serialized: string): JournalRecord {
	const value = JSON.parse(serialized) as Partial<JournalRecord>;
	if (
		value.version !== JOURNAL_VERSION ||
		(value.state !== "pending" && value.state !== "completed") ||
		typeof value.idempotencyKey !== "string" ||
		!/^sha256:[a-f0-9]{64}$/.test(String(value.requestDigest)) ||
		!Array.isArray(value.messageIds) ||
		!value.messageIds.every((messageId) => typeof messageId === "string") ||
		!Number.isSafeInteger(value.createdAtMs) ||
		!Number.isSafeInteger(value.updatedAtMs)
	) {
		throw new Error("WhatsApp bridge journal record is invalid");
	}
	if (value.state === "completed" && !isJournalResponse(value.response)) {
		throw new Error("WhatsApp bridge completed journal response is invalid");
	}
	return value as JournalRecord;
}

function isJournalResponse(value: unknown): value is WhatsAppBridgeJournalResponse {
	if (!value || typeof value !== "object") return false;
	const record = value as Record<string, unknown>;
	if (record.ok === true) {
		return (
			(record.platformMessageId === undefined || typeof record.platformMessageId === "string") &&
			(record.observedThreadMessageId === undefined ||
				typeof record.observedThreadMessageId === "string")
		);
	}
	return (
		record.ok === false &&
		typeof record.code === "string" &&
		(record.reason === undefined || typeof record.reason === "string") &&
		typeof record.retryable === "boolean"
	);
}

function journalFileName(idempotencyKey: string): string {
	return `${crypto.createHash("sha256").update(idempotencyKey).digest("hex")}.json`;
}

function positiveInteger(value: number, field: string): number {
	if (!Number.isSafeInteger(value) || value < 1)
		throw new Error(`${field} must be a positive integer`);
	return value;
}

function fsyncDirectory(directory: string): void {
	const fd = fs.openSync(directory, "r");
	try {
		fs.fsyncSync(fd);
	} finally {
		fs.closeSync(fd);
	}
}
