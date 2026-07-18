import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type Database from "better-sqlite3";
import {
	type AttachmentRef,
	AttachmentRefSchema,
	EdgeAdapterSchemaVersions,
} from "../hermes/edge-adapter-contract.js";
import { getDb } from "../storage/db.js";
import { CONFIG_DIR } from "../utils.js";
import {
	normalizeSuppliedMediaType,
	sniffAttachmentContent,
} from "./attachment-content-sniffer.js";
import type { QuarantinedBytes } from "./edge-channel-connector.js";

export const QUARANTINE_MAX_BYTES = 25 * 1024 * 1024;
export const QUARANTINE_HARD_TTL_MS = 24 * 60 * 60 * 1000;
const PROCESSOR_LEASE_TTL_MS = 5 * 60 * 1000;

export type QuarantineLifecycleState = "pending" | "clean" | "blocked" | "expired" | "deleted";
export type QuarantineAccessClass = "outbound-delivery" | "media-processor";

export interface QuarantineOwnerBinding {
	readonly actorId: string;
	readonly subjectUserId?: string;
	readonly bindingId?: string;
	readonly senderPrincipalId: string;
	readonly conversationId: string;
	readonly conversationToken: string;
}

export interface QuarantineStoreInput {
	readonly bytes: Uint8Array;
	/** Untrusted transport metadata. Processor entries use only the sniffed value. */
	readonly mediaType: string;
	readonly conversationToken: string;
	readonly owner?: QuarantineOwnerBinding;
	readonly accessClass?: QuarantineAccessClass;
	readonly receivedAtMs?: number;
	readonly scanState?: AttachmentRef["scanState"];
	readonly trustLabel?: AttachmentRef["trustLabel"];
	readonly ttlMs?: number;
}

export interface QuarantineResolveContext {
	readonly conversationToken: string;
}

export interface QuarantineInspection extends AttachmentRef {
	readonly state: QuarantineLifecycleState;
	readonly hasBytes: boolean;
}

export interface AttachmentProcessorCapability {
	readonly capabilityId: symbol;
}

export interface AttachmentProcessingLease extends QuarantinedBytes {
	readonly leaseId: string;
}

export interface AttachmentDeletionReceipt {
	readonly receiptId: `sha256:${string}`;
	readonly quarantineIdHash: `sha256:${string}`;
	readonly contentHash: `sha256:${string}`;
	readonly ownerScopeHash: `sha256:${string}`;
	readonly reason:
		| "scan_blocked"
		| "mime_mismatch"
		| "unsupported_type"
		| "unreadable"
		| "expired"
		| "processed"
		| "owner_request";
	readonly receivedAtMs: number;
	readonly deletedAtMs: number;
}

export interface AttachmentQuarantineSweepResult {
	readonly expired: number;
	readonly orphanedFilesDeleted: number;
}

export interface AttachmentQuarantineStore {
	store(input: QuarantineStoreInput): AttachmentRef;
	/** Legacy outbound-only byte release. Processor-class entries always deny it. */
	resolve(quarantineId: string, context: QuarantineResolveContext): QuarantinedBytes | null;
	inspect(quarantineId: string, owner?: QuarantineOwnerBinding): QuarantineInspection | null;
	recordScanResult(
		quarantineId: string,
		owner: QuarantineOwnerBinding,
		result: "clean" | "blocked",
	): QuarantineInspection | null;
	leaseForProcessing(
		quarantineId: string,
		owner: QuarantineOwnerBinding,
		capability: AttachmentProcessorCapability,
	): AttachmentProcessingLease | null;
	completeProcessing(
		lease: Pick<AttachmentProcessingLease, "leaseId" | "quarantineId">,
		owner: QuarantineOwnerBinding,
		capability: AttachmentProcessorCapability,
	): QuarantineInspection | null;
	deleteForOwner(quarantineId: string, owner: QuarantineOwnerBinding): QuarantineInspection | null;
	getDeletionReceipt(quarantineId: string): AttachmentDeletionReceipt | null;
	sweepExpired(): AttachmentQuarantineSweepResult;
	cleanupExpired(): number;
}

interface QuarantineEntry {
	quarantineId: string;
	ownerScopeHash: `sha256:${string}`;
	conversationToken: string;
	suppliedMediaType: string;
	sniffedMediaType: string;
	sizeBytes: number;
	contentHash: `sha256:${string}`;
	trustLabel: AttachmentRef["trustLabel"];
	accessClass: QuarantineAccessClass;
	state: QuarantineLifecycleState;
	bytePath: string | null;
	bytes?: Uint8Array;
	createdAtMs: number;
	updatedAtMs: number;
	expiresAtMs: number;
	leaseId: string | null;
	leaseExpiresAtMs: number | null;
	deletedAtMs: number | null;
	deletionReason: AttachmentDeletionReceipt["reason"] | null;
}

type QuarantineRow = {
	quarantine_id: string;
	owner_scope_hash: string;
	conversation_token: string;
	supplied_media_type: string;
	sniffed_media_type: string;
	size_bytes: number;
	content_hash: string;
	trust_label: AttachmentRef["trustLabel"];
	access_class: QuarantineAccessClass;
	state: QuarantineLifecycleState;
	byte_path: string | null;
	created_at_ms: number;
	updated_at_ms: number;
	expires_at_ms: number;
	lease_id: string | null;
	lease_expires_at_ms: number | null;
	deleted_at_ms: number | null;
	deletion_reason: AttachmentDeletionReceipt["reason"] | null;
};

type ReceiptRow = {
	receipt_id: string;
	quarantine_id_hash: string;
	content_hash: string;
	owner_scope_hash: string;
	reason: AttachmentDeletionReceipt["reason"];
	received_at_ms: number;
	deleted_at_ms: number;
};

export interface CreateAttachmentQuarantineStoreOptions {
	readonly now?: () => number;
	readonly maxBytes?: number;
	readonly durable?: boolean;
	readonly quarantineDir?: string;
	readonly processorCapability?: AttachmentProcessorCapability;
}

export function createAttachmentProcessorCapability(): AttachmentProcessorCapability {
	return Object.freeze({ capabilityId: Symbol("attachment-media-processor") });
}

export function createAttachmentQuarantineStore(
	options: CreateAttachmentQuarantineStoreOptions = {},
): AttachmentQuarantineStore {
	const now = options.now ?? Date.now;
	const maxBytes = options.maxBytes ?? QUARANTINE_MAX_BYTES;
	const durable = options.durable ?? false;
	const quarantineDir =
		options.quarantineDir ??
		path.join(process.env.TELCLAUDE_DATA_DIR ?? CONFIG_DIR, "attachment-quarantine");
	const processorCapability = options.processorCapability;
	const database = durable ? getDb() : null;
	const entries = database ? loadEntries(database) : new Map<string, QuarantineEntry>();
	const receipts = durable ? null : new Map<string, AttachmentDeletionReceipt>();
	if (durable) ensurePrivateDirectory(quarantineDir);

	function store(input: QuarantineStoreInput): AttachmentRef {
		const conversationToken = required(input.conversationToken, "conversationToken");
		if (input.bytes.byteLength > maxBytes) {
			throw new Error(
				`quarantine store denied: ${input.bytes.byteLength} bytes exceeds cap ${maxBytes}`,
			);
		}
		const accessClass = input.accessClass ?? "outbound-delivery";
		const owner = input.owner ?? legacyOwner(conversationToken);
		if (owner.conversationToken !== conversationToken) {
			throw new Error("quarantine store denied: owner conversation token mismatch");
		}
		if (accessClass === "media-processor" && !input.owner) {
			throw new Error("quarantine store denied: processor entries require owner binding");
		}
		const nowMs = integerTimestamp(now(), "now");
		const receivedAtMs = integerTimestamp(input.receivedAtMs ?? nowMs, "receivedAtMs");
		const requestedTtl = input.ttlMs ?? QUARANTINE_HARD_TTL_MS;
		if (!Number.isFinite(requestedTtl) || requestedTtl <= 0) {
			throw new Error("quarantine store denied: ttlMs must be positive");
		}
		const expiresAtMs = Math.min(receivedAtMs + QUARANTINE_HARD_TTL_MS, nowMs + requestedTtl);
		const quarantineId = `tc-quarantine:${randomBytes(16).toString("hex")}`;
		const suppliedMediaType = normalizeSuppliedMediaType(input.mediaType);
		if (!suppliedMediaType) throw new Error("quarantine store denied: mediaType is required");
		const contentHash = sha256Ref(input.bytes);
		const sniffed = sniffAttachmentContent(input.bytes);
		const processorState =
			!sniffed.ok || sniffed.mediaType !== suppliedMediaType ? "blocked" : "pending";
		const legacyState =
			input.scanState === "clean"
				? "clean"
				: input.scanState === "blocked" || input.scanState === "failed"
					? "blocked"
					: "pending";
		const state = accessClass === "media-processor" ? processorState : legacyState;
		const sniffedMediaType =
			accessClass === "outbound-delivery"
				? suppliedMediaType
				: sniffed.ok
					? sniffed.mediaType
					: "application/octet-stream";
		const blockedReason: AttachmentDeletionReceipt["reason"] | null =
			state !== "blocked"
				? null
				: !sniffed.ok
					? "unsupported_type"
					: sniffed.mediaType !== suppliedMediaType
						? "mime_mismatch"
						: "scan_blocked";
		const entry: QuarantineEntry = {
			quarantineId,
			ownerScopeHash: ownerScopeHash(owner),
			conversationToken: state === "blocked" ? "" : conversationToken,
			suppliedMediaType,
			sniffedMediaType,
			sizeBytes: input.bytes.byteLength,
			contentHash,
			trustLabel:
				state === "blocked"
					? "blocked"
					: (input.trustLabel ?? (state === "clean" ? "trusted" : "untrusted")),
			accessClass,
			state,
			bytePath: null,
			createdAtMs: receivedAtMs,
			updatedAtMs: nowMs,
			expiresAtMs,
			leaseId: null,
			leaseExpiresAtMs: null,
			deletedAtMs: state === "blocked" ? nowMs : null,
			deletionReason: blockedReason,
		};

		if (state !== "blocked") writeBytes(entry, input.bytes);
		try {
			entries.set(quarantineId, entry);
			persistEntry(database, entry);
		} catch (error) {
			deleteBytes(entry);
			entries.delete(quarantineId);
			throw error;
		}
		if (state === "blocked") {
			writeReceipt(entry, blockedReason ?? "scan_blocked", nowMs);
		}
		return refFor(entry);
	}

	function resolve(
		quarantineId: string,
		context: QuarantineResolveContext,
	): QuarantinedBytes | null {
		const entry = currentEntry(quarantineId);
		if (!entry) return null;
		if (
			entry.accessClass !== "outbound-delivery" ||
			entry.state !== "clean" ||
			integerTimestamp(now(), "now") >= entry.expiresAtMs ||
			requiredOrNull(context.conversationToken) !== entry.conversationToken
		) {
			return null;
		}
		const bytes = readBytes(entry);
		if (!bytes) return null;
		return quarantinedBytes(entry, bytes);
	}

	function inspect(
		quarantineId: string,
		owner?: QuarantineOwnerBinding,
	): QuarantineInspection | null {
		const entry = currentEntry(quarantineId);
		if (!entry) return null;
		if (entry.accessClass === "media-processor" && (!owner || !sameOwner(entry, owner)))
			return null;
		return inspectionFor(entry);
	}

	function recordScanResult(
		quarantineId: string,
		owner: QuarantineOwnerBinding,
		result: "clean" | "blocked",
	): QuarantineInspection | null {
		const entry = currentEntry(quarantineId);
		if (!entry) return null;
		if (entry.accessClass !== "media-processor" || !sameOwner(entry, owner)) return null;
		if (entry.state !== "pending") return null;
		entry.state = result;
		entry.trustLabel = result === "clean" ? "untrusted" : "blocked";
		entry.updatedAtMs = integerTimestamp(now(), "now");
		if (result === "blocked") {
			terminalize(entry, "blocked", "scan_blocked", entry.updatedAtMs);
		} else {
			persistEntry(database, entry);
		}
		return inspectionFor(entry);
	}

	function leaseForProcessing(
		quarantineId: string,
		owner: QuarantineOwnerBinding,
		capability: AttachmentProcessorCapability,
	): AttachmentProcessingLease | null {
		if (!processorCapability || capability !== processorCapability) return null;
		const entry = currentEntry(quarantineId);
		if (!entry) return null;
		if (entry.accessClass !== "media-processor" || !sameOwner(entry, owner)) return null;
		if (entry.state !== "clean") return null;
		const nowMs = integerTimestamp(now(), "now");
		if (entry.leaseId && (entry.leaseExpiresAtMs ?? 0) > nowMs) return null;
		const bytes = readBytes(entry);
		if (!bytes) {
			terminalize(entry, "blocked", "unreadable", nowMs);
			return null;
		}
		entry.leaseId = `quarantine-lease:${randomBytes(16).toString("hex")}`;
		entry.leaseExpiresAtMs = Math.min(entry.expiresAtMs, nowMs + PROCESSOR_LEASE_TTL_MS);
		entry.updatedAtMs = nowMs;
		persistEntry(database, entry);
		return {
			...quarantinedBytes(entry, bytes),
			leaseId: entry.leaseId,
		};
	}

	function completeProcessing(
		lease: Pick<AttachmentProcessingLease, "leaseId" | "quarantineId">,
		owner: QuarantineOwnerBinding,
		capability: AttachmentProcessorCapability,
	): QuarantineInspection | null {
		if (!processorCapability || capability !== processorCapability) return null;
		const entry = currentEntry(lease.quarantineId);
		if (!entry) return null;
		if (
			entry.accessClass !== "media-processor" ||
			!sameOwner(entry, owner) ||
			entry.state !== "clean" ||
			entry.leaseId !== lease.leaseId
		) {
			return null;
		}
		terminalize(entry, "deleted", "processed", integerTimestamp(now(), "now"));
		return inspectionFor(entry);
	}

	function deleteForOwner(
		quarantineId: string,
		owner: QuarantineOwnerBinding,
	): QuarantineInspection | null {
		const entry = currentEntry(quarantineId);
		if (!entry || !sameOwner(entry, owner) || isTerminal(entry.state)) return null;
		terminalize(entry, "deleted", "owner_request", integerTimestamp(now(), "now"));
		return inspectionFor(entry);
	}

	function getDeletionReceipt(quarantineId: string): AttachmentDeletionReceipt | null {
		const quarantineIdHash = sha256TextRef(quarantineId);
		if (!database) return receipts?.get(quarantineIdHash) ?? null;
		const row = database
			.prepare(
				`SELECT receipt_id, quarantine_id_hash, content_hash, owner_scope_hash,
				        reason, received_at_ms, deleted_at_ms
				 FROM attachment_quarantine_deletion_receipts WHERE quarantine_id_hash = ?`,
			)
			.get(quarantineIdHash) as ReceiptRow | undefined;
		return row ? receiptFromRow(row) : null;
	}

	function sweepExpired(): AttachmentQuarantineSweepResult {
		const nowMs = integerTimestamp(now(), "now");
		let expired = 0;
		for (const entry of entries.values()) {
			if (isTerminal(entry.state) && entry.deletionReason && entry.deletedAtMs !== null) {
				writeReceipt(entry, entry.deletionReason, entry.deletedAtMs);
			}
			if (!isTerminal(entry.state) && nowMs >= entry.expiresAtMs) {
				if (entry.accessClass === "outbound-delivery") {
					deleteBytes(entry);
					entries.delete(entry.quarantineId);
					database
						?.prepare("DELETE FROM attachment_quarantine WHERE quarantine_id = ?")
						.run(entry.quarantineId);
				} else {
					terminalize(entry, "expired", "expired", nowMs);
				}
				expired += 1;
			}
		}
		return { expired, orphanedFilesDeleted: durable ? deleteOrphanedFiles(entries) : 0 };
	}

	function cleanupExpired(): number {
		return sweepExpired().expired;
	}

	function currentEntry(quarantineId: string): QuarantineEntry | null {
		const entry = entries.get(quarantineId);
		if (!entry) return null;
		if (
			entry.accessClass === "media-processor" &&
			!isTerminal(entry.state) &&
			integerTimestamp(now(), "now") >= entry.expiresAtMs
		) {
			terminalize(entry, "expired", "expired", integerTimestamp(now(), "now"));
		}
		return entry;
	}

	function terminalize(
		entry: QuarantineEntry,
		state: "blocked" | "expired" | "deleted",
		reason: AttachmentDeletionReceipt["reason"],
		atMs: number,
	): void {
		deleteBytes(entry);
		entry.state = state;
		entry.trustLabel = state === "blocked" ? "blocked" : entry.trustLabel;
		entry.updatedAtMs = atMs;
		entry.deletedAtMs = atMs;
		entry.conversationToken = "";
		entry.leaseId = null;
		entry.leaseExpiresAtMs = null;
		entry.deletionReason = reason;
		persistEntry(database, entry);
		writeReceipt(entry, reason, atMs);
	}

	function writeReceipt(
		entry: QuarantineEntry,
		reason: AttachmentDeletionReceipt["reason"],
		deletedAtMs: number,
	): AttachmentDeletionReceipt {
		const existing = getDeletionReceipt(entry.quarantineId);
		if (existing) return existing;
		const quarantineIdHash = sha256TextRef(entry.quarantineId);
		const receiptId = sha256TextRef(
			JSON.stringify({
				domain: "telclaude.attachment-quarantine-deletion.v1",
				contentHash: entry.contentHash,
				ownerScopeHash: entry.ownerScopeHash,
				reason,
				receivedAtMs: entry.createdAtMs,
			}),
		);
		const receipt: AttachmentDeletionReceipt = {
			receiptId,
			quarantineIdHash,
			contentHash: entry.contentHash,
			ownerScopeHash: entry.ownerScopeHash,
			reason,
			receivedAtMs: entry.createdAtMs,
			deletedAtMs,
		};
		if (database) {
			database
				.prepare(
					`INSERT OR IGNORE INTO attachment_quarantine_deletion_receipts (
					 receipt_id, quarantine_id_hash, content_hash, owner_scope_hash,
					 reason, received_at_ms, deleted_at_ms
					) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				)
				.run(
					receipt.receiptId,
					receipt.quarantineIdHash,
					receipt.contentHash,
					receipt.ownerScopeHash,
					receipt.reason,
					receipt.receivedAtMs,
					receipt.deletedAtMs,
				);
		} else {
			receipts?.set(quarantineIdHash, receipt);
		}
		return receipt;
	}

	function writeBytes(entry: QuarantineEntry, bytes: Uint8Array): void {
		if (!durable) {
			entry.bytes = bytes.slice();
			return;
		}
		const finalPath = path.join(quarantineDir, `${sha256HexText(entry.quarantineId)}.bin`);
		const temporaryPath = path.join(
			quarantineDir,
			`.pending-${sha256HexText(entry.quarantineId)}-${randomBytes(6).toString("hex")}`,
		);
		fs.writeFileSync(temporaryPath, bytes, { mode: 0o600, flag: "wx" });
		fs.renameSync(temporaryPath, finalPath);
		entry.bytePath = finalPath;
	}

	function readBytes(entry: QuarantineEntry): Uint8Array | null {
		if (!durable) return entry.bytes?.slice() ?? null;
		if (!entry.bytePath || !isPathInside(quarantineDir, entry.bytePath)) return null;
		try {
			const bytes = fs.readFileSync(entry.bytePath);
			if (bytes.byteLength !== entry.sizeBytes || sha256Ref(bytes) !== entry.contentHash)
				return null;
			return new Uint8Array(bytes);
		} catch {
			return null;
		}
	}

	function deleteBytes(entry: QuarantineEntry): void {
		entry.bytes = undefined;
		if (entry.bytePath && isPathInside(quarantineDir, entry.bytePath)) {
			try {
				fs.unlinkSync(entry.bytePath);
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
			}
		}
		entry.bytePath = null;
	}

	function deleteOrphanedFiles(current: Map<string, QuarantineEntry>): number {
		const referenced = new Set(
			[...current.values()].flatMap((entry) =>
				entry.bytePath ? [path.resolve(entry.bytePath)] : [],
			),
		);
		let removed = 0;
		for (const name of fs.readdirSync(quarantineDir)) {
			const candidate = path.resolve(quarantineDir, name);
			const isQuarantineObject = name.endsWith(".bin") || name.startsWith(".pending-");
			if (!isQuarantineObject || referenced.has(candidate)) continue;
			fs.unlinkSync(candidate);
			removed += 1;
		}
		return removed;
	}

	return {
		store,
		resolve,
		inspect,
		recordScanResult,
		leaseForProcessing,
		completeProcessing,
		deleteForOwner,
		getDeletionReceipt,
		sweepExpired,
		cleanupExpired,
	};
}

function loadEntries(database: Database.Database): Map<string, QuarantineEntry> {
	const rows = database.prepare("SELECT * FROM attachment_quarantine").all() as QuarantineRow[];
	return new Map(rows.map((row) => [row.quarantine_id, entryFromRow(row)]));
}

function persistEntry(database: Database.Database | null, entry: QuarantineEntry): void {
	if (!database) return;
	database
		.prepare(
			`INSERT INTO attachment_quarantine (
			 quarantine_id, owner_scope_hash, conversation_token, supplied_media_type,
			 sniffed_media_type, size_bytes, content_hash, trust_label, access_class,
			 state, byte_path, created_at_ms, updated_at_ms, expires_at_ms,
			 lease_id, lease_expires_at_ms, deleted_at_ms, deletion_reason
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(quarantine_id) DO UPDATE SET
			 state = excluded.state,
			 trust_label = excluded.trust_label,
			 conversation_token = excluded.conversation_token,
			 byte_path = excluded.byte_path,
			 updated_at_ms = excluded.updated_at_ms,
			 lease_id = excluded.lease_id,
			 lease_expires_at_ms = excluded.lease_expires_at_ms,
			 deleted_at_ms = excluded.deleted_at_ms,
			 deletion_reason = excluded.deletion_reason`,
		)
		.run(
			entry.quarantineId,
			entry.ownerScopeHash,
			entry.conversationToken,
			entry.suppliedMediaType,
			entry.sniffedMediaType,
			entry.sizeBytes,
			entry.contentHash,
			entry.trustLabel,
			entry.accessClass,
			entry.state,
			entry.bytePath,
			entry.createdAtMs,
			entry.updatedAtMs,
			entry.expiresAtMs,
			entry.leaseId,
			entry.leaseExpiresAtMs,
			entry.deletedAtMs,
			entry.deletionReason,
		);
}

function entryFromRow(row: QuarantineRow): QuarantineEntry {
	return {
		quarantineId: row.quarantine_id,
		ownerScopeHash: row.owner_scope_hash as `sha256:${string}`,
		conversationToken: row.conversation_token,
		suppliedMediaType: row.supplied_media_type,
		sniffedMediaType: row.sniffed_media_type,
		sizeBytes: row.size_bytes,
		contentHash: row.content_hash as `sha256:${string}`,
		trustLabel: row.trust_label,
		accessClass: row.access_class,
		state: row.state,
		bytePath: row.byte_path,
		createdAtMs: row.created_at_ms,
		updatedAtMs: row.updated_at_ms,
		expiresAtMs: row.expires_at_ms,
		leaseId: row.lease_id,
		leaseExpiresAtMs: row.lease_expires_at_ms,
		deletedAtMs: row.deleted_at_ms,
		deletionReason: row.deletion_reason,
	};
}

function receiptFromRow(row: ReceiptRow): AttachmentDeletionReceipt {
	return {
		receiptId: row.receipt_id as `sha256:${string}`,
		quarantineIdHash: row.quarantine_id_hash as `sha256:${string}`,
		contentHash: row.content_hash as `sha256:${string}`,
		ownerScopeHash: row.owner_scope_hash as `sha256:${string}`,
		reason: row.reason,
		receivedAtMs: row.received_at_ms,
		deletedAtMs: row.deleted_at_ms,
	};
}

function refFor(entry: QuarantineEntry): AttachmentRef {
	return AttachmentRefSchema.parse({
		schemaVersion: EdgeAdapterSchemaVersions.attachmentRef,
		quarantineId: entry.quarantineId,
		mediaType: entry.sniffedMediaType,
		scanState:
			entry.state === "pending"
				? "pending"
				: entry.state === "clean"
					? "clean"
					: entry.state === "blocked"
						? "blocked"
						: "failed",
		sizeBytes: entry.sizeBytes,
		contentHash: entry.contentHash,
		trustLabel: entry.trustLabel,
		expiresAt: new Date(entry.expiresAtMs).toISOString(),
		lifecycle: {
			state:
				entry.state === "pending"
					? "quarantined"
					: entry.state === "clean"
						? "authorized"
						: entry.state === "expired"
							? "expired"
							: "denied",
			authorizedFor: entry.conversationToken ? [entry.conversationToken] : [],
		},
	});
}

function inspectionFor(entry: QuarantineEntry): QuarantineInspection {
	return Object.freeze({ ...refFor(entry), state: entry.state, hasBytes: hasBytes(entry) });
}

function hasBytes(entry: QuarantineEntry): boolean {
	return entry.bytes !== undefined || entry.bytePath !== null;
}

function quarantinedBytes(entry: QuarantineEntry, bytes: Uint8Array): QuarantinedBytes {
	return {
		quarantineId: entry.quarantineId,
		mediaType: entry.sniffedMediaType,
		bytes: bytes.slice(),
		contentHash: entry.contentHash,
	};
}

function ownerScopeHash(owner: QuarantineOwnerBinding): `sha256:${string}` {
	return sha256TextRef(
		JSON.stringify({
			actorId: required(owner.actorId, "actorId"),
			subjectUserId: owner.subjectUserId ? required(owner.subjectUserId, "subjectUserId") : null,
			bindingId: owner.bindingId ? required(owner.bindingId, "bindingId") : null,
			senderPrincipalId: required(owner.senderPrincipalId, "senderPrincipalId"),
			conversationId: required(owner.conversationId, "conversationId"),
			conversationToken: required(owner.conversationToken, "conversationToken"),
		}),
	);
}

function sameOwner(entry: QuarantineEntry, owner: QuarantineOwnerBinding): boolean {
	return entry.ownerScopeHash === ownerScopeHash(owner);
}

function legacyOwner(conversationToken: string): QuarantineOwnerBinding {
	return {
		actorId: `legacy:${conversationToken}`,
		senderPrincipalId: `legacy:${conversationToken}`,
		conversationId: `legacy:${conversationToken}`,
		conversationToken,
	};
}

function isTerminal(state: QuarantineLifecycleState): boolean {
	return state === "blocked" || state === "expired" || state === "deleted";
}

function sha256Ref(bytes: Uint8Array): `sha256:${string}` {
	return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function sha256TextRef(value: string): `sha256:${string}` {
	return `sha256:${sha256HexText(value)}`;
}

function sha256HexText(value: string): string {
	return createHash("sha256").update(value).digest("hex");
}

function required(value: string, field: string): string {
	const normalized = value.trim();
	if (!normalized) throw new Error(`quarantine store denied: ${field} is required`);
	return normalized;
}

function requiredOrNull(value: string): string | null {
	const normalized = value.trim();
	return normalized || null;
}

function integerTimestamp(value: number, field: string): number {
	if (!Number.isSafeInteger(value) || value < 0) {
		throw new Error(`quarantine store denied: ${field} must be a non-negative integer`);
	}
	return value;
}

function ensurePrivateDirectory(directory: string): void {
	fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
	fs.chmodSync(directory, 0o700);
}

function isPathInside(directory: string, candidate: string): boolean {
	const relative = path.relative(path.resolve(directory), path.resolve(candidate));
	return relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative);
}
