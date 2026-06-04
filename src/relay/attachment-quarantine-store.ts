import { createHash, randomBytes } from "node:crypto";
import {
	type AttachmentRef,
	AttachmentRefSchema,
	EdgeAdapterSchemaVersions,
} from "../hermes/edge-adapter-contract.js";
import type { QuarantinedBytes } from "./edge-channel-connector.js";

/**
 * Owner-bound attachment quarantine (CL-0). Inbound transports `store` raw
 * bytes (they stay relay-local; only an {@link AttachmentRef} crosses to the
 * model). Outbound delivery `resolve`s bytes ONLY when the caller proves the
 * attachment is authorized for the conversation it is being sent on.
 *
 * Owner-binding is the security invariant: `resolve(id, { conversationToken })`
 * returns bytes only when conversationToken is in the ref's `authorizedFor`,
 * the ref is `clean`, and not expired — so a connector handed an outbound for
 * conversation A can never exfiltrate an attachment belonging to conversation B
 * by guessing its quarantineId.
 */

export const QUARANTINE_MAX_BYTES = 25 * 1024 * 1024; // 25 MiB hard cap
const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000; // 24h

export interface QuarantineStoreInput {
	readonly bytes: Uint8Array;
	readonly mediaType: string;
	/** The relay conversation token this attachment is authorized for. */
	readonly conversationToken: string;
	/** Scan verdict from the inbound scanner; defaults to "pending" (fail-closed). */
	readonly scanState?: AttachmentRef["scanState"];
	readonly trustLabel?: AttachmentRef["trustLabel"];
	readonly ttlMs?: number;
}

export interface QuarantineResolveContext {
	readonly conversationToken: string;
}

export interface AttachmentQuarantineStore {
	/** Quarantine bytes and return a model-safe ref. Throws if over the size cap. */
	store(input: QuarantineStoreInput): AttachmentRef;
	/** Owner-bound byte release. Returns null (never throws) on any failed check. */
	resolve(quarantineId: string, context: QuarantineResolveContext): QuarantinedBytes | null;
	/** Inspect a ref without releasing bytes (audit/status). Null if unknown. */
	inspect(quarantineId: string): AttachmentRef | null;
	/** Drop expired entries; returns the count removed. */
	cleanupExpired(): number;
}

interface QuarantineEntry {
	readonly ref: AttachmentRef;
	readonly bytes: Uint8Array;
	readonly expiresAtMs: number;
}

export interface CreateAttachmentQuarantineStoreOptions {
	readonly now?: () => number;
	readonly maxBytes?: number;
}

function sha256Hex(bytes: Uint8Array): string {
	return createHash("sha256").update(bytes).digest("hex");
}

/** Recursively freeze an object so authority state cannot be mutated in-process. */
function deepFreeze<T>(value: T): T {
	if (value && typeof value === "object") {
		for (const key of Object.keys(value as Record<string, unknown>)) {
			deepFreeze((value as Record<string, unknown>)[key]);
		}
		Object.freeze(value);
	}
	return value;
}

export function createAttachmentQuarantineStore(
	options: CreateAttachmentQuarantineStoreOptions = {},
): AttachmentQuarantineStore {
	const now = options.now ?? Date.now;
	const maxBytes = options.maxBytes ?? QUARANTINE_MAX_BYTES;
	const entries = new Map<string, QuarantineEntry>();

	function store(input: QuarantineStoreInput): AttachmentRef {
		const token = input.conversationToken.trim();
		if (!token) {
			throw new Error("quarantine store denied: conversationToken is required");
		}
		if (input.bytes.byteLength > maxBytes) {
			throw new Error(
				`quarantine store denied: ${input.bytes.byteLength} bytes exceeds cap ${maxBytes}`,
			);
		}
		const scanState = input.scanState ?? "pending";
		// Bytes are only ever resolvable once clean; until then the ref is quarantined.
		const lifecycleState = scanState === "clean" ? "authorized" : "quarantined";
		const nowMs = now();
		const ttlMs = input.ttlMs ?? DEFAULT_TTL_MS;
		const expiresAtMs = nowMs + ttlMs;
		const quarantineId = `tc-quarantine:${randomBytes(16).toString("hex")}`;
		const ref = AttachmentRefSchema.parse({
			schemaVersion: EdgeAdapterSchemaVersions.attachmentRef,
			quarantineId,
			mediaType: input.mediaType,
			scanState,
			sizeBytes: input.bytes.byteLength,
			contentHash: `sha256:${sha256Hex(input.bytes)}`,
			trustLabel: input.trustLabel ?? (scanState === "clean" ? "trusted" : "untrusted"),
			expiresAt: new Date(expiresAtMs).toISOString(),
			lifecycle: {
				state: lifecycleState,
				authorizedFor: [token],
			},
		});
		// The store's authority copy is PRIVATE and deep-frozen: callers only ever
		// receive structural clones (here and from inspect()), so mutating a returned
		// ref — ref.scanState/lifecycle.state/lifecycle.authorizedFor — cannot change a
		// later resolve() decision (TypeScript `readonly` is compile-time only).
		// Bytes are sliced so a later mutation of the caller's buffer cannot alter
		// quarantined bytes after the contentHash was computed.
		const authority = deepFreeze(ref);
		entries.set(quarantineId, { ref: authority, bytes: input.bytes.slice(), expiresAtMs });
		return structuredClone(authority);
	}

	function resolve(
		quarantineId: string,
		context: QuarantineResolveContext,
	): QuarantinedBytes | null {
		const entry = entries.get(quarantineId);
		if (!entry) return null;
		if (now() >= entry.expiresAtMs) return null;
		if (entry.ref.scanState !== "clean") return null;
		if (entry.ref.lifecycle.state !== "authorized") return null;
		const token = context.conversationToken.trim();
		if (!token) return null;
		if (!entry.ref.lifecycle.authorizedFor.includes(token)) return null;
		return {
			quarantineId,
			mediaType: entry.ref.mediaType,
			bytes: entry.bytes.slice(),
			contentHash: entry.ref.contentHash,
		};
	}

	function inspect(quarantineId: string): AttachmentRef | null {
		const entry = entries.get(quarantineId);
		// Clone so a caller cannot mutate the frozen authority's structure by reference.
		return entry ? structuredClone(entry.ref) : null;
	}

	function cleanupExpired(): number {
		const nowMs = now();
		let removed = 0;
		for (const [id, entry] of entries) {
			if (nowMs >= entry.expiresAtMs) {
				entries.delete(id);
				removed += 1;
			}
		}
		return removed;
	}

	return { store, resolve, inspect, cleanupExpired };
}
