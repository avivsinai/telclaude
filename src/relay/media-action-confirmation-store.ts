import crypto from "node:crypto";
import { sortKeysDeep } from "../crypto/canonical-hash.js";
import { getDb } from "../storage/db.js";
import type { DerivedMediaEnvelopeV1 } from "./inbound-media-processor.js";
import { claimInteractiveChoiceLease } from "./interactive-choice-lease.js";

const DEFAULT_CONFIRMATION_TTL_MS = 10 * 60_000;
const MAX_ACTION_PAYLOAD_BYTES = 32 * 1024;
const MIN_ENCRYPTION_KEY_CHARS = 32;
const SHA256_REF_RE = /^sha256:[a-f0-9]{64}$/u;
const TURN_REF_RE = /^turn_[a-f0-9]{32}$/u;

export type MediaActionToolName =
	| "tc_provider_prepare_write"
	| "tc_schedule_create"
	| "tc_schedule_update"
	| "tc_schedule_cancel";

export type MediaConfirmationOwner = {
	readonly actorId: string;
	readonly subjectUserId: string;
	readonly profileId: string;
	readonly bindingId: string;
	readonly conversationId: string;
	readonly senderPrincipalHash: `sha256:${string}`;
};

export type MediaConfirmationAuthority = Pick<
	MediaConfirmationOwner,
	"actorId" | "subjectUserId" | "profileId"
>;

export type MediaConsequentialAction = {
	readonly toolName: MediaActionToolName;
	readonly params: Record<string, unknown>;
};

export type MediaActionConfirmation = MediaConfirmationOwner & {
	readonly confirmationId: string;
	readonly status: "pending" | "confirmed" | "rejected" | "expired" | "revoked";
	readonly originalTurnRef: string;
	readonly ownerScopeHash: `sha256:${string}`;
	readonly sourceDigest: `sha256:${string}`;
	readonly derivedDigest: `sha256:${string}`;
	readonly actionDigest: `sha256:${string}`;
	readonly actionToolName: MediaActionToolName;
	readonly jtiHash: `sha256:${string}`;
	readonly createdAtMs: number;
	readonly expiresAtMs: number;
	readonly resolvedAtMs?: number;
};

export type MediaActionConfirmationPayload = {
	readonly envelopes: readonly DerivedMediaEnvelopeV1[];
	readonly action: MediaConsequentialAction;
};

export type MediaActionConfirmationGate = {
	guardConsequentialAction(input: {
		readonly turnRef: string;
		readonly authority: MediaConfirmationAuthority;
		readonly action: MediaConsequentialAction;
		readonly nowMs?: number;
	}):
		| { readonly required: false }
		| { readonly required: true; readonly confirmation: MediaActionConfirmation };
};

export type MediaActionConfirmationStore = MediaActionConfirmationGate & {
	registerTurnDerivation(input: {
		readonly owner: MediaConfirmationOwner;
		readonly turnRef: string;
		readonly envelopes: readonly DerivedMediaEnvelopeV1[];
		readonly createdAtMs?: number;
	}): void;
	inspectConfirmation(confirmationId: string): MediaActionConfirmation | null;
	readPendingPayload(input: {
		readonly confirmationId: string;
		readonly owner: MediaConfirmationOwner;
		readonly nowMs?: number;
	}): MediaActionConfirmationPayload | null;
};

type DerivationRow = {
	turn_ref: string;
	actor_id: string;
	subject_user_id: string;
	profile_id: string;
	binding_id: string;
	conversation_id: string;
	sender_principal_hash: string;
	owner_scope_hash: string;
	source_digest: string;
	derived_digest: string;
	media_kinds_json: string;
	provenance_json: string;
	action_bearing: number;
	low_confidence: number;
	kdf_salt: string;
	iv: string;
	auth_tag: string;
	ciphertext: string;
	created_at_ms: number;
	expires_at_ms: number;
};

type ConfirmationRow = {
	confirmation_id: string;
	jti_hash: string;
	status: MediaActionConfirmation["status"];
	actor_id: string;
	subject_user_id: string;
	profile_id: string;
	binding_id: string;
	conversation_id: string;
	sender_principal_hash: string;
	original_turn_ref: string;
	owner_scope_hash: string;
	source_digest: string;
	derived_digest: string;
	action_digest: string;
	action_tool_name: MediaActionToolName;
	created_at_ms: number;
	expires_at_ms: number;
	resolved_at_ms: number | null;
};

type CipherRow = {
	kdf_salt: string;
	iv: string;
	auth_tag: string;
	ciphertext: string;
};

type Ciphertext = {
	readonly kdfSalt: string;
	readonly iv: string;
	readonly authTag: string;
	readonly ciphertext: string;
};

export class MediaConfirmationKeyUnavailableError extends Error {
	readonly code = "media_confirmation_key_unavailable";

	constructor() {
		super("media confirmation encryption key is unavailable");
		this.name = "MediaConfirmationKeyUnavailableError";
	}
}

export class MediaActionConfirmationRequiredError extends Error {
	readonly code = "media_action_confirmation_required";

	constructor() {
		super("media-derived consequential action requires relay confirmation");
		this.name = "MediaActionConfirmationRequiredError";
	}
}

export function createMediaActionConfirmationStore(options: {
	readonly encryptionKey: string | undefined;
	readonly nowMs?: () => number;
	readonly makeConfirmationId?: () => string;
	readonly makeJti?: () => string;
	readonly confirmationTtlMs?: number;
}): MediaActionConfirmationStore {
	const rawKey = encryptionKey(options.encryptionKey);
	const nowMs = options.nowMs ?? Date.now;
	const makeConfirmationId =
		options.makeConfirmationId ??
		(() => `media-confirmation-${crypto.randomBytes(18).toString("base64url")}`);
	const makeJti = options.makeJti ?? (() => crypto.randomBytes(32).toString("base64url"));
	const confirmationTtlMs = positiveInt(
		options.confirmationTtlMs ?? DEFAULT_CONFIRMATION_TTL_MS,
		"confirmationTtlMs",
	);

	function registerTurnDerivation(input: {
		readonly owner: MediaConfirmationOwner;
		readonly turnRef: string;
		readonly envelopes: readonly DerivedMediaEnvelopeV1[];
		readonly createdAtMs?: number;
	}): void {
		const owner = normalizeOwner(input.owner);
		const turnRef = turnRefValue(input.turnRef);
		const createdAtMs = timestamp(input.createdAtMs ?? nowMs(), "createdAtMs");
		const envelopes = normalizeEnvelopes(input.envelopes);
		const expiresAtMs = createdAtMs + confirmationTtlMs;
		const ownerScopeHash = ownerHash(owner);
		const sourceDigest = digest(
			"telclaude.media-confirmation.sources.v1",
			sourceBindings(envelopes),
		);
		const derivedDigest = digest("telclaude.media-confirmation.derivation.v1", envelopes);
		const encrypted = encryptJson(rawKey, { envelopes }, derivationAad(turnRef, ownerScopeHash));
		const mediaKinds = [...new Set(envelopes.map((envelope) => envelope.kind))].sort();
		const provenance = envelopes.map((envelope) => ({
			kind: envelope.kind,
			extractor: envelope.extractor,
			confidenceSource: envelope.confidenceSource,
			confidencePolicyVersion: envelope.confidencePolicyVersion,
			lowConfidence: envelope.lowConfidence,
			lowConfidenceReasonCodes: envelope.lowConfidenceReasonCodes,
			classifierVersion: envelope.classifierVersion,
			actionBearing: envelope.actionBearing,
			actionBearingReasonCodes: envelope.actionBearingReasonCodes,
		}));

		getDb().transaction(() => {
			getDb()
				.prepare("DELETE FROM household_media_turn_derivations WHERE expires_at_ms <= ?")
				.run(createdAtMs);
			const existing = readDerivation(turnRef);
			if (existing) {
				if (
					existing.owner_scope_hash === ownerScopeHash &&
					existing.source_digest === sourceDigest &&
					existing.derived_digest === derivedDigest
				) {
					return;
				}
				throw new Error("media turn derivation binding changed");
			}
			getDb()
				.prepare(
					`INSERT INTO household_media_turn_derivations (
					 turn_ref, actor_id, subject_user_id, profile_id, binding_id, conversation_id,
					 sender_principal_hash, owner_scope_hash, source_digest, derived_digest,
					 media_kinds_json, provenance_json, action_bearing, low_confidence,
					 kdf_salt, iv, auth_tag, ciphertext, created_at_ms, expires_at_ms
					) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				)
				.run(
					turnRef,
					owner.actorId,
					owner.subjectUserId,
					owner.profileId,
					owner.bindingId,
					owner.conversationId,
					owner.senderPrincipalHash,
					ownerScopeHash,
					sourceDigest,
					derivedDigest,
					JSON.stringify(mediaKinds),
					JSON.stringify(sortKeysDeep(provenance)),
					envelopes.some((envelope) => envelope.actionBearing) ? 1 : 0,
					envelopes.some((envelope) => envelope.lowConfidence) ? 1 : 0,
					encrypted.kdfSalt,
					encrypted.iv,
					encrypted.authTag,
					encrypted.ciphertext,
					createdAtMs,
					expiresAtMs,
				);
		})();
	}

	function guardConsequentialAction(input: {
		readonly turnRef: string;
		readonly authority: MediaConfirmationAuthority;
		readonly action: MediaConsequentialAction;
		readonly nowMs?: number;
	}):
		| { readonly required: false }
		| { readonly required: true; readonly confirmation: MediaActionConfirmation } {
		const turnRef = turnRefValue(input.turnRef);
		const atMs = timestamp(input.nowMs ?? nowMs(), "nowMs");
		const authority = normalizeAuthority(input.authority);
		const derivation = readDerivation(turnRef);
		if (!derivation) return { required: false };
		if (derivation.expires_at_ms <= atMs) {
			getDb()
				.prepare("DELETE FROM household_media_turn_derivations WHERE turn_ref = ?")
				.run(turnRef);
			return { required: false };
		}
		if (!authorityMatches(derivation, authority)) {
			throw new Error("media turn derivation authority mismatch");
		}
		if (derivation.action_bearing !== 1 && derivation.low_confidence !== 1) {
			return { required: false };
		}
		const action = normalizeAction(input.action);
		const actionDigest = digest("telclaude.media-confirmation.action.v1", action);
		const existing = readPendingForTurnAction(turnRef, actionDigest);
		if (existing) return { required: true, confirmation: rowToConfirmation(existing) };

		return getDb().transaction(() => {
			const payload = decryptJson<{ envelopes: DerivedMediaEnvelopeV1[] }>(
				rawKey,
				rowCipher(derivation),
				derivationAad(turnRef, derivation.owner_scope_hash),
			);
			if (
				!payload ||
				digest("telclaude.media-confirmation.derivation.v1", payload.envelopes) !==
					derivation.derived_digest
			) {
				throw new Error("media turn derivation decryption failed");
			}
			const confirmationId = required(makeConfirmationId(), "confirmationId");
			const jti = required(makeJti(), "jti");
			const expiresAtMs = atMs + confirmationTtlMs;
			const confirmationPayload: MediaActionConfirmationPayload = {
				envelopes: payload.envelopes,
				action,
			};
			const encrypted = encryptJson(
				rawKey,
				confirmationPayload,
				confirmationAad(confirmationId, derivation.owner_scope_hash),
			);
			claimInteractiveChoiceLease({
				actorId: derivation.actor_id,
				subjectUserId: derivation.subject_user_id,
				profileId: derivation.profile_id,
				bindingId: derivation.binding_id,
				conversationId: derivation.conversation_id,
				kind: "media_confirmation",
				ownerRef: confirmationId,
				createdAtMs: atMs,
				expiresAtMs,
			});
			getDb()
				.prepare(
					`INSERT INTO household_media_action_confirmations (
					 confirmation_id, jti_hash, status, actor_id, subject_user_id, profile_id,
					 binding_id, conversation_id, sender_principal_hash, original_turn_ref,
					 owner_scope_hash, source_digest, derived_digest, action_digest, action_tool_name,
					 created_at_ms, expires_at_ms
					) VALUES (?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				)
				.run(
					confirmationId,
					digest("telclaude.media-confirmation.jti.v1", jti),
					derivation.actor_id,
					derivation.subject_user_id,
					derivation.profile_id,
					derivation.binding_id,
					derivation.conversation_id,
					derivation.sender_principal_hash,
					turnRef,
					derivation.owner_scope_hash,
					derivation.source_digest,
					derivation.derived_digest,
					actionDigest,
					action.toolName,
					atMs,
					expiresAtMs,
				);
			getDb()
				.prepare(
					`INSERT INTO household_media_action_confirmation_content (
					 confirmation_id, kdf_salt, iv, auth_tag, ciphertext
					) VALUES (?, ?, ?, ?, ?)`,
				)
				.run(
					confirmationId,
					encrypted.kdfSalt,
					encrypted.iv,
					encrypted.authTag,
					encrypted.ciphertext,
				);
			const row = readConfirmation(confirmationId);
			if (!row) throw new Error("media action confirmation persistence failed");
			return { required: true as const, confirmation: rowToConfirmation(row) };
		})();
	}

	function readPendingPayload(input: {
		readonly confirmationId: string;
		readonly owner: MediaConfirmationOwner;
		readonly nowMs?: number;
	}): MediaActionConfirmationPayload | null {
		const confirmationId = required(input.confirmationId, "confirmationId");
		const owner = normalizeOwner(input.owner);
		const atMs = timestamp(input.nowMs ?? nowMs(), "nowMs");
		const row = readConfirmation(confirmationId);
		if (!row) return null;
		if (
			row.status !== "pending" ||
			row.expires_at_ms <= atMs ||
			!rowOwnerMatches(row, owner) ||
			row.owner_scope_hash !== ownerHash(owner)
		) {
			return null;
		}
		const content = getDb()
			.prepare(
				"SELECT kdf_salt, iv, auth_tag, ciphertext FROM household_media_action_confirmation_content WHERE confirmation_id = ?",
			)
			.get(confirmationId) as CipherRow | undefined;
		if (!content) return null;
		const payload = decryptJson<MediaActionConfirmationPayload>(
			rawKey,
			rowCipher(content),
			confirmationAad(confirmationId, row.owner_scope_hash),
		);
		if (!payload) return null;
		try {
			const action = normalizeAction(payload.action);
			const envelopes = normalizeEnvelopes(payload.envelopes);
			if (
				digest("telclaude.media-confirmation.action.v1", action) !== row.action_digest ||
				digest("telclaude.media-confirmation.derivation.v1", envelopes) !== row.derived_digest
			) {
				return null;
			}
			return { envelopes, action };
		} catch {
			return null;
		}
	}

	return {
		registerTurnDerivation,
		guardConsequentialAction,
		inspectConfirmation: (confirmationId) => {
			const row = readConfirmation(required(confirmationId, "confirmationId"));
			return row ? rowToConfirmation(row) : null;
		},
		readPendingPayload,
	};
}

function encryptionKey(value: string | undefined): string {
	if (!value || Array.from(value).length < MIN_ENCRYPTION_KEY_CHARS) {
		throw new MediaConfirmationKeyUnavailableError();
	}
	return value;
}

function readDerivation(turnRef: string): DerivationRow | null {
	return (
		(getDb()
			.prepare("SELECT * FROM household_media_turn_derivations WHERE turn_ref = ?")
			.get(turnRef) as DerivationRow | undefined) ?? null
	);
}

function readConfirmation(confirmationId: string): ConfirmationRow | null {
	return (
		(getDb()
			.prepare("SELECT * FROM household_media_action_confirmations WHERE confirmation_id = ?")
			.get(confirmationId) as ConfirmationRow | undefined) ?? null
	);
}

function readPendingForTurnAction(turnRef: string, actionDigest: string): ConfirmationRow | null {
	return (
		(getDb()
			.prepare(
				`SELECT * FROM household_media_action_confirmations
				 WHERE original_turn_ref = ? AND action_digest = ? AND status = 'pending'`,
			)
			.get(turnRef, actionDigest) as ConfirmationRow | undefined) ?? null
	);
}

function rowToConfirmation(row: ConfirmationRow): MediaActionConfirmation {
	return {
		confirmationId: row.confirmation_id,
		status: row.status,
		actorId: row.actor_id,
		subjectUserId: row.subject_user_id,
		profileId: row.profile_id,
		bindingId: row.binding_id,
		conversationId: row.conversation_id,
		senderPrincipalHash: sha256Ref(row.sender_principal_hash, "senderPrincipalHash"),
		originalTurnRef: row.original_turn_ref,
		ownerScopeHash: sha256Ref(row.owner_scope_hash, "ownerScopeHash"),
		sourceDigest: sha256Ref(row.source_digest, "sourceDigest"),
		derivedDigest: sha256Ref(row.derived_digest, "derivedDigest"),
		actionDigest: sha256Ref(row.action_digest, "actionDigest"),
		actionToolName: row.action_tool_name,
		jtiHash: sha256Ref(row.jti_hash, "jtiHash"),
		createdAtMs: row.created_at_ms,
		expiresAtMs: row.expires_at_ms,
		...(row.resolved_at_ms === null ? {} : { resolvedAtMs: row.resolved_at_ms }),
	};
}

function normalizeOwner(owner: MediaConfirmationOwner): MediaConfirmationOwner {
	return {
		actorId: required(owner.actorId, "actorId"),
		subjectUserId: required(owner.subjectUserId, "subjectUserId"),
		profileId: required(owner.profileId, "profileId"),
		bindingId: required(owner.bindingId, "bindingId"),
		conversationId: required(owner.conversationId, "conversationId"),
		senderPrincipalHash: sha256Ref(owner.senderPrincipalHash, "senderPrincipalHash"),
	};
}

function normalizeAuthority(authority: MediaConfirmationAuthority): MediaConfirmationAuthority {
	return {
		actorId: required(authority.actorId, "actorId"),
		subjectUserId: required(authority.subjectUserId, "subjectUserId"),
		profileId: required(authority.profileId, "profileId"),
	};
}

function normalizeAction(action: MediaConsequentialAction): MediaConsequentialAction {
	if (
		action.toolName !== "tc_provider_prepare_write" &&
		action.toolName !== "tc_schedule_create" &&
		action.toolName !== "tc_schedule_update" &&
		action.toolName !== "tc_schedule_cancel"
	) {
		throw new Error("media confirmation action tool is unsupported");
	}
	if (!action.params || typeof action.params !== "object" || Array.isArray(action.params)) {
		throw new Error("media confirmation action params are invalid");
	}
	const params = sortKeysDeep(action.params) as Record<string, unknown>;
	const encoded = JSON.stringify(params);
	if (Buffer.byteLength(encoded, "utf8") > MAX_ACTION_PAYLOAD_BYTES) {
		throw new Error("media confirmation action params exceed the byte cap");
	}
	return { toolName: action.toolName, params };
}

function normalizeEnvelopes(
	envelopes: readonly DerivedMediaEnvelopeV1[],
): readonly DerivedMediaEnvelopeV1[] {
	if (envelopes.length === 0 || envelopes.length > 8) {
		throw new Error("media confirmation derivation count is invalid");
	}
	for (const envelope of envelopes) {
		if (
			Array.from(envelope.text).length > 8_000 ||
			!/^[a-f0-9]{64}$/u.test(envelope.sourceSha256)
		) {
			throw new Error("media confirmation derivation is invalid");
		}
	}
	return structuredClone(envelopes);
}

function sourceBindings(envelopes: readonly DerivedMediaEnvelopeV1[]) {
	return envelopes.map((envelope) => ({
		kind: envelope.kind,
		sourceSha256: envelope.sourceSha256,
		sourceMediaType: envelope.sourceMediaType,
		...(envelope.kind === "document_extract"
			? { sourcePageCount: envelope.sourcePageCount }
			: { sourceDurationSeconds: envelope.sourceDurationSeconds ?? null }),
	}));
}

function ownerHash(owner: MediaConfirmationOwner): `sha256:${string}` {
	return digest("telclaude.media-confirmation.owner.v1", owner);
}

function authorityMatches(row: DerivationRow, authority: MediaConfirmationAuthority): boolean {
	return (
		row.actor_id === authority.actorId &&
		row.subject_user_id === authority.subjectUserId &&
		row.profile_id === authority.profileId
	);
}

function rowOwnerMatches(row: ConfirmationRow, owner: MediaConfirmationOwner): boolean {
	return (
		row.actor_id === owner.actorId &&
		row.subject_user_id === owner.subjectUserId &&
		row.profile_id === owner.profileId &&
		row.binding_id === owner.bindingId &&
		row.conversation_id === owner.conversationId &&
		row.sender_principal_hash === owner.senderPrincipalHash
	);
}

function encryptJson(rawKey: string, value: unknown, aad: string): Ciphertext {
	const plaintext = JSON.stringify(sortKeysDeep(value));
	const salt = crypto.randomBytes(16);
	const iv = crypto.randomBytes(12);
	const key = crypto.scryptSync(rawKey, salt, 32);
	const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
	cipher.setAAD(Buffer.from(aad, "utf8"));
	const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
	return {
		kdfSalt: salt.toString("base64"),
		iv: iv.toString("base64"),
		authTag: cipher.getAuthTag().toString("base64"),
		ciphertext: encrypted.toString("base64"),
	};
}

function decryptJson<T>(rawKey: string, encrypted: Ciphertext, aad: string): T | null {
	try {
		const salt = Buffer.from(encrypted.kdfSalt, "base64");
		const iv = Buffer.from(encrypted.iv, "base64");
		const key = crypto.scryptSync(rawKey, salt, 32);
		const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
		decipher.setAAD(Buffer.from(aad, "utf8"));
		decipher.setAuthTag(Buffer.from(encrypted.authTag, "base64"));
		const plaintext = Buffer.concat([
			decipher.update(Buffer.from(encrypted.ciphertext, "base64")),
			decipher.final(),
		]).toString("utf8");
		return JSON.parse(plaintext) as T;
	} catch {
		return null;
	}
}

function rowCipher(row: CipherRow | DerivationRow): Ciphertext {
	return {
		kdfSalt: row.kdf_salt,
		iv: row.iv,
		authTag: row.auth_tag,
		ciphertext: row.ciphertext,
	};
}

function derivationAad(turnRef: string, ownerScopeHash: string): string {
	return `telclaude.media-derivation.v1\n${turnRef}\n${ownerScopeHash}`;
}

function confirmationAad(confirmationId: string, ownerScopeHash: string): string {
	return `telclaude.media-confirmation.v1\n${confirmationId}\n${ownerScopeHash}`;
}

function digest(domain: string, value: unknown): `sha256:${string}` {
	return `sha256:${crypto
		.createHash("sha256")
		.update(JSON.stringify(sortKeysDeep({ domain, value })))
		.digest("hex")}`;
}

function sha256Ref(value: string, field: string): `sha256:${string}` {
	if (!SHA256_REF_RE.test(value)) throw new Error(`media confirmation ${field} is invalid`);
	return value as `sha256:${string}`;
}

function turnRefValue(value: string): string {
	const normalized = required(value, "turnRef");
	if (!TURN_REF_RE.test(normalized)) throw new Error("media confirmation turnRef is invalid");
	return normalized;
}

function required(value: string, field: string): string {
	const normalized = value.trim();
	if (!normalized) throw new Error(`media confirmation ${field} is required`);
	return normalized;
}

function timestamp(value: number, field: string): number {
	if (!Number.isSafeInteger(value) || value < 0) {
		throw new Error(`media confirmation ${field} must be a non-negative safe integer`);
	}
	return value;
}

function positiveInt(value: number, field: string): number {
	if (!Number.isSafeInteger(value) || value <= 0) {
		throw new Error(`media confirmation ${field} must be a positive safe integer`);
	}
	return value;
}
