import crypto from "node:crypto";
import { sortKeysDeep } from "../crypto/canonical-hash.js";
import type { VaultClient } from "../vault-daemon/client.js";
import { upsertVerifiedCuratorItem } from "./store.js";
import type { CuratorItem, CuratorItemInput, CuratorProducerKind } from "./types.js";

export const CURATOR_PRODUCER_SIGNING_PREFIX = "curator-producer-v1";
const DEFAULT_CURATOR_PRODUCER_TTL_MS = 5 * 60 * 1000;

export type SignedCuratorProducerKind = Exclude<CuratorProducerKind, "system">;

export type CuratorProducerEnvelope = {
	producerKind: SignedCuratorProducerKind;
	producerId: string;
	claimsHash: string;
	expiresAtMs: number;
	signature: string;
};

function canonicalJson(value: unknown): string {
	return JSON.stringify(sortKeysDeep(value));
}

function sha256Hex(value: string): string {
	return crypto.createHash("sha256").update(value).digest("hex");
}

function validateProducerKind(producerKind: CuratorProducerKind): SignedCuratorProducerKind {
	if (producerKind === "claude-code" || producerKind === "codex") {
		return producerKind;
	}
	throw new Error("curator producer envelope requires claude-code or codex producer");
}

function validateProducerId(producerId: string): string {
	const trimmed = producerId.trim();
	if (!trimmed) {
		throw new Error("curator producer envelope requires producerId");
	}
	return trimmed;
}

export function getCuratorItemClaimsHash(input: CuratorItemInput): string {
	const claims = {
		fingerprint: input.fingerprint,
		kind: input.kind,
		severity: input.severity,
		source: input.source,
		title: input.title,
		summary: input.summary,
		rationale: input.rationale ?? null,
		entityRef: input.entityRef,
		proposedAction: input.proposedAction,
		evidence: input.evidence,
		expiresAtMs: input.expiresAtMs ?? null,
	};
	return `sha256:${sha256Hex(canonicalJson(claims))}`;
}

function getEnvelopeSignedPayload(envelope: Omit<CuratorProducerEnvelope, "signature">): string {
	return canonicalJson({
		producerKind: envelope.producerKind,
		producerId: envelope.producerId,
		claimsHash: envelope.claimsHash,
		expiresAtMs: envelope.expiresAtMs,
	});
}

export async function signCuratorProducerEnvelope(
	input: CuratorItemInput,
	options: {
		vaultClient: Pick<VaultClient, "signPayload">;
		producerKind: SignedCuratorProducerKind;
		producerId: string;
		nowMs?: number;
		ttlMs?: number;
	},
): Promise<CuratorProducerEnvelope> {
	const nowMs = options.nowMs ?? Date.now();
	const expiresAtMs = nowMs + (options.ttlMs ?? DEFAULT_CURATOR_PRODUCER_TTL_MS);
	const producerKind = validateProducerKind(options.producerKind);
	const producerId = validateProducerId(options.producerId);
	const claimsHash = getCuratorItemClaimsHash(input);
	const unsigned = { producerKind, producerId, claimsHash, expiresAtMs };
	const signResult = await options.vaultClient.signPayload(
		getEnvelopeSignedPayload(unsigned),
		CURATOR_PRODUCER_SIGNING_PREFIX,
	);
	if (signResult.type !== "sign-payload" || !signResult.signature) {
		throw new Error("Vault signing failed");
	}
	return {
		...unsigned,
		signature: signResult.signature,
	};
}

export async function upsertSignedCuratorItem(
	input: CuratorItemInput,
	envelope: CuratorProducerEnvelope,
	options: {
		vaultClient: Pick<VaultClient, "verifyPayload">;
		nowMs?: number;
	},
): Promise<CuratorItem> {
	const nowMs = options.nowMs ?? Date.now();
	const producerKind = validateProducerKind(envelope.producerKind);
	const producerId = validateProducerId(envelope.producerId);
	if (input.producerKind && input.producerKind !== producerKind) {
		throw new Error("curator producer kind does not match signed envelope");
	}
	if (input.producerId && input.producerId !== producerId) {
		throw new Error("curator producer id does not match signed envelope");
	}
	if (envelope.expiresAtMs <= nowMs) {
		throw new Error("curator producer envelope expired");
	}
	const claimsHash = getCuratorItemClaimsHash(input);
	if (claimsHash !== envelope.claimsHash) {
		throw new Error("curator producer claims hash mismatch");
	}
	const verifyResult = await options.vaultClient.verifyPayload(
		getEnvelopeSignedPayload({
			producerKind,
			producerId,
			claimsHash: envelope.claimsHash,
			expiresAtMs: envelope.expiresAtMs,
		}),
		envelope.signature,
		CURATOR_PRODUCER_SIGNING_PREFIX,
	);
	if (verifyResult.type !== "verify-payload" || !verifyResult.valid) {
		throw new Error("curator producer signature invalid");
	}
	return upsertVerifiedCuratorItem(
		{
			...input,
			producerKind,
			producerId,
		},
		nowMs,
	);
}
