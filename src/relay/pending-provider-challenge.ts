import crypto from "node:crypto";
import { isValidHouseholdBindingId } from "../memory/source.js";
import {
	createProviderChallengeTurnControl,
	type ProviderChallengeTurnControl,
	providerChallengeTurnControl,
} from "./provider-challenge-turn-control.js";

export const DEFAULT_PROVIDER_CHALLENGE_TTL_MS = 180_000;

export type PendingProviderChallengeBindingEvidence = {
	readonly bindingId: string;
	readonly actorId: string;
	readonly subjectUserId: string;
	readonly profileId: string;
	readonly conversationToken: string;
	readonly conversationId: string;
	readonly senderPrincipalHash: `sha256:${string}`;
};

export type PendingProviderChallengeArmInput = {
	readonly origin: "relay_login_coordinator";
	readonly initiationRef: string;
	readonly initiatingTurnRef: string;
	readonly binding: PendingProviderChallengeBindingEvidence;
	readonly service: "clalit";
	readonly providerChallengeId: string;
	readonly challengeType: "sms_otp";
	readonly sidecarExpiresAtMs: number;
	readonly nowMs?: number;
};

export type PendingProviderChallengeClaim = {
	readonly ref: string;
	readonly bindingId: string;
	readonly actorId: string;
	readonly subjectUserId: string;
	readonly profileId: string;
	readonly service: "clalit";
	readonly providerChallengeId: string;
	readonly challengeType: "sms_otp";
	readonly initiationRef: string;
	readonly initiatingTurnRef: string;
	readonly claimedAtMs: number;
};

export type PendingProviderChallengeLookup =
	| { readonly status: "armed"; readonly expiresAtMs: number }
	| { readonly status: "none" }
	| { readonly status: "expired" }
	| { readonly status: "binding_mismatch" };

export type PendingProviderChallengeClaimResult =
	| { readonly ok: true; readonly claim: PendingProviderChallengeClaim }
	| {
			readonly ok: false;
			readonly status: Exclude<PendingProviderChallengeLookup["status"], "armed">;
	  };

export type PendingProviderChallengeRegistry = {
	arm(input: PendingProviderChallengeArmInput): {
		readonly ref: string;
		readonly expiresAtMs: number;
		readonly replaced: boolean;
	};
	peekForInbound(
		binding: PendingProviderChallengeBindingEvidence,
		nowMs?: number,
	): PendingProviderChallengeLookup;
	claimForInbound(
		binding: PendingProviderChallengeBindingEvidence,
		nowMs?: number,
	): PendingProviderChallengeClaimResult;
	cancel(bindingId: string): boolean;
	cleanup(nowMs?: number): number;
	clear(): void;
};

type StoredPendingProviderChallenge = {
	readonly ref: string;
	readonly bindingId: string;
	readonly actorId: string;
	readonly subjectUserId: string;
	readonly profileId: string;
	readonly conversationTokenHash: `sha256:${string}`;
	readonly conversationIdHash: `sha256:${string}`;
	readonly initiatingTurnRef: string;
	readonly senderPrincipalHash: `sha256:${string}`;
	readonly service: "clalit";
	readonly providerChallengeId: string;
	readonly challengeType: "sms_otp";
	readonly createdAtMs: number;
	readonly expiresAtMs: number;
	readonly initiationRef: string;
};

export function createPendingProviderChallengeRegistry(input?: {
	readonly nowMs?: () => number;
	readonly turnControl?: ProviderChallengeTurnControl;
	readonly makeRef?: () => string;
}): PendingProviderChallengeRegistry {
	const records = new Map<string, StoredPendingProviderChallenge>();
	const nowMs = input?.nowMs ?? Date.now;
	const turnControl =
		input?.turnControl ??
		(input?.nowMs
			? createProviderChallengeTurnControl({ nowMs: input.nowMs })
			: providerChallengeTurnControl);
	const makeRef =
		input?.makeRef ?? (() => `provider_challenge_${crypto.randomBytes(24).toString("base64url")}`);

	return {
		arm(rawInput) {
			const now = normalizeNow(rawInput.nowMs ?? nowMs());
			const binding = normalizeBinding(rawInput.binding);
			if (rawInput.origin !== "relay_login_coordinator") {
				throw new Error("provider challenge arming requires the relay login coordinator");
			}
			const initiationRef = normalizeInitiationRef(rawInput.initiationRef);
			const initiatingTurnRef = normalizeTurnRef(rawInput.initiatingTurnRef);
			if (rawInput.service !== "clalit" || rawInput.challengeType !== "sms_otp") {
				throw new Error("provider challenge must be a canonical Clalit sms_otp challenge");
			}
			const sidecarExpiry = normalizeNow(rawInput.sidecarExpiresAtMs);
			const expiresAtMs = Math.min(now + DEFAULT_PROVIDER_CHALLENGE_TTL_MS, sidecarExpiry);
			if (expiresAtMs <= now) throw new Error("provider challenge is already expired");
			const record: StoredPendingProviderChallenge = Object.freeze({
				ref: requiredTrimmed(makeRef(), "ref"),
				...storedBinding(binding),
				initiatingTurnRef,
				service: "clalit",
				providerChallengeId: boundedSecret(rawInput.providerChallengeId),
				challengeType: "sms_otp",
				createdAtMs: now,
				expiresAtMs,
				initiationRef,
			});
			const replaced = records.has(binding.bindingId);
			records.set(binding.bindingId, record);
			turnControl.block(initiatingTurnRef, expiresAtMs);
			return { ref: record.ref, expiresAtMs, replaced };
		},

		peekForInbound(binding, atMs = nowMs()) {
			try {
				return assess(records, normalizeBinding(binding), normalizeNow(atMs), false);
			} catch {
				return { status: "binding_mismatch" };
			}
		},

		claimForInbound(binding, atMs = nowMs()) {
			let normalizedBinding: PendingProviderChallengeBindingEvidence;
			try {
				normalizedBinding = normalizeBinding(binding);
			} catch {
				spendSuspectBinding(records, binding.bindingId);
				return { ok: false, status: "binding_mismatch" };
			}
			const now = normalizeNow(atMs);
			const assessment = assess(records, normalizedBinding, now, true);
			if (assessment.status !== "armed") return { ok: false, status: assessment.status };
			const record = records.get(normalizedBinding.bindingId);
			if (!record) return { ok: false, status: "none" };
			// Delete synchronously before the secret-bearing claim leaves the registry.
			records.delete(normalizedBinding.bindingId);
			return {
				ok: true,
				claim: Object.freeze({
					ref: record.ref,
					bindingId: record.bindingId,
					actorId: record.actorId,
					subjectUserId: record.subjectUserId,
					profileId: record.profileId,
					service: record.service,
					providerChallengeId: record.providerChallengeId,
					challengeType: record.challengeType,
					initiationRef: record.initiationRef,
					initiatingTurnRef: record.initiatingTurnRef,
					claimedAtMs: now,
				}),
			};
		},

		cancel(bindingId) {
			return records.delete(normalizeBindingId(bindingId));
		},

		cleanup(atMs = nowMs()) {
			const now = normalizeNow(atMs);
			let removed = 0;
			for (const [bindingId, record] of records) {
				if (record.expiresAtMs <= now) {
					records.delete(bindingId);
					removed += 1;
				}
			}
			turnControl.cleanup(now);
			return removed;
		},

		clear() {
			records.clear();
			turnControl.clear();
		},
	};
}

export const pendingProviderChallengeRegistry = createPendingProviderChallengeRegistry();

function spendSuspectBinding(
	records: Map<string, StoredPendingProviderChallenge>,
	bindingId: string,
): void {
	try {
		records.delete(normalizeBindingId(bindingId));
	} catch {
		// Malformed untrusted evidence has no addressable registry entry.
	}
}

function assess(
	records: Map<string, StoredPendingProviderChallenge>,
	binding: PendingProviderChallengeBindingEvidence,
	nowMs: number,
	deleteMismatch: boolean,
): PendingProviderChallengeLookup {
	const record = records.get(binding.bindingId);
	if (!record) return { status: "none" };
	if (record.expiresAtMs <= nowMs) {
		records.delete(binding.bindingId);
		return { status: "expired" };
	}
	if (!sameBinding(record, binding)) {
		if (deleteMismatch) records.delete(binding.bindingId);
		return { status: "binding_mismatch" };
	}
	return { status: "armed", expiresAtMs: record.expiresAtMs };
}

function sameBinding(
	record: StoredPendingProviderChallenge,
	binding: PendingProviderChallengeBindingEvidence,
): boolean {
	return (
		record.bindingId === binding.bindingId &&
		record.actorId === binding.actorId &&
		record.subjectUserId === binding.subjectUserId &&
		record.profileId === binding.profileId &&
		record.conversationTokenHash === digest(binding.conversationToken) &&
		record.conversationIdHash === digest(binding.conversationId) &&
		record.senderPrincipalHash === binding.senderPrincipalHash
	);
}

function storedBinding(binding: PendingProviderChallengeBindingEvidence) {
	return {
		bindingId: binding.bindingId,
		actorId: binding.actorId,
		subjectUserId: binding.subjectUserId,
		profileId: binding.profileId,
		conversationTokenHash: digest(binding.conversationToken),
		conversationIdHash: digest(binding.conversationId),
		senderPrincipalHash: binding.senderPrincipalHash,
	};
}

function normalizeBinding(
	binding: PendingProviderChallengeBindingEvidence,
): PendingProviderChallengeBindingEvidence {
	const bindingId = normalizeBindingId(binding.bindingId);
	const subjectUserId = requiredTrimmed(binding.subjectUserId, "subjectUserId");
	if (subjectUserId !== `household:${bindingId}`) {
		throw new Error("provider challenge subject must match its household binding");
	}
	const senderPrincipalHash = requiredTrimmed(binding.senderPrincipalHash, "senderPrincipalHash");
	if (!/^sha256:[a-f0-9]{64}$/.test(senderPrincipalHash)) {
		throw new Error("senderPrincipalHash must be a SHA-256 digest");
	}
	return {
		bindingId,
		actorId: requiredTrimmed(binding.actorId, "actorId"),
		subjectUserId,
		profileId: requiredTrimmed(binding.profileId, "profileId"),
		conversationToken: requiredTrimmed(binding.conversationToken, "conversationToken"),
		conversationId: requiredTrimmed(binding.conversationId, "conversationId"),
		senderPrincipalHash: senderPrincipalHash as `sha256:${string}`,
	};
}

function normalizeBindingId(value: string): string {
	const bindingId = requiredTrimmed(value, "bindingId");
	if (!isValidHouseholdBindingId(bindingId)) {
		throw new Error("bindingId must be an opaque household binding id");
	}
	return bindingId;
}

function normalizeInitiationRef(value: string): string {
	const ref = requiredTrimmed(value, "initiationRef");
	if (!/^provider_login_[A-Za-z0-9_-]{16,128}$/.test(ref)) {
		throw new Error("initiationRef must be a relay login coordinator ref");
	}
	return ref;
}

function normalizeTurnRef(value: string): string {
	const ref = requiredTrimmed(value, "initiatingTurnRef");
	if (!/^turn_[0-9a-f]{32}$/.test(ref)) {
		throw new Error("initiatingTurnRef must be a relay turn ref");
	}
	return ref;
}

function boundedSecret(value: string): string {
	const secret = requiredTrimmed(value, "providerChallengeId");
	if (secret.length > 512) throw new Error("providerChallengeId is too long");
	return secret;
}

function normalizeNow(value: number): number {
	if (!Number.isFinite(value) || !Number.isInteger(value) || value < 0) {
		throw new Error("provider challenge timestamp must be a non-negative integer");
	}
	return value;
}

function requiredTrimmed(value: string, field: string): string {
	const trimmed = value.trim();
	if (!trimmed) throw new Error(`${field} is required`);
	return trimmed;
}

function digest(value: string): `sha256:${string}` {
	return `sha256:${crypto.createHash("sha256").update(value, "utf8").digest("hex")}`;
}
