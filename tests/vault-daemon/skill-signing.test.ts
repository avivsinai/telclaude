/**
 * W9 vault protocol tests — `sign-skill` / `verify-skill` plus the
 * domain-separation invariant between `skill-v1`, `approval-v1`,
 * `session-v1`, and `pairing-v1`.
 *
 * The invariant: a signature produced under one domain prefix MUST NOT
 * verify under a different prefix, even though all domains share the
 * vault's master Ed25519 keypair. The vault enforces this by prepending
 * `<prefix>\n` to the payload before signing, so any mismatch mutates
 * the signed message and the signature fails to verify.
 */

import { describe, expect, it } from "vitest";

import {
	SignSkillRequestSchema,
	SignSkillResponseSchema,
	VaultRequestSchema,
	VaultResponseSchema,
	VerifySkillRequestSchema,
	VerifySkillResponseSchema,
} from "../../src/vault-daemon/protocol.js";

describe("vault sign-skill / verify-skill protocol", () => {
	const validDigest = "a".repeat(64);

	it("accepts a valid sign-skill request", () => {
		const result = VaultRequestSchema.safeParse({
			type: "sign-skill",
			digest: validDigest,
		});
		expect(result.success).toBe(true);
	});

	it("rejects sign-skill with uppercase hex digest", () => {
		const result = SignSkillRequestSchema.safeParse({
			type: "sign-skill",
			digest: "A".repeat(64),
		});
		expect(result.success).toBe(false);
	});

	it("rejects sign-skill with non-64-char digest", () => {
		const result = SignSkillRequestSchema.safeParse({
			type: "sign-skill",
			digest: "abc123",
		});
		expect(result.success).toBe(false);
	});

	it("accepts verify-skill with valid shape", () => {
		const result = VerifySkillRequestSchema.safeParse({
			type: "verify-skill",
			digest: validDigest,
			signature: "base64url-sig",
		});
		expect(result.success).toBe(true);
	});

	it("rejects verify-skill without signature", () => {
		const result = VerifySkillRequestSchema.safeParse({
			type: "verify-skill",
			digest: validDigest,
		});
		expect(result.success).toBe(false);
	});

	it("wraps sign-skill / verify-skill in the vault request discriminated union", () => {
		const s = VaultRequestSchema.safeParse({ type: "sign-skill", digest: validDigest });
		const v = VaultRequestSchema.safeParse({
			type: "verify-skill",
			digest: validDigest,
			signature: "sig",
		});
		expect(s.success).toBe(true);
		expect(v.success).toBe(true);
	});

	it("accepts sign-skill and verify-skill response shapes", () => {
		expect(
			SignSkillResponseSchema.safeParse({ type: "sign-skill", signature: "sig" }).success,
		).toBe(true);
		expect(
			VerifySkillResponseSchema.safeParse({ type: "verify-skill", valid: true }).success,
		).toBe(true);
	});

	it("wraps sign-skill / verify-skill in the vault response union", () => {
		const sig = VaultResponseSchema.safeParse({ type: "sign-skill", signature: "sig" });
		const ver = VaultResponseSchema.safeParse({ type: "verify-skill", valid: true });
		expect(sig.success).toBe(true);
		expect(ver.success).toBe(true);
	});
});

// ─────────────────────────────────────────────────────────────────────
// Domain separation: signature under one prefix must not verify under
// a different prefix. We exercise the same primitive the vault server
// uses (`<prefix>\n<payload>` signed with Ed25519) to prove that a
// skill signature cannot be replayed as an approval / session /
// pairing token and vice versa.
// ─────────────────────────────────────────────────────────────────────

import crypto from "node:crypto";

function keypair() {
	const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519", {
		privateKeyEncoding: { type: "pkcs8", format: "der" },
		publicKeyEncoding: { type: "spki", format: "der" },
	});
	return { privateKey, publicKey };
}

function signWithPrefix(privateKey: Buffer, prefix: string, payload: string): Buffer {
	return crypto.sign(null, Buffer.from(`${prefix}\n${payload}`), {
		key: privateKey,
		format: "der",
		type: "pkcs8",
	});
}

function verifyWithPrefix(
	publicKey: Buffer,
	prefix: string,
	payload: string,
	signature: Buffer,
): boolean {
	return crypto.verify(
		null,
		Buffer.from(`${prefix}\n${payload}`),
		{ key: publicKey, format: "der", type: "spki" },
		signature,
	);
}

describe("skill-v1 domain separation", () => {
	const { privateKey, publicKey } = keypair();
	const digest = "a".repeat(64);
	const skillSig = signWithPrefix(privateKey, "skill-v1", digest);

	it("verifies under its own prefix", () => {
		expect(verifyWithPrefix(publicKey, "skill-v1", digest, skillSig)).toBe(true);
	});

	it("does not verify as an approval-v1 signature", () => {
		expect(verifyWithPrefix(publicKey, "approval-v1", digest, skillSig)).toBe(false);
	});

	it("does not verify as a session-v1 signature", () => {
		expect(verifyWithPrefix(publicKey, "session-v1", digest, skillSig)).toBe(false);
	});

	it("does not verify as a pairing-v1 signature", () => {
		expect(verifyWithPrefix(publicKey, "pairing-v1", digest, skillSig)).toBe(false);
	});

	it("rejects approval-v1 signatures when presented as skill signatures", () => {
		const approvalSig = signWithPrefix(privateKey, "approval-v1", digest);
		expect(verifyWithPrefix(publicKey, "skill-v1", digest, approvalSig)).toBe(false);
	});

	it("rejects session-v1 signatures when presented as skill signatures", () => {
		const sessionSig = signWithPrefix(privateKey, "session-v1", digest);
		expect(verifyWithPrefix(publicKey, "skill-v1", digest, sessionSig)).toBe(false);
	});

	it("rejects pairing-v1 signatures when presented as skill signatures", () => {
		const pairingSig = signWithPrefix(privateKey, "pairing-v1", digest);
		expect(verifyWithPrefix(publicKey, "skill-v1", digest, pairingSig)).toBe(false);
	});
});
