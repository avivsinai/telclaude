import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { sortKeysDeep } from "../../src/crypto/canonical-hash.js";
import {
	createTelclaudeMcpSideEffectApprovalVerifier,
	generateTelclaudeMcpSideEffectApprovalToken,
	type TelclaudeMcpSideEffectApprovalClaims,
	TelclaudeMcpSideEffectJtiStore,
} from "../../src/hermes/mcp/approval-token.js";
import {
	createTelclaudeMcpSideEffectLedger,
	TELCLAUDE_MCP_OUTBOUND_APPROVAL_DOMAIN,
	TELCLAUDE_MCP_PROVIDER_APPROVAL_DOMAIN,
	type TelclaudeMcpOutboundApprovalBinding,
	type TelclaudeMcpProviderApprovalBinding,
	type TelclaudeMcpSideEffectApprovalBinding,
	type TelclaudeMcpSideEffectApprovalVerification,
} from "../../src/hermes/mcp/side-effect-ledger.js";

describe("Telclaude MCP side-effect approval tokens", () => {
	let tempDir: string;
	let jtiStore: TelclaudeMcpSideEffectJtiStore;
	let vault: MockVaultClient;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-mcp-approval-"));
		jtiStore = new TelclaudeMcpSideEffectJtiStore(tempDir);
		vault = new MockVaultClient();
	});

	afterEach(() => {
		jtiStore.close();
		fs.rmSync(tempDir, { recursive: true, force: true });
	});

	it("generates a token signed under the binding domain and embeds the exact binding", async () => {
		const binding = providerBinding();

		const token = await generateTelclaudeMcpSideEffectApprovalToken(binding, vault, {
			nowSeconds: () => 100,
			ttlSeconds: 60,
			jti: "jti-provider-1",
		});

		expect(token).toMatch(/^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
		expect(vault.signCalls).toEqual([
			expect.objectContaining({ prefix: TELCLAUDE_MCP_PROVIDER_APPROVAL_DOMAIN }),
		]);
		const claims = decodeTokenClaims(token);
		expect(claims).toEqual({
			ver: 1,
			iss: "telclaude-vault",
			aud: "telclaude-hermes-mcp-side-effect",
			iat: 100,
			exp: 160,
			jti: "jti-provider-1",
			binding,
		});
	});

	it("refuses to generate tokens with invalid TTL or JTI bounds", async () => {
		const binding = providerBinding();

		await expect(
			generateTelclaudeMcpSideEffectApprovalToken(binding, vault, {
				nowSeconds: () => 100,
				ttlSeconds: 301,
				jti: "jti-too-long-ttl",
			}),
		).rejects.toThrow("ttlSeconds must be an integer between 1 and 300");
		await expect(
			generateTelclaudeMcpSideEffectApprovalToken(binding, vault, {
				nowSeconds: () => 100,
				jti: "x".repeat(257),
			}),
		).rejects.toThrow("jti must be 256 characters or less");
	});

	it("accepts a matching token once and rejects replay through the durable JTI store", async () => {
		const binding = providerBinding();
		const verifier = createVerifier();
		const token = await generateTelclaudeMcpSideEffectApprovalToken(binding, vault, {
			nowSeconds: () => 100,
			jti: "jti-provider-replay",
		});

		await expect(verifier(verification(binding, token, 120_000))).resolves.toEqual({
			ok: true,
			approvalId: "jti-provider-replay",
		});
		await expect(verifier(verification(binding, token, 121_000))).resolves.toEqual({
			ok: false,
			code: "approval_replayed",
			reason: "Approval token already used",
		});
		expect(vault.verifyCalls).toEqual([
			expect.objectContaining({ prefix: TELCLAUDE_MCP_PROVIDER_APPROVAL_DOMAIN }),
			expect.objectContaining({ prefix: TELCLAUDE_MCP_PROVIDER_APPROVAL_DOMAIN }),
		]);
	});

	it("rejects cross-domain provider/outbound reuse without consuming the JTI", async () => {
		const provider = providerBinding();
		const outbound = outboundBinding({
			ref: provider.ref,
			actorId: provider.actorId,
			profileId: provider.profileId,
			domain: provider.domain,
			approvalRequestId: provider.approvalRequestId,
			approvalRevision: provider.approvalRevision,
		});
		const verifier = createVerifier();
		const token = await generateTelclaudeMcpSideEffectApprovalToken(provider, vault, {
			nowSeconds: () => 100,
			jti: "jti-cross-domain",
		});

		await expect(verifier(verification(outbound, token, 120_000))).resolves.toEqual({
			ok: false,
			code: "approval_required",
			reason: "Invalid token signature",
		});
		await expect(verifier(verification(provider, token, 121_000))).resolves.toEqual({
			ok: true,
			approvalId: "jti-cross-domain",
		});
	});

	it.each([
		["actor", { actorId: "telegram:attacker" }],
		["target", { providerAccountRef: "bank:other" }],
		["params hash", { paramsHash: hash("1") }],
		["body hash", { bodyHash: hash("2") }],
		["content hash", { contentHash: hash("3") }],
		["approval revision", { approvalRevision: 2 }],
	])("rejects a token when the %s binding changes without consuming the JTI", async (_label, mutation) => {
		const binding = providerBinding();
		const verifier = createVerifier();
		const token = await generateTelclaudeMcpSideEffectApprovalToken(binding, vault, {
			nowSeconds: () => 100,
			jti: `jti-mutated-${String(_label).replaceAll(" ", "-")}`,
		});
		const mutated = providerBinding(mutation);

		await expect(verifier(verification(mutated, token, 120_000))).resolves.toEqual({
			ok: false,
			code: "approval_mismatch",
			reason: "Approval token binding mismatch",
		});
		await expect(verifier(verification(binding, token, 121_000))).resolves.toEqual({
			ok: true,
			approvalId: `jti-mutated-${String(_label).replaceAll(" ", "-")}`,
		});
	});

	it("rejects expired and overlong-TTL tokens before consuming their JTI", async () => {
		const binding = providerBinding();
		const verifier = createVerifier();
		const expired = await generateTelclaudeMcpSideEffectApprovalToken(binding, vault, {
			nowSeconds: () => 100,
			ttlSeconds: 60,
			jti: "jti-expired",
		});

		await expect(verifier(verification(binding, expired, 161_000))).resolves.toEqual({
			ok: false,
			code: "approval_expired",
			reason: "Token expired",
		});

		const expiredRetry = await generateTelclaudeMcpSideEffectApprovalToken(binding, vault, {
			nowSeconds: () => 120,
			jti: "jti-expired",
		});
		await expect(verifier(verification(binding, expiredRetry, 121_000))).resolves.toEqual({
			ok: true,
			approvalId: "jti-expired",
		});

		const overlong = await signClaims(
			{
				ver: 1,
				iss: "telclaude-vault",
				aud: "telclaude-hermes-mcp-side-effect",
				iat: 100,
				exp: 401,
				jti: "jti-overlong",
				binding,
			},
			vault,
			binding.domainSeparator,
		);
		await expect(verifier(verification(binding, overlong, 120_000))).resolves.toEqual({
			ok: false,
			code: "approval_required",
			reason: "Token TTL exceeds maximum (300s)",
		});

		const retry = await generateTelclaudeMcpSideEffectApprovalToken(binding, vault, {
			nowSeconds: () => 100,
			jti: "jti-overlong",
		});
		await expect(verifier(verification(binding, retry, 121_000))).resolves.toEqual({
			ok: true,
			approvalId: "jti-overlong",
		});
	});

	it("fails closed on malformed tokens and vault verification errors without consuming", async () => {
		const binding = providerBinding();
		const verifier = createVerifier();
		const token = await generateTelclaudeMcpSideEffectApprovalToken(binding, vault, {
			nowSeconds: () => 100,
			jti: "jti-vault-error",
		});

		await expect(verifier(verification(binding, "not-a-token", 120_000))).resolves.toEqual({
			ok: false,
			code: "approval_required",
			reason: "Invalid token format",
		});

		vault.throwOnVerify = true;
		await expect(verifier(verification(binding, token, 120_000))).resolves.toEqual({
			ok: false,
			code: "approval_required",
			reason: "Vault verification failed",
		});
		vault.throwOnVerify = false;

		await expect(verifier(verification(binding, token, 121_000))).resolves.toEqual({
			ok: true,
			approvalId: "jti-vault-error",
		});
	});

	it("integrates with the ledger by authorizing the stored ref with a real vault token", async () => {
		let capturedBinding: TelclaudeMcpSideEffectApprovalBinding | undefined;
		const realVerifier = createVerifier();
		const ledger = createTelclaudeMcpSideEffectLedger({
			nowMs: () => 100_000,
			makeRef: () => "effect-ledger-token",
			defaultTtlMs: 60_000,
			verifyApproval: async (request) => {
				if (request.approvalToken === "capture-binding") {
					capturedBinding = request.binding;
					return { ok: false, code: "approval_required", reason: "captured" };
				}
				return realVerifier(request);
			},
		});
		const prepared = ledger.prepare({
			kind: "provider",
			actorId: "telegram:123",
			profileId: "private",
			domain: "private",
			service: "calendar",
			action: "event.create",
			params: { subject: "Lunch" },
			providerAccountRef: "google:primary",
			approvalRequestId: "approval-provider-1",
			approvalRevision: 1,
			wysiwysRender: "Calendar event: Lunch",
			idempotencyKey: "idem-provider-1",
		});

		await expect(ledger.authorize(prepared.ref, "capture-binding")).resolves.toEqual({
			ok: false,
			code: "approval_required",
			reason: "captured",
			retryable: true,
			record: expect.objectContaining({ ref: prepared.ref, status: "prepared" }),
		});
		expect(capturedBinding).toBeDefined();
		if (!capturedBinding) {
			throw new Error("expected ledger verifier to capture approval binding");
		}

		const token = await generateTelclaudeMcpSideEffectApprovalToken(capturedBinding, vault, {
			nowSeconds: () => 100,
			jti: "jti-ledger",
		});
		await expect(ledger.authorize(prepared.ref, token)).resolves.toEqual({
			ok: true,
			record: expect.objectContaining({
				ref: prepared.ref,
				status: "executed",
				approvalId: "jti-ledger",
			}),
		});
	});

	function createVerifier() {
		return createTelclaudeMcpSideEffectApprovalVerifier({ vaultClient: vault, jtiStore });
	}
});

class MockVaultClient {
	readonly signCalls: Array<{ payload: string; prefix: string }> = [];
	readonly verifyCalls: Array<{ payload: string; signature: string; prefix: string }> = [];
	throwOnVerify = false;

	async signPayload(payload: string, prefix: string): Promise<{ type: string; signature: string }> {
		this.signCalls.push({ payload, prefix });
		return { type: "sign-payload", signature: signatureFor(prefix, payload) };
	}

	async verifyPayload(
		payload: string,
		signature: string,
		prefix: string,
	): Promise<{ type: string; valid: boolean }> {
		this.verifyCalls.push({ payload, signature, prefix });
		if (this.throwOnVerify) {
			throw new Error("vault unavailable");
		}
		return { type: "verify-payload", valid: signature === signatureFor(prefix, payload) };
	}
}

function providerBinding(
	overrides: Partial<TelclaudeMcpProviderApprovalBinding> = {},
): TelclaudeMcpProviderApprovalBinding {
	return {
		domainSeparator: TELCLAUDE_MCP_PROVIDER_APPROVAL_DOMAIN,
		ref: "effect-provider-1",
		kind: "provider",
		actorId: "telegram:123",
		profileId: "private",
		domain: "private",
		service: "bank",
		action: "transfer.prepare",
		providerAccountRef: "bank:primary",
		approvalRequestId: "approval-provider-1",
		approvalRevision: 1,
		idempotencyKey: "idem-provider-1",
		paramsHash: hash("a"),
		bodyHash: hash("b"),
		contentHash: hash("c"),
		...overrides,
	};
}

function outboundBinding(
	overrides: Partial<TelclaudeMcpOutboundApprovalBinding> = {},
): TelclaudeMcpOutboundApprovalBinding {
	return {
		domainSeparator: TELCLAUDE_MCP_OUTBOUND_APPROVAL_DOMAIN,
		ref: "effect-outbound-1",
		kind: "outbound",
		actorId: "telegram:123",
		profileId: "private",
		domain: "private",
		channel: "whatsapp",
		destination: "+15551234567",
		conversationRef: "whatsapp:+15551234567",
		approvalRequestId: "approval-outbound-1",
		approvalRevision: 1,
		idempotencyKey: "idem-outbound-1",
		paramsHash: hash("d"),
		bodyHash: hash("e"),
		contentHash: hash("f"),
		...overrides,
	};
}

function verification(
	binding: TelclaudeMcpSideEffectApprovalBinding,
	approvalToken: string,
	nowMs: number,
): TelclaudeMcpSideEffectApprovalVerification {
	return {
		approvalToken,
		binding,
		nowMs,
		record: {} as TelclaudeMcpSideEffectApprovalVerification["record"],
	};
}

async function signClaims(
	claims: TelclaudeMcpSideEffectApprovalClaims,
	vault: MockVaultClient,
	prefix: string,
): Promise<string> {
	const claimsB64 = Buffer.from(JSON.stringify(sortKeysDeep(claims)), "utf8").toString("base64url");
	const signed = await vault.signPayload(claimsB64, prefix);
	return `v1.${claimsB64}.${signed.signature}`;
}

function decodeTokenClaims(token: string): TelclaudeMcpSideEffectApprovalClaims {
	const [, claimsB64] = token.split(".");
	return JSON.parse(Buffer.from(claimsB64, "base64url").toString("utf8"));
}

function signatureFor(prefix: string, payload: string): string {
	return Buffer.from(`${prefix}\n${payload}`, "utf8").toString("base64url");
}

function hash(char: string): `sha256:${string}` {
	return `sha256:${char.repeat(64)}`;
}
