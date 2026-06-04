import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { sortKeysDeep } from "../../src/crypto/canonical-hash.js";
import { edgePreparedPayloadHash } from "../../src/hermes/edge-adapter-runtime.js";
import {
	createTelclaudeMcpSideEffectApprovalVerifier,
	generateTelclaudeMcpSideEffectApprovalToken,
	type TelclaudeMcpSideEffectApprovalClaims,
	TelclaudeMcpSideEffectJtiStore,
} from "../../src/hermes/mcp/approval-token.js";
import {
	createTelclaudeMcpSideEffectLedger,
	getTelclaudeMcpSideEffectApprovalBinding,
	TELCLAUDE_MCP_OUTBOUND_APPROVAL_DOMAIN,
	TELCLAUDE_MCP_PROVIDER_APPROVAL_DOMAIN,
	type TelclaudeMcpOutboundApprovalBinding,
	type TelclaudeMcpOutboundSideEffectPrepareInput,
	type TelclaudeMcpProviderApprovalBinding,
	type TelclaudeMcpProviderSideEffectPrepareInput,
	type TelclaudeMcpSideEffectApprovalBinding,
	type TelclaudeMcpSideEffectApprovalVerification,
	type TelclaudeMcpSideEffectRecord,
} from "../../src/hermes/mcp/side-effect-ledger.js";

const providerMutations: Array<[string, Partial<TelclaudeMcpProviderApprovalBinding>]> = [
	["actor", { actorId: "telegram:attacker" }],
	["approver", { approverActorId: "telegram:wrong-approver" }],
	["target", { providerAccountRef: "bank:other" }],
	["params hash", { paramsHash: hash("1") }],
	["body hash", { bodyHash: hash("2") }],
	["content hash", { contentHash: hash("3") }],
	["approval revision", { approvalRevision: 2 }],
];

const outboundMutations: Array<[string, Partial<TelclaudeMcpOutboundApprovalBinding>]> = [
	["actor", { actorId: "telegram:attacker" }],
	["approver", { approverActorId: "telegram:wrong-approver" }],
	["profile", { profileId: "social" }],
	["domain", { domain: "social" }],
	["channel", { channel: "email" }],
	["destination", { destination: "alice@example.com" }],
	[
		"resolved destination conversationId",
		{
			resolvedDestination: {
				kind: "address",
				addressRef: "+15550009999",
				conversationId: "whatsapp:+15550009999",
			},
		},
	],
	["requested body", { requestedBody: "I'll pick up dinner at 20:00." }],
	[
		"prepared media refs",
		{
			preparedMediaRefs: [
				{
					quarantineId: "attachment:menu",
					contentHash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				},
			],
		},
	],
	["conversation ref", { conversationRef: "whatsapp:+15550009999" }],
	["authorization state", { authorizationState: "approval_required" }],
	["edge prepared ref", { edgePreparedRef: "edge-outbound-2" }],
	["edge prepared hash", { edgePreparedHash: "b".repeat(64) }],
	["params hash", { paramsHash: hash("1") }],
	["body hash", { bodyHash: hash("2") }],
	["content hash", { contentHash: hash("3") }],
	["approval request", { approvalRequestId: "approval-outbound-2" }],
	["approval revision", { approvalRevision: 2 }],
	["idempotency key", { idempotencyKey: "idem-outbound-2" }],
];

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
		const { binding } = providerFixture();

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
		const { binding } = providerFixture();

		await expect(
			generateTelclaudeMcpSideEffectApprovalToken(binding, vault, {
				nowSeconds: () => 100,
				ttlSeconds: 61,
				jti: "jti-too-long-ttl",
			}),
		).rejects.toThrow("ttlSeconds must be an integer between 1 and 60");
		await expect(
			generateTelclaudeMcpSideEffectApprovalToken(binding, vault, {
				nowSeconds: () => 100,
				jti: "x".repeat(257),
			}),
		).rejects.toThrow("jti must be 256 characters or less");
	});

	it("refuses to sign outbound approval bindings with malformed edge hashes", async () => {
		const { binding } = outboundFixture();

		await expect(
			generateTelclaudeMcpSideEffectApprovalToken(
				{ ...binding, edgePreparedHash: "edge-prepared-hash-1" },
				vault,
				{
					nowSeconds: () => 100,
					jti: "jti-invalid-edge-hash",
				},
			),
		).rejects.toThrow("Invalid side-effect approval binding");
	});

	it("accepts a matching token once and rejects replay through the durable JTI store", async () => {
		const { binding, record } = providerFixture();
		const verifier = createVerifier();
		const token = await generateTelclaudeMcpSideEffectApprovalToken(binding, vault, {
			nowSeconds: () => 100,
			jti: "jti-provider-replay",
		});

		await expect(verifier(verification(binding, token, 120_000, record))).resolves.toEqual({
			ok: true,
			approvalId: "jti-provider-replay",
		});
		await expect(verifier(verification(binding, token, 121_000, record))).resolves.toEqual({
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
		const provider = providerFixture();
		const outbound = outboundFixture({
			actorId: provider.binding.actorId,
			profileId: provider.binding.profileId,
			domain: provider.binding.domain,
			approvalRequestId: provider.binding.approvalRequestId,
			approvalRevision: provider.binding.approvalRevision,
		});
		const verifier = createVerifier();
		const token = await generateTelclaudeMcpSideEffectApprovalToken(provider.binding, vault, {
			nowSeconds: () => 100,
			jti: "jti-cross-domain",
		});

		await expect(
			verifier(verification(outbound.binding, token, 120_000, outbound.record)),
		).resolves.toEqual({
			ok: false,
			code: "approval_required",
			reason: "Invalid token signature",
		});
		await expect(
			verifier(verification(provider.binding, token, 121_000, provider.record)),
		).resolves.toEqual({
			ok: true,
			approvalId: "jti-cross-domain",
		});
		expect(vault.verifyCalls).toEqual([
			expect.objectContaining({ prefix: TELCLAUDE_MCP_OUTBOUND_APPROVAL_DOMAIN }),
			expect.objectContaining({ prefix: TELCLAUDE_MCP_PROVIDER_APPROVAL_DOMAIN }),
		]);
	});

	it.each(
		providerMutations,
	)("rejects caller-supplied %s binding drift before signature verification and without consuming the JTI", async (_label, mutation) => {
		const { binding, record } = providerFixture();
		const verifier = createVerifier();
		const token = await generateTelclaudeMcpSideEffectApprovalToken(binding, vault, {
			nowSeconds: () => 100,
			jti: `jti-request-drift-${String(_label).replaceAll(" ", "-")}`,
		});
		const mutated = { ...binding, ...mutation };

		await expect(verifier(verification(mutated, token, 120_000, record))).resolves.toEqual({
			ok: false,
			code: "approval_mismatch",
			reason: "Approval request binding mismatch",
		});
		expect(vault.verifyCalls).toHaveLength(0);
		await expect(verifier(verification(binding, token, 121_000, record))).resolves.toEqual({
			ok: true,
			approvalId: `jti-request-drift-${String(_label).replaceAll(" ", "-")}`,
		});
	});

	it.each(
		providerMutations,
	)("rejects token-claims %s binding drift after signature verification and without consuming the JTI", async (_label, mutation) => {
		const { binding, record } = providerFixture();
		const verifier = createVerifier();
		const jti = `jti-token-drift-${String(_label).replaceAll(" ", "-")}`;
		const mutated = { ...binding, ...mutation };
		const badToken = await generateTelclaudeMcpSideEffectApprovalToken(mutated, vault, {
			nowSeconds: () => 100,
			jti,
		});

		await expect(verifier(verification(binding, badToken, 120_000, record))).resolves.toEqual({
			ok: false,
			code: "approval_mismatch",
			reason: "Approval token binding mismatch",
		});

		const validToken = await generateTelclaudeMcpSideEffectApprovalToken(binding, vault, {
			nowSeconds: () => 100,
			jti,
		});
		await expect(verifier(verification(binding, validToken, 121_000, record))).resolves.toEqual({
			ok: true,
			approvalId: jti,
		});
	});

	it.each(
		outboundMutations,
	)("rejects caller-supplied outbound %s binding drift before signature verification and without consuming the JTI", async (_label, mutation) => {
		const { binding, record } = outboundFixture();
		const verifier = createVerifier();
		const jti = `jti-outbound-request-drift-${String(_label).replaceAll(" ", "-")}`;
		const token = await generateTelclaudeMcpSideEffectApprovalToken(binding, vault, {
			nowSeconds: () => 100,
			jti,
		});
		const mutated = { ...binding, ...mutation };

		await expect(verifier(verification(mutated, token, 120_000, record))).resolves.toEqual({
			ok: false,
			code: "approval_mismatch",
			reason: "Approval request binding mismatch",
		});
		expect(vault.verifyCalls).toHaveLength(0);
		await expect(verifier(verification(binding, token, 121_000, record))).resolves.toEqual({
			ok: true,
			approvalId: jti,
		});
	});

	it.each(
		outboundMutations,
	)("rejects outbound token-claims %s binding drift after signature verification and without consuming the JTI", async (_label, mutation) => {
		const { binding, record } = outboundFixture();
		const verifier = createVerifier();
		const jti = `jti-outbound-token-drift-${String(_label).replaceAll(" ", "-")}`;
		const mutated = { ...binding, ...mutation };
		const badToken = await generateTelclaudeMcpSideEffectApprovalToken(mutated, vault, {
			nowSeconds: () => 100,
			jti,
		});

		await expect(verifier(verification(binding, badToken, 120_000, record))).resolves.toEqual({
			ok: false,
			code: "approval_mismatch",
			reason: "Approval token binding mismatch",
		});

		const validToken = await generateTelclaudeMcpSideEffectApprovalToken(binding, vault, {
			nowSeconds: () => 100,
			jti,
		});
		await expect(verifier(verification(binding, validToken, 121_000, record))).resolves.toEqual({
			ok: true,
			approvalId: jti,
		});
	});

	it("accepts social MCP domains for outbound tokens and rejects edge-only public-social domains", async () => {
		const { binding } = outboundFixture({ domain: "social", profileId: "social" });

		await expect(
			generateTelclaudeMcpSideEffectApprovalToken(binding, vault, {
				nowSeconds: () => 100,
				jti: "jti-social-outbound",
			}),
		).resolves.toMatch(/^v1\./);
		await expect(
			generateTelclaudeMcpSideEffectApprovalToken(
				{ ...binding, domain: "public-social" } as unknown as TelclaudeMcpOutboundApprovalBinding,
				vault,
				{
					nowSeconds: () => 100,
					jti: "jti-public-social-outbound",
				},
			),
		).rejects.toThrow("Invalid side-effect approval binding");
	});

	it("applies replay and expiry windows to outbound approval tokens", async () => {
		const { binding, record } = outboundFixture();
		const verifier = createVerifier();
		const token = await generateTelclaudeMcpSideEffectApprovalToken(binding, vault, {
			nowSeconds: () => 100,
			jti: "jti-outbound-replay",
		});

		await expect(verifier(verification(binding, token, 120_000, record))).resolves.toEqual({
			ok: true,
			approvalId: "jti-outbound-replay",
		});
		await expect(verifier(verification(binding, token, 121_000, record))).resolves.toEqual({
			ok: false,
			code: "approval_replayed",
			reason: "Approval token already used",
		});

		const expired = await generateTelclaudeMcpSideEffectApprovalToken(binding, vault, {
			nowSeconds: () => 100,
			ttlSeconds: 60,
			jti: "jti-outbound-expired",
		});
		await expect(verifier(verification(binding, expired, 161_000, record))).resolves.toEqual({
			ok: false,
			code: "approval_expired",
			reason: "Token expired",
		});
		const expiredRetry = await generateTelclaudeMcpSideEffectApprovalToken(binding, vault, {
			nowSeconds: () => 120,
			jti: "jti-outbound-expired",
		});
		await expect(verifier(verification(binding, expiredRetry, 121_000, record))).resolves.toEqual({
			ok: true,
			approvalId: "jti-outbound-expired",
		});
	});

	it("rejects expired and overlong-TTL tokens before consuming their JTI", async () => {
		const { binding, record } = providerFixture();
		const verifier = createVerifier();
		const expired = await generateTelclaudeMcpSideEffectApprovalToken(binding, vault, {
			nowSeconds: () => 100,
			ttlSeconds: 60,
			jti: "jti-expired",
		});

		await expect(verifier(verification(binding, expired, 161_000, record))).resolves.toEqual({
			ok: false,
			code: "approval_expired",
			reason: "Token expired",
		});

		const expiredRetry = await generateTelclaudeMcpSideEffectApprovalToken(binding, vault, {
			nowSeconds: () => 120,
			jti: "jti-expired",
		});
		await expect(verifier(verification(binding, expiredRetry, 121_000, record))).resolves.toEqual({
			ok: true,
			approvalId: "jti-expired",
		});

		const overlong = await signClaims(
			{
				ver: 1,
				iss: "telclaude-vault",
				aud: "telclaude-hermes-mcp-side-effect",
				iat: 100,
				exp: 220,
				jti: "jti-overlong",
				binding,
			},
			vault,
			binding.domainSeparator,
		);
		await expect(verifier(verification(binding, overlong, 120_000, record))).resolves.toEqual({
			ok: false,
			code: "approval_required",
			reason: "Token TTL exceeds maximum (60s)",
		});

		const retry = await generateTelclaudeMcpSideEffectApprovalToken(binding, vault, {
			nowSeconds: () => 100,
			jti: "jti-overlong",
		});
		await expect(verifier(verification(binding, retry, 121_000, record))).resolves.toEqual({
			ok: true,
			approvalId: "jti-overlong",
		});
	});

	it("fails closed on malformed tokens, verifier clocks, and vault verification errors without consuming", async () => {
		const { binding, record } = providerFixture();
		const verifier = createVerifier();
		const token = await generateTelclaudeMcpSideEffectApprovalToken(binding, vault, {
			nowSeconds: () => 100,
			jti: "jti-vault-error",
		});

		await expect(verifier(verification(binding, "not-a-token", 120_000, record))).resolves.toEqual({
			ok: false,
			code: "approval_required",
			reason: "Invalid token format",
		});
		await expect(verifier(verification(binding, token, Number.NaN, record))).resolves.toEqual({
			ok: false,
			code: "approval_required",
			reason: "Invalid verifier clock",
		});

		vault.throwOnVerify = true;
		await expect(verifier(verification(binding, token, 120_000, record))).resolves.toEqual({
			ok: false,
			code: "approval_required",
			reason: "Vault verification failed",
		});
		vault.throwOnVerify = false;

		await expect(verifier(verification(binding, token, 121_000, record))).resolves.toEqual({
			ok: true,
			approvalId: "jti-vault-error",
		});
	});

	it("integrates with the ledger by authorizing the stored ref with a real vault token", async () => {
		const realVerifier = createVerifier();
		const ledger = createTelclaudeMcpSideEffectLedger({
			nowMs: () => 100_000,
			makeRef: () => "effect-ledger-token",
			defaultTtlMs: 60_000,
			verifyApproval: realVerifier,
		});
		const prepared = ledger.prepare(providerPrepareInput());
		const binding = getTelclaudeMcpSideEffectApprovalBinding(prepared);
		const token = await generateTelclaudeMcpSideEffectApprovalToken(binding, vault, {
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

function providerFixture(
	overrides: Partial<Omit<TelclaudeMcpProviderSideEffectPrepareInput, "kind">> = {},
): {
	readonly record: TelclaudeMcpSideEffectRecord;
	readonly binding: TelclaudeMcpProviderApprovalBinding;
} {
	const record = prepareFixture(providerPrepareInput(overrides));
	const binding = getTelclaudeMcpSideEffectApprovalBinding(record);
	if (binding.kind !== "provider") throw new Error("expected provider binding");
	return { record, binding };
}

function outboundFixture(
	overrides: Partial<Omit<TelclaudeMcpOutboundSideEffectPrepareInput, "kind">> = {},
): {
	readonly record: TelclaudeMcpSideEffectRecord;
	readonly binding: TelclaudeMcpOutboundApprovalBinding;
} {
	const record = prepareFixture(outboundPrepareInput(overrides));
	const binding = getTelclaudeMcpSideEffectApprovalBinding(record);
	if (binding.kind !== "outbound") throw new Error("expected outbound binding");
	return { record, binding };
}

let fixtureRefCounter = 0;

function prepareFixture(
	input: TelclaudeMcpProviderSideEffectPrepareInput | TelclaudeMcpOutboundSideEffectPrepareInput,
): TelclaudeMcpSideEffectRecord {
	const ledger = createTelclaudeMcpSideEffectLedger({
		nowMs: () => 100_000,
		makeRef: () => `effect-token-${++fixtureRefCounter}`,
		defaultTtlMs: 60_000,
		verifyApproval: async () => ({ ok: false, code: "approval_required", reason: "unused" }),
	});
	return ledger.prepare(input);
}

function providerPrepareInput(
	overrides: Partial<Omit<TelclaudeMcpProviderSideEffectPrepareInput, "kind">> = {},
): TelclaudeMcpProviderSideEffectPrepareInput {
	return {
		kind: "provider",
		actorId: "telegram:123",
		approverActorId: "telegram:operator",
		profileId: "private",
		domain: "private",
		providerId: "bank",
		service: "bank",
		action: "transfer.prepare",
		params: { amount: 100, currency: "ILS" },
		providerAccountRef: "bank:primary",
		approvalRequestId: "approval-provider-1",
		approvalRevision: 1,
		wysiwysRender: "Transfer ILS 100 to saved recipient",
		idempotencyKey: "idem-provider-1",
		...overrides,
	};
}

function outboundPrepareInput(
	overrides: Partial<Omit<TelclaudeMcpOutboundSideEffectPrepareInput, "kind">> = {},
): TelclaudeMcpOutboundSideEffectPrepareInput {
	const channel = "whatsapp";
	const requestedBody = "I'll pick up dinner at 19:00.";
	const resolvedDestination = {
		kind: "address" as const,
		addressRef: "+15551234567",
		conversationId: "whatsapp:+15551234567",
	};
	const preparedMediaRefs = [
		{
			quarantineId: "attachment:menu",
			contentHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	];
	return {
		kind: "outbound",
		actorId: "telegram:123",
		approverActorId: "telegram:operator",
		profileId: "private",
		domain: "private",
		channel,
		destination: "+15551234567",
		resolvedDestination,
		requestedBody,
		renderedBody: requestedBody,
		mediaRefs: ["attachment:menu"],
		preparedMediaRefs,
		conversationRef: "whatsapp:+15551234567",
		authorizationState: "authorized",
		edgePreparedRef: "edge-outbound-1",
		edgePreparedHash: edgePreparedPayloadHash({
			channel,
			resolvedDestination,
			body: requestedBody,
			mediaRefs: preparedMediaRefs,
		}),
		approvalRequestId: "approval-outbound-1",
		approvalRevision: 1,
		approvalMetadata: { category: "family-logistics" },
		idempotencyKey: "idem-outbound-1",
		...overrides,
	};
}

function verification(
	binding: TelclaudeMcpSideEffectApprovalBinding,
	approvalToken: string,
	nowMs: number,
	record: TelclaudeMcpSideEffectRecord,
): TelclaudeMcpSideEffectApprovalVerification {
	return {
		approvalToken,
		binding,
		record,
		nowMs,
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
