import { existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { JtiStore, canonicalHash, verifyApprovalToken } from "../../src/google-services/approval.js";
import type { FetchRequest } from "../../src/google-services/types.js";

// ═══════════════════════════════════════════════════════════════════════════════
// canonicalHash
// ═══════════════════════════════════════════════════════════════════════════════

describe("canonicalHash", () => {
	it("produces consistent hash for same input", () => {
		const input = {
			service: "gmail",
			action: "create_draft",
			params: { to: "a@b.com", subject: "hi" },
			actorUserId: "telegram:123",
			subjectUserId: null,
		};
		const h1 = canonicalHash(input);
		const h2 = canonicalHash(input);
		expect(h1).toBe(h2);
		expect(h1).toMatch(/^sha256:[a-f0-9]{64}$/);
	});

	it("produces different hash for different params", () => {
		const base = {
			service: "gmail",
			action: "create_draft",
			actorUserId: "telegram:123",
			subjectUserId: null,
		};
		const h1 = canonicalHash({ ...base, params: { to: "a@b.com" } });
		const h2 = canonicalHash({ ...base, params: { to: "c@d.com" } });
		expect(h1).not.toBe(h2);
	});
});

// ═══════════════════════════════════════════════════════════════════════════════
// JtiStore
// ═══════════════════════════════════════════════════════════════════════════════

describe("JtiStore", () => {
	let dir: string;
	let store: JtiStore;

	beforeEach(() => {
		dir = join(tmpdir(), `jti-test-${Date.now()}`);
		mkdirSync(dir, { recursive: true });
		store = new JtiStore(dir);
	});

	afterEach(() => {
		store.close();
		if (existsSync(dir)) rmSync(dir, { recursive: true });
	});

	it("records new JTI", () => {
		expect(store.recordJti("jti-1", Math.floor(Date.now() / 1000) + 300)).toBe(true);
	});

	it("rejects duplicate JTI (replay)", () => {
		const exp = Math.floor(Date.now() / 1000) + 300;
		expect(store.recordJti("jti-2", exp)).toBe(true);
		expect(store.recordJti("jti-2", exp)).toBe(false);
	});

	it("cleanup removes expired entries", () => {
		const past = Math.floor(Date.now() / 1000) - 10;
		store.recordJti("expired-jti", past);
		store.cleanup();
		// After cleanup, the expired JTI should be gone, so re-inserting succeeds
		expect(store.recordJti("expired-jti", past)).toBe(true);
	});
});

// ═══════════════════════════════════════════════════════════════════════════════
// verifyApprovalToken
// ═══════════════════════════════════════════════════════════════════════════════

describe("verifyApprovalToken", () => {
	let dir: string;
	let jtiStore: JtiStore;

	beforeEach(() => {
		dir = join(tmpdir(), `approval-test-${Date.now()}`);
		mkdirSync(dir, { recursive: true });
		jtiStore = new JtiStore(dir);
	});

	afterEach(() => {
		jtiStore.close();
		if (existsSync(dir)) rmSync(dir, { recursive: true });
	});

	const makeRequest = (overrides?: Partial<FetchRequest>): FetchRequest => ({
		service: "gmail",
		action: "create_draft",
		params: { to: "a@b.com", subject: "hi", body: "hello" },
		...overrides,
	});

	const makeClaims = (request: FetchRequest, actorUserId: string) => {
		const now = Math.floor(Date.now() / 1000);
		return {
			ver: 1 as const,
			iss: "telclaude-vault" as const,
			aud: "google-services" as const,
			iat: now,
			exp: now + 60,
			jti: `jti-${Date.now()}`,
			approvalNonce: "nonce-123",
			actorUserId,
			providerId: "google" as const,
			service: request.service as "gmail",
			action: request.action,
			subjectUserId: null,
			paramsHash: canonicalHash({
				service: request.service,
				action: request.action,
				params: request.params,
				actorUserId,
				subjectUserId: null,
			}),
		};
	};

	const makeToken = (claims: Record<string, unknown>, sigValid = true) => {
		const claimsB64 = Buffer.from(JSON.stringify(claims)).toString("base64url");
		const sig = "fakesig";
		return {
			token: `v1.${claimsB64}.${sig}`,
			verify: (_payload: string, _signature: string) => sigValid,
		};
	};

	it("accepts valid token for action request", () => {
		const request = makeRequest();
		const claims = makeClaims(request, "telegram:123");
		const { token, verify } = makeToken(claims);

		const result = verifyApprovalToken(token, request, "telegram:123", verify, jtiStore);
		expect(result.ok).toBe(true);
	});

	it("rejects missing/invalid format", () => {
		const result = verifyApprovalToken("bad-token", makeRequest(), "telegram:123", () => true, jtiStore);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe("approval_required");
	});

	it("rejects invalid signature", () => {
		const request = makeRequest();
		const claims = makeClaims(request, "telegram:123");
		const { token } = makeToken(claims, false);

		const result = verifyApprovalToken(token, request, "telegram:123", () => false, jtiStore);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe("approval_required");
	});

	it("rejects expired token", () => {
		const request = makeRequest();
		const claims = makeClaims(request, "telegram:123");
		claims.iat = Math.floor(Date.now() / 1000) - 400;
		claims.exp = Math.floor(Date.now() / 1000) - 100;
		const { token, verify } = makeToken(claims);

		const result = verifyApprovalToken(token, request, "telegram:123", verify, jtiStore);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe("approval_expired");
	});

	it("rejects token with wrong service", () => {
		const request = makeRequest();
		const claims = makeClaims(request, "telegram:123");
		claims.service = "calendar" as "gmail";
		const { token, verify } = makeToken(claims);

		const result = verifyApprovalToken(token, request, "telegram:123", verify, jtiStore);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe("approval_mismatch");
	});

	it("rejects token with wrong actor", () => {
		const request = makeRequest();
		const claims = makeClaims(request, "telegram:999");
		const { token, verify } = makeToken(claims);

		const result = verifyApprovalToken(token, request, "telegram:123", verify, jtiStore);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe("approval_mismatch");
	});

	it("rejects replayed token (same jti)", () => {
		const request = makeRequest();
		const claims = makeClaims(request, "telegram:123");
		const { token, verify } = makeToken(claims);

		const result1 = verifyApprovalToken(token, request, "telegram:123", verify, jtiStore);
		expect(result1.ok).toBe(true);

		const result2 = verifyApprovalToken(token, request, "telegram:123", verify, jtiStore);
		expect(result2.ok).toBe(false);
		if (!result2.ok) expect(result2.code).toBe("approval_replayed");
	});
});
