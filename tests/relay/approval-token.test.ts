import { describe, expect, it, vi } from "vitest";
import { generateApprovalToken } from "../../src/relay/approval-token.js";
import type { VaultClient } from "../../src/vault-daemon/client.js";

function createMockVaultClient(signature = "mock-signature-base64url"): VaultClient {
	return {
		signPayload: vi.fn().mockResolvedValue({
			type: "sign-payload",
			signature,
		}),
	} as unknown as VaultClient;
}

describe("generateApprovalToken", () => {
	const baseInput = {
		actorUserId: "telegram:123",
		service: "gmail",
		action: "create_draft",
		params: { to: "a@b.com", subject: "hi", body: "hello" },
		subjectUserId: null,
		approvalNonce: "nonce-abc",
	};

	it("returns v1 format token", async () => {
		const vault = createMockVaultClient();
		const token = await generateApprovalToken(baseInput, vault);

		expect(token).toMatch(/^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
	});

	it("calls vault signPayload with approval-v1 prefix", async () => {
		const vault = createMockVaultClient();
		await generateApprovalToken(baseInput, vault);

		expect(vault.signPayload).toHaveBeenCalledWith(expect.any(String), "approval-v1");
	});

	it("embeds correct claims in token", async () => {
		const vault = createMockVaultClient();
		const token = await generateApprovalToken(baseInput, vault);

		const [, claimsB64] = token.split(".");
		const claims = JSON.parse(Buffer.from(claimsB64, "base64url").toString("utf-8"));

		expect(claims.ver).toBe(1);
		expect(claims.iss).toBe("telclaude-vault");
		expect(claims.aud).toBe("google-services");
		expect(claims.actorUserId).toBe("telegram:123");
		expect(claims.service).toBe("gmail");
		expect(claims.action).toBe("create_draft");
		expect(claims.approvalNonce).toBe("nonce-abc");
		expect(claims.subjectUserId).toBeNull();
		expect(claims.paramsHash).toMatch(/^sha256:[a-f0-9]{64}$/);
	});

	it("sets exp = iat + 60 (1 minute TTL)", async () => {
		const vault = createMockVaultClient();
		const token = await generateApprovalToken(baseInput, vault);

		const [, claimsB64] = token.split(".");
		const claims = JSON.parse(Buffer.from(claimsB64, "base64url").toString("utf-8"));

		expect(claims.exp - claims.iat).toBe(60);
	});

	it("generates unique JTI for each call", async () => {
		const vault = createMockVaultClient();
		const token1 = await generateApprovalToken(baseInput, vault);
		const token2 = await generateApprovalToken(baseInput, vault);

		const claims1 = JSON.parse(Buffer.from(token1.split(".")[1], "base64url").toString());
		const claims2 = JSON.parse(Buffer.from(token2.split(".")[1], "base64url").toString());

		expect(claims1.jti).not.toBe(claims2.jti);
	});

	it("produces same paramsHash as sidecar canonicalHash", async () => {
		// Import sidecar's canonicalHash to verify consistency
		const { canonicalHash } = await import("../../src/google-services/approval.js");

		const vault = createMockVaultClient();
		const token = await generateApprovalToken(baseInput, vault);

		const claims = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString());
		const expected = canonicalHash({
			service: "gmail",
			action: "create_draft",
			params: baseInput.params,
			actorUserId: "telegram:123",
			subjectUserId: null,
		});

		expect(claims.paramsHash).toBe(expected);
	});

	it("throws when vault signing fails", async () => {
		const vault = {
			signPayload: vi.fn().mockResolvedValue({ type: "error", error: "key not found" }),
		} as unknown as VaultClient;

		await expect(generateApprovalToken(baseInput, vault)).rejects.toThrow("Vault signing failed");
	});
});
