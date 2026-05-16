import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { VaultClient } from "../../src/vault-daemon/client.js";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

const input = {
	fingerprint: "skill:review:abc:v1",
	kind: "skill_review" as const,
	severity: "low" as const,
	source: "skills",
	title: "Archive stale skill",
	summary: "Skill has not been allowed recently.",
	entityRef: "skill:agent:telegram:old-helper",
	proposedAction: { type: "archive_managed_skill", command: "telclaude skill-manage archive" },
	evidence: { skillName: "old-helper", allowedInvocations: 0 },
};

describe("curator producer auth", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-curator-auth-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		vi.resetModules();
		const { resetDatabase } = await import("../../src/storage/db.js");
		resetDatabase();
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("signs curator producer envelopes with a domain-separated prefix", async () => {
		const { CURATOR_PRODUCER_SIGNING_PREFIX, signCuratorProducerEnvelope } = await import(
			"../../src/curator/auth.js"
		);
		const vault = {
			signPayload: vi.fn().mockResolvedValue({ type: "sign-payload", signature: "sig" }),
		} as unknown as Pick<VaultClient, "signPayload">;

		const envelope = await signCuratorProducerEnvelope(input, {
			vaultClient: vault,
			producerKind: "codex",
			producerId: "codex:session1",
			nowMs: 1_000,
			ttlMs: 60_000,
		});

		expect(envelope).toMatchObject({
			producerKind: "codex",
			producerId: "codex:session1",
			expiresAtMs: 61_000,
			signature: "sig",
		});
		expect(envelope.claimsHash).toMatch(/^sha256:[a-f0-9]{64}$/);
		expect(vault.signPayload).toHaveBeenCalledWith(
			expect.stringContaining('"producerKind":"codex"'),
			CURATOR_PRODUCER_SIGNING_PREFIX,
		);
	});

	it("stores non-system producer attribution only after vault verification", async () => {
		const { signCuratorProducerEnvelope, upsertSignedCuratorItem } = await import(
			"../../src/curator/auth.js"
		);
		const vault = {
			signPayload: vi.fn().mockResolvedValue({ type: "sign-payload", signature: "sig" }),
			verifyPayload: vi.fn().mockResolvedValue({ type: "verify-payload", valid: true }),
		} as unknown as Pick<VaultClient, "signPayload" | "verifyPayload">;
		const envelope = await signCuratorProducerEnvelope(input, {
			vaultClient: vault,
			producerKind: "codex",
			producerId: "codex:session1",
			nowMs: 1_000,
			ttlMs: 60_000,
		});

		const item = await upsertSignedCuratorItem(input, envelope, {
			vaultClient: vault,
			nowMs: 2_000,
		});

		expect(item.producerKind).toBe("codex");
		expect(item.producerId).toBe("codex:session1");
		expect(vault.verifyPayload).toHaveBeenCalledWith(
			expect.stringContaining('"claimsHash"'),
			"sig",
			"curator-producer-v1",
		);
	});

	it("keeps raw store writes system-only", async () => {
		const { upsertCuratorItem } = await import("../../src/curator/store.js");

		expect(() =>
			upsertCuratorItem({
				...input,
				producerKind: "codex",
				producerId: "codex:session1",
			}),
		).toThrow(/signed curator auth/);
	});

	it("rejects expired, tampered, and invalid envelopes", async () => {
		const { signCuratorProducerEnvelope, upsertSignedCuratorItem } = await import(
			"../../src/curator/auth.js"
		);
		const vault = {
			signPayload: vi.fn().mockResolvedValue({ type: "sign-payload", signature: "sig" }),
			verifyPayload: vi.fn().mockResolvedValue({ type: "verify-payload", valid: false }),
		} as unknown as Pick<VaultClient, "signPayload" | "verifyPayload">;
		const envelope = await signCuratorProducerEnvelope(input, {
			vaultClient: vault,
			producerKind: "claude-code",
			producerId: "claude:session1",
			nowMs: 1_000,
			ttlMs: 60_000,
		});

		await expect(
			upsertSignedCuratorItem(input, envelope, { vaultClient: vault, nowMs: 61_000 }),
		).rejects.toThrow(/expired/);
		await expect(
			upsertSignedCuratorItem({ ...input, summary: "Tampered" }, envelope, {
				vaultClient: vault,
				nowMs: 2_000,
			}),
		).rejects.toThrow(/claims hash mismatch/);
		await expect(
			upsertSignedCuratorItem(input, envelope, { vaultClient: vault, nowMs: 2_000 }),
		).rejects.toThrow(/signature invalid/);
	});
});
