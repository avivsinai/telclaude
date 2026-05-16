import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { VaultClient } from "../../src/vault-daemon/client.js";

const mockVault = vi.hoisted(() => ({
	signPayload: vi.fn(),
	verifyPayload: vi.fn(),
}));

vi.mock("../../src/vault-daemon/client.js", () => ({
	getVaultClient: () => mockVault,
}));

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

const item = {
	fingerprint: "codex:review:abc:v1",
	kind: "background_attention",
	severity: "medium",
	source: "codex-review",
	title: "Review Codex finding",
	summary: "Codex found a bounded follow-up worth operator review.",
	rationale: "Signed producers should be able to submit review-only suggestions.",
	entityRef: "codex:session1",
	proposedAction: { type: "review_signed_producer_item" },
	evidence: { source: "codex", issue: "runtime-producer-path" },
};

async function runCuratorCli(args: string[]): Promise<void> {
	const { registerCuratorCommand } = await import("../../src/commands/curator.js");
	const program = new Command();
	registerCuratorCommand(program);
	await program.parseAsync(args, { from: "user" });
}

describe("curator command", () => {
	let tempDir: string;
	let itemPath: string;
	let envelopePath: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-curator-cmd-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		itemPath = path.join(tempDir, "item.json");
		envelopePath = path.join(tempDir, "envelope.json");
		fs.writeFileSync(itemPath, JSON.stringify({ item }));
		mockVault.signPayload.mockReset();
		mockVault.verifyPayload.mockReset();
		vi.spyOn(console, "log").mockImplementation(() => {});
		vi.spyOn(console, "error").mockImplementation(() => {});
		vi.resetModules();
		const { resetDatabase } = await import("../../src/storage/db.js");
		resetDatabase();
	});

	afterEach(() => {
		vi.restoreAllMocks();
		process.exitCode = undefined;
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("signs Curator item JSON for a non-system producer", async () => {
		mockVault.signPayload.mockResolvedValue({ type: "sign-payload", signature: "sig" });

		await runCuratorCli([
			"curator",
			"sign-producer",
			"--item",
			itemPath,
			"--producer-kind",
			"codex",
			"--producer-id",
			"codex:session1",
			"--ttl-ms",
			"60000",
		]);

		const output = JSON.parse(String(vi.mocked(console.log).mock.calls[0]?.[0])) as {
			envelope: { producerKind: string; producerId: string; signature: string; claimsHash: string };
		};
		expect(output.envelope).toMatchObject({
			producerKind: "codex",
			producerId: "codex:session1",
			signature: "sig",
		});
		expect(output.envelope.claimsHash).toMatch(/^sha256:[a-f0-9]{64}$/);
		expect(mockVault.signPayload).toHaveBeenCalledWith(
			expect.stringContaining('"producerKind":"codex"'),
			"curator-producer-v1",
		);
	});

	it("submits a signed producer item into the operator inbox", async () => {
		const { signCuratorProducerEnvelope } = await import("../../src/curator/auth.js");
		mockVault.signPayload.mockResolvedValue({ type: "sign-payload", signature: "sig" });
		mockVault.verifyPayload.mockResolvedValue({ type: "verify-payload", valid: true });
		const envelope = await signCuratorProducerEnvelope(item, {
			vaultClient: mockVault as unknown as Pick<VaultClient, "signPayload">,
			producerKind: "claude-code",
			producerId: "claude:session1",
			ttlMs: 60_000,
		});
		fs.writeFileSync(envelopePath, JSON.stringify({ envelope }));

		await runCuratorCli([
			"curator",
			"submit-signed",
			"--item",
			itemPath,
			"--envelope",
			envelopePath,
			"--json",
		]);

		const output = JSON.parse(String(vi.mocked(console.log).mock.calls[0]?.[0])) as {
			item: { producerKind: string; producerId: string; title: string };
		};
		expect(output.item).toMatchObject({
			producerKind: "claude-code",
			producerId: "claude:session1",
			title: "Review Codex finding",
		});
		expect(mockVault.verifyPayload).toHaveBeenCalledWith(
			expect.stringContaining('"producerKind":"claude-code"'),
			"sig",
			"curator-producer-v1",
		);
	});
});
