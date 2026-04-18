/**
 * W9 — `telclaude skills sign` / `skills verify` command tests.
 *
 * Uses a stubbed VaultClient so we can exercise the filesystem side
 * (SKILL.md.sig read/write, digest computation, signature detection)
 * without starting a real vault daemon. Integration coverage lives in
 * `tests/vault-daemon/skill-signing.test.ts` which exercises the real
 * Ed25519 primitives.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { signSkillByName, verifySkillByName } from "../../src/commands/skills-sign.js";
import { SKILL_SIGNATURE_FILENAME } from "../../src/security/skill-scanner.js";
import type { VaultClient } from "../../src/vault-daemon/client.js";

type MockVault = Pick<VaultClient, "signSkill" | "verifySkill">;

function makeVaultMock(opts: { signature?: string; valid?: boolean } = {}): MockVault {
	const sig = opts.signature ?? "base64url-signature";
	const valid = opts.valid ?? true;
	return {
		signSkill: vi.fn().mockResolvedValue({ type: "sign-skill", signature: sig }),
		verifySkill: vi.fn().mockResolvedValue({ type: "verify-skill", valid }),
	};
}

function writeDraft(
	root: string,
	name: string,
	content = [
		"---",
		"name: test",
		"description: test skill",
		"---",
		"",
		"Body.",
	].join("\n"),
): string {
	const dir = path.join(root, ".claude", "skills-draft", name);
	fs.mkdirSync(dir, { recursive: true });
	fs.writeFileSync(path.join(dir, "SKILL.md"), content, "utf8");
	return dir;
}

describe("skills sign / verify", () => {
	let tempCwd = "";
	let ORIGINAL_CWD = "";

	beforeEach(() => {
		ORIGINAL_CWD = process.cwd();
		tempCwd = fs.mkdtempSync(path.join(os.tmpdir(), "skills-sign-test-"));
		process.chdir(tempCwd);
	});

	afterEach(() => {
		process.chdir(ORIGINAL_CWD);
		fs.rmSync(tempCwd, { recursive: true, force: true });
	});

	it("rejects invalid skill names without touching the filesystem", async () => {
		const result = await signSkillByName("../etc/passwd", {
			vault: makeVaultMock() as unknown as VaultClient,
			cwd: tempCwd,
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error).toContain("Invalid skill name");
		}
	});

	it("writes a SKILL.md.sig file with the vault signature", async () => {
		const draftDir = writeDraft(tempCwd, "alpha");
		const vault = makeVaultMock({ signature: "AAA_sig" });
		const result = await signSkillByName("alpha", {
			vault: vault as unknown as VaultClient,
			cwd: tempCwd,
		});
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error("unreachable");
		expect(result.signature).toBe("AAA_sig");
		expect(result.sigPath).toBe(path.join(draftDir, SKILL_SIGNATURE_FILENAME));

		// Signature on disk
		expect(fs.existsSync(result.sigPath)).toBe(true);
		const raw = fs.readFileSync(result.sigPath, "utf8").trim();
		expect(raw).toBe("AAA_sig");

		// Digest is computed over the bytes of SKILL.md
		const content = fs.readFileSync(path.join(draftDir, "SKILL.md"));
		const expectedDigest = crypto.createHash("sha256").update(content).digest("hex");
		expect(result.digest).toBe(expectedDigest);

		expect(vault.signSkill).toHaveBeenCalledWith(expectedDigest);
	});

	it("returns an error when the skill is missing", async () => {
		const result = await signSkillByName("ghost", {
			vault: makeVaultMock() as unknown as VaultClient,
			cwd: tempCwd,
		});
		expect(result.ok).toBe(false);
	});

	it("propagates vault errors without creating a .sig file", async () => {
		const draftDir = writeDraft(tempCwd, "beta");
		const vault = {
			signSkill: vi.fn().mockRejectedValue(new Error("vault offline")),
			verifySkill: vi.fn(),
		} as unknown as VaultClient;
		const result = await signSkillByName("beta", { vault, cwd: tempCwd });
		expect(result.ok).toBe(false);
		if (result.ok) throw new Error("unreachable");
		expect(result.error).toContain("vault offline");
		expect(fs.existsSync(path.join(draftDir, SKILL_SIGNATURE_FILENAME))).toBe(false);
	});

	it("verify returns signaturePresent=false for unsigned skills", async () => {
		writeDraft(tempCwd, "gamma");
		const vault = makeVaultMock();
		const result = await verifySkillByName("gamma", {
			vault: vault as unknown as VaultClient,
			cwd: tempCwd,
		});
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error("unreachable");
		if (result.signaturePresent !== false) {
			throw new Error("expected signaturePresent=false");
		}
		expect(result.valid).toBe(false);
		expect(vault.verifySkill).not.toHaveBeenCalled();
	});

	it("verify returns valid=true when vault confirms", async () => {
		const draftDir = writeDraft(tempCwd, "delta");
		fs.writeFileSync(path.join(draftDir, SKILL_SIGNATURE_FILENAME), "sig123\n", "utf8");
		const vault = makeVaultMock({ valid: true });
		const result = await verifySkillByName("delta", {
			vault: vault as unknown as VaultClient,
			cwd: tempCwd,
		});
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error("unreachable");
		if (!result.signaturePresent) {
			throw new Error("expected signaturePresent=true");
		}
		expect(result.valid).toBe(true);
		expect(vault.verifySkill).toHaveBeenCalledWith(result.digest, "sig123");
	});

	it("verify returns valid=false when vault rejects", async () => {
		const draftDir = writeDraft(tempCwd, "epsilon");
		fs.writeFileSync(path.join(draftDir, SKILL_SIGNATURE_FILENAME), "tampered\n", "utf8");
		const vault = makeVaultMock({ valid: false });
		const result = await verifySkillByName("epsilon", {
			vault: vault as unknown as VaultClient,
			cwd: tempCwd,
		});
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error("unreachable");
		if (!result.signaturePresent) {
			throw new Error("expected signaturePresent=true");
		}
		expect(result.valid).toBe(false);
	});

	it("sign.verify roundtrip (vault mock acts as trusted verifier)", async () => {
		const draftDir = writeDraft(tempCwd, "roundtrip");
		const content = fs.readFileSync(path.join(draftDir, "SKILL.md"));
		const digest = crypto.createHash("sha256").update(content).digest("hex");

		// Use a single mock whose verifySkill returns true only for the exact
		// (digest, signature) pair produced by signSkill.
		const goodSignature = "round-sig";
		const vault = {
			signSkill: vi.fn().mockResolvedValue({
				type: "sign-skill",
				signature: goodSignature,
			}),
			verifySkill: vi.fn().mockImplementation((d: string, s: string) => ({
				type: "verify-skill",
				valid: d === digest && s === goodSignature,
			})),
		} as unknown as VaultClient;

		const signed = await signSkillByName("roundtrip", { vault, cwd: tempCwd });
		expect(signed.ok).toBe(true);
		const verified = await verifySkillByName("roundtrip", { vault, cwd: tempCwd });
		expect(verified.ok).toBe(true);
		if (!verified.ok) throw new Error("unreachable");
		if (!verified.signaturePresent) throw new Error("expected signaturePresent");
		expect(verified.valid).toBe(true);
	});
});
