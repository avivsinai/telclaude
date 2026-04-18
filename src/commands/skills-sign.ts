/**
 * `telclaude skills sign` / `telclaude skills verify` commands.
 *
 * Signs (or verifies) SKILL.md via the vault sidecar under the `skill-v1`
 * domain separation prefix. The signature is a detached Ed25519 signature
 * written to `<skill-dir>/SKILL.md.sig`.
 *
 * Signatures are OPTIONAL — unsigned skills are not blocked by the scanner;
 * they are flagged "community" in Telegram pickers and the draft-review
 * card. Signatures exist so operators can fast-path promotion of skills
 * they trust.
 *
 * Domain separation invariant: the vault hashes `skill-v1\n<digest>`
 * before signing, which means a skill signature cannot be replayed as an
 * approval token (`approval-v1`), a session token (`session-v1`), or a
 * pairing code (`pairing-v1`). See `tests/vault-daemon/skill-signing.test.ts`
 * for the cross-domain rejection test.
 */

import fs from "node:fs";
import path from "node:path";
import type { Command } from "commander";
import { getChildLogger } from "../logging.js";
import {
	computeSkillDigest,
	inspectSkillSignature,
	SKILL_SIGNATURE_FILENAME,
} from "../security/skill-scanner.js";
import { getVaultClient, type VaultClient } from "../vault-daemon/client.js";
import { getAllSkillRoots, getWritableDraftSkillRootCandidates } from "./skill-path.js";

const logger = getChildLogger({ module: "cmd-skills-sign" });

/** Strict slug pattern for skill names — no path traversal, no special chars. */
const SKILL_NAME_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/;

export type SignSkillResult =
	| { ok: true; skillName: string; digest: string; signature: string; sigPath: string }
	| { ok: false; skillName: string; error: string };

export type VerifySkillResult =
	| {
			ok: true;
			skillName: string;
			digest: string;
			/** Whether the on-disk signature verified against the vault's public key. */
			valid: boolean;
			signaturePresent: true;
	  }
	| { ok: true; skillName: string; digest?: string; valid: false; signaturePresent: false }
	| { ok: false; skillName: string; error: string };

/**
 * Locate the directory for a skill by name, searching draft roots first
 * then active roots. Signing is most often run on drafts pre-promotion.
 */
export function resolveSkillDir(skillName: string, cwd: string = process.cwd()): string | null {
	if (!SKILL_NAME_PATTERN.test(skillName)) return null;
	const draftRoots = getWritableDraftSkillRootCandidates(cwd);
	const activeRoots = getAllSkillRoots(cwd);
	for (const root of [...draftRoots, ...activeRoots]) {
		const candidate = path.join(root, skillName);
		if (fs.existsSync(path.join(candidate, "SKILL.md"))) {
			return candidate;
		}
	}
	return null;
}

/**
 * Sign SKILL.md for the given skill via the vault, writing the base64url
 * signature to `<skill-dir>/SKILL.md.sig`.
 */
export async function signSkillByName(
	skillName: string,
	options: { vault?: VaultClient; cwd?: string } = {},
): Promise<SignSkillResult> {
	if (!SKILL_NAME_PATTERN.test(skillName)) {
		return { ok: false, skillName, error: `Invalid skill name "${skillName}".` };
	}

	const skillDir = resolveSkillDir(skillName, options.cwd);
	if (!skillDir) {
		return { ok: false, skillName, error: `Skill "${skillName}" not found.` };
	}

	const skillMdPath = path.join(skillDir, "SKILL.md");
	const digest = computeSkillDigest(skillMdPath);
	if (!digest) {
		return { ok: false, skillName, error: `Cannot read ${skillMdPath}.` };
	}

	const vault = options.vault ?? getVaultClient();
	let signature: string;
	try {
		const response = await vault.signSkill(digest);
		if (response.type !== "sign-skill" || !response.signature) {
			return { ok: false, skillName, error: "Vault did not return a signature." };
		}
		signature = response.signature;
	} catch (err) {
		return { ok: false, skillName, error: `Vault sign-skill failed: ${String(err)}` };
	}

	const sigPath = path.join(skillDir, SKILL_SIGNATURE_FILENAME);
	try {
		fs.writeFileSync(sigPath, `${signature}\n`, { encoding: "utf8", mode: 0o600 });
	} catch (err) {
		return { ok: false, skillName, error: `Failed to write ${sigPath}: ${String(err)}` };
	}

	logger.info({ skillName, digestPrefix: digest.slice(0, 12) }, "skill signed");
	return { ok: true, skillName, digest, signature, sigPath };
}

/**
 * Verify the on-disk `SKILL.md.sig` against the vault's public key.
 */
export async function verifySkillByName(
	skillName: string,
	options: { vault?: VaultClient; cwd?: string } = {},
): Promise<VerifySkillResult> {
	if (!SKILL_NAME_PATTERN.test(skillName)) {
		return { ok: false, skillName, error: `Invalid skill name "${skillName}".` };
	}

	const skillDir = resolveSkillDir(skillName, options.cwd);
	if (!skillDir) {
		return { ok: false, skillName, error: `Skill "${skillName}" not found.` };
	}

	const info = inspectSkillSignature(skillDir);
	if (info.state === "unsigned") {
		return { ok: true, skillName, valid: false, signaturePresent: false, digest: info.digest };
	}
	if (info.state === "invalid" || !info.signature || !info.digest) {
		return { ok: false, skillName, error: `Signature file is empty or unreadable.` };
	}

	const vault = options.vault ?? getVaultClient();
	try {
		const response = await vault.verifySkill(info.digest, info.signature);
		if (response.type !== "verify-skill") {
			return { ok: false, skillName, error: "Unexpected vault response." };
		}
		return {
			ok: true,
			skillName,
			digest: info.digest,
			valid: response.valid,
			signaturePresent: true,
		};
	} catch (err) {
		return { ok: false, skillName, error: `Vault verify-skill failed: ${String(err)}` };
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Command registration
// ═══════════════════════════════════════════════════════════════════════════════

export function registerSkillsSignSubcommands(parent: Command): void {
	parent
		.command("sign")
		.description("Sign SKILL.md via the vault (writes SKILL.md.sig)")
		.argument("<name>", "Skill name")
		.action(async (name: string) => {
			const result = await signSkillByName(name);
			if (!result.ok) {
				console.error(`Error: ${result.error}`);
				process.exitCode = 1;
				return;
			}
			console.log(`Signed ${result.skillName}`);
			console.log(`  digest:    sha256:${result.digest}`);
			console.log(`  signature: ${result.signature.slice(0, 20)}…`);
			console.log(`  written:   ${result.sigPath}`);
		});

	parent
		.command("verify")
		.description("Verify SKILL.md.sig against the vault's public key")
		.argument("<name>", "Skill name")
		.action(async (name: string) => {
			const result = await verifySkillByName(name);
			if (!result.ok) {
				console.error(`Error: ${result.error}`);
				process.exitCode = 1;
				return;
			}
			if (!result.signaturePresent) {
				console.log(`${result.skillName}: unsigned (community skill)`);
				process.exitCode = 1;
				return;
			}
			if (result.valid) {
				console.log(`${result.skillName}: signature OK (trusted)`);
			} else {
				console.log(`${result.skillName}: signature INVALID`);
				process.exitCode = 1;
			}
		});
}
