import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { FixAction, FixReport } from "../../src/commands/audit-fixers.js";
import { formatFixReport, runAutoFix } from "../../src/commands/audit-fixers.js";
import type { TelclaudeConfig } from "../../src/config/config.js";

// ═══════════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════════

let tmpDir: string;

function makeMinimalConfig(overrides?: Partial<TelclaudeConfig>): TelclaudeConfig {
	const base: TelclaudeConfig = {
		telegram: { heartbeatSeconds: 60 },
		inbound: { reply: { enabled: true, timeoutSeconds: 600, typingIntervalSeconds: 8 } },
		transcription: { provider: "openai", model: "whisper-1", timeoutSeconds: 60 },
		imageGeneration: {
			provider: "gpt-image",
			model: "gpt-image-1.5",
			size: "1024x1024",
			quality: "medium",
			maxPerHourPerUser: 10,
			maxPerDayPerUser: 50,
		},
		videoProcessing: {
			enabled: false,
			frameInterval: 1,
			maxFrames: 30,
			maxDurationSeconds: 300,
			extractAudio: true,
		},
		tts: {
			provider: "openai",
			voice: "alloy",
			speed: 1.0,
			autoReadResponses: false,
			maxPerHourPerUser: 30,
			maxPerDayPerUser: 100,
		},
		security: {
			profile: "simple",
			permissions: { defaultTier: "READ_ONLY", users: {} },
			rateLimits: {
				global: { perMinute: 100, perHour: 1000 },
				perUser: { perMinute: 10, perHour: 100 },
			},
			audit: { enabled: true },
		},
		socialServices: [],
	} as unknown as TelclaudeConfig;

	if (overrides) {
		return { ...base, ...overrides } as TelclaudeConfig;
	}
	return base;
}

function writeJsonFile(filePath: string, content: unknown): void {
	const dir = path.dirname(filePath);
	fs.mkdirSync(dir, { recursive: true });
	fs.writeFileSync(filePath, `${JSON.stringify(content, null, "\t")}\n`, "utf-8");
}

function findByKind(actions: FixAction[], kind: string): FixAction[] {
	return actions.filter((a) => a.kind === kind);
}

function findApplied(actions: FixAction[]): FixAction[] {
	return actions.filter((a) => a.applied);
}

function findByTarget(actions: FixAction[], substring: string): FixAction | undefined {
	return actions.find((a) => a.target.includes(substring));
}

beforeEach(() => {
	tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "audit-fixers-test-"));
});

afterEach(() => {
	fs.rmSync(tmpDir, { recursive: true, force: true });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Config fixes
// ═══════════════════════════════════════════════════════════════════════════════

describe("config fixes", () => {
	it("changes test profile to simple", () => {
		const cfg = makeMinimalConfig({
			security: {
				profile: "test",
				permissions: { defaultTier: "READ_ONLY", users: {} },
				rateLimits: {
					global: { perMinute: 100, perHour: 1000 },
					perUser: { perMinute: 10, perHour: 100 },
				},
				audit: { enabled: true },
			},
		} as Partial<TelclaudeConfig>);

		const configPath = path.join(tmpDir, "telclaude.json");
		writeJsonFile(configPath, cfg);

		const report = runAutoFix(cfg, configPath, tmpDir, {});
		const profileFix = findByTarget(report.actions, "security.profile");
		expect(profileFix).toBeDefined();
		expect(profileFix!.applied).toBe(true);
		expect(profileFix!.before).toBe("test");
		expect(profileFix!.after).toBe("simple");

		// Verify atomic write created backup
		expect(report.configBackupPath).toBeTruthy();
		expect(fs.existsSync(report.configBackupPath!)).toBe(true);

		// Verify the config was actually written
		const written = JSON.parse(fs.readFileSync(configPath, "utf-8"));
		expect(written.security.profile).toBe("simple");
	});

	it("skips test profile fix when TELCLAUDE_ENABLE_TEST_PROFILE=1", () => {
		const cfg = makeMinimalConfig({
			security: {
				profile: "test",
				permissions: { defaultTier: "READ_ONLY", users: {} },
				rateLimits: {
					global: { perMinute: 100, perHour: 1000 },
					perUser: { perMinute: 10, perHour: 100 },
				},
				audit: { enabled: true },
			},
		} as Partial<TelclaudeConfig>);

		const configPath = path.join(tmpDir, "telclaude.json");
		writeJsonFile(configPath, cfg);

		const report = runAutoFix(cfg, configPath, tmpDir, {
			TELCLAUDE_ENABLE_TEST_PROFILE: "1",
		});

		const profileFix = findByTarget(report.actions, "security.profile");
		expect(profileFix).toBeDefined();
		expect(profileFix!.applied).toBe(false);
		expect(profileFix!.skipped).toContain("intentional test mode");
	});

	it("lowers FULL_ACCESS default tier to READ_ONLY", () => {
		const cfg = makeMinimalConfig({
			security: {
				profile: "simple",
				permissions: { defaultTier: "FULL_ACCESS", users: {} },
				rateLimits: {
					global: { perMinute: 100, perHour: 1000 },
					perUser: { perMinute: 10, perHour: 100 },
				},
				audit: { enabled: true },
			},
		} as Partial<TelclaudeConfig>);

		const configPath = path.join(tmpDir, "telclaude.json");
		writeJsonFile(configPath, cfg);

		const report = runAutoFix(cfg, configPath, tmpDir, {});
		const tierFix = findByTarget(report.actions, "defaultTier");
		expect(tierFix).toBeDefined();
		expect(tierFix!.applied).toBe(true);
		expect(tierFix!.before).toBe("FULL_ACCESS");
		expect(tierFix!.after).toBe("READ_ONLY");

		const written = JSON.parse(fs.readFileSync(configPath, "utf-8"));
		expect(written.security.permissions.defaultTier).toBe("READ_ONLY");
	});

	it("enables audit logging when disabled", () => {
		const cfg = makeMinimalConfig({
			security: {
				profile: "simple",
				permissions: { defaultTier: "READ_ONLY", users: {} },
				rateLimits: {
					global: { perMinute: 100, perHour: 1000 },
					perUser: { perMinute: 10, perHour: 100 },
				},
				audit: { enabled: false },
			},
		} as Partial<TelclaudeConfig>);

		const configPath = path.join(tmpDir, "telclaude.json");
		writeJsonFile(configPath, cfg);

		const report = runAutoFix(cfg, configPath, tmpDir, {});
		const auditFix = findByTarget(report.actions, "audit.enabled");
		expect(auditFix).toBeDefined();
		expect(auditFix!.applied).toBe(true);

		const written = JSON.parse(fs.readFileSync(configPath, "utf-8"));
		expect(written.security.audit.enabled).toBe(true);
	});

	it("does not write config when no config changes needed", () => {
		const cfg = makeMinimalConfig();
		const configPath = path.join(tmpDir, "telclaude.json");
		writeJsonFile(configPath, cfg);

		const report = runAutoFix(cfg, configPath, tmpDir, {});
		expect(report.configBackupPath).toBeNull();
		// No .bak file should exist
		expect(fs.existsSync(`${configPath}.bak`)).toBe(false);
	});
});

// ═══════════════════════════════════════════════════════════════════════════════
// Raw-policy-only write (private-overlay leak regression)
//
// `runAutoFix(_cfg, configPath, ...)` receives the fully MERGED config as `_cfg`
// (what loadConfig() produces: raw policy + telclaude.runtime.json overlay +
// TELCLAUDE_PRIVATE_CONFIG overlay + Zod defaults). The fix must derive its decisions
// AND its rewrite SOLELY from JSON5.parse(configPath) — the sparse raw policy file —
// never from `_cfg`. The old behavior stringified the merged `_cfg` back into the
// policy file, leaking private-only values (telegram.allowedChats,
// security.permissions.users, botToken, moltbook.adminChatId) into the agent-readable
// policy file. These tests fail against that old merged-write behavior.
// ═══════════════════════════════════════════════════════════════════════════════

describe("raw-policy-only write (no overlay/default leak)", () => {
	// Sentinel values that exist ONLY in the merged config / private overlay, never in
	// the raw policy file on disk. If any of these surface in the rewritten policy file,
	// the fixer leaked merged state.
	const PRIVATE_BOT_TOKEN = "1111111111:LEAKED-PRIVATE-BOT-TOKEN-do-not-write"; // gitleaks:allow -- fake sentinel, not a real bot token
	const PRIVATE_ALLOWED_CHAT = 7_001_002_003;
	const PRIVATE_ADMIN_CHAT = 9_008_007_006;
	const PRIVATE_USER_ID = "424242";

	/** A merged config (loadConfig() shape) carrying private-only values, as the real caller passes. */
	function makeMergedConfigWithPrivateValues(
		securityOverride: Record<string, unknown>,
	): TelclaudeConfig {
		return makeMinimalConfig({
			telegram: {
				heartbeatSeconds: 60,
				allowedChats: [PRIVATE_ALLOWED_CHAT],
				botToken: PRIVATE_BOT_TOKEN,
			},
			moltbook: { adminChatId: PRIVATE_ADMIN_CHAT },
			security: securityOverride,
		} as unknown as Partial<TelclaudeConfig>);
	}

	/** Walk a parsed-JSON object along `keys`, returning undefined if any segment is absent. */
	function at(obj: Record<string, unknown>, ...keys: string[]): unknown {
		let cur: unknown = obj;
		for (const key of keys) {
			if (typeof cur !== "object" || cur === null) return undefined;
			cur = (cur as Record<string, unknown>)[key];
		}
		return cur;
	}

	function assertNoPrivateValuesLeaked(
		writtenText: string,
		written: Record<string, unknown>,
	): void {
		// Raw text scan: catches the value showing up anywhere in the rewritten file.
		expect(writtenText).not.toContain(PRIVATE_BOT_TOKEN);
		expect(writtenText).not.toContain(String(PRIVATE_ALLOWED_CHAT));
		expect(writtenText).not.toContain(String(PRIVATE_ADMIN_CHAT));
		expect(writtenText).not.toContain(PRIVATE_USER_ID);
		// Structural scan: the private-only keys must not exist in the policy object.
		expect(at(written, "telegram", "allowedChats")).toBeUndefined();
		expect(at(written, "telegram", "botToken")).toBeUndefined();
		expect(at(written, "moltbook")).toBeUndefined();
		expect(at(written, "security", "permissions", "users")).toBeUndefined();
	}

	it("corrects the misconfig but does not bake private-overlay values into the policy file (test profile)", () => {
		// Raw policy file is SPARSE: only the fixable misconfig, no private keys.
		const rawPolicy = { security: { profile: "test" } };
		const configPath = path.join(tmpDir, "telclaude.json");
		writeJsonFile(configPath, rawPolicy);

		// Merged config (what loadConfig + private overlay produce) DOES carry private values.
		const merged = makeMergedConfigWithPrivateValues({
			profile: "test",
			permissions: {
				defaultTier: "READ_ONLY",
				users: { [PRIVATE_USER_ID]: { tier: "FULL_ACCESS" } },
			},
			rateLimits: {
				global: { perMinute: 100, perHour: 1000 },
				perUser: { perMinute: 10, perHour: 100 },
			},
			audit: { enabled: true },
		});

		const report = runAutoFix(merged, configPath, tmpDir, {});

		// (a) The misconfig was corrected.
		const profileFix = findByTarget(report.actions, "security.profile");
		expect(profileFix?.applied).toBe(true);
		expect(profileFix?.after).toBe("simple");

		const writtenText = fs.readFileSync(configPath, "utf-8");
		const written = JSON.parse(writtenText);
		expect(written.security.profile).toBe("simple");

		// (b) No private-overlay values leaked into the agent-readable policy file.
		assertNoPrivateValuesLeaked(writtenText, written);
	});

	it("does not inject Zod-defaulted keys from the merged config into the policy file", () => {
		// Raw policy mentions ONLY security.audit; the merged config is fully populated
		// with defaults (transcription, tts, imageGeneration, rateLimits, etc.).
		const rawPolicy = { security: { audit: { enabled: false } } };
		const configPath = path.join(tmpDir, "telclaude.json");
		writeJsonFile(configPath, rawPolicy);

		const merged = makeMergedConfigWithPrivateValues({
			profile: "simple",
			permissions: {
				defaultTier: "READ_ONLY",
				users: { [PRIVATE_USER_ID]: { tier: "FULL_ACCESS" } },
			},
			rateLimits: {
				global: { perMinute: 100, perHour: 1000 },
				perUser: { perMinute: 10, perHour: 100 },
			},
			audit: { enabled: false },
		});

		const report = runAutoFix(merged, configPath, tmpDir, {});

		const auditFix = findByTarget(report.actions, "audit.enabled");
		expect(auditFix?.applied).toBe(true);

		const writtenText = fs.readFileSync(configPath, "utf-8");
		const written = JSON.parse(writtenText);

		// Fix applied to the raw policy.
		expect(written.security.audit.enabled).toBe(true);
		// Raw policy never mentioned profile/permissions; the merged defaults must NOT appear.
		expect(written.security.profile).toBeUndefined();
		expect(written.security.permissions).toBeUndefined();
		// Top-level defaulted subtrees from the merged config must NOT be written.
		expect(written.transcription).toBeUndefined();
		expect(written.tts).toBeUndefined();
		expect(written.imageGeneration).toBeUndefined();
		assertNoPrivateValuesLeaked(writtenText, written);
	});

	it("only fixes values the operator actually wrote in the policy file (overlay-only danger is invisible)", () => {
		// The dangerous defaultTier=FULL_ACCESS lives ONLY in the merged config (e.g. from the
		// private overlay), NOT in the raw policy. The fixer must NOT touch the policy file for it.
		const rawPolicy = { security: { profile: "simple" } };
		const configPath = path.join(tmpDir, "telclaude.json");
		writeJsonFile(configPath, rawPolicy);

		const merged = makeMergedConfigWithPrivateValues({
			profile: "simple",
			permissions: {
				defaultTier: "FULL_ACCESS",
				users: { [PRIVATE_USER_ID]: { tier: "FULL_ACCESS" } },
			},
			rateLimits: {
				global: { perMinute: 100, perHour: 1000 },
				perUser: { perMinute: 10, perHour: 100 },
			},
			audit: { enabled: true },
		});

		const report = runAutoFix(merged, configPath, tmpDir, {});

		// No tier fix fired — the policy file never declared defaultTier.
		const tierFix = findByTarget(report.actions, "defaultTier");
		expect(tierFix).toBeUndefined();
		// No config write at all → no backup.
		expect(report.configBackupPath).toBeNull();

		const writtenText = fs.readFileSync(configPath, "utf-8");
		const written = JSON.parse(writtenText);
		// Policy file is untouched: still just the sparse raw shape, no overlay state folded in.
		expect(written.security.permissions).toBeUndefined();
		assertNoPrivateValuesLeaked(writtenText, written);
	});
});

// ═══════════════════════════════════════════════════════════════════════════════
// Overlay guard contract
//
// The documented protection is STRUCTURAL: runAutoFix never calls loadConfig() and
// never reads TELCLAUDE_PRIVATE_CONFIG, so the private overlay can never be folded into
// the rewritten policy file — even when the env var is set and points at a real overlay
// file. There is NO explicit refusal in audit-fixers.ts (verified by reading the code);
// the contract is "raw-only, regardless of the overlay env var". These tests assert that
// REAL contract, not an invented refusal.
// ═══════════════════════════════════════════════════════════════════════════════

describe("overlay guard (raw-only regardless of TELCLAUDE_PRIVATE_CONFIG)", () => {
	const PRIVATE_BOT_TOKEN = "2222222222:OVERLAY-TOKEN-must-not-leak"; // gitleaks:allow -- fake sentinel, not a real bot token
	const PRIVATE_ALLOWED_CHAT = 8_111_222_333;

	it("writes only the raw policy even when TELCLAUDE_PRIVATE_CONFIG is set and points at a real overlay", () => {
		// A real private-overlay file on disk, holding exactly the sensitive keys the relay owns.
		const privateOverlayPath = path.join(tmpDir, "telclaude-private.json");
		writeJsonFile(privateOverlayPath, {
			telegram: { allowedChats: [PRIVATE_ALLOWED_CHAT], botToken: PRIVATE_BOT_TOKEN },
			security: { permissions: { users: { "777": { tier: "FULL_ACCESS" } } } },
		});

		// Sparse raw policy with a fixable misconfig.
		const rawPolicy = { security: { profile: "test" } };
		const configPath = path.join(tmpDir, "telclaude.json");
		writeJsonFile(configPath, rawPolicy);

		// Merged config carries the overlay values, mirroring loadConfig() with the env var set.
		const merged = makeMinimalConfig({
			telegram: {
				heartbeatSeconds: 60,
				allowedChats: [PRIVATE_ALLOWED_CHAT],
				botToken: PRIVATE_BOT_TOKEN,
			},
			security: {
				profile: "test",
				permissions: { defaultTier: "READ_ONLY", users: { "777": { tier: "FULL_ACCESS" } } },
				rateLimits: {
					global: { perMinute: 100, perHour: 1000 },
					perUser: { perMinute: 10, perHour: 100 },
				},
				audit: { enabled: true },
			},
		} as unknown as Partial<TelclaudeConfig>);

		const report = runAutoFix(merged, configPath, tmpDir, {
			TELCLAUDE_PRIVATE_CONFIG: privateOverlayPath,
		});

		// The fixer still applies the raw-policy fix (it does not refuse when the env var is set)...
		const profileFix = findByTarget(report.actions, "security.profile");
		expect(profileFix?.applied).toBe(true);
		expect(profileFix?.after).toBe("simple");

		const writtenText = fs.readFileSync(configPath, "utf-8");
		const written = JSON.parse(writtenText);
		expect(written.security.profile).toBe("simple");

		// ...and the overlay's private values never reach the policy file.
		expect(writtenText).not.toContain(PRIVATE_BOT_TOKEN);
		expect(writtenText).not.toContain(String(PRIVATE_ALLOWED_CHAT));
		expect(written.telegram?.allowedChats).toBeUndefined();
		expect(written.telegram?.botToken).toBeUndefined();
		expect(written.security?.permissions?.users).toBeUndefined();
	});
});

// ═══════════════════════════════════════════════════════════════════════════════
// Malformed raw policy (try/catch fix)
//
// applyConfigFixes (ensureObject/readObject) throws when security or a known subtree is a
// non-object. runAutoFix wraps the parse + fix + write in one try/catch, so a malformed
// policy surfaces a single clear error action (applied:false, error set) rather than an
// uncaught/unhandled exception, and it does NOT rewrite the policy file.
// ═══════════════════════════════════════════════════════════════════════════════

describe("malformed raw policy fails cleanly (no uncaught throw)", () => {
	it("non-object security subtree yields an error action, not a thrown exception", () => {
		const rawPolicy = { security: "not-an-object" };
		const configPath = path.join(tmpDir, "telclaude.json");
		writeJsonFile(configPath, rawPolicy);
		const before = fs.readFileSync(configPath, "utf-8");
		const cfg = makeMinimalConfig();

		// The call itself must not throw.
		expect(() => runAutoFix(cfg, configPath, tmpDir, {})).not.toThrow();
		const report: FixReport = runAutoFix(cfg, configPath, tmpDir, {});

		const configError = report.actions.find(
			(a) => a.kind === "config" && a.error && a.target === configPath,
		);
		expect(configError).toBeDefined();
		expect(configError?.applied).toBe(false);
		expect(configError?.error).toContain("may be malformed");
		expect(report.summary.errors).toBeGreaterThanOrEqual(1);

		// The malformed policy file is left untouched (no half-applied rewrite, no backup).
		expect(fs.readFileSync(configPath, "utf-8")).toBe(before);
		expect(report.configBackupPath).toBeNull();
		expect(fs.existsSync(`${configPath}.bak`)).toBe(false);
	});

	it("non-object security.permissions subtree fails cleanly too", () => {
		const rawPolicy = { security: { profile: "test", permissions: ["not", "an", "object"] } };
		const configPath = path.join(tmpDir, "telclaude.json");
		writeJsonFile(configPath, rawPolicy);
		const before = fs.readFileSync(configPath, "utf-8");
		const cfg = makeMinimalConfig();

		expect(() => runAutoFix(cfg, configPath, tmpDir, {})).not.toThrow();
		const report: FixReport = runAutoFix(cfg, configPath, tmpDir, {});

		const configError = report.actions.find(
			(a) => a.kind === "config" && a.error && a.target === configPath,
		);
		expect(configError).toBeDefined();
		expect(configError?.error).toContain("malformed");
		// readObject reports which subtree was wrong.
		expect(configError?.error).toContain("permissions");

		// File untouched despite the profile:test misconfig that would otherwise have been fixed.
		expect(fs.readFileSync(configPath, "utf-8")).toBe(before);
		expect(report.configBackupPath).toBeNull();
	});

	it("malformed JSON5 in the policy file fails cleanly", () => {
		const configPath = path.join(tmpDir, "telclaude.json");
		fs.writeFileSync(configPath, "{ this is : not valid json5 ", "utf-8");
		const before = fs.readFileSync(configPath, "utf-8");
		const cfg = makeMinimalConfig();

		expect(() => runAutoFix(cfg, configPath, tmpDir, {})).not.toThrow();
		const report: FixReport = runAutoFix(cfg, configPath, tmpDir, {});

		const configError = report.actions.find(
			(a) => a.kind === "config" && a.error && a.target === configPath,
		);
		expect(configError).toBeDefined();
		expect(configError?.applied).toBe(false);

		// Unparseable file is left exactly as-is.
		expect(fs.readFileSync(configPath, "utf-8")).toBe(before);
		expect(report.configBackupPath).toBeNull();
	});
});

// ═══════════════════════════════════════════════════════════════════════════════
// Atomic write + backup
// ═══════════════════════════════════════════════════════════════════════════════

describe("atomic write + backup", () => {
	it("creates .bak with original content", () => {
		const cfg = makeMinimalConfig({
			security: {
				profile: "test",
				permissions: { defaultTier: "READ_ONLY", users: {} },
				rateLimits: {
					global: { perMinute: 100, perHour: 1000 },
					perUser: { perMinute: 10, perHour: 100 },
				},
				audit: { enabled: true },
			},
		} as Partial<TelclaudeConfig>);

		const configPath = path.join(tmpDir, "telclaude.json");
		const originalContent = `${JSON.stringify(cfg, null, "\t")}\n`;
		writeJsonFile(configPath, cfg);

		runAutoFix(cfg, configPath, tmpDir, {});

		const bakPath = `${configPath}.bak`;
		expect(fs.existsSync(bakPath)).toBe(true);

		// Backup should contain the original config
		const bakContent = fs.readFileSync(bakPath, "utf-8");
		const bakParsed = JSON.parse(bakContent);
		expect(bakParsed.security.profile).toBe("test");
	});

	it("sets 600 permissions on written config", () => {
		const cfg = makeMinimalConfig({
			security: {
				profile: "test",
				permissions: { defaultTier: "READ_ONLY", users: {} },
				rateLimits: {
					global: { perMinute: 100, perHour: 1000 },
					perUser: { perMinute: 10, perHour: 100 },
				},
				audit: { enabled: true },
			},
		} as Partial<TelclaudeConfig>);

		const configPath = path.join(tmpDir, "telclaude.json");
		writeJsonFile(configPath, cfg);
		fs.chmodSync(configPath, 0o644); // Start with loose permissions

		runAutoFix(cfg, configPath, tmpDir, {});

		const mode = fs.statSync(configPath).mode & 0o777;
		expect(mode).toBe(0o600);
	});

	it("no .tmp file left behind after write", () => {
		const cfg = makeMinimalConfig({
			security: {
				profile: "test",
				permissions: { defaultTier: "READ_ONLY", users: {} },
				rateLimits: {
					global: { perMinute: 100, perHour: 1000 },
					perUser: { perMinute: 10, perHour: 100 },
				},
				audit: { enabled: true },
			},
		} as Partial<TelclaudeConfig>);

		const configPath = path.join(tmpDir, "telclaude.json");
		writeJsonFile(configPath, cfg);

		runAutoFix(cfg, configPath, tmpDir, {});

		expect(fs.existsSync(`${configPath}.tmp`)).toBe(false);
	});
});

// ═══════════════════════════════════════════════════════════════════════════════
// Filesystem permission fixes
// ═══════════════════════════════════════════════════════════════════════════════

describe("filesystem permission fixes", () => {
	it("tightens world-readable config files", () => {
		const dockerDir = path.join(tmpDir, "docker");
		fs.mkdirSync(dockerDir, { recursive: true });

		const configFile = path.join(dockerDir, "telclaude.json");
		fs.writeFileSync(configFile, "{}", "utf-8");
		fs.chmodSync(configFile, 0o644); // world-readable

		const cfg = makeMinimalConfig();
		const configPath = path.join(tmpDir, "main-config.json");
		writeJsonFile(configPath, cfg);

		const report = runAutoFix(cfg, configPath, tmpDir, {});

		const chmodActions = findByKind(report.actions, "chmod").filter((a) => a.target === configFile);
		expect(chmodActions.length).toBe(1);
		expect(chmodActions[0].applied).toBe(true);
		expect(chmodActions[0].before).toBe("644");
		expect(chmodActions[0].after).toBe("600");

		const mode = fs.statSync(configFile).mode & 0o777;
		expect(mode).toBe(0o600);
	});

	it("skips files with correct permissions", () => {
		const dockerDir = path.join(tmpDir, "docker");
		fs.mkdirSync(dockerDir, { recursive: true });

		const configFile = path.join(dockerDir, "telclaude.json");
		fs.writeFileSync(configFile, "{}", "utf-8");
		fs.chmodSync(configFile, 0o600); // already correct

		const cfg = makeMinimalConfig();
		const configPath = path.join(tmpDir, "main-config.json");
		writeJsonFile(configPath, cfg);

		const report = runAutoFix(cfg, configPath, tmpDir, {});

		const chmodAction = findByKind(report.actions, "chmod").find((a) => a.target === configFile);
		expect(chmodAction).toBeDefined();
		expect(chmodAction!.applied).toBe(false);
		expect(chmodAction!.skipped).toBe("already correct");
	});

	it("never loosens permissions", () => {
		const dockerDir = path.join(tmpDir, "docker");
		fs.mkdirSync(dockerDir, { recursive: true });

		const configFile = path.join(dockerDir, "telclaude.json");
		fs.writeFileSync(configFile, "{}", "utf-8");
		fs.chmodSync(configFile, 0o400); // stricter than target 600

		const cfg = makeMinimalConfig();
		const configPath = path.join(tmpDir, "main-config.json");
		writeJsonFile(configPath, cfg);

		const report = runAutoFix(cfg, configPath, tmpDir, {});

		const chmodAction = findByKind(report.actions, "chmod").find((a) => a.target === configFile);
		expect(chmodAction).toBeDefined();
		expect(chmodAction!.applied).toBe(false);
		expect(chmodAction!.skipped).toBe("current permissions are already stricter");

		// Permissions should remain unchanged
		const mode = fs.statSync(configFile).mode & 0o777;
		expect(mode).toBe(0o400);
	});

	it("skips symlinks", () => {
		const dockerDir = path.join(tmpDir, "docker");
		fs.mkdirSync(dockerDir, { recursive: true });

		const realFile = path.join(tmpDir, "real-config.json");
		fs.writeFileSync(realFile, "{}", "utf-8");

		const symlinkFile = path.join(dockerDir, "telclaude.json");
		fs.symlinkSync(realFile, symlinkFile);

		const cfg = makeMinimalConfig();
		const configPath = path.join(tmpDir, "main-config.json");
		writeJsonFile(configPath, cfg);

		const report = runAutoFix(cfg, configPath, tmpDir, {});

		const chmodAction = findByKind(report.actions, "chmod").find((a) => a.target === symlinkFile);
		expect(chmodAction).toBeDefined();
		expect(chmodAction!.applied).toBe(false);
		expect(chmodAction!.skipped).toContain("symlink");
	});

	it("skips missing files without error", () => {
		// Don't create any docker files
		const cfg = makeMinimalConfig();
		const configPath = path.join(tmpDir, "main-config.json");
		writeJsonFile(configPath, cfg);

		const report = runAutoFix(cfg, configPath, tmpDir, {});

		const missingActions = findByKind(report.actions, "chmod").filter(
			(a) => a.skipped === "file not found",
		);
		expect(missingActions.length).toBeGreaterThan(0);
		expect(report.summary.errors).toBe(0);
	});
});

// ═══════════════════════════════════════════════════════════════════════════════
// Hook hardening fixes
// ═══════════════════════════════════════════════════════════════════════════════

describe("hook hardening fixes", () => {
	it("creates settings.json when missing", () => {
		const cfg = makeMinimalConfig();
		const configPath = path.join(tmpDir, "telclaude.json");
		writeJsonFile(configPath, cfg);

		const report = runAutoFix(cfg, configPath, tmpDir, {});

		const createAction = findByKind(report.actions, "create").find((a) =>
			a.target.includes("settings.json"),
		);
		expect(createAction).toBeDefined();
		expect(createAction!.applied).toBe(true);

		const settingsFile = path.join(tmpDir, ".claude", "settings.json");
		expect(fs.existsSync(settingsFile)).toBe(true);

		const settings = JSON.parse(fs.readFileSync(settingsFile, "utf-8"));
		expect(settings.settingSources).toEqual(["project"]);

		// Should have restrictive permissions
		const mode = fs.statSync(settingsFile).mode & 0o777;
		expect(mode).toBe(0o600);
	});

	it("adds settingSources when missing from existing settings.json", () => {
		const claudeDir = path.join(tmpDir, ".claude");
		fs.mkdirSync(claudeDir, { recursive: true });
		const settingsFile = path.join(claudeDir, "settings.json");
		writeJsonFile(settingsFile, { someOther: "setting" });
		fs.chmodSync(settingsFile, 0o600);

		const cfg = makeMinimalConfig();
		const configPath = path.join(tmpDir, "telclaude.json");
		writeJsonFile(configPath, cfg);

		const report = runAutoFix(cfg, configPath, tmpDir, {});

		const action = findByTarget(report.actions, "settingSources");
		expect(action).toBeDefined();
		expect(action!.applied).toBe(true);

		const settings = JSON.parse(fs.readFileSync(settingsFile, "utf-8"));
		expect(settings.settingSources).toEqual(["project"]);
		expect(settings.someOther).toBe("setting"); // Preserved existing settings
	});

	it("removes disableAllHooks from settings.json", () => {
		const claudeDir = path.join(tmpDir, ".claude");
		fs.mkdirSync(claudeDir, { recursive: true });
		const settingsFile = path.join(claudeDir, "settings.json");
		writeJsonFile(settingsFile, {
			settingSources: ["project"],
			disableAllHooks: true,
		});
		fs.chmodSync(settingsFile, 0o600);

		const cfg = makeMinimalConfig();
		const configPath = path.join(tmpDir, "telclaude.json");
		writeJsonFile(configPath, cfg);

		const report = runAutoFix(cfg, configPath, tmpDir, {});

		const action = findByTarget(report.actions, "disableAllHooks");
		expect(action).toBeDefined();
		expect(action!.applied).toBe(true);
		expect(action!.before).toBe("true");
		expect(action!.after).toBe("(removed)");

		const settings = JSON.parse(fs.readFileSync(settingsFile, "utf-8"));
		expect(settings.disableAllHooks).toBeUndefined();
		expect(settings.settingSources).toEqual(["project"]); // Preserved
	});

	it("removes disableAllHooks from settings.local.json", () => {
		const claudeDir = path.join(tmpDir, ".claude");
		fs.mkdirSync(claudeDir, { recursive: true });

		// Main settings file exists and is fine
		const settingsFile = path.join(claudeDir, "settings.json");
		writeJsonFile(settingsFile, { settingSources: ["project"] });
		fs.chmodSync(settingsFile, 0o600);

		// Local settings has the bad flag
		const localSettingsFile = path.join(claudeDir, "settings.local.json");
		writeJsonFile(localSettingsFile, {
			disableAllHooks: true,
			otherSetting: "keep",
		});
		fs.chmodSync(localSettingsFile, 0o600);

		const cfg = makeMinimalConfig();
		const configPath = path.join(tmpDir, "telclaude.json");
		writeJsonFile(configPath, cfg);

		const report = runAutoFix(cfg, configPath, tmpDir, {});

		const action = report.actions.find(
			(a) => a.target.includes("settings.local.json") && a.target.includes("disableAllHooks"),
		);
		expect(action).toBeDefined();
		expect(action!.applied).toBe(true);

		const localSettings = JSON.parse(fs.readFileSync(localSettingsFile, "utf-8"));
		expect(localSettings.disableAllHooks).toBeUndefined();
		expect(localSettings.otherSetting).toBe("keep"); // Preserved
	});

	it("does not touch settings.json when already correct", () => {
		const claudeDir = path.join(tmpDir, ".claude");
		fs.mkdirSync(claudeDir, { recursive: true });
		const settingsFile = path.join(claudeDir, "settings.json");
		writeJsonFile(settingsFile, { settingSources: ["project"] });
		fs.chmodSync(settingsFile, 0o600);

		const cfg = makeMinimalConfig();
		const configPath = path.join(tmpDir, "telclaude.json");
		writeJsonFile(configPath, cfg);

		const report = runAutoFix(cfg, configPath, tmpDir, {});

		// No "create" or "config" actions for settings.json (only chmod which should be skipped)
		const settingsActions = report.actions.filter(
			(a) => a.target.includes("settings.json") && !a.target.includes("local"),
		);
		const appliedSettingsActions = settingsActions.filter((a) => a.applied);
		expect(appliedSettingsActions.length).toBe(0);
	});
});

// ═══════════════════════════════════════════════════════════════════════════════
// Integration: runAutoFix
// ═══════════════════════════════════════════════════════════════════════════════

describe("runAutoFix integration", () => {
	it("clean config produces no applied actions", () => {
		const claudeDir = path.join(tmpDir, ".claude");
		fs.mkdirSync(claudeDir, { recursive: true });
		const settingsFile = path.join(claudeDir, "settings.json");
		writeJsonFile(settingsFile, { settingSources: ["project"] });
		fs.chmodSync(settingsFile, 0o600);

		const cfg = makeMinimalConfig();
		const configPath = path.join(tmpDir, "telclaude.json");
		writeJsonFile(configPath, cfg);

		const report = runAutoFix(cfg, configPath, tmpDir, {});

		expect(report.summary.applied).toBe(0);
		expect(report.summary.errors).toBe(0);
		expect(report.configBackupPath).toBeNull();
	});

	it("applies multiple fixes in one run", () => {
		const dockerDir = path.join(tmpDir, "docker");
		fs.mkdirSync(dockerDir, { recursive: true });
		const dockerConfig = path.join(dockerDir, "telclaude.json");
		fs.writeFileSync(dockerConfig, "{}", "utf-8");
		fs.chmodSync(dockerConfig, 0o644); // loose permissions

		const cfg = makeMinimalConfig({
			security: {
				profile: "test",
				permissions: { defaultTier: "FULL_ACCESS", users: {} },
				rateLimits: {
					global: { perMinute: 100, perHour: 1000 },
					perUser: { perMinute: 10, perHour: 100 },
				},
				audit: { enabled: false },
			},
		} as Partial<TelclaudeConfig>);

		const configPath = path.join(tmpDir, "telclaude.json");
		writeJsonFile(configPath, cfg);

		const report = runAutoFix(cfg, configPath, tmpDir, {});

		// Should have: profile fix, tier fix, audit fix, chmod fix, settings.json create
		expect(report.summary.applied).toBeGreaterThanOrEqual(5);
		expect(report.summary.errors).toBe(0);
		expect(report.configBackupPath).toBeTruthy();
	});

	it("report summary counts are correct", () => {
		const cfg = makeMinimalConfig();
		const configPath = path.join(tmpDir, "telclaude.json");
		writeJsonFile(configPath, cfg);

		const report = runAutoFix(cfg, configPath, tmpDir, {});

		const applied = report.actions.filter((a) => a.applied).length;
		const errored = report.actions.filter((a) => a.error).length;
		const skipped = report.actions.filter((a) => !a.applied && !a.error).length;

		expect(report.summary.applied).toBe(applied);
		expect(report.summary.errors).toBe(errored);
		expect(report.summary.skipped).toBe(skipped);
	});
});

// ═══════════════════════════════════════════════════════════════════════════════
// formatFixReport
// ═══════════════════════════════════════════════════════════════════════════════

describe("formatFixReport", () => {
	it("shows CLEAN status when nothing to fix", () => {
		const report: FixReport = {
			actions: [],
			configBackupPath: null,
			summary: { applied: 0, skipped: 0, errors: 0 },
		};

		const output = formatFixReport(report);
		expect(output).toContain("CLEAN");
		expect(output).toContain("nothing to fix");
	});

	it("shows FIXED status when fixes applied", () => {
		const report: FixReport = {
			actions: [
				{
					kind: "config",
					target: "security.profile",
					description: "Change test profile to simple",
					before: "test",
					after: "simple",
					applied: true,
				},
			],
			configBackupPath: "/tmp/backup.bak",
			summary: { applied: 1, skipped: 0, errors: 0 },
		};

		const output = formatFixReport(report);
		expect(output).toContain("FIXED");
		expect(output).toContain("APPLIED:");
		expect(output).toContain("test -> simple");
		expect(output).toContain("/tmp/backup.bak");
	});

	it("shows PARTIAL status on errors", () => {
		const report: FixReport = {
			actions: [
				{
					kind: "chmod",
					target: "/some/file",
					description: "Tighten permissions",
					before: null,
					after: "600",
					applied: false,
					error: "EPERM",
				},
			],
			configBackupPath: null,
			summary: { applied: 0, skipped: 0, errors: 1 },
		};

		const output = formatFixReport(report);
		expect(output).toContain("PARTIAL");
		expect(output).toContain("ERRORS:");
		expect(output).toContain("EPERM");
	});

	it("hides 'file not found' skips", () => {
		const report: FixReport = {
			actions: [
				{
					kind: "chmod",
					target: "/missing/file",
					description: "Tighten permissions",
					before: null,
					after: "600",
					applied: false,
					skipped: "file not found",
				},
				{
					kind: "chmod",
					target: "/some/file",
					description: "Tighten permissions",
					before: "644",
					after: "600",
					applied: false,
					skipped: "already correct",
				},
			],
			configBackupPath: null,
			summary: { applied: 0, skipped: 2, errors: 0 },
		};

		const output = formatFixReport(report);
		expect(output).toContain("SKIPPED:");
		expect(output).toContain("already correct");
		expect(output).not.toContain("file not found");
	});

	it("shows summary counts", () => {
		const report: FixReport = {
			actions: [],
			configBackupPath: null,
			summary: { applied: 3, skipped: 5, errors: 1 },
		};

		const output = formatFixReport(report);
		expect(output).toContain("3 applied");
		expect(output).toContain("5 skipped");
		expect(output).toContain("1 errors");
	});
});
