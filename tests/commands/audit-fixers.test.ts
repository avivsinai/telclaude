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
		sdk: { betas: [] },
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
				rateLimits: { global: { perMinute: 100, perHour: 1000 }, perUser: { perMinute: 10, perHour: 100 } },
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
				rateLimits: { global: { perMinute: 100, perHour: 1000 }, perUser: { perMinute: 10, perHour: 100 } },
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
				rateLimits: { global: { perMinute: 100, perHour: 1000 }, perUser: { perMinute: 10, perHour: 100 } },
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
				rateLimits: { global: { perMinute: 100, perHour: 1000 }, perUser: { perMinute: 10, perHour: 100 } },
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
// Atomic write + backup
// ═══════════════════════════════════════════════════════════════════════════════

describe("atomic write + backup", () => {
	it("creates .bak with original content", () => {
		const cfg = makeMinimalConfig({
			security: {
				profile: "test",
				permissions: { defaultTier: "READ_ONLY", users: {} },
				rateLimits: { global: { perMinute: 100, perHour: 1000 }, perUser: { perMinute: 10, perHour: 100 } },
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
				rateLimits: { global: { perMinute: 100, perHour: 1000 }, perUser: { perMinute: 10, perHour: 100 } },
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
				rateLimits: { global: { perMinute: 100, perHour: 1000 }, perUser: { perMinute: 10, perHour: 100 } },
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

		const chmodActions = findByKind(report.actions, "chmod").filter(
			(a) => a.target === configFile,
		);
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

		const chmodAction = findByKind(report.actions, "chmod").find(
			(a) => a.target === configFile,
		);
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

		const chmodAction = findByKind(report.actions, "chmod").find(
			(a) => a.target === configFile,
		);
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

		const chmodAction = findByKind(report.actions, "chmod").find(
			(a) => a.target === symlinkFile,
		);
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

		const createAction = findByKind(report.actions, "create").find(
			(a) => a.target.includes("settings.json"),
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
				rateLimits: { global: { perMinute: 100, perHour: 1000 }, perUser: { perMinute: 10, perHour: 100 } },
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
