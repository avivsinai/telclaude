import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	collectConfigFindings,
	collectDockerComposeFindings,
	collectExposureMatrixFindings,
	collectFilesystemFindings,
	collectHookHardeningFindings,
	collectSkillTrustFindings,
	formatAuditReport,
	runAuditCollectors,
	type AuditFinding,
	type AuditReport,
} from "../../src/commands/audit-collectors.js";
import type { TelclaudeConfig } from "../../src/config/config.js";

// ═══════════════════════════════════════════════════════════════════════════════
// Test helpers
// ═══════════════════════════════════════════════════════════════════════════════

function makeMinimalConfig(overrides: Record<string, unknown> = {}): TelclaudeConfig {
	return {
		security: {
			profile: "simple",
			permissions: {
				defaultTier: "READ_ONLY",
				users: {},
			},
			...(overrides.security as Record<string, unknown> | undefined),
		},
		telegram: { heartbeatSeconds: 60 },
		inbound: { reply: { enabled: true, timeoutSeconds: 600, typingIntervalSeconds: 8 } },
		logging: {},
		sdk: { betas: [] },
		openai: {},
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
		summarize: {
			maxPerHourPerUser: 30,
			maxPerDayPerUser: 100,
			maxCharacters: 8000,
			timeoutMs: 30000,
		},
		providers: [],
		socialServices: [],
		...overrides,
	} as TelclaudeConfig;
}

function findBySeverity(findings: AuditFinding[], severity: string): AuditFinding[] {
	return findings.filter((f) => f.severity === severity);
}

function findByCategory(findings: AuditFinding[], category: string): AuditFinding[] {
	return findings.filter((f) => f.category === category);
}

function findByMessage(findings: AuditFinding[], substring: string): AuditFinding | undefined {
	return findings.find((f) => f.message.includes(substring));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Config collector tests
// ═══════════════════════════════════════════════════════════════════════════════

describe("collectConfigFindings", () => {
	it("flags test profile as critical", () => {
		const cfg = makeMinimalConfig({ security: { profile: "test" } });
		const findings = collectConfigFindings(cfg, {});
		const finding = findByMessage(findings, "test");
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe("critical");
		expect(finding!.category).toBe("config");
	});

	it("flags test profile as warning when env guard is set", () => {
		const cfg = makeMinimalConfig({ security: { profile: "test" } });
		const findings = collectConfigFindings(cfg, { TELCLAUDE_ENABLE_TEST_PROFILE: "1" });
		const finding = findByMessage(findings, "test");
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe("warning");
	});

	it("flags open network mode as critical", () => {
		const cfg = makeMinimalConfig();
		const findings = collectConfigFindings(cfg, { TELCLAUDE_NETWORK_MODE: "open" });
		const finding = findByMessage(findings, "TELCLAUDE_NETWORK_MODE=open");
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe("critical");
	});

	it("flags permissive network mode as warning", () => {
		const cfg = makeMinimalConfig();
		const findings = collectConfigFindings(cfg, { TELCLAUDE_NETWORK_MODE: "permissive" });
		const finding = findByMessage(findings, "permissive");
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe("warning");
	});

	it("flags FULL_ACCESS default tier as critical", () => {
		const cfg = makeMinimalConfig({
			security: { profile: "simple", permissions: { defaultTier: "FULL_ACCESS", users: {} } },
		});
		const findings = collectConfigFindings(cfg, {});
		const finding = findByMessage(findings, "FULL_ACCESS");
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe("critical");
	});

	it("flags WRITE_LOCAL default tier as warning", () => {
		const cfg = makeMinimalConfig({
			security: { profile: "simple", permissions: { defaultTier: "WRITE_LOCAL", users: {} } },
		});
		const findings = collectConfigFindings(cfg, {});
		const finding = findByMessage(findings, "WRITE_LOCAL");
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe("warning");
	});

	it("does not flag READ_ONLY default tier", () => {
		const cfg = makeMinimalConfig();
		const findings = collectConfigFindings(cfg, {});
		const finding = findByMessage(findings, "Default permission tier");
		expect(finding).toBeUndefined();
	});

	it("flags disabled audit logging as warning", () => {
		const cfg = makeMinimalConfig({
			security: { profile: "simple", audit: { enabled: false } },
		});
		const findings = collectConfigFindings(cfg, {});
		const finding = findByMessage(findings, "Audit logging is disabled");
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe("warning");
	});

	it("flags video processing enabled as warning", () => {
		const cfg = makeMinimalConfig({
			videoProcessing: {
				enabled: true,
				frameInterval: 1,
				maxFrames: 30,
				maxDurationSeconds: 300,
				extractAudio: true,
			},
		});
		const findings = collectConfigFindings(cfg, {});
		const finding = findByMessage(findings, "Video processing");
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe("warning");
	});

	it("flags very long TOTP TTL as warning", () => {
		const cfg = makeMinimalConfig({
			security: { profile: "simple", totp: { sessionTtlMinutes: 720 } },
		});
		const findings = collectConfigFindings(cfg, {});
		const finding = findByMessage(findings, "TOTP session TTL");
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe("warning");
	});

	it("clean config produces no critical findings", () => {
		const cfg = makeMinimalConfig();
		const findings = collectConfigFindings(cfg, {});
		const critical = findBySeverity(findings, "critical");
		expect(critical).toHaveLength(0);
	});
});

// ═══════════════════════════════════════════════════════════════════════════════
// Filesystem collector tests
// ═══════════════════════════════════════════════════════════════════════════════

describe("collectFilesystemFindings", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "audit-fs-test-"));
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
	});

	it("flags world-readable config file as critical", () => {
		const dockerDir = path.join(tempDir, "docker");
		fs.mkdirSync(dockerDir, { recursive: true });
		const configFile = path.join(dockerDir, "telclaude.json");
		fs.writeFileSync(configFile, "{}", "utf-8");
		fs.chmodSync(configFile, 0o644);

		const findings = collectFilesystemFindings(tempDir);
		const finding = findByMessage(findings, "telclaude.json");
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe("critical");
	});

	it("flags group-writable config file as critical", () => {
		const dockerDir = path.join(tempDir, "docker");
		fs.mkdirSync(dockerDir, { recursive: true });
		const configFile = path.join(dockerDir, "telclaude-private.json");
		fs.writeFileSync(configFile, "{}", "utf-8");
		fs.chmodSync(configFile, 0o660);

		const findings = collectFilesystemFindings(tempDir);
		const finding = findByMessage(findings, "telclaude-private.json");
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe("critical");
	});

	it("no findings for properly secured config files", () => {
		const dockerDir = path.join(tempDir, "docker");
		fs.mkdirSync(dockerDir, { recursive: true });
		const configFile = path.join(dockerDir, "telclaude.json");
		fs.writeFileSync(configFile, "{}", "utf-8");
		fs.chmodSync(configFile, 0o600);

		const findings = collectFilesystemFindings(tempDir);
		const configFindings = findByCategory(findings, "fs").filter((f) =>
			f.message.includes("telclaude.json"),
		);
		expect(configFindings).toHaveLength(0);
	});

	it("flags .env in project root", () => {
		fs.writeFileSync(path.join(tempDir, ".env"), "SECRET=foo", "utf-8");
		const findings = collectFilesystemFindings(tempDir);
		const finding = findByMessage(findings, ".env file exists in project root");
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe("warning");
	});
});

// ═══════════════════════════════════════════════════════════════════════════════
// Skill trust collector tests
// ═══════════════════════════════════════════════════════════════════════════════

describe("collectSkillTrustFindings", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "audit-skills-test-"));
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
	});

	it("reports info when all skills are clean", () => {
		const skillDir = path.join(tempDir, ".claude", "skills", "test-skill");
		fs.mkdirSync(skillDir, { recursive: true });
		fs.writeFileSync(
			path.join(skillDir, "SKILL.md"),
			"# Test Skill\nA clean skill that does nothing dangerous.",
			"utf-8",
		);

		const findings = collectSkillTrustFindings(tempDir);
		// Should have an info finding about skills being clean (no critical or warning)
		const skillFindings = findByCategory(findings, "skills");
		expect(skillFindings.length).toBeGreaterThan(0);
		const criticalSkill = skillFindings.filter((f) => f.severity === "critical");
		expect(criticalSkill).toHaveLength(0);
	});

	it("flags skills-draft directory with contents", () => {
		const draftDir = path.join(tempDir, ".claude", "skills-draft", "unvetted-skill");
		fs.mkdirSync(draftDir, { recursive: true });
		fs.writeFileSync(path.join(draftDir, "SKILL.md"), "# Unvetted", "utf-8");

		const findings = collectSkillTrustFindings(tempDir);
		const finding = findByMessage(findings, "skills-draft");
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe("warning");
	});

	it("returns empty for non-existent skills directory", () => {
		const findings = collectSkillTrustFindings(tempDir);
		// No skills dir means no findings
		expect(findings).toHaveLength(0);
	});
});

// ═══════════════════════════════════════════════════════════════════════════════
// Hook hardening collector tests
// ═══════════════════════════════════════════════════════════════════════════════

describe("collectHookHardeningFindings", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "audit-hooks-test-"));
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
	});

	it("flags missing settings.json", () => {
		const claudeDir = path.join(tempDir, ".claude");
		fs.mkdirSync(claudeDir, { recursive: true });
		// No settings.json created

		const findings = collectHookHardeningFindings(tempDir);
		const finding = findByMessage(findings, "settings.json not found");
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe("warning");
	});

	it("flags missing settingSources", () => {
		const claudeDir = path.join(tempDir, ".claude");
		fs.mkdirSync(claudeDir, { recursive: true });
		fs.writeFileSync(path.join(claudeDir, "settings.json"), "{}", "utf-8");

		const findings = collectHookHardeningFindings(tempDir);
		const finding = findByMessage(findings, "settingSources not configured");
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe("critical");
	});

	it("flags disableAllHooks=true as critical", () => {
		const claudeDir = path.join(tempDir, ".claude");
		fs.mkdirSync(claudeDir, { recursive: true });
		fs.writeFileSync(
			path.join(claudeDir, "settings.json"),
			JSON.stringify({ settingSources: ["project"], disableAllHooks: true }),
			"utf-8",
		);

		const findings = collectHookHardeningFindings(tempDir);
		const finding = findByMessage(findings, "disableAllHooks is TRUE");
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe("critical");
	});

	it("flags user in settingSources as warning", () => {
		const claudeDir = path.join(tempDir, ".claude");
		fs.mkdirSync(claudeDir, { recursive: true });
		fs.writeFileSync(
			path.join(claudeDir, "settings.json"),
			JSON.stringify({ settingSources: ["project", "user"] }),
			"utf-8",
		);

		const findings = collectHookHardeningFindings(tempDir);
		const finding = findByMessage(findings, '"user"');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe("warning");
	});

	it("passes with correct settingSources", () => {
		const claudeDir = path.join(tempDir, ".claude");
		fs.mkdirSync(claudeDir, { recursive: true });
		const settingsPath = path.join(claudeDir, "settings.json");
		fs.writeFileSync(settingsPath, JSON.stringify({ settingSources: ["project"] }), "utf-8");
		fs.chmodSync(settingsPath, 0o600);

		const findings = collectHookHardeningFindings(tempDir);
		const critical = findBySeverity(findings, "critical");
		expect(critical).toHaveLength(0);
	});

	it("flags disableAllHooks in settings.local.json", () => {
		const claudeDir = path.join(tempDir, ".claude");
		fs.mkdirSync(claudeDir, { recursive: true });
		fs.writeFileSync(
			path.join(claudeDir, "settings.json"),
			JSON.stringify({ settingSources: ["project"] }),
			"utf-8",
		);
		fs.writeFileSync(
			path.join(claudeDir, "settings.local.json"),
			JSON.stringify({ disableAllHooks: true }),
			"utf-8",
		);

		const findings = collectHookHardeningFindings(tempDir);
		const finding = findByMessage(findings, "settings.local.json");
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe("critical");
	});
});

// ═══════════════════════════════════════════════════════════════════════════════
// Exposure matrix collector tests
// ═══════════════════════════════════════════════════════════════════════════════

describe("collectExposureMatrixFindings", () => {
	it("includes tier-to-tool matrix as info", () => {
		const cfg = makeMinimalConfig();
		const findings = collectExposureMatrixFindings(cfg);
		const matrixFinding = findByMessage(findings, "Tier-to-tool exposure matrix");
		expect(matrixFinding).toBeDefined();
		expect(matrixFinding!.severity).toBe("info");
		expect(matrixFinding!.category).toBe("exposure");
	});

	it("reports FULL_ACCESS users", () => {
		const cfg = makeMinimalConfig({
			security: {
				profile: "simple",
				permissions: {
					defaultTier: "READ_ONLY",
					users: {
						admin123: { tier: "FULL_ACCESS" },
					},
				},
			},
		});
		const findings = collectExposureMatrixFindings(cfg);
		const finding = findByMessage(findings, "user(s) with FULL_ACCESS");
		expect(finding).toBeDefined();
		expect(finding!.message).toContain("admin123");
	});

	it("warns when no user permissions configured", () => {
		const cfg = makeMinimalConfig({
			security: { profile: "simple" },
		});
		const findings = collectExposureMatrixFindings(cfg);
		const finding = findByMessage(findings, "No user permissions configured");
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe("warning");
	});

	it("warns about social services with enableSkills", () => {
		const cfg = makeMinimalConfig({
			socialServices: [
				{
					id: "moltbook",
					type: "moltbook",
					enabled: true,
					enableSkills: true,
					heartbeatIntervalHours: 4,
					notifyOnHeartbeat: "activity",
				},
			],
		});
		const findings = collectExposureMatrixFindings(cfg);
		const finding = findByMessage(findings, "enableSkills=true");
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe("warning");
	});
});

// ═══════════════════════════════════════════════════════════════════════════════
// Docker compose collector tests
// ═══════════════════════════════════════════════════════════════════════════════

describe("collectDockerComposeFindings", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "audit-docker-test-"));
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
	});

	it("flags docker socket mount as critical", () => {
		const dockerDir = path.join(tempDir, "docker");
		fs.mkdirSync(dockerDir, { recursive: true });
		fs.writeFileSync(
			path.join(dockerDir, "docker-compose.yml"),
			"volumes:\n  - /var/run/docker.sock:/var/run/docker.sock\n",
			"utf-8",
		);

		const findings = collectDockerComposeFindings(tempDir);
		const finding = findByMessage(findings, "Docker socket mount");
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe("critical");
	});

	it("flags host network mode as critical", () => {
		const dockerDir = path.join(tempDir, "docker");
		fs.mkdirSync(dockerDir, { recursive: true });
		fs.writeFileSync(
			path.join(dockerDir, "docker-compose.yml"),
			"services:\n  app:\n    network_mode: host\n",
			"utf-8",
		);

		const findings = collectDockerComposeFindings(tempDir);
		const finding = findByMessage(findings, "Host network mode");
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe("critical");
	});

	it("flags privileged mode as critical", () => {
		const dockerDir = path.join(tempDir, "docker");
		fs.mkdirSync(dockerDir, { recursive: true });
		fs.writeFileSync(
			path.join(dockerDir, "docker-compose.yml"),
			"services:\n  app:\n    privileged: true\n",
			"utf-8",
		);

		const findings = collectDockerComposeFindings(tempDir);
		const finding = findByMessage(findings, "Privileged mode");
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe("critical");
	});

	it("returns no findings for clean compose file", () => {
		const dockerDir = path.join(tempDir, "docker");
		fs.mkdirSync(dockerDir, { recursive: true });
		fs.writeFileSync(
			path.join(dockerDir, "docker-compose.yml"),
			"services:\n  app:\n    image: telclaude:latest\n",
			"utf-8",
		);

		const findings = collectDockerComposeFindings(tempDir);
		expect(findings).toHaveLength(0);
	});

	it("returns no findings when compose file does not exist", () => {
		const findings = collectDockerComposeFindings(tempDir);
		expect(findings).toHaveLength(0);
	});
});

// ═══════════════════════════════════════════════════════════════════════════════
// Integration: runAuditCollectors
// ═══════════════════════════════════════════════════════════════════════════════

describe("runAuditCollectors", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "audit-integration-test-"));
		// Create minimal directory structure with proper permissions
		fs.mkdirSync(path.join(tempDir, ".claude"), { recursive: true });
		const settingsPath = path.join(tempDir, ".claude", "settings.json");
		fs.writeFileSync(settingsPath, JSON.stringify({ settingSources: ["project"] }), "utf-8");
		fs.chmodSync(settingsPath, 0o600);
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
	});

	it("returns structured report with summary", () => {
		const cfg = makeMinimalConfig();
		const report = runAuditCollectors(cfg, tempDir, {});
		expect(report).toHaveProperty("findings");
		expect(report).toHaveProperty("summary");
		expect(report.summary).toHaveProperty("critical");
		expect(report.summary).toHaveProperty("warning");
		expect(report.summary).toHaveProperty("info");
	});

	it("clean config produces no critical findings", () => {
		const cfg = makeMinimalConfig();
		const report = runAuditCollectors(cfg, tempDir, {});
		expect(report.summary.critical).toBe(0);
	});

	it("vulnerable config produces critical findings", () => {
		const cfg = makeMinimalConfig({
			security: {
				profile: "test",
				permissions: { defaultTier: "FULL_ACCESS", users: {} },
			},
		});

		// Also add a docker-compose with dangerous mount
		const dockerDir = path.join(tempDir, "docker");
		fs.mkdirSync(dockerDir, { recursive: true });
		fs.writeFileSync(
			path.join(dockerDir, "docker-compose.yml"),
			"volumes:\n  - /var/run/docker.sock:/var/run/docker.sock\n",
			"utf-8",
		);

		// Also set disableAllHooks
		fs.writeFileSync(
			path.join(tempDir, ".claude", "settings.json"),
			JSON.stringify({ disableAllHooks: true }),
			"utf-8",
		);

		const report = runAuditCollectors(cfg, tempDir, {});
		expect(report.summary.critical).toBeGreaterThan(0);
	});
});

// ═══════════════════════════════════════════════════════════════════════════════
// formatAuditReport tests
// ═══════════════════════════════════════════════════════════════════════════════

describe("formatAuditReport", () => {
	it("formats critical findings first", () => {
		const report: AuditReport = {
			findings: [
				{ severity: "info", category: "config", message: "Info message" },
				{ severity: "critical", category: "config", message: "Critical issue", fix: "Fix it" },
				{ severity: "warning", category: "fs", message: "Warning message" },
			],
			summary: { critical: 1, warning: 1, info: 1 },
		};

		const output = formatAuditReport(report);
		const criticalIdx = output.indexOf("CRITICAL");
		const warningIdx = output.indexOf("WARNING");
		const infoIdx = output.indexOf("INFO");

		expect(criticalIdx).toBeLessThan(warningIdx);
		expect(warningIdx).toBeLessThan(infoIdx);
	});

	it("shows FAIL status for critical findings", () => {
		const report: AuditReport = {
			findings: [{ severity: "critical", category: "config", message: "Bad" }],
			summary: { critical: 1, warning: 0, info: 0 },
		};

		const output = formatAuditReport(report);
		expect(output).toContain("FAIL");
	});

	it("shows PASS status when no issues", () => {
		const report: AuditReport = {
			findings: [],
			summary: { critical: 0, warning: 0, info: 0 },
		};

		const output = formatAuditReport(report);
		expect(output).toContain("PASS");
	});

	it("shows WARN status for warnings only", () => {
		const report: AuditReport = {
			findings: [{ severity: "warning", category: "fs", message: "Not great" }],
			summary: { critical: 0, warning: 1, info: 0 },
		};

		const output = formatAuditReport(report);
		expect(output).toContain("WARN");
	});

	it("includes fix instructions when present", () => {
		const report: AuditReport = {
			findings: [{ severity: "warning", category: "config", message: "Issue", fix: "chmod 600" }],
			summary: { critical: 0, warning: 1, info: 0 },
		};

		const output = formatAuditReport(report);
		expect(output).toContain("Fix: chmod 600");
	});
});
