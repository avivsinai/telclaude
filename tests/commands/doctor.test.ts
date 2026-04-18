import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	buildReport,
	checkConfigLoaded,
	checkNetworkConfig,
	findInstalledSkills,
	summarize,
	worstStatus,
} from "../../src/commands/doctor-helpers.js";
import type { TelclaudeConfig } from "../../src/config/config.js";

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

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
		telegram: {
			heartbeatSeconds: 60,
			...(overrides.telegram as Record<string, unknown> | undefined),
		},
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
			enabled: true,
			fetchTimeoutSeconds: 15,
			maxPages: 5,
			maxContentBytes: 500_000,
			userAgent: "test",
			allowlistDomains: [],
			blocklistDomains: [],
		},
		providers: [],
		socialServices: [],
		cron: {
			enabled: false,
			pollIntervalSeconds: 15,
			timeoutSeconds: 900,
		},
		...overrides,
	} as unknown as TelclaudeConfig;
}

// ─────────────────────────────────────────────────────────────────────────────
// summarize / worstStatus / buildReport
// ─────────────────────────────────────────────────────────────────────────────

describe("summarize", () => {
	it("counts checks by status", () => {
		const checks = [
			{ name: "a", category: "X", status: "pass" as const, summary: "" },
			{ name: "b", category: "X", status: "pass" as const, summary: "" },
			{ name: "c", category: "X", status: "warn" as const, summary: "" },
			{ name: "d", category: "X", status: "fail" as const, summary: "" },
		];
		expect(summarize(checks)).toEqual({ pass: 2, warn: 1, fail: 1, skip: 0 });
	});
});

describe("worstStatus", () => {
	it("returns fail when any check failed", () => {
		expect(
			worstStatus([
				{ name: "a", category: "X", status: "pass", summary: "" },
				{ name: "b", category: "X", status: "fail", summary: "" },
				{ name: "c", category: "X", status: "warn", summary: "" },
			]),
		).toBe("fail");
	});
	it("returns warn when no fail but a warn is present", () => {
		expect(
			worstStatus([
				{ name: "a", category: "X", status: "pass", summary: "" },
				{ name: "b", category: "X", status: "warn", summary: "" },
			]),
		).toBe("warn");
	});
	it("returns pass when all checks pass", () => {
		expect(
			worstStatus([
				{ name: "a", category: "X", status: "pass", summary: "" },
				{ name: "b", category: "X", status: "skip", summary: "" },
			]),
		).toBe("pass");
	});
	it("returns skip when everything was skipped", () => {
		expect(
			worstStatus([
				{ name: "a", category: "X", status: "skip", summary: "" },
				{ name: "b", category: "X", status: "skip", summary: "" },
			]),
		).toBe("skip");
	});
});

describe("buildReport", () => {
	it("returns checks and summary together", () => {
		const report = buildReport([
			{ name: "a", category: "X", status: "pass", summary: "ok" },
			{ name: "b", category: "X", status: "warn", summary: "meh" },
		]);
		expect(report.checks).toHaveLength(2);
		expect(report.summary).toEqual({ pass: 1, warn: 1, fail: 0, skip: 0 });
	});
});

// ─────────────────────────────────────────────────────────────────────────────
// checkConfigLoaded
// ─────────────────────────────────────────────────────────────────────────────

describe("checkConfigLoaded", () => {
	it("fails when botToken is missing", () => {
		const cfg = makeMinimalConfig();
		const results = checkConfigLoaded(cfg);
		const tokenCheck = results.find((r) => r.name === "config.telegram.botToken");
		expect(tokenCheck?.status).toBe("fail");
		expect(tokenCheck?.remediation).toMatch(/telclaude onboard/);
	});

	it("fails on malformed botToken", () => {
		const cfg = makeMinimalConfig({ telegram: { botToken: "no-colon-here", heartbeatSeconds: 60 } });
		const results = checkConfigLoaded(cfg);
		const tokenCheck = results.find((r) => r.name === "config.telegram.botToken");
		expect(tokenCheck?.status).toBe("fail");
		expect(tokenCheck?.summary).toMatch(/invalid/);
	});

	it("passes when both botToken and allowedChats are present", () => {
		const cfg = makeMinimalConfig({
			telegram: {
				botToken: "12345:ABCDE",
				allowedChats: [42],
				heartbeatSeconds: 60,
			},
		});
		const results = checkConfigLoaded(cfg);
		expect(results.find((r) => r.name === "config.telegram.botToken")?.status).toBe("pass");
		expect(results.find((r) => r.name === "config.telegram.allowedChats")?.status).toBe("pass");
	});

	it("warns when allowedChats is empty", () => {
		const cfg = makeMinimalConfig({
			telegram: { botToken: "1:ABC", heartbeatSeconds: 60 },
		});
		const results = checkConfigLoaded(cfg);
		const allowed = results.find((r) => r.name === "config.telegram.allowedChats");
		expect(allowed?.status).toBe("warn");
		expect(allowed?.remediation).toMatch(/telclaude onboard/);
	});
});

// ─────────────────────────────────────────────────────────────────────────────
// checkNetworkConfig
// ─────────────────────────────────────────────────────────────────────────────

describe("checkNetworkConfig", () => {
	afterEach(() => {
		delete process.env.TELCLAUDE_NETWORK_MODE;
	});

	it("warns on TELCLAUDE_NETWORK_MODE=open", () => {
		process.env.TELCLAUDE_NETWORK_MODE = "open";
		const cfg = makeMinimalConfig();
		const results = checkNetworkConfig(cfg);
		const mode = results.find((r) => r.name === "network.mode");
		expect(mode?.status).toBe("warn");
	});

	it("fails when providers are configured but privateEndpoints is empty", () => {
		const cfg = makeMinimalConfig({
			providers: [{ id: "google", baseUrl: "http://google-services:3001", services: ["gmail"] }],
		});
		const results = checkNetworkConfig(cfg);
		const endpoints = results.find((r) => r.name === "network.privateEndpoints");
		expect(endpoints?.status).toBe("fail");
		expect(endpoints?.remediation).toMatch(/providers setup/);
	});

	it("passes on a clean restricted config", () => {
		const cfg = makeMinimalConfig();
		const results = checkNetworkConfig(cfg);
		expect(results.find((r) => r.name === "network.mode")?.status).toBe("pass");
		expect(results.find((r) => r.name === "network.privateEndpoints")?.status).toBe("pass");
	});
});

// ─────────────────────────────────────────────────────────────────────────────
// findInstalledSkills — replaces the old relay.ts ad-hoc scan and
// is the direct fix for bug #5 (doctor was only scanning cwd).
// ─────────────────────────────────────────────────────────────────────────────

describe("findInstalledSkills", () => {
	let tempRoot = "";
	let projectRoot = "";
	let claudeHome = "";
	let originalClaudeConfigDir: string | undefined;

	beforeEach(() => {
		tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "doctor-skills-"));
		projectRoot = path.join(tempRoot, "project");
		claudeHome = path.join(tempRoot, "claude-home");
		fs.mkdirSync(projectRoot, { recursive: true });
		fs.mkdirSync(claudeHome, { recursive: true });
		originalClaudeConfigDir = process.env.CLAUDE_CONFIG_DIR;
	});

	afterEach(() => {
		if (originalClaudeConfigDir === undefined) {
			delete process.env.CLAUDE_CONFIG_DIR;
		} else {
			process.env.CLAUDE_CONFIG_DIR = originalClaudeConfigDir;
		}
		if (tempRoot && fs.existsSync(tempRoot)) {
			fs.rmSync(tempRoot, { recursive: true, force: true });
		}
	});

	it("finds skills across project-local and CLAUDE_CONFIG_DIR", () => {
		process.env.CLAUDE_CONFIG_DIR = claudeHome;
		fs.mkdirSync(path.join(projectRoot, ".claude", "skills", "alpha"), { recursive: true });
		fs.mkdirSync(path.join(claudeHome, "skills", "beta"), { recursive: true });

		const result = findInstalledSkills(projectRoot).map((s) => s.name);
		expect(result).toContain("alpha");
		expect(result).toContain("beta");
	});

	it("treats symlinked skill directories as real skills", () => {
		const source = path.join(tempRoot, "external-skill");
		fs.mkdirSync(source, { recursive: true });
		fs.writeFileSync(path.join(source, "SKILL.md"), "x", "utf8");

		const skillsDir = path.join(projectRoot, ".claude", "skills");
		fs.mkdirSync(skillsDir, { recursive: true });
		fs.symlinkSync(source, path.join(skillsDir, "linked"), "dir");

		const result = findInstalledSkills(projectRoot).map((s) => s.name);
		expect(result).toContain("linked");
	});

	it("skips hidden entries and plain files", () => {
		const skillsDir = path.join(projectRoot, ".claude", "skills");
		fs.mkdirSync(skillsDir, { recursive: true });
		fs.mkdirSync(path.join(skillsDir, ".hidden"));
		fs.writeFileSync(path.join(skillsDir, "plain-file.md"), "x", "utf8");
		fs.mkdirSync(path.join(skillsDir, "real-skill"));

		const result = findInstalledSkills(projectRoot).map((s) => s.name);
		expect(result).toEqual(expect.arrayContaining(["real-skill"]));
		expect(result).not.toContain(".hidden");
		expect(result).not.toContain("plain-file.md");
	});

	it("deduplicates by name across roots", () => {
		process.env.CLAUDE_CONFIG_DIR = claudeHome;
		fs.mkdirSync(path.join(projectRoot, ".claude", "skills", "weather"), { recursive: true });
		fs.mkdirSync(path.join(claudeHome, "skills", "weather"), { recursive: true });

		const result = findInstalledSkills(projectRoot).filter((s) => s.name === "weather");
		expect(result).toHaveLength(1);
	});
});
