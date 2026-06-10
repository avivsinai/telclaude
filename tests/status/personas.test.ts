import { describe, expect, it } from "vitest";
import type { TelclaudeConfig } from "../../src/config/config.js";
import type { CronJob } from "../../src/cron/types.js";
import {
	buildPersonaStatusSnapshot,
	formatPersonaStatusSnapshot,
	type PersonaPluginStatus,
	type PersonaRuntimeStatus,
} from "../../src/status/personas.js";

const EMPTY_PLUGINS: PersonaPluginStatus = {
	configured: true,
	enabled: [],
	installed: [],
	error: null,
};

const CONFIGURED_RUNTIME: PersonaRuntimeStatus = {
	configured: true,
	source: "test",
	endpoint: "http://hermes:8642",
	reachability: "configured",
	checkedAt: "2026-04-23T00:00:00.000Z",
	error: null,
};

function makeConfig(overrides: Partial<TelclaudeConfig> = {}): TelclaudeConfig {
	return {
		security: {
			profile: "simple",
			permissions: { defaultTier: "READ_ONLY", users: {} },
			network: { additionalDomains: [], privateEndpoints: [] },
		},
		telegram: { heartbeatSeconds: 60 },
		inbound: { reply: { enabled: true, timeoutSeconds: 600, typingIntervalSeconds: 8 } },
		logging: {},
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
			speed: 1,
			autoReadResponses: false,
			maxPerHourPerUser: 30,
			maxPerDayPerUser: 100,
		},
		summarize: {
			maxPerHourPerUser: 30,
			maxPerDayPerUser: 100,
			maxCharacters: 8000,
			timeoutMs: 30_000,
		},
		providers: [],
		socialServices: [],
		cron: { enabled: true, pollIntervalSeconds: 15, timeoutSeconds: 900 },
		dashboard: { enabled: false, port: 3005 },
		...overrides,
	} as TelclaudeConfig;
}

function cronJob(input: {
	action: CronJob["action"];
	lastRunAtMs: number;
	lastStatus?: CronJob["lastStatus"];
	lastError?: string | null;
}): CronJob {
	return {
		id: "job",
		name: "job",
		enabled: true,
		running: false,
		ownerId: null,
		deliveryTarget: { kind: "origin" },
		schedule: { kind: "every", everyMs: 60_000 },
		action: input.action,
		nextRunAtMs: null,
		lastRunAtMs: input.lastRunAtMs,
		lastStatus: input.lastStatus ?? "success",
		lastError: input.lastError ?? null,
		createdAtMs: input.lastRunAtMs,
		updatedAtMs: input.lastRunAtMs,
	};
}

describe("persona status", () => {
	it("does not require a legacy social Claude profile", () => {
		const snapshot = buildPersonaStatusSnapshot({
			config: makeConfig({
				socialServices: [
					{
						id: "xtwitter",
						type: "xtwitter",
						enabled: true,
						heartbeatEnabled: true,
						heartbeatIntervalHours: 4,
						enableSkills: true,
						notifyOnHeartbeat: "activity",
					},
				],
			}),
			env: {
				TELCLAUDE_PRIVATE_CLAUDE_HOME: "/profiles/private",
				TELCLAUDE_HERMES_API_BASE_URL: "http://hermes:8642",
				TELCLAUDE_HERMES_API_KEY: "test-key",
				TELCLAUDE_HERMES_SOCIAL_API_BASE_URL: "http://social-hermes:8642",
				TELCLAUDE_HERMES_SOCIAL_API_KEY: "test-social-key",
			},
			nowMs: 0,
			activeSkillNames: ["memory"],
			privatePlugins: EMPTY_PLUGINS,
			runtimeReachability: { private: CONFIGURED_RUNTIME, social: CONFIGURED_RUNTIME },
		});

		expect(snapshot.overallHealth).toBe("degraded");
		expect(snapshot.personas.social.health).toBe("degraded");
		expect(snapshot.personas.social.profile).toEqual({
			configured: true,
			claudeHome: null,
			source: "Hermes social profile",
		});
		expect(snapshot.personas.social.skills.policy).toBe("fail_closed");
		expect(snapshot.personas.social.skills.effective).toEqual([]);
	});

	it("reports Hermes-only social healthy without a legacy social Claude home", () => {
		const snapshot = buildPersonaStatusSnapshot({
			config: makeConfig({
				socialServices: [
					{
						id: "xtwitter",
						type: "xtwitter",
						enabled: true,
						heartbeatEnabled: true,
						heartbeatIntervalHours: 4,
						enableSkills: true,
						allowedSkills: ["social-posting"],
						notifyOnHeartbeat: "activity",
					},
				],
			}),
			env: {
				TELCLAUDE_PRIVATE_CLAUDE_HOME: "/profiles/private",
				TELCLAUDE_HERMES_API_BASE_URL: "http://hermes:8642",
				TELCLAUDE_HERMES_API_KEY: "test-key",
				TELCLAUDE_HERMES_SOCIAL_API_BASE_URL: "http://social-hermes:8642",
				TELCLAUDE_HERMES_SOCIAL_API_KEY: "test-social-key",
			},
			nowMs: 0,
			activeSkillNames: ["social-posting"],
			privatePlugins: EMPTY_PLUGINS,
			runtimeReachability: { private: CONFIGURED_RUNTIME, social: CONFIGURED_RUNTIME },
		});

		expect(snapshot.personas.social.health).toBe("ok");
		expect(snapshot.personas.social.summary).toBe("social persona metadata healthy");
		expect(snapshot.personas.social.plugins).toEqual({
			configured: true,
			enabled: [],
			installed: [],
			error: null,
		});
	});

	it("keeps private and social memory, filesystem, and skill boundaries separate", () => {
		const snapshot = buildPersonaStatusSnapshot({
			config: makeConfig({
				providers: [
					{
						id: "google",
						baseUrl: "http://private-provider.internal:3001",
						services: ["gmail", "calendar"],
					},
				],
				socialServices: [
					{
						id: "xtwitter",
						type: "xtwitter",
						enabled: true,
						apiKey: "social-secret-api-key",
						heartbeatEnabled: true,
						heartbeatIntervalHours: 4,
						enableSkills: true,
						allowedSkills: ["social-posting"],
						notifyOnHeartbeat: "activity",
					},
				],
			}),
			env: {
				TELCLAUDE_PRIVATE_CLAUDE_HOME: "/profiles/private",
				TELCLAUDE_HERMES_HOME: "/profiles/hermes",
				TELCLAUDE_HERMES_API_BASE_URL: "http://hermes:8642",
				TELCLAUDE_HERMES_API_KEY: "test-key",
				TELCLAUDE_HERMES_SOCIAL_API_BASE_URL: "http://social-hermes:8642",
				TELCLAUDE_HERMES_SOCIAL_API_KEY: "test-social-key",
				TELCLAUDE_SKILL_CATALOG_DIR: "/catalog",
			},
			activeSkillNames: ["external-provider", "memory", "social-posting"],
			privatePlugins: {
				configured: true,
				enabled: ["github@official"],
				installed: ["github@official"],
				error: null,
			},
			socialPlugins: {
				configured: true,
				enabled: ["browser-use@official"],
				installed: ["browser-use@official"],
				error: null,
			},
			runtimeReachability: { private: CONFIGURED_RUNTIME, social: CONFIGURED_RUNTIME },
			latestSocialActivityAtMs: Date.parse("2026-04-23T10:00:00.000Z"),
		});

		expect(snapshot.personas.private.memory.source).toBe("telegram");
		expect(snapshot.personas.social.memory.source).toBe("social");
		expect(snapshot.personas.private.memory.contentsExposed).toBe(false);
		expect(snapshot.personas.social.memory.contentsExposed).toBe(false);
		expect(snapshot.personas.private.skills.effective).toEqual([
			"external-provider",
			"memory",
			"social-posting",
		]);
		expect(snapshot.personas.social.skills.effective).toEqual(["social-posting"]);
		expect(snapshot.personas.social.filesystem.workspace).toBe("not_mounted");
		expect(snapshot.personas.social.boundaries.socialHasWorkspaceMount).toBe(false);
		expect(snapshot.personas.private.boundaries.privateProcessesSocialMemory).toBe(false);
		expect(snapshot.personas.social.providers.providerIds).toEqual(["google"]);
		expect(snapshot.personas.social.providers.serviceIds).toEqual(["calendar", "gmail"]);

		const serialized = JSON.stringify(snapshot);
		expect(serialized).not.toContain("social-secret-api-key");
		expect(serialized).not.toContain("private-provider.internal");
	});

	it("does not treat private Hermes env as social runtime configuration", () => {
		const snapshot = buildPersonaStatusSnapshot({
			config: makeConfig({
				socialServices: [
					{
						id: "xtwitter",
						type: "xtwitter",
						enabled: true,
						heartbeatEnabled: true,
						heartbeatIntervalHours: 4,
						enableSkills: true,
						allowedSkills: ["social-posting"],
						notifyOnHeartbeat: "activity",
					},
				],
			}),
			env: {
				TELCLAUDE_PRIVATE_CLAUDE_HOME: "/profiles/private",
				TELCLAUDE_HERMES_API_BASE_URL: "http://private-hermes:8642",
				TELCLAUDE_HERMES_API_KEY: "private-key",
			},
			activeSkillNames: ["social-posting"],
			privatePlugins: EMPTY_PLUGINS,
			socialPlugins: EMPTY_PLUGINS,
		});

		expect(snapshot.personas.private.runtime.configured).toBe(true);
		expect(snapshot.personas.social.runtime).toMatchObject({
			configured: false,
			source: "Hermes social runtime not configured",
			reachability: "not_configured",
		});
		expect(snapshot.personas.social.services).toEqual([
			expect.objectContaining({
				id: "xtwitter",
				runtimeConfigured: false,
				runtimeSource: "Hermes social runtime not configured",
			}),
		]);
		expect(snapshot.personas.social.summary).toBe("social Hermes runtime not configured");
	});

	it("redacts secrets from operational errors before formatting", () => {
		const snapshot = buildPersonaStatusSnapshot({
			config: makeConfig(),
			env: {
				TELCLAUDE_PRIVATE_CLAUDE_HOME: "/profiles/private",
				TELCLAUDE_HERMES_API_BASE_URL: "http://hermes:8642",
				TELCLAUDE_HERMES_API_KEY: "test-key",
			},
			privatePlugins: EMPTY_PLUGINS,
			socialPlugins: EMPTY_PLUGINS,
			runtimeReachability: { private: CONFIGURED_RUNTIME, social: CONFIGURED_RUNTIME },
			cronJobs: [
				cronJob({
					action: { kind: "private-heartbeat" },
					lastRunAtMs: Date.parse("2026-04-23T09:00:00.000Z"),
					lastStatus: "error",
					lastError: "agent leaked sk-ant-1234567890abcdef in error",
				}),
			],
			activeSkillNames: [],
		});

		expect(snapshot.personas.private.operations.lastError).toContain(
			"[REDACTED:anthropic_api_key]",
		);
		expect(snapshot.personas.private.operations.lastError).not.toContain("sk-ant-1234567890abcdef");

		const formatted = formatPersonaStatusSnapshot(snapshot);
		expect(formatted).toContain("[REDACTED:anthropic_api_key]");
		expect(formatted).not.toContain("sk-ant-1234567890abcdef");
	});
});
