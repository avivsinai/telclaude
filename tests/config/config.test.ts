import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterAll, afterEach, describe, expect, it, vi } from "vitest";

const getTempDir = () =>
	(globalThis as Record<string, string | undefined>).__telclaudeTempConfigDir;

vi.mock("../../src/utils.js", async () => {
	const actual = await vi.importActual<typeof import("../../src/utils.js")>("../../src/utils.js");
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-config-"));
	(globalThis as Record<string, string>).__telclaudeTempConfigDir = tempDir;
	return {
		...actual,
		CONFIG_DIR: tempDir,
	};
});

import {
	createDefaultConfigIfMissing,
	loadConfig,
	resetConfigCache,
} from "../../src/config/config.js";
import { resetConfigPath, setConfigPath } from "../../src/config/path.js";

const configPath = () => path.join(getTempDir()!, "telclaude.json");
const privateConfigPath = () => path.join(getTempDir()!, "telclaude-private.json");

afterAll(() => {
	const tempDir = getTempDir();
	if (tempDir && fs.existsSync(tempDir)) {
		fs.rmSync(tempDir, { recursive: true, force: true });
	}
});

afterEach(() => {
	resetConfigCache();
	resetConfigPath();
	delete process.env.TELCLAUDE_PRIVATE_CONFIG;
	const cfgPath = getTempDir() ? configPath() : null;
	if (cfgPath && fs.existsSync(cfgPath)) {
		fs.rmSync(cfgPath, { force: true });
	}
	const privPath = getTempDir() ? privateConfigPath() : null;
	if (privPath && fs.existsSync(privPath)) {
		fs.rmSync(privPath, { force: true });
	}
});

describe("config defaults", () => {
	it("writes Hermes and profile defaults when creating config", async () => {
		setConfigPath(configPath());
		const created = await createDefaultConfigIfMissing();
		expect(created).toBe(true);

		const cfg = JSON.parse(fs.readFileSync(configPath(), "utf8"));
		const removedRuntimeKey = ["s", "d", "k"].join("");
		expect(Object.hasOwn(cfg, removedRuntimeKey)).toBe(false);
		expect(cfg.hermes).toEqual({
			privateRuntime: {
				providerScopes: [],
				capabilityScopes: [
					"web.fetch",
					"web.search",
					"media.image",
					"media.tts",
					"skills.request",
					"schedule.read",
					"schedule.write",
					"browse.use",
				],
				outboundChannels: ["whatsapp"],
			},
		});
		expect(cfg.profiles).toEqual([]);
		expect(cfg.webhooks).toMatchObject({
			enabled: false,
			port: 3015,
			maxBodyBytes: 256 * 1024,
			trustedProxies: [],
			allowedHosts: [],
		});
	});

	it("defaults webhooks to disabled local receiver settings", () => {
		setConfigPath(configPath());
		fs.writeFileSync(configPath(), JSON.stringify({}));

		const cfg = loadConfig();
		expect(cfg.webhooks).toEqual({
			enabled: false,
			port: 3015,
			maxBodyBytes: 256 * 1024,
			globalRateLimitPerHour: 600,
			defaultRateLimitPerHour: 60,
			unauthenticatedRateLimitPerHour: 120,
			trustedProxies: [],
			allowedHosts: [],
		});
		expect(cfg.profiles).toEqual([]);
		expect(cfg.hermes.privateRuntime.providerScopes).toEqual([]);
		expect(cfg.hermes.privateRuntime.capabilityScopes).toEqual([
			"web.fetch",
			"web.search",
			"media.image",
			"media.tts",
			"skills.request",
			"schedule.read",
			"schedule.write",
			"browse.use",
		]);
		expect(cfg.hermes.privateRuntime.outboundChannels).toEqual(["whatsapp"]);
	});

	it("accepts explicit Hermes private-runtime provider, capability, and outbound channel scopes", () => {
		setConfigPath(configPath());
		fs.writeFileSync(
			configPath(),
			JSON.stringify({
				hermes: {
					privateRuntime: {
						providerScopes: ["google", "bank"],
						capabilityScopes: ["web.search", "web.fetch", "browse.use", "github.read"],
						outboundChannels: [],
					},
				},
			}),
		);

		const cfg = loadConfig();
		expect(cfg.hermes.privateRuntime.providerScopes).toEqual(["google", "bank"]);
		expect(cfg.hermes.privateRuntime.capabilityScopes).toEqual([
			"web.search",
			"web.fetch",
			"browse.use",
			"github.read",
		]);
		expect(cfg.hermes.privateRuntime.outboundChannels).toEqual([]);
	});

	it("rejects non-canonical Hermes provider scope ids", () => {
		setConfigPath(configPath());
		fs.writeFileSync(
			configPath(),
			JSON.stringify({
				hermes: {
					privateRuntime: {
						providerScopes: ["google.gmail"],
					},
				},
			}),
		);

		expect(() => loadConfig()).toThrow(/provider scope/);
	});

	it("rejects unknown Hermes capability scopes", () => {
		setConfigPath(configPath());
		fs.writeFileSync(
			configPath(),
			JSON.stringify({
				hermes: {
					privateRuntime: {
						capabilityScopes: ["web.post"],
					},
				},
			}),
		);

		expect(() => loadConfig()).toThrow();
	});

	it("accepts valid operator profiles", () => {
		setConfigPath(configPath());
		fs.writeFileSync(
			configPath(),
			JSON.stringify({
				profiles: [
					{
						id: "engineer",
						label: "Engineer",
						description: "Code-heavy private operator profile",
						soulPath: "docs/soul.md",
						allowedSkills: ["telegram-reply"],
						providerScopes: ["google"],
						capabilityScopes: ["web.search", "browse.use"],
						outboundChannels: ["telegram"],
						defaultModel: {
							providerId: "anthropic",
							modelId: "claude-sonnet-4-5-20250929",
						},
					},
				],
			}),
		);

		const cfg = loadConfig();
		expect(cfg.profiles[0]).toMatchObject({
			id: "engineer",
			label: "Engineer",
			allowedSkills: ["telegram-reply"],
			providerScopes: ["google"],
			capabilityScopes: ["web.search", "browse.use"],
			outboundChannels: ["telegram"],
		});
	});

	it("accepts narrow household WhatsApp bindings and normalizes their addresses", () => {
		setConfigPath(configPath());
		fs.writeFileSync(
			configPath(),
			JSON.stringify({
				profiles: [
					{
						id: "parent-a",
						label: "Parent A",
						allowedSkills: [],
						providerScopes: ["clalit"],
						capabilityScopes: ["schedule.read", "schedule.write"],
						outboundChannels: ["whatsapp"],
						whatsappHouseholdBindings: [
							{
								bindingId: "parent-a",
								address: "+15551234567",
								replyAddress: "whatsapp:+15551234567",
								displayName: "Parent A",
								subjectUserId: "household:parent-a",
							},
						],
					},
				],
			}),
		);

		const cfg = loadConfig();
		expect(cfg.profiles[0]?.whatsappHouseholdBindings).toEqual([
			{
				bindingId: "parent-a",
				address: "whatsapp:+15551234567",
				replyAddress: "whatsapp:+15551234567",
				displayName: "Parent A",
				subjectUserId: "household:parent-a",
			},
		]);
	});

	it("rejects unsafe household subjects, broad profiles, and duplicate addresses", () => {
		setConfigPath(configPath());
		const householdProfile = (overrides: Record<string, unknown> = {}) => ({
			id: "parent-a",
			label: "Parent A",
			allowedSkills: [],
			providerScopes: ["clalit"],
			capabilityScopes: ["schedule.read", "schedule.write"],
			outboundChannels: ["whatsapp"],
			whatsappHouseholdBindings: [
				{
					bindingId: "parent-a",
					address: "whatsapp:+15551234567",
					replyAddress: "whatsapp:+15551234567",
					displayName: "Parent A",
					subjectUserId: "household:parent-a",
				},
			],
			...overrides,
		});

		fs.writeFileSync(
			configPath(),
			JSON.stringify({
				profiles: [
					householdProfile({
						whatsappHouseholdBindings: [
							{
								bindingId: "parent-a",
								address: "whatsapp:+15551234567",
								replyAddress: "whatsapp:+15551234567",
								displayName: "Parent A",
								subjectUserId: "123456789",
							},
						],
					}),
				],
			}),
		);
		expect(() => loadConfig()).toThrow(/subjectUserId|household/i);

		resetConfigCache();
		fs.writeFileSync(
			configPath(),
			JSON.stringify({ profiles: [householdProfile({ capabilityScopes: ["web.fetch"] })] }),
		);
		expect(() => loadConfig()).toThrow(/household.*capability|capability.*household/i);

		resetConfigCache();
		fs.writeFileSync(
			configPath(),
			JSON.stringify({
				profiles: [
					householdProfile(),
					householdProfile({
						id: "parent-b",
						label: "Parent B",
						whatsappHouseholdBindings: [
							{
								bindingId: "parent-b",
								address: "+15551234567",
								replyAddress: "+15551234567",
								displayName: "Parent B",
								subjectUserId: "household:parent-b",
							},
						],
					}),
				],
			}),
		);
		expect(() => loadConfig()).toThrow(/duplicate.*whatsapp|whatsapp.*duplicate/i);
	});

	it("accepts only content-free provider consent bound to the normalized channel", () => {
		setConfigPath(configPath());
		const address = "whatsapp:+15551234567";
		const receipt = {
			service: "clalit",
			state: "granted",
			ceremonyVersion: "phase0.v1",
			ceremonyHash: `sha256:${"a".repeat(64)}`,
			verifiedChannelHash: `sha256:${crypto.createHash("sha256").update(address).digest("hex")}`,
			categories: {
				otpRelay: true,
				subjectOwnership: true,
				retentionDisclosure: true,
				emergencyUnderstanding: true,
			},
			recordedAt: "2026-07-17T09:00:00.000Z",
			operatorId: "operator:phase0-admin",
		};
		const profile = {
			id: "parent-a",
			label: "Parent A",
			allowedSkills: [],
			providerScopes: ["clalit"],
			capabilityScopes: ["schedule.read", "schedule.write"],
			outboundChannels: ["whatsapp"],
			whatsappHouseholdBindings: [
				{
					bindingId: "parent-a",
					address,
					replyAddress: address,
					displayName: "Parent A",
					subjectUserId: "household:parent-a",
					providerConsent: receipt,
				},
			],
		};
		fs.writeFileSync(configPath(), JSON.stringify({ profiles: [profile] }));
		expect(loadConfig().profiles[0]?.whatsappHouseholdBindings?.[0]?.providerConsent).toEqual(
			receipt,
		);

		resetConfigCache();
		fs.writeFileSync(
			configPath(),
			JSON.stringify({
				profiles: [
					{
						...profile,
						whatsappHouseholdBindings: [
							{
								...profile.whatsappHouseholdBindings[0],
								providerConsent: { ...receipt, verifiedChannelHash: `sha256:${"b".repeat(64)}` },
							},
						],
					},
				],
			}),
		);
		expect(() => loadConfig()).toThrow(/channel.*hash|hash.*channel/i);

		resetConfigCache();
		fs.writeFileSync(
			configPath(),
			JSON.stringify({
				profiles: [
					{
						...profile,
						whatsappHouseholdBindings: [
							{
								...profile.whatsappHouseholdBindings[0],
								providerConsent: { ...receipt, phone: "+15551234567" },
							},
						],
					},
				],
			}),
		);
		expect(() => loadConfig()).toThrow();
	});

	it("keeps reminder consent content-free, channel-bound, and independently revocable", () => {
		setConfigPath(configPath());
		const address = "whatsapp:+15551234567";
		const verifiedChannelHash = `sha256:${crypto
			.createHash("sha256")
			.update(address)
			.digest("hex")}`;
		const reminderConsent = {
			state: "revoked",
			ceremonyVersion: "phase0.v1",
			ceremonyHash: `sha256:${"c".repeat(64)}`,
			verifiedChannelHash,
			categories: {
				proactiveDelivery: true,
				scheduleManagement: true,
				retentionDisclosure: true,
			},
			recordedAt: "2026-07-17T09:00:00.000Z",
			operatorId: "operator:phase0-admin",
			revokedAt: "2026-07-18T09:00:00.000Z",
		};
		const profile = {
			id: "parent-a",
			label: "Parent A",
			allowedSkills: [],
			providerScopes: ["clalit"],
			capabilityScopes: ["schedule.read", "schedule.write"],
			outboundChannels: ["whatsapp"],
			whatsappHouseholdBindings: [
				{
					bindingId: "parent-a",
					address,
					replyAddress: address,
					displayName: "Parent A",
					subjectUserId: "household:parent-a",
					reminderConsent,
				},
			],
		};
		fs.writeFileSync(configPath(), JSON.stringify({ profiles: [profile] }));
		expect(loadConfig().profiles[0]?.whatsappHouseholdBindings?.[0]?.reminderConsent).toEqual(
			reminderConsent,
		);

		resetConfigCache();
		fs.writeFileSync(
			configPath(),
			JSON.stringify({
				profiles: [
					{
						...profile,
						whatsappHouseholdBindings: [
							{
								...profile.whatsappHouseholdBindings[0],
								reminderConsent: {
									...reminderConsent,
									verifiedChannelHash: `sha256:${"d".repeat(64)}`,
								},
							},
						],
					},
				],
			}),
		);
		expect(() => loadConfig()).toThrow(/reminder.*channel|channel.*reminder/i);
	});

	it("rejects reserved, duplicate, and unsafe operator profiles", () => {
		setConfigPath(configPath());
		fs.writeFileSync(configPath(), JSON.stringify({ profiles: [{ id: "default", label: "Bad" }] }));
		expect(() => loadConfig()).toThrow();

		resetConfigCache();
		fs.writeFileSync(
			configPath(),
			JSON.stringify({
				profiles: [
					{ id: "engineer", label: "Engineer" },
					{ id: "engineer", label: "Duplicate" },
				],
			}),
		);
		expect(() => loadConfig()).toThrow(/duplicate profile id/);

		resetConfigCache();
		fs.writeFileSync(
			configPath(),
			JSON.stringify({
				profiles: [{ id: "engineer", label: "Engineer", soulPath: "/etc/passwd" }],
			}),
		);
		expect(() => loadConfig()).toThrow(/soulPath/);
	});
});

describe("config split (TELCLAUDE_PRIVATE_CONFIG)", () => {
	it("defaults social service heartbeatEnabled to true", () => {
		setConfigPath(configPath());
		fs.writeFileSync(
			configPath(),
			JSON.stringify({
				socialServices: [{ id: "xtwitter", type: "xtwitter", enabled: true }],
			}),
		);

		const cfg = loadConfig();
		expect(cfg.socialServices[0].heartbeatEnabled).toBe(true);
	});

	it("deep-merges private config on top of policy config", () => {
		setConfigPath(configPath());

		// Policy config: providers + security profile
		const policy = {
			providers: [{ id: "svc", baseUrl: "http://localhost:3001", services: ["health-api"] }],
			security: { profile: "strict" },
		};
		fs.writeFileSync(configPath(), JSON.stringify(policy));

		// Private config: adds allowedChats (relay-only)
		const priv = {
			telegram: { allowedChats: [12345] },
			security: { permissions: { users: { "tg:12345": { tier: "FULL_ACCESS" } } } },
		};
		fs.writeFileSync(privateConfigPath(), JSON.stringify(priv));
		process.env.TELCLAUDE_PRIVATE_CONFIG = privateConfigPath();

		const cfg = loadConfig();

		// Policy fields present
		expect(cfg.providers).toHaveLength(1);
		expect(cfg.providers[0].id).toBe("svc");
		expect(cfg.security.profile).toBe("strict");

		// Private fields merged in
		expect(cfg.telegram.allowedChats).toEqual([12345]);
		expect(cfg.security.permissions?.users?.["tg:12345"]?.tier).toBe("FULL_ACCESS");
	});

	it("works without private config (backward compat)", () => {
		setConfigPath(configPath());
		const policy = { providers: [{ id: "test", baseUrl: "http://localhost:3002", services: [] }] };
		fs.writeFileSync(configPath(), JSON.stringify(policy));

		// No TELCLAUDE_PRIVATE_CONFIG set
		const cfg = loadConfig();
		expect(cfg.providers).toHaveLength(1);
		expect(cfg.telegram.allowedChats).toBeUndefined();
	});

	it("private config arrays replace policy arrays (not concat)", () => {
		setConfigPath(configPath());

		const policy = { telegram: { allowedChats: [111, 222] } };
		fs.writeFileSync(configPath(), JSON.stringify(policy));

		const priv = { telegram: { allowedChats: [333] } };
		fs.writeFileSync(privateConfigPath(), JSON.stringify(priv));
		process.env.TELCLAUDE_PRIVATE_CONFIG = privateConfigPath();

		const cfg = loadConfig();
		expect(cfg.telegram.allowedChats).toEqual([333]);
	});

	it("ignores missing private config file gracefully", () => {
		setConfigPath(configPath());
		fs.writeFileSync(configPath(), JSON.stringify({}));
		process.env.TELCLAUDE_PRIVATE_CONFIG = "/nonexistent/telclaude-private.json";

		// Should not throw
		const cfg = loadConfig();
		expect(cfg.security.profile).toBe("simple"); // default
	});
});
