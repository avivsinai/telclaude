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
		expect(cfg.hermes).toEqual({ privateRuntime: { providerScopes: [] } });
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
	});

	it("accepts explicit Hermes private-runtime provider scopes", () => {
		setConfigPath(configPath());
		fs.writeFileSync(
			configPath(),
			JSON.stringify({
				hermes: {
					privateRuntime: {
						providerScopes: ["google", "bank"],
					},
				},
			}),
		);

		const cfg = loadConfig();
		expect(cfg.hermes.privateRuntime.providerScopes).toEqual(["google", "bank"]);
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
		});
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
