import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterAll, afterEach, describe, expect, it, vi } from "vitest";

const getTempDir = () => (globalThis as Record<string, string | undefined>).__telclaudeTempConfigDir;

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

describe("sdk config defaults", () => {
	it("writes sdk.betas default when creating config", async () => {
		setConfigPath(configPath());
		const created = await createDefaultConfigIfMissing();
		expect(created).toBe(true);

		const cfg = JSON.parse(fs.readFileSync(configPath(), "utf8"));
		expect(cfg.sdk).toEqual({ betas: [] });
	});

	it("rejects unknown beta values in config", async () => {
		setConfigPath(configPath());
		const badCfg = {
			sdk: { betas: ["bogus-beta"] },
		};
		fs.writeFileSync(configPath(), JSON.stringify(badCfg));

		await expect(() => loadConfig()).toThrow();
	});
});

describe("config split (TELCLAUDE_PRIVATE_CONFIG)", () => {
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
