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

afterAll(() => {
	const tempDir = getTempDir();
	if (tempDir && fs.existsSync(tempDir)) {
		fs.rmSync(tempDir, { recursive: true, force: true });
	}
});

afterEach(() => {
	resetConfigCache();
	resetConfigPath();
	const cfgPath = getTempDir() ? configPath() : null;
	if (cfgPath && fs.existsSync(cfgPath)) {
		fs.rmSync(cfgPath, { force: true });
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
