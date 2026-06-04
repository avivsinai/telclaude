import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterAll, afterEach, describe, expect, it, vi } from "vitest";

const getTempDir = () =>
	(globalThis as Record<string, string | undefined>).__telclaudeEmailConfigDir;

vi.mock("../../src/utils.js", async () => {
	const actual = await vi.importActual<typeof import("../../src/utils.js")>("../../src/utils.js");
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-email-config-"));
	(globalThis as Record<string, string>).__telclaudeEmailConfigDir = tempDir;
	return { ...actual, CONFIG_DIR: tempDir };
});

import { loadConfig, resetConfigCache } from "../../src/config/config.js";
import { resetConfigPath, setConfigPath } from "../../src/config/path.js";

const configPath = () => path.join(getTempDir()!, "telclaude.json");

afterAll(() => {
	const tempDir = getTempDir();
	if (tempDir && fs.existsSync(tempDir)) fs.rmSync(tempDir, { recursive: true, force: true });
});

afterEach(() => {
	resetConfigCache();
	resetConfigPath();
	const cfgPath = getTempDir() ? configPath() : null;
	if (cfgPath && fs.existsSync(cfgPath)) fs.rmSync(cfgPath, { force: true });
});

describe("email config", () => {
	it("defaults email delivery to OFF when absent (no live send by default)", () => {
		setConfigPath(configPath());
		fs.writeFileSync(configPath(), JSON.stringify({}));

		const cfg = loadConfig();
		// The safety invariant: default + test fixtures cannot send live email.
		expect(cfg.email).toEqual({
			enabled: false,
			defaultSubject: "Message from your assistant",
		});
		expect(cfg.email.from).toBeUndefined();
	});

	it("parses an enabled email config with from / subject / messageIdDomain", () => {
		setConfigPath(configPath());
		fs.writeFileSync(
			configPath(),
			JSON.stringify({
				email: {
					enabled: true,
					from: "assistant@relay.test",
					defaultSubject: "Re: your request",
					messageIdDomain: "relay.test",
				},
			}),
		);

		const cfg = loadConfig();
		expect(cfg.email).toEqual({
			enabled: true,
			from: "assistant@relay.test",
			defaultSubject: "Re: your request",
			messageIdDomain: "relay.test",
		});
	});

	it("rejects a non-email from address", () => {
		setConfigPath(configPath());
		fs.writeFileSync(
			configPath(),
			JSON.stringify({ email: { enabled: true, from: "not-an-address" } }),
		);
		expect(() => loadConfig()).toThrow();
	});

	it("permits enabled:true without from (relay fails closed at registration, not config load)", () => {
		// from-when-enabled is enforced fail-closed at the relay (it skips registering
		// the connector and logs DISABLED), so the schema itself accepts this shape.
		setConfigPath(configPath());
		fs.writeFileSync(configPath(), JSON.stringify({ email: { enabled: true } }));

		const cfg = loadConfig();
		expect(cfg.email.enabled).toBe(true);
		expect(cfg.email.from).toBeUndefined();
	});
});
