import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { resetConfigPath, setConfigPath } from "../../src/config/path.js";
import {
	readHermesPrivateRuntimeEffectiveState,
	setHermesPrivateRuntimeControlMode,
} from "../../src/hermes/private-runtime-control.js";

const ORIGINAL_ENV = {
	TELCLAUDE_CONFIG: process.env.TELCLAUDE_CONFIG,
	TELCLAUDE_HERMES_PRIVATE_RUNTIME: process.env.TELCLAUDE_HERMES_PRIVATE_RUNTIME,
};

afterEach(() => {
	resetConfigPath();
	for (const [key, value] of Object.entries(ORIGINAL_ENV)) {
		if (value === undefined) {
			delete process.env[key];
		} else {
			process.env[key] = value;
		}
	}
});

describe("Hermes private-runtime durable control", () => {
	it("keeps the effective mode legacy while the rollout env gate is disabled", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-runtime-control-"));
		const configPath = path.join(tempDir, "telclaude.json");
		setConfigPath(configPath);
		process.env.TELCLAUDE_HERMES_PRIVATE_RUNTIME = "0";

		setHermesPrivateRuntimeControlMode("hermes");
		const state = readHermesPrivateRuntimeEffectiveState();

		expect(state).toMatchObject({
			effectiveMode: "legacy",
			effectiveValue: "0",
			rolloutAllowed: false,
			controlMode: "hermes",
			controlSource: "env-disabled",
		});
	});

	it("drives effective mode through the runtime overlay when the rollout env gate is enabled", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-runtime-control-"));
		const configPath = path.join(tempDir, "telclaude.json");
		const runtimeConfigPath = path.join(tempDir, "telclaude.runtime.json");
		setConfigPath(configPath);
		process.env.TELCLAUDE_HERMES_PRIVATE_RUNTIME = "1";

		expect(readHermesPrivateRuntimeEffectiveState()).toMatchObject({
			effectiveMode: "hermes",
			effectiveValue: "1",
			controlSource: "runtime-config-default",
		});

		setHermesPrivateRuntimeControlMode("legacy");
		const state = readHermesPrivateRuntimeEffectiveState();
		const runtimeConfig = JSON.parse(fs.readFileSync(runtimeConfigPath, "utf8")) as {
			hermes?: { privateRuntime?: { mode?: string } };
		};

		expect(state).toMatchObject({
			effectiveMode: "legacy",
			effectiveValue: "0",
			controlMode: "legacy",
			controlSource: "runtime-config",
		});
		expect(runtimeConfig.hermes?.privateRuntime?.mode).toBe("legacy");
		expect(fs.statSync(runtimeConfigPath).mode & 0o777).toBe(0o600);
	});

	it("fails closed and can recover when the runtime overlay is malformed", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-runtime-control-"));
		const configPath = path.join(tempDir, "telclaude.json");
		const runtimeConfigPath = path.join(tempDir, "telclaude.runtime.json");
		setConfigPath(configPath);
		process.env.TELCLAUDE_HERMES_PRIVATE_RUNTIME = "1";
		fs.writeFileSync(runtimeConfigPath, "{ bad json", { mode: 0o600 });

		expect(readHermesPrivateRuntimeEffectiveState()).toMatchObject({
			effectiveMode: "legacy",
			effectiveValue: "0",
			controlMode: "legacy",
			controlSource: "runtime-config-invalid",
		});

		setHermesPrivateRuntimeControlMode("legacy");
		const runtimeConfig = JSON.parse(fs.readFileSync(runtimeConfigPath, "utf8")) as {
			hermes?: { privateRuntime?: { mode?: string } };
		};

		expect(runtimeConfig.hermes?.privateRuntime?.mode).toBe("legacy");
		expect(readHermesPrivateRuntimeEffectiveState()).toMatchObject({
			effectiveMode: "legacy",
			effectiveValue: "0",
			controlSource: "runtime-config",
		});
	});

	it.each([
		["non-object root", []],
		["non-object hermes", { hermes: [] }],
		["non-object privateRuntime", { hermes: { privateRuntime: [] } }],
		["invalid mode", { hermes: { privateRuntime: { mode: "maybe" } } }],
	])("fails closed for structurally invalid runtime overlay: %s", (_name, overlay) => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-runtime-control-"));
		const configPath = path.join(tempDir, "telclaude.json");
		const runtimeConfigPath = path.join(tempDir, "telclaude.runtime.json");
		setConfigPath(configPath);
		process.env.TELCLAUDE_HERMES_PRIVATE_RUNTIME = "1";
		fs.writeFileSync(runtimeConfigPath, `${JSON.stringify(overlay)}\n`, { mode: 0o600 });

		expect(readHermesPrivateRuntimeEffectiveState()).toMatchObject({
			effectiveMode: "legacy",
			effectiveValue: "0",
			controlMode: "legacy",
			controlSource: "runtime-config-invalid",
		});
	});
});
