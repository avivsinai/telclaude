import fs from "node:fs";
import path from "node:path";
import JSON5 from "json5";
import { resolveConfigPath, resolveRuntimeConfigPath } from "../config/path.js";

export const HERMES_PRIVATE_RUNTIME_FALLBACK_PATH = "telclaude.private-runtime.legacy";

export type HermesPrivateRuntimeControlMode = "hermes" | "legacy";
export type HermesPrivateRuntimeControlSource =
	| "env-disabled"
	| "runtime-config"
	| "runtime-config-default"
	| "runtime-config-invalid";

export type HermesPrivateRuntimeEffectiveState = {
	readonly ok: true;
	readonly effectiveMode: HermesPrivateRuntimeControlMode;
	readonly effectiveValue: "1" | "0";
	readonly rolloutAllowed: boolean;
	readonly rolloutEnvValue?: string;
	readonly controlMode: HermesPrivateRuntimeControlMode;
	readonly controlSource: HermesPrivateRuntimeControlSource;
	readonly fallbackPath: string;
};

type RuntimeConfig = Record<string, unknown>;

export function readHermesPrivateRuntimeEffectiveState(
	env: NodeJS.ProcessEnv = process.env,
): HermesPrivateRuntimeEffectiveState {
	const rolloutEnvValue = env.TELCLAUDE_HERMES_PRIVATE_RUNTIME;
	const rolloutAllowed = rolloutEnvValue === "1";
	const configuredMode = readConfiguredControlMode();

	if (!rolloutAllowed) {
		return {
			ok: true,
			effectiveMode: "legacy",
			effectiveValue: "0",
			rolloutAllowed,
			rolloutEnvValue,
			controlMode: configuredMode.mode ?? "legacy",
			controlSource: "env-disabled",
			fallbackPath: HERMES_PRIVATE_RUNTIME_FALLBACK_PATH,
		};
	}

	if (configuredMode.mode === "legacy") {
		return {
			ok: true,
			effectiveMode: "legacy",
			effectiveValue: "0",
			rolloutAllowed,
			rolloutEnvValue,
			controlMode: "legacy",
			controlSource: "runtime-config",
			fallbackPath: HERMES_PRIVATE_RUNTIME_FALLBACK_PATH,
		};
	}

	if (configuredMode.mode === "hermes") {
		return {
			ok: true,
			effectiveMode: "hermes",
			effectiveValue: "1",
			rolloutAllowed,
			rolloutEnvValue,
			controlMode: "hermes",
			controlSource: "runtime-config",
			fallbackPath: HERMES_PRIVATE_RUNTIME_FALLBACK_PATH,
		};
	}

	if (configuredMode.invalid) {
		return {
			ok: true,
			effectiveMode: "legacy",
			effectiveValue: "0",
			rolloutAllowed,
			rolloutEnvValue,
			controlMode: "legacy",
			controlSource: "runtime-config-invalid",
			fallbackPath: HERMES_PRIVATE_RUNTIME_FALLBACK_PATH,
		};
	}

	return {
		ok: true,
		effectiveMode: "hermes",
		effectiveValue: "1",
		rolloutAllowed,
		rolloutEnvValue,
		controlMode: "hermes",
		controlSource: "runtime-config-default",
		fallbackPath: HERMES_PRIVATE_RUNTIME_FALLBACK_PATH,
	};
}

export function setHermesPrivateRuntimeControlMode(
	mode: HermesPrivateRuntimeControlMode,
): HermesPrivateRuntimeEffectiveState {
	const runtimeConfigPath = resolveRuntimeConfigPath(resolveConfigPath());
	const config = readRuntimeConfigForWrite(runtimeConfigPath);
	const hermes = asPlainObject(config.hermes);
	const privateRuntime = asPlainObject(hermes.privateRuntime);
	config.hermes = {
		...hermes,
		privateRuntime: {
			...privateRuntime,
			mode,
		},
	};
	writeRuntimeConfig(runtimeConfigPath, config);
	return readHermesPrivateRuntimeEffectiveState();
}

function readConfiguredControlMode():
	| { mode: HermesPrivateRuntimeControlMode; invalid?: false }
	| { mode?: undefined; invalid?: false }
	| { mode?: undefined; invalid: true } {
	const runtimeConfigPath = resolveRuntimeConfigPath(resolveConfigPath());
	let config: RuntimeConfig;
	try {
		config = readRuntimeConfig(runtimeConfigPath);
	} catch (error) {
		if (isParseError(error)) return { invalid: true };
		throw error;
	}
	const hermes = asPlainObject(config.hermes);
	const privateRuntime = asPlainObject(hermes.privateRuntime);
	const rawMode = privateRuntime.mode;
	if (rawMode === undefined) return {};
	if (rawMode === "hermes" || rawMode === "legacy") return { mode: rawMode };
	return { invalid: true };
}

function readRuntimeConfig(runtimeConfigPath: string): RuntimeConfig {
	try {
		const raw = fs.readFileSync(runtimeConfigPath, "utf8");
		const parsed = JSON5.parse(raw) as unknown;
		return asPlainObject(parsed);
	} catch (error) {
		const code = (error as NodeJS.ErrnoException).code;
		if (code === "ENOENT") return {};
		throw error;
	}
}

function readRuntimeConfigForWrite(runtimeConfigPath: string): RuntimeConfig {
	try {
		return readRuntimeConfig(runtimeConfigPath);
	} catch (error) {
		if (isParseError(error)) return {};
		throw error;
	}
}

function writeRuntimeConfig(runtimeConfigPath: string, config: RuntimeConfig): void {
	fs.mkdirSync(path.dirname(runtimeConfigPath), { recursive: true, mode: 0o700 });
	const tmpPath = `${runtimeConfigPath}.tmp.${process.pid}.${Date.now()}`;
	fs.writeFileSync(tmpPath, `${JSON.stringify(config, null, 2)}\n`, {
		encoding: "utf8",
		mode: 0o600,
	});
	fs.renameSync(tmpPath, runtimeConfigPath);
	fs.chmodSync(runtimeConfigPath, 0o600);
}

function asPlainObject(value: unknown): RuntimeConfig {
	return typeof value === "object" && value !== null && !Array.isArray(value)
		? { ...(value as RuntimeConfig) }
		: {};
}

function isParseError(error: unknown): boolean {
	return error instanceof SyntaxError;
}
