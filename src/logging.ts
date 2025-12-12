import fs from "node:fs";
import path from "node:path";

import pino, { type Bindings, type LevelWithSilent, type Logger } from "pino";
import { type TelclaudeConfig, loadConfig } from "./config/config.js";
import { isVerbose } from "./globals.js";
import { CONFIG_DIR } from "./utils.js";

const DEFAULT_LOG_DIR = path.join(CONFIG_DIR, "logs");
export const DEFAULT_LOG_FILE = path.join(DEFAULT_LOG_DIR, "telclaude.log");

const ALLOWED_LEVELS: readonly LevelWithSilent[] = [
	"silent",
	"fatal",
	"error",
	"warn",
	"info",
	"debug",
	"trace",
];

export type LoggerSettings = {
	level?: LevelWithSilent;
	file?: string;
};

type ResolvedSettings = {
	level: LevelWithSilent;
	file: string;
};
export type LoggerResolvedSettings = ResolvedSettings;

let cachedLogger: Logger | null = null;
let cachedSettings: ResolvedSettings | null = null;
let overrideSettings: LoggerSettings | null = null;

function normalizeLevel(level?: string): LevelWithSilent {
	if (isVerbose()) return "debug";
	const candidate = level ?? "info";
	return ALLOWED_LEVELS.includes(candidate as LevelWithSilent)
		? (candidate as LevelWithSilent)
		: "info";
}

function resolveSettings(): ResolvedSettings {
	const cfg: TelclaudeConfig["logging"] | undefined = overrideSettings ?? loadConfig().logging;
	const level = normalizeLevel(cfg?.level);
	const file = cfg?.file ?? DEFAULT_LOG_FILE;
	return { level, file };
}

function settingsChanged(a: ResolvedSettings | null, b: ResolvedSettings) {
	if (!a) return true;
	return a.level !== b.level || a.file !== b.file;
}

function buildLogger(settings: ResolvedSettings): Logger {
	const logDir = path.dirname(settings.file);
	fs.mkdirSync(logDir, { recursive: true, mode: 0o700 });
	try {
		fs.chmodSync(logDir, 0o700);
	} catch {
		// Best effort; continue even if chmod fails (e.g., on some filesystems)
	}

	// Ensure file exists with 0600 to prevent world-readable logs
	if (!fs.existsSync(settings.file)) {
		fs.closeSync(fs.openSync(settings.file, "a", 0o600));
	} else {
		try {
			fs.chmodSync(settings.file, 0o600);
		} catch {
			// Ignore chmod errors; destination below will still open the file
		}
	}

	const destination = pino.destination({
		dest: settings.file,
		mkdir: true,
		sync: true, // deterministic for tests; log volume is modest.
	});
	return pino(
		{
			level: settings.level,
			base: undefined,
			timestamp: pino.stdTimeFunctions.isoTime,
		},
		destination,
	);
}

export function getLogger(): Logger {
	const settings = resolveSettings();
	if (!cachedLogger || settingsChanged(cachedSettings, settings)) {
		cachedLogger = buildLogger(settings);
		cachedSettings = settings;
	}
	return cachedLogger;
}

export function getChildLogger(bindings?: Bindings, opts?: { level?: LevelWithSilent }): Logger {
	return getLogger().child(bindings ?? {}, opts);
}

export function getResolvedLoggerSettings(): LoggerResolvedSettings {
	return resolveSettings();
}

// Test helpers
export function setLoggerOverride(settings: LoggerSettings | null) {
	overrideSettings = settings;
	cachedLogger = null;
	cachedSettings = null;
}

export function resetLogger() {
	cachedLogger = null;
	cachedSettings = null;
	overrideSettings = null;
}
