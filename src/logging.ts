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
let cachedDestination: unknown | null = null;
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

function closeDestination(dest: unknown): void {
	// pino.destination() returns a SonicBoom stream at runtime, but types only include `write()`.
	// We defensively close/flush any known methods to ensure CLI commands can exit cleanly.
	const d = dest as {
		flushSync?: () => void;
		end?: () => void;
		destroy?: () => void;
	};
	try {
		d.flushSync?.();
	} catch {
		// best-effort
	}
	try {
		d.end?.();
	} catch {
		// best-effort
	}
	try {
		d.destroy?.();
	} catch {
		// best-effort
	}
}

function buildLogger(settings: ResolvedSettings): { logger: Logger; destination: unknown } {
	const logDir = path.dirname(settings.file);
	fs.mkdirSync(logDir, { recursive: true, mode: 0o700 });
	try {
		fs.chmodSync(logDir, 0o700);
	} catch {
		// Best effort; continue even if chmod fails (e.g., on some filesystems)
	}

	// Ensure file exists with 0600 to prevent world-readable logs
	// SECURITY: Use O_CREAT to atomically create if not exists (avoids TOCTOU)
	try {
		// Try to create with O_CREAT | O_EXCL (atomic create-if-not-exists)
		const fd = fs.openSync(
			settings.file,
			fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL,
			0o600,
		);
		fs.closeSync(fd);
	} catch (err) {
		// File already exists (EEXIST) - that's fine, try to fix permissions
		if ((err as NodeJS.ErrnoException).code === "EEXIST") {
			try {
				fs.chmodSync(settings.file, 0o600);
			} catch {
				// Ignore chmod errors; destination below will still open the file
			}
		}
		// Other errors: let pino.destination handle it
	}

	const destination = pino.destination({
		dest: settings.file,
		mkdir: true,
		sync: true, // deterministic for tests; log volume is modest.
	});
	const logger = pino(
		{
			level: settings.level,
			base: undefined,
			timestamp: pino.stdTimeFunctions.isoTime,
		},
		destination,
	);
	return { logger, destination };
}

export function getLogger(): Logger {
	const settings = resolveSettings();
	if (!cachedLogger || settingsChanged(cachedSettings, settings)) {
		if (cachedDestination) {
			closeDestination(cachedDestination);
			cachedDestination = null;
		}
		const built = buildLogger(settings);
		cachedLogger = built.logger;
		cachedDestination = built.destination;
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
	if (cachedDestination) {
		closeDestination(cachedDestination);
		cachedDestination = null;
	}
	overrideSettings = null;
}

export function closeLogger(): void {
	if (cachedDestination) {
		closeDestination(cachedDestination);
		cachedDestination = null;
	}
	cachedLogger = null;
	cachedSettings = null;
}
