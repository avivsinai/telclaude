import fs from "node:fs";

import JSON5 from "json5";
import { z } from "zod";

import { CONFIG_DIR } from "../utils.js";
import { resolveConfigPath } from "./path.js";

// Session configuration schema
const SessionConfigSchema = z.object({
	scope: z.enum(["per-sender", "global"]).default("per-sender"),
	idleMinutes: z.number().int().positive().default(60),
	resetTriggers: z.array(z.string()).default(["/new"]),
	store: z.string().optional(),
});

// Reply configuration schema (SDK-based)
const ReplyConfigSchema = z.object({
	enabled: z.boolean().default(true),
	timeoutSeconds: z.number().int().positive().default(600),
	session: SessionConfigSchema.optional(),
	typingIntervalSeconds: z.number().positive().default(8),
});

// Inbound (auto-reply) configuration schema
const InboundConfigSchema = z.object({
	transcribeAudio: z
		.object({
			command: z.array(z.string()),
			timeoutSeconds: z.number().int().positive().default(45),
		})
		.optional(),
	reply: ReplyConfigSchema.optional(),
});

// Security observer configuration
const ObserverConfigSchema = z.object({
	enabled: z.boolean().default(true),
	maxLatencyMs: z.number().int().positive().default(2000),
	dangerThreshold: z.number().min(0).max(1).default(0.7),
	fallbackOnTimeout: z.enum(["allow", "block", "escalate"]).default("block"),
});

// Permission tier
export const PermissionTierSchema = z.enum(["READ_ONLY", "WRITE_SAFE", "FULL_ACCESS"]);
export type PermissionTier = z.infer<typeof PermissionTierSchema>;

// User permission configuration
const UserPermissionSchema = z.object({
	tier: PermissionTierSchema,
	rateLimit: z
		.object({
			perMinute: z.number().int().positive().optional(),
			perHour: z.number().int().positive().optional(),
		})
		.optional(),
});

// Security configuration schema
const SecurityConfigSchema = z.object({
	observer: ObserverConfigSchema.optional(),
	permissions: z
		.object({
			defaultTier: PermissionTierSchema.default("READ_ONLY"),
			users: z.record(z.string(), UserPermissionSchema).default({}),
		})
		.optional(),
	rateLimits: z
		.object({
			global: z
				.object({
					perMinute: z.number().int().positive().default(100),
					perHour: z.number().int().positive().default(1000),
				})
				.optional(),
			perUser: z
				.object({
					perMinute: z.number().int().positive().default(10),
					perHour: z.number().int().positive().default(60),
				})
				.optional(),
			perTier: z
				.object({
					READ_ONLY: z
						.object({
							perMinute: z.number().int().positive().default(20),
							perHour: z.number().int().positive().default(200),
						})
						.optional(),
					WRITE_SAFE: z
						.object({
							perMinute: z.number().int().positive().default(10),
							perHour: z.number().int().positive().default(100),
						})
						.optional(),
					FULL_ACCESS: z
						.object({
							perMinute: z.number().int().positive().default(5),
							perHour: z.number().int().positive().default(30),
						})
						.optional(),
				})
				.optional(),
		})
		.optional(),
	audit: z
		.object({
			enabled: z.boolean().default(true),
			logFile: z.string().optional(),
		})
		.optional(),
});

// Telegram configuration schema
const TelegramConfigSchema = z.object({
	// Bot token - stored here (in ~/.telclaude/) rather than .env for security
	// The ~/.telclaude/ directory is blocked from Claude's sandbox
	botToken: z.string().optional(),
	allowedChats: z.array(z.union([z.number(), z.string()])).optional(),
	polling: z
		.object({
			timeout: z.number().int().positive().default(30),
			limit: z.number().int().positive().default(100),
		})
		.optional(),
	webhook: z
		.object({
			port: z.number().int().positive().optional(),
			path: z.string().optional(),
			secretToken: z.string().optional(),
		})
		.optional(),
	heartbeatSeconds: z.number().int().positive().default(60),
	reconnect: z
		.object({
			initialMs: z.number().int().positive().default(1000),
			maxMs: z.number().int().positive().default(60000),
			factor: z.number().positive().default(2.0),
			jitter: z.number().min(0).max(1).default(0.3),
			maxAttempts: z.number().int().min(0).default(0), // 0 = unlimited
		})
		.optional(),
});

// Logging configuration schema
const LoggingConfigSchema = z.object({
	level: z.enum(["silent", "fatal", "error", "warn", "info", "debug", "trace"]).optional(),
	file: z.string().optional(),
});

// Main config schema
const TelclaudeConfigSchema = z.object({
	security: SecurityConfigSchema.optional(),
	telegram: TelegramConfigSchema.optional(),
	inbound: InboundConfigSchema.optional(),
	logging: LoggingConfigSchema.optional(),
});

export type TelclaudeConfig = z.infer<typeof TelclaudeConfigSchema>;
export type ReplyConfig = z.infer<typeof ReplyConfigSchema>;
export type SessionConfig = z.infer<typeof SessionConfigSchema>;
export type SecurityConfig = z.infer<typeof SecurityConfigSchema>;
export type TelegramConfig = z.infer<typeof TelegramConfigSchema>;

let cachedConfig: TelclaudeConfig | null = null;
let configMtime: number | null = null;
let cachedConfigPath: string | null = null;

/**
 * Load and parse the configuration file.
 * Uses resolveConfigPath() to determine the config file location.
 */
export function loadConfig(): TelclaudeConfig {
	const configPath = resolveConfigPath();

	try {
		const stat = fs.statSync(configPath);
		// Invalidate cache if path changed or mtime changed
		if (cachedConfig && cachedConfigPath === configPath && configMtime === stat.mtimeMs) {
			return cachedConfig;
		}

		const raw = fs.readFileSync(configPath, "utf-8");
		const parsed = JSON5.parse(raw);
		const validated = TelclaudeConfigSchema.parse(parsed);

		cachedConfig = validated;
		configMtime = stat.mtimeMs;
		cachedConfigPath = configPath;

		return validated;
	} catch (err) {
		if ((err as NodeJS.ErrnoException).code === "ENOENT") {
			// No config file, return defaults
			return {};
		}
		throw err;
	}
}

/**
 * Get the current config file path being used.
 */
export function getConfigPath(): string {
	return resolveConfigPath();
}

/**
 * Reset the config cache (useful for testing).
 */
export function resetConfigCache() {
	cachedConfig = null;
	configMtime = null;
	cachedConfigPath = null;
}

/**
 * Get the default config directory path.
 */
export function getConfigDir(): string {
	return CONFIG_DIR;
}

/**
 * Ensure the config directory exists.
 */
export async function ensureConfigDir(): Promise<void> {
	await fs.promises.mkdir(CONFIG_DIR, { recursive: true });
}

/**
 * Create a default config file if it doesn't exist.
 * Uses resolveConfigPath() for the target location.
 */
export async function createDefaultConfigIfMissing(): Promise<boolean> {
	const configPath = resolveConfigPath();

	try {
		await fs.promises.access(configPath);
		return false; // Already exists
	} catch {
		await ensureConfigDir();
		const defaultConfig = {
			security: {
				observer: {
					enabled: true,
					maxLatencyMs: 2000,
					dangerThreshold: 0.7,
					fallbackOnTimeout: "block",
				},
				permissions: {
					defaultTier: "READ_ONLY",
					users: {},
				},
				rateLimits: {
					global: {
						perMinute: 100,
						perHour: 1000,
					},
					perUser: {
						perMinute: 10,
						perHour: 60,
					},
				},
				audit: {
					enabled: true,
				},
			},
			telegram: {
				allowedChats: [],
				polling: {
					timeout: 30,
				},
			},
			inbound: {
				reply: {
					enabled: true,
					timeoutSeconds: 600,
				},
			},
			logging: {
				level: "info",
			},
		};

		await fs.promises.writeFile(configPath, JSON.stringify(defaultConfig, null, 2), "utf-8");
		return true;
	}
}
