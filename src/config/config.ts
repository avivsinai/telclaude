import fs from "node:fs";
import path from "node:path";

import JSON5 from "json5";
import { z } from "zod";

import { CONFIG_DIR } from "../utils.js";

export const CONFIG_PATH = path.join(CONFIG_DIR, "telclaude.json");

// Session configuration schema
const SessionConfigSchema = z.object({
	scope: z.enum(["per-sender", "global"]).default("per-sender"),
	idleMinutes: z.number().int().positive().default(60),
	resetTriggers: z.array(z.string()).default(["/new"]),
	sendSystemOnce: z.boolean().default(false),
	sessionIntro: z.string().optional(),
	sessionArgNew: z.array(z.string()).optional(),
	sessionArgResume: z.array(z.string()).optional(),
	sessionArgBeforeBody: z.boolean().default(true),
	store: z.string().optional(),
});

// Reply configuration schema
const ReplyConfigSchema = z.object({
	mode: z.enum(["text", "command"]).default("command"),
	text: z.string().optional(),
	command: z.array(z.string()).optional(),
	cwd: z.string().optional(),
	template: z.string().optional(),
	timeoutSeconds: z.number().int().positive().default(600),
	bodyPrefix: z.string().optional(),
	session: SessionConfigSchema.optional(),
	claudeOutputFormat: z.enum(["text", "json", "stream-json"]).optional(),
	mediaMaxMb: z.number().positive().optional(),
	typingIntervalSeconds: z.number().positive().default(8),
	heartbeatMinutes: z.number().positive().optional(),
	mediaUrl: z.string().optional(),
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

/**
 * Load and parse the configuration file.
 */
export function loadConfig(): TelclaudeConfig {
	try {
		const stat = fs.statSync(CONFIG_PATH);
		if (cachedConfig && configMtime === stat.mtimeMs) {
			return cachedConfig;
		}

		const raw = fs.readFileSync(CONFIG_PATH, "utf-8");
		const parsed = JSON5.parse(raw);
		const validated = TelclaudeConfigSchema.parse(parsed);

		cachedConfig = validated;
		configMtime = stat.mtimeMs;

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
 * Reset the config cache (useful for testing).
 */
export function resetConfigCache() {
	cachedConfig = null;
	configMtime = null;
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
 */
export async function createDefaultConfigIfMissing(): Promise<boolean> {
	try {
		await fs.promises.access(CONFIG_PATH);
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
					mode: "command",
					command: ["claude", "-p", "{{BodyStripped}}"],
					timeoutSeconds: 600,
					claudeOutputFormat: "json",
				},
			},
			logging: {
				level: "info",
			},
		};

		await fs.promises.writeFile(CONFIG_PATH, JSON.stringify(defaultConfig, null, 2), "utf-8");
		return true;
	}
}
