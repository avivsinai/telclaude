import fs from "node:fs";

import JSON5 from "json5";
import { z } from "zod";

import { CONFIG_DIR } from "../utils.js";
import { resolveConfigPath } from "./path.js";

// Lazy logger to avoid circular dependency (logging.ts imports config.ts)
type Logger = ReturnType<typeof import("../logging.js").getChildLogger>;
let _logger: Logger | null = null;
function getLogger(): Logger {
	if (!_logger) {
		// Dynamic import at runtime to break circular dependency
		// eslint-disable-next-line @typescript-eslint/no-require-imports
		const { getChildLogger } = require("../logging.js");
		_logger = getChildLogger({ module: "config" }) as Logger;
	}
	return _logger;
}

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

// SDK configuration schema (for Claude Agent SDK options)
const SdkBetaEnum = z.enum(["context-1m-2025-08-07"]);
const SdkConfigSchema = z.object({
	betas: z.array(SdkBetaEnum).default([]),
});

// OpenAI configuration schema (for Whisper, GPT Image, TTS)
const OpenAIConfigSchema = z.object({
	apiKey: z.string().optional(), // OPENAI_API_KEY env var takes precedence
	baseUrl: z.string().optional(), // Custom endpoint for local inference servers
	// SECURITY: Exposes OpenAI API key to the Claude tool sandbox so Bash tools can call OpenAI.
	// This allows the model to access the key. Use a restricted key and enable only if needed.
	exposeKeyToSandbox: z.boolean().default(false),
});

// Transcription configuration schema
const TranscriptionConfigSchema = z.object({
	provider: z.enum(["openai", "deepgram", "command"]).default("openai"),
	model: z.string().default("whisper-1"), // Any valid OpenAI transcription model
	language: z.string().optional(), // Auto-detect if not set
	// For provider: "command" - CLI-based transcription (like clawdis)
	command: z.array(z.string()).optional(),
	timeoutSeconds: z.number().int().positive().default(60),
});

// Image generation configuration schema (GPT Image 1.5)
const ImageGenerationConfigSchema = z.object({
	provider: z.enum(["gpt-image", "disabled"]).default("gpt-image"),
	model: z.string().default("gpt-image-1.5"), // GPT image model (gpt-image-1.5, gpt-image-1, etc.)
	size: z.enum(["auto", "1024x1024", "1536x1024", "1024x1536"]).default("1024x1024"),
	quality: z.enum(["low", "medium", "high"]).default("medium"),
	// Rate limiting for cost control
	maxPerHourPerUser: z.number().int().positive().default(10),
	maxPerDayPerUser: z.number().int().positive().default(50),
});

// Video processing configuration schema
// SECURITY: Disabled by default - FFmpeg runs unsandboxed and has historical parsing vulnerabilities.
// Enable only if you trust all users in allowedChats and accept the risk of processing untrusted video.
const VideoProcessingConfigSchema = z.object({
	enabled: z.boolean().default(false),
	frameInterval: z.number().positive().default(1), // Seconds between frames
	maxFrames: z.number().int().positive().default(30),
	maxDurationSeconds: z.number().int().positive().default(300), // 5 min max
	extractAudio: z.boolean().default(true), // Transcribe audio track
});

// Text-to-speech configuration schema
const TTSConfigSchema = z.object({
	provider: z.enum(["openai", "elevenlabs", "disabled"]).default("openai"),
	voice: z.enum(["alloy", "echo", "fable", "onyx", "nova", "shimmer"]).default("alloy"),
	speed: z.number().min(0.25).max(4.0).default(1.0),
	// Enable auto-read for voice responses
	autoReadResponses: z.boolean().default(false),
	// Rate limiting for cost control
	maxPerHourPerUser: z.number().int().positive().default(30),
	maxPerDayPerUser: z.number().int().positive().default(100),
});

// Security profile - determines which security layers are active
export const SecurityProfileSchema = z.enum(["simple", "strict", "test"]);
export type SecurityProfile = z.infer<typeof SecurityProfileSchema>;

// Security observer configuration
const ObserverConfigSchema = z.object({
	enabled: z.boolean().default(true),
	maxLatencyMs: z.number().int().positive().default(300000), // 5 minutes - SDK calls can be slow
	dangerThreshold: z.number().min(0).max(1).default(0.7),
	fallbackOnTimeout: z.enum(["allow", "block", "escalate"]).default("block"),
});

// Permission tier
// NOTE: WRITE_LOCAL provides accident prevention, NOT security isolation.
// It blocks common destructive commands (rm, chmod) but can be bypassed via
// interpreters (python -c, node -e). For actual isolation, use containers.
export const PermissionTierSchema = z.enum(["READ_ONLY", "WRITE_LOCAL", "FULL_ACCESS"]);
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

// Secret filter configuration for additive patterns
const SecretFilterConfigSchema = z.object({
	additionalPatterns: z
		.array(
			z.object({
				id: z.string(),
				pattern: z.string(),
			}),
		)
		.optional(),
	entropyDetection: z
		.object({
			enabled: z.boolean().default(true),
			threshold: z.number().min(0).max(8).default(4.5),
			minLength: z.number().int().positive().default(32),
		})
		.optional(),
});

// Security configuration schema
const SecurityConfigSchema = z.object({
	// Security profile determines which layers are active
	// "simple" (default): Hard enforcement only (sandbox, secret filter, rate limits)
	// "strict": Adds soft policy layers (observer, approvals)
	// "test": No security (for testing only)
	profile: SecurityProfileSchema.default("simple"),
	observer: ObserverConfigSchema.optional(),
	secretFilter: SecretFilterConfigSchema.optional(),
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
					WRITE_LOCAL: z
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
	totp: z
		.object({
			sessionTtlMinutes: z.number().int().positive().default(240), // 4 hours
		})
		.optional(),
});

// Telegram configuration schema
const TelegramGroupChatConfigSchema = z.object({
	// When enabled, group/supergroup messages must mention the bot (or reply to the bot)
	requireMention: z.boolean().default(false),
});

const TelegramConfigSchema = z.object({
	// Bot token - stored here (in ~/.telclaude/) rather than .env for security
	// The ~/.telclaude/ directory is blocked from Claude's sandbox
	botToken: z.string().optional(),
	allowedChats: z.array(z.union([z.number(), z.string()])).optional(),
	groupChat: TelegramGroupChatConfigSchema.optional(),
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
	sdk: SdkConfigSchema.optional(),
	// Multimedia capabilities
	openai: OpenAIConfigSchema.optional(),
	transcription: TranscriptionConfigSchema.optional(),
	imageGeneration: ImageGenerationConfigSchema.optional(),
	videoProcessing: VideoProcessingConfigSchema.optional(),
	tts: TTSConfigSchema.optional(),
});

export type TelclaudeConfig = z.infer<typeof TelclaudeConfigSchema>;
export type ReplyConfig = z.infer<typeof ReplyConfigSchema>;
export type SessionConfig = z.infer<typeof SessionConfigSchema>;
export type SecurityConfig = z.infer<typeof SecurityConfigSchema>;
export type TelegramConfig = z.infer<typeof TelegramConfigSchema>;
export type SdkConfig = z.infer<typeof SdkConfigSchema>;
export type OpenAIConfig = z.infer<typeof OpenAIConfigSchema>;
export type TranscriptionConfig = z.infer<typeof TranscriptionConfigSchema>;
export type ImageGenerationConfig = z.infer<typeof ImageGenerationConfigSchema>;
export type VideoProcessingConfig = z.infer<typeof VideoProcessingConfigSchema>;
export type TTSConfig = z.infer<typeof TTSConfigSchema>;

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
		const code = (err as NodeJS.ErrnoException).code;
		if (code === "ENOENT") {
			// No config file - use defaults
			return {};
		}
		if (code === "EACCES") {
			// Permission denied (e.g., running in sandbox where ~/.telclaude is blocked)
			getLogger().debug({ configPath }, "config file not accessible (EACCES), using defaults");
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
 * Ensure the config directory exists with secure permissions.
 *
 * SECURITY: Sets directory to 0700 (owner only).
 */
export async function ensureConfigDir(): Promise<void> {
	await fs.promises.mkdir(CONFIG_DIR, { recursive: true, mode: 0o700 });
	// Harden existing directory permissions
	try {
		await fs.promises.chmod(CONFIG_DIR, 0o700);
	} catch {
		// May fail on some filesystems, continue anyway
	}
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
					maxLatencyMs: 300000, // 5 minutes
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
			sdk: {
				betas: [],
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

		await fs.promises.writeFile(configPath, JSON.stringify(defaultConfig, null, 2), {
			encoding: "utf-8",
			mode: 0o600, // SECURITY: Owner read/write only
		});
		return true;
	}
}
