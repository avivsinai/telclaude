import fs from "node:fs";

import JSON5 from "json5";
import { z } from "zod";

import { CONFIG_DIR } from "../utils.js";
import { resolveConfigPath } from "./path.js";

// =============================================================================
// Default value constants (single source of truth for Zod 4 compatibility)
// =============================================================================

const REPLY_DEFAULTS = {
	enabled: true,
	timeoutSeconds: 600,
	typingIntervalSeconds: 8,
} as const;

const TRANSCRIPTION_DEFAULTS = {
	provider: "openai",
	model: "whisper-1",
	timeoutSeconds: 60,
} as const;

const IMAGE_GENERATION_DEFAULTS = {
	provider: "gpt-image",
	model: "gpt-image-1.5",
	size: "1024x1024",
	quality: "medium",
	maxPerHourPerUser: 10,
	maxPerDayPerUser: 50,
} as const;

const VIDEO_PROCESSING_DEFAULTS = {
	enabled: false,
	frameInterval: 1,
	maxFrames: 30,
	maxDurationSeconds: 300,
	extractAudio: true,
} as const;

const TTS_DEFAULTS = {
	provider: "openai",
	voice: "alloy",
	speed: 1.0,
	autoReadResponses: false,
	maxPerHourPerUser: 30,
	maxPerDayPerUser: 100,
} as const;

const SUMMARIZE_DEFAULTS = {
	maxPerHourPerUser: 30,
	maxPerDayPerUser: 100,
	maxCharacters: 8000,
	timeoutMs: 30_000,
} as const;

const SECURITY_DEFAULTS = { profile: "simple" } as const;
const TELEGRAM_DEFAULTS = { heartbeatSeconds: 60 } as const;
const SDK_DEFAULTS = { betas: [] as "context-1m-2025-08-07"[] };
const SOCIAL_SERVICE_DEFAULTS = { enabled: false, heartbeatIntervalHours: 4 } as const;
const CRON_DEFAULTS = { enabled: true, pollIntervalSeconds: 15, timeoutSeconds: 900 } as const;

// Session configuration schema
const SessionConfigSchema = z.object({
	scope: z.enum(["per-sender", "global"]).default("per-sender"),
	idleMinutes: z.number().int().positive().default(60),
	resetTriggers: z.array(z.string()).default(["/new"]),
	store: z.string().optional(),
});

// Streaming configuration schema for real-time Telegram updates
const StreamingConfigSchema = z.object({
	/** Enable streaming responses (editMessageText). Default: true */
	enabled: z.boolean().default(true),
	/** Minimum interval between updates in ms. Default: 1500 */
	minUpdateIntervalMs: z.number().int().positive().default(1500),
	/** Show inline keyboard buttons after responses. Default: false (can be noisy on mobile) */
	showInlineKeyboard: z.boolean().default(false),
});

// Reply configuration schema (SDK-based)
const ReplyConfigSchema = z
	.object({
		enabled: z.boolean().default(REPLY_DEFAULTS.enabled),
		timeoutSeconds: z.number().int().positive().default(REPLY_DEFAULTS.timeoutSeconds),
		session: SessionConfigSchema.optional(),
		typingIntervalSeconds: z.number().positive().default(REPLY_DEFAULTS.typingIntervalSeconds),
		/** Streaming response configuration */
		streaming: StreamingConfigSchema.optional(),
	})
	.default(REPLY_DEFAULTS);

// Inbound (auto-reply) configuration schema
const InboundConfigSchema = z
	.object({
		reply: ReplyConfigSchema,
	})
	.default({ reply: REPLY_DEFAULTS });

// SDK configuration schema (for Claude Agent SDK options)
const SdkBetaEnum = z.enum(["context-1m-2025-08-07"]);
const SdkConfigSchema = z.object({
	betas: z.array(SdkBetaEnum).default([]),
});

// OpenAI configuration schema (for Whisper, GPT Image, TTS)
// NOTE: Keys are automatically exposed to sandbox for FULL_ACCESS tier only.
const OpenAIConfigSchema = z.object({
	apiKey: z.string().optional(), // OPENAI_API_KEY env var takes precedence
	baseUrl: z.string().optional(), // Custom endpoint for local inference servers
});

// Transcription configuration schema
const TranscriptionConfigSchema = z.object({
	provider: z.enum(["openai", "deepgram", "command"]).default(TRANSCRIPTION_DEFAULTS.provider),
	model: z.string().default(TRANSCRIPTION_DEFAULTS.model),
	language: z.string().optional(), // Auto-detect if not set
	// For provider: "command" - CLI-based transcription (like clawdis)
	command: z.array(z.string()).optional(),
	timeoutSeconds: z.number().int().positive().default(TRANSCRIPTION_DEFAULTS.timeoutSeconds),
});

// Image generation configuration schema (GPT Image 1.5)
const ImageGenerationConfigSchema = z.object({
	provider: z.enum(["gpt-image", "disabled"]).default(IMAGE_GENERATION_DEFAULTS.provider),
	model: z.string().default(IMAGE_GENERATION_DEFAULTS.model),
	size: z
		.enum(["auto", "1024x1024", "1536x1024", "1024x1536"])
		.default(IMAGE_GENERATION_DEFAULTS.size),
	quality: z.enum(["low", "medium", "high"]).default(IMAGE_GENERATION_DEFAULTS.quality),
	// Rate limiting for cost control
	maxPerHourPerUser: z
		.number()
		.int()
		.positive()
		.default(IMAGE_GENERATION_DEFAULTS.maxPerHourPerUser),
	maxPerDayPerUser: z.number().int().positive().default(IMAGE_GENERATION_DEFAULTS.maxPerDayPerUser),
});

// Video processing configuration schema
// SECURITY: Disabled by default - FFmpeg runs unsandboxed and has historical parsing vulnerabilities.
// Enable only if you trust all users in allowedChats and accept the risk of processing untrusted video.
const VideoProcessingConfigSchema = z.object({
	enabled: z.boolean().default(VIDEO_PROCESSING_DEFAULTS.enabled),
	frameInterval: z.number().positive().default(VIDEO_PROCESSING_DEFAULTS.frameInterval),
	maxFrames: z.number().int().positive().default(VIDEO_PROCESSING_DEFAULTS.maxFrames),
	maxDurationSeconds: z
		.number()
		.int()
		.positive()
		.default(VIDEO_PROCESSING_DEFAULTS.maxDurationSeconds),
	extractAudio: z.boolean().default(VIDEO_PROCESSING_DEFAULTS.extractAudio),
});

// Text-to-speech configuration schema
const TTSConfigSchema = z.object({
	provider: z.enum(["openai", "elevenlabs", "disabled"]).default(TTS_DEFAULTS.provider),
	voice: z.enum(["alloy", "echo", "fable", "onyx", "nova", "shimmer"]).default(TTS_DEFAULTS.voice),
	speed: z.number().min(0.25).max(4.0).default(TTS_DEFAULTS.speed),
	// Enable auto-read for voice responses
	autoReadResponses: z.boolean().default(TTS_DEFAULTS.autoReadResponses),
	// Rate limiting for cost control
	maxPerHourPerUser: z.number().int().positive().default(TTS_DEFAULTS.maxPerHourPerUser),
	maxPerDayPerUser: z.number().int().positive().default(TTS_DEFAULTS.maxPerDayPerUser),
});

// Summarize (URL content extraction) configuration schema
const SummarizeConfigSchema = z.object({
	maxPerHourPerUser: z.number().int().positive().default(SUMMARIZE_DEFAULTS.maxPerHourPerUser),
	maxPerDayPerUser: z.number().int().positive().default(SUMMARIZE_DEFAULTS.maxPerDayPerUser),
	maxCharacters: z.number().int().positive().default(SUMMARIZE_DEFAULTS.maxCharacters),
	timeoutMs: z.number().int().positive().default(SUMMARIZE_DEFAULTS.timeoutMs),
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
export const PermissionTierSchema = z.enum(["READ_ONLY", "WRITE_LOCAL", "FULL_ACCESS", "SOCIAL"]);
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
	/** Skip two-phase plan preview for FULL_ACCESS approvals. */
	skipPlanPreview: z.boolean().optional(),
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

// Private network endpoint schema for local service allowlisting
// Allows access to specific private network hosts/CIDRs (e.g., Home Assistant, NAS, Plex)
// Security: Port enforcement is REQUIRED - without ports, only 80/443 are allowed
const PrivateEndpointSchema = z
	.object({
		// Human-readable label (like K8s metadata.name)
		label: z.string().min(1).max(64),
		// Target specification - exactly ONE of host or cidr must be provided
		host: z.string().optional(), // Single IP "192.168.1.100" or hostname "homeassistant.local"
		cidr: z.string().optional(), // CIDR range "192.168.1.0/24"
		// Allowed ports (REQUIRED for security - prevents service probing)
		// If not specified, only ports 80 and 443 are allowed
		ports: z.array(z.number().int().positive().max(65535)).optional(),
		// Optional documentation
		description: z.string().max(256).optional(),
	})
	.refine((data) => (data.host !== undefined) !== (data.cidr !== undefined), {
		message: "Exactly one of 'host' or 'cidr' must be provided for each private endpoint.",
	});

export type PrivateEndpoint = z.infer<typeof PrivateEndpointSchema>;

// Network isolation configuration schema
const NetworkConfigSchema = z.object({
	// Additional domains to allow beyond the default developer allowlist
	additionalDomains: z.array(z.string()).default([]),
	// Private network endpoints allowlist (default-deny: only listed endpoints allowed)
	// Metadata endpoints (169.254.169.254) and link-local remain ALWAYS blocked
	privateEndpoints: z.array(PrivateEndpointSchema).default([]),
});

// External provider configuration (sidecar services)
const ExternalProviderSchema = z.object({
	// Provider identifier (e.g., "citizen-services")
	id: z.string().min(1).max(64),
	// Base URL for provider API (should be localhost/private network)
	baseUrl: z.string().url(),
	// Service identifiers handled by this provider (e.g., "health-api", "bank-api")
	services: z.array(z.string()).default([]),
	// Optional description for admin/operator clarity
	description: z.string().max(256).optional(),
});

// Security configuration schema
const SecurityConfigSchema = z.object({
	// Security profile determines which layers are active
	// "simple" (default): Hard enforcement only (sandbox, secret filter, rate limits)
	// "strict": Adds soft policy layers (observer, approvals)
	// "test": No security (for testing only)
	profile: SecurityProfileSchema.default(SECURITY_DEFAULTS.profile),
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
					SOCIAL: z
						.object({
							perMinute: z.number().int().positive().default(10),
							perHour: z.number().int().positive().default(100),
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
	network: NetworkConfigSchema.optional(),
	/** Approval workflow configuration */
	approvals: z
		.object({
			/** Enable two-phase execution plan preview for FULL_ACCESS approvals. Default: true */
			executionPlanPreview: z.boolean().default(true),
			/** TTL for plan approval nonces in seconds. Default: 600 (10 minutes) */
			planApprovalTtlSeconds: z.number().int().positive().default(600),
		})
		.optional(),
});

// Telegram configuration schema
const TelegramGroupChatConfigSchema = z.object({
	// When enabled, group/supergroup messages must mention the bot (or reply to the bot)
	requireMention: z.boolean().default(false),
	// Allow known control commands in group chats without mention.
	// Authorization checks still happen in command handlers.
	allowTextCommands: z.boolean().default(false),
});

// Private heartbeat configuration (autonomous background tasks for telegram persona)
const TelegramHeartbeatConfigSchema = z.object({
	enabled: z.boolean().default(false),
	intervalHours: z.number().positive().default(6),
	/** Send Telegram notification when heartbeat takes action. Default: true */
	notifyOnActivity: z.boolean().default(true),
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
	heartbeatSeconds: z.number().int().positive().default(TELEGRAM_DEFAULTS.heartbeatSeconds),
	reconnect: z
		.object({
			initialMs: z.number().int().positive().default(1000),
			maxMs: z.number().int().positive().default(60000),
			factor: z.number().positive().default(2.0),
			jitter: z.number().min(0).max(1).default(0.3),
			maxAttempts: z.number().int().min(0).default(0), // 0 = unlimited
		})
		.optional(),
	/** Private heartbeat: autonomous background tasks for the telegram persona */
	heartbeat: TelegramHeartbeatConfigSchema.optional(),
});

// Logging configuration schema
const LoggingConfigSchema = z.object({
	level: z.enum(["silent", "fatal", "error", "warn", "info", "debug", "trace"]).optional(),
	file: z.string().optional(),
});

// Generic social service configuration
const SocialServiceConfigSchema = z.object({
	id: z.string().min(1),
	type: z.string().min(1),
	enabled: z.boolean().default(SOCIAL_SERVICE_DEFAULTS.enabled),
	apiKey: z.string().optional(),
	/** Public handle on the service (e.g. "telclaude" for @telclaude on X/Twitter) */
	handle: z.string().optional(),
	/** Display name on the service (e.g. "Claude Ici") */
	displayName: z.string().optional(),
	heartbeatIntervalHours: z
		.number()
		.positive()
		.default(SOCIAL_SERVICE_DEFAULTS.heartbeatIntervalHours),
	adminChatId: z.union([z.string(), z.number()]).optional(),
	agentUrl: z.string().optional(),
	/** Enable skills for autonomous heartbeat activity (Phase 3 only). Default: false */
	enableSkills: z.boolean().default(false),
	/** Future: filter which skills load for this service */
	allowedSkills: z.array(z.string()).optional(),
	/** When to send Telegram notifications on heartbeat. Default: "activity" */
	notifyOnHeartbeat: z.enum(["always", "activity", "never"]).default("activity"),
});

const CronConfigSchema = z.object({
	enabled: z.boolean().default(CRON_DEFAULTS.enabled),
	pollIntervalSeconds: z.number().int().positive().default(CRON_DEFAULTS.pollIntervalSeconds),
	timeoutSeconds: z.number().int().positive().default(CRON_DEFAULTS.timeoutSeconds),
});

// Main config schema
const TelclaudeConfigSchema = z.object({
	security: SecurityConfigSchema.default(SECURITY_DEFAULTS),
	telegram: TelegramConfigSchema.default(TELEGRAM_DEFAULTS),
	inbound: InboundConfigSchema,
	logging: LoggingConfigSchema.default({}),
	sdk: SdkConfigSchema.default(SDK_DEFAULTS),
	// Multimedia capabilities
	openai: OpenAIConfigSchema.default({}),
	transcription: TranscriptionConfigSchema.default(TRANSCRIPTION_DEFAULTS),
	imageGeneration: ImageGenerationConfigSchema.default(IMAGE_GENERATION_DEFAULTS),
	videoProcessing: VideoProcessingConfigSchema.default(VIDEO_PROCESSING_DEFAULTS),
	tts: TTSConfigSchema.default(TTS_DEFAULTS),
	// URL content extraction / summarization
	summarize: SummarizeConfigSchema.default(SUMMARIZE_DEFAULTS),
	// External providers (sidecars) - optional
	providers: z.array(ExternalProviderSchema).default([]),
	// Generic social services (replaces per-service top-level keys)
	socialServices: z.array(SocialServiceConfigSchema).default([]),
	cron: CronConfigSchema.default(CRON_DEFAULTS),
});

export type TelclaudeConfig = z.infer<typeof TelclaudeConfigSchema>;
export type ReplyConfig = z.infer<typeof ReplyConfigSchema>;
export type SessionConfig = z.infer<typeof SessionConfigSchema>;
export type SecurityConfig = z.infer<typeof SecurityConfigSchema>;
export type NetworkConfig = z.infer<typeof NetworkConfigSchema>;
export type ExternalProviderConfig = z.infer<typeof ExternalProviderSchema>;
export type TelegramConfig = z.infer<typeof TelegramConfigSchema>;
export type SdkConfig = z.infer<typeof SdkConfigSchema>;
export type SocialServiceConfig = z.infer<typeof SocialServiceConfigSchema>;
export type CronConfig = z.infer<typeof CronConfigSchema>;
export type OpenAIConfig = z.infer<typeof OpenAIConfigSchema>;
export type TranscriptionConfig = z.infer<typeof TranscriptionConfigSchema>;
export type ImageGenerationConfig = z.infer<typeof ImageGenerationConfigSchema>;
export type VideoProcessingConfig = z.infer<typeof VideoProcessingConfigSchema>;
export type TTSConfig = z.infer<typeof TTSConfigSchema>;
export type SummarizeConfig = z.infer<typeof SummarizeConfigSchema>;

let cachedConfig: TelclaudeConfig | null = null;
let configMtime: number | null = null;
let privateMtime: number | null = null;
let cachedConfigPath: string | null = null;

/**
 * Deep-merge two plain objects. Source values override target values.
 * Arrays are replaced (not concatenated) — source is authoritative.
 */
function deepMerge(
	target: Record<string, unknown>,
	source: Record<string, unknown>,
): Record<string, unknown> {
	const result = { ...target };
	for (const key of Object.keys(source)) {
		const tVal = target[key];
		const sVal = source[key];
		if (isPlainObject(tVal) && isPlainObject(sVal)) {
			result[key] = deepMerge(tVal as Record<string, unknown>, sVal as Record<string, unknown>);
		} else {
			result[key] = sVal;
		}
	}
	return result;
}

function isPlainObject(val: unknown): val is Record<string, unknown> {
	return typeof val === "object" && val !== null && !Array.isArray(val);
}

function safeStat(filePath: string): fs.Stats | null {
	try {
		return fs.statSync(filePath);
	} catch {
		return null;
	}
}

/**
 * Load and parse the configuration file.
 * Uses resolveConfigPath() to determine the config file location.
 *
 * Supports a two-file split for Docker deployments:
 *   - TELCLAUDE_CONFIG → policy config (safe for all containers: providers, network, etc.)
 *   - TELCLAUDE_PRIVATE_CONFIG → relay-only overrides (allowedChats, permissions, secrets)
 *
 * The private config is deep-merged on top of the policy config. Arrays are replaced,
 * not concatenated. If TELCLAUDE_PRIVATE_CONFIG is not set, single-file behavior is preserved.
 */
export function loadConfig(): TelclaudeConfig {
	const configPath = resolveConfigPath();
	const privateConfigPath = process.env.TELCLAUDE_PRIVATE_CONFIG;

	try {
		const stat = fs.statSync(configPath);
		const pStat = privateConfigPath ? safeStat(privateConfigPath) : null;

		// Invalidate cache if any file changed
		if (
			cachedConfig &&
			cachedConfigPath === configPath &&
			configMtime === stat.mtimeMs &&
			privateMtime === (pStat?.mtimeMs ?? null)
		) {
			return cachedConfig;
		}

		const raw = fs.readFileSync(configPath, "utf-8");
		let parsed = JSON5.parse(raw) as Record<string, unknown>;

		// Deep-merge private config if available (relay-only overlay)
		if (privateConfigPath && pStat) {
			try {
				const privateRaw = fs.readFileSync(privateConfigPath, "utf-8");
				const privateParsed = JSON5.parse(privateRaw) as Record<string, unknown>;
				parsed = deepMerge(parsed, privateParsed);
			} catch {
				// Private config is optional — log at debug level
				if (process.env.TELCLAUDE_LOG_LEVEL === "debug") {
					console.debug(`[config] failed to read private config: ${privateConfigPath}`);
				}
			}
		}

		const validated = TelclaudeConfigSchema.parse(parsed);

		cachedConfig = validated;
		configMtime = stat.mtimeMs;
		privateMtime = pStat?.mtimeMs ?? null;
		cachedConfigPath = configPath;

		return validated;
	} catch (err) {
		const code = (err as NodeJS.ErrnoException).code;
		if (code === "ENOENT") {
			// No config file - use schema defaults
			return TelclaudeConfigSchema.parse({});
		}
		if (code === "EACCES") {
			// Permission denied (e.g., running in sandbox where ~/.telclaude is blocked)
			// NOTE: Cannot use getLogger() here - would cause circular dependency with logging.ts
			if (process.env.TELCLAUDE_LOG_LEVEL === "debug") {
				console.debug(
					`[config] config file not accessible (EACCES), using defaults: ${configPath}`,
				);
			}
			return TelclaudeConfigSchema.parse({});
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
	privateMtime = null;
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
