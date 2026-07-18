import crypto from "node:crypto";
import fs from "node:fs";

import JSON5 from "json5";
import { z } from "zod";
import { isValidHouseholdBindingId } from "../memory/source.js";
import { resolveInsideRoot } from "../path-safety.js";
import { CONFIG_DIR } from "../utils.js";
import { normalizeWhatsAppAddressRef } from "../whatsapp/address.js";
import { resolveConfigPath, resolveRuntimeConfigPath } from "./path.js";

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

const WEB_DEFAULTS = {
	maxPerHourPerUser: 20,
	maxPerDayPerUser: 100,
} as const;

const SECURITY_DEFAULTS = { profile: "simple" } as const;
const TELEGRAM_DEFAULTS = { heartbeatSeconds: 60 } as const;
const TELEGRAM_NUDGES_DEFAULTS = {
	enabled: false,
	intervalSeconds: 300,
	maxPerHour: 5,
	digestIntervalHours: 24,
} as const;
const SOCIAL_SERVICE_DEFAULTS = {
	enabled: false,
	heartbeatEnabled: true,
	heartbeatIntervalHours: 4,
} as const;
const CRON_DEFAULTS = { enabled: true, pollIntervalSeconds: 15, timeoutSeconds: 900 } as const;
const DASHBOARD_DEFAULTS = { enabled: false, port: 3005 } as const;
const WEBHOOKS_DEFAULTS = {
	enabled: false,
	port: 3015,
	maxBodyBytes: 256 * 1024,
	globalRateLimitPerHour: 600,
	defaultRateLimitPerHour: 60,
	unauthenticatedRateLimitPerHour: 120,
	trustedProxies: [] as string[],
	allowedHosts: [] as string[],
} as const;

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

// Reply configuration schema
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

const ProviderScopeIdSchema = z
	.string()
	.min(1)
	.max(64)
	.regex(/^[a-zA-Z0-9_-]+$/, "provider scope must be a canonical provider id");

const HermesCapabilityScopeSchema = z.enum([
	"web.fetch",
	"web.search",
	"media.image",
	"media.tts",
	"skills.request",
	"schedule.read",
	"schedule.write",
	"browse.use",
	// Interactive browser writes (tc_browse_act*). A RECOGNIZED but opt-in scope: it is
	// intentionally absent from the private-runtime defaults below, so an operator must
	// grant it explicitly. policy.ts maps tc_browse_act* -> browse.act and fails closed
	// ("no browse.act, no act"), so without this enum entry the scope could not be granted
	// at all and the interactive-write tools would be permanently unreachable.
	"browse.act",
	// Authenticated GitHub repository reads (tc_github_*). Another RECOGNIZED but opt-in
	// scope, intentionally absent from the private-runtime defaults below: reading private
	// repo contents through the GitHub App installation token must be granted explicitly.
	// policy.ts maps tc_github_* -> github.read and fails closed, so without this enum entry
	// the scope could not be granted and the repo-read tools would be permanently unreachable.
	"github.read",
]);
const HermesOutboundChannelSchema = z.enum(["whatsapp", "email", "agentmail", "social"]);

const HERMES_PRIVATE_RUNTIME_DEFAULT_CAPABILITY_SCOPES = [
	"web.fetch",
	"web.search",
	"media.image",
	"media.tts",
	"skills.request",
	"schedule.read",
	"schedule.write",
	"browse.use",
] satisfies z.infer<typeof HermesCapabilityScopeSchema>[];

const HERMES_PRIVATE_RUNTIME_DEFAULT_OUTBOUND_CHANNELS = ["whatsapp"] satisfies z.infer<
	typeof HermesOutboundChannelSchema
>[];

const HERMES_DEFAULTS = {
	privateRuntime: {
		providerScopes: [],
		capabilityScopes: HERMES_PRIVATE_RUNTIME_DEFAULT_CAPABILITY_SCOPES,
		outboundChannels: HERMES_PRIVATE_RUNTIME_DEFAULT_OUTBOUND_CHANNELS,
	},
};

const HermesConfigSchema = z.object({
	privateRuntime: z
		.object({
			providerScopes: z.array(ProviderScopeIdSchema).default([]),
			capabilityScopes: z
				.array(HermesCapabilityScopeSchema)
				.default(HERMES_DEFAULTS.privateRuntime.capabilityScopes),
			outboundChannels: z
				.array(HermesOutboundChannelSchema)
				.default(HERMES_DEFAULTS.privateRuntime.outboundChannels),
		})
		.default(HERMES_DEFAULTS.privateRuntime),
});

const OperatorProfileIdSchema = z
	.string()
	.regex(/^[a-z0-9-]{1,32}$/, "profile id must match ^[a-z0-9-]{1,32}$")
	.refine((id) => id !== "default", "'default' is reserved for the implicit profile");

const WhatsAppAddressRefSchema = z.string().transform((value, ctx) => {
	const normalized = normalizeWhatsAppAddressRef(value);
	if (!normalized) {
		ctx.addIssue({
			code: z.ZodIssueCode.custom,
			message: "WhatsApp address must be an E.164 number with optional whatsapp: prefix",
		});
		return z.NEVER;
	}
	return normalized;
});

const Sha256RefSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);

export const HOUSEHOLD_ROLLOUT_RUNGS = [
	"shadow",
	"parentA_text",
	"parentA_clalit",
	"parentA_media",
	"parentA_renewal",
	"parentA_reminders",
	"hold_72h",
	"parentB_text",
	"parentB_clalit",
	"parentB_media",
	"parentB_renewal",
	"parentB_reminders",
	"parentB_hold_72h",
	"complete",
] as const;

const HouseholdRolloutRungSchema = z.enum(HOUSEHOLD_ROLLOUT_RUNGS);

const HouseholdDataControlAckSchema = z
	.object({
		acknowledged: z.boolean(),
		posture: z.enum(["zdr", "standard-abuse-monitoring"]),
		recordedAt: z.iso.datetime(),
		operatorId: z.string().regex(/^operator:[a-z0-9-]{1,64}$/),
	})
	.strict();

const HouseholdProviderConsentSchema = z
	.object({
		service: z.literal("clalit"),
		state: z.enum(["granted", "revoked"]),
		ceremonyVersion: z.literal("phase0.v1"),
		ceremonyHash: Sha256RefSchema,
		verifiedChannelHash: Sha256RefSchema,
		categories: z
			.object({
				otpRelay: z.literal(true),
				subjectOwnership: z.literal(true),
				retentionDisclosure: z.literal(true),
				emergencyUnderstanding: z.literal(true),
			})
			.strict(),
		recordedAt: z.iso.datetime(),
		operatorId: z.string().regex(/^operator:[a-z0-9-]{1,64}$/),
		revokedAt: z.iso.datetime().optional(),
	})
	.strict()
	.superRefine((receipt, ctx) => {
		if (receipt.state === "revoked" && !receipt.revokedAt) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				path: ["revokedAt"],
				message: "revoked household provider consent requires revokedAt",
			});
		}
		if (receipt.state === "granted" && receipt.revokedAt) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				path: ["revokedAt"],
				message: "granted household provider consent cannot include revokedAt",
			});
		}
	});

const HouseholdReminderConsentSchema = z
	.object({
		state: z.enum(["granted", "revoked"]),
		ceremonyVersion: z.literal("phase0.v1"),
		ceremonyHash: Sha256RefSchema,
		verifiedChannelHash: Sha256RefSchema,
		categories: z
			.object({
				proactiveDelivery: z.literal(true),
				scheduleManagement: z.literal(true),
				retentionDisclosure: z.literal(true),
			})
			.strict(),
		recordedAt: z.iso.datetime(),
		operatorId: z.string().regex(/^operator:[a-z0-9-]{1,64}$/),
		revokedAt: z.iso.datetime().optional(),
	})
	.strict()
	.superRefine((receipt, ctx) => {
		if (receipt.state === "revoked" && !receipt.revokedAt) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				path: ["revokedAt"],
				message: "revoked household reminder consent requires revokedAt",
			});
		}
		if (receipt.state === "granted" && receipt.revokedAt) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				path: ["revokedAt"],
				message: "granted household reminder consent cannot include revokedAt",
			});
		}
	});

const WhatsAppHouseholdBindingSchema = z
	.object({
		bindingId: z.string().refine(isValidHouseholdBindingId, "invalid opaque household binding id"),
		addresseeGender: z.enum(["f", "m"]),
		address: WhatsAppAddressRefSchema,
		replyAddress: WhatsAppAddressRefSchema,
		displayName: z.string().trim().min(1).max(80),
		subjectUserId: z.string().trim().min(1).max(80),
		providerConsent: HouseholdProviderConsentSchema.optional(),
		reminderConsent: HouseholdReminderConsentSchema.optional(),
		remindersEnabled: z.boolean().optional(),
		mediaEnabled: z.boolean().optional(),
		emergencyEnabled: z.boolean().optional(),
	})
	.superRefine((binding, ctx) => {
		if (binding.replyAddress !== binding.address) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				path: ["replyAddress"],
				message: "household WhatsApp replyAddress must match the enrolled address",
			});
		}
		if (binding.subjectUserId !== `household:${binding.bindingId}`) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				path: ["subjectUserId"],
				message:
					"household subjectUserId must be the opaque local key household:<binding-id>, never an ID or phone",
			});
		}
		if (
			binding.providerConsent &&
			binding.providerConsent.verifiedChannelHash !== sha256Ref(binding.address)
		) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				path: ["providerConsent", "verifiedChannelHash"],
				message: "household provider consent must bind the normalized WhatsApp address hash",
			});
		}
		if (
			binding.reminderConsent &&
			binding.reminderConsent.verifiedChannelHash !== sha256Ref(binding.address)
		) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				path: ["reminderConsent", "verifiedChannelHash"],
				message: "household reminder consent must bind the normalized WhatsApp channel hash",
			});
		}
	});

function sha256Ref(value: string): `sha256:${string}` {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

const OperatorProfileConfigSchema = z
	.object({
		id: OperatorProfileIdSchema,
		label: z.string().min(1).max(80),
		description: z.string().max(500).optional(),
		soulPath: z.string().min(1).optional(),
		allowedSkills: z.array(z.string().min(1).max(128)).optional(),
		providerScopes: z.array(ProviderScopeIdSchema).optional(),
		capabilityScopes: z.array(HermesCapabilityScopeSchema).optional(),
		outboundChannels: z.array(z.string().min(1).max(64)).optional(),
		whatsappHouseholdBindings: z.array(WhatsAppHouseholdBindingSchema).max(1).optional(),
		defaultModel: z
			.object({
				providerId: z.string().min(1).max(64),
				modelId: z.string().min(1).max(128),
			})
			.optional(),
	})
	.superRefine((profile, ctx) => {
		if (!profile.whatsappHouseholdBindings?.length) return;
		for (const [path, actual, expected] of [
			["allowedSkills", profile.allowedSkills, []],
			["providerScopes", profile.providerScopes, ["clalit"]],
			["capabilityScopes", profile.capabilityScopes, ["schedule.read", "schedule.write"]],
			["outboundChannels", profile.outboundChannels, ["whatsapp"]],
		] as const) {
			if (!sameStringSet(actual, expected)) {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					path: [path],
					message: `household profile ${path} must exactly equal ${JSON.stringify(expected)}`,
				});
			}
		}
	});

function sameStringSet(
	actual: readonly string[] | undefined,
	expected: readonly string[],
): boolean {
	return (
		actual !== undefined &&
		actual.length === expected.length &&
		new Set(actual).size === actual.length &&
		expected.every((value) => actual.includes(value))
	);
}

function validateProfileSoulPaths(
	profiles: readonly z.infer<typeof OperatorProfileConfigSchema>[],
) {
	const root = process.cwd();
	for (const profile of profiles) {
		if (!profile.soulPath) continue;
		resolveInsideRoot(profile.soulPath, root, `profile ${profile.id} soulPath`);
	}
}

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

// Relay-served web capability tools (Hermes MCP tc_web_fetch / tc_web_search)
const WebConfigSchema = z.object({
	maxPerHourPerUser: z.number().int().positive().default(WEB_DEFAULTS.maxPerHourPerUser),
	maxPerDayPerUser: z.number().int().positive().default(WEB_DEFAULTS.maxPerDayPerUser),
});

// Security profile - determines which security layers are active
export const SecurityProfileSchema = z.enum(["simple", "strict", "test"]);
export type SecurityProfile = z.infer<typeof SecurityProfileSchema>;

// Security observer configuration
const ObserverConfigSchema = z.object({
	enabled: z.boolean().default(true),
	maxLatencyMs: z.number().int().positive().default(300000), // 5 minutes - Hermes calls can be slow
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
	/** DM pairing code configuration (Workstream W4). */
	pairing: z
		.object({
			/** Emit pairing codes to unknown private chats. Default: true. */
			enabled: z.boolean().default(true),
			/** Tier granted when a paired chat is approved. Default: READ_ONLY. */
			defaultTier: PermissionTierSchema.default("READ_ONLY"),
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

const TelegramNudgesConfigSchema = z.object({
	enabled: z.boolean().default(TELEGRAM_NUDGES_DEFAULTS.enabled),
	intervalSeconds: z.number().int().positive().default(TELEGRAM_NUDGES_DEFAULTS.intervalSeconds),
	quietHoursStart: z.number().int().min(0).max(23).optional(),
	quietHoursEnd: z.number().int().min(0).max(23).optional(),
	maxPerHour: z.number().int().positive().default(TELEGRAM_NUDGES_DEFAULTS.maxPerHour),
	digestIntervalHours: z.number().positive().default(TELEGRAM_NUDGES_DEFAULTS.digestIntervalHours),
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
	/** Proactive Telegram cards for auth expiry, approvals, failures, and periodic digest. */
	nudges: TelegramNudgesConfigSchema.optional(),
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
	/** Controls automatic heartbeats only. Manual social ask/run still work when enabled=true. */
	heartbeatEnabled: z.boolean().default(SOCIAL_SERVICE_DEFAULTS.heartbeatEnabled),
	heartbeatIntervalHours: z
		.number()
		.positive()
		.default(SOCIAL_SERVICE_DEFAULTS.heartbeatIntervalHours),
	adminChatId: z.union([z.string(), z.number()]).optional(),
	/** Enable skills for autonomous heartbeat activity (Phase 3 only). Default: false */
	enableSkills: z.boolean().default(false),
	/** Hermes social skill allowlist for trusted social activity. */
	allowedSkills: z.array(z.string()).optional(),
	/** When to send Telegram notifications on heartbeat. Default: "activity" */
	notifyOnHeartbeat: z.enum(["always", "activity", "never"]).default("activity"),
});

const CronConfigSchema = z.object({
	enabled: z.boolean().default(CRON_DEFAULTS.enabled),
	pollIntervalSeconds: z.number().int().positive().default(CRON_DEFAULTS.pollIntervalSeconds),
	timeoutSeconds: z.number().int().positive().default(CRON_DEFAULTS.timeoutSeconds),
});

/**
 * Local-only web dashboard (W15). Binds to 127.0.0.1 exclusively; TOTP-gated.
 * Disabled by default — opt-in via config.
 */
const DashboardConfigSchema = z.object({
	enabled: z.boolean().default(DASHBOARD_DEFAULTS.enabled),
	port: z.number().int().positive().default(DASHBOARD_DEFAULTS.port),
});

/**
 * Local-only signed webhook receiver. Binds to 127.0.0.1 exclusively; put
 * nginx/Caddy/Cloudflare Tunnel in front for TLS/public ingress.
 */
const WebhooksConfigSchema = z.object({
	enabled: z.boolean().default(WEBHOOKS_DEFAULTS.enabled),
	port: z.number().int().positive().default(WEBHOOKS_DEFAULTS.port),
	maxBodyBytes: z.number().int().positive().default(WEBHOOKS_DEFAULTS.maxBodyBytes),
	globalRateLimitPerHour: z
		.number()
		.int()
		.positive()
		.default(WEBHOOKS_DEFAULTS.globalRateLimitPerHour),
	defaultRateLimitPerHour: z
		.number()
		.int()
		.positive()
		.default(WEBHOOKS_DEFAULTS.defaultRateLimitPerHour),
	/** Per source+slug hourly cap before secret lookup/HMAC verification. */
	unauthenticatedRateLimitPerHour: z
		.number()
		.int()
		.positive()
		.default(WEBHOOKS_DEFAULTS.unauthenticatedRateLimitPerHour),
	/**
	 * Immediate proxy hops whose X-Forwarded-For headers Fastify may trust.
	 * Leave empty to ignore X-Forwarded-For entirely.
	 */
	trustedProxies: z.array(z.string().min(1)).default(WEBHOOKS_DEFAULTS.trustedProxies),
	/** Additional accepted Host header names for reverse proxies that preserve public Host. */
	allowedHosts: z.array(z.string().min(1)).default(WEBHOOKS_DEFAULTS.allowedHosts),
});

// Main config schema
const TelclaudeConfigSchema = z.object({
	security: SecurityConfigSchema.default(SECURITY_DEFAULTS),
	telegram: TelegramConfigSchema.default(TELEGRAM_DEFAULTS),
	inbound: InboundConfigSchema,
	logging: LoggingConfigSchema.default({}),
	hermes: HermesConfigSchema.default(HERMES_DEFAULTS),
	// Multimedia capabilities
	openai: OpenAIConfigSchema.default({}),
	transcription: TranscriptionConfigSchema.default(TRANSCRIPTION_DEFAULTS),
	imageGeneration: ImageGenerationConfigSchema.default(IMAGE_GENERATION_DEFAULTS),
	videoProcessing: VideoProcessingConfigSchema.default(VIDEO_PROCESSING_DEFAULTS),
	tts: TTSConfigSchema.default(TTS_DEFAULTS),
	// URL content extraction / summarization
	summarize: SummarizeConfigSchema.default(SUMMARIZE_DEFAULTS),
	// Relay-served web fetch/search rate limits
	web: WebConfigSchema.default(WEB_DEFAULTS),
	// External providers (sidecars) - optional
	providers: z.array(ExternalProviderSchema).default([]),
	// Generic social services (replaces per-service top-level keys)
	socialServices: z.array(SocialServiceConfigSchema).default([]),
	// Private Telegram operator profiles. Social services remain a separate trust boundary.
	profiles: z
		.array(OperatorProfileConfigSchema)
		.default([])
		.superRefine((profiles, ctx) => {
			const seenProfiles = new Set<string>();
			const seenBindingIds = new Set<string>();
			const seenAddresses = new Set<string>();
			const seenSubjects = new Set<string>();
			for (const [index, profile] of profiles.entries()) {
				if (seenProfiles.has(profile.id)) {
					ctx.addIssue({
						code: z.ZodIssueCode.custom,
						path: [index, "id"],
						message: `duplicate profile id: ${profile.id}`,
					});
				}
				seenProfiles.add(profile.id);
				for (const [bindingIndex, binding] of (profile.whatsappHouseholdBindings ?? []).entries()) {
					for (const [seen, value, label, field] of [
						[seenBindingIds, binding.bindingId, "binding id", "bindingId"],
						[seenAddresses, binding.address, "WhatsApp address", "address"],
						[seenSubjects, binding.subjectUserId, "subject", "subjectUserId"],
					] as const) {
						if (seen.has(value)) {
							ctx.addIssue({
								code: z.ZodIssueCode.custom,
								path: [index, "whatsappHouseholdBindings", bindingIndex, field],
								message: `duplicate household ${label}: ${value}`,
							});
						}
						seen.add(value);
					}
				}
			}
		}),
	householdReminders: z.object({ enabled: z.boolean().default(false) }).default({ enabled: false }),
	householdMedia: z
		.object({
			enabled: z.boolean().default(false),
			dataControlAck: HouseholdDataControlAckSchema.optional(),
		})
		.default({ enabled: false }),
	householdEmergency: z.object({ enabled: z.boolean().default(false) }).default({ enabled: false }),
	householdRollout: z
		.object({ rung: HouseholdRolloutRungSchema.default("shadow") })
		.default({ rung: "shadow" }),
	householdMetrics: z
		.object({
			enabled: z.boolean().default(false),
			dailyDigest: z
				.object({
					enabled: z.boolean().default(false),
					atHour: z.number().int().min(0).max(23).default(8),
				})
				.default({ enabled: false, atHour: 8 }),
		})
		.default({ enabled: false, dailyDigest: { enabled: false, atHour: 8 } }),
	cron: CronConfigSchema.default(CRON_DEFAULTS),
	dashboard: DashboardConfigSchema.default(DASHBOARD_DEFAULTS),
	webhooks: WebhooksConfigSchema.default(WEBHOOKS_DEFAULTS),
});

export type TelclaudeConfig = z.infer<typeof TelclaudeConfigSchema>;
export type HouseholdRolloutRung = (typeof HOUSEHOLD_ROLLOUT_RUNGS)[number];
export type ReplyConfig = z.infer<typeof ReplyConfigSchema>;
export type SessionConfig = z.infer<typeof SessionConfigSchema>;
export type SecurityConfig = z.infer<typeof SecurityConfigSchema>;
export type NetworkConfig = z.infer<typeof NetworkConfigSchema>;
export type ExternalProviderConfig = z.infer<typeof ExternalProviderSchema>;
export type TelegramConfig = z.infer<typeof TelegramConfigSchema>;
export type HermesConfig = z.infer<typeof HermesConfigSchema>;
export type OperatorProfileConfig = z.infer<typeof OperatorProfileConfigSchema>;
export type SocialServiceConfig = z.infer<typeof SocialServiceConfigSchema>;
export type CronConfig = z.infer<typeof CronConfigSchema>;
export type DashboardConfig = z.infer<typeof DashboardConfigSchema>;
export type WebhooksConfig = z.infer<typeof WebhooksConfigSchema>;
export type OpenAIConfig = z.infer<typeof OpenAIConfigSchema>;
export type TranscriptionConfig = z.infer<typeof TranscriptionConfigSchema>;
export type ImageGenerationConfig = z.infer<typeof ImageGenerationConfigSchema>;
export type VideoProcessingConfig = z.infer<typeof VideoProcessingConfigSchema>;
export type TTSConfig = z.infer<typeof TTSConfigSchema>;
export type SummarizeConfig = z.infer<typeof SummarizeConfigSchema>;
export type WebConfig = z.infer<typeof WebConfigSchema>;

let cachedConfig: TelclaudeConfig | null = null;
let configMtime: number | null = null;
let runtimeMtime: number | null = null;
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
	const runtimeConfigPath = resolveRuntimeConfigPath(configPath);
	const privateConfigPath = process.env.TELCLAUDE_PRIVATE_CONFIG;

	try {
		const stat = safeStat(configPath);
		const rStat = safeStat(runtimeConfigPath);
		const pStat = privateConfigPath ? safeStat(privateConfigPath) : null;

		// Invalidate cache if any file changed
		if (
			cachedConfig &&
			cachedConfigPath === configPath &&
			configMtime === (stat?.mtimeMs ?? null) &&
			runtimeMtime === (rStat?.mtimeMs ?? null) &&
			privateMtime === (pStat?.mtimeMs ?? null)
		) {
			return cachedConfig;
		}

		let parsed: Record<string, unknown> = {};
		if (stat) {
			const raw = fs.readFileSync(configPath, "utf-8");
			parsed = JSON5.parse(raw) as Record<string, unknown>;
		}

		if (rStat) {
			try {
				const runtimeRaw = fs.readFileSync(runtimeConfigPath, "utf-8");
				const runtimeParsed = JSON5.parse(runtimeRaw) as Record<string, unknown>;
				parsed = deepMerge(parsed, runtimeParsed);
			} catch {
				if (process.env.TELCLAUDE_LOG_LEVEL === "debug") {
					console.debug(`[config] failed to read runtime config: ${runtimeConfigPath}`);
				}
			}
		}

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
		validateProfileSoulPaths(validated.profiles);

		cachedConfig = validated;
		configMtime = stat?.mtimeMs ?? null;
		runtimeMtime = rStat?.mtimeMs ?? null;
		privateMtime = pStat?.mtimeMs ?? null;
		cachedConfigPath = configPath;

		return validated;
	} catch (err) {
		const code = (err as NodeJS.ErrnoException).code;
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
	runtimeMtime = null;
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
			hermes: {
				privateRuntime: {
					providerScopes: [],
					capabilityScopes: [...HERMES_DEFAULTS.privateRuntime.capabilityScopes],
					outboundChannels: [...HERMES_DEFAULTS.privateRuntime.outboundChannels],
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
			profiles: [],
			cron: CRON_DEFAULTS,
			webhooks: WEBHOOKS_DEFAULTS,
		};

		await fs.promises.writeFile(configPath, JSON.stringify(defaultConfig, null, 2), {
			encoding: "utf-8",
			mode: 0o600, // SECURITY: Owner read/write only
		});
		return true;
	}
}
