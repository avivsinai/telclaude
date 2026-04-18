/**
 * Claude Agent SDK layer for telclaude.
 *
 * Provides a typed interface to the Claude Agent SDK with:
 * - Session pooling with resume for multi-turn conversations
 * - Tier-aligned sandbox configurations
 * - Security enforcement via PreToolUse hooks (PRIMARY) and canUseTool (FALLBACK)
 *
 * IMPORTANT: Security enforcement uses PreToolUse hooks as PRIMARY enforcement.
 * The canUseTool callback is a FALLBACK only - it only runs when the SDK would prompt.
 * In acceptEdits/auto-approve modes, it won't run for auto-approved tool calls.
 * See: https://code.claude.com/docs/en/sdk/sdk-permissions
 *
 * Hook response format (per https://docs.claude.com/en/docs/claude-code/hooks):
 * { hookSpecificOutput: { permissionDecision: "deny", permissionDecisionReason: "..." } }
 */

import fs from "node:fs";
import {
	type HookCallback,
	type HookCallbackMatcher,
	type HookInput,
	type OutputFormat,
	type PermissionMode,
	query,
	type SDKMessage,
	type Options as SDKOptions,
	type SdkBeta,
} from "@anthropic-ai/claude-agent-sdk";
import {
	type ExternalProviderConfig,
	loadConfig,
	type PermissionTier,
	type PrivateEndpoint,
} from "../config/config.js";
import { buildInternalAuthHeaders } from "../internal-auth.js";
import { getChildLogger } from "../logging.js";
import { materializeClaudeProjectMemory } from "../memory/materialize.js";
import { buildAllowedDomainNames, domainMatchesPattern } from "../sandbox/domains.js";
import { shouldEnableSdkSandbox } from "../sandbox/mode.js";
import { checkPrivateNetworkAccess } from "../sandbox/network-proxy.js";
import { buildSdkPermissionsForTier } from "../sandbox/sdk-settings.js";
import { redactSecrets } from "../security/output-filter.js";
import { containsBlockedCommand, TIER_TOOLS } from "../security/permissions.js";
import {
	isAssistantMessage,
	isBashInput,
	isContentBlockStopEvent,
	isEditInput,
	isInputJsonDeltaEvent,
	isResultMessage,
	isStreamEvent,
	isTextDeltaEvent,
	isToolResultMessage,
	isToolUseStartEvent,
	isWriteInput,
} from "./message-guards.js";
import {
	buildOverflowRecoverySummary,
	DEFAULT_MAX_TOOL_RESULT_CHARS,
	guardToolResultOutput,
	isContextOverflowError,
} from "./output-guard.js";
import { executeWithSession, getSessionManager } from "./session-manager.js";
import { getUrlPortNumber, validateToolPath } from "./tool-validation.js";

const logger = getChildLogger({ module: "sdk-client" });

/**
 * Timeout for PreToolUse hooks in seconds.
 * Set to 10s to allow for DNS lookups (3s timeout) + validation overhead.
 */
const HOOK_TIMEOUT_SECONDS = 10;

function isSocialContext(actorUserId?: string): boolean {
	return actorUserId?.startsWith("social:") ?? false;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Security Helpers
// ═══════════════════════════════════════════════════════════════════════════════

const TOOL_INPUT_LOG_LIMIT = 200;

function formatToolInputForLog(input: unknown, limit = TOOL_INPUT_LOG_LIMIT): string {
	let serialized: string;
	try {
		serialized = JSON.stringify(input);
	} catch {
		serialized = String(input);
	}
	const redacted = redactSecrets(serialized);
	return redacted.length > limit ? `${redacted.slice(0, limit)}...` : redacted;
}

function redactForLog(value: string): string {
	return redactSecrets(value);
}

function isWritableDir(dirPath: string): boolean {
	try {
		fs.accessSync(dirPath, fs.constants.W_OK);
		return true;
	} catch {
		return false;
	}
}

/**
 * Options for SDK queries.
 */
export type TelclaudeQueryOptions = {
	/** Working directory for the query. Tools operate relative to this path. */
	cwd: string;

	/** Permission tier controlling which tools are available. */
	tier: PermissionTier;

	/** Request-scoped user identifier for rate limiting (e.g., Telegram chat/user ID). */
	userId?: string;

	/** Resume a previous session by ID for conversation continuity. */
	resumeSessionId?: string;

	/** Custom system prompt to append to the default claude_code preset. */
	systemPromptAppend?: string;

	/** Override the model (defaults to SDK's default model). */
	model?: string;

	/** Maximum conversation turns before stopping. */
	maxTurns?: number;

	/** Include streaming partial messages for real-time text updates. */
	includePartialMessages?: boolean;

	/** Permission mode override. */
	permissionMode?: PermissionMode;

	/** Enable skills loading from project's .claude/skills directory. */
	enableSkills?: boolean;

	/** When set, only these skills can be invoked via the Skill tool. Requires enableSkills: true.
	 * Empty array [] means deny ALL skills.
	 * SOCIAL tier: required when enableSkills is true (fail-closed if omitted).
	 * Other tiers: omitting allows all skills (private agents are trusted). */
	allowedSkills?: string[];

	/** Pre-minted session token for relay capabilities (request-scoped, NOT from process.env). */
	sessionToken?: string;

	/** Abort controller for external cancellation. */
	abortController?: AbortController;

	/** Timeout in milliseconds. Query aborts if exceeded. */
	timeoutMs?: number;

	/** Optional beta features to enable (e.g., 1M context window). */
	betas?: SdkBeta[];

	/** Structured output format (JSON Schema). Agent returns validated data instead of free-form text. */
	outputFormat?: OutputFormat;

	/** Native/dev fallback credentials.
	 * Docker deployments must keep raw credentials inside the relay and use
	 * the git proxy / HTTP credential proxy instead of sandbox env injection. */
	exposedCredentials?: ExposedCredentials;

	/** Relay-compiled memory snapshot for Claude's local working-memory file. */
	compiledMemoryMd?: string;
};

/**
 * Native/dev fallback credentials.
 * Narrow type — avoids turning the relay→agent payload into arbitrary env injection.
 */
export type ExposedCredentials = {
	githubToken?: string;
	openaiApiKey?: string;
};

/**
 * Result of a completed query.
 */
export type QueryResult = {
	response: string;
	success: boolean;
	error?: string;
	costUsd: number;
	numTurns: number;
	durationMs: number;
	structuredOutput?: unknown;
};

/**
 * Streaming chunk from the SDK.
 */
export type StreamChunk =
	| { type: "text"; content: string }
	| { type: "tool_use"; toolName: string; input: unknown }
	| { type: "tool_result"; toolName: string; output: unknown }
	| { type: "done"; result: QueryResult };

// ═══════════════════════════════════════════════════════════════════════════════
// PreToolUse Hook for Network Security
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Helper to create a deny response in the correct hook format.
 * Per https://docs.claude.com/en/docs/claude-code/hooks:
 * "Use hookSpecificOutput.permissionDecision instead of deprecated decision field."
 * The hookEventName field is required by the SDK types.
 */
function denyHookResponse(reason: string) {
	return {
		hookSpecificOutput: {
			hookEventName: "PreToolUse" as const,
			permissionDecision: "deny" as const,
			permissionDecisionReason: reason,
		},
	};
}

/**
 * Helper to create an allow response in the correct hook format.
 */
function allowHookResponse(updatedInput?: Record<string, unknown>) {
	return {
		hookSpecificOutput: {
			hookEventName: "PreToolUse" as const,
			permissionDecision: "allow" as const,
			...(updatedInput ? { updatedInput } : {}),
		},
	};
}

function matchProviderForUrl(
	url: URL,
	providers: ExternalProviderConfig[],
): ExternalProviderConfig | null {
	for (const provider of providers) {
		try {
			const base = new URL(provider.baseUrl);
			if (base.hostname === url.hostname && getUrlPortNumber(base) === getUrlPortNumber(url)) {
				return provider;
			}
		} catch {
			logger.warn({ provider: provider.id }, "invalid provider baseUrl");
		}
	}
	return null;
}

function isRelayAttachmentEndpoint(url: URL): boolean {
	const capabilitiesUrl = process.env.TELCLAUDE_CAPABILITIES_URL;
	if (!capabilitiesUrl) return false;
	try {
		const relayUrl = new URL(capabilitiesUrl);
		return (
			url.protocol === relayUrl.protocol &&
			url.hostname === relayUrl.hostname &&
			getUrlPortNumber(url) === getUrlPortNumber(relayUrl)
		);
	} catch {
		return false;
	}
}

function normalizeRequestBody(body: unknown): { body?: string; error?: string } {
	if (body === undefined || body === null) {
		return { error: "Missing request body." };
	}
	if (typeof body === "string") {
		return { body };
	}
	try {
		return { body: JSON.stringify(body) };
	} catch {
		return { error: "Unable to serialize request body." };
	}
}

function hasHeader(headers: Record<string, string>, name: string): boolean {
	const target = name.toLowerCase();
	return Object.keys(headers).some((key) => key.toLowerCase() === target);
}

const ALLOWED_RELAY_PATHS = new Set(["/v1/attachment/fetch", "/v1/attachment/deliver"]);

function buildRelayAttachmentRequest(
	toolInput: { method?: string; headers?: Record<string, string>; body?: unknown },
	url: URL,
	actorUserId?: string,
): { updatedInput?: Record<string, unknown>; error?: string } {
	if (actorUserId?.startsWith("social:")) {
		return { error: "Relay attachment endpoints are not available in Social context." };
	}
	if (!ALLOWED_RELAY_PATHS.has(url.pathname)) {
		return { error: "Only attachment endpoints allowed on relay." };
	}

	const method = toolInput.method?.toUpperCase();
	if (method && method !== "POST") {
		return { error: "Relay attachment endpoints require POST." };
	}

	const normalizedBody = normalizeRequestBody(toolInput.body);
	if (normalizedBody.error || normalizedBody.body === undefined) {
		return { error: normalizedBody.error ?? "Invalid request body." };
	}

	let headers = { ...(toolInput.headers ?? {}) };
	if (!hasHeader(headers, "content-type")) {
		headers["Content-Type"] = "application/json";
	}

	try {
		const path = `${url.pathname}${url.search}`;
		const authHeaders = buildInternalAuthHeaders("POST", path, normalizedBody.body, {
			scope: "telegram",
		});
		headers = { ...headers, ...authHeaders };
	} catch {
		return { error: "Relay attachment fetch is not configured." };
	}

	return {
		updatedInput: {
			...toolInput,
			method: "POST",
			headers,
			body: normalizedBody.body,
		},
	};
}

/**
 * Create a PreToolUse hook that blocks WebFetch to private networks and metadata endpoints.
 *
 * CRITICAL: PreToolUse hooks run UNCONDITIONALLY before every tool use.
 * Unlike canUseTool (which only runs when a permission prompt would appear), PreToolUse hooks
 * are guaranteed to run. This is the PRIMARY enforcement mechanism.
 * See: https://code.claude.com/docs/en/sdk/sdk-permissions
 *
 * SECURITY ALGORITHM (per Gemini 2.5 Pro review):
 * 1. Check for non-overridable blocks (metadata, link-local) - ALWAYS blocked
 * 2. For private IPs, check against privateEndpoints allowlist with port enforcement
 * 3. For public domains, check against domain allowlist (in strict mode)
 *
 * NOTE: WebSearch is NOT filtered - it uses server-side requests by Anthropic.
 */
function createNetworkSecurityHook(
	isPermissiveMode: boolean,
	allowedDomains: string[],
	privateEndpoints: PrivateEndpoint[],
	providers: ExternalProviderConfig[],
	actorUserId?: string,
): HookCallbackMatcher {
	const socialContext = isSocialContext(actorUserId);
	const effectivePrivateEndpoints = socialContext ? [] : privateEndpoints;
	const effectiveProviders = socialContext ? [] : providers;

	const hookCallback: HookCallback = async (input: HookInput) => {
		if (input.hook_event_name !== "PreToolUse") {
			return allowHookResponse();
		}

		const toolName = input.tool_name;
		if (toolName !== "WebFetch") {
			return allowHookResponse();
		}

		const toolInput = input.tool_input as {
			url?: string;
			method?: string;
			headers?: Record<string, string>;
			body?: unknown;
		};
		if (!toolInput.url) {
			return allowHookResponse();
		}

		try {
			const url = new URL(toolInput.url);
			const providerMatch = matchProviderForUrl(url, effectiveProviders);

			// DEBUG: Log WebFetch interception
			logger.debug(
				{
					url: toolInput.url,
					hostname: url.hostname,
					port: url.port,
					providerMatch: providerMatch?.id ?? null,
					providersCount: effectiveProviders.length,
					actorUserId: actorUserId ?? null,
				},
				"[hook] WebFetch intercepted",
			);

			// Block non-HTTP protocols
			if (!["http:", "https:"].includes(url.protocol)) {
				logger.warn(
					{ url: redactForLog(toolInput.url), tool: toolName },
					"[hook] blocked non-HTTP protocol",
				);
				return denyHookResponse("Only HTTP/HTTPS protocols are allowed.");
			}

			// Relay attachment fetch (internal capabilities broker)
			if (isRelayAttachmentEndpoint(url)) {
				const relayRequest = buildRelayAttachmentRequest(toolInput, url, actorUserId);
				if (relayRequest.error) {
					logger.warn(
						{ url: url.pathname, error: relayRequest.error },
						"[hook] blocked relay attachment fetch",
					);
					return denyHookResponse(relayRequest.error);
				}
				logger.info({ url: url.pathname }, "[hook] injected auth for relay attachment fetch");
				return allowHookResponse(relayRequest.updatedInput ?? toolInput);
			}

			// Block direct WebFetch to configured provider endpoints (public or private).
			// Providers must be queried via `telclaude providers query` which routes through the relay.
			if (providerMatch) {
				logger.warn(
					{ provider: providerMatch.id, url: url.pathname },
					"[hook] blocked direct WebFetch to provider endpoint",
				);
				return denyHookResponse(
					`Provider endpoints must be queried via \`telclaude providers query\` (Bash), not WebFetch. Use: telclaude providers query ${providerMatch.id} <svc> <act>. If Bash is unavailable in your tier, ask the operator to run the query.`,
				);
			}

			const port = getUrlPortNumber(url);

			// Check private network access with allowlist and port enforcement
			const privateCheck = await checkPrivateNetworkAccess(
				url.hostname,
				port,
				effectivePrivateEndpoints,
			);

			if (!privateCheck.allowed) {
				logger.warn(
					{ host: url.hostname, port, tool: toolName, reason: privateCheck.reason },
					"[hook] blocked network access",
				);
				return denyHookResponse(privateCheck.reason || "Network access denied.");
			}

			// If it matched a private endpoint, allow it (port already checked)
			if (privateCheck.matchedEndpoint) {
				logger.debug(
					{
						host: url.hostname,
						port,
						endpoint: privateCheck.matchedEndpoint.label,
					},
					"[hook] allowed private endpoint access",
				);
				return allowHookResponse();
			}

			// For non-private addresses, check domain allowlist in strict mode
			if (!isPermissiveMode) {
				if (!allowedDomains.some((pattern) => domainMatchesPattern(url.hostname, pattern))) {
					logger.warn(
						{ host: url.hostname, tool: toolName },
						"[hook] blocked non-allowlisted domain",
					);
					return denyHookResponse(`Domain not in allowlist: ${url.hostname}`);
				}
			}

			return allowHookResponse();
		} catch {
			logger.warn({ url: redactForLog(toolInput.url), tool: toolName }, "[hook] invalid URL");
			return denyHookResponse("Invalid URL format.");
		}
	};

	return {
		matcher: "WebFetch",
		hooks: [hookCallback],
		timeout: HOOK_TIMEOUT_SECONDS,
	};
}

function createSocialToolRestrictionHook(actorUserId?: string): HookCallbackMatcher {
	const socialContext = isSocialContext(actorUserId);
	// DESIGN: The container IS the sandbox (read-only rootfs, AppArmor, no secrets mounted).
	// This hook provides defense-in-depth for two specific threats:
	// 1. Skill poisoning (untrusted input writes to skills, later executed in trusted context)
	// 2. Bash in untrusted flows (regex-based command inspection is unwinnable against
	//    shell obfuscation — so we disable Bash entirely for untrusted actors instead)
	// File reads are NOT restricted — the container controls what paths exist.
	// See: docs/architecture.md "Trust Boundaries"

	// Trusted social actors that get full tool access (including Bash).
	// Untrusted actors (notifications) get no Bash at all.
	// This eliminates the entire class of skill-poisoning-via-Bash attacks without
	// playing regex whack-a-mole against shell obfuscation.
	const trustedActorSuffixes = [":operator", ":autonomous", ":proactive"];
	const isTrustedActor =
		actorUserId != null && trustedActorSuffixes.some((suffix) => actorUserId.endsWith(suffix));

	// Paths where writes are blocked via Write/Edit tools (all actors, trusted or not)
	const writeProtectedPaths = [
		/\/home\/telclaude-skills(?:\/|$)/i, // skill poisoning: write skill → trusted loads it
		/\/home\/telclaude-auth(?:\/|$)/i, // auth tokens (not mounted, but explicit)
		/\/social\/memory(?:\/|$)/i, // memory integrity (container has :ro, belt-and-suspenders)
	];

	const isWriteProtected = (filePath: string): boolean =>
		writeProtectedPaths.some((pattern) => pattern.test(filePath));

	const hookCallback: HookCallback = async (input: HookInput) => {
		if (input.hook_event_name !== "PreToolUse") {
			return allowHookResponse();
		}

		if (!socialContext) {
			return allowHookResponse();
		}

		const toolName = input.tool_name;
		const toolInput = input.tool_input as Record<string, unknown>;

		// Block tools that have no legitimate social use
		if (toolName === "NotebookEdit") {
			logger.warn({ toolName, actorUserId: actorUserId ?? null }, "[hook] blocked social tool");
			return denyHookResponse(`Social context: ${toolName} is not permitted.`);
		}

		// Bash: only allowed for trusted actors (operator, autonomous, proactive).
		// Untrusted actors (notifications) don't get Bash — notification content
		// could inject shell commands, and regex inspection can't stop obfuscation.
		if (toolName === "Bash" && !isTrustedActor) {
			logger.warn(
				{ actorUserId: actorUserId ?? null },
				"[hook] blocked Bash for untrusted social actor",
			);
			return denyHookResponse(
				"Social context: Bash is not available for this operation. Use file tools or WebFetch instead.",
			);
		}

		// Write/Edit: block writes to protected paths (all actors, even trusted)
		if (toolName === "Write" && isWriteInput(toolInput) && isWriteProtected(toolInput.file_path)) {
			logger.warn(
				{ path: redactForLog(toolInput.file_path), actorUserId: actorUserId ?? null },
				"[hook] blocked social write to protected path",
			);
			return denyHookResponse("Social context: writing to this location is not permitted.");
		}
		if (toolName === "Edit" && isEditInput(toolInput) && isWriteProtected(toolInput.file_path)) {
			logger.warn(
				{ path: redactForLog(toolInput.file_path), actorUserId: actorUserId ?? null },
				"[hook] blocked social edit of protected path",
			);
			return denyHookResponse("Social context: editing this file is not permitted.");
		}

		// All other tools: allow (container isolation is the boundary)
		return allowHookResponse();
	};

	return {
		hooks: [hookCallback],
		timeout: HOOK_TIMEOUT_SECONDS,
	};
}

/**
 * Patterns matching active skill directories (Write/Edit blocked).
 * Agent can write to .claude/skills-draft/ but NOT .claude/skills/.
 */
const ACTIVE_SKILL_WRITE_PATTERNS: RegExp[] = [
	/(?:^|[/\\])\.claude[/\\]skills[/\\]/i,
	...(process.env.CLAUDE_CONFIG_DIR
		? [
				new RegExp(
					`^${process.env.CLAUDE_CONFIG_DIR.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?:[/\\\\])skills(?:[/\\\\])`,
					"i",
				),
			]
		: []),
];

/**
 * Check if a path is an active skill directory (NOT skills-draft).
 * Returns true if writes should be blocked.
 *
 * Uses explicit path segment matching to prevent bypass via names like
 * "skills/skills-draft-evil/" which would contain "skills-draft" as substring.
 */
function isActiveSkillPath(filePath: string): boolean {
	// Normalize to forward slashes for consistent matching
	const normalized = filePath.replace(/\\/g, "/");

	// Allow writes to an actual skills-draft/ directory (exact segment match)
	if (/(?:^|[/])\.claude\/skills-draft\//.test(normalized)) return false;
	if (
		process.env.CLAUDE_CONFIG_DIR &&
		normalized.startsWith(`${process.env.CLAUDE_CONFIG_DIR.replace(/\\/g, "/")}/skills-draft/`)
	)
		return false;

	return ACTIVE_SKILL_WRITE_PATTERNS.some((p) => p.test(filePath));
}

/**
 * Create a PreToolUse hook that blocks writes to active skill directories.
 * Agents can only write to .claude/skills-draft/<name>/; promotion is operator-only.
 */
function createSkillWriteProtectionHook(): HookCallbackMatcher {
	const hookCallback: HookCallback = async (input: HookInput) => {
		if (input.hook_event_name !== "PreToolUse") {
			return allowHookResponse();
		}

		const toolName = input.tool_name;
		const toolInput = input.tool_input as Record<string, unknown>;

		// Only check Write and Edit tools
		if (toolName === "Write" && isWriteInput(toolInput)) {
			if (isActiveSkillPath(toolInput.file_path)) {
				logger.warn(
					{ path: toolInput.file_path },
					"[hook] blocked write to active skill directory",
				);
				return denyHookResponse(
					"Cannot write to active skill directory. Use .claude/skills-draft/<name>/ instead, then ask the operator to promote with /promote-skill.",
				);
			}
		}

		if (toolName === "Edit" && isEditInput(toolInput)) {
			if (isActiveSkillPath(toolInput.file_path)) {
				logger.warn({ path: toolInput.file_path }, "[hook] blocked edit of active skill file");
				return denyHookResponse(
					"Cannot edit active skill files. Draft changes to .claude/skills-draft/<name>/ instead.",
				);
			}
		}

		return allowHookResponse();
	};

	return {
		hooks: [hookCallback],
		timeout: HOOK_TIMEOUT_SECONDS,
	};
}

/**
 * Recognized keys that may carry the skill name in Skill tool input.
 * The SDK's Skill tool input schema uses "skill" but other keys are checked defensively.
 */
const SKILL_NAME_KEYS = ["skill", "name", "command"] as const;

/**
 * Extract skill name from Skill tool input.
 * Checks multiple key candidates since the SDK's Skill tool input schema could vary.
 *
 * SECURITY: If multiple keys carry different values, returns null (fail-closed).
 * This prevents bypass via conflicting keys (e.g. {skill: "memory", command: "external-provider"})
 * where enforcement validates one field but runtime execution uses another.
 *
 * Returns null if skill name cannot be determined or keys conflict (caller should deny).
 */
function extractSkillName(toolInput: Record<string, unknown>): string | null {
	let found: string | null = null;
	for (const key of SKILL_NAME_KEYS) {
		const value = toolInput[key];
		if (typeof value === "string" && value.length > 0) {
			if (found !== null && value !== found) {
				// Conflicting skill names across keys — fail-closed
				logger.warn(
					{ keys: { [key]: value, previous: found } },
					"[hook] conflicting skill name keys detected — denying",
				);
				return null;
			}
			found = value;
		}
	}
	return found;
}

/**
 * Create a PreToolUse hook that restricts which skills can be invoked.
 *
 * FAIL-CLOSED: If tool_input shape is unexpected or skill name can't be extracted, DENY.
 * Empty allowedSkills [] = deny ALL skills (not allow all).
 */
function createSkillAllowlistHook(allowedSkills: string[]): HookCallbackMatcher {
	const allowSet = new Set(allowedSkills);

	const hookCallback: HookCallback = async (input: HookInput) => {
		if (input.hook_event_name !== "PreToolUse") {
			return allowHookResponse();
		}

		if (input.tool_name !== "Skill") {
			return allowHookResponse();
		}

		const toolInput = input.tool_input as Record<string, unknown>;
		const skillName = extractSkillName(toolInput);

		if (!skillName) {
			logger.warn(
				{ toolInput: formatToolInputForLog(toolInput) },
				"[hook] denied Skill: could not extract skill name (fail-closed)",
			);
			return denyHookResponse(
				"Skill invocation denied: could not determine skill name from input.",
			);
		}

		if (!allowSet.has(skillName)) {
			logger.warn(
				{ skill: skillName, allowed: allowedSkills },
				"[hook] denied Skill: not in allowedSkills",
			);
			return denyHookResponse(
				`Skill "${skillName}" is not in the allowedSkills list for this service.`,
			);
		}

		return allowHookResponse();
	};

	return {
		matcher: "Skill",
		hooks: [hookCallback],
		timeout: HOOK_TIMEOUT_SECONDS,
	};
}

/**
 * Create a PreToolUse hook for sensitive path protection on filesystem tools.
 *
 * CRITICAL: This is the PRIMARY enforcement for sensitive path blocking.
 * The canUseTool callback only runs when a permission prompt would appear, so PreToolUse
 * hooks are required for guaranteed enforcement.
 * See: https://code.claude.com/docs/en/sdk/sdk-permissions
 */
function createSensitivePathHook(tier: PermissionTier): HookCallbackMatcher {
	const hookCallback: HookCallback = async (input: HookInput) => {
		if (input.hook_event_name !== "PreToolUse") {
			return allowHookResponse();
		}

		const toolName = input.tool_name;
		const toolInput = input.tool_input as Record<string, unknown>;

		// Unified path validation (shared with canUseTool fallback)
		const pathResult = validateToolPath(toolName, toolInput);
		if (pathResult.denied) {
			logger.warn(
				{ toolName, input: formatToolInputForLog(toolInput) },
				`[hook] blocked: ${pathResult.reason}`,
			);
			return denyHookResponse(pathResult.reason);
		}

		// Tier-specific: WRITE_LOCAL blocked commands (Bash only)
		if (toolName === "Bash" && tier === "WRITE_LOCAL" && isBashInput(toolInput)) {
			const blocked = containsBlockedCommand(toolInput.command);
			if (blocked) {
				logger.warn(
					{ command: redactForLog(toolInput.command), blocked },
					"[hook] blocked dangerous command",
				);
				return denyHookResponse(`Command contains blocked operation: ${blocked}`);
			}
		}

		return allowHookResponse();
	};

	// No matcher specified = runs for ALL tools. The callback filters by tool name internally.
	return {
		hooks: [hookCallback],
		timeout: HOOK_TIMEOUT_SECONDS,
	};
}

/**
 * Build SDK options based on tier and configuration.
 *
 * Sandbox mode detection:
 * - Docker: SDK sandbox DISABLED. Docker container provides isolation.
 * - Native: SDK sandbox ENABLED. bubblewrap (Linux) or Seatbelt (macOS).
 */
export async function buildSdkOptions(opts: TelclaudeQueryOptions): Promise<SDKOptions> {
	if (opts.compiledMemoryMd) {
		try {
			materializeClaudeProjectMemory(opts.cwd, opts.compiledMemoryMd);
		} catch (error) {
			logger.warn({ error: String(error) }, "failed to materialize compiled Claude memory");
		}
	}

	// Create abort controller with timeout if specified
	let abortController = opts.abortController;
	if (opts.timeoutMs && !abortController) {
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), opts.timeoutMs);
		controller.signal.addEventListener(
			"abort",
			() => {
				clearTimeout(timeoutId);
			},
			{ once: true },
		);
		abortController = controller;
	}

	const config = loadConfig();
	const sandboxEnabled = shouldEnableSdkSandbox();

	// Environment handling for SDK spawn process
	//
	// IMPORTANT: When sandbox is enabled, do NOT pass custom `env` option to SDK.
	// The SDK sandbox handles environment isolation internally, and passing
	// a custom env causes the spawn process to hang. Instead, set variables in
	// process.env before calling the SDK - the sandbox inherits from process.env.
	//
	// In Docker mode (sandbox disabled), pass explicit env to control what
	// variables the spawned process sees.
	let sandboxEnv: Record<string, string> | undefined;

	if (sandboxEnabled) {
		// Native mode: Don't pass custom env (causes hang with sandbox.enabled).
		// User ID for rate limiting is passed via system prompt below instead of
		// env var to avoid race conditions with concurrent requests.
		// OPENAI_API_KEY and GITHUB_TOKEN should already be in process.env.
		//
		// Session token: In native mode we must use process.env since there's no
		// sandboxEnv to inject into (SDK hangs with custom env + sandbox.enabled).
		// KNOWN LIMITATION: Under concurrent requests in native mode, there is a
		// race window between this set and the SDK subprocess spawn. This is an
		// inherent SDK constraint — the production Docker path uses per-request
		// sandboxEnv and is fully race-free. Native mode is dev/test only.
		// Always set-or-delete to prevent stale tokens from prior requests.
		if (opts.sessionToken) {
			process.env.TELCLAUDE_SESSION_TOKEN = opts.sessionToken;
		} else {
			delete process.env.TELCLAUDE_SESSION_TOKEN;
		}
	} else {
		// Docker mode: Pass explicit env since container provides isolation
		// Use cwd as HOME when actual HOME is read-only (e.g., social agent's HOME=/social)
		// This ensures tools like agent-browser can create temp files
		const effectiveHome = isWritableDir(process.env.HOME ?? "")
			? (process.env.HOME ?? "")
			: opts.cwd;
		sandboxEnv = {
			HOME: effectiveHome,
			USER: process.env.USER ?? "",
			PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
			SHELL: process.env.SHELL ?? "/bin/sh",
			TERM: process.env.TERM ?? "xterm-256color",
			LANG: process.env.LANG ?? "en_US.UTF-8",
		};

		if (opts.userId) {
			sandboxEnv.TELCLAUDE_REQUEST_USER_ID = opts.userId;
		}

		// Pass relay capability config for image/TTS/transcription commands
		// These are needed by `telclaude generate-image` etc. when run via Bash
		if (process.env.TELCLAUDE_CAPABILITIES_URL) {
			sandboxEnv.TELCLAUDE_CAPABILITIES_URL = process.env.TELCLAUDE_CAPABILITIES_URL;
		}
		// Subprocess gets relay public key (for verification) but NOT agent private key.
		// Auth to relay is via TELCLAUDE_SESSION_TOKEN (passed below), not raw private key.
		const relayPublicKey = process.env.TELEGRAM_RPC_RELAY_PUBLIC_KEY;
		if (relayPublicKey) {
			sandboxEnv.TELEGRAM_RPC_RELAY_PUBLIC_KEY = relayPublicKey;
		}
		// Pass relay-minted session token to Claude subprocess (request-scoped via opts).
		// This allows telclaude CLI tools to authenticate to the relay without the private key.
		if (opts.sessionToken) {
			sandboxEnv.TELCLAUDE_SESSION_TOKEN = opts.sessionToken;
		}
		// Credential proxy URL — agents route OpenAI/media API calls through relay proxy
		if (process.env.TELCLAUDE_CREDENTIAL_PROXY_URL) {
			sandboxEnv.TELCLAUDE_CREDENTIAL_PROXY_URL = process.env.TELCLAUDE_CREDENTIAL_PROXY_URL;
		}
		// Media directories for generated content
		if (process.env.TELCLAUDE_MEDIA_INBOX_DIR) {
			sandboxEnv.TELCLAUDE_MEDIA_INBOX_DIR = process.env.TELCLAUDE_MEDIA_INBOX_DIR;
		}
		if (process.env.TELCLAUDE_MEDIA_OUTBOX_DIR) {
			sandboxEnv.TELCLAUDE_MEDIA_OUTBOX_DIR = process.env.TELCLAUDE_MEDIA_OUTBOX_DIR;
		}

		// Claude SDK needs CLAUDE_CONFIG_DIR to discover user-level skills and CLAUDE.md
		if (process.env.CLAUDE_CONFIG_DIR) {
			sandboxEnv.CLAUDE_CONFIG_DIR = process.env.CLAUDE_CONFIG_DIR;
		}
		// Playwright browsers path for agent-browser headless automation
		if (process.env.PLAYWRIGHT_BROWSERS_PATH) {
			sandboxEnv.PLAYWRIGHT_BROWSERS_PATH = process.env.PLAYWRIGHT_BROWSERS_PATH;
		}

		// Anthropic proxy config — SDK process needs these to route API calls through relay
		if (process.env.ANTHROPIC_BASE_URL) {
			sandboxEnv.ANTHROPIC_BASE_URL = process.env.ANTHROPIC_BASE_URL;
		}
		if (process.env.ANTHROPIC_AUTH_TOKEN) {
			sandboxEnv.ANTHROPIC_AUTH_TOKEN = process.env.ANTHROPIC_AUTH_TOKEN;
		}
	}

	const sdkOpts: SDKOptions = {
		cwd: opts.cwd,
		model: opts.model,
		maxTurns: opts.maxTurns,
		includePartialMessages: opts.includePartialMessages,
		abortController,
		resume: opts.resumeSessionId,
		// Only pass env in Docker mode (when sandboxEnv is defined)
		// In native mode, let SDK use process.env and handle sandbox env internally
		...(sandboxEnv && { env: sandboxEnv }),
		...(opts.outputFormat && { outputFormat: opts.outputFormat }),
	};

	// Check if permissive network mode is enabled (affects WebFetch/WebSearch via canUseTool)
	// Social agents that need public browsing must opt in via TELCLAUDE_NETWORK_MODE=permissive
	// on their container — the SDK no longer unconditionally forces permissive for social contexts.
	// RFC1918/metadata blocks still apply unconditionally in the network hook.
	const envNetworkMode = process.env.TELCLAUDE_NETWORK_MODE?.toLowerCase();
	const isPermissiveMode = envNetworkMode === "open" || envNetworkMode === "permissive";

	// Build permissions (filesystem only - network handled by canUseTool and SDK sandbox)
	const additionalDomains = config.security?.network?.additionalDomains ?? [];
	const privateEndpoints = config.security?.network?.privateEndpoints ?? [];
	const permissions = buildSdkPermissionsForTier(opts.tier);
	sdkOpts.extraArgs = {
		...sdkOpts.extraArgs,
		settings: JSON.stringify({ permissions }),
	};

	// Build allowed domains for network filtering
	const allowedDomains = buildAllowedDomainNames(additionalDomains);

	// Sandbox configuration based on environment:
	// - Docker: SDK sandbox DISABLED (container provides isolation)
	// - Native: SDK sandbox ENABLED (bubblewrap/Seatbelt)
	if (sandboxEnabled) {
		logger.debug("native mode: enabling SDK sandbox");
		sdkOpts.sandbox = {
			enabled: true,
			allowUnsandboxedCommands: false,
			network: {
				allowedDomains,
			},
		};
	} else {
		logger.debug("docker mode: SDK sandbox disabled (container provides isolation)");
		sdkOpts.sandbox = {
			enabled: false,
		};
	}

	// CRITICAL: PreToolUse hooks are the PRIMARY enforcement mechanism.
	// They run UNCONDITIONALLY before every tool use, even in acceptEdits mode.
	// Unlike canUseTool (which only runs when a permission prompt would appear), these are guaranteed.
	// See: https://code.claude.com/docs/en/sdk/sdk-permissions
	const preToolUseHooks: HookCallbackMatcher[] = [
		createNetworkSecurityHook(
			isPermissiveMode,
			allowedDomains,
			privateEndpoints,
			config.providers ?? [],
			opts.userId,
		),
		createSocialToolRestrictionHook(opts.userId),
		createSensitivePathHook(opts.tier),
		createSkillWriteProtectionHook(),
	];

	// Skill allowlist enforcement:
	// - When allowedSkills is set: only listed skills can be invoked
	// - SOCIAL tier with enableSkills but no allowedSkills: fail-closed (deny all)
	// - Other tiers without allowedSkills: no restriction (private agent is trusted)
	if (opts.allowedSkills) {
		preToolUseHooks.push(createSkillAllowlistHook(opts.allowedSkills));
	} else if (opts.tier === "SOCIAL" && opts.enableSkills) {
		// SOCIAL tier must explicitly declare which skills are allowed.
		// Fail-closed: deny all skills rather than allowing everything.
		// Keyed on tier (not userId prefix) so this fires even if userId is missing.
		logger.warn(
			{ userId: opts.userId },
			"SOCIAL tier has enableSkills=true but no allowedSkills — denying all skills",
		);
		preToolUseHooks.push(createSkillAllowlistHook([]));
	}

	sdkOpts.hooks = {
		PreToolUse: preToolUseHooks,
	};

	// Configure tools based on tier
	if (opts.tier === "FULL_ACCESS") {
		sdkOpts.permissionMode = opts.permissionMode ?? "acceptEdits";
		sdkOpts.allowDangerouslySkipPermissions = false;
	} else {
		const tierTools = TIER_TOOLS[opts.tier];
		const effectiveTools = opts.enableSkills ? [...tierTools, "Skill"] : tierTools;
		sdkOpts.tools = effectiveTools;
		sdkOpts.allowedTools = effectiveTools;
		sdkOpts.permissionMode = opts.permissionMode ?? "acceptEdits";
	}
	// Opt-in beta headers
	if (opts.betas?.length) {
		sdkOpts.betas = opts.betas;
	}

	// FALLBACK: canUseTool only runs when a permission prompt would appear.
	// PRIMARY enforcement is via PreToolUse hooks above.
	// This is belt-and-suspenders for cases where hooks might not run.
	// See: https://code.claude.com/docs/en/sdk/sdk-permissions
	sdkOpts.canUseTool = async (toolName, input) => {
		logger.debug(
			{ toolName, input: formatToolInputForLog(input) },
			"canUseTool invoked (fallback)",
		);

		// Defense-in-depth: skill allowlist check (PRIMARY enforcement is PreToolUse hook above)
		// SOCIAL tier without allowedSkills also fails closed here.
		if (toolName === "Skill") {
			const effectiveAllowedSkills =
				opts.allowedSkills ?? (opts.tier === "SOCIAL" && opts.enableSkills ? [] : null);
			if (effectiveAllowedSkills !== null) {
				const skillName = extractSkillName(input as Record<string, unknown>);
				if (!skillName || !effectiveAllowedSkills.includes(skillName)) {
					logger.warn(
						{ skill: skillName ?? "unknown" },
						"blocked Skill not in allowedSkills (canUseTool fallback)",
					);
					return {
						behavior: "deny",
						message: `Skill "${skillName ?? "unknown"}" is not in the allowedSkills list for this service.`,
					};
				}
			}
		}

		// Unified path validation (shared with PreToolUse hook)
		const pathResult = validateToolPath(toolName, input as Record<string, unknown>);
		if (pathResult.denied) {
			logger.warn(
				{ toolName, input: formatToolInputForLog(input) },
				`blocked (canUseTool fallback): ${pathResult.reason}`,
			);
			return {
				behavior: "deny",
				message: pathResult.reason,
			};
		}

		// Tier-specific: WRITE_LOCAL blocked commands (Bash only)
		if (toolName === "Bash" && opts.tier === "WRITE_LOCAL" && isBashInput(input)) {
			const blocked = containsBlockedCommand(input.command);
			if (blocked) {
				logger.warn(
					{ command: redactForLog(input.command), blocked },
					"blocked dangerous bash command",
				);
				return {
					behavior: "deny",
					message: `Command contains blocked operation: ${blocked}`,
				};
			}
		}

		// Belt-and-suspenders: Application-layer network check for WebFetch/WebSearch
		// PRIMARY enforcement is via PreToolUse hook (runs unconditionally).
		// This canUseTool check is a FALLBACK for cases where the hook might not run.
		if (toolName === "WebFetch") {
			const webInput = input as { url?: string };
			if (webInput.url) {
				try {
					const url = new URL(webInput.url);

					// Block non-HTTP protocols (prevent file:// access)
					if (!["http:", "https:"].includes(url.protocol)) {
						logger.warn(
							{ url: redactForLog(webInput.url) },
							"blocked non-HTTP protocol in WebFetch",
						);
						return {
							behavior: "deny",
							message: "Only HTTP/HTTPS protocols are allowed.",
						};
					}

					const port = getUrlPortNumber(url);

					// Check private network access with allowlist and port enforcement
					const privateCheck = await checkPrivateNetworkAccess(
						url.hostname,
						port,
						privateEndpoints,
					);

					if (!privateCheck.allowed) {
						logger.warn(
							{ host: url.hostname, port, reason: privateCheck.reason },
							"blocked network access in WebFetch (canUseTool fallback)",
						);
						return {
							behavior: "deny",
							message: privateCheck.reason || "Network access denied.",
						};
					}

					// If matched a private endpoint, allow it (port already checked)
					if (privateCheck.matchedEndpoint) {
						logger.debug(
							{
								host: url.hostname,
								port,
								endpoint: privateCheck.matchedEndpoint.label,
							},
							"allowed private endpoint access in WebFetch (canUseTool fallback)",
						);
						return { behavior: "allow", updatedInput: input };
					}

					// Check domain allowlist (belt-and-suspenders with SDK sandbox)
					// In permissive mode, skip allowlist check - only block private/metadata above
					if (
						!isPermissiveMode &&
						!allowedDomains.some((pattern) => domainMatchesPattern(url.hostname, pattern))
					) {
						logger.warn({ host: url.hostname }, "blocked non-allowlisted domain in WebFetch");
						return {
							behavior: "deny",
							message: `Domain not in allowlist: ${url.hostname}`,
						};
					}
				} catch {
					logger.warn({ url: redactForLog(webInput.url) }, "invalid URL in WebFetch");
					return {
						behavior: "deny",
						message: "Invalid URL format.",
					};
				}
			}
		}

		// NOTE: WebSearch is NOT filtered because:
		// - WebSearch uses `query` parameter, not `url` - our URL checks would never match
		// - Search requests are made server-side by Anthropic, not by the local process
		// - We cannot control which domains Anthropic's search service accesses

		return { behavior: "allow", updatedInput: input };
	};

	// SECURITY: Always project-only. Loading "user" settings would allow a pre-seeded
	// settings.json in CLAUDE_CONFIG_DIR to set disableAllHooks: true, bypassing
	// PreToolUse security hooks. Skills are discovered via CLAUDE_CONFIG_DIR/skills/
	// which the SDK loads regardless of settingSources when enableSkills is true.
	sdkOpts.settingSources = ["project"];

	// System prompt configuration
	// Include user ID in system prompt for skills that need to make authenticated API calls
	// (can't use env var due to SDK hang with custom env + sandbox.enabled)
	let systemPromptAppend = opts.systemPromptAppend ?? "";
	if (opts.userId) {
		const userIdLine = `\n\n<request-context user-id="${opts.userId}" />`;
		systemPromptAppend = systemPromptAppend + userIdLine;
		logger.info({ userId: opts.userId }, "appending request-context to system prompt");
	} else {
		logger.warn("no userId provided, request-context will not be appended");
	}
	if (systemPromptAppend) {
		sdkOpts.systemPrompt = {
			type: "preset",
			preset: "claude_code",
			append: systemPromptAppend,
		};
	}

	return sdkOpts;
}

// NOTE: applyTierSandboxConfig() was removed - SDK sandbox handles all sandboxing now
// We pass allowedDomains to SDK via sdkOpts.sandbox.network.allowedDomains in buildSdkOptions()

/**
 * Shared stream processing for SDK query iterables.
 *
 * Both executeQueryStream and executePooledQuery use the same message
 * processing logic. This helper extracts it to avoid duplication.
 */
async function* processMessageStream(
	iterable: AsyncIterable<SDKMessage>,
	options: {
		startTime: number;
		label: string;
		/** When true, also extract tool_use blocks from assistant messages (pooled mode). */
		extractToolUseFromAssistant?: boolean;
		/** Called on non-success result messages for extra logging. */
		onFailure?: (
			error: string | undefined,
			costUsd: number,
			numTurns: number,
			durationMs: number,
		) => void;
		/** Maximum chars per tool result (default: DEFAULT_MAX_TOOL_RESULT_CHARS). */
		maxToolResultChars?: number;
		/** Pool key for session management (used in overflow recovery). */
		poolKey?: string;
	},
): AsyncGenerator<StreamChunk, void, unknown> {
	let response = "";
	let assistantMessageFallback = "";
	let costUsd = 0;
	let numTurns = 0;
	let durationMs = 0;
	let currentToolUse: { name: string; input: unknown; inputJson: string } | null = null;
	let lastToolUseName: string | null = null;

	try {
		for await (const msg of iterable) {
			if (isStreamEvent(msg)) {
				const event = msg.event;
				if (isTextDeltaEvent(event)) {
					yield { type: "text", content: event.delta.text };
					response += event.delta.text;
				} else if (isToolUseStartEvent(event)) {
					const cb = (event as unknown as { content_block: { name: string; input?: unknown } })
						.content_block;
					currentToolUse = {
						name: cb.name,
						input: cb.input ?? {},
						inputJson: "",
					};
				} else if (isInputJsonDeltaEvent(event) && currentToolUse) {
					currentToolUse.inputJson += event.delta.partial_json;
				} else if (isContentBlockStopEvent(event) && currentToolUse) {
					let input = currentToolUse.input;
					if (currentToolUse.inputJson) {
						try {
							input = JSON.parse(currentToolUse.inputJson);
						} catch {
							input = currentToolUse.inputJson;
						}
					}
					lastToolUseName = currentToolUse.name;
					yield { type: "tool_use", toolName: currentToolUse.name, input };
					currentToolUse = null;
				}
			} else if (isAssistantMessage(msg)) {
				for (const block of msg.message.content) {
					if (options.extractToolUseFromAssistant && block.type === "tool_use") {
						lastToolUseName = block.name;
						yield { type: "tool_use", toolName: block.name, input: block.input };
					} else if (block.type === "text") {
						assistantMessageFallback += block.text;
					}
				}
			} else if (isToolResultMessage(msg)) {
				// Apply output size guard to tool results before they accumulate
				const maxChars = options.maxToolResultChars ?? DEFAULT_MAX_TOOL_RESULT_CHARS;
				const guarded = guardToolResultOutput(msg.tool_use_result, maxChars);
				yield {
					type: "tool_result",
					toolName: lastToolUseName ?? "unknown",
					output: guarded.output,
				};
				lastToolUseName = null;
			} else if (isResultMessage(msg)) {
				costUsd = msg.total_cost_usd;
				numTurns = msg.num_turns;
				durationMs = msg.duration_ms;

				const success = msg.subtype === "success";
				const error = !success && "errors" in msg ? msg.errors.join("; ") : undefined;

				if (!success && options.onFailure) {
					options.onFailure(error, costUsd, numTurns, durationMs);
				}

				const finalResponse = response || assistantMessageFallback;
				if (!response && assistantMessageFallback) {
					logger.debug(
						{ streamedLength: response.length, fallbackLength: assistantMessageFallback.length },
						"using assistant message fallback",
					);
					yield { type: "text", content: assistantMessageFallback };
				}

				yield {
					type: "done",
					result: {
						response: finalResponse,
						success,
						error,
						costUsd,
						numTurns,
						durationMs,
						...("structured_output" in msg &&
							msg.structured_output !== undefined && {
								structuredOutput: msg.structured_output,
							}),
					},
				};
			}
		}
	} catch (err) {
		const isAborted =
			(err instanceof Error && err.name === "AbortError") ||
			String(err).includes("aborted by user");
		const isOverflow = !isAborted && isContextOverflowError(err);

		if (isAborted) {
			logger.warn({ durationMs: Date.now() - options.startTime }, `${options.label} aborted`);
		} else if (isOverflow) {
			logger.error(
				{
					error: String(err),
					numTurns,
					poolKey: options.poolKey,
				},
				`${options.label} context overflow detected`,
			);
		} else {
			logger.error({ error: String(err) }, `${options.label} error`);
		}

		// Clear session on terminal errors (abort, overflow) where the session
		// is definitely dead. Transient errors (network hiccups, etc.) should NOT
		// clear the session — it may still be valid for resume on the next turn.
		if ((isAborted || isOverflow) && options.poolKey) {
			const sessionManager = getSessionManager();
			sessionManager.clearSession(options.poolKey);
			logger.info(
				{ poolKey: options.poolKey, isAborted, isOverflow },
				"session cleared after terminal error",
			);
		}

		const finalResponse = response || assistantMessageFallback;
		const errorMsg = isAborted
			? "Request was aborted"
			: isOverflow
				? buildOverflowRecoverySummary({
						poolKey: options.poolKey,
						error: String(err),
						numTurns,
					})
				: String(err);

		yield {
			type: "done",
			result: {
				response: finalResponse,
				success: false,
				error: errorMsg,
				costUsd,
				numTurns,
				durationMs: Date.now() - options.startTime,
			},
		};
	}
}

/**
 * Execute a query with streaming, yielding chunks as they arrive.
 */
export async function* executeQueryStream(
	prompt: string,
	inputOpts: TelclaudeQueryOptions,
): AsyncGenerator<StreamChunk, void, unknown> {
	const startTime = Date.now();

	const sdkOpts = await buildSdkOptions({
		...inputOpts,
		includePartialMessages: true,
	});

	logger.debug(
		{
			tier: inputOpts.tier,
			cwd: inputOpts.cwd,
			allowedTools: sdkOpts.allowedTools,
		},
		"executing streaming SDK query",
	);

	yield* processMessageStream(query({ prompt, options: sdkOpts }), {
		startTime,
		label: "SDK streaming query",
	});
}

// ═══════════════════════════════════════════════════════════════════════════════
// Session Pool API
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Options for pooled queries.
 */
export type PooledQueryOptions = TelclaudeQueryOptions & {
	poolKey: string;
};

/**
 * Execute a query using the session pool with resume support.
 */
export async function* executePooledQuery(
	prompt: string,
	inputOpts: PooledQueryOptions,
): AsyncGenerator<StreamChunk, void, unknown> {
	const startTime = Date.now();

	const sdkOpts = await buildSdkOptions({
		...inputOpts,
		includePartialMessages: true,
	});

	logger.debug(
		{
			tier: inputOpts.tier,
			poolKey: inputOpts.poolKey,
			cwd: inputOpts.cwd,
		},
		"executing pooled SDK query",
	);

	const sessionManager = getSessionManager();
	const iterable = executeWithSession(sessionManager, inputOpts.poolKey, prompt, sdkOpts);

	yield* processMessageStream(iterable, {
		startTime,
		label: "pooled query",
		extractToolUseFromAssistant: true,
		poolKey: inputOpts.poolKey,
		onFailure: (error, costUsd, numTurns, durationMs) => {
			logger.error(
				{
					requestError: error,
					costUsd,
					numTurns,
					durationMs,
					poolKey: inputOpts.poolKey,
				},
				"SDK result message reported failure",
			);
		},
	});
}
