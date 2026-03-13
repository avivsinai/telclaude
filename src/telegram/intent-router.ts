/**
 * Natural Language Intent Router for Telegram Control Commands.
 *
 * Maps natural language messages to typed domain intents using a two-phase approach:
 * 1. Pattern matching (fast, no LLM) — conservative regex patterns for common phrases.
 * 2. Heuristic gate — if no pattern matches, checks whether the message looks like
 *    a potential control-plane intent (short, contains domain keywords, starts with
 *    an action verb). If it does, falls through to the existing system intent
 *    resolution. If not, returns the agent:freeform fallback.
 *
 * Integration point:
 *   In auto-reply.ts (or wherever inbound messages are dispatched), call:
 *     const intent = resolveIntent(text);
 *     if (intent && intent.domain !== 'agent') {
 *       const commandId = intentToCommandId(intent);
 *       // dispatch to the existing control command handler
 *     }
 *   The caller is responsible for dispatching — this module only classifies.
 */

import type { TelegramCommandId } from "./control-commands.js";

// ═══════════════════════════════════════════════════════════════════════════════
// Domain Intent Types
// ═══════════════════════════════════════════════════════════════════════════════

export type DomainIntent =
	// System
	| { domain: "system"; action: "status" }
	| { domain: "system"; action: "sessions" }
	| { domain: "system"; action: "cron" }
	| { domain: "system"; action: "ask"; question: string }
	// Identity
	| { domain: "me"; action: "show" }
	| { domain: "me"; action: "link"; code: string }
	| { domain: "me"; action: "unlink" }
	// Auth
	| { domain: "auth"; action: "setup" }
	| { domain: "auth"; action: "verify"; code: string }
	| { domain: "auth"; action: "logout" }
	| { domain: "auth"; action: "disable" }
	| { domain: "auth"; action: "skip" }
	// Social
	| { domain: "social"; action: "queue" }
	| { domain: "social"; action: "promote"; entryId: string }
	| { domain: "social"; action: "run"; serviceId?: string }
	| { domain: "social"; action: "log"; serviceId?: string; hours?: number }
	| { domain: "social"; action: "ask"; serviceId?: string; question: string }
	// Skills
	| { domain: "skills"; action: "drafts" }
	| { domain: "skills"; action: "promote"; name: string }
	| { domain: "skills"; action: "reload" }
	// Fast paths
	| { domain: "approval"; action: "approve"; nonce: string }
	| { domain: "approval"; action: "deny"; nonce?: string }
	| { domain: "session"; action: "reset" }
	// Fallback — pass to agent for open-ended handling
	| { domain: "agent"; action: "freeform"; text: string };

// ═══════════════════════════════════════════════════════════════════════════════
// Pattern Definitions
// ═══════════════════════════════════════════════════════════════════════════════

type PatternEntry = {
	patterns: RegExp[];
	intent: DomainIntent | ((match: RegExpMatchArray) => DomainIntent);
};

/**
 * Conservative patterns for unambiguous natural language → intent mapping.
 *
 * Design principles:
 * - False positives are worse than false negatives (user can always use /command).
 * - Patterns require clear action + domain signals together.
 * - Capture groups extract parameters where needed.
 */
const INTENT_PATTERNS: PatternEntry[] = [
	// ── Session ──────────────────────────────────────────────────────────────
	{
		patterns: [
			/^(?:reset|new|clear|start fresh|fresh) (?:the )?(?:session|conversation|chat|context)$/i,
			/^(?:start (?:a )?)?new (?:session|conversation|chat)$/i,
		],
		intent: { domain: "session", action: "reset" },
	},

	// ── System ───────────────────────────────────────────────────────────────
	{
		patterns: [
			/^(?:check|show|what(?:'s| is)) (?:the )?(?:system )?status$/i,
			/^(?:how(?:'s| is)) (?:the )?(?:system|bot|relay)(?: doing)?$/i,
			/^(?:system )?health(?: check)?$/i,
		],
		intent: { domain: "system", action: "status" },
	},
	{
		patterns: [
			/^(?:show|list|check) (?:the )?(?:active )?sessions?$/i,
			/^(?:what|any) (?:active )?sessions?/i,
		],
		intent: { domain: "system", action: "sessions" },
	},
	{
		patterns: [
			/^(?:show|list|check) (?:the )?(?:cron|scheduled) (?:jobs?|schedule|tasks?)$/i,
			/^(?:what|any) (?:cron )?(?:jobs?|scheduled tasks?)/i,
			/^(?:when(?:'s| is)) (?:the )?next (?:heartbeat|cron|run|job)$/i,
			/^cron (?:status|overview|state)$/i,
		],
		intent: { domain: "system", action: "cron" },
	},

	// ── Identity ─────────────────────────────────────────────────────────────
	{
		patterns: [
			/^who am i$/i,
			/^(?:show|check) (?:my )?identity$/i,
			/^(?:what(?:'s| is)) my (?:identity|link|user)$/i,
		],
		intent: { domain: "me", action: "show" },
	},
	{
		patterns: [/^(?:unlink|disconnect|remove (?:my )?link)$/i],
		intent: { domain: "me", action: "unlink" },
	},
	{
		patterns: [/^link (?:me (?:with|to) )?(\S+)$/i],
		intent: (m) => ({ domain: "me", action: "link", code: m[1] }),
	},

	// ── Social ───────────────────────────────────────────────────────────────
	{
		patterns: [
			/^(?:show|list|what(?:'s| is)) (?:the )?(?:pending|queued|queue)(?:\s+posts?)?$/i,
			/^(?:any )?pending (?:posts?|ideas?)$/i,
		],
		intent: { domain: "social", action: "queue" },
	},
	{
		patterns: [/^promote (?:post |entry |idea )?(\S+)$/i],
		intent: (m) => ({ domain: "social", action: "promote", entryId: m[1] }),
	},
	{
		patterns: [
			/^(?:run|start|trigger) (?:a )?(?:social )?heartbeat(?:\s+(\S+))?$/i,
			/^(?:post|publish) now(?:\s+(?:on|to)\s+(\S+))?$/i,
		],
		intent: (m) => ({ domain: "social", action: "run", serviceId: m[1] || undefined }),
	},
	{
		patterns: [
			/^(?:show|what(?:'s| is)) (?:the )?(?:public |social )?(?:activity )?log(?:\s+(\S+))?(?:\s+(\d+)\s*h(?:ours?)?)?$/i,
			/^(?:recent )?(?:public |social )?activity(?:\s+(\S+))?(?:\s+(\d+)\s*h(?:ours?)?)?$/i,
		],
		intent: (m) => ({
			domain: "social",
			action: "log",
			serviceId: m[1] || undefined,
			hours: m[2] ? Number.parseInt(m[2], 10) : undefined,
		}),
	},
	{
		patterns: [/^ask (?:the )?(?:public|social)(?: persona)?\s+(.+)$/i],
		intent: (m) => ({ domain: "social", action: "ask", question: m[1] }),
	},

	// ── Approvals ────────────────────────────────────────────────────────────
	{
		patterns: [/^(?:approve|accept|yes|ok|confirm)\s+(\S+)$/i],
		intent: (m) => ({ domain: "approval", action: "approve", nonce: m[1] }),
	},
	{
		patterns: [/^(?:deny|reject|no|decline)\s+(\S+)$/i],
		intent: (m) => ({ domain: "approval", action: "deny", nonce: m[1] }),
	},
	{
		patterns: [/^(?:deny|reject|no|decline)$/i],
		intent: { domain: "approval", action: "deny" },
	},

	// ── Auth ─────────────────────────────────────────────────────────────────
	{
		patterns: [/^(?:setup|enable|configure) (?:2fa|totp|two.?factor)$/i],
		intent: { domain: "auth", action: "setup" },
	},
	{
		patterns: [/^(?:verify|confirm) (?:2fa|totp|two.?factor)\s+(\d{6})$/i],
		intent: (m) => ({ domain: "auth", action: "verify", code: m[1] }),
	},
	{
		patterns: [/^(?:2fa |totp )?logout$/i, /^(?:end|invalidate) (?:2fa |totp |auth )?session$/i],
		intent: { domain: "auth", action: "logout" },
	},
	{
		patterns: [/^(?:disable|remove|turn off) (?:2fa|totp|two.?factor)$/i],
		intent: { domain: "auth", action: "disable" },
	},
	{
		patterns: [/^skip (?:2fa|totp|two.?factor)(?: setup)?$/i],
		intent: { domain: "auth", action: "skip" },
	},

	// ── Skills ───────────────────────────────────────────────────────────────
	{
		patterns: [
			/^(?:show|list) (?:the )?(?:draft |pending )?skills?$/i,
			/^(?:any )?draft skills?$/i,
		],
		intent: { domain: "skills", action: "drafts" },
	},
	{
		patterns: [/^promote skill (\S+)$/i],
		intent: (m) => ({ domain: "skills", action: "promote", name: m[1] }),
	},
	{
		patterns: [/^(?:reload|refresh) skills?$/i],
		intent: { domain: "skills", action: "reload" },
	},
];

// ═══════════════════════════════════════════════════════════════════════════════
// Heuristic Intent Detection
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Domain keywords that suggest a message is a control-plane intent rather than
 * a freeform chat message. Kept conservative to avoid false positives.
 */
const DOMAIN_KEYWORDS = new Set([
	"status",
	"pending",
	"approve",
	"deny",
	"heartbeat",
	"session",
	"sessions",
	"social",
	"auth",
	"2fa",
	"totp",
	"skills",
	"cron",
	"promote",
	"queue",
	"queued",
	"drafts",
	"link",
	"unlink",
	"whoami",
	"identity",
	"reload",
	"log",
	"activity",
	"public",
]);

const ACTION_VERBS = new Set([
	"show",
	"list",
	"check",
	"run",
	"start",
	"trigger",
	"reset",
	"clear",
	"promote",
	"approve",
	"deny",
	"setup",
	"enable",
	"disable",
	"verify",
	"reload",
	"refresh",
	"ask",
]);

const MAX_INTENT_WORDS = 50;

/**
 * Heuristic check for whether a message looks like it could be a control-plane
 * intent. Must pass at least two of three signals:
 * 1. Contains a domain keyword
 * 2. Is short (< MAX_INTENT_WORDS)
 * 3. Starts with an action verb
 */
function looksLikeIntent(text: string): boolean {
	const words = text.toLowerCase().split(/\s+/);
	if (words.length === 0) return false;

	let signals = 0;

	// Signal 1: contains a domain keyword
	if (words.some((word) => DOMAIN_KEYWORDS.has(word))) {
		signals++;
	}

	// Signal 2: short message
	if (words.length <= MAX_INTENT_WORDS) {
		signals++;
	}

	// Signal 3: starts with an action verb
	if (ACTION_VERBS.has(words[0])) {
		signals++;
	}

	return signals >= 2;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Intent Resolution
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Resolve a text message to a domain intent.
 *
 * Returns null if the text is definitely not a control intent (should go to
 * normal agent chat). Returns a DomainIntent if it matches a known pattern
 * or passes the heuristic gate.
 *
 * Phase 1: Try all regex patterns — fast, no LLM.
 * Phase 2: If no pattern matches and the heuristic gate passes, return
 *   a system:ask intent so the existing system resolution can handle it.
 *   If the heuristic gate fails, return null (go to agent).
 */
export function resolveIntent(text: string): DomainIntent | null {
	const trimmed = text.trim();
	if (!trimmed) return null;

	// Skip messages that start with / — those are already handled as commands
	if (trimmed.startsWith("/")) return null;

	// Phase 1: pattern matching
	for (const entry of INTENT_PATTERNS) {
		for (const pattern of entry.patterns) {
			const match = trimmed.match(pattern);
			if (match) {
				return typeof entry.intent === "function" ? entry.intent(match) : entry.intent;
			}
		}
	}

	// Phase 2: heuristic gate
	if (looksLikeIntent(trimmed)) {
		// This looks like it could be a control intent, but we couldn't match it
		// to a specific pattern. Return a system:ask intent so the existing
		// resolution logic (resolveTelegramSystemIntent) can try to handle it.
		return { domain: "system", action: "ask", question: trimmed };
	}

	// Definitely not a control intent — let the agent handle it
	return null;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Intent → Command ID Mapping
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Maps a DomainIntent to the corresponding TelegramCommandId, so the existing
 * dispatch logic (dispatchTelegramControlCommand) can handle it.
 *
 * Returns null for intents that don't map to a single command ID (e.g., system:ask
 * needs the system NL router, and agent:freeform goes to the agent).
 */
export function intentToCommandId(intent: DomainIntent): TelegramCommandId | null {
	switch (intent.domain) {
		case "system":
			switch (intent.action) {
				case "status":
					return "system";
				case "sessions":
					return "system:sessions";
				case "cron":
					return "system:cron";
				case "ask":
					return "system:ask";
			}
			break;
		case "me":
			switch (intent.action) {
				case "show":
					return "me";
				case "link":
					return "me:link";
				case "unlink":
					return "me:unlink";
			}
			break;
		case "auth":
			switch (intent.action) {
				case "setup":
					return "auth:setup";
				case "verify":
					return "auth:verify";
				case "logout":
					return "auth:logout";
				case "disable":
					return "auth:disable";
				case "skip":
					return "auth:skip";
			}
			break;
		case "social":
			switch (intent.action) {
				case "queue":
					return "social:queue";
				case "promote":
					return "social:promote";
				case "run":
					return "social:run";
				case "log":
					return "social:log";
				case "ask":
					return "social:ask";
			}
			break;
		case "skills":
			switch (intent.action) {
				case "drafts":
					return "skills:drafts";
				case "promote":
					return "skills:promote";
				case "reload":
					return "skills:reload";
			}
			break;
		case "approval":
			switch (intent.action) {
				case "approve":
					return "approve";
				case "deny":
					return "deny";
			}
			break;
		case "session":
			if (intent.action === "reset") return "new";
			break;
		case "agent":
			// Freeform messages go to the agent, not a command
			return null;
	}

	return null;
}

/**
 * Extracts the raw arguments string that should be passed to the command handler,
 * synthesized from the intent's parameters.
 *
 * For example, a social:promote intent with entryId "post_123" returns "post_123",
 * which is what the /promote handler expects as rawArgs.
 *
 * Returns undefined if the intent has no extra arguments beyond the command itself.
 */
export function intentToRawArgs(intent: DomainIntent): string | undefined {
	switch (intent.domain) {
		case "system":
			if (intent.action === "ask") return intent.question;
			return undefined;
		case "me":
			if (intent.action === "link") return intent.code;
			return undefined;
		case "auth":
			if (intent.action === "verify") return intent.code;
			return undefined;
		case "social":
			switch (intent.action) {
				case "promote":
					return intent.entryId;
				case "run":
					return intent.serviceId;
				case "log": {
					const parts: string[] = [];
					if (intent.serviceId) parts.push(intent.serviceId);
					if (intent.hours !== undefined) parts.push(String(intent.hours));
					return parts.length > 0 ? parts.join(" ") : undefined;
				}
				case "ask": {
					const parts: string[] = [];
					if (intent.serviceId) parts.push(intent.serviceId);
					parts.push(intent.question);
					return parts.join(" ");
				}
				default:
					return undefined;
			}
		case "skills":
			if (intent.action === "promote") return intent.name;
			return undefined;
		case "approval":
			if (intent.action === "approve") return intent.nonce;
			if (intent.action === "deny") return intent.nonce;
			return undefined;
		default:
			return undefined;
	}
}
