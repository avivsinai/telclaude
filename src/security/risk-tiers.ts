/**
 * Risk classification for tool calls and graduated approvals (W1).
 *
 * Three tiers (orthogonal to PermissionTier):
 * - low: read-only tools (Read/Glob/Grep/WebFetch-allowlisted/WebSearch)
 * - medium: Write/Edit, Bash (non-destructive), Skill calls
 * - high: destructive Bash, FULL_ACCESS ops, cross-persona queries,
 *         network egress to private endpoints
 *
 * The classifier is intentionally conservative: when unsure, return the
 * *higher* tier. High-risk actions never upgrade to "always" — enforced at
 * the allowlist layer before the scope is persisted.
 */

import type { PermissionTier } from "../config/config.js";

export type RiskTier = "low" | "medium" | "high";

// Destructive/irreversible bash patterns. Expanded from existing fast-path
// patterns — the security-pipeline classifier consults this list to decide
// whether a Bash-tagged request can ever be upgraded to "always".
const DESTRUCTIVE_BASH_PATTERNS: RegExp[] = [
	/\brm\s+-[a-z]*r[a-z]*f\b/i,
	/\brm\s+-[a-z]*f[a-z]*r\b/i,
	/\brm\s+-rf\s+[~/]/i,
	/\bchmod\s+[0-7]*7[0-7]{2}\b/i,
	/\bchown\s+/i,
	/\bmkfs\b/i,
	/\bdd\s+if=/i,
	/\bshred\b/i,
	/\bgit\s+push\s+--force\b/i,
	/\bgit\s+push\s+-f\b/i,
	/\bgit\s+reset\s+--hard\b/i,
	/\bgit\s+clean\s+-[a-z]*f/i,
	/\bsudo\b/i,
	/\bsu\s+-\b/i,
	/\bpkexec\b/i,
	/\b>\s*\/(etc|usr|var|boot|sys|proc)\b/i,
	/\bcurl\s+[^|]+\|\s*(sh|bash|zsh)\b/i,
	/\bwget\s+[^|]+\|\s*(sh|bash|zsh)\b/i,
	/\b(npm|pnpm|yarn)\s+publish\b/i,
	/\bdocker\s+(rm|rmi)\s+-f\b/i,
	/\bkill\s+-9\s+1\b/i,
	/\brebase\b.*-i\b/i,
];

/**
 * Tools whose default risk is low (read-only surface).
 */
const LOW_RISK_TOOLS = new Set(["Read", "Glob", "Grep", "WebFetch", "WebSearch", "NotebookRead"]);

/**
 * Tools whose default risk is medium (write surface, can be capped to "always").
 */
const MEDIUM_RISK_TOOLS = new Set(["Write", "Edit", "NotebookEdit", "Skill", "Task", "TodoWrite"]);

/**
 * Tools that always start at high risk (explicit classification required).
 */
const HIGH_RISK_TOOLS = new Set(["cross_persona_query", "provider_query_action"]);

export type RiskClassificationInput = {
	toolName: string;
	/** Raw bash command string (only inspected for Bash/Shell tool names). */
	bashCommand?: string;
	/** Current permission tier — FULL_ACCESS forces at least medium. */
	permissionTier?: PermissionTier;
	/** Explicit escalation (e.g. provider-approval actions carry actionKind="action"). */
	actionKind?: "read" | "action";
};

/**
 * Classify a tool call into low/medium/high risk.
 *
 * The pipeline uses this classification to:
 * 1. Auto-approve low-risk calls against the allowlist.
 * 2. Gate medium-risk calls behind a single approval (allowlist-aware).
 * 3. Force a fresh prompt for high-risk calls (always, even with "always" grant).
 */
export function classifyRisk(input: RiskClassificationInput): RiskTier {
	const { toolName, bashCommand, permissionTier, actionKind } = input;

	// Explicit escalations always win.
	if (actionKind === "action") {
		return "high";
	}
	if (HIGH_RISK_TOOLS.has(toolName)) {
		return "high";
	}

	// Bash is special-cased: inspect the command text.
	if (toolName === "Bash" || toolName === "Shell") {
		if (bashCommand && isDestructiveBash(bashCommand)) {
			return "high";
		}
		return "medium";
	}

	if (LOW_RISK_TOOLS.has(toolName)) {
		// FULL_ACCESS raises the floor — even a read in FULL_ACCESS tier
		// benefits from at least a medium approval path because FULL_ACCESS
		// implies the request itself is trusted beyond the tool default.
		if (permissionTier === "FULL_ACCESS") {
			return "medium";
		}
		return "low";
	}

	if (MEDIUM_RISK_TOOLS.has(toolName)) {
		return "medium";
	}

	// Unknown tool: conservatively medium. High is reserved for things
	// we can positively identify as destructive.
	return "medium";
}

/**
 * Check whether a raw bash command matches any destructive pattern.
 * Exported for tests and for integration in other tool-level guards.
 */
export function isDestructiveBash(command: string): boolean {
	if (!command) return false;
	for (const pattern of DESTRUCTIVE_BASH_PATTERNS) {
		if (pattern.test(command)) {
			return true;
		}
	}
	return false;
}

/**
 * Whether a tier cap permits the requested approval scope.
 *
 * Rules:
 * - High-risk actions can never be upgraded past "once".
 * - FULL_ACCESS "always" grants require an admin-claimed context; the pipeline
 *   should downgrade to "session" for non-admin FULL_ACCESS.
 * - SOCIAL / WRITE_LOCAL cannot escalate to FULL_ACCESS "always" — this is a
 *   defensive cap; callers must validate the *acting* tier matches the grant
 *   tier at lookup time.
 */
export function scopeAllowedForRisk(risk: RiskTier, scope: ApprovalScope): boolean {
	if (risk === "high") {
		return scope === "once";
	}
	return true;
}

export type ApprovalScope = "once" | "session" | "always";
export const APPROVAL_SCOPES: readonly ApprovalScope[] = ["once", "session", "always"] as const;

export function isApprovalScope(value: unknown): value is ApprovalScope {
	return value === "once" || value === "session" || value === "always";
}
