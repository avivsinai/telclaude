/**
 * Shared prompt injection detection patterns.
 *
 * Centralizes injection patterns used across multiple security modules:
 * - fast-path.ts (inbound message classification)
 * - external-content.ts (untrusted content scanning)
 * - skill-scanner.ts (skill file static analysis)
 *
 * This is the single source of truth for prompt injection detection.
 * Each module may use only a subset, but the patterns themselves live here.
 */

export type InjectionSeverity = "low" | "medium" | "high" | "critical";

export type PromptInjectionPattern = {
	name: string;
	regex: RegExp;
	severity: InjectionSeverity;
};

/**
 * Prompt injection patterns for detecting instruction override attempts,
 * tool manipulation, exfiltration, social engineering, and obfuscation.
 *
 * SECURITY: This is a superset of patterns from fast-path, external-content,
 * and skill-scanner. Any additions should be made here, not in individual modules.
 */
export const PROMPT_INJECTION_PATTERNS: PromptInjectionPattern[] = [
	// === Instruction override ===
	{
		name: "ignore-instructions",
		regex:
			/\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|above|prior|your)\s+(?:instructions|rules|guidelines|constraints)\b/gi,
		severity: "critical",
	},
	{
		name: "new-instructions",
		regex: /\b(?:new|updated|revised)\s+(?:system\s+)?(?:instructions|prompt|rules)\s*:/gi,
		severity: "critical",
	},
	{
		name: "identity-override",
		regex:
			/\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|your\s+new\s+(?:role|persona|identity))\b/gi,
		severity: "critical",
	},
	{
		name: "system-prompt-override",
		regex: /\b(?:system\s*:\s*|<system>|<<SYS>>|\[SYSTEM\])/gi,
		severity: "critical",
	},
	{
		name: "system-prompt-reveal",
		regex: /\b(?:reveal|show|display|print)\s+your\s+(?:system\s+)?prompt\b/gi,
		severity: "critical",
	},
	{
		name: "override-safety",
		regex: /\b(?:override\s+(?:your\s+)?(?:system|safety)\s+(?:prompt|instructions))\b/gi,
		severity: "critical",
	},

	// === Tool/action manipulation ===
	{
		name: "tool-invocation",
		regex: /\b(?:run|execute|call|use)\s+(?:the\s+)?(?:bash|shell|terminal|command|tool)\b/gi,
		severity: "high",
	},
	{
		name: "file-operations",
		regex: /\b(?:write|create|delete|modify|edit)\s+(?:the\s+)?(?:file|config|\.env|\.ssh)\b/gi,
		severity: "high",
	},
	{
		name: "code-execution",
		regex:
			/```(?:bash|sh|python|node|javascript)\s*\n[^`]*(?:curl|wget|rm|chmod|eval|exec)[^`]*```/gis,
		severity: "high",
	},

	// === Exfiltration attempts ===
	{
		name: "data-request",
		regex:
			/\b(?:send|post|upload|transmit)\s+(?:the\s+)?(?:api\s*key|token|secret|password|credential)\b/gi,
		severity: "critical",
	},
	{
		name: "url-injection",
		regex: /\b(?:fetch|visit|navigate|go\s+to|open)\s+(?:https?:\/\/)/gi,
		severity: "medium",
	},
	{
		name: "env-harvest",
		regex:
			/\b(?:show|print|display|output)\s+(?:your\s+)?(?:environment|env\s*vars?|process\.env|api\s*key|token)\b/gi,
		severity: "critical",
	},

	// === Social engineering ===
	{
		name: "urgency-pressure",
		regex:
			/\b(?:urgent|emergency|immediately|critical)\s*[!:]\s*(?:you\s+must|please\s+(?:do|run|execute))/gi,
		severity: "medium",
	},
	{
		name: "authority-claim",
		regex:
			/\b(?:I\s+am\s+(?:the\s+)?(?:admin|developer|owner|operator)|authorized\s+(?:by|to))\b/gi,
		severity: "high",
	},
	{
		name: "permission-claim",
		regex: /\b(?:you\s+(?:are|have)\s+(?:been\s+)?(?:authorized|permitted|allowed)\s+to)\b/gi,
		severity: "high",
	},

	// === Encoding/obfuscation ===
	{
		name: "base64-block",
		regex: /[A-Za-z0-9+/]{40,}={0,2}/g,
		severity: "low",
	},
	{
		name: "hex-block",
		regex: /(?:0x)?[0-9a-f]{40,}/gi,
		severity: "low",
	},
	{
		name: "unicode-escape",
		regex: /(?:\\u[0-9a-f]{4}){4,}/gi,
		severity: "medium",
	},

	// === Hidden content ===
	{
		name: "invisible-chars",
		regex: /(?:\u200B|\u200C|\u200D|\u2060|\uFEFF){2,}/g,
		severity: "high",
	},
	{
		name: "rtl-override",
		regex: /[\u202A-\u202E\u2066-\u2069]/g,
		severity: "high",
	},
];
