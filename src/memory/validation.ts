import { filterOutput, redactSecrets } from "../security/output-filter.js";
import type { MemoryEntryInput } from "./store.js";
import type { MemoryCategory, TrustLevel } from "./types.js";

const MAX_STRING_LENGTH = 500;
const MAX_ID_LENGTH = 128;
const MAX_METADATA_LENGTH = 1_000;

const FORBIDDEN_PATTERNS: RegExp[] = [
	/^(system|assistant|developer|user)\s*:/i,
	/\bignore\s+(all\s+)?previous\s+instructions?\b/i,
	/\bdisregard\s+(all\s+)?previous\s+instructions?\b/i,
	/\boverride\s+(the\s+)?(system|previous)\s+instructions?\b/i,
	/\{\{[^}]{1,200}\}\}/,
	/<script/i,
	/javascript:/i,
];

export const VALID_CATEGORIES: MemoryCategory[] = [
	"profile",
	"interests",
	"threads",
	"posts",
	"meta",
];
export const VALID_TRUST: TrustLevel[] = ["trusted", "quarantined", "untrusted"];
export const VALID_SOURCE_PATTERN = /^[a-z][a-z0-9_-]{0,63}$/;

export function isValidCategory(value: unknown): value is MemoryCategory {
	return typeof value === "string" && VALID_CATEGORIES.includes(value as MemoryCategory);
}

export function isValidTrust(value: unknown): value is TrustLevel {
	return typeof value === "string" && VALID_TRUST.includes(value as TrustLevel);
}

export function isValidSource(value: unknown): boolean {
	return typeof value === "string" && VALID_SOURCE_PATTERN.test(value);
}

export function checkForbiddenMemoryPatterns(value: string): string | null {
	const trimmed = value.trim();
	for (const pattern of FORBIDDEN_PATTERNS) {
		if (pattern.test(trimmed)) {
			return `Forbidden pattern detected (${pattern.source}).`;
		}
	}
	if (/<\/?[a-z][^>]*>/i.test(value)) {
		return "HTML/XML tags not allowed in memory entries.";
	}
	return null;
}

export function validateMemoryEntryInput(entry: MemoryEntryInput): string | null {
	if (!entry || typeof entry !== "object") {
		return "Invalid memory entry.";
	}
	if (typeof entry.id !== "string" || entry.id.trim().length === 0) {
		return "Entry id is required.";
	}
	const trimmedId = entry.id.trim();
	if (trimmedId.length > MAX_ID_LENGTH) {
		return "Entry id too long.";
	}
	if (!isValidCategory(entry.category)) {
		return "Invalid memory category.";
	}
	if (typeof entry.content !== "string" || entry.content.trim().length === 0) {
		return "Entry content is required.";
	}
	if (entry.content.length > MAX_STRING_LENGTH) {
		return "Entry content too long.";
	}
	const forbidden = checkForbiddenMemoryPatterns(entry.content);
	if (forbidden) {
		return forbidden;
	}
	const secretResult = filterOutput(entry.content);
	if (secretResult.blocked) {
		const names = secretResult.matches.map((m) => m.pattern).join(", ");
		return `Content rejected: potential secret detected (${names}).`;
	}
	if (entry.metadata !== undefined) {
		if (!entry.metadata || typeof entry.metadata !== "object" || Array.isArray(entry.metadata)) {
			return "Entry metadata must be an object.";
		}
		try {
			const serialized = JSON.stringify(entry.metadata);
			if (serialized.length > MAX_METADATA_LENGTH) {
				return "Entry metadata too long.";
			}
		} catch {
			return "Entry metadata must be JSON-serializable.";
		}
	}
	return null;
}

export function sanitizeEpisodeText(value: string, maxLength: number): string {
	const normalized = value.replace(/\s+/g, " ").trim();
	if (!normalized) {
		return "";
	}
	const secretSafe = redactSecrets(normalized);
	if (checkForbiddenMemoryPatterns(secretSafe)) {
		return "Instruction-like content omitted from episodic recall.";
	}
	if (secretSafe.length <= maxLength) {
		return secretSafe;
	}
	return `${secretSafe.slice(0, maxLength - 1).trimEnd()}…`;
}
