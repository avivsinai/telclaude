import crypto from "node:crypto";

import type { MemoryEntryInput } from "./store.js";
import { validateMemoryEntryInput } from "./validation.js";

type ExtractorPattern = {
	category: MemoryEntryInput["category"];
	pattern: RegExp;
	prefix?: string;
	maxLength?: number;
};

const EXPLICIT_PATTERNS: ExtractorPattern[] = [
	{
		category: "meta",
		pattern: /\b(?:please\s+)?(?:remember|note)\s+(?:that\s+)?([^.!?\n]{4,160})/i,
		maxLength: 160,
	},
	{
		category: "threads",
		pattern:
			/\b(?:i am working on|i'm working on|we are working on|we're working on)\s+([^.!?\n]{4,140})/i,
		prefix: "Working on",
		maxLength: 140,
	},
	{
		category: "interests",
		pattern: /\b(?:i prefer|i like|i love|i enjoy)\s+([^.!?\n]{3,100})/i,
		prefix: "Prefers",
		maxLength: 100,
	},
	{
		category: "meta",
		pattern: /\b(?:my timezone is|i'm in timezone|i am in timezone)\s+([^.!?\n]{3,60})/i,
		prefix: "Timezone",
		maxLength: 60,
	},
];

function normalizeValue(value: string, maxLength: number): string {
	const normalized = value.replace(/\s+/g, " ").trim();
	if (normalized.length <= maxLength) {
		return normalized;
	}
	return `${normalized.slice(0, maxLength - 1).trimEnd()}…`;
}

function buildEntryId(
	chatId: string,
	category: MemoryEntryInput["category"],
	content: string,
): string {
	const hash = crypto.createHash("sha1").update(`${chatId}:${category}:${content}`).digest("hex");
	return `auto-${category}-${hash.slice(0, 16)}`;
}

export function extractExplicitMemoryEntries(
	text: string,
	options: { chatId: string },
): MemoryEntryInput[] {
	const sourceText = text.trim();
	if (!sourceText) return [];

	const entries: MemoryEntryInput[] = [];
	for (const rule of EXPLICIT_PATTERNS) {
		const match = sourceText.match(rule.pattern);
		if (!match?.[1]) continue;

		const value = normalizeValue(match[1], rule.maxLength ?? 120);
		if (!value) continue;
		const content = rule.prefix ? `${rule.prefix}: ${value}` : value;
		const entry: MemoryEntryInput = {
			id: buildEntryId(options.chatId, rule.category, content),
			category: rule.category,
			content,
			chatId: options.chatId,
			metadata: {
				capture: "auto-explicit",
				source: "telegram-turn",
			},
		};
		if (!validateMemoryEntryInput(entry)) {
			entries.push(entry);
		}
	}

	return entries;
}
