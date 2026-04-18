/**
 * Natural-language intent router for Telegram messages (W2).
 *
 * Resolves free-form text like "switch to sonnet" or "use haiku" to a
 * typed domain intent that auto-reply can dispatch to the same code paths
 * used by slash commands. This is deliberately small — only the intents
 * W2 needs. Future workstreams can add more intent kinds without changing
 * the resolver contract.
 */

import { resolveModelHint } from "../config/model-catalog.js";

export type TelegramIntent =
	| {
			kind: "open-model-picker";
			/** Pre-selected provider (e.g. anthropic) when user hinted a family. */
			providerHint?: string;
			/** Specific model id if the phrase named one concretely. */
			modelHint?: string;
	  }
	| {
			kind: "open-provider-list";
	  }
	| {
			kind: "open-skill-picker";
	  };

/**
 * Minimal stopword list — keep conservative. The goal is to strip "please"
 * and "the" without eating meaningful tokens like "to" out of "switch to X".
 */
const FILLER_WORDS = new Set(["please", "kindly", "the", "my", "default", "model"]);

function normalize(text: string): string {
	return text
		.toLowerCase()
		.replace(/[^a-z0-9\s-]+/g, " ")
		.replace(/\s+/g, " ")
		.trim();
}

function hasAny(body: string, phrases: string[]): boolean {
	return phrases.some((phrase) => body.includes(phrase));
}

function extractModelToken(body: string): string | null {
	// Strip filler words so "switch the model to sonnet" → "switch to sonnet".
	const tokens = body.split(" ").filter((token) => token.length > 0 && !FILLER_WORDS.has(token));
	const joined = tokens.join(" ");

	// Patterns we try in order. We capture everything after the marker up to
	// end-of-phrase punctuation so "switch to sonnet for now" also works.
	const patterns: RegExp[] = [
		/\bswitch\s+to\s+(.+)$/,
		/\buse\s+(?:the\s+)?(.+?)(?:\s+model)?$/,
		/\bmodel\s+(.+)$/,
		/\b(?:run|set)\s+(?:on\s+)?(.+)$/,
	];

	for (const pattern of patterns) {
		const match = joined.match(pattern);
		if (match?.[1]) {
			return match[1].trim();
		}
	}
	return null;
}

/**
 * Resolve a Telegram message body to a typed intent. Returns `null` when
 * nothing matches — caller should continue normal routing in that case.
 *
 * Only triggers on strong signals. Bare "sonnet" does NOT open the picker
 * on its own; the user must express switching intent.
 */
export function resolveTelegramIntent(body: string): TelegramIntent | null {
	if (!body) return null;
	const normalized = normalize(body);
	if (!normalized) return null;

	// Model-related intents
	const modelTrigger =
		hasAny(normalized, [
			"switch to ",
			"switch model",
			"change model",
			"use sonnet",
			"use opus",
			"use haiku",
			"use gpt",
			"use claude",
		]) || /^use\s+[a-z]/.test(normalized);
	if (modelTrigger) {
		const token = extractModelToken(normalized);
		if (token) {
			const hint = resolveModelHint(token);
			if (hint) {
				return {
					kind: "open-model-picker",
					providerHint: hint.providerId,
					modelHint: hint.modelId,
				};
			}
		}
		// User said "switch model" without a recognised token — still open
		// the picker so they can browse.
		return { kind: "open-model-picker" };
	}

	// Provider-related intents
	if (
		hasAny(normalized, [
			"list providers",
			"show providers",
			"provider health",
			"provider status",
			"provider list",
			"what providers",
		])
	) {
		return { kind: "open-provider-list" };
	}

	// Skill-related intents
	if (
		hasAny(normalized, [
			"open skill picker",
			"skill picker",
			"show skills",
			"list skills",
			"promote skill",
			"reload skills",
		])
	) {
		return { kind: "open-skill-picker" };
	}

	return null;
}
