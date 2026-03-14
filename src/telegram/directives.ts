/**
 * Telegram Directive Tag System
 *
 * Inline tags embedded in agent output text that control Telegram-specific behavior
 * without requiring separate tool calls. Inspired by openclaw's reply-directives pattern.
 *
 * Directives are parsed from agent output, stripped from the rendered text, and executed
 * as side effects by the streaming pipeline.
 *
 * Tag syntax:
 *   @reply(12345)                      - Reply to message 12345
 *   @silent                            - Suppress sending to Telegram
 *   @social(question)                  - Route to first social service
 *   @social(moltbook, question here)   - Route to specific service
 *   @thread(98765)                     - Post in forum thread
 *   @reaction(emoji)                   - React to the original message
 *   @reaction(emoji, 12345)            - React to specific message
 *   @card(status)                      - Render a card
 *   @card(approval, title=Review, body=Should I publish?)  - Card with params
 *   @tts                               - Convert entire response to speech
 *   @tts(just this part)               - Convert specific text to speech
 *   @typing(start)                     - Start typing indicator
 *   @typing(stop)                      - Stop typing indicator
 *
 * Integration points (streaming.ts — do NOT modify streaming.ts):
 *   1. const { text, directives } = parseDirectives(rawOutput);
 *   2. const result = executeDirectives(directives, ctx);
 *   3. if (!result.suppressSend) { sendMessage(text, { replyTo: result.replyToMessageId, thread: result.threadId }); }
 *   4. await Promise.all(result.sideEffects.map(fn => fn()));
 */

import type { Api } from "grammy";
import type { ReactionTypeEmoji } from "grammy/types";

import { getChildLogger } from "../logging.js";
import {
	sendApprovalCard,
	sendHeartbeatCard,
	sendPendingQueueCard,
	sendSessionCard,
	sendSkillDraftCard,
	sendStatusCard,
} from "./cards/create-helpers.js";

const logger = getChildLogger({ module: "telegram-directives" });

/**
 * Telegram-allowed bot reaction emoji. Agent-provided emoji not in this set are rejected.
 */
const VALID_REACTION_EMOJI = new Set<string>([
	"👍",
	"👎",
	"❤",
	"🔥",
	"🥰",
	"👏",
	"😁",
	"🤔",
	"🤯",
	"😱",
	"🤬",
	"😢",
	"🎉",
	"🤩",
	"🤮",
	"💩",
	"🙏",
	"👌",
	"🕊",
	"🤡",
	"🥱",
	"🥴",
	"😍",
	"🐳",
	"❤‍🔥",
	"🌚",
	"🌭",
	"💯",
	"🤣",
	"⚡",
	"🍌",
	"🏆",
	"💔",
	"🤨",
	"😐",
	"🍓",
	"🍾",
	"💋",
	"🖕",
	"😈",
	"😴",
	"😭",
	"🤓",
	"👻",
	"👨‍💻",
	"👀",
	"🎃",
	"🙈",
	"😇",
	"😨",
	"🤝",
	"✍",
	"🤗",
	"🫡",
	"🎅",
	"🎄",
	"☃",
	"💅",
	"🤪",
	"🗿",
	"🆒",
	"💘",
	"🙉",
	"🦄",
	"😘",
	"💊",
	"🙊",
	"😎",
	"👾",
	"🤷‍♂",
	"🤷",
	"🤷‍♀",
	"😡",
]);

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

export type Directive =
	| { type: "reply"; messageId: number }
	| { type: "silent" }
	| { type: "social"; serviceId?: string; question: string }
	| { type: "thread"; threadId: number }
	| { type: "reaction"; emoji: string; messageId?: number }
	| { type: "card"; cardType: string; params: Record<string, string> }
	| { type: "tts"; text?: string }
	| { type: "typing"; action: "start" | "stop" };

export type ParsedOutput = {
	/** Clean text with directives stripped */
	text: string;
	/** Extracted directives in order of appearance */
	directives: Directive[];
};

export type DirectiveContext = {
	api: Api;
	chatId: number;
	/** The bot's reply message ID (may not exist yet during streaming) */
	messageId?: number;
	/** The user's original message ID */
	originalMessageId?: number;
	/** Current forum thread ID */
	threadId?: number;
};

export type DirectiveResult = {
	/** If true, don't send text to Telegram */
	suppressSend: boolean;
	/** Override reply target */
	replyToMessageId?: number;
	/** Override thread target */
	threadId?: number;
	/** Async side effects to execute after sending (or instead of sending if suppressSend) */
	sideEffects: Array<() => Promise<void>>;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Known directive names — only these are parsed; unknown names are left as-is
// ═══════════════════════════════════════════════════════════════════════════════

const KNOWN_DIRECTIVES = new Set([
	"reply",
	"silent",
	"social",
	"thread",
	"reaction",
	"card",
	"tts",
	"typing",
]);

// ═══════════════════════════════════════════════════════════════════════════════
// Parser
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Regex for directive tags. Matches:
 *   @name(args)  — directive with arguments
 *   @name        — bare directive (only for directives that accept no args: silent, tts)
 *
 * The pattern requires:
 *   - `@` at a word boundary (not preceded by a word char, e.g. email user@reply would not match)
 *   - Lowercase name matching a known directive
 *   - Optional parenthesized arguments (balanced parens, no nesting)
 *
 * We use a function-based approach rather than a single global regex to handle
 * the word-boundary constraint and known-name validation in one pass.
 */

type RawMatch = {
	fullMatch: string;
	name: string;
	args: string | undefined;
	index: number;
};

function findDirectiveMatches(raw: string): RawMatch[] {
	// Match @name or @name(...)
	// Negative lookbehind: not preceded by a word character (prevents matching emails like user@reply)
	const re = /(?<!\w)@([a-z]+)(?:\(([^)]*)\))?/g;
	const matches: RawMatch[] = [];

	for (const m of raw.matchAll(re)) {
		const name = m[1];
		const args = m[2]; // undefined if no parens, "" if empty parens

		// Only parse known directive names
		if (!KNOWN_DIRECTIVES.has(name)) {
			continue;
		}

		matches.push({
			fullMatch: m[0],
			name,
			args,
			index: m.index,
		});
	}

	return matches;
}

/**
 * Parse a single directive from a raw match.
 * Returns undefined if the match is not a valid directive.
 */
function parseOneDirective(match: RawMatch): Directive | undefined {
	const { name, args } = match;

	switch (name) {
		case "reply": {
			if (args === undefined) return undefined;
			const messageId = Number.parseInt(args.trim(), 10);
			if (Number.isNaN(messageId)) return undefined;
			return { type: "reply", messageId };
		}

		case "silent": {
			// @silent takes no arguments
			return { type: "silent" };
		}

		case "social": {
			if (args === undefined || args.trim() === "") return undefined;
			const trimmed = args.trim();
			// Check for serviceId prefix: @social(moltbook, question here)
			const commaIdx = trimmed.indexOf(",");
			if (commaIdx > 0) {
				const possibleServiceId = trimmed.slice(0, commaIdx).trim();
				const question = trimmed.slice(commaIdx + 1).trim();
				// Service IDs are short alphanumeric strings (no spaces)
				if (possibleServiceId.length > 0 && !/\s/.test(possibleServiceId) && question.length > 0) {
					return { type: "social", serviceId: possibleServiceId, question };
				}
			}
			// No comma or invalid service ID — entire args is the question
			return { type: "social", question: trimmed };
		}

		case "thread": {
			if (args === undefined) return undefined;
			const threadId = Number.parseInt(args.trim(), 10);
			if (Number.isNaN(threadId)) return undefined;
			return { type: "thread", threadId };
		}

		case "reaction": {
			if (args === undefined || args.trim() === "") return undefined;
			const trimmed = args.trim();
			const commaIdx = trimmed.indexOf(",");
			if (commaIdx > 0) {
				const emoji = trimmed.slice(0, commaIdx).trim();
				const messageId = Number.parseInt(trimmed.slice(commaIdx + 1).trim(), 10);
				if (emoji.length > 0 && !Number.isNaN(messageId)) {
					return { type: "reaction", emoji, messageId };
				}
			}
			// No comma — just emoji, react to original message
			return { type: "reaction", emoji: trimmed };
		}

		case "card": {
			if (args === undefined || args.trim() === "") return undefined;
			const trimmed = args.trim();
			const commaIdx = trimmed.indexOf(",");
			if (commaIdx > 0) {
				const cardType = trimmed.slice(0, commaIdx).trim();
				const paramsStr = trimmed.slice(commaIdx + 1).trim();
				const params = parseCardParams(paramsStr);
				return { type: "card", cardType, params };
			}
			// No params — just card type
			return { type: "card", cardType: trimmed, params: {} };
		}

		case "tts": {
			// @tts — convert entire response; @tts(text) — convert specific text
			if (args === undefined) {
				return { type: "tts" };
			}
			const trimmed = args.trim();
			return trimmed.length > 0 ? { type: "tts", text: trimmed } : { type: "tts" };
		}

		case "typing": {
			if (args === undefined) return undefined;
			const action = args.trim();
			if (action !== "start" && action !== "stop") return undefined;
			return { type: "typing", action };
		}

		default:
			return undefined;
	}
}

/**
 * Parse key=value pairs from card params string.
 * Example: "title=Review post, body=Should I publish?" -> { title: "Review post", body: "Should I publish?" }
 */
function parseCardParams(paramsStr: string): Record<string, string> {
	const params: Record<string, string> = {};
	// Split on comma-separated key=value pairs
	// We need to be careful: values can contain commas if there's no = after the comma
	const parts = paramsStr.split(/,\s*(?=\w+=)/);
	for (const part of parts) {
		const eqIdx = part.indexOf("=");
		if (eqIdx > 0) {
			const key = part.slice(0, eqIdx).trim();
			const value = part.slice(eqIdx + 1).trim();
			if (key.length > 0) {
				params[key] = value;
			}
		}
	}
	return params;
}

/**
 * Parse directives from agent output text.
 *
 * Extracts known directive tags, strips them from the text, and returns
 * both the cleaned text and the list of parsed directives.
 *
 * Unknown @-prefixed names are preserved as-is (could be email addresses,
 * social media handles, etc.).
 */
export function parseDirectives(raw: string): ParsedOutput {
	const matches = findDirectiveMatches(raw);
	if (matches.length === 0) {
		return { text: raw, directives: [] };
	}

	const directives: Directive[] = [];
	// Track regions to strip (start, end) — process in reverse to preserve indices
	const stripRegions: Array<{ start: number; end: number }> = [];

	for (const match of matches) {
		const directive = parseOneDirective(match);
		if (directive) {
			directives.push(directive);
			stripRegions.push({
				start: match.index,
				end: match.index + match.fullMatch.length,
			});
		}
		// If parseOneDirective returns undefined (e.g., @reply with non-numeric args),
		// we don't strip it — leave it as text.
	}

	// Build cleaned text by removing strip regions
	let text = raw;
	// Process in reverse order to preserve earlier indices
	for (let i = stripRegions.length - 1; i >= 0; i--) {
		const region = stripRegions[i];
		text = text.slice(0, region.start) + text.slice(region.end);
	}

	// Clean up whitespace artifacts from stripping:
	// - Multiple consecutive spaces -> single space
	// - Trim leading/trailing whitespace per line
	// - Remove empty lines caused by stripping a directive that was on its own line
	text = text
		.split("\n")
		.map((line) => line.replace(/ {2,}/g, " ").trim())
		.filter((line, idx, arr) => {
			// Remove empty lines at start/end
			if (idx === 0 && line === "") return false;
			if (idx === arr.length - 1 && line === "") return false;
			// Remove consecutive empty lines (keep at most one)
			if (line === "" && idx > 0 && arr[idx - 1].trim() === "") return false;
			return true;
		})
		.join("\n")
		.trim();

	return { text, directives };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Executor
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Card type name -> card create helper dispatch.
 * Maps the string from @card(type) to the appropriate sendXCard helper.
 */
const CARD_TYPE_MAP: Record<
	string,
	(api: Api, chatId: number, params: Record<string, string>, threadId?: number) => Promise<void>
> = {
	status: async (api, chatId, params, threadId) => {
		await sendStatusCard(api, chatId, {
			title: params.title,
			summary: params.summary ?? params.body ?? "Status",
			details: params.details?.split(";"),
			actorScope: `chat:${chatId}`,
			threadId,
		});
	},
	approval: async (api, chatId, params, threadId) => {
		await sendApprovalCard(api, chatId, {
			title: params.title ?? "Approval Required",
			body: params.body ?? "Please approve this action.",
			nonce: params.nonce ?? `directive-${Date.now()}`,
			actorScope: `chat:${chatId}`,
			threadId,
		});
	},
	session: async (api, chatId, params, threadId) => {
		await sendSessionCard(api, chatId, {
			summary: params.summary ?? "Current session",
			sessionKey: params.sessionKey,
			actorScope: `chat:${chatId}`,
			threadId,
		});
	},
	heartbeat: async (api, chatId, _params, threadId) => {
		await sendHeartbeatCard(api, chatId, {
			services: [],
			actorScope: `chat:${chatId}`,
			threadId,
		});
	},
	pending: async (api, chatId, _params, threadId) => {
		await sendPendingQueueCard(api, chatId, {
			entries: [],
			actorScope: `chat:${chatId}`,
			threadId,
		});
	},
	"skill-draft": async (api, chatId, _params, threadId) => {
		await sendSkillDraftCard(api, chatId, {
			drafts: [],
			actorScope: `chat:${chatId}`,
			threadId,
		});
	},
};

/**
 * Process parsed directives into execution instructions.
 *
 * The executor does NOT perform side effects directly — it returns them as
 * closures. The caller (streaming pipeline) decides when to execute them.
 *
 * Directive behavior:
 * - reply    -> sets replyToMessageId
 * - silent   -> sets suppressSend = true
 * - social   -> adds side effect: dispatch query to social agent
 * - thread   -> sets threadId override
 * - reaction -> adds side effect: call setMessageReaction API
 * - card     -> adds side effect: call card render helper
 * - tts      -> adds side effect: call TTS service
 * - typing   -> adds side effect: call sendChatAction
 */
export function executeDirectives(directives: Directive[], ctx: DirectiveContext): DirectiveResult {
	const result: DirectiveResult = {
		suppressSend: false,
		sideEffects: [],
	};

	for (const directive of directives) {
		switch (directive.type) {
			case "reply": {
				result.replyToMessageId = directive.messageId;
				break;
			}

			case "silent": {
				result.suppressSend = true;
				break;
			}

			case "social": {
				const { serviceId, question } = directive;
				result.sideEffects.push(async () => {
					// Requires relay routing: the social directive dispatches a query to the social
					// agent via queryPublicPersona, which is mediated by the relay. The directive
					// context does not have access to the relay or service config — this must be
					// wired at the streaming pipeline level where the relay connection is available.
					// See: src/telegram/auto-reply.ts (case "ask-public") and src/social/handler.ts
					logger.info(
						{ chatId: ctx.chatId, serviceId, questionLength: question.length },
						"social directive: requires relay integration (not available in directive context)",
					);
				});
				break;
			}

			case "thread": {
				result.threadId = directive.threadId;
				break;
			}

			case "reaction": {
				const { emoji, messageId: reactionTargetId } = directive;
				if (!VALID_REACTION_EMOJI.has(emoji)) {
					logger.warn({ emoji }, "reaction directive: unsupported emoji, skipping");
					break;
				}
				const targetMessageId = reactionTargetId ?? ctx.originalMessageId;
				if (targetMessageId) {
					result.sideEffects.push(async () => {
						try {
							await ctx.api.setMessageReaction(ctx.chatId, targetMessageId, [
								{ type: "emoji", emoji: emoji as ReactionTypeEmoji["emoji"] },
							]);
							logger.debug(
								{ chatId: ctx.chatId, messageId: targetMessageId, emoji },
								"reaction directive: set reaction",
							);
						} catch (err) {
							// Non-fatal — reaction may fail if emoji is unsupported or message is old
							logger.warn(
								{ error: String(err), chatId: ctx.chatId, emoji },
								"reaction directive failed",
							);
						}
					});
				} else {
					logger.debug(
						{ chatId: ctx.chatId, emoji },
						"reaction directive: no target message ID available",
					);
				}
				break;
			}

			case "card": {
				const { cardType, params } = directive;
				const handler = CARD_TYPE_MAP[cardType];
				if (handler) {
					result.sideEffects.push(async () => {
						try {
							await handler(ctx.api, ctx.chatId, params, ctx.threadId);
							logger.debug({ chatId: ctx.chatId, cardType }, "card directive: card sent");
						} catch (err) {
							logger.warn(
								{ error: String(err), chatId: ctx.chatId, cardType },
								"card directive: failed to send card",
							);
						}
					});
				} else {
					logger.warn({ chatId: ctx.chatId, cardType }, "card directive: unknown card type");
				}
				break;
			}

			case "tts": {
				const { text: ttsText } = directive;
				result.sideEffects.push(async () => {
					// Requires credential proxy: TTS goes through the relay's credential proxy
					// to reach the OpenAI TTS API. The directive context does not have access to
					// the credential proxy or TTS service — this must be wired at the streaming
					// pipeline level where the proxy connection is available.
					// See: src/services/ for TTS service integration.
					logger.info(
						{
							chatId: ctx.chatId,
							hasCustomText: ttsText !== undefined,
							textLength: ttsText?.length,
						},
						"tts directive: requires credential proxy (not available in directive context)",
					);
				});
				break;
			}

			case "typing": {
				const { action } = directive;
				if (action === "start") {
					result.sideEffects.push(async () => {
						try {
							await ctx.api.sendChatAction(ctx.chatId, "typing", {
								message_thread_id: ctx.threadId,
							});
						} catch {
							// Non-fatal
						}
					});
				}
				// "stop" has no Telegram API equivalent — typing stops automatically
				// after sending a message or after ~5 seconds. We log it for completeness.
				if (action === "stop") {
					logger.debug({ chatId: ctx.chatId }, "typing stop directive (no-op: typing auto-stops)");
				}
				break;
			}
		}
	}

	return result;
}
