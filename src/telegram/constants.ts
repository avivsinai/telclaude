/**
 * Telegram message length constants.
 *
 * Centralised limits for all Telegram-related message sizing.
 * Import from here instead of defining local constants.
 */

/**
 * Telegram Bot API hard character limit per message.
 *
 * DO NOT use this directly for sending — MarkdownV2 escaping expands text,
 * so downstream limits must include headroom. Documented here as the
 * canonical reference for why the other limits exist.
 *
 * @see https://core.telegram.org/bots/api#sendmessage
 */
export const TELEGRAM_API_CHAR_LIMIT = 4096;

/**
 * Maximum characters per message chunk after splitting.
 *
 * Set to 3200 to leave ~900 chars headroom for MarkdownV2 escape expansion
 * (e.g., "test.com" becomes "test\.com"). Used by sanitizeAndSplitResponse().
 */
export const MAX_MESSAGE_CHUNK_LENGTH = 3200;

/**
 * Maximum total response size (bytes) before truncation.
 *
 * Prevents DoS from extremely long LLM responses that could block the
 * event loop during sanitisation and splitting. 500 KB is well above any
 * reasonable Telegram conversation response.
 */
export const MAX_TOTAL_RESPONSE_SIZE = 500 * 1024; // 500KB

/**
 * Maximum length for heartbeat / admin notification text.
 *
 * These are metadata-only summaries (counts, service IDs, action labels),
 * not raw LLM output, so a moderate limit is safe. 800 chars gives enough
 * room for multi-service heartbeat summaries while staying well under the
 * Telegram API limit.
 */
export const MAX_NOTIFICATION_LENGTH = 800;

/**
 * Maximum display length for in-flight streaming updates.
 *
 * Streaming edits include a "generating..." suffix and may use MarkdownV2,
 * so this is set just below the API hard limit to leave room for the
 * indicator text and escaping.
 */
export const MAX_STREAMING_UPDATE_LENGTH = 3900;
