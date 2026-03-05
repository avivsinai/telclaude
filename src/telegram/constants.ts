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
 * Telegram's 4096 limit applies to text after entities parsing, not the raw
 * MarkdownV2 payload. We split at 3800 (not 4096) to leave modest headroom
 * for edge cases. The sendWithMarkdownFallback path handles rare post-conversion
 * overflows by retrying as plain text.
 */
export const MAX_MESSAGE_CHUNK_LENGTH = 3800;

/**
 * Maximum total response size (characters) before truncation.
 *
 * Prevents DoS from extremely long LLM responses that could block the
 * event loop during sanitisation and splitting. ~500K characters is well
 * above any reasonable Telegram conversation response.
 *
 * Note: compared against string length (UTF-16 code units), not byte count.
 */
export const MAX_TOTAL_RESPONSE_SIZE = 500 * 1024;

/**
 * Maximum length for heartbeat / admin notification text.
 *
 * These are sanitised summaries (counts, service IDs, action labels),
 * not raw LLM output. 2000 chars leaves headroom for MarkdownV2 escaping
 * while fitting in a single Telegram message (4096 after entities parsing).
 */
export const MAX_NOTIFICATION_LENGTH = 2000;

/**
 * Telegram Bot API hard character limit for media captions.
 *
 * Media captions (photos, videos, documents, etc.) are limited to 1024
 * characters after entities parsing — much smaller than the 4096 text limit.
 *
 * @see https://core.telegram.org/bots/api#sendphoto
 */
export const TELEGRAM_CAPTION_CHAR_LIMIT = 1024;

/**
 * Maximum display length for in-flight streaming updates.
 *
 * Streaming edits include a "generating..." suffix and may use MarkdownV2,
 * so this is set just below the API hard limit to leave room for the
 * indicator text and escaping.
 */
export const MAX_STREAMING_UPDATE_LENGTH = 3900;
