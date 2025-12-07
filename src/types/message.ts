/**
 * Provider-agnostic message context types.
 *
 * These types are used for session derivation and templating,
 * independent of the specific messaging provider.
 */

/**
 * Basic message context for session derivation and templating.
 */
export type MsgContext = {
	Body?: string;
	From?: string;
	To?: string;
	MessageId?: string;
	MediaPath?: string;
	MediaFilePath?: string;
	MediaType?: string;
	Transcript?: string;
	Username?: string;
};
