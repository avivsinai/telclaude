/**
 * SDK module exports.
 */

export { executeQueryStream, type StreamChunk, type TelclaudeQueryOptions } from "./client.js";
export {
	isAssistantMessage,
	isBashInput,
	isContentBlockStopEvent,
	isGlobInput,
	isGrepInput,
	isReadInput,
	isResultMessage,
	isStreamEvent,
	isTextDeltaEvent,
	isToolResultMessage,
	isToolUseStartEvent,
	isWriteInput,
} from "./message-guards.js";
