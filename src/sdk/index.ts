/**
 * SDK module exports.
 */

export {
	executePooledQuery,
	executeQueryStream,
	type PooledQueryOptions,
	type StreamChunk,
	type TelclaudeQueryOptions,
} from "./client.js";
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
export {
	destroySessionManager,
	executeWithSession,
	getSessionManager,
	type SessionInfo,
} from "./session-manager.js";
