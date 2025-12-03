/**
 * SDK module exports.
 */

export {
	executeQueryStream,
	executePooledQuery,
	type StreamChunk,
	type TelclaudeQueryOptions,
	type PooledQueryOptions,
} from "./client.js";

export {
	getSessionManager,
	destroySessionManager,
	executeWithSession,
	type SessionInfo,
} from "./session-manager.js";

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
