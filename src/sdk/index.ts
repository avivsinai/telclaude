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
	SessionPool,
	getSessionPool,
	destroySessionPool,
	type PooledSession,
	type SessionPoolOptions,
} from "./session-pool.js";

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
