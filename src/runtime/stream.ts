export type QueryResult = {
	response: string;
	success: boolean;
	error?: string;
	costUsd: number;
	numTurns: number;
	durationMs: number;
	sessionId?: string;
	totalInputTokens?: number;
	totalOutputTokens?: number;
	structuredOutput?: unknown;
};

export type StreamChunk =
	| { type: "text"; content: string }
	| { type: "tool_use"; toolName: string; input: unknown }
	| { type: "tool_result"; toolName: string; output: unknown }
	| { type: "done"; result: QueryResult };
