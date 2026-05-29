import type { PermissionTier } from "../config/config.js";
import type { StreamChunk } from "../sdk/client.js";
import {
	executeHermesPrivateRuntime,
	type HermesPrivateRuntimeRequest,
	type HermesRuntimeAdapter,
} from "./private-runtime.js";
import { hermesSessionMap } from "./session-map.js";

export type HermesPrivateQueryOptions = {
	cwd: string;
	tier: PermissionTier;
	poolKey: string;
	telclaudeSessionId: string;
	profileId: string;
	model?: string;
	resumeSessionId?: string;
	enableSkills: boolean;
	allowedSkills?: readonly string[];
	timeoutMs: number;
	userId?: string;
	chatId?: number;
	actorId?: number | string;
	threadId?: number;
	systemPromptAppend?: string;
	compiledMemoryMd?: string;
};

let privateRuntimeAdapter: HermesRuntimeAdapter | null = null;

export function shouldUseHermesPrivateRuntime(env: NodeJS.ProcessEnv = process.env): boolean {
	return env.TELCLAUDE_HERMES_PRIVATE_RUNTIME === "1";
}

export function setHermesPrivateRuntimeAdapterForTest(adapter: HermesRuntimeAdapter | null): void {
	privateRuntimeAdapter = adapter;
}

export async function* executeHermesPrivateQuery(
	prompt: string,
	options: HermesPrivateQueryOptions,
): AsyncGenerator<StreamChunk, void, unknown> {
	if (!privateRuntimeAdapter) {
		yield {
			type: "done",
			result: {
				response: "",
				success: false,
				error: "Hermes private runtime adapter is not configured",
				costUsd: 0,
				numTurns: 0,
				durationMs: 0,
			},
		};
		return;
	}

	const controller = new AbortController();
	const timeout = setTimeout(() => controller.abort(), options.timeoutMs);
	try {
		const request: HermesPrivateRuntimeRequest = {
			prompt,
			cwd: options.cwd,
			sessionKey: options.poolKey,
			telclaudeSessionId: options.telclaudeSessionId,
			profileId: options.profileId,
			model: options.model,
			systemPromptAppend: options.systemPromptAppend,
			allowedSkills: options.enableSkills ? options.allowedSkills : [],
			isNewSession: !options.resumeSessionId,
			timeoutMs: options.timeoutMs,
			signal: controller.signal,
		};
		yield* executeHermesPrivateRuntime({
			runtime: privateRuntimeAdapter,
			sessions: hermesSessionMap,
			request,
		});
	} finally {
		clearTimeout(timeout);
	}
}
