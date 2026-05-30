import type { PermissionTier } from "../config/config.js";
import type { StreamChunk } from "../sdk/client.js";
import { HermesApiRuntimeAdapter } from "./api-adapter.js";
import {
	executeHermesPrivateRuntime,
	type HermesPrivateMcpAuthorityOptions,
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
	mcpAuthority?: HermesPrivateMcpAuthorityOptions;
};

let privateRuntimeAdapter: HermesRuntimeAdapter | null = null;

export function shouldUseHermesPrivateRuntime(env: NodeJS.ProcessEnv = process.env): boolean {
	return env.TELCLAUDE_HERMES_PRIVATE_RUNTIME === "1";
}

export function setHermesPrivateRuntimeAdapterForTest(adapter: HermesRuntimeAdapter | null): void {
	privateRuntimeAdapter = adapter;
}

export function buildHermesPrivateRuntimeAdapterFromEnv(
	env: NodeJS.ProcessEnv = process.env,
): HermesRuntimeAdapter | null {
	const baseUrl = env.TELCLAUDE_HERMES_API_BASE_URL?.trim();
	const apiKey = env.TELCLAUDE_HERMES_API_KEY?.trim();
	if (!baseUrl && !apiKey) return null;
	if (!baseUrl) {
		throw new Error(
			"TELCLAUDE_HERMES_API_BASE_URL is required when TELCLAUDE_HERMES_API_KEY is set",
		);
	}
	if (!apiKey) {
		throw new Error(
			"TELCLAUDE_HERMES_API_KEY is required when TELCLAUDE_HERMES_API_BASE_URL is set",
		);
	}
	return new HermesApiRuntimeAdapter({ baseUrl, apiKey });
}

export async function* executeHermesPrivateQuery(
	prompt: string,
	options: HermesPrivateQueryOptions,
): AsyncGenerator<StreamChunk, void, unknown> {
	let runtime: HermesRuntimeAdapter | null;
	try {
		runtime = privateRuntimeAdapter ?? buildHermesPrivateRuntimeAdapterFromEnv();
	} catch (error) {
		yield {
			type: "done",
			result: {
				response: "",
				success: false,
				error: error instanceof Error ? error.message : String(error),
				costUsd: 0,
				numTurns: 0,
				durationMs: 0,
			},
		};
		return;
	}

	if (!runtime) {
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
			tier: options.tier,
			sessionKey: options.poolKey,
			telclaudeSessionId: options.telclaudeSessionId,
			profileId: options.profileId,
			identity: {
				userId: options.userId,
				chatId: options.chatId,
				actorId: options.actorId,
				threadId: options.threadId,
			},
			memory: options.compiledMemoryMd ? { compiledMemoryMd: options.compiledMemoryMd } : undefined,
			model: options.model,
			systemPromptAppend: options.systemPromptAppend,
			allowedSkills: options.enableSkills ? options.allowedSkills : [],
			mcpAuthority: options.mcpAuthority,
			isNewSession: !options.resumeSessionId,
			timeoutMs: options.timeoutMs,
			signal: controller.signal,
		};
		yield* executeHermesPrivateRuntime({
			runtime,
			sessions: hermesSessionMap,
			request,
		});
	} finally {
		clearTimeout(timeout);
	}
}
