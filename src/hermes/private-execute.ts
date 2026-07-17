import type { PermissionTier } from "../config/config.js";
import type { StreamChunk } from "../runtime/stream.js";
import { HermesApiRuntimeAdapter } from "./api-adapter.js";
import {
	executeHermesPrivateRuntime,
	type HermesPrivateMcpAuthorityOptions,
	type HermesPrivateRuntimeRequest,
	type HermesRuntimeAdapter,
	type HermesRuntimeMcpAuthorityActivation,
} from "./private-runtime.js";
import { hermesSessionMap } from "./session-map.js";

export type HermesQueryOptions = {
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
	signal?: AbortSignal;
	userId?: string;
	chatId?: number;
	actorId?: number | string;
	threadId?: number;
	systemPromptAppend?: string;
	compiledMemoryMd?: string;
	runtimeDomain?: HermesRuntimeDomain;
	mcpAuthority?: HermesPrivateMcpAuthorityOptions | false;
};

export type HermesRuntimeDomain = "private" | "social";

const HERMES_RUNTIME_ENV: Record<
	HermesRuntimeDomain,
	{
		baseUrl: string;
		apiKey: string;
		notConfiguredError: string;
	}
> = {
	private: {
		baseUrl: "TELCLAUDE_HERMES_API_BASE_URL",
		apiKey: "TELCLAUDE_HERMES_API_KEY",
		notConfiguredError: "Hermes private runtime adapter is not configured",
	},
	social: {
		baseUrl: "TELCLAUDE_HERMES_SOCIAL_API_BASE_URL",
		apiKey: "TELCLAUDE_HERMES_SOCIAL_API_KEY",
		notConfiguredError: "Hermes social runtime adapter is not configured",
	},
};

const runtimeAdapters: Record<HermesRuntimeDomain, HermesRuntimeAdapter | null> = {
	private: null,
	social: null,
};
let privateRuntimeMcpAuthorityActivation: HermesRuntimeMcpAuthorityActivation | null = null;

export function setHermesPrivateRuntimeAdapterForTest(adapter: HermesRuntimeAdapter | null): void {
	runtimeAdapters.private = adapter;
}

export function setHermesRuntimeAdapterForTest(
	domain: HermesRuntimeDomain,
	adapter: HermesRuntimeAdapter | null,
): void {
	runtimeAdapters[domain] = adapter;
}

export function setHermesPrivateRuntimeMcpAuthorityActivation(
	activation: HermesRuntimeMcpAuthorityActivation | null,
): void {
	privateRuntimeMcpAuthorityActivation = activation;
}

export function buildHermesPrivateRuntimeAdapterFromEnv(
	env: NodeJS.ProcessEnv = process.env,
): HermesRuntimeAdapter | null {
	return buildHermesRuntimeAdapterFromEnv("private", env);
}

export function buildHermesRuntimeAdapterFromEnv(
	domain: HermesRuntimeDomain,
	env: NodeJS.ProcessEnv = process.env,
): HermesRuntimeAdapter | null {
	const spec = HERMES_RUNTIME_ENV[domain];
	const baseUrl = env[spec.baseUrl]?.trim();
	const apiKey = env[spec.apiKey]?.trim();
	if (!baseUrl && !apiKey) return null;
	if (!baseUrl) {
		throw new Error(`${spec.baseUrl} is required when ${spec.apiKey} is set`);
	}
	if (!apiKey) {
		throw new Error(`${spec.apiKey} is required when ${spec.baseUrl} is set`);
	}
	return new HermesApiRuntimeAdapter({ baseUrl, apiKey });
}

function resolveHermesRuntimeDomain(options: HermesQueryOptions): HermesRuntimeDomain {
	if (options.runtimeDomain) return options.runtimeDomain;
	return options.mcpAuthority && options.mcpAuthority.domain === "social" ? "social" : "private";
}

export async function* executeHermesQuery(
	prompt: string,
	options: HermesQueryOptions,
): AsyncGenerator<StreamChunk, void, unknown> {
	const runtimeDomain = resolveHermesRuntimeDomain(options);
	let runtime: HermesRuntimeAdapter | null;
	try {
		runtime = runtimeAdapters[runtimeDomain] ?? buildHermesRuntimeAdapterFromEnv(runtimeDomain);
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
		const spec = HERMES_RUNTIME_ENV[runtimeDomain];
		yield {
			type: "done",
			result: {
				response: "",
				success: false,
				error: spec.notConfiguredError,
				costUsd: 0,
				numTurns: 0,
				durationMs: 0,
			},
		};
		return;
	}

	const controller = new AbortController();
	const abortFromCaller = () => controller.abort(options.signal?.reason);
	if (options.signal?.aborted) {
		abortFromCaller();
	} else {
		options.signal?.addEventListener("abort", abortFromCaller, { once: true });
	}
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
			...(privateRuntimeMcpAuthorityActivation
				? { mcpAuthorityActivation: privateRuntimeMcpAuthorityActivation }
				: {}),
		});
	} finally {
		clearTimeout(timeout);
		options.signal?.removeEventListener("abort", abortFromCaller);
	}
}
