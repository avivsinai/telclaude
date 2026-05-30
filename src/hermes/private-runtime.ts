import type { PermissionTier } from "../config/config.js";
import { telegramMemorySource } from "../memory/source.js";
import type { MemorySource } from "../memory/types.js";
import type { StreamChunk } from "../sdk/client.js";
import { filterOutput, redactSecrets } from "../security/output-filter.js";
import {
	hermesMcpAuthorityRegistry,
	type TelclaudeMcpAuthorityConnection,
	type TelclaudeMcpAuthorityRegistry,
} from "./mcp/authority-registry.js";
import type { TelclaudeMcpAuthority, TelclaudeMcpDomain } from "./mcp/bridge.js";
import type { HermesSessionMap } from "./session-map.js";

export const HERMES_PROBE_RESULT_SCHEMA_VERSION = "telclaude.hermes.probe-result.v1";
const DEFAULT_PRIVATE_MCP_ENDPOINT_ID = "telclaude-private-runtime";
const DEFAULT_PRIVATE_MCP_NETWORK_NAMESPACE = "telclaude-private";

export type HermesRuntimeRequest = {
	prompt: string;
	cwd: string;
	tier: PermissionTier;
	sessionKey: string;
	telclaudeSessionId: string;
	profileId: string;
	identity: {
		userId?: string;
		chatId?: number;
		actorId?: number | string;
		threadId?: number;
	};
	memory?: {
		compiledMemoryMd?: string;
	};
	resumeHermesSessionId?: string;
	model?: string;
	systemPromptAppend?: string;
	allowedSkills?: readonly string[];
	mcpAuthority?: HermesRuntimeMcpAuthorityGrant;
	isNewSession: boolean;
	timeoutMs: number;
	signal: AbortSignal;
};

export type HermesRuntimeMcpAuthorityGrant = {
	readonly handle: string;
	readonly connection: TelclaudeMcpAuthorityConnection;
	readonly expiresAtMs: number;
};

export type HermesPrivateMcpAuthorityOptions = {
	readonly domain?: TelclaudeMcpDomain;
	readonly memorySource?: MemorySource;
	readonly writableNamespace?: string;
	readonly providerScopes?: readonly string[];
	readonly outboundChannels?: readonly string[];
	readonly endpointId?: string;
	readonly networkNamespace?: string;
	readonly ttlMs?: number;
};

export type HermesRuntimeEvent =
	| { type: "session"; hermesSessionId: string }
	| { type: "text_delta"; text: string }
	| { type: "tool_use"; toolName: string; input: unknown }
	| { type: "tool_result"; toolName: string; output: unknown }
	| {
			type: "done";
			response?: string;
			success?: boolean;
			error?: string;
			costUsd?: number;
			numTurns?: number;
			durationMs?: number;
	  };

export type HermesRuntimeAdapter = {
	run(request: HermesRuntimeRequest): AsyncIterable<HermesRuntimeEvent>;
};

export type HermesPrivateRuntimeRequest = Omit<
	HermesRuntimeRequest,
	"telclaudeSessionId" | "resumeHermesSessionId" | "mcpAuthority"
> & {
	telclaudeSessionId?: string;
	mcpAuthority?: HermesPrivateMcpAuthorityOptions;
};

export type HermesLaunchInvocation = {
	command: string;
	args: string[];
	cwd: string;
	env: Record<string, string>;
};

export type HermesLaunchSecretFinding = {
	location: string;
	reason: string;
};

export type HermesCliProbeReport = {
	schemaVersion: typeof HERMES_PROBE_RESULT_SCHEMA_VERSION;
	probeId: "execution.cli_headless";
	status: "pass" | "fail" | "pending";
	ran: boolean;
	summary: string;
	exitCode?: number;
	stdoutPreview?: string;
	stderrPreview?: string;
	findings: HermesLaunchSecretFinding[];
};

export async function* executeHermesPrivateRuntime(input: {
	runtime: HermesRuntimeAdapter;
	sessions: HermesSessionMap;
	request: HermesPrivateRuntimeRequest;
	mcpAuthorityRegistry?: TelclaudeMcpAuthorityRegistry;
	now?: () => number;
}): AsyncGenerator<StreamChunk, void, unknown> {
	const now = input.now ?? Date.now;
	const registry = input.mcpAuthorityRegistry ?? hermesMcpAuthorityRegistry;
	const startedAt = now();
	const { record } = input.sessions.getOrCreate({
		sessionKey: input.request.sessionKey,
		profileId: input.request.profileId,
		now: startedAt,
		telclaudeSessionId: input.request.telclaudeSessionId,
	});
	const { mcpAuthority: mcpAuthorityOptions, ...requestWithoutPrivateAuthority } = input.request;
	let mcpAuthorityHandle: string | undefined;
	let runtimeRequest: HermesRuntimeRequest;
	try {
		const mcpAuthority = buildPrivateMcpAuthority(input.request, mcpAuthorityOptions);
		const connection: TelclaudeMcpAuthorityConnection = {
			sessionKey: input.request.sessionKey,
			profileId: input.request.profileId,
			endpointId: mcpAuthority.endpointId,
			networkNamespace: mcpAuthority.networkNamespace,
		};
		const grant = registry.register({
			connection,
			authority: mcpAuthority,
			nowMs: startedAt,
			ttlMs: mcpAuthorityOptions?.ttlMs,
		});
		mcpAuthorityHandle = grant.handle;
		runtimeRequest = {
			...requestWithoutPrivateAuthority,
			telclaudeSessionId: record.telclaudeSessionId,
			...(input.request.isNewSession ? {} : { resumeHermesSessionId: record.hermesSessionId }),
			mcpAuthority: {
				handle: grant.handle,
				connection,
				expiresAtMs: grant.expiresAtMs,
			},
		};
	} catch (error) {
		yield {
			type: "done",
			result: {
				response: "",
				success: false,
				error: error instanceof Error ? error.message : String(error),
				costUsd: 0,
				numTurns: 1,
				durationMs: Math.max(0, now() - startedAt),
			},
		};
		return;
	}

	let response = "";
	let sawDone = false;

	try {
		for await (const event of input.runtime.run(runtimeRequest)) {
			switch (event.type) {
				case "session":
					input.sessions.updateHermesSessionId(
						input.request.sessionKey,
						input.request.profileId,
						event.hermesSessionId,
						now(),
					);
					break;
				case "text_delta":
					response += event.text;
					yield { type: "text", content: event.text };
					break;
				case "tool_use":
					yield { type: "tool_use", toolName: event.toolName, input: event.input };
					break;
				case "tool_result":
					yield { type: "tool_result", toolName: event.toolName, output: event.output };
					break;
				case "done":
					sawDone = true;
					yield {
						type: "done",
						result: {
							response: event.response ?? response,
							success: event.success ?? true,
							...(event.error ? { error: event.error } : {}),
							costUsd: event.costUsd ?? 0,
							numTurns: event.numTurns ?? 1,
							durationMs: event.durationMs ?? Math.max(0, now() - startedAt),
						},
					};
					break;
			}
		}
		if (!sawDone) {
			yield {
				type: "done",
				result: {
					response,
					success: true,
					costUsd: 0,
					numTurns: 1,
					durationMs: Math.max(0, now() - startedAt),
				},
			};
		}
	} catch (error) {
		yield {
			type: "done",
			result: {
				response,
				success: false,
				error: error instanceof Error ? error.message : String(error),
				costUsd: 0,
				numTurns: 1,
				durationMs: Math.max(0, now() - startedAt),
			},
		};
	} finally {
		if (mcpAuthorityHandle) {
			registry.revoke(mcpAuthorityHandle, "Hermes private runtime completed", now());
		}
	}
}

function buildPrivateMcpAuthority(
	request: HermesPrivateRuntimeRequest,
	options: HermesPrivateMcpAuthorityOptions | undefined,
): TelclaudeMcpAuthority {
	const domain = options?.domain ?? "private";
	const memorySource = options?.memorySource ?? defaultMemorySource(domain, request.profileId);
	return {
		actorId: runtimeActorId(request),
		profileId: request.profileId,
		domain,
		memorySource,
		writableNamespace: options?.writableNamespace ?? `${domain}:${request.profileId}`,
		providerScopes: options?.providerScopes ?? [],
		outboundChannels: options?.outboundChannels ?? [],
		endpointId: options?.endpointId ?? DEFAULT_PRIVATE_MCP_ENDPOINT_ID,
		networkNamespace: options?.networkNamespace ?? DEFAULT_PRIVATE_MCP_NETWORK_NAMESPACE,
	};
}

function defaultMemorySource(domain: TelclaudeMcpDomain, profileId: string): MemorySource {
	return domain === "social" || domain === "public" ? "social" : telegramMemorySource(profileId);
}

function runtimeActorId(request: HermesPrivateRuntimeRequest): string {
	const identity = request.identity;
	return String(identity.actorId ?? identity.userId ?? identity.chatId ?? request.sessionKey);
}

export function buildHermesCliProbeInvocation(input: {
	hermesBin: string;
	hermesHome: string;
	cwd: string;
	prompt?: string;
}): HermesLaunchInvocation {
	return {
		command: input.hermesBin,
		args: ["-z", input.prompt ?? "telclaude probe ok"],
		cwd: input.cwd,
		env: {
			HERMES_HOME: input.hermesHome,
			NO_COLOR: "1",
		},
	};
}

export async function runHermesCliHeadlessProbe(input: {
	allowRun: boolean;
	invocation: HermesLaunchInvocation;
	runProcess?: (
		invocation: HermesLaunchInvocation,
	) => Promise<{ exitCode: number; stdout: string; stderr: string }>;
}): Promise<HermesCliProbeReport> {
	const findings = findHermesLaunchSecretFindings(input.invocation);
	if (findings.length > 0) {
		return probeReport({
			status: "fail",
			ran: false,
			summary: "Hermes CLI probe launch contains forbidden credential material",
			findings,
		});
	}
	if (!input.allowRun) {
		return probeReport({
			status: "pending",
			ran: false,
			summary: "Hermes CLI probe requires --allow-run",
			findings,
		});
	}
	if (!input.runProcess) {
		return probeReport({
			status: "pending",
			ran: false,
			summary: "Hermes CLI probe runner is not configured",
			findings,
		});
	}

	const result = await input.runProcess(input.invocation);
	const status = result.exitCode === 0 ? "pass" : "fail";
	return probeReport({
		status,
		ran: true,
		summary:
			status === "pass"
				? "Hermes CLI oneshot probe completed successfully"
				: "Hermes CLI oneshot probe failed",
		exitCode: result.exitCode,
		stdoutPreview: preview(redactHermesRuntimeText(result.stdout)),
		stderrPreview: preview(redactHermesRuntimeText(result.stderr)),
		findings,
	});
}

export function findHermesLaunchSecretFindings(
	invocation: HermesLaunchInvocation,
): HermesLaunchSecretFinding[] {
	const findings: HermesLaunchSecretFinding[] = [];
	for (const [key, value] of Object.entries(invocation.env)) {
		if (isForbiddenCredentialKey(key)) {
			findings.push({
				location: `env.${key}`,
				reason: "forbidden credential environment key",
			});
			continue;
		}
		if (containsCredentialValue(value)) {
			findings.push({
				location: `env.${key}`,
				reason: "credential-like environment value",
			});
		}
	}
	for (const [index, arg] of invocation.args.entries()) {
		if (containsCredentialValue(arg)) {
			findings.push({
				location: `argv[${index}]`,
				reason: "credential-like process argument",
			});
		}
	}
	return findings;
}

export function redactHermesRuntimeText(value: string): string {
	return redactSecrets(value);
}

function probeReport(
	input: Omit<HermesCliProbeReport, "schemaVersion" | "probeId">,
): HermesCliProbeReport {
	return {
		schemaVersion: HERMES_PROBE_RESULT_SCHEMA_VERSION,
		probeId: "execution.cli_headless" as const,
		...input,
	};
}

function isForbiddenCredentialKey(key: string): boolean {
	return /(^|_)(API_KEY|AUTH_TOKEN|OAUTH_TOKEN|TOKEN|KEY|PASSWORD|SECRET|COOKIE|CREDENTIALS?)(_|$)/i.test(
		key,
	);
}

function containsCredentialValue(value: string): boolean {
	return filterOutput(value).blocked;
}

function preview(value: string, maxLength = 400): string {
	return value.length <= maxLength ? value : `${value.slice(0, maxLength)}...`;
}
