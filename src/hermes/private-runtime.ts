import { spawn } from "node:child_process";
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
export const DEFAULT_HERMES_CLI_HEADLESS_EVIDENCE_PATH =
	"artifacts/hermes/probes/execution-cli-headless.json";
const DEFAULT_HERMES_CLI_PROBE_TOKEN = "TELCLAUDE_HERMES_CLI_OK";
const DEFAULT_PRIVATE_MCP_ENDPOINT_ID = "telclaude-private-runtime";
const DEFAULT_PRIVATE_MCP_NETWORK_NAMESPACE = "telclaude-private";
const DEFAULT_HERMES_PROBE_TIMEOUT_MS = 120_000;
const MAX_CAPTURED_PROCESS_OUTPUT_BYTES = 1_000_000;
const HERMES_RELAY_ANTHROPIC_BASE_URL_ENV = "ANTHROPIC_BASE_URL";
const HERMES_RELAY_ANTHROPIC_AUTH_ENV = "ANTHROPIC_API_KEY";
const HERMES_RELAY_ANTHROPIC_PROXY_PATH = "/v1/anthropic-proxy";

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
	invocation?: {
		command: string;
		args: string[];
		cwd: string;
		envKeys: string[];
	};
	modelProvider?: {
		baseUrl: string;
		baseUrlHost: string;
		authEnvKey: typeof HERMES_RELAY_ANTHROPIC_AUTH_ENV;
		authScope: "relay-anthropic-proxy";
		tokenScoping: "static-shared" | "peer-bound";
	};
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
	env?: NodeJS.ProcessEnv;
}): HermesLaunchInvocation {
	const sourceEnv = input.env ?? {};
	return {
		command: input.hermesBin,
		args: ["-z", input.prompt ?? `Reply with exactly ${DEFAULT_HERMES_CLI_PROBE_TOKEN}`],
		cwd: input.cwd,
		env: {
			HERMES_HOME: input.hermesHome,
			NO_COLOR: "1",
			...hermesRelayModelEnv(sourceEnv),
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
			invocation: probeInvocation(input.invocation),
			modelProvider: probeModelProvider(input.invocation),
			findings,
		});
	}
	if (!input.allowRun) {
		return probeReport({
			status: "pending",
			ran: false,
			summary: "Hermes CLI probe requires --allow-run",
			invocation: probeInvocation(input.invocation),
			modelProvider: probeModelProvider(input.invocation),
			findings,
		});
	}
	if (!input.runProcess) {
		return probeReport({
			status: "pending",
			ran: false,
			summary: "Hermes CLI probe runner is not configured",
			invocation: probeInvocation(input.invocation),
			modelProvider: probeModelProvider(input.invocation),
			findings,
		});
	}

	const result = await input.runProcess(input.invocation);
	const runtimeFailure = hermesCliRuntimeFailure(result.stdout, result.stderr);
	const expectedToken = hermesCliExpectedProofToken(input.invocation);
	const hasPositiveProof = expectedToken ? result.stdout.includes(expectedToken) : false;
	const status = result.exitCode === 0 && !runtimeFailure && hasPositiveProof ? "pass" : "fail";
	return probeReport({
		status,
		ran: true,
		summary:
			status === "pass"
				? "Hermes CLI oneshot probe completed successfully"
				: runtimeFailure
					? `Hermes CLI oneshot probe reported runtime failure: ${runtimeFailure}`
					: result.exitCode === 0 && !hasPositiveProof
						? `Hermes CLI oneshot probe did not return expected proof token: ${expectedToken ?? DEFAULT_HERMES_CLI_PROBE_TOKEN}`
						: "Hermes CLI oneshot probe failed",
		invocation: probeInvocation(input.invocation),
		modelProvider: probeModelProvider(input.invocation),
		exitCode: result.exitCode,
		stdoutPreview: preview(redactHermesRuntimeText(result.stdout)),
		stderrPreview: preview(redactHermesRuntimeText(result.stderr)),
		findings,
	});
}

export async function runHermesLaunchInvocation(
	invocation: HermesLaunchInvocation,
	options: { timeoutMs?: number } = {},
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
	const timeoutMs = normalizeProbeTimeoutMs(options.timeoutMs);
	return new Promise((resolve) => {
		let settled = false;
		let timedOut = false;
		let stdout = "";
		let stderr = "";
		const child = spawn(invocation.command, invocation.args, {
			cwd: invocation.cwd,
			env: {
				PATH: process.env.PATH ?? "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin",
				...invocation.env,
			},
			stdio: ["ignore", "pipe", "pipe"],
		});

		const timer = setTimeout(() => {
			timedOut = true;
			child.kill("SIGTERM");
			setTimeout(() => {
				if (!settled) child.kill("SIGKILL");
			}, 2_000).unref();
		}, timeoutMs);
		timer.unref();

		child.stdout?.on("data", (chunk: Buffer) => {
			stdout = appendBoundedOutput(stdout, chunk);
		});
		child.stderr?.on("data", (chunk: Buffer) => {
			stderr = appendBoundedOutput(stderr, chunk);
		});
		child.on("error", (error) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			resolve({
				exitCode: 127,
				stdout,
				stderr: appendLine(stderr, `failed to launch Hermes probe: ${error.message}`),
			});
		});
		child.on("close", (code, signal) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			resolve({
				exitCode: timedOut ? 124 : (code ?? 1),
				stdout,
				stderr: timedOut
					? appendLine(stderr, `Hermes probe timed out after ${timeoutMs}ms`)
					: signal
						? appendLine(stderr, `Hermes probe terminated by ${signal}`)
						: stderr,
			});
		});
	});
}

export function findHermesLaunchSecretFindings(
	invocation: HermesLaunchInvocation,
): HermesLaunchSecretFinding[] {
	const findings: HermesLaunchSecretFinding[] = [];
	const relayModelConfigured = isRelayAnthropicProxyUrl(
		invocation.env[HERMES_RELAY_ANTHROPIC_BASE_URL_ENV],
	);
	for (const [key, value] of Object.entries(invocation.env)) {
		if (key === HERMES_RELAY_ANTHROPIC_BASE_URL_ENV) {
			if (value && !relayModelConfigured) {
				findings.push({
					location: `env.${key}`,
					reason: "model base URL must point at the relay Anthropic proxy",
				});
			}
			continue;
		}
		if (key === HERMES_RELAY_ANTHROPIC_AUTH_ENV && relayModelConfigured) {
			if (containsRawModelProviderCredential(value)) {
				findings.push({
					location: `env.${key}`,
					reason: "raw model-provider credential is forbidden",
				});
			}
			continue;
		}
		if (isForbiddenCredentialKey(key)) {
			findings.push({
				location: `env.${key}`,
				reason: "forbidden credential environment key",
			});
			continue;
		}
		if (containsRawModelProviderCredential(value) || containsCredentialValue(value)) {
			findings.push({
				location: `env.${key}`,
				reason: "credential-like environment value",
			});
		}
	}
	for (const [index, arg] of invocation.args.entries()) {
		if (containsRawModelProviderCredential(arg) || containsCredentialValue(arg)) {
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

function hermesCliRuntimeFailure(stdout: string, stderr: string): string | null {
	const combined = `${stdout}\n${stderr}`;
	const patterns: ReadonlyArray<[RegExp, string]> = [
		[/API call failed after \d+ retries/i, "model API call failed"],
		[/No inference provider configured/i, "inference provider is not configured"],
		[/Anthropic credentials not configured/i, "relay Anthropic credentials are not configured"],
	];
	for (const [pattern, reason] of patterns) {
		if (pattern.test(combined)) return reason;
	}
	return null;
}

function hermesCliExpectedProofToken(invocation: HermesLaunchInvocation): string | null {
	const prompt = invocation.args[1] ?? "";
	const match = prompt.match(/TELCLAUDE_HERMES_CLI_OK|HERMES_OK_[A-Za-z0-9_-]+/);
	return match?.[0] ?? DEFAULT_HERMES_CLI_PROBE_TOKEN;
}

function probeReport(
	input: Omit<HermesCliProbeReport, "schemaVersion" | "probeId">,
): HermesCliProbeReport {
	const report: HermesCliProbeReport = {
		schemaVersion: HERMES_PROBE_RESULT_SCHEMA_VERSION,
		probeId: "execution.cli_headless" as const,
		...input,
	};
	if (report.modelProvider === undefined) {
		delete report.modelProvider;
	}
	return report;
}

function probeInvocation(
	invocation: HermesLaunchInvocation,
): NonNullable<HermesCliProbeReport["invocation"]> {
	return {
		command: redactHermesRuntimeText(invocation.command),
		args: invocation.args.map((arg) => redactHermesRuntimeText(arg)),
		cwd: redactHermesRuntimeText(invocation.cwd),
		envKeys: Object.keys(invocation.env).sort(),
	};
}

function probeModelProvider(
	invocation: HermesLaunchInvocation,
): HermesCliProbeReport["modelProvider"] | undefined {
	const baseUrl = invocation.env[HERMES_RELAY_ANTHROPIC_BASE_URL_ENV];
	const authToken = invocation.env[HERMES_RELAY_ANTHROPIC_AUTH_ENV];
	if (!baseUrl || !authToken || !isRelayAnthropicProxyUrl(baseUrl)) return undefined;
	const parsed = new URL(baseUrl);
	return {
		baseUrl,
		baseUrlHost: parsed.hostname,
		authEnvKey: HERMES_RELAY_ANTHROPIC_AUTH_ENV,
		authScope: "relay-anthropic-proxy",
		tokenScoping: "static-shared",
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

function containsRawModelProviderCredential(value: string): boolean {
	return /\b(?:sk-ant|sk-proj|sk-[A-Za-z0-9])[A-Za-z0-9_-]{8,}\b/.test(value);
}

function hermesRelayModelEnv(env: NodeJS.ProcessEnv): Record<string, string> {
	const baseUrl = env[HERMES_RELAY_ANTHROPIC_BASE_URL_ENV]?.trim();
	const authToken = env[HERMES_RELAY_ANTHROPIC_AUTH_ENV]?.trim();
	if (!baseUrl && !authToken) return {};
	return {
		...(baseUrl ? { [HERMES_RELAY_ANTHROPIC_BASE_URL_ENV]: baseUrl } : {}),
		...(authToken ? { [HERMES_RELAY_ANTHROPIC_AUTH_ENV]: authToken } : {}),
	};
}

function isRelayAnthropicProxyUrl(value: string | undefined): boolean {
	if (!value) return false;
	try {
		const parsed = new URL(value);
		return (
			(parsed.protocol === "http:" || parsed.protocol === "https:") &&
			parsed.pathname.replace(/\/+$/, "") === HERMES_RELAY_ANTHROPIC_PROXY_PATH &&
			!isDirectModelProviderHost(parsed.hostname)
		);
	} catch {
		return false;
	}
}

function isDirectModelProviderHost(hostname: string): boolean {
	return new Set([
		"api.anthropic.com",
		"api.openai.com",
		"generativelanguage.googleapis.com",
		"openrouter.ai",
		"api.x.ai",
	]).has(hostname.toLowerCase());
}

function preview(value: string, maxLength = 400): string {
	return value.length <= maxLength ? value : `${value.slice(0, maxLength)}...`;
}

function normalizeProbeTimeoutMs(value: number | undefined): number {
	if (value === undefined) return DEFAULT_HERMES_PROBE_TIMEOUT_MS;
	if (!Number.isFinite(value) || value <= 0) return DEFAULT_HERMES_PROBE_TIMEOUT_MS;
	return Math.min(Math.trunc(value), DEFAULT_HERMES_PROBE_TIMEOUT_MS);
}

function appendBoundedOutput(current: string, chunk: Buffer): string {
	if (current.length >= MAX_CAPTURED_PROCESS_OUTPUT_BYTES) return current;
	const next = `${current}${chunk.toString("utf8")}`;
	return next.length <= MAX_CAPTURED_PROCESS_OUTPUT_BYTES
		? next
		: next.slice(0, MAX_CAPTURED_PROCESS_OUTPUT_BYTES);
}

function appendLine(current: string, line: string): string {
	return current ? `${current}\n${line}` : line;
}
