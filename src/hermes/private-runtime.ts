import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import type { PermissionTier } from "../config/config.js";
import type { InternalResponseProof } from "../internal-auth.js";
import { telegramMemorySource } from "../memory/source.js";
import type { MemorySource } from "../memory/types.js";
import {
	mintOpenAiCodexPeerBoundProxyToken,
	OPENAI_CODEX_CONTAINED_RELAY_TOKEN_TTL_MS,
} from "../relay/openai-codex-proxy.js";
import {
	extractOpenAiCodexRelayProofToken,
	OPENAI_CODEX_RELAY_PROOF_SCHEMA_VERSION,
	OPENAI_CODEX_RELAY_PROOF_SOURCE,
	OPENAI_CODEX_RESPONSES_PATH,
	type OpenAiCodexRelayProof,
	openAiCodexRelayProofSignatureFailure,
	openAiCodexRelayProofTokenSha256,
} from "../relay/openai-codex-relay-proof.js";
import type { StreamChunk } from "../runtime/stream.js";
import { filterOutput, redactSecrets } from "../security/output-filter.js";
import type { HermesSignedEvidenceValidationOptions } from "./attestation-validation.js";
import {
	hermesMcpAuthorityRegistry,
	type TelclaudeMcpAuthorityConnection,
	type TelclaudeMcpAuthorityRegistry,
} from "./mcp/authority-registry.js";
import type {
	TelclaudeMcpAuthority,
	TelclaudeMcpCapabilityScope,
	TelclaudeMcpDomain,
} from "./mcp/bridge.js";
import { DEFAULT_HERMES_CONTAINED_IP, DEFAULT_HERMES_RELAY_IP } from "./runtime-network.js";
import type { HermesSessionMap } from "./session-map.js";

export const HERMES_PROBE_RESULT_SCHEMA_VERSION = "telclaude.hermes.probe-result.v1";
export const DEFAULT_HERMES_CLI_HEADLESS_EVIDENCE_PATH =
	"artifacts/hermes/probes/execution-cli-headless.json";
const DEFAULT_HERMES_CLI_PROBE_TOKEN = "TELCLAUDE_HERMES_CLI_OK";
const DEFAULT_PRIVATE_MCP_ENDPOINT_ID = "telclaude-private-runtime";
const DEFAULT_PRIVATE_MCP_NETWORK_NAMESPACE = "telclaude-private";
const DEFAULT_HERMES_PROBE_TIMEOUT_MS = 120_000;
const MAX_CAPTURED_PROCESS_OUTPUT_BYTES = 1_000_000;
const HERMES_RELAY_OPENAI_CODEX_BASE_URL_ENV = "HERMES_CODEX_BASE_URL";
const HERMES_RELAY_OPENAI_CODEX_AUTH_ENV = "TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN";
const HERMES_RELAY_OPENAI_CODEX_PROXY_PATH = "/v1/openai-codex-proxy";
const HERMES_RELAY_OPENAI_CODEX_PROXY_URL = "http://telclaude:8790/v1/openai-codex-proxy";
const HERMES_RELAY_OPENAI_CODEX_PROVIDER = "openai-codex";
const HERMES_RELAY_OPENAI_CODEX_POOL_SOURCE = "manual:telclaude-relay";
const HERMES_INFERENCE_PROVIDER_ENV = "HERMES_INFERENCE_PROVIDER";
const HERMES_INFERENCE_MODEL_ENV = "HERMES_INFERENCE_MODEL";
const HERMES_CLI_HEADLESS_PROVENANCE_RUNNER = "telclaude-hermes-cli-probe";
const HERMES_CLI_HEADLESS_PROVENANCE_SOURCE = "live-allow-run";
const HERMES_CLI_HEADLESS_RUNTIME_PROVENANCE_SOURCE = "docker-inspect-container-dns-and-relay-peer";
const HERMES_CLI_HEADLESS_RELAY_PROOF_SCHEMA_VERSION = OPENAI_CODEX_RELAY_PROOF_SCHEMA_VERSION;
const HERMES_CLI_HEADLESS_RELAY_PROOF_SOURCE = OPENAI_CODEX_RELAY_PROOF_SOURCE;
const HERMES_CODEX_RESPONSES_PATH = OPENAI_CODEX_RESPONSES_PATH;

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

export type HermesRuntimeMcpAuthorityActivation = {
	activate(input: {
		readonly authorityHandle: string;
		readonly connection: TelclaudeMcpAuthorityConnection;
		readonly nowMs?: number;
		readonly ttlMs?: number;
	}): { readonly id: string; readonly expiresAtMs: number };
	revoke(id: string, reason?: string, nowMs?: number): boolean;
};

export type HermesPrivateMcpAuthorityOptions = {
	readonly domain?: TelclaudeMcpDomain;
	readonly memorySource?: MemorySource;
	readonly writableNamespace?: string;
	readonly providerScopes?: readonly string[];
	readonly outboundChannels?: readonly string[];
	readonly capabilityScopes?: readonly TelclaudeMcpCapabilityScope[];
	readonly turnConversationRef?: string;
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
	mcpAuthority?: HermesPrivateMcpAuthorityOptions | false;
};

export type HermesLaunchInvocation = {
	command: string;
	args: string[];
	cwd: string;
	env: Record<string, string>;
	authSetup?: {
		openAiCodexRelayToken?: string;
	};
};

export type HermesLaunchSecretFinding = {
	location: string;
	reason: string;
};

export type HermesCliHeadlessReadinessGate = {
	name: string;
	status: "pass" | "fail";
	detail: string;
};

export type HermesCliHeadlessReadiness = {
	status: "pass" | "fail";
	gates: HermesCliHeadlessReadinessGate[];
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
		provider: "openai-codex";
		baseUrl: string;
		baseUrlHost: string;
		model: string;
		modelSource: `env:${typeof HERMES_INFERENCE_MODEL_ENV}` | "missing";
		authLocation: "hermes-auth-store:openai-codex";
		authScope: "relay-openai-codex-subscription-proxy";
		tokenScoping: "static-shared" | "peer-bound";
		auxiliaryAuthSource?: typeof HERMES_RELAY_OPENAI_CODEX_POOL_SOURCE;
		auxiliaryBaseUrl?: string;
		auxiliaryBaseUrlHost?: string;
		refreshTokenPolicy?: "non-refreshable-placeholder";
	};
	provenance?: {
		runner: typeof HERMES_CLI_HEADLESS_PROVENANCE_RUNNER;
		source: typeof HERMES_CLI_HEADLESS_PROVENANCE_SOURCE;
		startedAt: string;
		endedAt: string;
		expectedProofToken: string;
		proofTokenObserved: boolean;
		invocationSha256: string;
		stdoutSha256: string;
		stderrSha256: string;
		runtimeSha256: string;
		relayProofSha256: string;
	};
	exitCode?: number;
	stdoutPreview?: string;
	stderrPreview?: string;
	readiness?: HermesCliHeadlessReadiness;
	runtime?: {
		kind: "contained-docker";
		containerName: string;
		networkName: "telclaude-hermes-private";
		containerId: string;
		image: string;
		imageDigest: `sha256:${string}`;
		hostname: string;
		relayHost: "telclaude";
		relayResolvedAddress: string;
		containerIpAddress: string;
		observedPeerAddress: string;
		provenanceSource: typeof HERMES_CLI_HEADLESS_RUNTIME_PROVENANCE_SOURCE;
	};
	relayProof?: {
		schemaVersion: typeof HERMES_CLI_HEADLESS_RELAY_PROOF_SCHEMA_VERSION;
		source: typeof HERMES_CLI_HEADLESS_RELAY_PROOF_SOURCE;
		requestId: string;
		method: "POST";
		path: typeof HERMES_CODEX_RESPONSES_PATH;
		observedPeerAddress: string;
		upstreamStatus: number;
		model: string;
		requestBodySha256: `sha256:${string}`;
		proofTokenSha256?: `sha256:${string}`;
		observedAt: string;
		signature: InternalResponseProof;
	};
	findings: HermesLaunchSecretFinding[];
};

type HermesCliRuntimeEvidence = NonNullable<HermesCliProbeReport["runtime"]>;
type HermesCliRelayProof = NonNullable<HermesCliProbeReport["relayProof"]>;

type HermesLaunchResult = {
	exitCode: number;
	stdout: string;
	stderr: string;
	startedAt?: string;
	endedAt?: string;
	runtime?: HermesCliRuntimeEvidence;
	relayProof?: HermesCliRelayProof;
};

export async function* executeHermesPrivateRuntime(input: {
	runtime: HermesRuntimeAdapter;
	sessions: HermesSessionMap;
	request: HermesPrivateRuntimeRequest;
	mcpAuthorityRegistry?: TelclaudeMcpAuthorityRegistry;
	mcpAuthorityActivation?: HermesRuntimeMcpAuthorityActivation;
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
	let mcpAuthorityActivationId: string | undefined;
	let runtimeRequest: HermesRuntimeRequest;
	try {
		runtimeRequest = {
			...requestWithoutPrivateAuthority,
			telclaudeSessionId: record.telclaudeSessionId,
			...(input.request.isNewSession ? {} : { resumeHermesSessionId: record.hermesSessionId }),
		};
		if (mcpAuthorityOptions !== false) {
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
			const activation = input.mcpAuthorityActivation?.activate({
				authorityHandle: grant.handle,
				connection,
				nowMs: startedAt,
				ttlMs: runtimeAuthorityActivationTtlMs(input.request, mcpAuthorityOptions),
			});
			mcpAuthorityActivationId = activation?.id;
			runtimeRequest.mcpAuthority = {
				handle: grant.handle,
				connection,
				expiresAtMs: grant.expiresAtMs,
			};
		}
	} catch (error) {
		if (mcpAuthorityActivationId) {
			tryRevokeMcpAuthorityActivation(
				input.mcpAuthorityActivation,
				mcpAuthorityActivationId,
				"Hermes private runtime setup failed",
				now(),
			);
		}
		if (mcpAuthorityHandle) {
			registry.revoke(mcpAuthorityHandle, "Hermes private runtime setup failed", now());
		}
		const message = redactHermesRuntimeText(error instanceof Error ? error.message : String(error));
		yield {
			type: "done",
			result: {
				response: "",
				success: false,
				error: message,
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
					yield { type: "text", content: redactHermesRuntimeText(event.text) };
					break;
				case "tool_use":
					yield {
						type: "tool_use",
						toolName: event.toolName,
						input: redactHermesRuntimeValue(event.input),
					};
					break;
				case "tool_result":
					yield {
						type: "tool_result",
						toolName: event.toolName,
						output: redactHermesRuntimeValue(event.output),
					};
					break;
				case "done":
					sawDone = true;
					yield {
						type: "done",
						result: {
							response: redactHermesRuntimeText(event.response ?? response),
							success: event.success ?? true,
							...(event.error ? { error: redactHermesRuntimeText(event.error) } : {}),
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
					response: redactHermesRuntimeText(response),
					success: true,
					costUsd: 0,
					numTurns: 1,
					durationMs: Math.max(0, now() - startedAt),
				},
			};
		}
	} catch (error) {
		const message = redactHermesRuntimeText(error instanceof Error ? error.message : String(error));
		yield {
			type: "done",
			result: {
				response: redactHermesRuntimeText(response),
				success: false,
				error: message,
				costUsd: 0,
				numTurns: 1,
				durationMs: Math.max(0, now() - startedAt),
			},
		};
	} finally {
		if (mcpAuthorityActivationId) {
			tryRevokeMcpAuthorityActivation(
				input.mcpAuthorityActivation,
				mcpAuthorityActivationId,
				"Hermes private runtime completed",
				now(),
			);
		}
		if (mcpAuthorityHandle) {
			registry.revoke(mcpAuthorityHandle, "Hermes private runtime completed", now());
		}
	}
}

function tryRevokeMcpAuthorityActivation(
	activation: HermesRuntimeMcpAuthorityActivation | undefined,
	id: string,
	reason: string,
	nowMs: number,
): void {
	try {
		activation?.revoke(id, reason, nowMs);
	} catch {
		// Registry revocation is the durable cleanup; activation adapters must not block it.
	}
}

function runtimeAuthorityActivationTtlMs(
	request: HermesPrivateRuntimeRequest,
	options: HermesPrivateMcpAuthorityOptions | undefined,
): number | undefined {
	if (options?.ttlMs !== undefined) return options.ttlMs;
	if (!Number.isFinite(request.timeoutMs) || request.timeoutMs <= 0) return undefined;
	return Math.trunc(request.timeoutMs) + 30_000;
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
		...(options?.capabilityScopes?.length ? { capabilityScopes: options.capabilityScopes } : {}),
		...(options?.turnConversationRef ? { turnConversationRef: options.turnConversationRef } : {}),
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
	const relayModel = hermesRelayModelConfig(sourceEnv);
	return {
		command: input.hermesBin,
		args: ["chat", "-q", input.prompt ?? `Reply with exactly ${DEFAULT_HERMES_CLI_PROBE_TOKEN}`],
		cwd: input.cwd,
		env: {
			HERMES_HOME: input.hermesHome,
			NO_COLOR: "1",
			...relayModel.env,
		},
		...(relayModel.openAiCodexRelayToken
			? { authSetup: { openAiCodexRelayToken: relayModel.openAiCodexRelayToken } }
			: {}),
	};
}

export async function runHermesCliHeadlessProbe(input: {
	allowRun: boolean;
	invocation: HermesLaunchInvocation;
	readiness?: HermesCliHeadlessReadiness;
	runProcess?: (invocation: HermesLaunchInvocation) => Promise<HermesLaunchResult>;
}): Promise<HermesCliProbeReport> {
	const findings = findHermesLaunchSecretFindings(input.invocation);
	const readiness =
		input.readiness ?? evaluateHermesCliHeadlessReadiness(input.invocation, findings);
	if (findings.length > 0) {
		return probeReport({
			status: "fail",
			ran: false,
			summary: "Hermes CLI probe launch contains forbidden credential material",
			invocation: probeInvocation(input.invocation),
			modelProvider: probeModelProvider(input.invocation),
			readiness,
			findings,
		});
	}
	if (readiness.status === "fail") {
		return probeReport({
			status: "fail",
			ran: false,
			summary: "Hermes CLI probe launch failed readiness checks",
			invocation: probeInvocation(input.invocation),
			modelProvider: probeModelProvider(input.invocation),
			readiness,
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
			readiness,
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
			readiness,
			findings,
		});
	}

	const probeStartedAt = new Date().toISOString();
	const result = await input.runProcess(input.invocation);
	const probeEndedAt = new Date().toISOString();
	const startedAt = result.startedAt ?? probeStartedAt;
	const endedAt = result.endedAt ?? probeEndedAt;
	const runtimeFailure = hermesCliRuntimeFailure(result.stdout, result.stderr);
	const expectedToken = hermesCliExpectedProofToken(input.invocation);
	const hasPositiveProof = expectedToken ? result.stdout.includes(expectedToken) : false;
	const stdout = redactHermesRuntimeText(result.stdout);
	const stderr = redactHermesRuntimeText(result.stderr);
	const invocation = probeInvocation(input.invocation);
	const modelProvider = probeModelProvider(input.invocation);
	const relayProofFailure = hermesCliRelayProofFailure(result.relayProof, {
		expectedProofToken: expectedToken,
		modelProvider,
		runtime: result.runtime,
		startedAt,
		endedAt,
	});
	const status =
		result.exitCode === 0 && !runtimeFailure && hasPositiveProof && !relayProofFailure
			? "pass"
			: "fail";
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
						: relayProofFailure
							? `Hermes CLI oneshot probe lacks relay-backed model proof: ${relayProofFailure}`
							: "Hermes CLI oneshot probe failed",
		invocation,
		modelProvider,
		exitCode: result.exitCode,
		stdoutPreview: stdout,
		stderrPreview: stderr,
		...(result.runtime ? { runtime: result.runtime } : {}),
		...(result.relayProof ? { relayProof: result.relayProof } : {}),
		provenance: {
			runner: HERMES_CLI_HEADLESS_PROVENANCE_RUNNER,
			source: HERMES_CLI_HEADLESS_PROVENANCE_SOURCE,
			startedAt,
			endedAt,
			expectedProofToken: expectedToken ?? DEFAULT_HERMES_CLI_PROBE_TOKEN,
			proofTokenObserved: hasPositiveProof,
			invocationSha256: sha256Digest(stableStringify(invocation)),
			stdoutSha256: sha256Digest(stdout),
			stderrSha256: sha256Digest(stderr),
			runtimeSha256: sha256Digest(stableStringify(result.runtime ?? null)),
			relayProofSha256: sha256Digest(stableStringify(result.relayProof ?? null)),
		},
		readiness,
		findings,
	});
}

export function evaluateHermesCliHeadlessReadiness(
	invocation: HermesLaunchInvocation,
	findings: readonly HermesLaunchSecretFinding[] = findHermesLaunchSecretFindings(invocation),
): HermesCliHeadlessReadiness {
	const gates: HermesCliHeadlessReadinessGate[] = [];
	gates.push(
		invocation.command.trim()
			? passReadiness("command.present", "Hermes command is configured")
			: failReadiness("command.present", "Hermes command is missing"),
	);
	gates.push(
		fs.existsSync(invocation.cwd)
			? passReadiness("cwd.exists", "Hermes probe cwd exists")
			: failReadiness("cwd.exists", "Hermes probe cwd is missing"),
	);
	gates.push(
		invocation.env[HERMES_INFERENCE_PROVIDER_ENV] === HERMES_RELAY_OPENAI_CODEX_PROVIDER
			? passReadiness("provider.openaiCodex", "HERMES_INFERENCE_PROVIDER is openai-codex")
			: failReadiness("provider.openaiCodex", "HERMES_INFERENCE_PROVIDER must be openai-codex"),
	);
	gates.push(
		isRelayOpenAiCodexProxyUrl(invocation.env[HERMES_RELAY_OPENAI_CODEX_BASE_URL_ENV])
			? passReadiness("relay.baseUrl", "HERMES_CODEX_BASE_URL points at Telclaude relay proxy")
			: failReadiness(
					"relay.baseUrl",
					"HERMES_CODEX_BASE_URL must be http://telclaude:8790/v1/openai-codex-proxy",
				),
	);
	gates.push(
		invocation.env[HERMES_INFERENCE_MODEL_ENV]?.trim()
			? passReadiness("model.present", "HERMES_INFERENCE_MODEL is configured")
			: failReadiness("model.present", "HERMES_INFERENCE_MODEL is missing"),
	);
	gates.push(
		invocation.authSetup?.openAiCodexRelayToken?.trim()
			? passReadiness(
					"auth.relayToken",
					"relay-scoped Codex proxy token will be written to auth store",
				)
			: failReadiness("auth.relayToken", "TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN is missing"),
	);
	gates.push(
		findings.length === 0
			? passReadiness(
					"launch.noForbiddenMaterial",
					"launch environment and argv contain no forbidden credential material",
				)
			: failReadiness(
					"launch.noForbiddenMaterial",
					`launch contains forbidden material: ${findings.map((finding) => finding.location).join(", ")}`,
				),
	);
	return {
		status: gates.every((gate) => gate.status === "pass") ? "pass" : "fail",
		gates,
	};
}

export async function runHermesLaunchInvocation(
	invocation: HermesLaunchInvocation,
	options: { timeoutMs?: number } = {},
): Promise<HermesLaunchResult> {
	const timeoutMs = normalizeProbeTimeoutMs(options.timeoutMs);
	return new Promise((resolve) => {
		let settled = false;
		let timedOut = false;
		let stdout = "";
		let stderr = "";
		const launchEnv: Record<string, string> = {
			PATH: process.env.PATH ?? "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin",
			...invocation.env,
		};
		try {
			prepareHermesLaunchAuthStore(invocation, launchEnv);
		} catch (error) {
			const failedAt = new Date().toISOString();
			resolve(
				hermesLaunchResult({
					exitCode: 126,
					stdout,
					stderr: appendLine(
						stderr,
						`failed to prepare Hermes probe auth store: ${
							error instanceof Error ? error.message : String(error)
						}`,
					),
					hermesHome: launchEnv.HERMES_HOME,
					startedAt: failedAt,
					endedAt: failedAt,
				}),
			);
			return;
		}

		const childStartedAt = new Date().toISOString();
		const child = spawn(invocation.command, invocation.args, {
			cwd: invocation.cwd,
			env: launchEnv,
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
			resolve(
				hermesLaunchResult({
					exitCode: 127,
					stdout,
					stderr: appendLine(stderr, `failed to launch Hermes probe: ${error.message}`),
					hermesHome: launchEnv.HERMES_HOME,
					startedAt: childStartedAt,
					endedAt: new Date().toISOString(),
				}),
			);
		});
		child.on("close", (code, signal) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			resolve(
				hermesLaunchResult({
					exitCode: timedOut ? 124 : (code ?? 1),
					stdout,
					stderr: timedOut
						? appendLine(stderr, `Hermes probe timed out after ${timeoutMs}ms`)
						: signal
							? appendLine(stderr, `Hermes probe terminated by ${signal}`)
							: stderr,
					hermesHome: launchEnv.HERMES_HOME,
					startedAt: childStartedAt,
					endedAt: new Date().toISOString(),
				}),
			);
		});
	});
}

function hermesLaunchResult(input: {
	exitCode: number;
	stdout: string;
	stderr: string;
	hermesHome?: string;
	startedAt?: string;
	endedAt?: string;
}): HermesLaunchResult {
	const runtimeEvidence = readHermesRuntimeEvidence(input.hermesHome);
	const relayProofEvidence = readHermesRelayProofEvidence(input.hermesHome);
	const stderr = [
		input.stderr,
		runtimeEvidence.error ? `failed to read Hermes runtime evidence: ${runtimeEvidence.error}` : "",
		relayProofEvidence.error
			? `failed to read Hermes relay proof evidence: ${relayProofEvidence.error}`
			: "",
	]
		.filter(Boolean)
		.join("\n");
	return {
		exitCode: input.exitCode,
		stdout: input.stdout,
		stderr,
		...(input.startedAt ? { startedAt: input.startedAt } : {}),
		...(input.endedAt ? { endedAt: input.endedAt } : {}),
		...(runtimeEvidence.runtime ? { runtime: runtimeEvidence.runtime } : {}),
		...(relayProofEvidence.relayProof ? { relayProof: relayProofEvidence.relayProof } : {}),
	};
}

function readHermesRuntimeEvidence(hermesHome: string | undefined): {
	runtime?: HermesCliRuntimeEvidence;
	error?: string;
} {
	const normalizedHome = hermesHome?.trim();
	if (!normalizedHome) return {};
	const evidencePath = path.join(normalizedHome, "runtime-evidence.json");
	if (!fs.existsSync(evidencePath)) return {};
	let raw: unknown;
	try {
		raw = JSON.parse(fs.readFileSync(evidencePath, "utf8")) as unknown;
	} catch (error) {
		return {
			error: error instanceof Error ? error.message : String(error),
		};
	}
	try {
		return { runtime: parseHermesRuntimeEvidence(raw) };
	} catch (error) {
		return {
			error: error instanceof Error ? error.message : String(error),
		};
	}
}

function readHermesRelayProofEvidence(hermesHome: string | undefined): {
	relayProof?: HermesCliRelayProof;
	error?: string;
} {
	const normalizedHome = hermesHome?.trim();
	if (!normalizedHome) return {};
	const evidencePath = path.join(normalizedHome, "relay-proof.json");
	if (!fs.existsSync(evidencePath)) return {};
	let raw: unknown;
	try {
		raw = JSON.parse(fs.readFileSync(evidencePath, "utf8")) as unknown;
	} catch (error) {
		return {
			error: error instanceof Error ? error.message : String(error),
		};
	}
	try {
		return { relayProof: parseHermesRelayProofEvidence(raw) };
	} catch (error) {
		return {
			error: error instanceof Error ? error.message : String(error),
		};
	}
}

function parseHermesRuntimeEvidence(raw: unknown): HermesCliRuntimeEvidence {
	if (!isRecord(raw)) {
		throw new Error("runtime evidence must be a JSON object");
	}
	if (raw.kind !== "contained-docker") {
		throw new Error("runtime evidence kind is not contained-docker");
	}
	if (raw.networkName !== "telclaude-hermes-private") {
		throw new Error("runtime evidence networkName is not telclaude-hermes-private");
	}
	if (raw.relayHost !== "telclaude") {
		throw new Error("runtime evidence relayHost is not telclaude");
	}
	if (raw.provenanceSource !== HERMES_CLI_HEADLESS_RUNTIME_PROVENANCE_SOURCE) {
		throw new Error(
			`runtime evidence provenanceSource is not ${HERMES_CLI_HEADLESS_RUNTIME_PROVENANCE_SOURCE}`,
		);
	}
	const imageDigest = runtimeString(raw, "imageDigest");
	if (!/^sha256:[a-f0-9]{64}$/i.test(imageDigest)) {
		throw new Error("runtime evidence imageDigest is not a sha256 digest");
	}
	const containerName = runtimeString(raw, "containerName");
	if (containerName !== "tc-hermes-contained") {
		throw new Error("runtime evidence containerName is not tc-hermes-contained");
	}
	const relayResolvedAddress = runtimeString(raw, "relayResolvedAddress");
	const containerIpAddress = runtimeString(raw, "containerIpAddress");
	const observedPeerAddress = runtimeString(raw, "observedPeerAddress");
	const relayAddressFailure = runtimeContainerAddressFailure(
		"runtime evidence relayResolvedAddress",
		relayResolvedAddress,
	);
	if (relayAddressFailure) {
		throw new Error(relayAddressFailure);
	}
	const peerAddressFailure = runtimeContainerAddressFailure(
		"runtime evidence observedPeerAddress",
		observedPeerAddress,
	);
	if (peerAddressFailure) {
		throw new Error(peerAddressFailure);
	}
	const containerAddressFailure = runtimeContainerAddressFailure(
		"runtime evidence containerIpAddress",
		containerIpAddress,
	);
	if (containerAddressFailure) {
		throw new Error(containerAddressFailure);
	}
	const expectedRelayAddress = expectedHermesRelayIp();
	const expectedContainedAddress = expectedHermesContainedIp();
	if (normalizeRuntimeAddress(relayResolvedAddress) !== expectedRelayAddress) {
		throw new Error(
			`runtime evidence relayResolvedAddress is ${relayResolvedAddress}, expected ${expectedRelayAddress}`,
		);
	}
	if (normalizeRuntimeAddress(containerIpAddress) !== expectedContainedAddress) {
		throw new Error(
			`runtime evidence containerIpAddress is ${containerIpAddress}, expected ${expectedContainedAddress}`,
		);
	}
	if (normalizeRuntimeAddress(observedPeerAddress) !== expectedContainedAddress) {
		throw new Error(
			`runtime evidence observedPeerAddress is ${observedPeerAddress}, expected ${expectedContainedAddress}`,
		);
	}
	if (
		normalizeRuntimeAddress(relayResolvedAddress) === normalizeRuntimeAddress(observedPeerAddress)
	) {
		throw new Error("runtime evidence relayResolvedAddress matches observedPeerAddress");
	}
	if (
		normalizeRuntimeAddress(containerIpAddress) !== normalizeRuntimeAddress(observedPeerAddress)
	) {
		throw new Error("runtime evidence containerIpAddress does not match observedPeerAddress");
	}
	return {
		kind: "contained-docker",
		containerName,
		networkName: "telclaude-hermes-private",
		containerId: runtimeString(raw, "containerId"),
		image: runtimeString(raw, "image"),
		imageDigest: imageDigest as `sha256:${string}`,
		hostname: runtimeString(raw, "hostname"),
		relayHost: "telclaude",
		relayResolvedAddress,
		containerIpAddress,
		observedPeerAddress,
		provenanceSource: HERMES_CLI_HEADLESS_RUNTIME_PROVENANCE_SOURCE,
	};
}

function runtimeString(raw: Record<string, unknown>, key: string): string {
	const value = raw[key];
	if (typeof value !== "string" || !value.trim()) {
		throw new Error(`runtime evidence ${key} is missing`);
	}
	return value.trim();
}

export function parseHermesRelayProofEvidence(raw: unknown): HermesCliRelayProof {
	if (!isRecord(raw)) {
		throw new Error("relay proof evidence must be a JSON object");
	}
	if (raw.schemaVersion !== HERMES_CLI_HEADLESS_RELAY_PROOF_SCHEMA_VERSION) {
		throw new Error("relay proof evidence schemaVersion is not trusted");
	}
	if (raw.source !== HERMES_CLI_HEADLESS_RELAY_PROOF_SOURCE) {
		throw new Error("relay proof evidence source is not the OpenAI Codex proxy");
	}
	if (raw.method !== "POST") {
		throw new Error("relay proof evidence method is not POST");
	}
	if (raw.path !== HERMES_CODEX_RESPONSES_PATH) {
		throw new Error("relay proof evidence path is not the Codex responses endpoint");
	}
	const upstreamStatus = raw.upstreamStatus;
	if (typeof upstreamStatus !== "number" || !Number.isInteger(upstreamStatus)) {
		throw new Error("relay proof evidence upstreamStatus is not an integer");
	}
	const requestBodySha256 = runtimeString(raw, "requestBodySha256");
	if (!/^sha256:[a-f0-9]{64}$/i.test(requestBodySha256)) {
		throw new Error("relay proof evidence requestBodySha256 is not a sha256 digest");
	}
	const proofTokenSha256 =
		typeof raw.proofTokenSha256 === "string" ? raw.proofTokenSha256 : undefined;
	if (proofTokenSha256 !== undefined && !/^sha256:[a-f0-9]{64}$/i.test(proofTokenSha256)) {
		throw new Error("relay proof evidence proofTokenSha256 is not a sha256 digest");
	}
	return {
		schemaVersion: HERMES_CLI_HEADLESS_RELAY_PROOF_SCHEMA_VERSION,
		source: HERMES_CLI_HEADLESS_RELAY_PROOF_SOURCE,
		requestId: runtimeString(raw, "requestId"),
		method: "POST",
		path: HERMES_CODEX_RESPONSES_PATH,
		observedPeerAddress: runtimeString(raw, "observedPeerAddress"),
		upstreamStatus,
		model: runtimeString(raw, "model"),
		requestBodySha256: requestBodySha256 as `sha256:${string}`,
		...(proofTokenSha256 ? { proofTokenSha256: proofTokenSha256 as `sha256:${string}` } : {}),
		observedAt: runtimeString(raw, "observedAt"),
		signature: parseInternalResponseProof(raw.signature),
	};
}

function parseInternalResponseProof(raw: unknown): InternalResponseProof {
	if (!isRecord(raw)) {
		throw new Error("relay proof evidence signature must be a JSON object");
	}
	return {
		version: runtimeString(raw, "version") as InternalResponseProof["version"],
		scope: runtimeString(raw, "scope"),
		timestamp: runtimeString(raw, "timestamp"),
		nonce: runtimeString(raw, "nonce"),
		method: runtimeString(raw, "method"),
		path: runtimeString(raw, "path"),
		requestBodySha256: runtimeString(raw, "requestBodySha256"),
		responseBodySha256: runtimeString(raw, "responseBodySha256"),
		signature: runtimeString(raw, "signature"),
	};
}

export function findHermesLaunchSecretFindings(
	invocation: HermesLaunchInvocation,
): HermesLaunchSecretFinding[] {
	const findings: HermesLaunchSecretFinding[] = [];
	const relayOpenAiCodexConfigured = isRelayOpenAiCodexProxyUrl(
		invocation.env[HERMES_RELAY_OPENAI_CODEX_BASE_URL_ENV],
	);
	const relayOpenAiCodexToken = invocation.authSetup?.openAiCodexRelayToken;
	if (
		relayOpenAiCodexToken &&
		!relayOpenAiCodexConfigured &&
		!invocation.env[HERMES_RELAY_OPENAI_CODEX_BASE_URL_ENV]?.trim()
	) {
		findings.push({
			location: `env.${HERMES_RELAY_OPENAI_CODEX_BASE_URL_ENV}`,
			reason: "model base URL must point at the relay OpenAI Codex proxy",
		});
	}
	if (relayOpenAiCodexToken && containsRawModelProviderCredential(relayOpenAiCodexToken)) {
		findings.push({
			location: "authSetup.openAiCodexRelayToken",
			reason: "raw model-provider credential is forbidden",
		});
	}
	for (const [key, value] of Object.entries(invocation.env)) {
		if (key === HERMES_RELAY_OPENAI_CODEX_BASE_URL_ENV) {
			if (value && !relayOpenAiCodexConfigured) {
				findings.push({
					location: `env.${key}`,
					reason: "model base URL must point at the relay OpenAI Codex proxy",
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

export function redactHermesRuntimeValue(value: unknown): unknown {
	if (typeof value === "string") return redactHermesRuntimeText(value);
	if (Array.isArray(value)) return value.map((item) => redactHermesRuntimeValue(item));
	if (!isRecord(value)) return value;
	return Object.fromEntries(
		Object.entries(value).map(([key, entry]) => [key, redactHermesRuntimeValue(entry)]),
	);
}

export function readHermesCliHeadlessProbeReport(
	reportPath: string,
	options: HermesSignedEvidenceValidationOptions = {},
): HermesCliProbeReport {
	const raw = JSON.parse(fs.readFileSync(path.resolve(reportPath), "utf8")) as unknown;
	if (!isRecord(raw)) {
		throw new Error("cli-headless probe report must be a JSON object");
	}
	if (raw.schemaVersion !== HERMES_PROBE_RESULT_SCHEMA_VERSION) {
		throw new Error("cli-headless probe report has an unsupported schemaVersion");
	}
	if (raw.probeId !== "execution.cli_headless") {
		throw new Error(`cli-headless probe report probeId is ${String(raw.probeId)}`);
	}
	if (raw.ran !== true) {
		throw new Error("cli-headless probe report was not machine-observed");
	}
	if (raw.status !== "pass") {
		throw new Error(`cli-headless probe report status is ${String(raw.status)}`);
	}
	if (raw.exitCode !== 0) {
		throw new Error(`cli-headless probe report exitCode is ${String(raw.exitCode)}`);
	}
	if (!isRecord(raw.invocation)) {
		throw new Error("cli-headless probe report invocation is missing");
	}
	if (!isRecord(raw.modelProvider)) {
		throw new Error("cli-headless probe report modelProvider is missing");
	}
	if (!isRecord(raw.provenance)) {
		throw new Error("cli-headless probe report provenance is missing");
	}
	if (raw.provenance.runner !== HERMES_CLI_HEADLESS_PROVENANCE_RUNNER) {
		throw new Error("cli-headless probe report provenance runner is not trusted");
	}
	if (raw.provenance.source !== HERMES_CLI_HEADLESS_PROVENANCE_SOURCE) {
		throw new Error("cli-headless probe report provenance source is not live-allow-run");
	}
	if (raw.provenance.proofTokenObserved !== true) {
		throw new Error("cli-headless probe report did not observe the expected proof token");
	}
	if (
		raw.provenance.invocationSha256 !==
		sha256Digest(stableStringify(raw.invocation as Record<string, unknown>))
	) {
		throw new Error("cli-headless probe report provenance invocationSha256 does not match");
	}
	if (
		typeof raw.provenance.expectedProofToken !== "string" ||
		!String(raw.stdoutPreview ?? "").includes(raw.provenance.expectedProofToken)
	) {
		throw new Error("cli-headless probe report stdoutPreview lacks expected proof token");
	}
	const stdoutPreview = String(raw.stdoutPreview ?? "");
	const stderrPreview = String(raw.stderrPreview ?? "");
	if (isTruncatedProbePreview(stdoutPreview)) {
		throw new Error("cli-headless probe report stdoutPreview is truncated");
	}
	if (isTruncatedProbePreview(stderrPreview)) {
		throw new Error("cli-headless probe report stderrPreview is truncated");
	}
	if (raw.provenance.stdoutSha256 !== sha256Digest(stdoutPreview)) {
		throw new Error(
			"cli-headless probe report provenance stdoutSha256 does not match stdoutPreview",
		);
	}
	if (raw.provenance.stderrSha256 !== sha256Digest(stderrPreview)) {
		throw new Error(
			"cli-headless probe report provenance stderrSha256 does not match stderrPreview",
		);
	}
	if (raw.provenance.runtimeSha256 !== sha256Digest(stableStringify(raw.runtime ?? null))) {
		throw new Error("cli-headless probe report provenance runtimeSha256 does not match runtime");
	}
	if (raw.provenance.relayProofSha256 !== sha256Digest(stableStringify(raw.relayProof ?? null))) {
		throw new Error(
			"cli-headless probe report provenance relayProofSha256 does not match relayProof",
		);
	}
	const startedAtMs = Date.parse(String(raw.provenance.startedAt ?? ""));
	const endedAtMs = Date.parse(String(raw.provenance.endedAt ?? ""));
	if (Number.isNaN(startedAtMs) || Number.isNaN(endedAtMs) || startedAtMs > endedAtMs) {
		throw new Error("cli-headless probe report provenance timestamps are invalid");
	}
	if (!Array.isArray(raw.findings) || raw.findings.length !== 0) {
		throw new Error("cli-headless probe report findings are not empty");
	}
	const runtime = isRecord(raw.runtime) ? raw.runtime : null;
	if (!runtime) {
		throw new Error("cli-headless probe report runtime evidence is missing");
	}
	if (runtime.kind !== "contained-docker") {
		throw new Error("cli-headless probe report runtime kind is not contained-docker");
	}
	if (runtime.networkName !== "telclaude-hermes-private") {
		throw new Error("cli-headless probe report runtime network is not telclaude-hermes-private");
	}
	if (runtime.relayHost !== "telclaude") {
		throw new Error("cli-headless probe report runtime relayHost is not telclaude");
	}
	if (runtime.provenanceSource !== HERMES_CLI_HEADLESS_RUNTIME_PROVENANCE_SOURCE) {
		throw new Error("cli-headless probe report runtime provenance source is not machine-derived");
	}
	const parsedRuntime = parseHermesRuntimeEvidence(runtime);
	const relayProof = isRecord(raw.relayProof) ? (raw.relayProof as HermesCliRelayProof) : undefined;
	const relayProofFailure = hermesCliRelayProofFailure(relayProof, {
		expectedProofToken: String(raw.provenance.expectedProofToken ?? ""),
		modelProvider: raw.modelProvider as HermesCliProbeReport["modelProvider"],
		runtime: parsedRuntime,
		startedAt: String(raw.provenance.startedAt ?? ""),
		endedAt: String(raw.provenance.endedAt ?? ""),
		allowStaleSignature: true,
		relayPublicKey: options.relayPublicKey,
	});
	if (relayProofFailure) {
		throw new Error(`cli-headless probe report relay proof is invalid: ${relayProofFailure}`);
	}
	return raw as HermesCliProbeReport;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function runtimeContainerAddressFailure(label: string, value: string): string | null {
	const address = normalizeRuntimeAddress(value);
	if (net.isIP(address) === 0) {
		return `${label} is not an IP address`;
	}
	if (isLoopbackAddress(address)) {
		return `${label} is loopback`;
	}
	if (isUnspecifiedAddress(address)) {
		return `${label} is unspecified`;
	}
	if (!isPrivateContainerAddress(address)) {
		return `${label} is not a private container-network IP`;
	}
	return null;
}

function expectedHermesRelayIp(): string {
	return expectedConfiguredRuntimeIp("TELCLAUDE_HERMES_RELAY_IP", DEFAULT_HERMES_RELAY_IP);
}

function expectedHermesContainedIp(): string {
	return expectedConfiguredRuntimeIp("TELCLAUDE_HERMES_CONTAINED_IP", DEFAULT_HERMES_CONTAINED_IP);
}

function expectedConfiguredRuntimeIp(envKey: string, fallback: string): string {
	const address = normalizeRuntimeAddress(process.env[envKey]?.trim() || fallback);
	if (net.isIP(address) === 0) {
		throw new Error(`configured ${envKey} is not an IP address`);
	}
	return address;
}

function normalizeRuntimeAddress(value: string): string {
	const address = value.trim().toLowerCase();
	return address.startsWith("::ffff:") ? address.slice("::ffff:".length) : address;
}

function isLoopbackAddress(address: string): boolean {
	return address === "::1" || address === "0:0:0:0:0:0:0:1" || address.startsWith("127.");
}

function isUnspecifiedAddress(address: string): boolean {
	return address === "::" || address === "0:0:0:0:0:0:0:0" || address === "0.0.0.0";
}

function isPrivateContainerAddress(address: string): boolean {
	if (net.isIP(address) === 6) {
		return address.startsWith("fc") || address.startsWith("fd");
	}
	const octets = address.split(".").map((part) => Number.parseInt(part, 10));
	if (octets.length !== 4 || octets.some((octet) => Number.isNaN(octet))) return false;
	const [first, second] = octets;
	return (
		first === 10 ||
		(first === 172 && second >= 16 && second <= 31) ||
		(first === 192 && second === 168)
	);
}

function hermesCliRuntimeFailure(stdout: string, stderr: string): string | null {
	const combined = `${stdout}\n${stderr}`;
	const patterns: ReadonlyArray<[RegExp, string]> = [
		[/API call failed after \d+ retries/i, "model API call failed"],
		[/No inference provider configured/i, "inference provider is not configured"],
		[/Anthropic credentials not configured/i, "relay Anthropic credentials are not configured"],
		[/Codex auth .*missing/i, "relay OpenAI Codex auth store is not configured"],
		[/Missing Authentication header/i, "relay OpenAI Codex credentials are not configured"],
		[
			/failed to prepare docker exec Hermes auth store/i,
			"relay OpenAI Codex auth store is not configured",
		],
	];
	for (const [pattern, reason] of patterns) {
		if (pattern.test(combined)) return reason;
	}
	return null;
}

function hermesCliExpectedProofToken(invocation: HermesLaunchInvocation): string {
	return (
		extractOpenAiCodexRelayProofToken(invocation.args.join("\n")) ?? DEFAULT_HERMES_CLI_PROBE_TOKEN
	);
}

function hermesCliRelayProofFailure(
	proof: HermesCliRelayProof | undefined,
	context: {
		expectedProofToken: string;
		modelProvider?: HermesCliProbeReport["modelProvider"];
		runtime?: HermesCliRuntimeEvidence;
		startedAt: string;
		endedAt: string;
		allowStaleSignature?: boolean;
		relayPublicKey?: string;
	},
): string | null {
	if (!proof) return "relay proof is missing";
	if (proof.schemaVersion !== HERMES_CLI_HEADLESS_RELAY_PROOF_SCHEMA_VERSION) {
		return "relay proof schemaVersion is not trusted";
	}
	if (proof.source !== HERMES_CLI_HEADLESS_RELAY_PROOF_SOURCE) {
		return "relay proof source is not the OpenAI Codex proxy";
	}
	if (!proof.requestId.trim()) return "relay proof requestId is missing";
	if (proof.method !== "POST") return "relay proof method is not POST";
	if (proof.path !== HERMES_CODEX_RESPONSES_PATH) {
		return "relay proof path is not the Codex responses endpoint";
	}
	if (proof.upstreamStatus < 200 || proof.upstreamStatus >= 300) {
		return `relay proof upstreamStatus is ${proof.upstreamStatus}`;
	}
	if (!/^sha256:[a-f0-9]{64}$/i.test(proof.requestBodySha256)) {
		return "relay proof requestBodySha256 is not a sha256 digest";
	}
	const signatureFailure = openAiCodexRelayProofSignatureFailure(proof as OpenAiCodexRelayProof, {
		allowStale: context.allowStaleSignature,
		relayPublicKey: context.relayPublicKey,
	});
	if (signatureFailure) {
		return `relay proof signature is invalid: ${signatureFailure}`;
	}
	if (!context.expectedProofToken.trim()) return "expected proof token is missing";
	const expectedProofTokenSha256 = openAiCodexRelayProofTokenSha256(context.expectedProofToken);
	if (!proof.proofTokenSha256) return "relay proof proofTokenSha256 is missing";
	if (proof.proofTokenSha256 !== expectedProofTokenSha256) {
		return "relay proof proofTokenSha256 does not match expected proof token";
	}
	if (!context.runtime) return "runtime evidence is missing";
	if (
		normalizeRuntimeAddress(proof.observedPeerAddress) !==
		normalizeRuntimeAddress(context.runtime.observedPeerAddress)
	) {
		return "relay proof observedPeerAddress does not match runtime observedPeerAddress";
	}
	if (
		normalizeRuntimeAddress(proof.observedPeerAddress) !==
		normalizeRuntimeAddress(context.runtime.containerIpAddress)
	) {
		return "relay proof observedPeerAddress does not match containerIpAddress";
	}
	if (!context.modelProvider?.model.trim()) return "modelProvider model is missing";
	if (proof.model !== context.modelProvider.model) {
		return "relay proof model does not match modelProvider model";
	}
	const observedAtMs = Date.parse(proof.observedAt);
	const startedAtMs = Date.parse(context.startedAt);
	const endedAtMs = Date.parse(context.endedAt);
	if (Number.isNaN(observedAtMs) || Number.isNaN(startedAtMs) || Number.isNaN(endedAtMs)) {
		return "relay proof timestamps are invalid";
	}
	if (observedAtMs < startedAtMs || observedAtMs > endedAtMs) {
		return "relay proof observedAt is outside the probe window";
	}
	return null;
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
	const codexBaseUrl = invocation.env[HERMES_RELAY_OPENAI_CODEX_BASE_URL_ENV];
	const codexToken = invocation.authSetup?.openAiCodexRelayToken;
	if (codexBaseUrl && codexToken && isRelayOpenAiCodexProxyUrl(codexBaseUrl)) {
		const parsed = new URL(codexBaseUrl);
		return {
			provider: HERMES_RELAY_OPENAI_CODEX_PROVIDER,
			baseUrl: codexBaseUrl,
			baseUrlHost: parsed.hostname,
			model: invocation.env[HERMES_INFERENCE_MODEL_ENV]?.trim() ?? "",
			modelSource: invocation.env[HERMES_INFERENCE_MODEL_ENV]?.trim()
				? `env:${HERMES_INFERENCE_MODEL_ENV}`
				: "missing",
			authLocation: "hermes-auth-store:openai-codex",
			authScope: "relay-openai-codex-subscription-proxy",
			tokenScoping: "peer-bound",
			auxiliaryAuthSource: HERMES_RELAY_OPENAI_CODEX_POOL_SOURCE,
			auxiliaryBaseUrl: codexBaseUrl,
			auxiliaryBaseUrlHost: parsed.hostname,
			refreshTokenPolicy: "non-refreshable-placeholder",
		};
	}
	return undefined;
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

function hermesRelayModelConfig(env: NodeJS.ProcessEnv): {
	env: Record<string, string>;
	openAiCodexRelayToken?: string;
} {
	const codexBaseUrl = env[HERMES_RELAY_OPENAI_CODEX_BASE_URL_ENV]?.trim();
	const codexRelayToken = env[HERMES_RELAY_OPENAI_CODEX_AUTH_ENV]?.trim();
	const provider = env[HERMES_INFERENCE_PROVIDER_ENV]?.trim();
	const model = env[HERMES_INFERENCE_MODEL_ENV]?.trim();
	if (codexBaseUrl || codexRelayToken || provider === HERMES_RELAY_OPENAI_CODEX_PROVIDER) {
		return {
			env: {
				[HERMES_INFERENCE_PROVIDER_ENV]: HERMES_RELAY_OPENAI_CODEX_PROVIDER,
				...(codexBaseUrl ? { [HERMES_RELAY_OPENAI_CODEX_BASE_URL_ENV]: codexBaseUrl } : {}),
				...(model ? { [HERMES_INFERENCE_MODEL_ENV]: model } : {}),
			},
			...(codexRelayToken ? { openAiCodexRelayToken: codexRelayToken } : {}),
		};
	}

	if (!model) return { env: {} };
	return {
		env: {
			[HERMES_INFERENCE_MODEL_ENV]: model,
		},
	};
}

function prepareHermesLaunchAuthStore(
	invocation: HermesLaunchInvocation,
	launchEnv: Record<string, string>,
): void {
	const relayToken = invocation.authSetup?.openAiCodexRelayToken?.trim();
	if (!relayToken) return;
	if (containsRawModelProviderCredential(relayToken)) {
		throw new Error("relay OpenAI Codex token is raw-provider-like");
	}
	const hermesHome = launchEnv.HERMES_HOME?.trim();
	if (!hermesHome) {
		throw new Error("HERMES_HOME is required for relay OpenAI Codex auth setup");
	}
	const relayBaseUrl = launchEnv[HERMES_RELAY_OPENAI_CODEX_BASE_URL_ENV]?.trim();
	if (!isRelayOpenAiCodexProxyUrl(relayBaseUrl)) {
		throw new Error("HERMES_CODEX_BASE_URL must point at the relay OpenAI Codex proxy");
	}
	const model = launchEnv[HERMES_INFERENCE_MODEL_ENV]?.trim();
	if (!model) {
		throw new Error("HERMES_INFERENCE_MODEL is required for relay OpenAI Codex auth setup");
	}
	const peerBoundRelayToken = mintOpenAiCodexPeerBoundProxyToken({
		secret: relayToken,
		peerAddress: expectedHermesContainedIp(),
		runId: `hermes-cli-${crypto.randomUUID()}`,
		tokenScope: "run",
		ttlMs: OPENAI_CODEX_CONTAINED_RELAY_TOKEN_TTL_MS,
	});
	writeHermesOpenAiCodexRelayAuthStore(hermesHome, peerBoundRelayToken, relayBaseUrl, model);
	delete launchEnv[HERMES_RELAY_OPENAI_CODEX_AUTH_ENV];
}

export function buildHermesOpenAiCodexRelayAuthStorePayload(
	relayToken: string,
	relayBaseUrl: string,
): Record<string, unknown> {
	return {
		version: 1,
		active_provider: HERMES_RELAY_OPENAI_CODEX_PROVIDER,
		suppressed_sources: {
			[HERMES_RELAY_OPENAI_CODEX_PROVIDER]: ["device_code"],
		},
		providers: {
			[HERMES_RELAY_OPENAI_CODEX_PROVIDER]: {
				auth_mode: "telclaude-relay",
				last_refresh: new Date(0).toISOString(),
			},
		},
		credential_pool: {
			[HERMES_RELAY_OPENAI_CODEX_PROVIDER]: [
				{
					id: "telclaude-relay",
					label: "Telclaude OpenAI Codex relay",
					auth_type: "api_key",
					priority: 0,
					source: HERMES_RELAY_OPENAI_CODEX_POOL_SOURCE,
					access_token: relayToken,
					base_url: relayBaseUrl,
				},
			],
		},
	};
}

function writeHermesOpenAiCodexRelayAuthStore(
	hermesHome: string,
	relayToken: string,
	relayBaseUrl: string,
	model: string,
): void {
	fs.mkdirSync(hermesHome, { recursive: true, mode: 0o700 });
	const configPath = path.join(hermesHome, "config.yaml");
	const authPath = path.join(hermesHome, "auth.json");
	const manifestPath = path.join(hermesHome, "secret-manifest.json");
	const payload = buildHermesOpenAiCodexRelayAuthStorePayload(relayToken, relayBaseUrl);
	fs.writeFileSync(
		configPath,
		[
			"model:",
			"  provider: openai-codex",
			`  default: ${model}`,
			"  api_mode: codex_responses",
			"  openai_runtime: auto",
			"",
		].join("\n"),
		{ encoding: "utf8", mode: 0o600 },
	);
	const tmpPath = `${authPath}.tmp.${process.pid}`;
	fs.writeFileSync(tmpPath, `${JSON.stringify(payload, null, 2)}\n`, {
		encoding: "utf8",
		mode: 0o600,
	});
	fs.renameSync(tmpPath, authPath);
	fs.writeFileSync(
		manifestPath,
		`${JSON.stringify(
			{
				schemaVersion: 1,
				rawCredentialPolicy: "relay-owned-only",
				relayTokenBinding: "run-peer-bound",
			},
			null,
			2,
		)}\n`,
		{ encoding: "utf8", mode: 0o600 },
	);
	try {
		fs.chmodSync(configPath, 0o600);
		fs.chmodSync(authPath, 0o600);
		fs.chmodSync(manifestPath, 0o600);
	} catch {
		// Best effort on platforms without POSIX modes.
	}
}

function isRelayOpenAiCodexProxyUrl(value: string | undefined): boolean {
	if (!value) return false;
	try {
		const parsed = new URL(value);
		return (
			parsed.protocol === "http:" &&
			parsed.hostname === "telclaude" &&
			parsed.port === "8790" &&
			parsed.pathname.replace(/\/+$/, "") === HERMES_RELAY_OPENAI_CODEX_PROXY_PATH &&
			parsed.search === "" &&
			parsed.hash === "" &&
			value.replace(/\/+$/, "") === HERMES_RELAY_OPENAI_CODEX_PROXY_URL
		);
	} catch {
		return false;
	}
}

function passReadiness(name: string, detail: string): HermesCliHeadlessReadinessGate {
	return { name, status: "pass", detail };
}

function failReadiness(name: string, detail: string): HermesCliHeadlessReadinessGate {
	return { name, status: "fail", detail };
}

function isTruncatedProbePreview(value: string): boolean {
	return value.endsWith("...");
}

function sha256Digest(value: string): string {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function stableStringify(value: unknown): string {
	if (value === null || typeof value !== "object") return JSON.stringify(value);
	if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
	const entries = Object.entries(value as Record<string, unknown>).sort(([left], [right]) =>
		left.localeCompare(right),
	);
	return `{${entries
		.map(([key, entry]) => `${JSON.stringify(key)}:${stableStringify(entry)}`)
		.join(",")}}`;
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
