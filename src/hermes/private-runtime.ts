import type { PermissionTier } from "../config/config.js";
import type { StreamChunk } from "../sdk/client.js";
import { filterOutput, redactSecrets } from "../security/output-filter.js";
import type { HermesSessionMap } from "./session-map.js";

export const HERMES_PROBE_RESULT_SCHEMA_VERSION = "telclaude.hermes.probe-result.v1";

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
	isNewSession: boolean;
	timeoutMs: number;
	signal: AbortSignal;
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
	"telclaudeSessionId" | "resumeHermesSessionId"
> & {
	telclaudeSessionId?: string;
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
	now?: () => number;
}): AsyncGenerator<StreamChunk, void, unknown> {
	const now = input.now ?? Date.now;
	const startedAt = now();
	const { record } = input.sessions.getOrCreate({
		sessionKey: input.request.sessionKey,
		profileId: input.request.profileId,
		now: startedAt,
		telclaudeSessionId: input.request.telclaudeSessionId,
	});
	const runtimeRequest: HermesRuntimeRequest = {
		...input.request,
		telclaudeSessionId: record.telclaudeSessionId,
		...(input.request.isNewSession ? {} : { resumeHermesSessionId: record.hermesSessionId }),
	};

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
	}
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
