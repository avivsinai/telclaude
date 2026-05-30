import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { redactSecrets } from "../security/output-filter.js";
import { resolveHermesArtifactPath } from "./foundation.js";
import {
	findHermesLaunchSecretFindings,
	type HermesLaunchInvocation,
	type HermesLaunchSecretFinding,
	redactHermesRuntimeText,
	runHermesLaunchInvocation,
} from "./private-runtime.js";

export const HERMES_API_SERVER_CONTAINMENT_SCHEMA_VERSION =
	"telclaude.hermes.api-server-containment.v1";
export const DEFAULT_HERMES_API_SERVER_CONTAINMENT_EVIDENCE_PATH =
	"artifacts/hermes/probes/execution-api-server-containment.json";
export const DEFAULT_HERMES_API_SERVER_DOCKER_IMAGE =
	"nousresearch/hermes-agent@sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7";
export const DEFAULT_HERMES_API_SERVER_CONTAINER_NAME = "tc-hermes-contained";
export const DEFAULT_HERMES_API_SERVER_NETWORK = "telclaude-hermes-relay";
export const DEFAULT_HERMES_API_SERVER_PORT = 8642;
export const DEFAULT_HERMES_API_SERVER_HERMES_HOME = "/home/hermes/.hermes";
export const DEFAULT_HERMES_RELAY_INTERNAL_HOST = "telclaude";
export const DEFAULT_HERMES_RELAY_CONTAINER_NAME = "telclaude";
export const DEFAULT_HERMES_API_SERVER_RUNTIME_USER = "10000:10000";

type ApiServerContainmentStatus = "pass" | "fail" | "pending";

export type HermesApiServerLaunchPlan = {
	readonly invocation: HermesLaunchInvocation;
	readonly apiKey: string;
	readonly containerName: string;
	readonly apiPort: number;
	readonly networkName: string;
	readonly relayInternalHost: string;
	readonly relayContainerName: string;
	readonly runtimeUser: string;
};

export type HermesApiServerContainmentObservation = {
	readonly lifecycle?: {
		readonly started: boolean;
		readonly stopped: boolean;
		readonly containerId?: string;
		readonly detail?: string;
	};
	readonly posture?: {
		readonly appArmorApplied: boolean;
		readonly appArmorProfile?: string;
		readonly appArmorEvidence: "docker_inspect.AppArmorProfile";
		readonly securityOptions: readonly string[];
		readonly noNewPrivileges: boolean;
		readonly readOnlyRootfs: boolean;
		readonly capDropAll: boolean;
		readonly tmpfsRun?: string;
		readonly detail: string;
	};
	readonly health?: {
		readonly ok: boolean;
		readonly status?: string;
		readonly detail?: string;
	};
	readonly capabilities?: {
		readonly ok: boolean;
		readonly runSubmission?: boolean;
		readonly runEventsSse?: boolean;
		readonly runStop?: boolean;
		readonly runApprovalResponse?: boolean;
		readonly bearerAuthRequired?: boolean;
		readonly serverToolExecution?: boolean;
		readonly splitRuntime?: boolean;
		readonly detail?: string;
	};
	readonly network?: {
		readonly topologyInternal: boolean;
		readonly relayContainerPresent: boolean;
		readonly unexpectedPeers: readonly string[];
		readonly attachedContainers: readonly string[];
		readonly relayControlReachable: boolean;
		readonly directProviderDenied: boolean;
		readonly directVaultDenied: boolean;
		readonly directModelProviderDenied: boolean;
		readonly dnsPrivateDenied: boolean;
		readonly authoritativeBoundary: "docker_internal_network";
		readonly networkName?: string;
		readonly tamper?: {
			readonly runtimeUid?: string;
			readonly runtimeUser?: string;
			readonly runtimeNonRoot: boolean;
			readonly firewallFlushDenied: boolean;
			readonly routeAddDenied: boolean;
			readonly tamperCommandSucceeded: boolean;
			readonly forbiddenReachableAfterTamper: boolean;
			readonly detail?: string;
		};
		readonly detail?: string;
	};
};

export type HermesApiServerContainmentReport = {
	readonly schemaVersion: typeof HERMES_API_SERVER_CONTAINMENT_SCHEMA_VERSION;
	readonly probeId: "execution.api_server_containment";
	readonly status: ApiServerContainmentStatus;
	readonly ran: boolean;
	readonly summary: string;
	readonly invocation?: {
		readonly command: string;
		readonly args: string[];
		readonly cwd: string;
		readonly envKeys: string[];
		readonly ephemeralAuth: {
			readonly envKey: "API_SERVER_KEY";
			readonly classification: "ephemeral_api_auth";
		};
	};
	readonly gates: Array<{
		readonly name: string;
		readonly status: "pass" | "fail" | "pending";
		readonly detail: string;
	}>;
	readonly findings: HermesLaunchSecretFinding[];
	readonly observation?: HermesApiServerContainmentObservation;
};

export type HermesApiServerContainmentRunner = (
	plan: HermesApiServerLaunchPlan,
) => Promise<HermesApiServerContainmentObservation>;

export function buildHermesApiServerLaunchPlan(input: {
	readonly dockerBin?: string;
	readonly image?: string;
	readonly containerName?: string;
	readonly network?: string;
	readonly cwd?: string;
	readonly hermesHome?: string;
	readonly apiPort?: number;
	readonly relayInternalHost?: string;
	readonly relayContainerName?: string;
	readonly runtimeUser?: string;
	readonly apiKey?: string;
}): HermesApiServerLaunchPlan {
	const apiKey = input.apiKey ?? createEphemeralHermesApiServerKey();
	const containerName = cleanNonEmpty(
		input.containerName,
		DEFAULT_HERMES_API_SERVER_CONTAINER_NAME,
	);
	const network = cleanNonEmpty(input.network, DEFAULT_HERMES_API_SERVER_NETWORK);
	const apiPort = normalizePort(input.apiPort);
	const relayInternalHost = cleanNonEmpty(
		input.relayInternalHost,
		DEFAULT_HERMES_RELAY_INTERNAL_HOST,
	);
	const relayContainerName = cleanNonEmpty(
		input.relayContainerName,
		DEFAULT_HERMES_RELAY_CONTAINER_NAME,
	);
	const runtimeUser = cleanNonEmpty(input.runtimeUser, DEFAULT_HERMES_API_SERVER_RUNTIME_USER);
	const hermesHome = cleanNonEmpty(input.hermesHome, DEFAULT_HERMES_API_SERVER_HERMES_HOME);
	const image = normalizeDigestPinnedImage(
		cleanNonEmpty(input.image, DEFAULT_HERMES_API_SERVER_DOCKER_IMAGE),
	);
	// API_SERVER_KEY is a fresh relay-to-contained-Hermes bearer token, not a
	// provider/model/vault credential. It is generated for this launch only,
	// passed through process env instead of argv, and omitted from artifacts.
	const env = {
		API_SERVER_ENABLED: "true",
		API_SERVER_HOST: "0.0.0.0",
		API_SERVER_PORT: String(apiPort),
		API_SERVER_KEY: apiKey,
		HERMES_HOME: hermesHome,
		HOME: path.dirname(hermesHome),
		TELCLAUDE_INTERNAL_HOSTS: relayInternalHost,
		NO_COLOR: "1",
		...dockerClientEnv(process.env),
	};

	return {
		invocation: {
			command: cleanNonEmpty(input.dockerBin, "docker"),
			args: [
				"run",
				"--detach",
				"--rm",
				"--name",
				containerName,
				"--network",
				network,
				"--user",
				runtimeUser,
				"--cap-drop",
				"ALL",
				"--security-opt",
				"no-new-privileges",
				"--read-only",
				"--tmpfs",
				"/tmp:size=128m,mode=1777,noexec",
				"--tmpfs",
				"/run:size=16m,uid=10000,gid=10000,mode=0755,noexec",
				"--tmpfs",
				`${path.dirname(hermesHome)}:size=512m,uid=10000,gid=10000,mode=0700,noexec`,
				"--pids-limit",
				"256",
				"--memory",
				"2g",
				"--cpus",
				"2",
				"--env",
				"API_SERVER_ENABLED",
				"--env",
				"API_SERVER_HOST",
				"--env",
				"API_SERVER_PORT",
				"--env",
				"API_SERVER_KEY",
				"--env",
				"HERMES_HOME",
				"--env",
				"HOME",
				"--env",
				"TELCLAUDE_INTERNAL_HOSTS",
				"--env",
				"NO_COLOR",
				"--entrypoint",
				"/opt/hermes/hermes",
				image,
				"gateway",
				"run",
			],
			cwd: path.resolve(input.cwd ?? process.cwd()),
			env,
		},
		apiKey,
		containerName,
		apiPort,
		networkName: network,
		relayInternalHost,
		relayContainerName,
		runtimeUser,
	};
}

export function createEphemeralHermesApiServerKey(): string {
	return randomBytes(32).toString("base64url");
}

function dockerClientEnv(env: NodeJS.ProcessEnv): Record<string, string> {
	const result: Record<string, string> = {};
	for (const key of ["DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"]) {
		const value = env[key]?.trim();
		if (value) result[key] = value;
	}
	return result;
}

export function findHermesApiServerLaunchSecretFindings(
	plan: HermesApiServerLaunchPlan,
): HermesLaunchSecretFinding[] {
	const findings: HermesLaunchSecretFinding[] = [];
	if (plan.invocation.env.API_SERVER_KEY !== plan.apiKey || !plan.apiKey) {
		findings.push({
			location: "env.API_SERVER_KEY",
			reason: "API_SERVER_KEY must be the generated ephemeral launch key",
		});
	}
	for (const [index, arg] of plan.invocation.args.entries()) {
		if (arg === plan.apiKey || arg === `API_SERVER_KEY=${plan.apiKey}`) {
			findings.push({
				location: `argv[${index}]`,
				reason: "ephemeral API_SERVER_KEY must not be passed through argv",
			});
		}
	}
	const { API_SERVER_KEY: _ephemeralApiKey, ...envWithoutEphemeralKey } = plan.invocation.env;
	return [
		...findings,
		...findHermesLaunchSecretFindings({
			...plan.invocation,
			env: envWithoutEphemeralKey,
		}).map((finding) =>
			finding.reason === "forbidden credential environment key"
				? { ...finding, reason: "forbidden standing credential environment key" }
				: finding,
		),
	];
}

export async function runHermesApiServerContainmentProbe(input: {
	readonly allowRun: boolean;
	readonly launch: HermesApiServerLaunchPlan;
	readonly runner?: HermesApiServerContainmentRunner;
}): Promise<HermesApiServerContainmentReport> {
	const findings = findHermesApiServerLaunchSecretFindings(input.launch);
	if (findings.length > 0) {
		return apiServerContainmentReport({
			status: "fail",
			ran: false,
			summary: "Hermes API-server launch contains forbidden credential material",
			launch: input.launch,
			findings,
			gates: [
				{
					name: "launch.credentials",
					status: "fail",
					detail: findings.map((finding) => `${finding.location}: ${finding.reason}`).join("; "),
				},
			],
		});
	}
	if (!input.allowRun) {
		return apiServerContainmentReport({
			status: "pending",
			ran: false,
			summary: "Hermes API-server containment probe requires --allow-run",
			launch: input.launch,
			findings,
			gates: [
				{
					name: "probe.allowed",
					status: "pending",
					detail: "pass --allow-run to start the contained Hermes API server",
				},
			],
		});
	}
	if (!input.runner) {
		return apiServerContainmentReport({
			status: "pending",
			ran: false,
			summary: "Hermes API-server containment runner is not configured",
			launch: input.launch,
			findings,
			gates: [
				{
					name: "runner.configured",
					status: "pending",
					detail: "no runner was provided for a live containment probe",
				},
			],
		});
	}

	const observation = sanitizeObservation(await input.runner(input.launch), input.launch);
	const gates = evaluateContainmentObservation(observation);
	const status = gates.every((gate) => gate.status === "pass") ? "pass" : "fail";
	return apiServerContainmentReport({
		status,
		ran: true,
		summary:
			status === "pass"
				? "Hermes API-server containment probe passed"
				: "Hermes API-server containment probe failed",
		launch: input.launch,
		findings,
		gates,
		observation,
	});
}

export async function runHermesApiServerDockerContainment(
	plan: HermesApiServerLaunchPlan,
	options: {
		readonly timeoutMs?: number;
		readonly relayControlUrl?: string;
		readonly providerUrls?: readonly string[];
		readonly vaultSocketPath?: string;
		readonly modelProviderUrl?: string;
		readonly dnsPrivateUrls?: readonly string[];
	} = {},
): Promise<HermesApiServerContainmentObservation> {
	const start = await runHermesLaunchInvocation(plan.invocation, { timeoutMs: options.timeoutMs });
	if (start.exitCode !== 0) {
		return {
			lifecycle: {
				started: false,
				stopped: false,
				detail: redactHermesRuntimeText(
					start.stderr || start.stdout || `docker exited ${start.exitCode}`,
				),
			},
		};
	}
	const containerId = (start.stdout.trim().split(/\s+/)[0] || plan.containerName).trim();
	let observation: HermesApiServerContainmentObservation = {
		lifecycle: {
			started: true,
			stopped: false,
			containerId: redactSecrets(containerId),
			detail: "contained Hermes API-server container started",
		},
	};
	try {
		const posture = await readRuntimePosture(plan, options.timeoutMs);
		const health = await waitForHealth(plan, options.timeoutMs);
		const capabilities = await readCapabilities(plan, options.timeoutMs);
		const network = await readContainerNetworkEvidence(plan, options);
		observation = {
			lifecycle: {
				started: true,
				stopped: false,
				containerId: redactSecrets(containerId),
				detail: "contained Hermes API-server container started",
			},
			posture,
			health,
			capabilities,
			network,
		};
	} catch (error) {
		observation = {
			...observation,
			health: {
				ok: false,
				detail: redactHermesRuntimeText(error instanceof Error ? error.message : String(error)),
			},
		};
	} finally {
		const stop = await runDockerCommand(plan, ["rm", "-f", plan.containerName], options.timeoutMs);
		observation = {
			...observation,
			lifecycle: {
				...observation.lifecycle,
				started: observation.lifecycle?.started ?? false,
				stopped: stop.exitCode === 0,
				detail:
					stop.exitCode === 0
						? observation.lifecycle?.detail
						: redactHermesRuntimeText(stop.stderr || stop.stdout || "container cleanup failed"),
			},
		};
	}
	return observation;
}

async function readRuntimePosture(
	plan: HermesApiServerLaunchPlan,
	timeoutMs: number | undefined,
): Promise<NonNullable<HermesApiServerContainmentObservation["posture"]>> {
	const result = await runDockerCommand(
		plan,
		["inspect", plan.containerName, "--format", "{{json .}}"],
		timeoutMs,
	);
	if (result.exitCode !== 0) {
		return {
			appArmorApplied: false,
			appArmorEvidence: "docker_inspect.AppArmorProfile",
			securityOptions: [],
			noNewPrivileges: false,
			readOnlyRootfs: false,
			capDropAll: false,
			detail: `docker inspect posture unavailable: ${redactHermesRuntimeText(
				result.stderr || result.stdout,
			)}`,
		};
	}
	try {
		const inspected = JSON.parse(result.stdout) as {
			AppArmorProfile?: unknown;
			HostConfig?: {
				SecurityOpt?: unknown;
				ReadonlyRootfs?: unknown;
				CapDrop?: unknown;
				Tmpfs?: unknown;
			};
		};
		const securityOptions = Array.isArray(inspected.HostConfig?.SecurityOpt)
			? inspected.HostConfig.SecurityOpt.filter((item): item is string => typeof item === "string")
			: [];
		const appArmorFromSecurityOpt = securityOptions
			.find((option) => option.startsWith("apparmor:"))
			?.slice("apparmor:".length);
		const appArmorProfile =
			typeof inspected.AppArmorProfile === "string" && inspected.AppArmorProfile
				? inspected.AppArmorProfile
				: appArmorFromSecurityOpt;
		const appArmorApplied = Boolean(appArmorProfile && appArmorProfile !== "unconfined");
		const capDrop = Array.isArray(inspected.HostConfig?.CapDrop)
			? inspected.HostConfig.CapDrop.filter((item): item is string => typeof item === "string")
			: [];
		const tmpfs =
			typeof inspected.HostConfig?.Tmpfs === "object" && inspected.HostConfig.Tmpfs !== null
				? (inspected.HostConfig.Tmpfs as Record<string, unknown>)
				: {};
		const tmpfsRun = typeof tmpfs["/run"] === "string" ? tmpfs["/run"] : undefined;
		return {
			appArmorApplied,
			...(appArmorProfile ? { appArmorProfile } : {}),
			appArmorEvidence: "docker_inspect.AppArmorProfile",
			securityOptions,
			noNewPrivileges: securityOptions.some((option) =>
				/^no-new-privileges(?::true)?$/.test(option),
			),
			readOnlyRootfs: inspected.HostConfig?.ReadonlyRootfs === true,
			capDropAll: capDrop.includes("ALL"),
			...(tmpfsRun ? { tmpfsRun } : {}),
			detail: appArmorApplied
				? `AppArmor profile observed: ${appArmorProfile}`
				: "AppArmor profile not observed; evidence is local/dry-run posture, not production-posture proof",
		};
	} catch {
		return {
			appArmorApplied: false,
			appArmorEvidence: "docker_inspect.AppArmorProfile",
			securityOptions: [],
			noNewPrivileges: false,
			readOnlyRootfs: false,
			capDropAll: false,
			detail: "docker inspect posture returned malformed JSON",
		};
	}
}

export function writeHermesApiServerContainmentEvidence(
	report: HermesApiServerContainmentReport,
	outputPath = DEFAULT_HERMES_API_SERVER_CONTAINMENT_EVIDENCE_PATH,
): HermesApiServerContainmentReport {
	const artifactPath = resolveHermesArtifactPath(outputPath);
	writeJsonArtifact(artifactPath, report);
	return report;
}

function apiServerContainmentReport(input: {
	status: ApiServerContainmentStatus;
	ran: boolean;
	summary: string;
	launch: HermesApiServerLaunchPlan;
	findings: HermesLaunchSecretFinding[];
	gates: HermesApiServerContainmentReport["gates"];
	observation?: HermesApiServerContainmentObservation;
}): HermesApiServerContainmentReport {
	return {
		schemaVersion: HERMES_API_SERVER_CONTAINMENT_SCHEMA_VERSION,
		probeId: "execution.api_server_containment",
		status: input.status,
		ran: input.ran,
		summary: input.summary,
		invocation: sanitizedLaunchInvocation(input.launch),
		gates: input.gates,
		findings: input.findings,
		...(input.observation ? { observation: input.observation } : {}),
	};
}

function sanitizedLaunchInvocation(
	plan: HermesApiServerLaunchPlan,
): NonNullable<HermesApiServerContainmentReport["invocation"]> {
	return {
		command: redactApiServerText(plan.invocation.command, plan),
		args: plan.invocation.args.map((arg) => redactApiServerText(arg, plan)),
		cwd: redactApiServerText(plan.invocation.cwd, plan),
		envKeys: Object.keys(plan.invocation.env).sort(),
		ephemeralAuth: {
			envKey: "API_SERVER_KEY",
			classification: "ephemeral_api_auth",
		},
	};
}

function evaluateContainmentObservation(
	observation: HermesApiServerContainmentObservation,
): HermesApiServerContainmentReport["gates"] {
	const lifecycle = observation.lifecycle;
	const health = observation.health;
	const capabilities = observation.capabilities;
	const network = observation.network;
	const topologyPasses = topologyGatePasses(network);
	return [
		{
			name: "lifecycle.started",
			status: lifecycle?.started ? "pass" : "fail",
			detail: lifecycle?.started
				? `container started${lifecycle.containerId ? `: ${lifecycle.containerId}` : ""}`
				: lifecycle?.detail || "container start was not observed",
		},
		{
			name: "lifecycle.stopped",
			status: lifecycle?.stopped ? "pass" : "fail",
			detail: lifecycle?.stopped
				? "probe container was explicitly stopped"
				: "probe did not observe explicit container cleanup",
		},
		{
			name: "readiness.health",
			status: health?.ok ? "pass" : "fail",
			detail: health?.ok
				? health.detail || "GET /health returned ok"
				: health?.detail || "missing health evidence",
		},
		{
			name: "readiness.capabilities",
			status:
				capabilities?.ok &&
				capabilities.runSubmission &&
				capabilities.runEventsSse &&
				capabilities.runStop &&
				capabilities.runApprovalResponse &&
				capabilities.bearerAuthRequired &&
				capabilities.serverToolExecution
					? "pass"
					: "fail",
			detail: capabilities?.detail || "missing /v1/capabilities evidence",
		},
		{
			name: "network.topology",
			status: topologyPasses ? "pass" : "fail",
			detail: topologyPasses
				? "Docker internal network contains only the contained Hermes server and relay"
				: network?.detail ||
					"missing dedicated internal Docker network evidence or unexpected peers are attached",
		},
		{
			name: "network.relay_only",
			status:
				network?.relayControlReachable &&
				network.directProviderDenied &&
				network.directVaultDenied &&
				network.directModelProviderDenied &&
				network.dnsPrivateDenied
					? "pass"
					: "fail",
			detail:
				network?.detail ||
				"missing relay reachability and direct provider/vault/model/private DNS denial evidence",
		},
		{
			name: "network.tamper_resistant",
			status:
				network?.tamper?.runtimeNonRoot && !network.tamper.forbiddenReachableAfterTamper
					? "pass"
					: "fail",
			detail:
				network?.tamper?.detail ||
				"missing in-container tamper probe evidence for firewall/route modification",
		},
	];
}

function topologyGatePasses(network: HermesApiServerContainmentObservation["network"]): boolean {
	return (
		network?.topologyInternal === true &&
		network.relayContainerPresent === true &&
		(network.unexpectedPeers?.length ?? 1) === 0
	);
}

function sanitizeObservation(
	observation: HermesApiServerContainmentObservation,
	plan: HermesApiServerLaunchPlan,
): HermesApiServerContainmentObservation {
	return JSON.parse(
		redactApiServerText(JSON.stringify(observation), plan),
	) as HermesApiServerContainmentObservation;
}

async function waitForHealth(
	plan: HermesApiServerLaunchPlan,
	timeoutMs: number | undefined,
): Promise<NonNullable<HermesApiServerContainmentObservation["health"]>> {
	const deadline = Date.now() + Math.min(timeoutMs ?? 60_000, 120_000);
	let lastDetail = "health endpoint was not reached";
	while (Date.now() < deadline) {
		const health = await readApiJson(plan, "/health", false, timeoutMs);
		if (health.ok) return { ok: true, status: "ok", detail: "GET /health returned ok" };
		lastDetail = health.detail;
		await new Promise((resolve) => setTimeout(resolve, 500));
	}
	return { ok: false, detail: lastDetail };
}

async function readCapabilities(
	plan: HermesApiServerLaunchPlan,
	timeoutMs: number | undefined,
): Promise<NonNullable<HermesApiServerContainmentObservation["capabilities"]>> {
	const result = await readApiJson(plan, "/v1/capabilities", true, timeoutMs);
	if (!result.ok) return { ok: false, detail: result.detail };
	const body = result.body;
	const features = objectAt(body, "features");
	const runtime = objectAt(body, "runtime");
	const auth = objectAt(body, "auth");
	const runSubmission = features?.run_submission === true;
	const runEventsSse = features?.run_events_sse === true;
	const runStop = features?.run_stop === true;
	const runApprovalResponse = features?.run_approval_response === true;
	const bearerAuthRequired = auth?.type === "bearer" && auth.required === true;
	const serverToolExecution = runtime?.tool_execution === "server";
	const splitRuntime = runtime?.split_runtime === true;
	return {
		ok: true,
		runSubmission,
		runEventsSse,
		runStop,
		runApprovalResponse,
		bearerAuthRequired,
		serverToolExecution,
		splitRuntime,
		detail:
			runSubmission &&
			runEventsSse &&
			runStop &&
			runApprovalResponse &&
			bearerAuthRequired &&
			serverToolExecution
				? "capabilities advertise runs, approvals, stop, bearer auth, and server-side tool execution"
				: "capabilities are missing one or more required API-server contract fields",
	};
}

async function readApiJson(
	plan: HermesApiServerLaunchPlan,
	pathname: string,
	authorized: boolean,
	timeoutMs: number | undefined,
): Promise<{ ok: boolean; detail: string; body?: Record<string, unknown> }> {
	const script = [
		"import json, os, sys, urllib.request",
		`url = "http://127.0.0.1:${plan.apiPort}${pathname}"`,
		"headers = {}",
		authorized ? 'headers["Authorization"] = "Bearer " + os.environ["API_SERVER_KEY"]' : "",
		"try:",
		"    req = urllib.request.Request(url, headers=headers)",
		"    with urllib.request.urlopen(req, timeout=5) as response:",
		"        print(response.read().decode('utf-8'))",
		"except Exception as exc:",
		"    print(str(exc), file=sys.stderr)",
		"    sys.exit(1)",
	]
		.filter(Boolean)
		.join("\n");
	const result = await runDockerCommand(
		plan,
		[
			"exec",
			...(authorized ? ["--env", "API_SERVER_KEY"] : []),
			plan.containerName,
			"python",
			"-c",
			script,
		],
		timeoutMs,
	);
	if (result.exitCode !== 0) {
		return { ok: false, detail: redactHermesRuntimeText(result.stderr || result.stdout) };
	}
	try {
		return { ok: true, detail: "request succeeded", body: JSON.parse(result.stdout) };
	} catch {
		return { ok: false, detail: "endpoint returned non-JSON output" };
	}
}

async function readContainerNetworkEvidence(
	plan: HermesApiServerLaunchPlan,
	options: {
		readonly timeoutMs?: number;
		readonly relayControlUrl?: string;
		readonly providerUrls?: readonly string[];
		readonly vaultSocketPath?: string;
		readonly modelProviderUrl?: string;
		readonly dnsPrivateUrls?: readonly string[];
	},
): Promise<NonNullable<HermesApiServerContainmentObservation["network"]>> {
	const topology = await inspectDockerNetworkTopology(plan, options.timeoutMs);
	const relayControlReachable = options.relayControlUrl
		? (await containerHttpProbe(plan, options.relayControlUrl, "allow", options.timeoutMs)).ok
		: false;
	const directProviderDenied =
		(options.providerUrls?.length ?? 0) > 0 &&
		(
			await Promise.all(
				(options.providerUrls ?? []).map((url) =>
					containerHttpProbe(plan, url, "deny", options.timeoutMs),
				),
			)
		).every((probe) => probe.ok);
	const directModelProviderDenied = options.modelProviderUrl
		? (await containerHttpProbe(plan, options.modelProviderUrl, "deny", options.timeoutMs)).ok
		: false;
	const dnsPrivateDenied =
		(options.dnsPrivateUrls?.length ?? 0) > 0 &&
		(
			await Promise.all(
				(options.dnsPrivateUrls ?? []).map((url) =>
					containerHttpProbe(plan, url, "deny", options.timeoutMs),
				),
			)
		).every((probe) => probe.ok);
	const directVaultDenied = options.vaultSocketPath
		? (
				await runDockerCommand(
					plan,
					["exec", plan.containerName, "test", "!", "-e", options.vaultSocketPath],
					options.timeoutMs,
				)
			).exitCode === 0
		: false;
	const tamper = await runTamperResistanceProbe(plan, options);
	return {
		topologyInternal: topology.internal,
		relayContainerPresent: topology.relayContainerPresent,
		unexpectedPeers: topology.unexpectedPeers,
		attachedContainers: topology.attachedContainers,
		relayControlReachable,
		directProviderDenied,
		directVaultDenied,
		directModelProviderDenied,
		dnsPrivateDenied,
		authoritativeBoundary: "docker_internal_network",
		networkName: plan.networkName,
		tamper,
		detail:
			topology.internal &&
			topology.relayContainerPresent &&
			topology.unexpectedPeers.length === 0 &&
			relayControlReachable &&
			directProviderDenied &&
			directVaultDenied &&
			directModelProviderDenied &&
			dnsPrivateDenied &&
			tamper.runtimeNonRoot &&
			!tamper.forbiddenReachableAfterTamper
				? "dedicated internal Docker network allows relay only and remains closed after tamper attempts"
				: "one or more topology, relay-only, or tamper-resistance checks failed",
	};
}

async function inspectDockerNetworkTopology(
	plan: HermesApiServerLaunchPlan,
	timeoutMs: number | undefined,
): Promise<{
	internal: boolean;
	relayContainerPresent: boolean;
	attachedContainers: string[];
	unexpectedPeers: string[];
}> {
	const result = await runDockerCommand(
		plan,
		["network", "inspect", plan.networkName, "--format", "{{json .}}"],
		timeoutMs,
	);
	if (result.exitCode !== 0) {
		return {
			internal: false,
			relayContainerPresent: false,
			attachedContainers: [],
			unexpectedPeers: [
				`network inspect failed: ${redactHermesRuntimeText(result.stderr || result.stdout)}`,
			],
		};
	}
	try {
		const inspected = JSON.parse(result.stdout) as {
			Internal?: unknown;
			Containers?: Record<string, { Name?: unknown }>;
		};
		const attachedContainers = Object.values(inspected.Containers ?? {})
			.map((container) => (typeof container.Name === "string" ? container.Name : ""))
			.filter((name) => name.length > 0)
			.sort();
		const allowed = new Set([plan.containerName, plan.relayContainerName]);
		return {
			internal: inspected.Internal === true,
			relayContainerPresent: attachedContainers.includes(plan.relayContainerName),
			attachedContainers,
			unexpectedPeers: attachedContainers.filter((name) => !allowed.has(name)),
		};
	} catch {
		return {
			internal: false,
			relayContainerPresent: false,
			attachedContainers: [],
			unexpectedPeers: ["network inspect returned malformed JSON"],
		};
	}
}

async function runTamperResistanceProbe(
	plan: HermesApiServerLaunchPlan,
	options: {
		readonly timeoutMs?: number;
		readonly modelProviderUrl?: string;
		readonly dnsPrivateUrls?: readonly string[];
	},
): Promise<NonNullable<NonNullable<HermesApiServerContainmentObservation["network"]>["tamper"]>> {
	const identity = await runDockerCommand(
		plan,
		[
			"exec",
			"--user",
			plan.runtimeUser,
			plan.containerName,
			"sh",
			"-lc",
			'printf \'%s:%s\' "$(id -u)" "$(id -un 2>/dev/null || printf unknown)"',
		],
		options.timeoutMs,
	);
	const [runtimeUid, runtimeUser] =
		identity.exitCode === 0 ? identity.stdout.trim().split(":", 2) : [];
	const firewallFlush = await runDockerCommand(
		plan,
		[
			"exec",
			"--user",
			plan.runtimeUser,
			plan.containerName,
			"sh",
			"-lc",
			"iptables -F OUTPUT >/dev/null 2>&1",
		],
		options.timeoutMs,
	);
	const routeAdd = await runDockerCommand(
		plan,
		[
			"exec",
			"--user",
			plan.runtimeUser,
			plan.containerName,
			"sh",
			"-lc",
			"ip route add 203.0.113.0/24 via 127.0.0.1 >/dev/null 2>&1",
		],
		options.timeoutMs,
	);
	const forbiddenTarget =
		options.modelProviderUrl || options.dnsPrivateUrls?.[0] || "http://169.254.169.254/";
	const forbiddenReachableAfterTamper = (
		await containerHttpProbe(plan, forbiddenTarget, "allow", options.timeoutMs, plan.runtimeUser)
	).ok;
	const tamperCommandSucceeded = firewallFlush.exitCode === 0 || routeAdd.exitCode === 0;
	const runtimeNonRoot = runtimeUid !== undefined && runtimeUid !== "" && runtimeUid !== "0";
	return {
		...(runtimeUid ? { runtimeUid } : {}),
		...(runtimeUser ? { runtimeUser } : {}),
		runtimeNonRoot,
		firewallFlushDenied: firewallFlush.exitCode !== 0,
		routeAddDenied: routeAdd.exitCode !== 0,
		tamperCommandSucceeded,
		forbiddenReachableAfterTamper,
		detail:
			runtimeNonRoot && !forbiddenReachableAfterTamper
				? tamperCommandSucceeded
					? "non-root runtime user ran a tamper command but topology still denied forbidden egress"
					: "non-root runtime user could not modify firewall/routes and forbidden egress stayed denied"
				: "runtime user is root/unknown or forbidden egress became reachable after tamper attempt",
	};
}

async function containerHttpProbe(
	plan: HermesApiServerLaunchPlan,
	url: string,
	expectation: "allow" | "deny",
	timeoutMs: number | undefined,
	user?: string,
): Promise<{ ok: boolean }> {
	const script = [
		"import sys, urllib.request",
		`url = ${JSON.stringify(url)}`,
		"try:",
		"    with urllib.request.urlopen(url, timeout=5) as response:",
		"        status = response.getcode()",
		"        print(status)",
		"        sys.exit(0)",
		"except Exception as exc:",
		"    print(str(exc), file=sys.stderr)",
		"    sys.exit(42)",
	].join("\n");
	const result = await runDockerCommand(
		plan,
		["exec", ...(user ? ["--user", user] : []), plan.containerName, "python", "-c", script],
		timeoutMs,
	);
	return { ok: expectation === "allow" ? result.exitCode === 0 : result.exitCode !== 0 };
}

async function runDockerCommand(
	plan: HermesApiServerLaunchPlan,
	args: string[],
	timeoutMs: number | undefined,
) {
	return runHermesLaunchInvocation(
		{
			command: plan.invocation.command,
			args,
			cwd: plan.invocation.cwd,
			env: plan.invocation.env,
		},
		{ timeoutMs },
	);
}

function objectAt(value: Record<string, unknown> | undefined, key: string) {
	const child = value?.[key];
	return typeof child === "object" && child !== null
		? (child as Record<string, unknown>)
		: undefined;
}

function cleanNonEmpty(value: string | undefined, fallback: string): string {
	const trimmed = value?.trim();
	return trimmed ? trimmed : fallback;
}

function normalizePort(value: number | undefined): number {
	if (value === undefined) return DEFAULT_HERMES_API_SERVER_PORT;
	if (!Number.isFinite(value) || value <= 0 || value > 65535) {
		throw new Error(`Invalid Hermes API-server port: ${value}`);
	}
	return Math.trunc(value);
}

function normalizeDigestPinnedImage(image: string): string {
	const trimmed = image.trim();
	const match = trimmed.match(/^([^\s@]+)@sha256:([a-f0-9]{64})$/i);
	if (!match) {
		throw new Error("Hermes API-server image must be pinned by sha256 digest");
	}
	const repository = match[1] ?? "";
	const lastComponent = repository.slice(repository.lastIndexOf("/") + 1);
	if (!repository || lastComponent.includes(":")) {
		throw new Error("Hermes API-server image must be pinned as repository@sha256:digest");
	}
	return trimmed;
}

function redactApiServerText(value: string, plan: HermesApiServerLaunchPlan): string {
	return redactSecrets(redactHermesRuntimeText(value)).replaceAll(
		plan.apiKey,
		"[REDACTED:ephemeral_api_auth]",
	);
}

function writeJsonArtifact(filePath: string, value: unknown): void {
	fs.mkdirSync(path.dirname(filePath), { recursive: true });
	const tmpPath = `${filePath}.tmp.${process.pid}`;
	fs.writeFileSync(tmpPath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
	fs.renameSync(tmpPath, filePath);
}
