import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import type { Command } from "commander";
import {
	buildHermesApiServerLaunchPlan,
	DEFAULT_HERMES_API_SERVER_CONTAINER_NAME,
	DEFAULT_HERMES_API_SERVER_CONTAINMENT_EVIDENCE_PATH,
	DEFAULT_HERMES_API_SERVER_DOCKER_IMAGE,
	DEFAULT_HERMES_API_SERVER_NETWORK,
	DEFAULT_HERMES_API_SERVER_PORT,
	DEFAULT_HERMES_RELAY_CONTAINER_NAME,
	DEFAULT_HERMES_RELAY_INTERNAL_HOST,
	runHermesApiServerContainmentProbe,
	runHermesApiServerDockerContainment,
	writeHermesApiServerContainmentEvidence,
} from "../hermes/api-server-containment.js";
import {
	DEFAULT_APPROVAL_CONTINUATION_EVIDENCE_PATH,
	evaluateApprovalContinuationEvidence,
} from "../hermes/approval-continuation.js";
import {
	runHermesApprovalContinuationProbe,
	writeApprovalContinuationArtifacts,
} from "../hermes/approval-continuation-runner.js";
import {
	buildEdgeAdapterProbeEvidence,
	isEdgeAdapterFeatureSurfaceId,
} from "../hermes/edge-adapter-probes.js";
import {
	allPrivateTelegramRequiredAssertions,
	analyzeVitestFixtureReport,
	buildCompatibilityLockfileDraft,
	buildCutoverInputBundleFromArtifacts,
	buildCutoverProofBundle,
	buildCutoverScopeManifestFromInventory,
	buildHermesDoctorReport,
	buildHermesGenerateDryRun,
	buildHermesQueueSnapshot,
	CutoverProofBundleSchema,
	collectFeatureProbeEvidence,
	DEFAULT_COMPAT_LOCKFILE_PATH,
	DEFAULT_CUTOVER_PROOF_BUNDLE_PATH,
	DEFAULT_CUTOVER_SCOPE_PATH,
	DEFAULT_DECISION_LOG_PATH,
	DEFAULT_FEATURE_PROBE_MATRIX_PATH,
	DEFAULT_FIXTURE_RESULTS_PATH,
	DEFAULT_INVENTORY_PATH,
	DEFAULT_NETWORK_PROBES_PATH,
	DEFAULT_NO_FORK_PROOF_PATH,
	DEFAULT_PROFILE_GENERATION_PROOF_PATH,
	DEFAULT_QUEUE_SNAPSHOT_PATH,
	DEFAULT_ROLLBACK_REHEARSAL_PATH,
	evaluateCutoverCheck,
	PRIVATE_TELEGRAM_FIXTURE_DIGEST_PATHS,
	PRIVATE_TELEGRAM_FIXTURE_REQUIREMENTS,
	PRIVATE_TELEGRAM_FIXTURE_TEST_FILES,
	parseHermesPin,
	privateTelegramAssertionKey,
	readJsonFile,
	readOptionalJsonFile,
	resolveHermesArtifactPath,
	writeHermesProfileGenerationProof,
} from "../hermes/foundation.js";
import { collectHermesInventory } from "../hermes/inventory.js";
import {
	DEFAULT_TELCLAUDE_LIVE_MCP_ADMIN_SOCKET,
	requestTelclaudeLiveMcpProbeTokens,
} from "../hermes/mcp/live-admin.js";
import type { TelclaudeLiveMcpProbeTokenBundle } from "../hermes/mcp/live-probe-tokens.js";
import {
	DEFAULT_TELCLAUDE_LIVE_MCP_NETWORK,
	type TelclaudeLiveMcpRuntimeProbeTokenInput,
} from "../hermes/mcp/live-runtime.js";
import {
	DEFAULT_SIDE_EFFECT_LEDGER_EVIDENCE_PATH,
	runTelclaudeMcpSideEffectLedgerProbe,
} from "../hermes/mcp/side-effect-ledger-probe.js";
import {
	DEFAULT_MODEL_RELAY_EVIDENCE_PATH,
	DEFAULT_MODEL_RELAY_POSTURE,
	type ModelRelayPosture,
	runHermesModelRelayProbe,
	writeHermesModelRelayEvidence,
} from "../hermes/model-relay.js";
import {
	DEFAULT_DNS_EXFIL_PROBE_URL,
	DEFAULT_FIREWALL_SENTINEL_PATH,
	DEFAULT_MODEL_PROVIDER_PROBE_URL,
	DEFAULT_NETWORK_PROBE_BUNDLE_PATH,
	DEFAULT_NETWORK_PROBE_EVIDENCE_DIR,
	DEFAULT_VAULT_SOCKET_PATH,
	type NetworkProbePosture,
	readHermesNetworkProbeRunReport,
	runHermesNetworkProbes,
	writeHermesNetworkProbeArtifacts,
} from "../hermes/network-probes.js";
import {
	buildNoForkProof,
	DEFAULT_HERMES_NO_FORK_EVIDENCE_PATH,
	DEFAULT_HERMES_UPSTREAM_CHECKOUT_PATH,
	DEFAULT_HERMES_UPSTREAM_REF,
	DEFAULT_HERMES_UPSTREAM_VERSION,
	writeNoForkProofReport,
} from "../hermes/no-fork-proof.js";
import {
	buildHermesCliProbeInvocation,
	DEFAULT_HERMES_CLI_HEADLESS_EVIDENCE_PATH,
	type HermesCliProbeReport,
	type HermesLaunchInvocation,
	readHermesCliHeadlessProbeReport,
	runHermesCliHeadlessProbe,
	runHermesLaunchInvocation,
} from "../hermes/private-runtime.js";
import {
	DEFAULT_PRO_REVIEW_NATIVE_CANARY_PATH,
	DEFAULT_PRO_REVIEW_REQUEST_PATH,
	evaluateProReviewCheck,
} from "../hermes/pro-review.js";
import {
	DEFAULT_PROVIDER_APPROVAL_BINDING_EVIDENCE_PATH,
	runTelclaudeProviderApprovalBindingProbe,
} from "../hermes/provider-approval-binding-probe.js";
import {
	DEFAULT_HERMES_ROLLBACK_REHEARSAL_EVIDENCE_PATH,
	runHermesRollbackRehearsal,
	writeHermesRollbackRehearsalEvidence,
} from "../hermes/rollback-rehearsal.js";
import {
	DEFAULT_SERVED_MCP_CONTAINED_CONTAINER_NAME,
	DEFAULT_SERVED_MCP_CONTAINMENT_EVIDENCE_PATH,
	runServedMcpContainmentProbe,
	type ServedMcpEndpoint,
	writeServedMcpContainmentEvidence,
} from "../hermes/served-mcp-containment.js";
import {
	buildServedMcpProviderToolsProbeEvidence,
	DEFAULT_SERVED_MCP_PROVIDER_TOOLS_EVIDENCE_PATH,
	DEFAULT_SERVED_MCP_PROVIDER_TOOLS_SOURCE_EVIDENCE_PATH,
	readServedMcpProviderToolsSourceEvidence,
} from "../hermes/served-mcp-provider-tools-probe.js";
import {
	relayGetHermesPrivateRuntimeState,
	relaySetHermesPrivateRuntimeMode,
} from "../relay/capabilities-client.js";

type JsonOption = {
	json?: boolean;
};

type PinOption = {
	pin?: string;
	lockfile?: string;
};

type ProbeOption = JsonOption & {
	allowRun?: boolean;
	apiPort?: string;
	containerName?: string;
	cwd?: string;
	dnsUrl?: string;
	dockerExecContainer?: string;
	dockerBin?: string;
	evidence: string;
	expectedPeerAddress?: string;
	firewallSentinel?: string;
	fromReport?: string;
	hermesBin?: string;
	hermesHome?: string;
	mcpAuth?: string;
	mcpForgedAuth?: string;
	mcpOffDomainPeerAuth?: string;
	mcpUrl?: string;
	mcpWrongConnectionAuth?: string;
	image?: string;
	modelUrl?: string;
	profileDir?: string;
	network?: string;
	out?: string;
	posture?: string;
	prompt?: string;
	providerUrl?: string;
	relayContainer?: string;
	relayPeerAddress?: string;
	relayHost?: string;
	relayUrl?: string;
	timeoutMs?: string;
	vaultSocket?: string;
	pin?: string;
};

type NetworkProbeOption = JsonOption & {
	allowRun?: boolean;
	fromReport?: string;
	out: string;
	evidenceDir: string;
	relayUrl?: string;
	providerUrl?: string;
	vaultUrl?: string;
	vaultSocket: string;
	modelUrl: string;
	dnsUrl: string;
	firewallSentinel: string;
	posture?: string;
	timeoutMs?: string;
};

type InventoryOption = JsonOption & {
	out?: string;
};

type RollbackRehearsalOption = JsonOption & {
	allowRun?: boolean;
	out: string;
	evidencePath?: string;
};

type QueueSnapshotOption = JsonOption & {
	inventory?: string;
	out?: string;
};

type ProofBundleOption = JsonOption &
	PinOption & {
		inventory: string;
		scopeManifest: string;
		decisionLog: string;
		compatibilityLockfile: string;
		featureProbeMatrix: string;
		fixtureResults: string;
		noforkProofFile: string;
		networkProbeBundle: string;
		queueSnapshot: string;
		rollbackEvidence: string;
		out?: string;
	};

type FixtureResultOption = JsonOption & {
	write?: boolean;
	out: string;
	evidenceDir: string;
	testReport?: string;
	reportOut: string;
	observedAt?: string;
};

type ProReviewCheckOption = JsonOption & {
	request: string;
	canary: string;
	requireApproval?: boolean;
};

type ProReviewSendOption = JsonOption & {
	request: string;
	canary: string;
	bundleOut?: string;
	execute?: boolean;
};

type PrivateRuntimeMode = "hermes" | "legacy";

type LiveMcpProbeTokenOption = JsonOption & {
	socket?: string;
	sessionKey?: string;
	profile?: string;
	profileId?: string;
	endpointId?: string;
	networkNamespace?: string;
	wrongSessionKey?: string;
	wrongProfile?: string;
	wrongEndpointId?: string;
	wrongNetworkNamespace?: string;
	actor?: string;
	memorySource?: string;
	writableNamespace?: string;
	providerScope?: string;
	providerScopes?: string;
	outboundChannel?: string;
	outboundChannels?: string;
	ttlMs?: string;
	peerAddress?: string;
	offDomainPeerAddress?: string;
	timeoutMs?: string;
};

function printJson(value: unknown): void {
	console.log(JSON.stringify(value, null, 2));
}

function resolvePin(options: PinOption) {
	const explicitPin = parseHermesPin(options.pin ?? process.env.TELCLAUDE_HERMES_PIN);
	if (explicitPin) return explicitPin;
	const lockfile = readOptionalJsonFile(
		resolveHermesArtifactPath(options.lockfile ?? DEFAULT_COMPAT_LOCKFILE_PATH),
	);
	if (
		typeof lockfile !== "object" ||
		lockfile === null ||
		!("hermes" in lockfile) ||
		typeof lockfile.hermes !== "object" ||
		lockfile.hermes === null
	) {
		return null;
	}
	const pin = lockfile.hermes as {
		version?: unknown;
		commit?: unknown;
		package?: unknown;
		imageDigest?: unknown;
	};
	const lockfilePin = {
		...(typeof pin.version === "string" && pin.version.trim()
			? { version: pin.version.trim() }
			: {}),
		...(typeof pin.commit === "string" && pin.commit.trim() ? { commit: pin.commit.trim() } : {}),
		...(typeof pin.package === "string" && pin.package.trim()
			? { package: pin.package.trim() }
			: {}),
		...(typeof pin.imageDigest === "string" && pin.imageDigest.trim()
			? { imageDigest: pin.imageDigest.trim() }
			: {}),
	};
	return Object.keys(lockfilePin).length > 0 ? lockfilePin : null;
}

function writeJsonArtifact(filePath: string, value: unknown): void {
	fs.mkdirSync(path.dirname(filePath), { recursive: true });
	const tmpPath = `${filePath}.tmp.${process.pid}`;
	fs.writeFileSync(tmpPath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
	fs.renameSync(tmpPath, filePath);
}

function cutoverProofArtifact(artifactPath: string, sourceCommand: string, gateIds: string[]) {
	return { artifactPath, sourceCommand, gateIds, checkIds: gateIds };
}

function resolveInventorySnapshotPath(explicitPath?: string): string | undefined {
	if (explicitPath) return explicitPath;
	return fs.existsSync(resolveHermesArtifactPath(DEFAULT_INVENTORY_PATH))
		? DEFAULT_INVENTORY_PATH
		: undefined;
}

function readInventorySnapshot(explicitPath?: string): unknown {
	const inventoryPath = resolveInventorySnapshotPath(explicitPath);
	return inventoryPath
		? readJsonFile(resolveHermesArtifactPath(inventoryPath))
		: collectHermesInventory();
}

function fileSha256(filePath: string): string {
	return `sha256:${crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex")}`;
}

function resolveProReviewBundlePath(bundleOut: string | undefined): string {
	return bundleOut
		? resolveHermesArtifactPath(bundleOut)
		: path.join(os.tmpdir(), `telclaude-hermes-pro-review-${process.pid}.md`);
}

function writeProReviewBundle(requestPath: string, bundlePath: string): void {
	const request = readJsonFile(resolveHermesArtifactPath(requestPath)) as {
		prompt?: unknown;
		selectedFiles?: unknown;
		payloadBinding?: { payloadSha256?: unknown };
		transport?: unknown;
		model?: unknown;
		fallbackAllowed?: unknown;
	};
	if (typeof request.prompt !== "string" || !Array.isArray(request.selectedFiles)) {
		throw new Error("Pro review request cannot be converted to a bundle");
	}
	const lines = [
		"# Telclaude Hermes Wrapper Pro Review",
		"",
		"## Request",
		"",
		request.prompt,
		"",
		"## Native Review Binding",
		"",
		`- transport: ${String(request.transport)}`,
		`- model: ${String(request.model)}`,
		`- fallbackAllowed: ${String(request.fallbackAllowed)}`,
		`- payloadSha256: ${String(request.payloadBinding?.payloadSha256 ?? "")}`,
		"",
		"## Files",
		"",
	];
	for (const file of request.selectedFiles) {
		if (typeof file !== "string") continue;
		const resolved = resolveHermesArtifactPath(file);
		lines.push(`### ${file}`, "", "```text", fs.readFileSync(resolved, "utf8"), "```", "");
	}
	fs.mkdirSync(path.dirname(bundlePath), { recursive: true });
	fs.writeFileSync(bundlePath, `${lines.join("\n")}\n`, "utf8");
}

type FixtureVitestInvocation = {
	command: string[];
	cwd: string;
	exitCode: 0;
	startedAt: string;
	endedAt: string;
	reportPath: string;
	reportSha256: string;
	sourceDigests: Record<string, string>;
};

function privateTelegramSourceDigests(): Record<string, string> {
	return Object.fromEntries(
		PRIVATE_TELEGRAM_FIXTURE_DIGEST_PATHS.map((sourcePath) => [
			sourcePath,
			fileSha256(resolveHermesArtifactPath(sourcePath)),
		]),
	);
}

function runPrivateTelegramFixtureVitest(reportPath: string): FixtureVitestInvocation {
	const startedAt = new Date().toISOString();
	const command = [
		"pnpm",
		"exec",
		"vitest",
		"run",
		...PRIVATE_TELEGRAM_FIXTURE_TEST_FILES,
		"--reporter=json",
		`--outputFile=${reportPath}`,
	];
	fs.mkdirSync(path.dirname(resolveHermesArtifactPath(reportPath)), { recursive: true });
	const result = spawnSync(command[0], command.slice(1), {
		cwd: process.cwd(),
		encoding: "utf8",
	});
	const endedAt = new Date().toISOString();
	if (result.error) {
		throw result.error;
	}
	if (result.status !== 0) {
		throw new Error(
			`private Telegram Vitest fixture command exited ${String(result.status)}: ${result.stderr}`,
		);
	}
	return {
		command,
		cwd: process.cwd(),
		exitCode: 0,
		startedAt,
		endedAt,
		reportPath,
		reportSha256: fileSha256(resolveHermesArtifactPath(reportPath)),
		sourceDigests: privateTelegramSourceDigests(),
	};
}

function buildPrivateTelegramFixtureResultBundle(options: {
	testReportPath: string;
	evidenceDir: string;
	observedAt: string;
	invocation?: FixtureVitestInvocation;
}): {
	schemaVersion: 1;
	results: Array<{ id: string; status: "pass" | "fail"; evidence_path: string }>;
	evidence: unknown[];
} {
	const resolvedReport = resolveHermesArtifactPath(options.testReportPath);
	const report = analyzeVitestFixtureReport(resolvedReport, allPrivateTelegramRequiredAssertions());
	if (report.failures.length > 0) {
		throw new Error(`Vitest fixture report failed validation: ${report.failures.join("; ")}`);
	}
	const reportDigest = fileSha256(resolvedReport);
	const evidence = PRIVATE_TELEGRAM_FIXTURE_REQUIREMENTS.map((fixture) => {
		const checks = fixture.requiredAssertions.map((assertion) => ({
			name: assertion.fullName,
			status:
				report.statuses.get(privateTelegramAssertionKey(assertion)) === "passed" ? "pass" : "fail",
			detail:
				report.statuses.get(privateTelegramAssertionKey(assertion)) === "passed"
					? "required fixture assertion passed in machine-observed Vitest report"
					: `required fixture assertion status is ${
							report.statuses.get(privateTelegramAssertionKey(assertion)) ?? "missing"
						}`,
		}));
		const status = checks.every((check) => check.status === "pass") ? "pass" : "fail";
		const evidencePath = path.join(options.evidenceDir, `${fixture.id}.json`);
		return {
			schemaVersion: "telclaude.hermes.fixture-evidence.v1",
			id: fixture.id,
			status,
			ran: true,
			evidence_path: evidencePath,
			observedAt: options.observedAt,
			provenance: {
				runner: "vitest-json",
				command: options.invocation?.command.join(" "),
				source: options.invocation ? "machine-observed-test-report" : "imported-test-report",
			},
			testReport: {
				path: options.testReportPath,
				sha256: reportDigest,
				requiredTests: fixture.requiredTests,
				requiredAssertions: fixture.requiredAssertions,
			},
			...(options.invocation ? { invocation: options.invocation } : {}),
			checks,
		};
	});
	return {
		schemaVersion: 1,
		results: evidence.map((item) => ({
			id: item.id,
			status: item.status as "pass" | "fail",
			evidence_path: item.evidence_path,
		})),
		evidence,
	};
}

function resolveHermesBin(value: string | undefined): string {
	return value?.trim() || process.env.TELCLAUDE_HERMES_BIN?.trim() || "hermes";
}

function resolveHermesHome(value: string | undefined): string {
	return path.resolve(
		value?.trim() ||
			process.env.TELCLAUDE_HERMES_HOME?.trim() ||
			path.join(os.tmpdir(), "telclaude-hermes-cli-headless"),
	);
}

function runHermesLaunchInvocationInDockerExec(
	invocation: HermesLaunchInvocation,
	options: { dockerBin?: string; containerName: string; timeoutMs?: number },
): Promise<{
	exitCode: number;
	stdout: string;
	stderr: string;
	runtime?: HermesCliProbeReport["runtime"];
}> {
	const dockerBin = options.dockerBin?.trim() || process.env.DOCKER_BIN?.trim() || "docker";
	const runtime = collectDockerExecRuntimeEvidence(
		dockerBin,
		options.containerName,
		options.timeoutMs,
	);
	const args = ["exec", "-i", "-w", invocation.cwd];
	for (const [key, value] of Object.entries(invocation.env).sort(([left], [right]) =>
		left.localeCompare(right),
	)) {
		args.push("-e", `${key}=${value}`);
	}
	args.push(options.containerName, invocation.command, ...invocation.args);
	const result = spawnSync(dockerBin, args, {
		encoding: "utf8",
		env: { PATH: process.env.PATH ?? "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin" },
		timeout: options.timeoutMs,
	});
	return Promise.resolve({
		exitCode: result.status ?? (result.signal ? 124 : 1),
		stdout: result.stdout ?? "",
		stderr: [
			runtime.stderr,
			result.stderr ?? "",
			result.error ? `failed to launch docker exec Hermes probe: ${result.error.message}` : "",
		]
			.filter(Boolean)
			.join("\n"),
		...(runtime.evidence ? { runtime: runtime.evidence } : {}),
	});
}

function collectDockerExecRuntimeEvidence(
	dockerBin: string,
	containerName: string,
	timeoutMs: number | undefined,
): { evidence?: HermesCliProbeReport["runtime"]; stderr: string } {
	const inspect = spawnSync(dockerBin, ["inspect", containerName, "--format", "{{json .}}"], {
		encoding: "utf8",
		env: { PATH: process.env.PATH ?? "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin" },
		timeout: timeoutMs,
	});
	if (inspect.status !== 0) {
		return {
			stderr: `failed to inspect Hermes container ${containerName}: ${inspect.stderr || inspect.error?.message || "unknown error"}`,
		};
	}
	try {
		const data = JSON.parse(inspect.stdout) as {
			Id?: string;
			Image?: string;
			Config?: { Image?: string; Hostname?: string };
			NetworkSettings?: { Networks?: Record<string, { IPAddress?: string }> };
		};
		const networkName = "telclaude-hermes-relay";
		const containerIpAddress = data.NetworkSettings?.Networks?.[networkName]?.IPAddress?.trim();
		const relayObservation = resolveDockerRelayObservation(dockerBin, containerName, timeoutMs);
		if (
			!containerIpAddress ||
			!relayObservation.relayResolvedAddress ||
			!relayObservation.observedPeerAddress
		) {
			return {
				stderr: [
					containerIpAddress ? "" : `Hermes container ${containerName} is not on ${networkName}`,
					relayObservation.stderr,
				]
					.filter(Boolean)
					.join("\n"),
			};
		}
		return {
			evidence: {
				kind: "contained-docker",
				containerName,
				networkName,
				containerId: data.Id ?? containerName,
				image: data.Config?.Image ?? data.Image ?? "unknown",
				imageDigest: normalizeDockerImageDigest(data.Image),
				hostname: data.Config?.Hostname ?? containerName,
				relayHost: "telclaude",
				relayResolvedAddress: relayObservation.relayResolvedAddress,
				containerIpAddress,
				observedPeerAddress: relayObservation.observedPeerAddress,
				provenanceSource: "docker-inspect-container-dns-and-relay-peer",
			},
			stderr: relayObservation.stderr,
		};
	} catch (error) {
		return {
			stderr: `failed to parse Hermes container inspect output: ${
				error instanceof Error ? error.message : String(error)
			}`,
		};
	}
}

function resolveDockerRelayObservation(
	dockerBin: string,
	containerName: string,
	timeoutMs: number | undefined,
): { relayResolvedAddress?: string; observedPeerAddress?: string; stderr: string } {
	const script = [
		"import json, socket, urllib.request",
		"relay_ip = socket.gethostbyname('telclaude')",
		"request = urllib.request.Request('http://telclaude:8790/v1/models', method='GET')",
		"with urllib.request.urlopen(request, timeout=5) as response:",
		"    observed_peer = response.headers.get('x-telclaude-model-relay-observed-peer-address', '')",
		"print(json.dumps({'relayResolvedAddress': relay_ip, 'observedPeerAddress': observed_peer}, sort_keys=True))",
	].join("\n");
	const result = spawnSync(dockerBin, ["exec", containerName, "python", "-c", script], {
		encoding: "utf8",
		env: { PATH: process.env.PATH ?? "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin" },
		timeout: timeoutMs,
	});
	if (result.status !== 0) {
		return {
			stderr: `failed to resolve telclaude from Hermes container ${containerName}: ${
				result.stderr || result.error?.message || "unknown error"
			}`,
		};
	}
	try {
		const parsed = JSON.parse(result.stdout) as {
			relayResolvedAddress?: string;
			observedPeerAddress?: string;
		};
		return {
			relayResolvedAddress: parsed.relayResolvedAddress?.trim(),
			observedPeerAddress: parsed.observedPeerAddress?.trim(),
			stderr: "",
		};
	} catch (error) {
		return {
			stderr: `failed to parse relay observation from Hermes container ${containerName}: ${
				error instanceof Error ? error.message : String(error)
			}`,
		};
	}
}

function normalizeDockerImageDigest(value: string | undefined): `sha256:${string}` {
	const image = value?.trim() ?? "";
	if (image.startsWith("sha256:")) return image as `sha256:${string}`;
	return `sha256:${crypto.createHash("sha256").update(image).digest("hex")}`;
}

function parseTimeoutMs(value: string | undefined): number | undefined {
	if (!value?.trim()) return undefined;
	const parsed = Number.parseInt(value, 10);
	if (!Number.isFinite(parsed) || parsed <= 0) {
		throw new Error(`Invalid --timeout-ms value: ${value}`);
	}
	return parsed;
}

function parseNetworkProbePosture(value: string | undefined): NetworkProbePosture {
	const posture =
		value?.trim() || process.env.TELCLAUDE_HERMES_NETWORK_PROBE_POSTURE?.trim() || "agent-iptables";
	if (posture === "agent-iptables" || posture === "contained-internal") return posture;
	throw new Error(`Invalid network probe posture: ${posture}`);
}

function parseModelRelayPosture(value: string | undefined): ModelRelayPosture {
	const posture =
		value?.trim() ||
		process.env.TELCLAUDE_HERMES_MODEL_RELAY_POSTURE?.trim() ||
		DEFAULT_MODEL_RELAY_POSTURE;
	if (posture === "agent-iptables" || posture === "contained-internal") return posture;
	throw new Error(`Invalid model-relay posture: ${posture}`);
}

function parsePort(value: string | undefined): number | undefined {
	if (!value?.trim()) return undefined;
	const parsed = Number.parseInt(value, 10);
	if (!Number.isFinite(parsed) || parsed <= 0 || parsed > 65535) {
		throw new Error(`Invalid --api-port value: ${value}`);
	}
	return parsed;
}

function parseCsvOption(value: string | undefined): string[] {
	return (value ?? "")
		.split(",")
		.map((entry) => entry.trim())
		.filter((entry) => entry.length > 0);
}

function resolveServedMcpOriginConfig(): {
	containerName: string;
	expectedPeerAddress?: string;
	relayPeerAddress?: string;
} {
	const expectedPeerAddress = resolveServedMcpExpectedPeerAddress();
	const relayPeerAddress = optionalConfiguredIp(
		process.env.TELCLAUDE_HERMES_RELAY_IP,
		"TELCLAUDE_HERMES_RELAY_IP",
	);
	return {
		containerName: DEFAULT_SERVED_MCP_CONTAINED_CONTAINER_NAME,
		...(expectedPeerAddress ? { expectedPeerAddress } : {}),
		...(relayPeerAddress ? { relayPeerAddress } : {}),
	};
}

function resolveServedMcpExpectedPeerAddress(): string | undefined {
	const containedIp = optionalConfiguredIp(
		process.env.TELCLAUDE_HERMES_CONTAINED_IP,
		"TELCLAUDE_HERMES_CONTAINED_IP",
	);
	if (containedIp) return containedIp;
	const allowedPeers = parseCsvOption(process.env.TELCLAUDE_HERMES_LIVE_MCP_ALLOWED_PEERS);
	if (allowedPeers.length === 0) return undefined;
	if (allowedPeers.length > 1) {
		throw new Error(
			"TELCLAUDE_HERMES_CONTAINED_IP is required when TELCLAUDE_HERMES_LIVE_MCP_ALLOWED_PEERS contains multiple peers",
		);
	}
	return requiredConfiguredIp(allowedPeers[0], "TELCLAUDE_HERMES_LIVE_MCP_ALLOWED_PEERS");
}

function optionalConfiguredIp(value: string | undefined, name: string): string | undefined {
	const trimmed = value?.trim();
	return trimmed ? requiredConfiguredIp(trimmed, name) : undefined;
}

function requiredConfiguredIp(value: string | undefined, name: string): string {
	const trimmed = value?.trim();
	if (!trimmed || net.isIP(trimmed) === 0) {
		throw new Error(`${name} must be an IP address`);
	}
	return trimmed;
}

function parsePositiveIntegerOption(
	value: string | undefined,
	optionName: string,
): number | undefined {
	if (!value?.trim()) return undefined;
	const parsed = Number.parseInt(value, 10);
	if (!Number.isFinite(parsed) || parsed <= 0) {
		throw new Error(`Invalid ${optionName} value: ${value}`);
	}
	return parsed;
}

function parseHeaderOption(value: string | undefined): Record<string, string> | undefined {
	if (!value?.trim()) return undefined;
	const separatorIndex = value.indexOf(":");
	if (separatorIndex <= 0) {
		throw new Error("MCP auth header must use 'Name: value' format");
	}
	const name = value.slice(0, separatorIndex).trim();
	const headerValue = value.slice(separatorIndex + 1).trim();
	if (!name || !headerValue) {
		throw new Error("MCP auth header must include a non-empty name and value");
	}
	return { [name]: headerValue };
}

function resolveLiveMcpAdminSocket(value: string | undefined): string {
	return (
		value?.trim() ||
		process.env.TELCLAUDE_HERMES_LIVE_MCP_ADMIN_SOCKET?.trim() ||
		DEFAULT_TELCLAUDE_LIVE_MCP_ADMIN_SOCKET
	);
}

function buildLiveMcpProbeTokenRequest(
	options: LiveMcpProbeTokenOption,
): TelclaudeLiveMcpRuntimeProbeTokenInput {
	const profileId = nonEmptyOption(options.profileId ?? options.profile, "default");
	const endpointId = nonEmptyOption(options.endpointId, "tc-hermes-private");
	const networkNamespace = nonEmptyOption(
		options.networkNamespace,
		process.env.TELCLAUDE_HERMES_LIVE_MCP_NETWORK?.trim() || DEFAULT_TELCLAUDE_LIVE_MCP_NETWORK,
	);
	const wrongProfileId = nonEmptyOption(
		options.wrongProfile,
		profileId === "social" ? "default" : "social",
	);
	const wrongEndpointId = nonEmptyOption(options.wrongEndpointId, "tc-hermes-wrong");
	const wrongNetworkNamespace = nonEmptyOption(options.wrongNetworkNamespace, networkNamespace);
	const providerScopes = parseCsvOption(options.providerScopes ?? options.providerScope ?? "bank");
	const outboundChannels = parseCsvOption(
		options.outboundChannels ?? options.outboundChannel ?? "whatsapp",
	);

	return {
		privateConnection: {
			sessionKey: nonEmptyOption(options.sessionKey, "probe:private"),
			profileId,
			endpointId,
			networkNamespace,
		},
		wrongConnection: {
			sessionKey: nonEmptyOption(options.wrongSessionKey, "probe:wrong"),
			profileId: wrongProfileId,
			endpointId: wrongEndpointId,
			networkNamespace: wrongNetworkNamespace,
		},
		privateAuthority: {
			actorId: nonEmptyOption(options.actor, "operator:probe"),
			profileId,
			domain: "private",
			memorySource: nonEmptyOption(options.memorySource, `telegram:${profileId}`),
			writableNamespace: nonEmptyOption(options.writableNamespace, `private:${profileId}`),
			providerScopes,
			outboundChannels,
			endpointId,
			networkNamespace,
		},
		ttlMs: parsePositiveIntegerOption(options.ttlMs, "--ttl-ms"),
		peerAddress: options.peerAddress?.trim() || undefined,
		offDomainPeerAddress: options.offDomainPeerAddress?.trim() || undefined,
	};
}

function nonEmptyOption(value: string | undefined, fallback: string): string {
	const resolved = value?.trim() || fallback;
	if (!resolved.trim()) throw new Error("Hermes live-MCP probe-token option resolved empty");
	return resolved;
}

function formatLiveMcpProbeTokenExports(response: TelclaudeLiveMcpProbeTokenBundle): string {
	return [
		`export TELCLAUDE_HERMES_SERVED_MCP_AUTH=${shellQuote(
			`Authorization: ${response.allowed.authorizationHeader}`,
		)}`,
		`export TELCLAUDE_HERMES_SERVED_MCP_OFF_DOMAIN_PEER_AUTH=${shellQuote(
			`Authorization: ${response.offDomainPeer.authorizationHeader}`,
		)}`,
		`export TELCLAUDE_HERMES_SERVED_MCP_WRONG_CONNECTION_AUTH=${shellQuote(
			`Authorization: ${response.wrongConnection.authorizationHeader}`,
		)}`,
		`export TELCLAUDE_HERMES_SERVED_MCP_FORGED_AUTH=${shellQuote(
			`Authorization: ${response.forged.authorizationHeader}`,
		)}`,
		`# expires_at_ms=${response.metadata.expiresAtMs}`,
	].join("\n");
}

function formatLiveMcpProbeTokenJson(response: TelclaudeLiveMcpProbeTokenBundle): unknown {
	return {
		schemaVersion: "telclaude.hermes.live-mcp.probe-token-cli.v1",
		type: "probe_tokens",
		env: {
			TELCLAUDE_HERMES_SERVED_MCP_AUTH: `Authorization: ${response.allowed.authorizationHeader}`,
			TELCLAUDE_HERMES_SERVED_MCP_OFF_DOMAIN_PEER_AUTH: `Authorization: ${response.offDomainPeer.authorizationHeader}`,
			TELCLAUDE_HERMES_SERVED_MCP_WRONG_CONNECTION_AUTH: `Authorization: ${response.wrongConnection.authorizationHeader}`,
			TELCLAUDE_HERMES_SERVED_MCP_FORGED_AUTH: `Authorization: ${response.forged.authorizationHeader}`,
		},
		metadata: response.metadata,
	};
}

function shellQuote(value: string): string {
	return `'${value.replace(/'/g, "'\\''")}'`;
}

function servedMcpEndpoint(
	url: string | undefined,
	header: string | undefined,
): ServedMcpEndpoint | undefined {
	const resolvedUrl = url?.trim() || process.env.TELCLAUDE_HERMES_SERVED_MCP_URL?.trim();
	if (!resolvedUrl) return undefined;
	return { url: resolvedUrl, headers: parseHeaderOption(header) };
}

function collectHermesFeatureProbeEvidence(featureProbeMatrix: unknown) {
	const collected = collectFeatureProbeEvidence(featureProbeMatrix) ?? {
		schemaVersion: 1,
		results: [],
	};
	if (
		typeof featureProbeMatrix !== "object" ||
		featureProbeMatrix === null ||
		!("probes" in featureProbeMatrix) ||
		!Array.isArray(featureProbeMatrix.probes)
	) {
		return collected;
	}
	const approvalProbes = featureProbeMatrix.probes.filter(
		(probe) =>
			typeof probe === "object" &&
			probe !== null &&
			"surface_id" in probe &&
			(probe.surface_id === "execution.approval_continuation" ||
				probe.surface_id === "approval.continuation") &&
			"evidence_path" in probe &&
			typeof probe.evidence_path === "string",
	);
	if (approvalProbes.length === 0) return collected;
	return {
		schemaVersion: 1 as const,
		results: [
			...collected.results,
			...approvalProbes.map((approvalProbe) => {
				const evidencePath = resolveHermesArtifactPath(approvalProbe.evidence_path);
				const report = evaluateApprovalContinuationEvidence(readOptionalJsonFile(evidencePath), {
					missingPath: evidencePath,
				});
				return {
					surface_id: approvalProbe.surface_id,
					status:
						report.status === "pass" && report.productionEnable
							? ("pass" as const)
							: ("fail" as const),
					evidence_path: approvalProbe.evidence_path,
					detail:
						report.status === "pass" && report.productionEnable
							? `approval-continuation evidence passed in ${report.mode} mode`
							: report.gates.map((gate) => gate.detail).join("; "),
				};
			}),
		],
	};
}

function readWrapperPackageVersion(): string {
	const packageJson = readJsonFile(resolveHermesArtifactPath("package.json"));
	if (
		typeof packageJson === "object" &&
		packageJson !== null &&
		"version" in packageJson &&
		typeof packageJson.version === "string"
	) {
		return packageJson.version;
	}
	throw new Error("package.json is missing a string version");
}

export function registerHermesCommand(program: Command): void {
	const hermes = program
		.command("hermes")
		.description("Inspect and generate the no-fork Hermes wrapper foundation");

	hermes
		.command("doctor")
		.description("Check pinned Hermes wrapper readiness")
		.option("--json", "Emit structured JSON")
		.option("--pin <pin>", "Pinned Hermes version, commit, package, or image digest")
		.option(
			"--feature-probes <path>",
			"Feature-probe matrix JSON path",
			DEFAULT_FEATURE_PROBE_MATRIX_PATH,
		)
		.option("--probes", "Require and validate the feature-probe matrix")
		.option("--lockfile <path>", "Compatibility lockfile JSON path", DEFAULT_COMPAT_LOCKFILE_PATH)
		.option("--compat-lock", "Require and validate the compatibility lockfile")
		.action(
			(
				options: JsonOption &
					PinOption & {
						featureProbes: string;
						probes?: boolean;
						lockfile: string;
						compatLock?: boolean;
					},
			) => {
				let featureProbeMatrix: unknown;
				let featureProbeMatrixMissing: string | undefined;
				if (options.probes) {
					const artifactPath = resolveHermesArtifactPath(options.featureProbes);
					featureProbeMatrix = readOptionalJsonFile(artifactPath);
					if (featureProbeMatrix === undefined) {
						featureProbeMatrixMissing = `required feature-probe matrix is missing: ${artifactPath}`;
					}
				}

				let lockfile: unknown;
				let lockfileMissing: string | undefined;
				if (options.compatLock) {
					const artifactPath = resolveHermesArtifactPath(options.lockfile);
					lockfile = readOptionalJsonFile(artifactPath);
					if (lockfile === undefined) {
						lockfileMissing = `required compatibility lockfile is missing: ${artifactPath}`;
					}
				}

				const report = buildHermesDoctorReport({
					pin: resolvePin(options),
					featureProbeMatrix,
					featureProbeMatrixMissing,
					lockfile,
					lockfileMissing,
				});
				if (options.json) {
					printJson(report);
				} else {
					console.log(`Hermes wrapper doctor: ${report.status}`);
					for (const check of report.checks) {
						console.log(`- ${check.status.toUpperCase()} ${check.name}: ${check.detail}`);
					}
				}
				process.exitCode = report.status === "pass" ? 0 : 1;
			},
		);

	hermes
		.command("generate")
		.description("Generate Hermes wrapper profile artifacts")
		.option("--dry-run", "Preview generated artifacts without writing files")
		.option("--write", "Write generated profile artifacts and proof")
		.option("--json", "Emit structured JSON")
		.option("--pin <pin>", "Pinned Hermes version, commit, package, or image digest")
		.option("--out <dir>", "Output directory for generated Hermes profiles", "/tmp/tc-hermes")
		.option("--lockfile <path>", "Compatibility lockfile JSON path", DEFAULT_COMPAT_LOCKFILE_PATH)
		.option(
			"--proof-out <path>",
			"Profile generation proof JSON path",
			DEFAULT_PROFILE_GENERATION_PROOF_PATH,
		)
		.action(
			(
				options: JsonOption &
					PinOption & {
						out: string;
						dryRun?: boolean;
						write?: boolean;
						lockfile: string;
						proofOut: string;
					},
			) => {
				try {
					if (options.dryRun && options.write) {
						throw new Error("Use either --dry-run or --write, not both.");
					}
					if (options.write) {
						const report = writeHermesProfileGenerationProof({
							pin: resolvePin(options),
							outDir: options.out,
							lockfile: readJsonFile(resolveHermesArtifactPath(options.lockfile)),
							evidencePath: options.proofOut,
						});
						if (options.json) {
							printJson(report);
						} else {
							console.log(`Hermes generate proof: ${report.status}`);
							console.log(`- outDir ${report.outDir}`);
							console.log(`- proof ${report.evidence_path}`);
						}
						process.exitCode = report.status === "pass" ? 0 : 1;
						return;
					}
					const report = buildHermesGenerateDryRun({
						pin: resolvePin(options),
						outDir: options.out,
					});
					if (options.json) {
						printJson(report);
					} else {
						console.log(`Hermes generate dry-run: ${report.outDir}`);
						for (const output of report.outputs) {
							console.log(`- ${output.classification} ${output.path}`);
						}
					}
					process.exitCode = 0;
				} catch (error) {
					console.error(`Error: ${String(error instanceof Error ? error.message : error)}`);
					process.exitCode = 1;
				}
			},
		);

	hermes
		.command("fixtures")
		.description("Generate Hermes wrapper parity fixture result artifacts")
		.option("--json", "Emit structured JSON")
		.option("--write", "Write fixture result bundle and per-fixture evidence")
		.option(
			"--test-report <path>",
			"Import an existing Vitest JSON report as non-production evidence",
		)
		.option(
			"--report-out <path>",
			"Machine-observed Vitest JSON report output path",
			"artifacts/hermes/fixtures/private-telegram-vitest.json",
		)
		.option("--out <path>", "Fixture result bundle JSON path", DEFAULT_FIXTURE_RESULTS_PATH)
		.option(
			"--evidence-dir <dir>",
			"Directory for generated per-fixture evidence",
			"artifacts/hermes/fixtures",
		)
		.option("--observed-at <iso>", "Observed timestamp for generated evidence")
		.action((options: FixtureResultOption) => {
			try {
				const observedAt = options.observedAt ?? new Date().toISOString();
				const invocation = options.testReport
					? undefined
					: runPrivateTelegramFixtureVitest(options.reportOut);
				const bundle = buildPrivateTelegramFixtureResultBundle({
					testReportPath: options.testReport ?? options.reportOut,
					evidenceDir: options.evidenceDir,
					observedAt,
					invocation,
				});
				if (options.write) {
					if (options.testReport) {
						throw new Error(
							"Imported private Telegram fixture reports cannot be written; omit --test-report so the command runs Vitest and records machine-observed evidence.",
						);
					}
					for (const evidence of bundle.evidence) {
						const evidencePath =
							typeof evidence === "object" &&
							evidence !== null &&
							"evidence_path" in evidence &&
							typeof evidence.evidence_path === "string"
								? evidence.evidence_path
								: undefined;
						if (!evidencePath) throw new Error("fixture evidence is missing evidence_path");
						writeJsonArtifact(evidencePath, evidence);
					}
					writeJsonArtifact(options.out, {
						schemaVersion: bundle.schemaVersion,
						results: bundle.results,
					});
				}
				const report = {
					schemaVersion: 1,
					status: bundle.results.every((result) => result.status === "pass") ? "pass" : "fail",
					written: options.write === true,
					out: options.out,
					results: bundle.results,
				};
				if (options.json) {
					printJson(report);
				} else {
					console.log(`Hermes fixtures: ${report.status}`);
					for (const result of bundle.results) {
						console.log(`- ${result.status.toUpperCase()} ${result.id}: ${result.evidence_path}`);
					}
				}
				process.exitCode = report.status === "pass" ? 0 : 1;
			} catch (error) {
				const detail = String(error instanceof Error ? error.message : error);
				if (options.json) {
					printJson({ schemaVersion: 1, status: "input_error", detail });
				} else {
					console.error(`Error: ${detail}`);
				}
				process.exitCode = 1;
			}
		});

	hermes
		.command("prove")
		.description("Generate fail-closed Hermes wrapper proof artifacts")
		.option("--json", "Emit structured JSON")
		.option("--upstream-clean", "Prove the pinned upstream Hermes checkout is clean")
		.option("--p0", "Evaluate P0 migration proof gates")
		.option(
			"--checkout <path>",
			"Upstream Hermes checkout path",
			DEFAULT_HERMES_UPSTREAM_CHECKOUT_PATH,
		)
		.option("--expected-ref <ref>", "Pinned upstream Hermes ref", DEFAULT_HERMES_UPSTREAM_REF)
		.option(
			"--expected-version <version>",
			"Pinned upstream Hermes package version",
			DEFAULT_HERMES_UPSTREAM_VERSION,
		)
		.option("--out <path>", "No-fork proof evidence path", DEFAULT_HERMES_NO_FORK_EVIDENCE_PATH)
		.option(
			"--inventory <path>",
			"P0 inventory snapshot JSON path; collects live inventory when omitted",
		)
		.option("--scope <path>", "P0 cutover scope manifest JSON path", DEFAULT_CUTOVER_SCOPE_PATH)
		.option("--decisions <path>", "P0 decision log JSON path", DEFAULT_DECISION_LOG_PATH)
		.option(
			"--proof-bundle <path>",
			"P0 cutover proof bundle JSON path",
			DEFAULT_CUTOVER_PROOF_BUNDLE_PATH,
		)
		.option(
			"--feature-probes <path>",
			"P0 feature-probe matrix JSON path",
			DEFAULT_FEATURE_PROBE_MATRIX_PATH,
		)
		.option(
			"--lockfile <path>",
			"P0 compatibility lockfile JSON path",
			DEFAULT_COMPAT_LOCKFILE_PATH,
		)
		.option("--fixtures <path>", "P0 fixture result bundle JSON path", DEFAULT_FIXTURE_RESULTS_PATH)
		.option(
			"--network-probes <path>",
			"P0 network probe bundle JSON path",
			DEFAULT_NETWORK_PROBES_PATH,
		)
		.option(
			"--profile-proof <path>",
			"P0 profile generation proof JSON path",
			DEFAULT_PROFILE_GENERATION_PROOF_PATH,
		)
		.option(
			"--rollback <path>",
			"P0 rollback rehearsal evidence JSON path",
			DEFAULT_ROLLBACK_REHEARSAL_PATH,
		)
		.action(
			(
				options: JsonOption & {
					upstreamClean?: boolean;
					p0?: boolean;
					checkout: string;
					expectedRef: string;
					expectedVersion: string;
					out: string;
					inventory?: string;
					scope: string;
					decisions: string;
					proofBundle: string;
					featureProbes: string;
					lockfile: string;
					fixtures: string;
					networkProbes: string;
					profileProof: string;
					rollback: string;
				},
			) => {
				if (!options.upstreamClean) {
					const report = {
						schemaVersion: 1,
						hermesCheckoutClean: false,
						evidence_path: options.out,
						checks: [
							{
								name: "prove.upstreamClean",
								status: "fail",
								detail: "pass --upstream-clean to prove the pinned Hermes checkout",
							},
						],
					};
					if (options.json) {
						printJson(report);
					} else {
						console.log("Hermes prove: fail");
						console.log("- FAIL prove.upstreamClean: pass --upstream-clean");
					}
					process.exitCode = 2;
					return;
				}
				const report = writeNoForkProofReport(
					buildNoForkProof({
						checkoutPath: options.checkout,
						expectedRef: options.expectedRef,
						expectedVersion: options.expectedVersion,
						evidencePath: options.out,
					}),
				);
				if (options.p0) {
					const strict = true;
					const dryRun = true;
					try {
						const featureProbeMatrix = readJsonFile(
							resolveHermesArtifactPath(options.featureProbes),
						);
						const proofTemplate = CutoverProofBundleSchema.parse(
							readJsonFile(resolveHermesArtifactPath(options.proofBundle)),
						);
						const cutoverProofBundle = buildCutoverProofBundle({
							hermes: proofTemplate.hermes,
							wrapperVersion: proofTemplate.wrapper.version,
							artifacts: {
								inventory: proofTemplate.artifacts.inventory,
								scopeManifest: proofTemplate.artifacts.scopeManifest,
								decisionLog: proofTemplate.artifacts.decisionLog,
								compatibilityLockfile: proofTemplate.artifacts.compatibilityLockfile,
								featureProbeMatrix: proofTemplate.artifacts.featureProbeMatrix,
								fixtureResults: proofTemplate.artifacts.fixtureResults,
								noForkProof: {
									...proofTemplate.artifacts.noForkProof,
									artifactPath: options.out,
								},
								networkProbeBundle: proofTemplate.artifacts.networkProbeBundle,
								queueSnapshot: proofTemplate.artifacts.queueSnapshot,
								rollbackEvidence: proofTemplate.artifacts.rollbackEvidence,
							},
						});
						const cutover = evaluateCutoverCheck(
							buildCutoverInputBundleFromArtifacts({
								inventory: options.inventory
									? readJsonFile(resolveHermesArtifactPath(options.inventory))
									: collectHermesInventory(),
								scopeManifest: readJsonFile(resolveHermesArtifactPath(options.scope)),
								decisionLog: readJsonFile(resolveHermesArtifactPath(options.decisions)),
								cutoverProofBundle,
								lockfile: readJsonFile(resolveHermesArtifactPath(options.lockfile)),
								featureProbeMatrix,
								featureProbeEvidence: collectHermesFeatureProbeEvidence(featureProbeMatrix),
								fixtureResults: readJsonFile(resolveHermesArtifactPath(options.fixtures)),
								noForkProof: readJsonFile(resolveHermesArtifactPath(options.out)),
								profileGenerationProof: readOptionalJsonFile(
									resolveHermesArtifactPath(options.profileProof),
								),
								networkProbes: readJsonFile(resolveHermesArtifactPath(options.networkProbes)),
								rollbackRehearsal: readJsonFile(resolveHermesArtifactPath(options.rollback)),
							}),
							{ strict, dryRun, liveCutover: false },
						);
						const proveReport = { schemaVersion: 1, noForkProof: report, p0: cutover };
						if (options.json) {
							printJson(proveReport);
						} else {
							console.log(`Hermes prove: ${cutover.status}`);
							for (const check of report.checks) {
								console.log(`- ${check.status.toUpperCase()} ${check.name}: ${check.detail}`);
							}
							for (const gate of cutover.gates) {
								console.log(`- ${gate.status.toUpperCase()} ${gate.name}: ${gate.detail}`);
							}
							console.log(`- evidence: ${report.evidence_path}`);
						}
						process.exitCode =
							report.hermesCheckoutClean && cutover.exitCode === 0 ? 0 : cutover.exitCode || 1;
						return;
					} catch (error) {
						const cutover = {
							status: "input_error",
							exitCode: 2,
							mode: { strict, dryRun },
							gates: [
								{
									name: "inputs.readable",
									status: "fail",
									detail: String(error instanceof Error ? error.message : error),
								},
							],
						};
						const proveReport = { schemaVersion: 1, noForkProof: report, p0: cutover };
						if (options.json) {
							printJson(proveReport);
						} else {
							console.log("Hermes prove: input_error");
							console.log(`- FAIL ${cutover.gates[0].name}: ${cutover.gates[0].detail}`);
						}
						process.exitCode = cutover.exitCode;
						return;
					}
				}
				if (options.json) {
					printJson(report);
				} else {
					console.log(`Hermes prove: ${report.hermesCheckoutClean ? "pass" : "fail"}`);
					for (const check of report.checks) {
						console.log(`- ${check.status.toUpperCase()} ${check.name}: ${check.detail}`);
					}
					console.log(`- evidence: ${report.evidence_path}`);
				}
				process.exitCode = report.hermesCheckoutClean ? 0 : 1;
			},
		);

	hermes
		.command("inventory")
		.description("Emit the Phase 0 wrapper inventory")
		.option("--json", "Emit structured JSON")
		.option("--out <path>", "Write inventory snapshot JSON to this path")
		.action((options: InventoryOption) => {
			const inventory = collectHermesInventory();
			if (options.out) {
				writeJsonArtifact(resolveHermesArtifactPath(options.out), inventory);
			}
			if (options.json) {
				printJson(inventory);
			} else {
				console.log(
					`Hermes inventory: ${inventory.status}, ${inventory.summary.workflows} workflow(s), ${inventory.summary.issues} issue(s)`,
				);
				if (options.out) console.log(`- evidence: ${options.out}`);
			}
		});

	const liveMcp = hermes
		.command("live-mcp")
		.description("Operate relay-local Hermes live MCP helpers");

	liveMcp
		.command("probe-tokens")
		.description("Issue served-MCP containment probe tokens through the relay admin socket")
		.option("--json", "Emit structured JSON with the token bundle")
		.option(
			"--socket <path>",
			`Relay-local admin Unix socket path (default: ${DEFAULT_TELCLAUDE_LIVE_MCP_ADMIN_SOCKET})`,
		)
		.option("--session-key <key>", "Private probe connection session key")
		.option("--profile <id>", "Private probe profile id")
		.option("--profile-id <id>", "Private probe profile id")
		.option("--endpoint-id <id>", "Private probe MCP endpoint id")
		.option("--network-namespace <id>", "Private probe network namespace")
		.option("--wrong-session-key <key>", "Wrong-connection probe session key")
		.option("--wrong-profile <id>", "Wrong-connection probe profile id")
		.option("--wrong-endpoint-id <id>", "Wrong-connection probe endpoint id")
		.option("--wrong-network-namespace <id>", "Wrong-connection probe network namespace")
		.option("--actor <id>", "Private authority actor id")
		.option("--memory-source <source>", "Private authority memory source")
		.option("--writable-namespace <namespace>", "Private authority writable namespace")
		.option("--provider-scope <csv>", "Private authority provider scopes")
		.option("--provider-scopes <csv>", "Private authority provider scopes")
		.option("--outbound-channel <csv>", "Private authority outbound channels")
		.option("--outbound-channels <csv>", "Private authority outbound channels")
		.option("--ttl-ms <ms>", "Token TTL in milliseconds")
		.option("--peer-address <address>", "Bind issued tokens to a specific MCP peer address")
		.option(
			"--off-domain-peer-address <address>",
			"Bind the off-domain negative-control token to this non-origin peer address",
		)
		.option("--timeout-ms <ms>", "Admin socket request timeout in milliseconds")
		.action(async (options: LiveMcpProbeTokenOption) => {
			try {
				const response = await requestTelclaudeLiveMcpProbeTokens({
					socketPath: resolveLiveMcpAdminSocket(options.socket),
					input: buildLiveMcpProbeTokenRequest(options),
					timeoutMs: parseTimeoutMs(options.timeoutMs),
				});
				if (options.json) {
					printJson(formatLiveMcpProbeTokenJson(response));
				} else {
					console.log(formatLiveMcpProbeTokenExports(response));
				}
			} catch (error) {
				const message = String(error instanceof Error ? error.message : error);
				console.error(`Error: ${message}`);
				process.exitCode = 1;
			}
		});

	hermes
		.command("probe")
		.description("Evaluate a single Hermes wrapper feature probe")
		.argument("<surface>", "Feature surface id")
		.option("--json", "Emit structured JSON")
		.option("--allow-run", "Permit the probe to execute a real pinned-Hermes command")
		.option("--pin <pin>", "Pinned Hermes artifact for evidence-generating probes")
		.option("--hermes-bin <path>", "Hermes executable path for executable probes")
		.option("--docker-bin <path>", "Docker executable path for contained API-server probes")
		.option(
			"--docker-exec-container <name>",
			"Run execution.cli_headless through docker exec inside the contained Hermes runtime",
		)
		.option("--hermes-home <dir>", "HERMES_HOME for executable probes")
		.option("--cwd <dir>", "Working directory for executable probes", process.cwd())
		.option("--out <path>", "Write executable probe evidence to this path")
		.option("--prompt <prompt>", "Prompt for execution.cli_headless")
		.option("--timeout-ms <ms>", "Maximum executable probe runtime in milliseconds")
		.option("--image <image>", "Hermes Docker image for execution.api_server_containment")
		.option("--mcp-url <url>", "Relay-only served MCP HTTP endpoint URL")
		.option("--mcp-auth <header>", "Authorized served MCP context header as 'Name: value'")
		.option(
			"--mcp-off-domain-peer-auth <header>",
			"Off-domain/wrong-peer served MCP context header as 'Name: value'",
		)
		.option(
			"--mcp-forged-auth <header>",
			"Forged/unregistered served MCP context header as 'Name: value'",
		)
		.option(
			"--mcp-wrong-connection-auth <header>",
			"Wrong-connection served MCP context header as 'Name: value'",
		)
		.option("--container-name <name>", "Hermes contained runtime container name")
		.option("--network <name>", "Relay-only Docker network for the contained Hermes server")
		.option("--api-port <port>", "Hermes API-server container port")
		.option("--relay-host <host>", "Relay host allowed by the contained runtime topology")
		.option(
			"--relay-container <name>",
			"Relay container expected on the dedicated internal network",
		)
		.option(
			"--relay-url <url>",
			"Relay/control URL that must be reachable from the contained runtime",
		)
		.option("--provider-url <csv>", "Direct provider URL(s) that must be denied")
		.option("--vault-socket <path>", "Vault socket path that must be absent")
		.option("--model-url <url>", "Direct model-provider URL that must be denied")
		.option(
			"--from-report <path>",
			"Promote a machine-observed probe report into the canonical evidence path",
		)
		.option("--profile-dir <dir>", "Generated Hermes profile directory to scan for model secrets")
		.option("--posture <posture>", "Model relay posture: agent-iptables or contained-internal")
		.option(
			"--firewall-sentinel <path>",
			"Firewall sentinel path required for production model-relay evidence",
		)
		.option(
			"--expected-peer-address <ip>",
			"Expected contained Hermes peer IP echoed by the relay endpoint",
		)
		.option(
			"--relay-peer-address <ip>",
			"Relay namespace peer IP; matching it marks evidence as relay-self smoke",
		)
		.option("--dns-url <csv>", "DNS/private egress URL(s) that must be denied")
		.option(
			"--evidence <path>",
			"Approval-continuation evidence JSON path",
			DEFAULT_APPROVAL_CONTINUATION_EVIDENCE_PATH,
		)
		.action(async (surface: string, options: ProbeOption) => {
			if (surface === "execution.cli_headless") {
				let report: Awaited<ReturnType<typeof runHermesCliHeadlessProbe>>;
				let outPath: string | undefined;
				const fromReport = options.fromReport?.trim();
				try {
					if (fromReport) {
						if (options.allowRun === true) {
							throw new Error("Use either --from-report or --allow-run, not both.");
						}
						report = readHermesCliHeadlessProbeReport(fromReport);
						if (options.out) {
							throw new Error(
								"Imported cli-headless reports cannot write evidence; run --allow-run in the contained runtime to update canonical evidence.",
							);
						}
					} else {
						const invocation = buildHermesCliProbeInvocation({
							hermesBin: resolveHermesBin(options.hermesBin),
							hermesHome: resolveHermesHome(options.hermesHome),
							cwd: path.resolve(options.cwd ?? process.cwd()),
							prompt: options.prompt,
							env: process.env,
						});
						const timeoutMs = parseTimeoutMs(options.timeoutMs);
						report = await runHermesCliHeadlessProbe({
							allowRun: options.allowRun === true,
							invocation,
							runProcess: options.dockerExecContainer?.trim()
								? (launch) =>
										runHermesLaunchInvocationInDockerExec(launch, {
											dockerBin: options.dockerBin,
											containerName: options.dockerExecContainer?.trim() ?? "",
											timeoutMs,
										})
								: (launch) => runHermesLaunchInvocation(launch, { timeoutMs }),
						});
					}
				} catch (error) {
					report = {
						schemaVersion: "telclaude.hermes.probe-result.v1",
						probeId: "execution.cli_headless",
						status: "fail",
						ran: false,
						summary: error instanceof Error ? error.message : String(error),
						findings: [],
					};
				}

				outPath ??= fromReport
					? undefined
					: options.allowRun === true
						? resolveHermesArtifactPath(options.out ?? DEFAULT_HERMES_CLI_HEADLESS_EVIDENCE_PATH)
						: options.out
							? resolveHermesArtifactPath(options.out)
							: undefined;
				if (outPath && report.status !== "pending") {
					writeJsonArtifact(outPath, report);
				}

				if (options.json) {
					printJson(report);
				} else {
					console.log(`Hermes probe ${surface}: ${report.status}`);
					console.log(`- ${report.status.toUpperCase()} execution.cli_headless: ${report.summary}`);
					if (outPath && report.status !== "pending") console.log(`- evidence: ${outPath}`);
				}
				process.exitCode = report.status === "pass" ? 0 : report.status === "pending" ? 2 : 1;
				return;
			}

			if (surface === "execution.api_server_containment") {
				let report: Awaited<ReturnType<typeof runHermesApiServerContainmentProbe>>;
				let outPath: string | undefined;
				try {
					const timeoutMs = parseTimeoutMs(options.timeoutMs);
					const launch = buildHermesApiServerLaunchPlan({
						dockerBin: options.dockerBin,
						image: options.image ?? DEFAULT_HERMES_API_SERVER_DOCKER_IMAGE,
						containerName: options.containerName ?? DEFAULT_HERMES_API_SERVER_CONTAINER_NAME,
						network: options.network ?? DEFAULT_HERMES_API_SERVER_NETWORK,
						cwd: path.resolve(options.cwd ?? process.cwd()),
						hermesHome: options.hermesHome,
						apiPort: parsePort(options.apiPort) ?? DEFAULT_HERMES_API_SERVER_PORT,
						relayInternalHost: options.relayHost ?? DEFAULT_HERMES_RELAY_INTERNAL_HOST,
						relayContainerName: options.relayContainer ?? DEFAULT_HERMES_RELAY_CONTAINER_NAME,
					});
					report = await runHermesApiServerContainmentProbe({
						allowRun: options.allowRun === true,
						launch,
						runner:
							options.allowRun === true
								? (plan) =>
										runHermesApiServerDockerContainment(plan, {
											timeoutMs,
											relayControlUrl:
												options.relayUrl?.trim() ||
												process.env.TELCLAUDE_HERMES_NETWORK_RELAY_URL?.trim() ||
												undefined,
											providerUrls: parseCsvOption(
												options.providerUrl ?? process.env.TELCLAUDE_HERMES_NETWORK_PROVIDER_URL,
											),
											vaultSocketPath: options.vaultSocket ?? DEFAULT_VAULT_SOCKET_PATH,
											modelProviderUrl:
												options.modelUrl?.trim() ||
												process.env.TELCLAUDE_HERMES_NETWORK_MODEL_URL?.trim() ||
												DEFAULT_MODEL_PROVIDER_PROBE_URL,
											dnsPrivateUrls: parseCsvOption(
												options.dnsUrl ||
													process.env.TELCLAUDE_HERMES_NETWORK_DNS_URL ||
													DEFAULT_DNS_EXFIL_PROBE_URL,
											),
										})
								: undefined,
					});
					if (options.allowRun === true && report.status !== "pending") {
						outPath = resolveHermesArtifactPath(
							options.out ?? DEFAULT_HERMES_API_SERVER_CONTAINMENT_EVIDENCE_PATH,
						);
						writeHermesApiServerContainmentEvidence(report, outPath);
					}
				} catch (error) {
					report = {
						schemaVersion: "telclaude.hermes.api-server-containment.v1",
						probeId: "execution.api_server_containment",
						status: "fail",
						ran: false,
						summary: error instanceof Error ? error.message : String(error),
						gates: [
							{
								name: "probe.exception",
								status: "fail",
								detail: error instanceof Error ? error.message : String(error),
							},
						],
						findings: [],
					};
				}

				if (options.json) {
					printJson(report);
				} else {
					console.log(`Hermes probe ${surface}: ${report.status}`);
					console.log(
						`- ${report.status.toUpperCase()} execution.api_server_containment: ${report.summary}`,
					);
					for (const gate of report.gates) {
						console.log(`- ${gate.status.toUpperCase()} ${gate.name}: ${gate.detail}`);
					}
					if (outPath) console.log(`- evidence: ${outPath}`);
				}
				process.exitCode = report.status === "pass" ? 0 : report.status === "pending" ? 2 : 1;
				return;
			}

			if (surface === "execution.served_mcp_containment") {
				let report: Awaited<ReturnType<typeof runServedMcpContainmentProbe>>;
				let outPath: string | undefined;
				try {
					const timeoutMs = parseTimeoutMs(options.timeoutMs);
					const endpoint = servedMcpEndpoint(options.mcpUrl, options.mcpAuth);
					report = await runServedMcpContainmentProbe({
						allowRun: options.allowRun === true,
						endpoint,
						offDomainPeerEndpoint: servedMcpEndpoint(options.mcpUrl, options.mcpOffDomainPeerAuth),
						forgedAuthorityEndpoint: servedMcpEndpoint(options.mcpUrl, options.mcpForgedAuth),
						wrongConnectionEndpoint: servedMcpEndpoint(
							options.mcpUrl,
							options.mcpWrongConnectionAuth,
						),
						unauthenticatedEndpoint: endpoint ? { url: endpoint.url } : undefined,
						origin: options.allowRun === true ? resolveServedMcpOriginConfig() : undefined,
						timeoutMs,
					});
					if (options.allowRun === true && report.status !== "pending") {
						outPath = resolveHermesArtifactPath(
							options.out ?? DEFAULT_SERVED_MCP_CONTAINMENT_EVIDENCE_PATH,
						);
						writeServedMcpContainmentEvidence(report, outPath);
					}
				} catch (error) {
					report = {
						schemaVersion: "telclaude.hermes.served-mcp-containment.v1",
						probeId: "execution.served_mcp_containment",
						status: "fail",
						ran: false,
						generatedAt: new Date().toISOString(),
						summary: error instanceof Error ? error.message : String(error),
						endpoint: {
							transport: "http",
							target: "redacted-http-mcp-endpoint",
						},
						placement: {
							loadBearing: false,
							detail:
								"Placement metadata is informational; relay-internal bind enforcement remains a deployment live-run gate.",
						},
						origin: {
							kind: "unknown",
							detail: "probe origin was not declared",
						},
						negativeControls: {
							forgedAuthorityDenied: false,
							wrongConnectionDenied: false,
							offDomainPeerDenied: false,
						},
						properties: {},
						checks: [],
					};
				}
				if (options.json) {
					printJson(report);
				} else {
					console.log(`Hermes probe ${surface}: ${report.status}`);
					console.log(
						`- ${report.status.toUpperCase()} execution.served_mcp_containment: ${report.summary}`,
					);
					for (const check of report.checks) {
						console.log(`- ${check.status.toUpperCase()} ${check.name}: ${check.detail}`);
					}
					if (outPath) console.log(`- evidence: ${outPath}`);
				}
				process.exitCode = report.status === "pass" ? 0 : report.status === "pending" ? 2 : 1;
				return;
			}

			if (surface === "served_mcp.provider-tools") {
				const sourcePath = resolveHermesArtifactPath(
					options.fromReport?.trim() || DEFAULT_SERVED_MCP_PROVIDER_TOOLS_SOURCE_EVIDENCE_PATH,
				);
				const report = buildServedMcpProviderToolsProbeEvidence({
					sourceEvidencePath: path.relative(process.cwd(), sourcePath) || sourcePath,
					sourceEvidence: readServedMcpProviderToolsSourceEvidence(sourcePath),
				});
				let outPath: string | undefined;
				if (options.out || options.allowRun === true || options.fromReport) {
					outPath = resolveHermesArtifactPath(
						options.out ?? DEFAULT_SERVED_MCP_PROVIDER_TOOLS_EVIDENCE_PATH,
					);
					writeJsonArtifact(outPath, report);
				}
				if (options.json) {
					printJson(report);
				} else {
					console.log(`Hermes probe ${surface}: ${report.status}`);
					console.log(`- ${report.status.toUpperCase()} ${surface}: ${report.summary}`);
					for (const check of report.checks) {
						console.log(`- ${check.status.toUpperCase()} ${check.name}: ${check.detail}`);
					}
					if (outPath) console.log(`- evidence: ${outPath}`);
				}
				process.exitCode = report.status === "pass" ? 0 : 1;
				return;
			}

			if (surface === "model.relay") {
				let report: Awaited<ReturnType<typeof runHermesModelRelayProbe>>;
				let outPath: string | undefined;
				let posture: ModelRelayPosture = DEFAULT_MODEL_RELAY_POSTURE;
				try {
					if (options.fromReport?.trim()) {
						if (options.allowRun === true) {
							throw new Error("Use either --from-report or --allow-run, not both.");
						}
						report = readJsonFile(resolveHermesArtifactPath(options.fromReport)) as Awaited<
							ReturnType<typeof runHermesModelRelayProbe>
						>;
						outPath = resolveHermesArtifactPath(options.out ?? DEFAULT_MODEL_RELAY_EVIDENCE_PATH);
						writeHermesModelRelayEvidence(report, outPath);
						if (report.posture) posture = report.posture;
					} else {
						posture = parseModelRelayPosture(options.posture);
						report = await runHermesModelRelayProbe({
							allowRun: options.allowRun === true,
							posture,
							relayUrl:
								options.relayUrl?.trim() ||
								process.env.TELCLAUDE_HERMES_MODEL_RELAY_URL?.trim() ||
								undefined,
							directModelUrl:
								options.modelUrl?.trim() ||
								process.env.TELCLAUDE_HERMES_NETWORK_MODEL_URL?.trim() ||
								DEFAULT_MODEL_PROVIDER_PROBE_URL,
							profileDir:
								options.profileDir?.trim() ||
								process.env.TELCLAUDE_HERMES_PROFILE_DIR?.trim() ||
								undefined,
							firewallSentinelPath:
								options.firewallSentinel?.trim() ||
								process.env.TELCLAUDE_HERMES_FIREWALL_SENTINEL?.trim() ||
								DEFAULT_FIREWALL_SENTINEL_PATH,
							containerName:
								options.containerName?.trim() ||
								process.env.TELCLAUDE_HERMES_CONTAINED_CONTAINER_NAME?.trim() ||
								undefined,
							expectedPeerAddress:
								options.expectedPeerAddress?.trim() ||
								process.env.TELCLAUDE_HERMES_CONTAINED_IP?.trim() ||
								undefined,
							relayPeerAddress:
								options.relayPeerAddress?.trim() ||
								process.env.TELCLAUDE_HERMES_RELAY_IP?.trim() ||
								undefined,
							timeoutMs: parseTimeoutMs(options.timeoutMs),
						});
						if (options.allowRun === true && report.status !== "pending") {
							outPath = resolveHermesArtifactPath(options.out ?? DEFAULT_MODEL_RELAY_EVIDENCE_PATH);
							writeHermesModelRelayEvidence(report, outPath);
						}
					}
				} catch (error) {
					report = {
						schemaVersion: "telclaude.hermes.model-relay.v1",
						probeId: "model.relay",
						posture,
						status: "fail",
						ran: false,
						generatedAt: new Date().toISOString(),
						summary: error instanceof Error ? error.message : String(error),
						origin: {
							kind: "unknown",
							detail: "model-relay probe failed before origin observation",
						},
						gates: [
							{
								name: "modelRelay.exception",
								status: "fail",
								detail: error instanceof Error ? error.message : String(error),
							},
						],
					};
				}

				if (options.json) {
					printJson(report);
				} else {
					console.log(`Hermes probe ${surface}: ${report.status}`);
					console.log(`- ${report.status.toUpperCase()} model.relay: ${report.summary}`);
					for (const gate of report.gates) {
						console.log(`- ${gate.status.toUpperCase()} ${gate.name}: ${gate.detail}`);
					}
					if (outPath) console.log(`- evidence: ${outPath}`);
				}
				process.exitCode = report.status === "pass" ? 0 : report.status === "pending" ? 2 : 1;
				return;
			}

			if (isEdgeAdapterFeatureSurfaceId(surface)) {
				const report = buildEdgeAdapterProbeEvidence({
					surfaceId: surface,
					allowRun: options.allowRun === true,
				});
				let outPath: string | undefined;
				if (options.allowRun === true || options.out) {
					outPath = resolveHermesArtifactPath(
						options.out ?? `artifacts/hermes/probes/${surface}.json`,
					);
					writeJsonArtifact(outPath, report);
				}
				if (options.json) {
					printJson(report);
				} else {
					console.log(`Hermes probe ${surface}: ${report.status}`);
					console.log(`- ${report.status.toUpperCase()} ${surface}: ${report.summary}`);
					for (const control of report.controls) {
						console.log(`- ${control.status.toUpperCase()} ${control.name}: ${control.detail}`);
					}
					if (outPath) console.log(`- evidence: ${outPath}`);
				}
				process.exitCode = report.status === "pass" ? 0 : 1;
				return;
			}

			if (surface === "sideeffect.ledger") {
				const report = await runTelclaudeMcpSideEffectLedgerProbe({
					allowRun: options.allowRun === true,
				});
				let outPath: string | undefined;
				if (options.allowRun === true || options.out) {
					outPath = resolveHermesArtifactPath(
						options.out ?? DEFAULT_SIDE_EFFECT_LEDGER_EVIDENCE_PATH,
					);
					writeJsonArtifact(outPath, report);
				}
				if (options.json) {
					printJson(report);
				} else {
					console.log(`Hermes probe ${surface}: ${report.status}`);
					console.log(`- ${report.status.toUpperCase()} ${surface}: ${report.summary}`);
					for (const check of report.checks) {
						console.log(`- ${check.status.toUpperCase()} ${check.name}: ${check.detail}`);
					}
					if (outPath) console.log(`- evidence: ${outPath}`);
				}
				process.exitCode = report.status === "pass" ? 0 : 1;
				return;
			}

			if (surface === "providers.approval-binding") {
				const report = await runTelclaudeProviderApprovalBindingProbe({
					allowRun: options.allowRun === true,
				});
				let outPath: string | undefined;
				if (options.allowRun === true || options.out) {
					outPath = resolveHermesArtifactPath(
						options.out ?? DEFAULT_PROVIDER_APPROVAL_BINDING_EVIDENCE_PATH,
					);
					writeJsonArtifact(outPath, report);
				}
				if (options.json) {
					printJson(report);
				} else {
					console.log(`Hermes probe ${surface}: ${report.status}`);
					console.log(`- ${report.status.toUpperCase()} ${surface}: ${report.summary}`);
					for (const check of report.checks) {
						console.log(`- ${check.status.toUpperCase()} ${check.name}: ${check.detail}`);
					}
					if (outPath) console.log(`- evidence: ${outPath}`);
				}
				process.exitCode = report.status === "pass" ? 0 : 1;
				return;
			}

			if (surface !== "execution.approval_continuation") {
				const report = {
					schemaVersion: "telclaude.hermes.probe-report.v1",
					status: "input_error",
					surface,
					detail: `Unsupported Hermes probe surface: ${surface}`,
				};
				if (options.json) {
					printJson(report);
				} else {
					console.log(`Hermes probe ${surface}: ${report.status}`);
					console.log(`- FAIL surface: ${report.detail}`);
				}
				process.exitCode = 2;
				return;
			}

			if (options.allowRun === true) {
				let run = await runHermesApprovalContinuationProbe({
					allowRun: true,
					hermes: resolvePin(options),
				});
				if (run.evidence) {
					run = writeApprovalContinuationArtifacts(run, {
						evidencePath: options.out ?? options.evidence,
					});
				}
				if (options.json) {
					printJson(run);
				} else {
					console.log(`Hermes probe ${surface}: ${run.status}`);
					console.log(
						`- ${run.status.toUpperCase()} execution.approval_continuation: ${run.summary}`,
					);
					if (run.evidencePath) console.log(`- evidence: ${run.evidencePath}`);
					if (run.fixtureEvidenceDir) console.log(`- fixture evidence: ${run.fixtureEvidenceDir}`);
				}
				process.exitCode = run.status === "pass" ? 0 : run.status === "pending" ? 2 : 1;
				return;
			}

			const run = await runHermesApprovalContinuationProbe({
				allowRun: false,
				hermes: resolvePin(options),
			});
			if (options.json) {
				printJson(run);
			} else {
				console.log(`Hermes probe ${surface}: ${run.status}`);
				console.log(
					`- ${run.status.toUpperCase()} execution.approval_continuation: ${run.summary}`,
				);
			}
			process.exitCode = 2;
		});

	hermes
		.command("network-probes")
		.description("Run gated Hermes network isolation probes and write cutover evidence")
		.option("--json", "Emit structured JSON")
		.option("--allow-run", "Permit real network probes and artifact writes")
		.option(
			"--from-report <path>",
			"Promote a machine-observed network-probe run report into canonical cutover artifacts",
		)
		.option("--out <path>", "Network probe bundle JSON path", DEFAULT_NETWORK_PROBE_BUNDLE_PATH)
		.option(
			"--evidence-dir <dir>",
			"Per-probe evidence output directory",
			DEFAULT_NETWORK_PROBE_EVIDENCE_DIR,
		)
		.option(
			"--relay-url <url>",
			"Allowed relay/control URL that must remain reachable; defaults to TELCLAUDE_HERMES_NETWORK_RELAY_URL",
		)
		.option(
			"--provider-url <csv>",
			"Direct provider URL(s) that must be denied; defaults to TELCLAUDE_HERMES_NETWORK_PROVIDER_URL",
		)
		.option(
			"--vault-url <url>",
			"Optional direct vault HTTP URL that must be denied; defaults to TELCLAUDE_HERMES_NETWORK_VAULT_URL",
		)
		.option(
			"--vault-socket <path>",
			"Vault socket path that must be absent from the Hermes runtime",
			DEFAULT_VAULT_SOCKET_PATH,
		)
		.option(
			"--model-url <url>",
			"Direct model-provider URL that must be denied",
			DEFAULT_MODEL_PROVIDER_PROBE_URL,
		)
		.option(
			"--dns-url <csv>",
			"DNS/private egress URL(s) that must be denied",
			DEFAULT_DNS_EXFIL_PROBE_URL,
		)
		.option(
			"--firewall-sentinel <path>",
			"Firewall sentinel required for agent-iptables network evidence",
			DEFAULT_FIREWALL_SENTINEL_PATH,
		)
		.option("--posture <posture>", "Network boundary posture: agent-iptables or contained-internal")
		.option("--timeout-ms <ms>", "Maximum time per HTTP probe in milliseconds")
		.action(async (options: NetworkProbeOption) => {
			try {
				let report: Awaited<ReturnType<typeof runHermesNetworkProbes>>;
				if (options.fromReport?.trim()) {
					if (options.allowRun === true) {
						throw new Error("Use either --from-report or --allow-run, not both.");
					}
					report = writeHermesNetworkProbeArtifacts(
						readHermesNetworkProbeRunReport(options.fromReport),
						{
							outPath: options.out,
							evidenceDir: options.evidenceDir,
						},
					);
				} else {
					report = await runHermesNetworkProbes({
						allowRun: options.allowRun === true,
						posture: parseNetworkProbePosture(options.posture),
						relayUrl:
							options.relayUrl?.trim() ||
							process.env.TELCLAUDE_HERMES_NETWORK_RELAY_URL?.trim() ||
							undefined,
						providerUrls: parseCsvOption(
							options.providerUrl ?? process.env.TELCLAUDE_HERMES_NETWORK_PROVIDER_URL,
						),
						vaultUrl:
							options.vaultUrl?.trim() ||
							process.env.TELCLAUDE_HERMES_NETWORK_VAULT_URL?.trim() ||
							undefined,
						vaultSocketPath: options.vaultSocket,
						modelProviderUrl:
							options.modelUrl?.trim() ||
							process.env.TELCLAUDE_HERMES_NETWORK_MODEL_URL?.trim() ||
							DEFAULT_MODEL_PROVIDER_PROBE_URL,
						dnsExfilUrls: parseCsvOption(
							options.dnsUrl ||
								process.env.TELCLAUDE_HERMES_NETWORK_DNS_URL ||
								DEFAULT_DNS_EXFIL_PROBE_URL,
						),
						firewallSentinelPath: options.firewallSentinel,
						timeoutMs: parseTimeoutMs(options.timeoutMs),
					});
				}

				if (options.allowRun === true) {
					report = writeHermesNetworkProbeArtifacts(report, {
						outPath: options.out,
						evidenceDir: options.evidenceDir,
					});
				}

				if (options.json) {
					printJson(report);
				} else {
					console.log(`Hermes network-probes: ${report.status}`);
					console.log(`- ${report.status.toUpperCase()}: ${report.summary}`);
					for (const probe of report.evidence) {
						console.log(`- ${probe.status.toUpperCase()} ${probe.id}: ${probe.summary}`);
					}
					if (report.bundlePath) console.log(`- bundle: ${report.bundlePath}`);
					if (report.evidenceDir) console.log(`- evidence: ${report.evidenceDir}`);
				}
				process.exitCode = report.status === "pass" ? 0 : report.status === "pending" ? 2 : 1;
			} catch (error) {
				const report = {
					schemaVersion: "telclaude.hermes.network-probe-run.v1",
					status: "fail",
					ran: false,
					summary: String(error instanceof Error ? error.message : error),
				};
				if (options.json) {
					printJson(report);
				} else {
					console.log(`Hermes network-probes: ${report.status}`);
					console.log(`- FAIL: ${report.summary}`);
				}
				process.exitCode = 1;
			}
		});

	hermes
		.command("rollback-rehearsal")
		.description("Generate relay-observed Hermes private-runtime rollback evidence")
		.option("--allow-run", "Actually drive the relay durable control surface")
		.option("--json", "Emit structured JSON")
		.option(
			"--out <path>",
			"Rollback rehearsal evidence path",
			DEFAULT_HERMES_ROLLBACK_REHEARSAL_EVIDENCE_PATH,
		)
		.option(
			"--evidence-path <path>",
			"Logical evidence_path recorded inside the artifact; defaults to --out",
		)
		.action(async (options: RollbackRehearsalOption) => {
			try {
				const outPath = resolveHermesArtifactPath(options.out);
				const evidencePath = options.evidencePath?.trim() || options.out;
				const report = await runHermesRollbackRehearsal({
					allowRun: options.allowRun === true,
					evidencePath,
				});
				const written = writeHermesRollbackRehearsalEvidence(report, outPath);
				if (options.json) {
					printJson({ ...report, written });
				} else {
					console.log(`Hermes rollback-rehearsal: ${report.passed ? "pass" : "fail"}`);
					for (const check of report.checks ?? []) {
						console.log(`- ${check.status.toUpperCase()} ${check.name}: ${check.detail}`);
					}
					if (written) console.log(`- evidence: ${outPath}`);
				}
				process.exitCode = report.passed ? 0 : written ? 1 : 2;
			} catch (error) {
				const report = {
					schemaVersion: 1,
					passed: false,
					written: false,
					evidence_path: options.evidencePath?.trim() || options.out,
					checks: [
						{
							name: "rollback.controlSurface",
							status: "fail",
							detail: String(error instanceof Error ? error.message : error),
						},
					],
				};
				if (options.json) {
					printJson(report);
				} else {
					console.log("Hermes rollback-rehearsal: fail");
					console.log(`- FAIL rollback.controlSurface: ${report.checks[0].detail}`);
				}
				process.exitCode = 1;
			}
		});

	const privateRuntime = hermes
		.command("private-runtime")
		.description("Observe or drive Hermes private-runtime durable mode through relay operator RPC");

	privateRuntime
		.command("status")
		.description("Show the relay-observed Hermes private-runtime effective state")
		.option("--json", "Emit structured JSON")
		.action(async (options: JsonOption) => {
			try {
				const state = await relayGetHermesPrivateRuntimeState();
				if (options.json) {
					printJson(state);
				} else {
					console.log(`Hermes private-runtime: ${state.effectiveMode}`);
					console.log(`- effectiveValue: ${state.effectiveValue}`);
					console.log(`- controlMode: ${state.controlMode}`);
					console.log(`- controlSource: ${state.controlSource}`);
					console.log(`- rolloutAllowed: ${String(state.rolloutAllowed)}`);
				}
				process.exitCode = 0;
			} catch (error) {
				if (options.json) {
					printJson({ ok: false, error: String(error instanceof Error ? error.message : error) });
				} else {
					console.log(`Hermes private-runtime: fail`);
					console.log(`- FAIL: ${String(error instanceof Error ? error.message : error)}`);
				}
				process.exitCode = 1;
			}
		});

	privateRuntime
		.command("set <mode>")
		.description("Set Hermes private-runtime durable mode through relay operator RPC")
		.option("--json", "Emit structured JSON")
		.action(async (mode: string, options: JsonOption) => {
			try {
				if (mode !== "hermes" && mode !== "legacy") {
					throw new Error("mode must be hermes or legacy");
				}
				const state = await relaySetHermesPrivateRuntimeMode({ mode: mode as PrivateRuntimeMode });
				if (options.json) {
					printJson(state);
				} else {
					console.log(`Hermes private-runtime: ${state.effectiveMode}`);
					console.log(`- controlMode: ${state.controlMode}`);
					console.log(`- controlSource: ${state.controlSource}`);
				}
				process.exitCode = 0;
			} catch (error) {
				if (options.json) {
					printJson({ ok: false, error: String(error instanceof Error ? error.message : error) });
				} else {
					console.log(`Hermes private-runtime: fail`);
					console.log(`- FAIL: ${String(error instanceof Error ? error.message : error)}`);
				}
				process.exitCode = 1;
			}
		});

	hermes
		.command("pro-review-check")
		.description("Validate ChatGPT Pro native-extension review request evidence")
		.option("--json", "Emit structured JSON")
		.option(
			"--request <path>",
			"ChatGPT Pro review request JSON path",
			DEFAULT_PRO_REVIEW_REQUEST_PATH,
		)
		.option(
			"--canary <path>",
			"Yoetz ChatGPT native-extension canary JSON path",
			DEFAULT_PRO_REVIEW_NATIVE_CANARY_PATH,
		)
		.option(
			"--require-approval",
			"Fail unless the private workspace disclosure approval is present and digest-bound",
		)
		.action((options: ProReviewCheckOption) => {
			const report = evaluateProReviewCheck({
				requestPath: options.request,
				canaryPath: options.canary,
				requireApproval: options.requireApproval,
			});
			if (options.json) {
				printJson(report);
			} else {
				console.log(`Hermes pro-review-check: ${report.status}`);
				for (const gate of report.gates) {
					console.log(`- ${gate.status.toUpperCase()} ${gate.name}: ${gate.detail}`);
				}
			}
			process.exitCode = report.status === "fail" ? 1 : report.status === "pending" ? 2 : 0;
		});

	hermes
		.command("pro-review-send")
		.description(
			"Gate and optionally send the ChatGPT Pro review bundle through Yoetz native extension",
		)
		.option("--json", "Emit structured JSON")
		.option(
			"--request <path>",
			"ChatGPT Pro review request JSON path",
			DEFAULT_PRO_REVIEW_REQUEST_PATH,
		)
		.option(
			"--canary <path>",
			"Yoetz ChatGPT native-extension canary JSON path",
			DEFAULT_PRO_REVIEW_NATIVE_CANARY_PATH,
		)
		.option("--bundle-out <path>", "Write the generated Yoetz bundle to this path")
		.option("--execute", "Actually invoke Yoetz native extension after all approval gates pass")
		.action((options: ProReviewSendOption) => {
			const report = evaluateProReviewCheck({
				requestPath: options.request,
				canaryPath: options.canary,
				requireApproval: true,
			});
			const bundlePath = resolveProReviewBundlePath(options.bundleOut);
			const yoetzCommand = [
				"yoetz",
				"browser",
				"recipe",
				"--recipe",
				"chatgpt",
				"--transport",
				"chrome-extension-native",
				"--bundle",
				bundlePath,
				"--format",
				"json",
			];
			if (report.status !== "pass") {
				const result = {
					report,
					send: {
						status: "refused",
						reason: "pro-review-check did not pass with approval required",
						yoetzCommand,
					},
				};
				if (options.json) {
					printJson(result);
				} else {
					console.log("Hermes pro-review-send: refused");
					for (const gate of report.gates) {
						console.log(`- ${gate.status.toUpperCase()} ${gate.name}: ${gate.detail}`);
					}
				}
				process.exitCode = 1;
				return;
			}

			writeProReviewBundle(options.request, bundlePath);
			if (!options.execute) {
				const result = {
					report,
					send: {
						status: "ready",
						bundlePath,
						yoetzCommand,
						note: "not sent; pass --execute to invoke Yoetz native extension",
					},
				};
				if (options.json) {
					printJson(result);
				} else {
					console.log("Hermes pro-review-send: ready");
					console.log(`- bundle: ${bundlePath}`);
					console.log(`- command: YOETZ_AGENT=1 ${yoetzCommand.join(" ")}`);
				}
				process.exitCode = 0;
				return;
			}

			const result = spawnSync(yoetzCommand[0], yoetzCommand.slice(1), {
				encoding: "utf8",
				env: { ...process.env, YOETZ_AGENT: "1" },
			});
			const send = {
				status: result.status === 0 ? "sent" : "failed",
				bundlePath,
				yoetzCommand,
				exitCode: result.status,
				stdout: result.stdout,
				stderr: result.stderr,
				error: result.error?.message,
			};
			if (options.json) {
				printJson({ report, send });
			} else {
				console.log(`Hermes pro-review-send: ${send.status}`);
				if (send.stdout.trim()) console.log(send.stdout.trim());
				if (send.stderr.trim()) console.error(send.stderr.trim());
				if (send.error) console.error(send.error);
			}
			process.exitCode = result.status === 0 ? 0 : 1;
		});

	hermes
		.command("queue-snapshot")
		.description("Build cutover queue ownership evidence from live or supplied Hermes inventory")
		.option("--json", "Emit structured JSON")
		.option(
			"--inventory <path>",
			`Inventory snapshot JSON path; uses ${DEFAULT_INVENTORY_PATH} when present, otherwise collects live inventory`,
		)
		.option("--out <path>", "Write queue snapshot JSON to this path")
		.action((options: QueueSnapshotOption) => {
			try {
				const inventory = readInventorySnapshot(options.inventory);
				const snapshot = buildHermesQueueSnapshot({ inventory });
				const outPath = options.out ?? DEFAULT_QUEUE_SNAPSHOT_PATH;
				if (options.out) {
					writeJsonArtifact(resolveHermesArtifactPath(outPath), snapshot);
				}
				if (options.json) {
					printJson(snapshot);
				} else {
					console.log(
						`Hermes queue-snapshot: ${snapshot.unownedActiveCount} unowned active item(s)`,
					);
					if (options.out) console.log(`- evidence: ${outPath}`);
				}
				process.exitCode = snapshot.unownedActiveCount === 0 ? 0 : 1;
			} catch (error) {
				const report = {
					status: "input_error",
					exitCode: 2,
					gates: [
						{
							name: "queueSnapshot.inventory",
							status: "fail",
							detail: String(error instanceof Error ? error.message : error),
						},
					],
				};
				if (options.json) {
					printJson(report);
				} else {
					console.log("Hermes queue-snapshot: input_error");
					console.log(`- FAIL queueSnapshot.inventory: ${report.gates[0].detail}`);
				}
				process.exitCode = 2;
			}
		});

	hermes
		.command("proof-bundle")
		.description("Build a byte-bound cutover proof bundle from strict evidence artifacts")
		.requiredOption("--inventory <path>", "Inventory snapshot JSON path")
		.requiredOption("--scope-manifest <path>", "Cutover scope manifest JSON path")
		.requiredOption("--decision-log <path>", "Decision log JSON path")
		.requiredOption("--compatibility-lockfile <path>", "Compatibility lockfile JSON path")
		.requiredOption("--feature-probe-matrix <path>", "Feature-probe matrix JSON path")
		.requiredOption("--fixture-results <path>", "Fixture result bundle JSON path")
		.requiredOption("--nofork-proof-file <path>", "No-fork proof bundle JSON path")
		.requiredOption("--network-probe-bundle <path>", "Network probe bundle JSON path")
		.requiredOption("--queue-snapshot <path>", "Queue ownership snapshot JSON path")
		.requiredOption("--rollback-evidence <path>", "Rollback rehearsal evidence JSON path")
		.option("--pin <pin>", "Pinned Hermes version, commit, package, or image digest")
		.option("--out <path>", "Write proof bundle JSON to this path")
		.option("--json", "Emit structured JSON")
		.action((options: ProofBundleOption) => {
			try {
				const hermesPin = resolvePin({
					pin: options.pin,
					lockfile: options.compatibilityLockfile,
				});
				if (!hermesPin) {
					throw new Error("Cannot build cutover proof bundle without a pinned Hermes artifact.");
				}
				const proofBundle = buildCutoverProofBundle({
					hermes: hermesPin,
					wrapperVersion: readWrapperPackageVersion(),
					artifacts: {
						inventory: cutoverProofArtifact(
							options.inventory,
							`pnpm dev hermes inventory --out ${options.inventory} --json`,
							["inputs.inventory"],
						),
						scopeManifest: cutoverProofArtifact(
							options.scopeManifest,
							"pnpm dev hermes cutover-scope --json",
							["inputs.scopeManifest", "workflow.scope"],
						),
						decisionLog: cutoverProofArtifact(
							options.decisionLog,
							"pnpm dev hermes decision-log --json",
							["inputs.decisionLog", "decisions.resolved"],
						),
						compatibilityLockfile: cutoverProofArtifact(
							options.compatibilityLockfile,
							"pnpm dev hermes compat-lock --dry-run --json",
							["inputs.lockfile", "lockfile.consistent"],
						),
						featureProbeMatrix: cutoverProofArtifact(
							options.featureProbeMatrix,
							"pnpm dev hermes probes --json",
							["inputs.featureProbeMatrix", "featureProbes.pass"],
						),
						fixtureResults: cutoverProofArtifact(
							options.fixtureResults,
							"pnpm dev hermes fixtures --json",
							["inputs.fixtureResults", "fixtures.pass"],
						),
						noForkProof: cutoverProofArtifact(
							options.noforkProofFile,
							"pnpm dev hermes prove --upstream-clean --p0 --json",
							["inputs.noForkProof", "nofork.clean"],
						),
						networkProbeBundle: cutoverProofArtifact(
							options.networkProbeBundle,
							"pnpm dev hermes network-probes --json",
							["inputs.networkProbes", "networkProbes.pass"],
						),
						queueSnapshot: cutoverProofArtifact(
							options.queueSnapshot,
							`pnpm dev hermes queue-snapshot --inventory ${options.inventory} --out ${options.queueSnapshot} --json`,
							["inputs.queueSnapshot", "queues.owned"],
						),
						rollbackEvidence: cutoverProofArtifact(
							options.rollbackEvidence,
							"pnpm dev hermes rollback-rehearsal --json",
							["inputs.rollbackRehearsal", "rollback.rehearsed"],
						),
					},
				});
				if (options.out) {
					writeJsonArtifact(resolveHermesArtifactPath(options.out), proofBundle);
				}
				if (options.json || !options.out) {
					printJson(proofBundle);
				} else {
					console.log(`Hermes proof-bundle: ${options.out}`);
				}
				process.exitCode = proofBundle
					? Object.values(proofBundle.artifacts).every((artifact) => artifact.status === "pass")
						? 0
						: 1
					: 1;
			} catch (error) {
				const report = {
					status: "input_error",
					exitCode: 2,
					gates: [
						{
							name: "proofBundle.readable",
							status: "fail",
							detail: String(error instanceof Error ? error.message : error),
						},
					],
				};
				if (options.json) {
					printJson(report);
				} else {
					console.error(`Error: ${report.gates[0].detail}`);
				}
				process.exitCode = 2;
			}
		});

	hermes
		.command("cutover-check")
		.description("Evaluate strict Hermes wrapper cutover evidence")
		.option("--strict", "Fail closed for missing or unsafe evidence")
		.option("--dry-run", "Evaluate evidence without changing runtime state")
		.option("--json", "Emit structured JSON")
		.option(
			"--inventory <path>",
			"Inventory snapshot JSON path; collects live inventory when omitted",
		)
		.option(
			"--queue-snapshot <path>",
			"Queue ownership snapshot JSON path; derives from inventory when omitted",
		)
		.option("--scope <path>", "Cutover scope manifest JSON path", DEFAULT_CUTOVER_SCOPE_PATH)
		.option("--decisions <path>", "Decision log JSON path", DEFAULT_DECISION_LOG_PATH)
		.option(
			"--proof-bundle <path>",
			"Cutover proof bundle JSON path",
			DEFAULT_CUTOVER_PROOF_BUNDLE_PATH,
		)
		.option(
			"--feature-probes <path>",
			"Feature-probe matrix JSON path",
			DEFAULT_FEATURE_PROBE_MATRIX_PATH,
		)
		.option("--lockfile <path>", "Compatibility lockfile JSON path", DEFAULT_COMPAT_LOCKFILE_PATH)
		.option("--fixtures <path>", "Fixture result bundle JSON path", DEFAULT_FIXTURE_RESULTS_PATH)
		.option(
			"--network-probes <path>",
			"Network probe bundle JSON path",
			DEFAULT_NETWORK_PROBES_PATH,
		)
		.option("--nofork <path>", "No-fork proof bundle JSON path", DEFAULT_NO_FORK_PROOF_PATH)
		.option(
			"--profile-proof <path>",
			"Profile generation proof JSON path",
			DEFAULT_PROFILE_GENERATION_PROOF_PATH,
		)
		.option(
			"--rollback <path>",
			"Rollback rehearsal evidence JSON path",
			DEFAULT_ROLLBACK_REHEARSAL_PATH,
		)
		.action(
			(
				options: JsonOption & {
					inventory?: string;
					scope: string;
					decisions: string;
					proofBundle: string;
					featureProbes: string;
					lockfile: string;
					fixtures: string;
					queueSnapshot?: string;
					networkProbes: string;
					nofork: string;
					profileProof: string;
					rollback: string;
					strict?: boolean;
					dryRun?: boolean;
				},
			) => {
				const strict = options.strict ?? true;
				const dryRun = options.dryRun ?? false;
				let input: unknown;
				try {
					const featureProbeMatrix = readJsonFile(resolveHermesArtifactPath(options.featureProbes));
					input = buildCutoverInputBundleFromArtifacts({
						inventory: readInventorySnapshot(options.inventory),
						scopeManifest: readJsonFile(resolveHermesArtifactPath(options.scope)),
						decisionLog: readJsonFile(resolveHermesArtifactPath(options.decisions)),
						cutoverProofBundle: readJsonFile(resolveHermesArtifactPath(options.proofBundle)),
						lockfile: readJsonFile(resolveHermesArtifactPath(options.lockfile)),
						featureProbeMatrix,
						featureProbeEvidence: collectHermesFeatureProbeEvidence(featureProbeMatrix),
						fixtureResults: readJsonFile(resolveHermesArtifactPath(options.fixtures)),
						noForkProof: readJsonFile(resolveHermesArtifactPath(options.nofork)),
						profileGenerationProof: readOptionalJsonFile(
							resolveHermesArtifactPath(options.profileProof),
						),
						networkProbes: readJsonFile(resolveHermesArtifactPath(options.networkProbes)),
						queueSnapshot: options.queueSnapshot
							? readJsonFile(resolveHermesArtifactPath(options.queueSnapshot))
							: undefined,
						rollbackRehearsal: readJsonFile(resolveHermesArtifactPath(options.rollback)),
					});
				} catch (error) {
					const report = {
						status: "input_error",
						exitCode: 2,
						mode: { strict, dryRun },
						gates: [
							{
								name: "inputs.readable",
								status: "fail",
								detail: String(error instanceof Error ? error.message : error),
							},
						],
					};
					if (options.json) {
						printJson(report);
					} else {
						console.log(`Hermes cutover-check: ${report.status}`);
						console.log(`- FAIL ${report.gates[0].name}: ${report.gates[0].detail}`);
					}
					process.exitCode = report.exitCode;
					return;
				}

				const report = evaluateCutoverCheck(input, {
					strict,
					dryRun,
					liveCutover: strict && !dryRun,
					now: new Date(),
				});
				if (options.json) {
					printJson(report);
				} else {
					console.log(`Hermes cutover-check: ${report.status}`);
					for (const gate of report.gates) {
						console.log(`- ${gate.status.toUpperCase()} ${gate.name}: ${gate.detail}`);
					}
				}
				process.exitCode = report.exitCode;
			},
		);

	hermes
		.command("cutover-scope")
		.description("Generate a fail-closed cutover scope skeleton from an inventory snapshot")
		.requiredOption("--inventory <path>", "Inventory snapshot JSON path")
		.option("--json", "Emit structured JSON")
		.action((options: JsonOption & { inventory: string }) => {
			try {
				const manifest = buildCutoverScopeManifestFromInventory(
					readJsonFile(resolveHermesArtifactPath(options.inventory)),
				);
				if (options.json) {
					printJson(manifest);
				} else {
					console.log(`Hermes cutover-scope: ${manifest.workflows.length} workflow(s)`);
					for (const workflow of manifest.workflows) {
						console.log(`- ${workflow.status.toUpperCase()} ${workflow.workflow_id}`);
					}
				}
			} catch (error) {
				console.error(`Error: ${String(error instanceof Error ? error.message : error)}`);
				process.exitCode = 1;
			}
		});

	hermes
		.command("compat-lock")
		.description("Generate a Hermes compatibility lockfile draft")
		.requiredOption("--dry-run", "Emit lockfile content without writing files")
		.option("--json", "Emit structured JSON")
		.option("--pin <pin>", "Pinned Hermes version, commit, package, or image digest")
		.option(
			"--feature-probes <path>",
			"Feature-probe matrix JSON path",
			DEFAULT_FEATURE_PROBE_MATRIX_PATH,
		)
		.action((options: JsonOption & PinOption & { featureProbes: string }) => {
			try {
				const lockfile = buildCompatibilityLockfileDraft({
					pin: resolvePin(options),
					featureProbeMatrix: readJsonFile(resolveHermesArtifactPath(options.featureProbes)),
					wrapperPackageVersion: readWrapperPackageVersion(),
				});
				if (options.json) {
					printJson(lockfile);
				} else {
					console.log(`Hermes compat-lock dry-run: ${lockfile.featureProbes.length} probe(s)`);
					for (const probe of lockfile.featureProbes) {
						console.log(`- ${probe.status.toUpperCase()} ${probe.surface_id}`);
					}
				}
			} catch (error) {
				console.error(`Error: ${String(error instanceof Error ? error.message : error)}`);
				process.exitCode = 1;
			}
		});
}
