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
	buildCompatibilityLockfileDraft,
	buildCutoverInputBundleFromArtifacts,
	buildCutoverScopeManifestFromInventory,
	buildHermesDoctorReport,
	buildHermesGenerateDryRun,
	collectFeatureProbeEvidence,
	DEFAULT_COMPAT_LOCKFILE_PATH,
	DEFAULT_CUTOVER_SCOPE_PATH,
	DEFAULT_DECISION_LOG_PATH,
	DEFAULT_FEATURE_PROBE_MATRIX_PATH,
	DEFAULT_FIXTURE_RESULTS_PATH,
	DEFAULT_NETWORK_PROBES_PATH,
	DEFAULT_NO_FORK_PROOF_PATH,
	DEFAULT_ROLLBACK_REHEARSAL_PATH,
	evaluateCutoverCheck,
	parseHermesPin,
	readJsonFile,
	readOptionalJsonFile,
	resolveHermesArtifactPath,
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
	DEFAULT_MODEL_RELAY_EVIDENCE_PATH,
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
	runHermesCliHeadlessProbe,
	runHermesLaunchInvocation,
} from "../hermes/private-runtime.js";
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
	relayGetHermesPrivateRuntimeState,
	relaySetHermesPrivateRuntimeMode,
} from "../relay/capabilities-client.js";

type JsonOption = {
	json?: boolean;
};

type PinOption = {
	pin?: string;
};

type ProbeOption = JsonOption & {
	allowRun?: boolean;
	apiPort?: string;
	containerName?: string;
	cwd?: string;
	dnsUrl?: string;
	dockerBin?: string;
	evidence: string;
	expectedPeerAddress?: string;
	firewallSentinel?: string;
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

type RollbackRehearsalOption = JsonOption & {
	allowRun?: boolean;
	out: string;
	evidencePath?: string;
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
	return parseHermesPin(options.pin ?? process.env.TELCLAUDE_HERMES_PIN);
}

function writeJsonArtifact(filePath: string, value: unknown): void {
	fs.mkdirSync(path.dirname(filePath), { recursive: true });
	const tmpPath = `${filePath}.tmp.${process.pid}`;
	fs.writeFileSync(tmpPath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
	fs.renameSync(tmpPath, filePath);
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
	const approvalProbe = featureProbeMatrix.probes.find(
		(probe) =>
			typeof probe === "object" &&
			probe !== null &&
			"surface_id" in probe &&
			probe.surface_id === "execution.approval_continuation" &&
			"evidence_path" in probe &&
			typeof probe.evidence_path === "string",
	);
	if (!approvalProbe || typeof approvalProbe.evidence_path !== "string") return collected;
	const evidencePath = resolveHermesArtifactPath(approvalProbe.evidence_path);
	const report = evaluateApprovalContinuationEvidence(readOptionalJsonFile(evidencePath), {
		missingPath: evidencePath,
	});
	return {
		schemaVersion: 1 as const,
		results: [
			...collected.results,
			{
				surface_id: "execution.approval_continuation",
				status:
					report.status === "pass" && report.productionEnable
						? ("pass" as const)
						: ("fail" as const),
				evidence_path: approvalProbe.evidence_path,
				detail:
					report.status === "pass" && report.productionEnable
						? `approval-continuation evidence passed in ${report.mode} mode`
						: report.gates.map((gate) => gate.detail).join("; "),
			},
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
		.requiredOption("--dry-run", "Preview generated artifacts without writing files")
		.option("--json", "Emit structured JSON")
		.option("--pin <pin>", "Pinned Hermes version, commit, package, or image digest")
		.option("--out <dir>", "Output directory for generated Hermes profiles", "/tmp/tc-hermes")
		.action((options: JsonOption & PinOption & { out: string }) => {
			try {
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
			} catch (error) {
				console.error(`Error: ${String(error instanceof Error ? error.message : error)}`);
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
					featureProbes: string;
					lockfile: string;
					fixtures: string;
					networkProbes: string;
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
						const cutover = evaluateCutoverCheck(
							buildCutoverInputBundleFromArtifacts({
								inventory: options.inventory
									? readJsonFile(resolveHermesArtifactPath(options.inventory))
									: collectHermesInventory(),
								scopeManifest: readJsonFile(resolveHermesArtifactPath(options.scope)),
								decisionLog: readJsonFile(resolveHermesArtifactPath(options.decisions)),
								lockfile: readJsonFile(resolveHermesArtifactPath(options.lockfile)),
								featureProbeMatrix,
								featureProbeEvidence: collectHermesFeatureProbeEvidence(featureProbeMatrix),
								fixtureResults: readJsonFile(resolveHermesArtifactPath(options.fixtures)),
								noForkProof: readJsonFile(resolveHermesArtifactPath(options.out)),
								networkProbes: readJsonFile(resolveHermesArtifactPath(options.networkProbes)),
								rollbackRehearsal: readJsonFile(resolveHermesArtifactPath(options.rollback)),
							}),
							{ strict, dryRun },
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
		.action((options: JsonOption) => {
			const inventory = collectHermesInventory();
			if (options.json) {
				printJson(inventory);
			} else {
				console.log(
					`Hermes inventory: ${inventory.status}, ${inventory.summary.workflows} workflow(s), ${inventory.summary.issues} issue(s)`,
				);
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
		.option("--profile-dir <dir>", "Generated Hermes profile directory to scan for model secrets")
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
				try {
					const invocation = buildHermesCliProbeInvocation({
						hermesBin: resolveHermesBin(options.hermesBin),
						hermesHome: resolveHermesHome(options.hermesHome),
						cwd: path.resolve(options.cwd ?? process.cwd()),
						prompt: options.prompt,
					});
					const timeoutMs = parseTimeoutMs(options.timeoutMs);
					report = await runHermesCliHeadlessProbe({
						allowRun: options.allowRun === true,
						invocation,
						runProcess: (launch) => runHermesLaunchInvocation(launch, { timeoutMs }),
					});
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

				const outPath =
					options.allowRun === true
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

			if (surface === "model.relay") {
				let report: Awaited<ReturnType<typeof runHermesModelRelayProbe>>;
				let outPath: string | undefined;
				try {
					report = await runHermesModelRelayProbe({
						allowRun: options.allowRun === true,
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
				} catch (error) {
					report = {
						schemaVersion: "telclaude.hermes.model-relay.v1",
						probeId: "model.relay",
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
				let report = await runHermesNetworkProbes({
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
		.command("cutover-check")
		.description("Evaluate strict Hermes wrapper cutover evidence")
		.option("--strict", "Fail closed for missing or unsafe evidence")
		.option("--dry-run", "Evaluate evidence without changing runtime state")
		.option("--json", "Emit structured JSON")
		.option(
			"--inventory <path>",
			"Inventory snapshot JSON path; collects live inventory when omitted",
		)
		.option("--scope <path>", "Cutover scope manifest JSON path", DEFAULT_CUTOVER_SCOPE_PATH)
		.option("--decisions <path>", "Decision log JSON path", DEFAULT_DECISION_LOG_PATH)
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
					featureProbes: string;
					lockfile: string;
					fixtures: string;
					networkProbes: string;
					nofork: string;
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
						inventory: options.inventory
							? readJsonFile(resolveHermesArtifactPath(options.inventory))
							: collectHermesInventory(),
						scopeManifest: readJsonFile(resolveHermesArtifactPath(options.scope)),
						decisionLog: readJsonFile(resolveHermesArtifactPath(options.decisions)),
						lockfile: readJsonFile(resolveHermesArtifactPath(options.lockfile)),
						featureProbeMatrix,
						featureProbeEvidence: collectHermesFeatureProbeEvidence(featureProbeMatrix),
						fixtureResults: readJsonFile(resolveHermesArtifactPath(options.fixtures)),
						noForkProof: readJsonFile(resolveHermesArtifactPath(options.nofork)),
						networkProbes: readJsonFile(resolveHermesArtifactPath(options.networkProbes)),
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

				const report = evaluateCutoverCheck(input, { strict, dryRun });
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
