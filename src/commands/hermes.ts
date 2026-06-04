import { spawn, spawnSync } from "node:child_process";
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
import type { HermesSignedEvidenceValidationOptions } from "../hermes/attestation-validation.js";
import {
	buildBrowserComputerBrokerFixtureEvidenceBundle,
	buildNetworkEgressBrokerProbeEvidenceFromReport,
	DEFAULT_BROWSER_COMPUTER_BROKER_EVIDENCE_PATHS,
	isBrowserComputerBrokerSurfaceId,
	readNetworkEgressBrokerRunReport,
	runTelclaudeBrowserComputerBrokerProbe,
} from "../hermes/browser-computer-broker-probes.js";
import {
	buildEdgeAdapterFixtureEvidenceBundle,
	buildEdgeAdapterProbeEvidence,
	DEFAULT_EDGE_ADAPTER_EVIDENCE_PATHS,
	isEdgeAdapterFeatureSurfaceId,
} from "../hermes/edge-adapter-probes.js";
import {
	allPrivateTelegramRequiredAssertions,
	analyzeVitestFixtureReport,
	archivedHermesEvidenceValidationOptions,
	buildCompatibilityLockfileDraft,
	buildCutoverInputBundleFromArtifacts,
	buildCutoverProofBundle,
	buildCutoverScopeManifestFromInventory,
	buildHermesDoctorReport,
	buildHermesGenerateDryRun,
	buildHermesProfileGenerationRedSeed,
	buildHermesQueueSnapshot,
	buildMissingDefaultCutoverFixtureResults,
	buildMissingDefaultCutoverNetworkProbes,
	buildMissingDefaultRollbackRehearsal,
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
	type DecisionLog,
	evaluateCutoverCheck,
	type FeatureProbeMatrix,
	type HermesArtifactWriteOptions,
	type HermesPin,
	PRIVATE_TELEGRAM_FIXTURE_DIGEST_PATHS,
	PRIVATE_TELEGRAM_FIXTURE_REQUIREMENTS,
	PRIVATE_TELEGRAM_FIXTURE_TEST_FILES,
	parseHermesPin,
	privateTelegramAssertionKey,
	readJsonFile,
	readOptionalJsonFile,
	resolveHermesArtifactPath,
	writeHermesJsonArtifact,
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
	DEFAULT_MODEL_RELAY_PROFILE_DIR,
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
	type NoForkWrapperRunEvidence,
	noForkSha256Digest,
	writeNoForkProofReport,
} from "../hermes/no-fork-proof.js";
import {
	buildHermesCliProbeInvocation,
	buildHermesOpenAiCodexRelayAuthStorePayload,
	DEFAULT_HERMES_CLI_HEADLESS_EVIDENCE_PATH,
	type HermesCliProbeReport,
	type HermesLaunchInvocation,
	parseHermesRelayProofEvidence,
	readHermesCliHeadlessProbeReport,
	runHermesCliHeadlessProbe,
	runHermesLaunchInvocation,
} from "../hermes/private-runtime.js";
import { signPrivateTelegramFixtureEvidenceAttestation } from "../hermes/private-telegram-fixture-attestation.js";
import {
	approveProReviewRequest,
	buildProReviewNativeYoetzEnv,
	buildProReviewRequestDraft,
	buildProReviewYoetzCommand,
	DEFAULT_PRO_REVIEW_NATIVE_CANARY_PATH,
	DEFAULT_PRO_REVIEW_REQUEST_PATH,
	evaluateProReviewCheck,
	type ProReviewShard,
	readProReviewNativeCanary,
	readProReviewRequest,
	readProReviewShardItemContent,
	validateProReviewYoetzInspectOutput,
	validateProReviewYoetzSendOutput,
} from "../hermes/pro-review.js";
import {
	DEFAULT_PROVIDER_APPROVAL_BINDING_EVIDENCE_PATH,
	runTelclaudeProviderApprovalBindingProbe,
} from "../hermes/provider-approval-binding-probe.js";
import {
	buildProviderDomainFixtureEvidenceBundle,
	DEFAULT_PROVIDER_DOMAIN_EVIDENCE_PATHS,
	isProviderDomainSurfaceId,
	runTelclaudeProviderDomainProbe,
} from "../hermes/provider-domain-probes.js";
import {
	buildGoogleProviderFixtureEvidenceBundle,
	DEFAULT_PROVIDER_GOOGLE_EVIDENCE_PATH,
	runTelclaudeGoogleProviderProbe,
} from "../hermes/provider-google-probe.js";
import {
	DEFAULT_PROVIDER_RELEASE_POLICY_EVIDENCE_PATH,
	runTelclaudeProviderReleasePolicyProbe,
} from "../hermes/provider-release-policy-probe.js";
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
	buildHermesWorkflowFixtureEvidenceBundle,
	DEFAULT_HERMES_WORKFLOW_EVIDENCE_PATHS,
	isHermesWorkflowSurfaceId,
	runHermesWorkflowProbe,
} from "../hermes/workflow-probes.js";
import {
	buildInternalResponseProof,
	internalResponseProofVerificationFailure,
} from "../internal-auth.js";
import {
	relayGetHermesPrivateRuntimeState,
	relaySetHermesPrivateRuntimeMode,
} from "../relay/capabilities-client.js";
import {
	mintOpenAiCodexPeerBoundProxyToken,
	OPENAI_CODEX_CONTAINED_RELAY_TOKEN_TTL_MS,
} from "../relay/openai-codex-proxy.js";

type JsonOption = {
	json?: boolean;
};

type PinOption = {
	pin?: string;
	lockfile?: string;
};

type TrackedSeedWriteOption = {
	writeTrackedSeed?: boolean;
};

const WRITE_TRACKED_SEED_OPTION_DESCRIPTION =
	"Allow writing tracked docs/hermes seed files; use only for deliberate seed regeneration";

type FeatureProbeDefinition = Omit<FeatureProbeMatrix["probes"][number], "hermes_pin" | "status">;

const DEFAULT_HERMES_FEATURE_PROBE_PIN: HermesPin = {
	version: DEFAULT_HERMES_UPSTREAM_VERSION,
};

const HERMES_FEATURE_PROBE_DEFINITIONS = [
	{
		surface_id: "execution.cli_headless",
		documented_seam: "Hermes chat -q headless mode in hermes_cli/main.py and hermes_cli/chat.py",
		probe_command:
			'pnpm dev hermes probe execution.cli_headless --allow-run --hermes-bin scripts/hermes-contained-cli-probe.sh --hermes-home "$PWD/.cache/tc-hermes-cli-headless" --cwd "$PWD" --prompt "Reply with exactly HERMES_OK_CODEX_SUB" --out artifacts/hermes/probes/execution-cli-headless.json',
		expected_result:
			"Wrapper launches pinned Hermes through the contained script, receives the proof token, and records Docker inspect plus relay server-observed peer evidence",
		negative_probe:
			"Wrapper rejects forbidden env keys, credential-like env values, credential-like argv values, host-gateway relay routes, loopback/public peers, stale runtime digests, and runtime evidence not bound to the contained network",
		evidence_path: DEFAULT_HERMES_CLI_HEADLESS_EVIDENCE_PATH,
		lockfile_key: "featureProbes.execution.cliHeadless",
		security_scope: "headless-availability-only",
		approval_equivalent: false,
		failure_outcome: "disable",
	},
	{
		surface_id: "execution.approval_continuation",
		documented_seam:
			"Hermes MCP bridge tools events_wait, permissions_list_open, and permissions_respond in mcp_serve.py",
		probe_command: "pnpm dev hermes probe execution.approval_continuation --allow-run",
		expected_result:
			"Approval request is observed, responded to, and the same Hermes run continues without cross-thread leakage",
		negative_probe:
			"Wrong actor, stale request, replayed approval, and mutated decision are denied",
		evidence_path: DEFAULT_APPROVAL_CONTINUATION_EVIDENCE_PATH,
		lockfile_key: "featureProbes.execution.approvalContinuation",
		security_scope: "approval-continuation",
		approval_equivalent: true,
		failure_outcome: "disable",
	},
	{
		surface_id: "execution.api_server_containment",
		documented_seam:
			"Pinned Hermes API server runs as a contained process behind Telclaude relay control",
		probe_command: "pnpm dev hermes probe execution.api_server_containment --allow-run",
		expected_result:
			"Contained Hermes API server starts with ephemeral bearer auth, advertises required run/approval/stop capabilities, and proves relay-only network containment",
		negative_probe:
			"Direct provider, vault, model-provider, private DNS, firewall flush, route add, and privileged runtime tamper attempts fail closed",
		evidence_path: DEFAULT_HERMES_API_SERVER_CONTAINMENT_EVIDENCE_PATH,
		lockfile_key: "featureProbes.execution.apiServerContainment",
		security_scope: "api-server-containment",
		approval_equivalent: false,
		failure_outcome: "disable",
	},
	{
		surface_id: "execution.served_mcp_containment",
		documented_seam: "Telclaude-served Hermes MCP relay-only HTTP endpoint",
		probe_command: "pnpm dev hermes probe execution.served_mcp_containment --allow-run",
		expected_result:
			"HTTP JSON-RPC client proves positive tools-only control and specific adversarial denials",
		negative_probe:
			"Forged handle, wrong connection, cross-domain memory, out-of-scope provider/outbound, sampling, malformed, unauthenticated, batch, prototype-key, and execute-without-ledger calls fail closed",
		evidence_path: DEFAULT_SERVED_MCP_CONTAINMENT_EVIDENCE_PATH,
		lockfile_key: "featureProbes.execution.servedMcpContainment",
		security_scope: "served-mcp-containment",
		approval_equivalent: true,
		failure_outcome: "disable",
	},
	{
		surface_id: "model.relay",
		documented_seam:
			"Hermes model provider and endpoint configuration is generated by the wrapper and mounted read-only",
		probe_command: `pnpm dev hermes probe model.relay --allow-run --posture contained-internal --relay-url http://telclaude:8790/v1/models --model-url 'https://chatgpt.com/backend-api/codex/models?client_version=1.0.0' --profile-dir ${DEFAULT_MODEL_RELAY_PROFILE_DIR} --container-name tc-hermes-contained --expected-peer-address $TELCLAUDE_HERMES_CONTAINED_IP --relay-peer-address $TELCLAUDE_HERMES_RELAY_IP`,
		expected_result:
			"Default model traffic uses the Telclaude relay-owned ChatGPT/Codex subscription path and reaches only relay endpoints; direct non-relay model-provider egress fails",
		negative_probe:
			"A planted model-provider plugin, writable profile override, raw OpenAI API key, or mounted Hermes/Codex OAuth file cannot bypass the relay route",
		evidence_path: DEFAULT_MODEL_RELAY_EVIDENCE_PATH,
		lockfile_key: "featureProbes.model.relay",
		security_scope: "model-relay",
		approval_equivalent: false,
		failure_outcome: "disable",
	},
] as const satisfies readonly FeatureProbeDefinition[];

function allHermesFeatureProbeDefinitions(): readonly FeatureProbeDefinition[] {
	return [
		...HERMES_FEATURE_PROBE_DEFINITIONS,
		...Object.entries(DEFAULT_EDGE_ADAPTER_EVIDENCE_PATHS).map(
			([surfaceId, evidencePath]): FeatureProbeDefinition => ({
				surface_id: surfaceId,
				documented_seam:
					"Telclaude edge adapter mediates channel ingress, outbound delivery, identity, attachments, and credential custody before Hermes sees sanitized events.",
				probe_command: `pnpm dev hermes probe ${surfaceId} --allow-run --out ${evidencePath}`,
				expected_result:
					"Edge events reach the correct Hermes profile as sanitized refs and outbound delivery remains owned by Telclaude policy.",
				negative_probe:
					"Unknown actors, direct bridge access, raw credentials, raw attachments, cross-domain reuse, and unscoped sensitive actions fail closed.",
				evidence_path: evidencePath,
				lockfile_key: `featureProbes.${surfaceId}`,
				security_scope: "edge-adapter",
				approval_equivalent: !["identity.migration", "attachment.quarantine"].includes(surfaceId),
				failure_outcome: "disable",
			}),
		),
		{
			surface_id: "providers.release-policy",
			documented_seam:
				"Telclaude provider release policy owns the final provider-read/write disclosure boundary before Hermes receives provider refs.",
			probe_command: `pnpm dev hermes probe providers.release-policy --allow-run --out ${DEFAULT_PROVIDER_RELEASE_POLICY_EVIDENCE_PATH}`,
			expected_result:
				"Provider release artifacts expose scoped refs and audit metadata only after actor, recipient, strong-link, and approval policy pass.",
			negative_probe:
				"Wrong actor, wrong recipient, missing strong link, urgent-health misclassification, private memory leakage, and unapproved sensitive writes fail closed.",
			evidence_path: DEFAULT_PROVIDER_RELEASE_POLICY_EVIDENCE_PATH,
			lockfile_key: "featureProbes.providers.releasePolicy",
			approval_equivalent: true,
			failure_outcome: "disable",
		},
		...Object.entries(DEFAULT_PROVIDER_DOMAIN_EVIDENCE_PATHS).map(
			([surfaceId, evidencePath]): FeatureProbeDefinition => ({
				surface_id: surfaceId,
				documented_seam:
					"Telclaude provider sidecar remains credential owner and Hermes uses MCP/provider proxy tools.",
				probe_command: `pnpm dev hermes probe ${surfaceId} --allow-run --out ${evidencePath}`,
				expected_result:
					"Provider reads and prepared writes route through server-side policy, side-effect ledger, idempotency, and provider proxy custody.",
				negative_probe:
					"Direct provider access, replayed writes, wrong actor, missing approval, leaked credentials, and server-side approval bypass fail closed.",
				evidence_path: evidencePath,
				lockfile_key: `featureProbes.${surfaceId}`,
				approval_equivalent: true,
				failure_outcome: "disable",
			}),
		),
		{
			surface_id: "providers.approval-binding",
			documented_seam:
				"Telclaude provider sidecar binds sensitive provider writes to server-derived approval tokens.",
			probe_command: `pnpm dev hermes probe providers.approval-binding --allow-run --out ${DEFAULT_PROVIDER_APPROVAL_BINDING_EVIDENCE_PATH}`,
			expected_result:
				"Prepared provider writes execute only when approval token, actor, content hash, provider account, and idempotency key match.",
			negative_probe:
				"Replay, wrong actor, mutated content, wrong provider account, direct-provider bypass, and server-side approval forgery fail closed.",
			evidence_path: DEFAULT_PROVIDER_APPROVAL_BINDING_EVIDENCE_PATH,
			lockfile_key: "featureProbes.providers.approvalBinding",
			security_scope: "provider-approval-binding",
			approval_equivalent: true,
			failure_outcome: "disable",
		},
		{
			surface_id: "served_mcp.provider-tools",
			documented_seam:
				"Served-MCP exposes provider tools only inside Telclaude-owned connection context and side-effect policy.",
			probe_command: `pnpm dev hermes probe served_mcp.provider-tools --from-report ${DEFAULT_SERVED_MCP_PROVIDER_TOOLS_SOURCE_EVIDENCE_PATH} --out ${DEFAULT_SERVED_MCP_PROVIDER_TOOLS_EVIDENCE_PATH}`,
			expected_result:
				"Served-MCP provider tools are exposed only through relay-originated, scoped, non-forgeable connection context.",
			negative_probe:
				"Missing source evidence, forged connection, wrong peer, direct provider credentials, and execute-without-ledger attempts fail closed.",
			evidence_path: DEFAULT_SERVED_MCP_PROVIDER_TOOLS_EVIDENCE_PATH,
			lockfile_key: "featureProbes.served_mcp.providerTools",
			security_scope: "served-mcp-provider-tools",
			approval_equivalent: true,
			failure_outcome: "disable",
		},
		{
			surface_id: "providers.google",
			documented_seam:
				"Google sidecar owns Gmail/Calendar/Drive credentials and exposes only scoped provider tools to Hermes.",
			probe_command: `pnpm dev hermes probe providers.google --allow-run --out ${DEFAULT_PROVIDER_GOOGLE_EVIDENCE_PATH}`,
			expected_result:
				"Google reads and prepared writes remain sidecar-owned, approval-bound, and audited without exposing OAuth material to Hermes.",
			negative_probe:
				"Direct OAuth access, wrong actor, replayed write, unapproved mutation, and raw credential exposure fail closed.",
			evidence_path: DEFAULT_PROVIDER_GOOGLE_EVIDENCE_PATH,
			lockfile_key: "featureProbes.providers.google",
			approval_equivalent: true,
			failure_outcome: "disable",
		},
		...Object.entries(DEFAULT_HERMES_WORKFLOW_EVIDENCE_PATHS).map(
			([surfaceId, evidencePath]): FeatureProbeDefinition => ({
				surface_id: surfaceId,
				documented_seam:
					"Telclaude workflow run ledger owns scheduled and long-running run authority, checkpoints, idempotency, approval resume, and terminal status.",
				probe_command: `pnpm dev hermes probe ${surfaceId} --allow-run --out ${evidencePath}`,
				expected_result:
					"Workflow runs record server-derived authority, durable checkpoints, deduplication, resume binding, and stale-resume denial.",
				negative_probe:
					"Duplicate delivery, stale resume, forged checkpoint, wrong approval, and cross-run continuation fail closed.",
				evidence_path: evidencePath,
				lockfile_key: `featureProbes.${surfaceId}`,
				security_scope: "workflow-ledger",
				approval_equivalent: surfaceId === "workflow.longrun",
				failure_outcome: "disable",
			}),
		),
		{
			surface_id: "approval.continuation",
			documented_seam: "Hermes MCP approval fallback through Telclaude MCP bridge",
			probe_command: "pnpm dev hermes probe execution.approval_continuation --allow-run",
			expected_result:
				"Approval continuation remains available through the canonical fallback surface and is bound to the same execution proof.",
			negative_probe:
				"Wrong actor, stale request, replayed approval, and mutated decision are denied",
			evidence_path: DEFAULT_APPROVAL_CONTINUATION_EVIDENCE_PATH,
			lockfile_key: "featureProbes.approval.continuation",
			security_scope: "approval-continuation",
			approval_equivalent: true,
			failure_outcome: "disable",
		},
		{
			surface_id: "sideeffect.ledger",
			documented_seam:
				"Telclaude MCP side-effect ledger prepares, approves, executes, and audits side-effecting tool calls.",
			probe_command: `pnpm dev hermes probe sideeffect.ledger --allow-run --out ${DEFAULT_SIDE_EFFECT_LEDGER_EVIDENCE_PATH}`,
			expected_result:
				"MCP execute calls require durable prepared refs, actor binding, approval binding, idempotency, and audit records.",
			negative_probe:
				"Execute-without-ledger, replay, wrong actor, mutated args, expired refs, and forged approval fail closed.",
			evidence_path: DEFAULT_SIDE_EFFECT_LEDGER_EVIDENCE_PATH,
			lockfile_key: "featureProbes.sideeffect.ledger",
			security_scope: "side-effect-ledger",
			approval_equivalent: true,
			failure_outcome: "disable",
		},
		...Object.entries(DEFAULT_BROWSER_COMPUTER_BROKER_EVIDENCE_PATHS).map(
			([surfaceId, evidencePath]): FeatureProbeDefinition => ({
				surface_id: surfaceId,
				documented_seam:
					"Telclaude browser/computer broker owns browser profile custody, computer target authorization, and outbound network egress mediation.",
				probe_command: `pnpm dev hermes probe ${surfaceId} --allow-run --out ${evidencePath}`,
				expected_result:
					"Browser/computer actions are scoped to approved targets with audit refs, quarantine refs, and direct-egress denial evidence.",
				negative_probe:
					"Unauthorized targets, cookie/profile leakage, cross-domain browser access, direct upload, SMTP/IMAP/WhatsApp, and provider/model bypass fail closed.",
				evidence_path: evidencePath,
				lockfile_key:
					surfaceId === "network.egress-broker"
						? "featureProbes.network.egressBroker"
						: `featureProbes.${surfaceId}`,
				approval_equivalent: surfaceId === "computer.broker",
				failure_outcome: "disable",
			}),
		),
	];
}

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
} & TrackedSeedWriteOption;

type NetworkProbeOption = JsonOption & {
	allowRun?: boolean;
	deferAttestation?: boolean;
	fromReport?: string;
	runReportOut?: string;
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
} & TrackedSeedWriteOption;

type InventoryOption = JsonOption & {
	out?: string;
} & TrackedSeedWriteOption;

type RollbackRehearsalOption = JsonOption & {
	allowRun?: boolean;
	out: string;
	evidencePath?: string;
} & TrackedSeedWriteOption;

type QueueSnapshotOption = JsonOption & {
	inventory?: string;
	out?: string;
} & TrackedSeedWriteOption;

type CutoverScopeOption = JsonOption & {
	inventory: string;
	out?: string;
} & TrackedSeedWriteOption;

type DecisionLogOption = JsonOption & {
	inventory?: string;
	out?: string;
} & TrackedSeedWriteOption;

type FeatureProbeMatrixOption = JsonOption &
	PinOption & {
		out?: string;
	} & TrackedSeedWriteOption;

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
	} & TrackedSeedWriteOption;

type FixtureResultOption = JsonOption & {
	write?: boolean;
	includeBrowserComputer?: boolean;
	includeEdgeAdapter?: boolean;
	includeProviderDomain?: boolean;
	includeWorkflow?: boolean;
	onlyProviderDomain?: boolean;
	skipPrivateTelegram?: boolean;
	mergeExisting?: boolean;
	out: string;
	evidenceDir: string;
	testReport?: string;
	reportOut: string;
	observedAt?: string;
} & TrackedSeedWriteOption;

type ProReviewCheckOption = JsonOption & {
	request: string;
	canary: string;
	requireApproval?: boolean;
};

type ProReviewRefreshOption = JsonOption & {
	request: string;
	canary: string;
	prompt?: string;
	selectedFile?: string[];
	replaceSelectedFiles?: boolean;
	shardMaxSourceBytes?: string;
	write?: boolean;
} & TrackedSeedWriteOption;

type ProReviewApproveOption = JsonOption & {
	request: string;
	approvalId: string;
	operator: string;
	approvedAt?: string;
	payloadSha256?: string;
	write?: boolean;
} & TrackedSeedWriteOption;

type ProReviewSendOption = JsonOption & {
	request: string;
	canary: string;
	bundleOut?: string;
	execute?: boolean;
	waitTimeoutMs?: string;
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

function collectOption(value: string, previous: string[]): string[] {
	return [...previous, value];
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

function trackedSeedWriteOptions(options: TrackedSeedWriteOption): HermesArtifactWriteOptions {
	return options.writeTrackedSeed === true ? { allowTrackedSeedWrite: true } : {};
}

function writeJsonArtifact(
	filePath: string,
	value: unknown,
	options: HermesArtifactWriteOptions = {},
): void {
	writeHermesJsonArtifact(filePath, value, options);
}

function dirtyTrackedProReviewSelectedFiles(selectedFiles: readonly string[]): readonly string[] {
	const topLevel = spawnSync("git", ["rev-parse", "--show-toplevel"], {
		cwd: process.cwd(),
		encoding: "utf8",
		stdio: ["ignore", "pipe", "ignore"],
	});
	if (topLevel.status !== 0 || !topLevel.stdout.trim()) return [];
	const repoRoot = fs.realpathSync.native(topLevel.stdout.trim());
	const repoRelativeFiles = selectedFiles
		.map((file) => {
			const resolved = path.resolve(file);
			return fs.existsSync(resolved) ? fs.realpathSync.native(resolved) : resolved;
		})
		.filter((file) => file === repoRoot || file.startsWith(`${repoRoot}${path.sep}`))
		.map((file) => path.relative(repoRoot, file))
		.filter((file) => file.length > 0);
	if (repoRelativeFiles.length === 0) return [];

	const dirty = new Set<string>();
	for (const args of [
		["diff", "--name-only", "--", ...repoRelativeFiles],
		["diff", "--cached", "--name-only", "--", ...repoRelativeFiles],
	]) {
		const result = spawnSync("git", ["-C", repoRoot, ...args], {
			encoding: "utf8",
			stdio: ["ignore", "pipe", "pipe"],
		});
		if (result.status !== 0) {
			throw new Error(
				`Unable to verify Pro review selected file cleanliness: ${
					result.stderr.trim() || "git diff failed"
				}`,
			);
		}
		for (const line of result.stdout.split(/\r?\n/)) {
			const file = line.trim();
			if (file) dirty.add(file);
		}
	}
	return [...dirty].sort();
}

function assertProReviewTrackedSeedSelectedFilesClean(
	selectedFiles: readonly string[],
	options: ProReviewRefreshOption,
): void {
	if (options.write !== true || options.writeTrackedSeed !== true) return;
	const dirtyFiles = dirtyTrackedProReviewSelectedFiles(selectedFiles);
	if (dirtyFiles.length === 0) return;
	throw new Error(
		`Refusing to write tracked Pro review request while selected tracked file(s) are dirty: ${dirtyFiles.join(", ")}`,
	);
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

function defaultCutoverArtifactIsMissing(filePath: string, defaultPath: string): boolean {
	const resolvedPath = resolveHermesArtifactPath(filePath);
	return resolvedPath === resolveHermesArtifactPath(defaultPath) && !fs.existsSync(resolvedPath);
}

function readCutoverFixtureResults(filePath: string, options: { dryRun: boolean }): unknown {
	if (options.dryRun && defaultCutoverArtifactIsMissing(filePath, DEFAULT_FIXTURE_RESULTS_PATH)) {
		return buildMissingDefaultCutoverFixtureResults();
	}
	return readJsonFile(resolveHermesArtifactPath(filePath));
}

function readCutoverNetworkProbes(filePath: string, options: { dryRun: boolean }): unknown {
	if (options.dryRun && defaultCutoverArtifactIsMissing(filePath, DEFAULT_NETWORK_PROBES_PATH)) {
		return buildMissingDefaultCutoverNetworkProbes();
	}
	return readJsonFile(resolveHermesArtifactPath(filePath));
}

function readCutoverRollbackRehearsal(filePath: string, options: { dryRun: boolean }): unknown {
	if (
		options.dryRun &&
		defaultCutoverArtifactIsMissing(filePath, DEFAULT_ROLLBACK_REHEARSAL_PATH)
	) {
		return buildMissingDefaultRollbackRehearsal();
	}
	return readJsonFile(resolveHermesArtifactPath(filePath));
}

function buildHermesDecisionLogDraft(input: { inventory?: unknown } = {}): DecisionLog {
	const workflows = inventoryWorkflowDecisionInputs(input.inventory);
	const decisions = new Map<string, DecisionLog["decisions"][number]>();
	const addDecision = (id: string, affectedWorkflows: readonly string[]) => {
		if (!id.trim()) return;
		const existing = decisions.get(id);
		const affected = Array.from(
			new Set([...(existing?.affected_workflows ?? []), ...affectedWorkflows]),
		).sort();
		decisions.set(id, {
			id,
			status: "unresolved",
			owner: "operator",
			deadline_phase: "pre-cutover",
			affected_workflows: affected,
			cutover_impact: `Cutover remains blocked until ${id} is resolved by an operator-owned decision.`,
		});
	};

	addDecision(
		"D-first-cutover-workflow-set",
		workflows.map((workflow) => workflow.workflowId),
	);
	for (const workflow of workflows) {
		for (const decisionId of workflow.unresolvedDecisionIds) {
			addDecision(decisionId, [workflow.workflowId]);
		}
	}

	return {
		schemaVersion: 1,
		decisions: Array.from(decisions.values()).sort((left, right) =>
			left.id.localeCompare(right.id),
		),
	};
}

function inventoryWorkflowDecisionInputs(inventory: unknown): Array<{
	workflowId: string;
	unresolvedDecisionIds: string[];
}> {
	if (!isJsonRecord(inventory) || !Array.isArray(inventory.workflows)) return [];
	return inventory.workflows.flatMap((workflow) => {
		if (!isJsonRecord(workflow) || typeof workflow.workflow_id !== "string") return [];
		return [
			{
				workflowId: workflow.workflow_id,
				unresolvedDecisionIds: Array.isArray(workflow.unresolved_decision_ids)
					? workflow.unresolved_decision_ids.filter(
							(decisionId): decisionId is string =>
								typeof decisionId === "string" && decisionId.trim().length > 0,
						)
					: [],
			},
		];
	});
}

function fileSha256(filePath: string): string {
	return `sha256:${crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex")}`;
}

function noForkFileSha256(filePath: string): `sha256:${string}` {
	return fileSha256(filePath) as `sha256:${string}`;
}

function buildNoForkWrapperPackageDigest(): `sha256:${string}` {
	const sourcePaths = [
		"package.json",
		"pnpm-lock.yaml",
		"src/commands/hermes.ts",
		"src/hermes/no-fork-attestation.ts",
		"src/hermes/no-fork-proof.ts",
	];
	return noForkSha256Digest(
		JSON.stringify(
			sourcePaths.map((sourcePath) => {
				const resolved = resolveHermesArtifactPath(sourcePath);
				return {
					path: sourcePath,
					sha256: fs.existsSync(resolved) ? fileSha256(resolved) : null,
				};
			}),
		),
	);
}

function buildNoForkP0Command(options: {
	readonly checkout: string;
	readonly expectedRef: string;
	readonly expectedVersion: string;
	readonly out: string;
	readonly inventory?: string;
	readonly scope: string;
	readonly decisions: string;
	readonly proofBundle: string;
	readonly featureProbes: string;
	readonly lockfile: string;
	readonly fixtures: string;
	readonly networkProbes: string;
	readonly profileProof: string;
	readonly rollback: string;
}): readonly string[] {
	const command = [
		"telclaude",
		"hermes",
		"prove",
		"--upstream-clean",
		"--p0",
		"--checkout",
		options.checkout,
		"--expected-ref",
		options.expectedRef,
		"--expected-version",
		options.expectedVersion,
		"--out",
		options.out,
		...(options.inventory ? ["--inventory", options.inventory] : []),
		"--scope",
		options.scope,
		"--decisions",
		options.decisions,
		"--proof-bundle",
		options.proofBundle,
		"--feature-probes",
		options.featureProbes,
		"--lockfile",
		options.lockfile,
		"--fixtures",
		options.fixtures,
		"--network-probes",
		options.networkProbes,
		"--profile-proof",
		options.profileProof,
		"--rollback",
		options.rollback,
	];
	return command;
}

const NO_FORK_BOOTSTRAP_FAILURE_PATTERNS = [
	/^no-fork evidence runnerAttestation is missing$/,
	/^missing no-fork evidence check runner\.attestation$/,
	/^missing no-fork evidence check runner\.p0$/,
	/^missing no-fork evidence check runner\.noRuntimeSourceReplacement$/,
	/^missing no-fork evidence check runner\.noMonkeypatch$/,
	/^missing no-fork evidence check runner\.postStatusClean$/,
	/^missing no-fork evidence check runner\.postDiffClean$/,
	/^missing no-fork evidence check runner\.postIndexClean$/,
	/^no-fork evidence required check runner\.attestation is fail: /,
	/^no-fork evidence required check runner\.p0 is fail: /,
	/^no-fork evidence required check runner\.noRuntimeSourceReplacement is fail: /,
	/^no-fork evidence required check runner\.noMonkeypatch is fail: /,
	/^no-fork evidence check runner\.attestation is fail: /,
	/^no-fork evidence check runner\.p0 is fail: /,
	/^no-fork evidence check runner\.noRuntimeSourceReplacement is fail: /,
	/^no-fork evidence check runner\.noMonkeypatch is fail: /,
];

const NO_FORK_BOOTSTRAP_SUMMARY_FAILURE_PATTERNS = [
	/^no-fork proof summary hermesCheckoutClean is false$/,
	/^no-fork evidence hermesCheckoutClean is false$/,
];

const NO_FORK_BOOTSTRAP_SIGNAL_PATTERNS = [
	/^no-fork evidence runnerAttestation is missing$/,
	/^no-fork evidence required check runner\.attestation is fail: no-fork wrapper run attestation is missing$/,
	/^no-fork evidence check runner\.attestation is fail: no-fork wrapper run attestation is missing$/,
];

const PROOF_BUNDLE_NO_FORK_INVALID_PREFIX = "proof bundle artifact noForkProof invalid: ";
const PROOF_BUNDLE_STATUS_MISMATCH_DETAIL =
	"artifact status does not match on-disk semantic evidence";
const PROOF_BUNDLE_SEMANTIC_FAILURE_PREFIX = "artifact semantic evidence failed: ";

function isNoForkBootstrapFailure(detail: string): boolean {
	const clauses = detail
		.split(";")
		.map((clause) => clause.trim())
		.filter((clause) => clause.length > 0);
	let sawMissingAttestationSignal = false;
	const allClausesAllowed =
		clauses.length > 0 &&
		clauses.every((clause) => {
			if (NO_FORK_BOOTSTRAP_FAILURE_PATTERNS.some((pattern) => pattern.test(clause))) {
				if (NO_FORK_BOOTSTRAP_SIGNAL_PATTERNS.some((pattern) => pattern.test(clause))) {
					sawMissingAttestationSignal = true;
				}
				return true;
			}
			return NO_FORK_BOOTSTRAP_SUMMARY_FAILURE_PATTERNS.some((pattern) => pattern.test(clause));
		});
	return allClausesAllowed && sawMissingAttestationSignal;
}

function isProofBundleNoForkBootstrapFailure(detail: string): boolean {
	if (!detail.startsWith(PROOF_BUNDLE_NO_FORK_INVALID_PREFIX)) return false;
	const clauses = detail
		.slice(PROOF_BUNDLE_NO_FORK_INVALID_PREFIX.length)
		.split(";")
		.map((clause) => clause.trim())
		.filter((clause) => clause.length > 0);
	if (!clauses.includes(PROOF_BUNDLE_STATUS_MISMATCH_DETAIL)) return false;
	if (
		!clauses.every(
			(clause) =>
				clause === PROOF_BUNDLE_STATUS_MISMATCH_DETAIL ||
				clause.startsWith(PROOF_BUNDLE_SEMANTIC_FAILURE_PREFIX),
		)
	) {
		return false;
	}
	const semanticFailures = clauses
		.filter((clause) => clause.startsWith(PROOF_BUNDLE_SEMANTIC_FAILURE_PREFIX))
		.map((clause) => clause.slice(PROOF_BUNDLE_SEMANTIC_FAILURE_PREFIX.length).trim())
		.filter((clause) => clause.length > 0);
	return semanticFailures.length > 0 && isNoForkBootstrapFailure(semanticFailures.join("; "));
}

function isLockfileNoForkBootstrapFailure(detail: string): boolean {
	return detail === "lockfile noForkProofEvidencePath does not match no-fork evidence path";
}

export function deriveNoForkP0Status(
	cutover: ReturnType<typeof evaluateCutoverCheck>,
): "pass" | "fail" {
	const failingGates = cutover.gates.filter((gate) => gate.status !== "pass");
	if (failingGates.length === 0) return "pass";
	if (
		failingGates.every((gate) => {
			if (gate.name === "nofork.clean") return isNoForkBootstrapFailure(gate.detail);
			if (gate.name === "proofBundle.noForkProof.valid") {
				return isProofBundleNoForkBootstrapFailure(gate.detail);
			}
			if (gate.name === "lockfile.consistent") {
				return isLockfileNoForkBootstrapFailure(gate.detail);
			}
			return false;
		})
	) {
		return "pass";
	}
	return "fail";
}

function profileProofDeniesSourceReplacement(profileProof: unknown): boolean {
	if (!isJsonRecord(profileProof) || !Array.isArray(profileProof.checks)) return false;
	return profileProof.checks.some(
		(check) =>
			isJsonRecord(check) &&
			check.name === "profile.noSourceReplacement" &&
			check.status === "pass",
	);
}

function isJsonRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function resolveProReviewBundlePath(bundleOut: string | undefined): string {
	return bundleOut
		? resolveHermesArtifactPath(bundleOut)
		: path.join(os.tmpdir(), `telclaude-hermes-pro-review-${process.pid}.md`);
}

function writeProReviewBundle(requestPath: string, bundlePath: string): void {
	const request = readProReviewRequest(requestPath);
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
	fs.writeFileSync(bundlePath, `${lines.join("\n")}\n`, { encoding: "utf8", mode: 0o600 });
	fs.chmodSync(bundlePath, 0o600);
}

function writeProReviewShardBundle(
	requestPath: string,
	bundlePath: string,
	shard: ProReviewShard,
): void {
	const request = readProReviewRequest(requestPath);
	const lines = [
		"# Telclaude Hermes Wrapper Pro Review Shard",
		"",
		"## Request",
		"",
		request.prompt,
		"",
		"## Root Native Review Binding",
		"",
		`- transport: ${String(request.transport)}`,
		`- model: ${String(request.model)}`,
		`- fallbackAllowed: ${String(request.fallbackAllowed)}`,
		`- payloadSha256: ${String(request.payloadBinding.payloadSha256)}`,
		`- shardPlanSha256: ${String(request.payloadBinding.shardPlanSha256 ?? "")}`,
		"",
		"## Shard Binding",
		"",
		`- shardId: ${shard.shardId}`,
		`- shardIndex: ${shard.index + 1}/${shard.count}`,
		`- shardSha256: ${shard.shardSha256}`,
		`- sourceBytes: ${shard.sourceBytes}`,
		`- focus: ${shard.focus}`,
		"",
		"Review this shard only. At the top of your response, echo these exact binding lines:",
		`payloadSha256: ${String(request.payloadBinding.payloadSha256)}`,
		`shardPlanSha256: ${String(request.payloadBinding.shardPlanSha256 ?? "")}`,
		`shardId: ${shard.shardId}`,
		`shardSha256: ${shard.shardSha256}`,
		"Then return a Findings section and a Residual risk section.",
		"Do not review outside this shard or claim full-context coverage.",
		"",
		"## Files",
		"",
	];
	for (const item of shard.items) {
		lines.push(
			`### ${item.path}:${item.startLine}-${item.endLine}`,
			"",
			"```text",
			readProReviewShardItemContent(item),
			"```",
			"",
		);
	}
	fs.mkdirSync(path.dirname(bundlePath), { recursive: true });
	fs.writeFileSync(bundlePath, `${lines.join("\n")}\n`, { encoding: "utf8", mode: 0o600 });
	fs.chmodSync(bundlePath, 0o600);
}

function proReviewShardBundlePath(bundlePath: string, shard: ProReviewShard): string {
	const extension = path.extname(bundlePath) || ".md";
	const basename = path.basename(bundlePath, extension);
	return path.join(path.dirname(bundlePath), `${basename}.${shard.shardId}${extension}`);
}

function buildProReviewRunId(): string {
	const timestamp = new Date().toISOString().replace(/\D/g, "").slice(0, 14);
	return `hermes_${timestamp}_${crypto.randomBytes(4).toString("hex")}`;
}

function buildProReviewInspectCommand(extensionInstanceId: string, runId: string): string[] {
	return [
		"yoetz",
		"browser",
		"extension",
		"inspect",
		"--chatgpt",
		"--run-id",
		runId,
		"--extension-instance-id",
		extensionInstanceId,
		"--format",
		"json",
	];
}

function parseProReviewWaitTimeoutMs(value: string | undefined): number | undefined {
	if (value === undefined) return undefined;
	const parsed = Number(value);
	if (!Number.isInteger(parsed) || parsed <= 0) {
		throw new Error("--wait-timeout-ms must be a positive integer");
	}
	return parsed;
}

function parseProReviewShardMaxSourceBytes(value: string | undefined): number | undefined {
	if (value === undefined) return undefined;
	const parsed = Number(value);
	if (!Number.isInteger(parsed) || parsed <= 0) {
		throw new Error("--shard-max-source-bytes must be a positive integer");
	}
	return parsed;
}

type ProReviewYoetzProcessResult = {
	readonly status: number | null;
	readonly stdout: string;
	readonly stderr: string;
	readonly error?: string;
};

function runProReviewYoetzCommand(
	command: readonly string[],
	env: NodeJS.ProcessEnv,
): Promise<ProReviewYoetzProcessResult> {
	const executable = command[0];
	if (!executable) {
		return Promise.resolve({
			status: null,
			stdout: "",
			stderr: "",
			error: "Yoetz command is empty",
		});
	}
	return new Promise((resolve) => {
		const child = spawn(executable, command.slice(1), { env });
		let stdout = "";
		let stderr = "";
		let settled = false;
		const finish = (result: ProReviewYoetzProcessResult) => {
			if (settled) return;
			settled = true;
			resolve(result);
		};
		child.stdout?.setEncoding("utf8");
		child.stdout?.on("data", (chunk: string) => {
			stdout += chunk;
		});
		child.stderr?.setEncoding("utf8");
		child.stderr?.on("data", (chunk: string) => {
			stderr += chunk;
			process.stderr.write(chunk);
		});
		child.on("error", (error) => {
			finish({ status: null, stdout, stderr, error: error.message });
		});
		child.on("close", (code) => {
			finish({ status: code, stdout, stderr });
		});
	});
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
		const provenanceSource = options.invocation
			? "machine-observed-test-report"
			: "imported-test-report";
		const item = {
			schemaVersion: "telclaude.hermes.fixture-evidence.v1",
			id: fixture.id,
			status,
			ran: true,
			evidence_path: evidencePath,
			observedAt: options.observedAt,
			provenance: {
				runner: "vitest-json",
				command: options.invocation?.command.join(" "),
				source: provenanceSource,
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
		return options.invocation
			? {
					...item,
					privateTelegramRunnerAttestation: signPrivateTelegramFixtureEvidenceAttestation({
						fixtureId: fixture.id,
						status,
						observedAt: options.observedAt,
						provenanceRunner: "vitest-json",
						provenanceSource,
						testReportPath: options.testReportPath,
						testReportSha256: reportDigest as `sha256:${string}`,
						invocation: options.invocation,
						requiredTests: fixture.requiredTests,
						requiredAssertions: fixture.requiredAssertions,
						checks,
					}),
				}
			: item;
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

function assertPrivateTelegramFixtureWritePreconditions(options: FixtureResultOption): void {
	if (options.write !== true) return;
	if (options.testReport) {
		throw new Error(
			"Imported private Telegram fixture reports cannot be written; omit --test-report so the command runs Vitest and records machine-observed evidence.",
		);
	}
	assertOperatorRelaySigningEnv();
}

function operatorRelaySigningEnvFailure(): string | null {
	if (!process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY?.trim()) {
		return "Missing relay response signing key for operator. Set OPERATOR_RPC_RELAY_PRIVATE_KEY.";
	}
	return operatorRelayVerificationEnvFailure() ?? operatorRelaySigningRoundTripFailure();
}

function operatorRelayVerificationEnvFailure(): string | null {
	if (!process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY?.trim()) {
		return "Missing relay response verification key for operator. Set OPERATOR_RPC_RELAY_PUBLIC_KEY.";
	}
	return null;
}

function operatorRelaySigningRoundTripFailure(): string | null {
	const body = "telclaude-hermes-operator-relay-signing-preflight";
	const requestPath = "/v1/hermes.operator-relay-signing-preflight";
	try {
		const proof = buildInternalResponseProof("POST", requestPath, body, body, {
			scope: "operator",
		});
		const failure = internalResponseProofVerificationFailure(
			proof,
			"POST",
			requestPath,
			body,
			body,
			{ scope: "operator" },
		);
		return failure
			? `Operator relay signing keys failed round-trip verification: ${failure}`
			: null;
	} catch (error) {
		return `Operator relay signing keys failed round-trip verification: ${
			error instanceof Error ? error.message : String(error)
		}`;
	}
}

function assertOperatorRelaySigningEnv(): void {
	const failure = operatorRelaySigningEnvFailure();
	if (failure) throw new Error(failure);
}

function importedNetworkProbeReportRequiresSigning(reportPath: string): boolean {
	const raw = readJsonFile(resolveHermesArtifactPath(reportPath));
	if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return false;
	const evidence = (raw as { readonly evidence?: unknown }).evidence;
	if (!Array.isArray(evidence)) return false;
	return evidence.some((probe) => {
		if (typeof probe !== "object" || probe === null || Array.isArray(probe)) return false;
		const item = probe as { readonly status?: unknown; readonly attestation?: unknown };
		return item.status === "pass" && item.attestation === undefined;
	});
}

function failHermesProbeInput(
	surface: string,
	options: { readonly json?: boolean },
	detail: string,
): void {
	const report = {
		schemaVersion: "telclaude.hermes.probe-report.v1",
		status: "input_error",
		surface,
		detail,
	};
	if (options.json) {
		printJson(report);
	} else {
		console.log(`Hermes probe ${surface}: input_error`);
		console.log(`- FAIL surface: ${detail}`);
	}
	process.exitCode = 1;
}

function mergeFixtureResults(
	existing: Array<{ id: string; status: "pass" | "fail"; evidence_path: string }>,
	generated: Array<{ id: string; status: "pass" | "fail"; evidence_path: string }>,
): Array<{ id: string; status: "pass" | "fail"; evidence_path: string }> {
	const generatedById = new Map(generated.map((result) => [result.id, result]));
	const merged = existing.map((result) => generatedById.get(result.id) ?? result);
	const existingIds = new Set(existing.map((result) => result.id));
	for (const result of generated) {
		if (!existingIds.has(result.id)) merged.push(result);
	}
	return merged;
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

const HERMES_CODEX_BASE_URL_ENV = "HERMES_CODEX_BASE_URL";
const HERMES_INFERENCE_MODEL_ENV = "HERMES_INFERENCE_MODEL";
const OPENAI_CODEX_PROXY_PROOF_LATEST_URL =
	"http://telclaude:8790/v1/openai-codex-proxy/_telclaude/relay-proof/latest";

function runHermesLaunchInvocationInDockerExec(
	invocation: HermesLaunchInvocation,
	options: { dockerBin?: string; containerName: string; timeoutMs?: number },
): Promise<{
	exitCode: number;
	stdout: string;
	stderr: string;
	startedAt?: string;
	endedAt?: string;
	runtime?: HermesCliProbeReport["runtime"];
	relayProof?: HermesCliProbeReport["relayProof"];
}> {
	const dockerBin = options.dockerBin?.trim() || process.env.DOCKER_BIN?.trim() || "docker";
	const runtime = collectDockerExecRuntimeEvidence(
		dockerBin,
		options.containerName,
		options.timeoutMs,
	);
	const authSetup = prepareDockerExecHermesAuthStore(
		dockerBin,
		options.containerName,
		invocation,
		runtime.evidence,
		options.timeoutMs,
	);
	if (authSetup.stderr) {
		return Promise.resolve({
			exitCode: 1,
			stdout: "",
			stderr: [runtime.stderr, authSetup.stderr].filter(Boolean).join("\n"),
			...(authSetup.observedAt
				? { startedAt: authSetup.observedAt, endedAt: authSetup.observedAt }
				: {}),
			...(runtime.evidence ? { runtime: runtime.evidence } : {}),
		});
	}
	const args = ["exec", "-i", "-w", invocation.cwd];
	for (const [key, value] of Object.entries(invocation.env).sort(([left], [right]) =>
		left.localeCompare(right),
	)) {
		args.push("-e", `${key}=${value}`);
	}
	args.push(options.containerName, invocation.command, ...invocation.args);
	const childStartedAt = new Date().toISOString();
	const result = spawnSync(dockerBin, args, {
		encoding: "utf8",
		env: { PATH: process.env.PATH ?? "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin" },
		timeout: options.timeoutMs,
	});
	const childEndedAt = new Date().toISOString();
	const relayProof = collectDockerExecRelayProof(
		dockerBin,
		options.containerName,
		invocation,
		options.timeoutMs,
	);
	return Promise.resolve({
		exitCode: result.status ?? (result.signal ? 124 : 1),
		stdout: result.stdout ?? "",
		stderr: [
			runtime.stderr,
			authSetup.stderr,
			result.stderr ?? "",
			result.error ? `failed to launch docker exec Hermes probe: ${result.error.message}` : "",
			relayProof.stderr,
		]
			.filter(Boolean)
			.join("\n"),
		startedAt: childStartedAt,
		endedAt: childEndedAt,
		...(runtime.evidence ? { runtime: runtime.evidence } : {}),
		...(relayProof.evidence ? { relayProof: relayProof.evidence } : {}),
	});
}

function prepareDockerExecHermesAuthStore(
	dockerBin: string,
	containerName: string,
	invocation: HermesLaunchInvocation,
	runtime: HermesCliProbeReport["runtime"] | undefined,
	timeoutMs: number | undefined,
): { stderr: string; observedAt?: string } {
	const relayToken = invocation.authSetup?.openAiCodexRelayToken?.trim();
	if (!relayToken) return { stderr: "" };
	const hermesHome = invocation.env.HERMES_HOME?.trim();
	if (!hermesHome) return { stderr: "HERMES_HOME is required for docker exec auth setup" };
	const relayBaseUrl = invocation.env[HERMES_CODEX_BASE_URL_ENV]?.trim();
	if (!relayBaseUrl)
		return { stderr: "HERMES_CODEX_BASE_URL is required for docker exec auth setup" };
	const model = invocation.env[HERMES_INFERENCE_MODEL_ENV]?.trim();
	if (!model) return { stderr: "HERMES_INFERENCE_MODEL is required for docker exec auth setup" };
	const peerAddress = runtime?.observedPeerAddress?.trim();
	if (!peerAddress) {
		return { stderr: "runtime observedPeerAddress is required for docker exec auth setup" };
	}
	const peerBoundRelayToken = mintOpenAiCodexPeerBoundProxyToken({
		secret: relayToken,
		peerAddress,
		runId: `hermes-docker-exec-${crypto.randomUUID()}`,
		tokenScope: "run",
		ttlMs: OPENAI_CODEX_CONTAINED_RELAY_TOKEN_TTL_MS,
	});
	const payload = buildHermesOpenAiCodexRelayAuthStorePayload(peerBoundRelayToken, relayBaseUrl);
	const script = [
		"import json, os, sys",
		"home = sys.argv[1]",
		"model = sys.argv[2]",
		"payload = json.load(sys.stdin)",
		"runtime_uid = int(os.environ.get('TELCLAUDE_HERMES_RUNTIME_UID', '10000'))",
		"runtime_gid = int(os.environ.get('TELCLAUDE_HERMES_RUNTIME_GID', '10000'))",
		"os.makedirs(home, mode=0o700, exist_ok=True)",
		"os.chown(home, 0, runtime_gid)",
		"os.chmod(home, 0o1770)",
		"config_path = os.path.join(home, 'config.yaml')",
		"config_tmp_path = f'{config_path}.tmp'",
		"with open(config_tmp_path, 'w', encoding='utf-8') as handle:",
		"    handle.write('model:\\n')",
		"    handle.write('  provider: openai-codex\\n')",
		"    handle.write(f'  default: {model}\\n')",
		"    handle.write('  api_mode: codex_responses\\n')",
		"    handle.write('  openai_runtime: auto\\n')",
		"os.chown(config_tmp_path, 0, runtime_gid)",
		"os.chmod(config_tmp_path, 0o440)",
		"os.replace(config_tmp_path, config_path)",
		"os.chown(config_path, 0, runtime_gid)",
		"os.chmod(config_path, 0o440)",
		"path = os.path.join(home, 'auth.json')",
		"tmp_path = f'{path}.tmp'",
		"with open(tmp_path, 'w', encoding='utf-8') as handle:",
		"    json.dump(payload, handle, indent=2, sort_keys=True)",
		"    handle.write('\\n')",
		"os.chown(tmp_path, 0, runtime_gid)",
		"os.chmod(tmp_path, 0o440)",
		"os.replace(tmp_path, path)",
		"os.chown(path, 0, runtime_gid)",
		"os.chmod(path, 0o440)",
		"manifest_path = os.path.join(home, 'secret-manifest.json')",
		"manifest_tmp_path = f'{manifest_path}.tmp'",
		"with open(manifest_tmp_path, 'w', encoding='utf-8') as handle:",
		"    json.dump({'schemaVersion': 1, 'rawCredentialPolicy': 'relay-owned-only', 'relayTokenBinding': 'run-peer-bound'}, handle, indent=2, sort_keys=True)",
		"    handle.write('\\n')",
		"os.chown(manifest_tmp_path, 0, runtime_gid)",
		"os.chmod(manifest_tmp_path, 0o440)",
		"os.replace(manifest_tmp_path, manifest_path)",
		"os.chown(manifest_path, 0, runtime_gid)",
		"os.chmod(manifest_path, 0o440)",
	].join("\n");
	const result = spawnSync(
		dockerBin,
		["exec", "-i", containerName, "python", "-c", script, hermesHome, model],
		{
			encoding: "utf8",
			env: { PATH: process.env.PATH ?? "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin" },
			input: `${JSON.stringify(payload)}\n`,
			timeout: timeoutMs,
		},
	);
	if (result.status === 0) return { stderr: "" };
	const rawStderr = result.stderr || result.error?.message || "unknown error";
	return {
		stderr: `failed to prepare docker exec Hermes auth store: ${redactDockerExecAuthHelperOutput(
			rawStderr,
			relayToken,
			payload,
		)}`,
		observedAt: new Date().toISOString(),
	};
}

function redactDockerExecAuthHelperOutput(
	value: string,
	relayToken: string,
	payload: Record<string, unknown>,
): string {
	let redacted = value;
	const replacements = [
		relayToken,
		JSON.stringify(payload),
		JSON.stringify(payload, null, 2),
		...collectJsonStringValues(payload),
	].filter((item) => item.length > 0);
	for (const item of replacements) {
		redacted = redacted.split(item).join("[REDACTED]");
	}
	return redacted;
}

function collectJsonStringValues(value: unknown): string[] {
	if (typeof value === "string") return [value];
	if (Array.isArray(value)) return value.flatMap((item) => collectJsonStringValues(item));
	if (value && typeof value === "object") {
		return Object.values(value).flatMap((item) => collectJsonStringValues(item));
	}
	return [];
}

function collectDockerExecRelayProof(
	dockerBin: string,
	containerName: string,
	invocation: HermesLaunchInvocation,
	timeoutMs: number | undefined,
): { evidence?: HermesCliProbeReport["relayProof"]; stderr: string } {
	const hermesHome = invocation.env.HERMES_HOME?.trim();
	if (!hermesHome) return { stderr: "HERMES_HOME is required for docker exec relay proof" };
	const script = [
		"import json, os, sys, urllib.request",
		"home = sys.argv[1]",
		"auth_path = os.path.join(home, 'auth.json')",
		"with open(auth_path, encoding='utf-8') as handle:",
		"    auth = json.load(handle)",
		"token = auth.get('providers', {}).get('openai-codex', {}).get('tokens', {}).get('access_token', '')",
		"if not token:",
		"    raise RuntimeError('relay token missing from Hermes auth store')",
		`request = urllib.request.Request(${JSON.stringify(
			OPENAI_CODEX_PROXY_PROOF_LATEST_URL,
		)}, headers={'Authorization': f'Bearer {token}'}, method='GET')`,
		"with urllib.request.urlopen(request, timeout=10) as response:",
		"    proof = json.loads(response.read().decode('utf-8'))",
		"print(json.dumps(proof, sort_keys=True))",
	].join("\n");
	const result = spawnSync(dockerBin, ["exec", containerName, "python", "-c", script, hermesHome], {
		encoding: "utf8",
		env: { PATH: process.env.PATH ?? "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin" },
		timeout: timeoutMs,
	});
	if (result.status !== 0) {
		return {
			stderr: `failed to collect docker exec Hermes relay proof: ${
				result.stderr || result.error?.message || "unknown error"
			}`,
		};
	}
	try {
		return { evidence: parseHermesRelayProofEvidence(JSON.parse(result.stdout)), stderr: "" };
	} catch (error) {
		return {
			stderr: `failed to parse docker exec Hermes relay proof: ${
				error instanceof Error ? error.message : String(error)
			}`,
		};
	}
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

function collectHermesFeatureProbeEvidence(
	featureProbeMatrix: unknown,
	options: HermesSignedEvidenceValidationOptions = {},
) {
	const collected = collectFeatureProbeEvidence(featureProbeMatrix, options) ?? {
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

function buildHermesFeatureProbeMatrixDraft(input: { pin?: HermesPin | null }): FeatureProbeMatrix {
	const initial: FeatureProbeMatrix = {
		schemaVersion: 1,
		probes: allHermesFeatureProbeDefinitions().map((definition) => ({
			...definition,
			hermes_pin: input.pin ?? DEFAULT_HERMES_FEATURE_PROBE_PIN,
			status: "fail",
		})),
	};
	const evidenceBySurface = new Map(
		collectHermesFeatureProbeEvidence(
			initial,
			archivedHermesEvidenceValidationOptions(),
		).results.map((result) => [result.surface_id, result.status]),
	);
	return {
		...initial,
		probes: initial.probes.map((probe) => ({
			...probe,
			status: evidenceBySurface.get(probe.surface_id) === "pass" ? "pass" : "fail",
		})),
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
		.command("probes")
		.description("Generate the canonical Hermes feature-probe matrix from observed evidence")
		.option("--json", "Emit structured JSON")
		.option("--pin <pin>", "Pinned Hermes artifact for matrix entries")
		.option("--lockfile <path>", "Compatibility lockfile JSON path", DEFAULT_COMPAT_LOCKFILE_PATH)
		.option("--out <path>", "Write feature-probe matrix JSON to this path")
		.option("--write-tracked-seed", WRITE_TRACKED_SEED_OPTION_DESCRIPTION)
		.action((options: FeatureProbeMatrixOption) => {
			try {
				const matrix = buildHermesFeatureProbeMatrixDraft({
					pin: resolvePin(options) ?? DEFAULT_HERMES_FEATURE_PROBE_PIN,
				});
				if (options.out) {
					writeJsonArtifact(
						resolveHermesArtifactPath(options.out),
						matrix,
						trackedSeedWriteOptions(options),
					);
				}
				if (options.json || !options.out) {
					printJson(matrix);
				} else {
					const passCount = matrix.probes.filter((probe) => probe.status === "pass").length;
					console.log(`Hermes probes: ${passCount}/${matrix.probes.length} pass`);
					console.log(`- evidence: ${options.out}`);
				}
				process.exitCode = matrix.probes.every((probe) => probe.status === "pass") ? 0 : 1;
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
		.command("generate")
		.description("Generate Hermes wrapper profile artifacts")
		.option("--dry-run", "Preview generated artifacts without writing files")
		.option("--write", "Write generated profile artifacts and proof")
		.option("--red-seed", "Write a fail-closed profile-generation proof seed")
		.option("--json", "Emit structured JSON")
		.option("--pin <pin>", "Pinned Hermes version, commit, package, or image digest")
		.option("--out <dir>", "Output directory for generated Hermes profiles", "/tmp/tc-hermes")
		.option("--lockfile <path>", "Compatibility lockfile JSON path", DEFAULT_COMPAT_LOCKFILE_PATH)
		.option(
			"--proof-out <path>",
			"Profile generation proof JSON path",
			DEFAULT_PROFILE_GENERATION_PROOF_PATH,
		)
		.option("--write-tracked-seed", WRITE_TRACKED_SEED_OPTION_DESCRIPTION)
		.action(
			(
				options: JsonOption &
					PinOption & {
						out: string;
						dryRun?: boolean;
						write?: boolean;
						redSeed?: boolean;
						lockfile: string;
						proofOut: string;
					} & TrackedSeedWriteOption,
			) => {
				try {
					const selectedModes = [options.dryRun, options.write, options.redSeed].filter(
						Boolean,
					).length;
					if (selectedModes > 1) {
						throw new Error("Use only one of --dry-run, --write, or --red-seed.");
					}
					if (options.redSeed) {
						const report = buildHermesProfileGenerationRedSeed({
							pin: resolvePin(options) ?? DEFAULT_HERMES_FEATURE_PROBE_PIN,
							evidencePath: options.proofOut,
							lockfile: readOptionalJsonFile(resolveHermesArtifactPath(options.lockfile)),
							outDir: options.out,
						});
						writeJsonArtifact(
							resolveHermesArtifactPath(options.proofOut),
							report,
							trackedSeedWriteOptions(options),
						);
						if (options.json) {
							printJson(report);
						} else {
							console.log(`Hermes generate red-seed: ${report.status}`);
							console.log(`- proof ${report.evidence_path}`);
						}
						process.exitCode = 1;
						return;
					}
					if (options.write) {
						const report = writeHermesProfileGenerationProof({
							pin: resolvePin(options),
							outDir: options.out,
							lockfile: readJsonFile(resolveHermesArtifactPath(options.lockfile)),
							evidencePath: options.proofOut,
							allowTrackedSeedWrite: options.writeTrackedSeed === true,
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
		.option(
			"--include-provider-domain",
			"Generate provider-domain fixture evidence from provider-domain probe artifacts",
		)
		.option(
			"--only-provider-domain",
			"Refresh only provider-domain fixture evidence and preserve existing fixture results",
		)
		.option(
			"--include-browser-computer",
			"Generate browser/computer broker fixture evidence from broker probe artifacts",
		)
		.option(
			"--include-edge-adapter",
			"Generate public/household edge fixture evidence from edge probe artifacts",
		)
		.option(
			"--include-workflow",
			"Generate workflow fixture evidence from workflow probe artifacts",
		)
		.option(
			"--skip-private-telegram",
			"Do not rerun private Telegram fixtures; use with --merge-existing for targeted refreshes",
		)
		.option("--merge-existing", "Merge generated fixture evidence into the existing output bundle")
		.option("--observed-at <iso>", "Observed timestamp for generated evidence")
		.option("--write-tracked-seed", WRITE_TRACKED_SEED_OPTION_DESCRIPTION)
		.action((options: FixtureResultOption) => {
			try {
				const observedAt = options.observedAt ?? new Date().toISOString();
				const includeProviderDomain =
					options.includeProviderDomain === true || options.onlyProviderDomain === true;
				const skipPrivateTelegram =
					options.skipPrivateTelegram === true || options.onlyProviderDomain === true;
				if (skipPrivateTelegram && options.testReport) {
					throw new Error("Use either --skip-private-telegram or --test-report, not both.");
				}
				if (skipPrivateTelegram && options.write === true && options.mergeExisting !== true) {
					throw new Error("--skip-private-telegram writes require --merge-existing.");
				}
				const resolvedOutPath = resolveHermesArtifactPath(options.out);
				if (skipPrivateTelegram && options.write === true && !fs.existsSync(resolvedOutPath)) {
					throw new Error(
						"--skip-private-telegram writes require an existing --out fixture results bundle.",
					);
				}
				const bundle = skipPrivateTelegram
					? undefined
					: (() => {
							assertPrivateTelegramFixtureWritePreconditions(options);
							const invocation = options.testReport
								? undefined
								: runPrivateTelegramFixtureVitest(options.reportOut);
							return buildPrivateTelegramFixtureResultBundle({
								testReportPath: options.testReport ?? options.reportOut,
								evidenceDir: options.evidenceDir,
								observedAt,
								invocation,
							});
						})();
				const providerDomainBundle =
					includeProviderDomain === true
						? buildProviderDomainFixtureEvidenceBundle({
								evidenceDir: options.evidenceDir,
								observedAt,
							})
						: undefined;
				const googleProviderBundle =
					includeProviderDomain === true
						? buildGoogleProviderFixtureEvidenceBundle({
								evidenceDir: options.evidenceDir,
								observedAt,
							})
						: undefined;
				const workflowBundle =
					options.includeWorkflow === true
						? buildHermesWorkflowFixtureEvidenceBundle({
								evidenceDir: options.evidenceDir,
								observedAt,
							})
						: undefined;
				const browserComputerBundle =
					options.includeBrowserComputer === true
						? buildBrowserComputerBrokerFixtureEvidenceBundle({
								evidenceDir: options.evidenceDir,
								observedAt,
							})
						: undefined;
				const edgeAdapterBundle =
					options.includeEdgeAdapter === true
						? buildEdgeAdapterFixtureEvidenceBundle({
								evidenceDir: options.evidenceDir,
								observedAt,
							})
						: undefined;
				const existingResults =
					options.mergeExisting === true && fs.existsSync(resolvedOutPath)
						? ((
								readJsonFile(resolvedOutPath) as {
									results?: Array<{ id: string; status: "pass" | "fail"; evidence_path: string }>;
								}
							).results ?? [])
						: [];
				const generatedResults = [
					...(bundle?.results ?? []),
					...(providerDomainBundle?.results ?? []),
					...(googleProviderBundle?.results ?? []),
					...(workflowBundle?.results ?? []),
					...(browserComputerBundle?.results ?? []),
					...(edgeAdapterBundle?.results ?? []),
				] as Array<{
					id: string;
					status: "pass" | "fail";
					evidence_path: string;
				}>;
				const results =
					options.mergeExisting === true
						? mergeFixtureResults(existingResults, generatedResults)
						: generatedResults;
				const evidence = [
					...(bundle?.evidence ?? []),
					...(providerDomainBundle?.evidence ?? []),
					...(googleProviderBundle?.evidence ?? []),
					...(workflowBundle?.evidence ?? []),
					...(browserComputerBundle?.evidence ?? []),
					...(edgeAdapterBundle?.evidence ?? []),
				];
				if (options.write) {
					for (const evidenceItem of evidence) {
						const evidencePath =
							typeof evidenceItem === "object" &&
							evidenceItem !== null &&
							"evidence_path" in evidenceItem &&
							typeof evidenceItem.evidence_path === "string"
								? evidenceItem.evidence_path
								: undefined;
						if (!evidencePath) throw new Error("fixture evidence is missing evidence_path");
						writeJsonArtifact(evidencePath, evidenceItem, trackedSeedWriteOptions(options));
					}
					writeJsonArtifact(
						options.out,
						{
							schemaVersion: bundle?.schemaVersion ?? 1,
							results,
						},
						trackedSeedWriteOptions(options),
					);
				}
				const report = {
					schemaVersion: 1,
					status: results.every((result) => result.status === "pass") ? "pass" : "fail",
					written: options.write === true,
					out: options.out,
					results,
				};
				if (options.json) {
					printJson(report);
				} else {
					console.log(`Hermes fixtures: ${report.status}`);
					for (const result of report.results) {
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
		.option("--write-tracked-seed", WRITE_TRACKED_SEED_OPTION_DESCRIPTION)
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
				} & TrackedSeedWriteOption,
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
				const noForkProofInput = {
					checkoutPath: options.checkout,
					expectedRef: options.expectedRef,
					expectedVersion: options.expectedVersion,
					evidencePath: options.out,
				};
				let report = buildNoForkProof(noForkProofInput);
				if (options.p0) {
					const strict = true;
					const dryRun = true;
					const relaySigningFailure = operatorRelaySigningEnvFailure();
					if (relaySigningFailure) {
						const cutover = {
							status: "input_error",
							exitCode: 2,
							mode: { strict, dryRun },
							gates: [
								{
									name: "inputs.operatorRelaySigning",
									status: "fail",
									detail: relaySigningFailure,
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
					const startedAt = new Date().toISOString();
					const preliminaryNoForkPath = path.join(
						os.tmpdir(),
						`telclaude-hermes-nofork-${process.pid}-${Date.now()}.json`,
					);
					try {
						writeNoForkProofReport(
							buildNoForkProof({ ...noForkProofInput, evidencePath: preliminaryNoForkPath }),
						);
						const featureProbeMatrix = readJsonFile(
							resolveHermesArtifactPath(options.featureProbes),
						);
						const profileGenerationProof = readOptionalJsonFile(
							resolveHermesArtifactPath(options.profileProof),
						);
						const proofTemplate = CutoverProofBundleSchema.parse(
							readJsonFile(resolveHermesArtifactPath(options.proofBundle)),
						);
						const evaluateP0Cutover = (noForkPath: string) => {
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
										artifactPath: noForkPath,
									},
									networkProbeBundle: proofTemplate.artifacts.networkProbeBundle,
									queueSnapshot: proofTemplate.artifacts.queueSnapshot,
									rollbackEvidence: proofTemplate.artifacts.rollbackEvidence,
								},
							});
							return evaluateCutoverCheck(
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
									noForkProof: readJsonFile(resolveHermesArtifactPath(noForkPath)),
									profileGenerationProof,
									networkProbes: readJsonFile(resolveHermesArtifactPath(options.networkProbes)),
									rollbackRehearsal: readJsonFile(resolveHermesArtifactPath(options.rollback)),
								}),
								{ strict, dryRun, liveCutover: false },
							);
						};
						const preliminaryCutover = evaluateP0Cutover(preliminaryNoForkPath);
						const p0Status = deriveNoForkP0Status(preliminaryCutover);
						const endedAt = new Date().toISOString();
						const p0Command = buildNoForkP0Command(options);
						const transcript = {
							command: p0Command,
							startedAt,
							endedAt,
							preliminaryCutover: {
								status: preliminaryCutover.status,
								exitCode: preliminaryCutover.exitCode,
								gates: preliminaryCutover.gates,
							},
							derivedP0Status: p0Status,
						};
						const sourceReplacementDenied =
							profileProofDeniesSourceReplacement(profileGenerationProof);
						const wrapperRun: NoForkWrapperRunEvidence = {
							startedAt,
							endedAt,
							wrapperPackageSha256: buildNoForkWrapperPackageDigest(),
							profileGenerationSha256: noForkFileSha256(
								resolveHermesArtifactPath(options.profileProof),
							),
							fixtureResultsSha256: noForkFileSha256(resolveHermesArtifactPath(options.fixtures)),
							transcriptSha256: noForkSha256Digest(JSON.stringify(transcript)),
							p0Command,
							p0ExitCode: p0Status === "pass" ? 0 : preliminaryCutover.exitCode || 1,
							p0Status,
							runtimeSourceReplacementDenied: sourceReplacementDenied,
							monkeypatchDenied: sourceReplacementDenied,
						};
						report = writeNoForkProofReport(
							buildNoForkProof({
								checkoutPath: options.checkout,
								expectedRef: options.expectedRef,
								expectedVersion: options.expectedVersion,
								evidencePath: options.out,
								wrapperRun,
							}),
							trackedSeedWriteOptions(options),
						);
						const cutover = evaluateP0Cutover(options.out);
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
					} finally {
						fs.rmSync(preliminaryNoForkPath, { force: true });
					}
				}
				report = writeNoForkProofReport(report, trackedSeedWriteOptions(options));
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
		.option("--write-tracked-seed", WRITE_TRACKED_SEED_OPTION_DESCRIPTION)
		.action((options: InventoryOption) => {
			const inventory = collectHermesInventory();
			if (options.out) {
				writeJsonArtifact(
					resolveHermesArtifactPath(options.out),
					inventory,
					trackedSeedWriteOptions(options),
				);
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
		.option("--write-tracked-seed", WRITE_TRACKED_SEED_OPTION_DESCRIPTION)
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
						report = readHermesCliHeadlessProbeReport(
							fromReport,
							archivedHermesEvidenceValidationOptions(),
						);
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
					writeJsonArtifact(outPath, report, trackedSeedWriteOptions(options));
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
						writeHermesApiServerContainmentEvidence(
							report,
							outPath,
							trackedSeedWriteOptions(options),
						);
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
						writeServedMcpContainmentEvidence(report, outPath, trackedSeedWriteOptions(options));
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
					writeJsonArtifact(outPath, report, trackedSeedWriteOptions(options));
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
						writeHermesModelRelayEvidence(report, outPath, trackedSeedWriteOptions(options));
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
								DEFAULT_MODEL_RELAY_PROFILE_DIR,
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
							writeHermesModelRelayEvidence(report, outPath, trackedSeedWriteOptions(options));
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
				if (options.allowRun === true) {
					const relaySigningFailure = operatorRelaySigningEnvFailure();
					if (relaySigningFailure) {
						failHermesProbeInput(surface, options, relaySigningFailure);
						return;
					}
				}
				const report = await buildEdgeAdapterProbeEvidence({
					surfaceId: surface,
					allowRun: options.allowRun === true,
				});
				let outPath: string | undefined;
				if (options.allowRun === true || options.out) {
					outPath = resolveHermesArtifactPath(
						options.out ?? `artifacts/hermes/probes/${surface}.json`,
					);
					writeJsonArtifact(outPath, report, trackedSeedWriteOptions(options));
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
				if (options.allowRun === true) {
					const relaySigningFailure = operatorRelaySigningEnvFailure();
					if (relaySigningFailure) {
						failHermesProbeInput(surface, options, relaySigningFailure);
						return;
					}
				}
				const report = await runTelclaudeMcpSideEffectLedgerProbe({
					allowRun: options.allowRun === true,
				});
				let outPath: string | undefined;
				if (options.allowRun === true || options.out) {
					outPath = resolveHermesArtifactPath(
						options.out ?? DEFAULT_SIDE_EFFECT_LEDGER_EVIDENCE_PATH,
					);
					writeJsonArtifact(outPath, report, trackedSeedWriteOptions(options));
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
				if (options.allowRun === true) {
					const relaySigningFailure = operatorRelaySigningEnvFailure();
					if (relaySigningFailure) {
						failHermesProbeInput(surface, options, relaySigningFailure);
						return;
					}
				}
				const report = await runTelclaudeProviderApprovalBindingProbe({
					allowRun: options.allowRun === true,
				});
				let outPath: string | undefined;
				if (options.allowRun === true || options.out) {
					outPath = resolveHermesArtifactPath(
						options.out ?? DEFAULT_PROVIDER_APPROVAL_BINDING_EVIDENCE_PATH,
					);
					writeJsonArtifact(outPath, report, trackedSeedWriteOptions(options));
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

			if (isProviderDomainSurfaceId(surface)) {
				const report = await runTelclaudeProviderDomainProbe({
					surfaceId: surface,
					allowRun: options.allowRun === true,
				});
				let outPath: string | undefined;
				if (options.allowRun === true || options.out) {
					outPath = resolveHermesArtifactPath(
						options.out ?? DEFAULT_PROVIDER_DOMAIN_EVIDENCE_PATHS[surface],
					);
					writeJsonArtifact(outPath, report, trackedSeedWriteOptions(options));
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

			if (surface === "providers.release-policy") {
				const report = runTelclaudeProviderReleasePolicyProbe({
					allowRun: options.allowRun === true,
				});
				let outPath: string | undefined;
				if (options.allowRun === true || options.out) {
					outPath = resolveHermesArtifactPath(
						options.out ?? DEFAULT_PROVIDER_RELEASE_POLICY_EVIDENCE_PATH,
					);
					writeJsonArtifact(outPath, report, trackedSeedWriteOptions(options));
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

			if (surface === "providers.google") {
				const report = await runTelclaudeGoogleProviderProbe({
					allowRun: options.allowRun === true,
				});
				let outPath: string | undefined;
				if (options.allowRun === true || options.out) {
					outPath = resolveHermesArtifactPath(options.out ?? DEFAULT_PROVIDER_GOOGLE_EVIDENCE_PATH);
					writeJsonArtifact(outPath, report, trackedSeedWriteOptions(options));
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

			if (isBrowserComputerBrokerSurfaceId(surface)) {
				let report: ReturnType<typeof runTelclaudeBrowserComputerBrokerProbe>;
				try {
					if (options.fromReport?.trim()) {
						if (options.allowRun === true) {
							throw new Error("Use either --from-report or --allow-run, not both.");
						}
						if (surface !== "network.egress-broker") {
							throw new Error("--from-report is supported only for network.egress-broker");
						}
						report = buildNetworkEgressBrokerProbeEvidenceFromReport(
							readNetworkEgressBrokerRunReport(resolveHermesArtifactPath(options.fromReport)),
						);
					} else {
						report = runTelclaudeBrowserComputerBrokerProbe({
							surfaceId: surface,
							allowRun: options.allowRun === true,
						});
					}
				} catch (error) {
					report = {
						schemaVersion: "telclaude.hermes.browser-computer-broker-probe.v1",
						probeId: surface,
						status: "fail",
						ran: false,
						observedAt: new Date().toISOString(),
						source: "telclaude-browser-computer-broker-harness",
						summary: error instanceof Error ? error.message : String(error),
						checks: [
							{
								name: `${surface}.exception`,
								status: "fail",
								detail: error instanceof Error ? error.message : String(error),
							},
						],
						observations: {
							auditEntryCount: 0,
							deniedAttemptCount: 0,
							quarantineRefCount: 0,
							directEgressDenialCount: 0,
						},
					};
				}
				let outPath: string | undefined;
				if (options.allowRun === true || options.fromReport?.trim() || options.out) {
					outPath = resolveHermesArtifactPath(
						options.out ?? DEFAULT_BROWSER_COMPUTER_BROKER_EVIDENCE_PATHS[surface],
					);
					writeJsonArtifact(outPath, report, trackedSeedWriteOptions(options));
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

			if (isHermesWorkflowSurfaceId(surface)) {
				if (options.allowRun === true) {
					const relaySigningFailure = operatorRelaySigningEnvFailure();
					if (relaySigningFailure) {
						failHermesProbeInput(surface, options, relaySigningFailure);
						return;
					}
				}
				const report = runHermesWorkflowProbe({
					surfaceId: surface,
					allowRun: options.allowRun === true,
				});
				let outPath: string | undefined;
				if (options.allowRun === true || options.out) {
					outPath = resolveHermesArtifactPath(
						options.out ?? DEFAULT_HERMES_WORKFLOW_EVIDENCE_PATHS[surface],
					);
					writeJsonArtifact(outPath, report, trackedSeedWriteOptions(options));
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
						allowTrackedSeedWrite: options.writeTrackedSeed === true,
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
			"--defer-attestation",
			"Run probes without relay signing and emit/write a machine-observed run report for later promotion",
		)
		.option(
			"--from-report <path>",
			"Promote a machine-observed network-probe run report into canonical cutover artifacts",
		)
		.option(
			"--run-report-out <path>",
			"Machine-observed network-probe run report path for --defer-attestation",
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
		.option("--write-tracked-seed", WRITE_TRACKED_SEED_OPTION_DESCRIPTION)
		.action(async (options: NetworkProbeOption) => {
			try {
				let report: Awaited<ReturnType<typeof runHermesNetworkProbes>>;
				if (options.fromReport?.trim()) {
					if (options.allowRun === true) {
						throw new Error("Use either --from-report or --allow-run, not both.");
					}
					if (importedNetworkProbeReportRequiresSigning(options.fromReport)) {
						assertOperatorRelaySigningEnv();
					}
					report = writeHermesNetworkProbeArtifacts(
						readHermesNetworkProbeRunReport(options.fromReport, { requireAttestation: false }),
						{
							outPath: options.out,
							evidenceDir: options.evidenceDir,
							allowTrackedSeedWrite: options.writeTrackedSeed === true,
						},
					);
				} else {
					if (options.allowRun === true && options.deferAttestation !== true) {
						assertOperatorRelaySigningEnv();
					}
					report = await runHermesNetworkProbes({
						allowRun: options.allowRun === true,
						signEvidence: options.deferAttestation === true ? false : undefined,
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

				if (options.deferAttestation === true) {
					if (options.fromReport?.trim()) {
						throw new Error("Use either --from-report or --defer-attestation, not both.");
					}
					if (options.runReportOut?.trim()) {
						writeJsonArtifact(options.runReportOut, report, trackedSeedWriteOptions(options));
						report = {
							...report,
							bundlePath: options.runReportOut,
						};
					}
				} else if (options.allowRun === true) {
					report = writeHermesNetworkProbeArtifacts(report, {
						outPath: options.out,
						evidenceDir: options.evidenceDir,
						allowTrackedSeedWrite: options.writeTrackedSeed === true,
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
		.option("--write-tracked-seed", WRITE_TRACKED_SEED_OPTION_DESCRIPTION)
		.action(async (options: RollbackRehearsalOption) => {
			try {
				if (options.allowRun === true) {
					const relayVerificationFailure = operatorRelayVerificationEnvFailure();
					if (relayVerificationFailure) throw new Error(relayVerificationFailure);
				}
				const outPath = resolveHermesArtifactPath(options.out);
				const evidencePath = options.evidencePath?.trim() || options.out;
				const report = await runHermesRollbackRehearsal({
					allowRun: options.allowRun === true,
					evidencePath,
				});
				const written = writeHermesRollbackRehearsalEvidence(
					report,
					outPath,
					trackedSeedWriteOptions(options),
				);
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
		.command("pro-review-refresh")
		.description("Refresh the ChatGPT Pro native-extension request payload binding")
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
		.option("--prompt <text>", "Prompt text for a new request when no request exists")
		.option("--selected-file <path>", "Additional selected file path", collectOption, [])
		.option("--replace-selected-files", "Use only required files plus --selected-file entries")
		.option(
			"--shard-max-source-bytes <bytes>",
			"Build a root-bound sharded native Pro review plan with this max source-byte budget",
		)
		.option("--write", "Write the refreshed request JSON")
		.option("--write-tracked-seed", WRITE_TRACKED_SEED_OPTION_DESCRIPTION)
		.action((options: ProReviewRefreshOption) => {
			try {
				const shardMaxSourceBytes = parseProReviewShardMaxSourceBytes(options.shardMaxSourceBytes);
				const request = buildProReviewRequestDraft({
					existingRequestPath: options.request,
					canaryPath: options.canary,
					prompt: options.prompt,
					selectedFiles: options.selectedFile ?? [],
					includeExistingSelectedFiles: options.replaceSelectedFiles !== true,
					shardMaxSourceBytes,
				});
				assertProReviewTrackedSeedSelectedFilesClean(request.selectedFiles, options);
				const result = {
					status: "pass",
					requestPath: options.request,
					written: options.write === true,
					payloadSha256: request.payloadBinding.payloadSha256,
					selectedFileContentsSha256: request.payloadBinding.selectedFileContentsSha256,
					transportEvidenceSha256: request.payloadBinding.transportEvidenceSha256,
					reviewMode: request.reviewMode ?? "single",
					shardCount: request.shardPlan?.shards.length ?? 0,
					approval: request.privateWorkspaceDisclosure,
					selectedFiles: request.selectedFiles,
					request,
				};
				if (options.write === true) {
					writeJsonArtifact(options.request, request, trackedSeedWriteOptions(options));
				}
				if (options.json) {
					printJson(result);
				} else {
					console.log("Hermes pro-review-refresh: pass");
					console.log(`- payloadSha256: ${request.payloadBinding.payloadSha256}`);
					console.log(`- selectedFiles: ${request.selectedFiles.length}`);
					console.log(
						`- disclosureApproved: ${String(request.privateWorkspaceDisclosure.approved)}`,
					);
					if (options.write === true) console.log(`- wrote: ${options.request}`);
				}
				process.exitCode = 0;
			} catch (error) {
				const detail = error instanceof Error ? error.message : String(error);
				if (options.json) {
					printJson({ status: "input_error", detail });
				} else {
					console.log("Hermes pro-review-refresh: input_error");
					console.log(`- FAIL: ${detail}`);
				}
				process.exitCode = 1;
			}
		});

	hermes
		.command("pro-review-approve")
		.description("Record exact operator disclosure approval for a ChatGPT Pro review payload")
		.option("--json", "Emit structured JSON")
		.option(
			"--request <path>",
			"ChatGPT Pro review request JSON path",
			DEFAULT_PRO_REVIEW_REQUEST_PATH,
		)
		.requiredOption("--approval-id <id>", "Operator approval identifier or quoted approval text")
		.requiredOption("--operator <name>", "Operator who approved the disclosure")
		.option("--approved-at <iso>", "Approval timestamp; defaults to current time")
		.option("--payload-sha256 <digest>", "Expected payloadSha256 to bind approval to")
		.option("--write", "Write the approved request JSON")
		.option("--write-tracked-seed", WRITE_TRACKED_SEED_OPTION_DESCRIPTION)
		.action((options: ProReviewApproveOption) => {
			try {
				const request = approveProReviewRequest({
					requestPath: options.request,
					approvalId: options.approvalId,
					operator: options.operator,
					approvedAt: options.approvedAt,
					expectedPayloadSha256: options.payloadSha256,
				});
				const result = {
					status: "pass",
					requestPath: options.request,
					written: options.write === true,
					payloadSha256: request.payloadBinding.payloadSha256,
					approval: request.privateWorkspaceDisclosure,
					request,
				};
				if (options.write === true) {
					writeJsonArtifact(options.request, request, trackedSeedWriteOptions(options));
				}
				if (options.json) {
					printJson(result);
				} else {
					console.log("Hermes pro-review-approve: pass");
					console.log(`- payloadSha256: ${request.payloadBinding.payloadSha256}`);
					console.log(`- approvalId: ${String(request.privateWorkspaceDisclosure.approvalId)}`);
					if (options.write === true) console.log(`- wrote: ${options.request}`);
				}
				process.exitCode = 0;
			} catch (error) {
				const detail = error instanceof Error ? error.message : String(error);
				if (options.json) {
					printJson({ status: "input_error", detail });
				} else {
					console.log("Hermes pro-review-approve: input_error");
					console.log(`- FAIL: ${detail}`);
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
		.option("--wait-timeout-ms <ms>", "Yoetz ChatGPT response wait timeout in milliseconds")
		.action(async (options: ProReviewSendOption) => {
			const report = evaluateProReviewCheck({
				requestPath: options.request,
				canaryPath: options.canary,
				requireApproval: true,
			});
			const bundlePath = resolveProReviewBundlePath(options.bundleOut);
			if (report.status !== "pass") {
				const result = {
					report,
					send: {
						status: "refused",
						reason: "pro-review-check did not pass with approval required",
						note: "no Yoetz command is constructed until all approval and native-extension evidence gates pass",
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

			const canary = (() => {
				try {
					return readProReviewNativeCanary(options.canary);
				} catch (error) {
					if (error instanceof Error) return error;
					return new Error(String(error));
				}
			})();
			const canaryError = canary instanceof Error ? canary.message : undefined;
			const nativeCanary = canary instanceof Error ? null : canary;
			if (!nativeCanary) {
				const result = {
					report,
					send: {
						status: "refused",
						reason: "validated native canary is unavailable",
						...(canaryError ? { canaryError } : {}),
					},
				};
				if (options.json) {
					printJson(result);
				} else {
					console.log("Hermes pro-review-send: refused");
					if (canaryError) console.log(`- FAIL nativeCanary.read: ${canaryError}`);
				}
				process.exitCode = 1;
				return;
			}
			let waitTimeoutMs: number | undefined;
			try {
				waitTimeoutMs = parseProReviewWaitTimeoutMs(options.waitTimeoutMs);
			} catch (error) {
				const result = {
					report,
					send: {
						status: "refused",
						reason: error instanceof Error ? error.message : String(error),
					},
				};
				if (options.json) {
					printJson(result);
				} else {
					console.log("Hermes pro-review-send: refused");
					console.log(`- FAIL: ${result.send.reason}`);
				}
				process.exitCode = 1;
				return;
			}
			const request = readProReviewRequest(options.request);
			if ((request.reviewMode ?? "single") === "sharded" && request.shardPlan) {
				const shardPlanSha256 = request.payloadBinding.shardPlanSha256 ?? undefined;
				const shards = request.shardPlan.shards.map((shard) => {
					const shardBundlePath = proReviewShardBundlePath(bundlePath, shard);
					writeProReviewShardBundle(options.request, shardBundlePath, shard);
					const bundleSha256 = fileSha256(shardBundlePath);
					const runId = `${buildProReviewRunId()}_${shard.shardId}`;
					const inspectCommand = buildProReviewInspectCommand(
						nativeCanary.extensionInstanceId,
						runId,
					);
					const yoetzCommand = buildProReviewYoetzCommand({
						canary: nativeCanary,
						bundlePath: shardBundlePath,
						payloadSha256: report.payloadSha256,
						bundleSha256,
						runId,
						waitTimeoutMs,
						shard,
						shardPlanSha256,
					});
					return {
						shardId: shard.shardId,
						index: shard.index,
						count: shard.count,
						focus: shard.focus,
						bundlePath: shardBundlePath,
						payloadSha256: report.payloadSha256,
						shardPlanSha256,
						shardSha256: shard.shardSha256,
						bundleSha256,
						runId,
						inspectCommand,
						yoetzCommand,
						shard,
					};
				});
				if (!options.execute) {
					const readyShards = shards.map(({ shard, ...metadata }) => metadata);
					const result = {
						report,
						send: {
							status: "ready_sharded",
							mode: "sharded",
							payloadSha256: report.payloadSha256,
							shardPlanSha256,
							shardCount: shards.length,
							shards: readyShards,
							note: "not sent; pass --execute to invoke Yoetz native extension for every shard",
						},
					};
					if (options.json) {
						printJson(result);
					} else {
						console.log("Hermes pro-review-send: ready_sharded");
						console.log(`- shards: ${shards.length}`);
					}
					process.exitCode = 0;
					return;
				}

				const executedShards = [];
				for (const shardSend of shards) {
					console.error(
						`Hermes pro-review-send: native shard ${shardSend.shardId} run ${shardSend.runId}; inspect with: YOETZ_AGENT=1 ${shardSend.inspectCommand.join(" ")}`,
					);
					const result = await runProReviewYoetzCommand(
						shardSend.yoetzCommand,
						buildProReviewNativeYoetzEnv(),
					);
					const validation =
						result.status === 0
							? validateProReviewYoetzSendOutput({
									stdout: result.stdout,
									expectedExtensionInstanceId: nativeCanary.extensionInstanceId,
									expectedBundlePath: shardSend.bundlePath,
									expectedPayloadSha256: report.payloadSha256,
									expectedBundleSha256: shardSend.bundleSha256,
									expectedShard: shardSend.shard,
									expectedShardPlanSha256: shardPlanSha256,
								})
							: null;
					const bundleAfterSendSha256 =
						result.status === 0 && validation?.status === "pass"
							? fileSha256(shardSend.bundlePath)
							: null;
					const bundleValidation =
						bundleAfterSendSha256 === null
							? null
							: bundleAfterSendSha256 === shardSend.bundleSha256
								? {
										status: "pass",
										detail: "shard bundle artifact hash still matches the approved pre-send bundle",
									}
								: {
										status: "fail",
										detail: `shard bundle artifact hash changed after send: ${bundleAfterSendSha256}, expected ${shardSend.bundleSha256}`,
									};
					const inspectResult =
						result.status === 0 &&
						validation?.status === "pass" &&
						bundleValidation?.status === "pass"
							? await runProReviewYoetzCommand(
									shardSend.inspectCommand,
									buildProReviewNativeYoetzEnv(),
								)
							: null;
					const inspectValidation =
						inspectResult?.status === 0
							? validateProReviewYoetzInspectOutput({
									stdout: inspectResult.stdout,
									expectedRunId: shardSend.runId,
								})
							: null;
					const shardStatus =
						result.status === 0 &&
						validation?.status === "pass" &&
						bundleValidation?.status === "pass" &&
						inspectResult?.status === 0 &&
						inspectValidation?.status === "pass"
							? "sent"
							: "failed";
					executedShards.push({
						status: shardStatus,
						shardId: shardSend.shardId,
						index: shardSend.index,
						count: shardSend.count,
						focus: shardSend.focus,
						bundlePath: shardSend.bundlePath,
						payloadSha256: shardSend.payloadSha256,
						shardPlanSha256: shardSend.shardPlanSha256,
						shardSha256: shardSend.shardSha256,
						bundleSha256: shardSend.bundleSha256,
						bundleAfterSendSha256,
						runId: shardSend.runId,
						inspectCommand: shardSend.inspectCommand,
						yoetzCommand: shardSend.yoetzCommand,
						exitCode: result.status,
						validation,
						bundleValidation,
						stdout: result.stdout,
						stderr: result.stderr,
						error: result.error,
						inspect: inspectResult
							? {
									exitCode: inspectResult.status,
									validation: inspectValidation,
									stdout: inspectResult.stdout,
									stderr: inspectResult.stderr,
									error: inspectResult.error,
								}
							: null,
					});
					if (shardStatus !== "sent") break;
				}
				const allSent =
					executedShards.length === shards.length &&
					executedShards.every((shard) => shard.status === "sent");
				const send = {
					status: allSent ? "sent_sharded" : "failed",
					mode: "sharded",
					payloadSha256: report.payloadSha256,
					shardPlanSha256,
					shardCount: shards.length,
					shards: executedShards,
				};
				if (options.json) {
					printJson({ report, send });
				} else {
					console.log(`Hermes pro-review-send: ${send.status}`);
				}
				process.exitCode = send.status === "sent_sharded" ? 0 : 1;
				return;
			}
			writeProReviewBundle(options.request, bundlePath);
			const payloadSha256 = report.payloadSha256;
			const bundleSha256 = fileSha256(bundlePath);
			const runId = buildProReviewRunId();
			const inspectCommand = buildProReviewInspectCommand(nativeCanary.extensionInstanceId, runId);
			const yoetzCommand = buildProReviewYoetzCommand({
				canary: nativeCanary,
				bundlePath,
				payloadSha256,
				bundleSha256,
				runId,
				waitTimeoutMs,
			});
			if (!options.execute) {
				const result = {
					report,
					send: {
						status: "ready",
						bundlePath,
						payloadSha256,
						bundleSha256,
						runId,
						inspectCommand,
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

			console.error(
				`Hermes pro-review-send: native run ${runId}; inspect with: YOETZ_AGENT=1 ${inspectCommand.join(" ")}`,
			);
			const result = await runProReviewYoetzCommand(yoetzCommand, buildProReviewNativeYoetzEnv());
			const validation =
				result.status === 0
					? validateProReviewYoetzSendOutput({
							stdout: result.stdout,
							expectedExtensionInstanceId: nativeCanary.extensionInstanceId,
							expectedBundlePath: bundlePath,
							expectedPayloadSha256: payloadSha256,
							expectedBundleSha256: bundleSha256,
						})
					: null;
			const bundleAfterSendSha256 =
				result.status === 0 && validation?.status === "pass" ? fileSha256(bundlePath) : null;
			const bundleValidation =
				bundleAfterSendSha256 === null
					? null
					: bundleAfterSendSha256 === bundleSha256
						? {
								status: "pass",
								detail: "bundle artifact hash still matches the approved pre-send bundle",
							}
						: {
								status: "fail",
								detail: `bundle artifact hash changed after send: ${bundleAfterSendSha256}, expected ${bundleSha256}`,
							};
			const inspectResult =
				result.status === 0 && validation?.status === "pass" && bundleValidation?.status === "pass"
					? await runProReviewYoetzCommand(inspectCommand, buildProReviewNativeYoetzEnv())
					: null;
			const inspectValidation =
				inspectResult?.status === 0
					? validateProReviewYoetzInspectOutput({
							stdout: inspectResult.stdout,
							expectedRunId: runId,
						})
					: null;
			const send = {
				status:
					result.status === 0 &&
					validation?.status === "pass" &&
					bundleValidation?.status === "pass" &&
					inspectResult?.status === 0 &&
					inspectValidation?.status === "pass"
						? "sent"
						: "failed",
				bundlePath,
				payloadSha256,
				bundleSha256,
				bundleAfterSendSha256,
				runId,
				inspectCommand,
				yoetzCommand,
				exitCode: result.status,
				validation,
				bundleValidation,
				stdout: result.stdout,
				stderr: result.stderr,
				error: result.error,
				inspect: inspectResult
					? {
							exitCode: inspectResult.status,
							validation: inspectValidation,
							stdout: inspectResult.stdout,
							stderr: inspectResult.stderr,
							error: inspectResult.error,
						}
					: null,
			};
			if (options.json) {
				printJson({ report, send });
			} else {
				console.log(`Hermes pro-review-send: ${send.status}`);
				if (send.stdout.trim()) console.log(send.stdout.trim());
				if (send.error) console.error(send.error);
				if (send.inspect?.error) console.error(send.inspect.error);
			}
			process.exitCode = send.status === "sent" ? 0 : 1;
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
		.option("--write-tracked-seed", WRITE_TRACKED_SEED_OPTION_DESCRIPTION)
		.action((options: QueueSnapshotOption) => {
			try {
				const inventory = readInventorySnapshot(options.inventory);
				const snapshot = buildHermesQueueSnapshot({ inventory });
				const outPath = options.out ?? DEFAULT_QUEUE_SNAPSHOT_PATH;
				if (options.out) {
					writeJsonArtifact(
						resolveHermesArtifactPath(outPath),
						snapshot,
						trackedSeedWriteOptions(options),
					);
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
		.option("--write-tracked-seed", WRITE_TRACKED_SEED_OPTION_DESCRIPTION)
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
					writeJsonArtifact(
						resolveHermesArtifactPath(options.out),
						proofBundle,
						trackedSeedWriteOptions(options),
					);
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
				const liveCutover = strict && !dryRun;
				const now = new Date();
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
						featureProbeEvidence: collectHermesFeatureProbeEvidence(featureProbeMatrix, {
							allowStaleAttestations: !liveCutover,
							now,
						}),
						fixtureResults: readCutoverFixtureResults(options.fixtures, { dryRun }),
						noForkProof: readJsonFile(resolveHermesArtifactPath(options.nofork)),
						profileGenerationProof: readOptionalJsonFile(
							resolveHermesArtifactPath(options.profileProof),
						),
						networkProbes: readCutoverNetworkProbes(options.networkProbes, { dryRun }),
						queueSnapshot: options.queueSnapshot
							? readJsonFile(resolveHermesArtifactPath(options.queueSnapshot))
							: undefined,
						rollbackRehearsal: readCutoverRollbackRehearsal(options.rollback, { dryRun }),
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
					liveCutover,
					now,
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
		.command("decision-log")
		.description("Generate a fail-closed Hermes cutover decision log draft")
		.option("--json", "Emit structured JSON")
		.option(
			"--inventory <path>",
			`Inventory snapshot JSON path; uses ${DEFAULT_INVENTORY_PATH} when present, otherwise collects live inventory`,
		)
		.option("--out <path>", "Write decision log JSON to this path")
		.option("--write-tracked-seed", WRITE_TRACKED_SEED_OPTION_DESCRIPTION)
		.action((options: DecisionLogOption) => {
			try {
				const decisionLog = buildHermesDecisionLogDraft({
					inventory: readInventorySnapshot(options.inventory),
				});
				if (options.out) {
					writeJsonArtifact(
						resolveHermesArtifactPath(options.out),
						decisionLog,
						trackedSeedWriteOptions(options),
					);
				}
				if (options.json) {
					printJson(decisionLog);
				} else {
					console.log(`Hermes decision-log: ${decisionLog.decisions.length} decision(s)`);
					for (const decision of decisionLog.decisions) {
						console.log(`- ${decision.status.toUpperCase()} ${decision.id}`);
					}
					if (options.out) console.log(`- evidence: ${options.out}`);
				}
				process.exitCode = decisionLog.decisions.every((decision) => decision.status === "accepted")
					? 0
					: 1;
			} catch (error) {
				const report = {
					status: "input_error",
					exitCode: 2,
					gates: [
						{
							name: "decisionLog.inventory",
							status: "fail",
							detail: String(error instanceof Error ? error.message : error),
						},
					],
				};
				if (options.json) {
					printJson(report);
				} else {
					console.log("Hermes decision-log: input_error");
					console.log(`- FAIL decisionLog.inventory: ${report.gates[0].detail}`);
				}
				process.exitCode = 2;
			}
		});

	hermes
		.command("cutover-scope")
		.description("Generate a fail-closed cutover scope skeleton from an inventory snapshot")
		.requiredOption("--inventory <path>", "Inventory snapshot JSON path")
		.option("--json", "Emit structured JSON")
		.option("--out <path>", "Write cutover scope manifest JSON to this path")
		.option("--write-tracked-seed", WRITE_TRACKED_SEED_OPTION_DESCRIPTION)
		.action((options: CutoverScopeOption) => {
			try {
				const manifest = buildCutoverScopeManifestFromInventory(
					readJsonFile(resolveHermesArtifactPath(options.inventory)),
				);
				if (options.out) {
					writeJsonArtifact(
						resolveHermesArtifactPath(options.out),
						manifest,
						trackedSeedWriteOptions(options),
					);
				}
				if (options.json) {
					printJson(manifest);
				} else {
					console.log(`Hermes cutover-scope: ${manifest.workflows.length} workflow(s)`);
					for (const workflow of manifest.workflows) {
						console.log(`- ${workflow.status.toUpperCase()} ${workflow.workflow_id}`);
					}
					if (options.out) console.log(`- evidence: ${options.out}`);
				}
				process.exitCode = 0;
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
		.option(
			"--nofork-proof <path>",
			"No-fork proof evidence path to bind in the compatibility lockfile",
			DEFAULT_NO_FORK_PROOF_PATH,
		)
		.option("--out <path>", "Write compatibility lockfile JSON to this path")
		.option("--write-tracked-seed", WRITE_TRACKED_SEED_OPTION_DESCRIPTION)
		.action(
			(
				options: JsonOption &
					PinOption & {
						featureProbes: string;
						noforkProof: string;
						out?: string;
					} & TrackedSeedWriteOption,
			) => {
				try {
					const lockfile = buildCompatibilityLockfileDraft({
						pin: resolvePin(options),
						featureProbeMatrix: readJsonFile(resolveHermesArtifactPath(options.featureProbes)),
						wrapperPackageVersion: readWrapperPackageVersion(),
						noForkProofEvidencePath: options.noforkProof,
					});
					if (options.out) {
						writeJsonArtifact(
							resolveHermesArtifactPath(options.out),
							lockfile,
							trackedSeedWriteOptions(options),
						);
					}
					if (options.json) {
						printJson(lockfile);
					} else {
						console.log(`Hermes compat-lock dry-run: ${lockfile.featureProbes.length} probe(s)`);
						for (const probe of lockfile.featureProbes) {
							console.log(`- ${probe.status.toUpperCase()} ${probe.surface_id}`);
						}
						if (options.out) console.log(`- evidence: ${options.out}`);
					}
				} catch (error) {
					console.error(`Error: ${String(error instanceof Error ? error.message : error)}`);
					process.exitCode = 1;
				}
			},
		);
}
