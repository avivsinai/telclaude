import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { z } from "zod";
import {
	type InternalResponseProof,
	internalResponseProofVerificationFailure,
} from "../internal-auth.js";
import { redactSecrets } from "../security/output-filter.js";
import {
	browserComputerBrokerFixtureEvidenceFailure,
	browserComputerBrokerProbeEvidenceFailure,
	isBrowserComputerBrokerSurfaceId,
} from "./browser-computer-broker-probes.js";
import {
	edgeAdapterProbeEvidenceFailure,
	isEdgeAdapterFeatureSurfaceId,
} from "./edge-adapter-probes.js";
import { sideEffectLedgerProbeEvidenceFailure } from "./mcp/side-effect-ledger-probe.js";
import { providerApprovalBindingProbeEvidenceFailure } from "./provider-approval-binding-probe.js";
import {
	isProviderDomainSurfaceId,
	providerDomainFixtureEvidenceFailure,
	providerDomainProbeEvidenceFailure,
} from "./provider-domain-probes.js";
import { providerReleasePolicyProbeEvidenceFailure } from "./provider-release-policy-probe.js";
import { evaluateServedMcpContainmentEvidence } from "./served-mcp-containment.js";
import { servedMcpProviderToolsProbeEvidenceFailure } from "./served-mcp-provider-tools-probe.js";
import {
	isHermesWorkflowSurfaceId,
	workflowFixtureEvidenceFailure,
	workflowProbeEvidenceFailure,
} from "./workflow-probes.js";

export const DEFAULT_FEATURE_PROBE_MATRIX_PATH = "docs/hermes/feature-probes.json";
export const DEFAULT_COMPAT_LOCKFILE_PATH = "docs/hermes/hermes-compat.lock.json";
export const DEFAULT_CUTOVER_SCOPE_PATH = "docs/hermes/cutover-scope.json";
export const DEFAULT_DECISION_LOG_PATH = "docs/hermes/decisions.json";
export const DEFAULT_FIXTURE_RESULTS_PATH = "docs/hermes/fixture-results.json";
export const DEFAULT_INVENTORY_PATH = "docs/hermes/inventory.json";
export const DEFAULT_NETWORK_PROBES_PATH = "docs/hermes/network-probes.json";
export const DEFAULT_QUEUE_SNAPSHOT_PATH = "docs/hermes/queue-snapshot.json";
export const DEFAULT_NO_FORK_PROOF_PATH = "docs/hermes/no-fork-proof.json";
export const DEFAULT_CUTOVER_PROOF_BUNDLE_PATH = "docs/hermes/cutover-proof-bundle.json";
export const DEFAULT_PROFILE_GENERATION_PROOF_PATH = "docs/hermes/profile-generation-proof.json";
export const DEFAULT_ROLLBACK_REHEARSAL_PATH = "docs/hermes/rollback-rehearsal.json";
export const HERMES_TRACKED_SEED_PATHS = [
	DEFAULT_FEATURE_PROBE_MATRIX_PATH,
	DEFAULT_COMPAT_LOCKFILE_PATH,
	DEFAULT_CUTOVER_SCOPE_PATH,
	DEFAULT_DECISION_LOG_PATH,
	DEFAULT_FIXTURE_RESULTS_PATH,
	DEFAULT_INVENTORY_PATH,
	DEFAULT_NETWORK_PROBES_PATH,
	DEFAULT_QUEUE_SNAPSHOT_PATH,
	DEFAULT_NO_FORK_PROOF_PATH,
	DEFAULT_CUTOVER_PROOF_BUNDLE_PATH,
	DEFAULT_PROFILE_GENERATION_PROOF_PATH,
	DEFAULT_ROLLBACK_REHEARSAL_PATH,
] as const;
export const HERMES_PROBE_RESULT_SCHEMA_VERSION = "telclaude.hermes.probe-result.v1";
export const CUTOVER_PROOF_BUNDLE_SCHEMA_VERSION = "telclaude.hermes.cutover-proof-bundle.v1";
const HERMES_CLI_HEADLESS_PROVENANCE_RUNNER = "telclaude-hermes-cli-probe";
const HERMES_CLI_HEADLESS_PROVENANCE_SOURCE = "live-allow-run";
const HERMES_CLI_HEADLESS_RUNTIME_PROVENANCE_SOURCE = "docker-inspect-container-dns-and-relay-peer";
const HERMES_CLI_HEADLESS_RELAY_PROOF_SCHEMA_VERSION =
	"telclaude.hermes.cli-headless-relay-proof.v1";
const HERMES_CLI_HEADLESS_RELAY_PROOF_SOURCE = "telclaude-openai-codex-proxy";
const HERMES_CODEX_RESPONSES_PATH = "/backend-api/codex/responses";
const DEFAULT_HERMES_RELAY_IP = "172.29.92.10";
const DEFAULT_HERMES_CONTAINED_IP = "172.29.92.11";
export const NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION = "telclaude.hermes.network-probe.v1";
export const PROFILE_GENERATION_PROOF_SCHEMA_VERSION =
	"telclaude.hermes.profile-generation-proof.v1";
export const GUARDRAIL_MANIFEST_SCHEMA_VERSION = "telclaude.hermes.guardrail-manifest.v1";
export const GUARDRAIL_MOUNT_PLAN_SCHEMA_VERSION = "telclaude.hermes.guardrail-mount-plan.v1";
export const NETWORK_PROBE_POSTURES = ["agent-iptables", "contained-internal"] as const;
export const REQUIRED_CUTOVER_NETWORK_PROBE_IDS = [
	"network.relay-control-allowed",
	"network.direct-provider-denied",
	"network.direct-vault-denied",
	"network.direct-model-provider-denied",
	"network.dns-exfil-denied",
] as const;
export const REQUIRED_CUTOVER_NETWORK_PROBE_POSTURE = "contained-internal" as const;

const NonEmptyString = z.string().trim().min(1);
const SHA256_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/i;
const GIT_COMMIT_PATTERN = /^[0-9a-f]{7,40}$/i;
const PLACEHOLDER_VALUES = new Set([
	"pending",
	"todo",
	"tbd",
	"fixme",
	"sha256:pending",
	"sha256:todo",
	"sha256:tbd",
]);

const MAX_CUTOVER_PROOF_ARTIFACT_AGE_MS = 7 * 24 * 60 * 60 * 1000;

export const HermesPinSchema = z
	.object({
		version: NonEmptyString.optional(),
		commit: NonEmptyString.optional(),
		package: NonEmptyString.optional(),
		imageDigest: NonEmptyString.optional(),
	})
	.strict()
	.refine((pin) => Object.values(pin).some((value) => value !== undefined), {
		message: "at least one Hermes pin field is required",
	});

export type HermesPin = z.infer<typeof HermesPinSchema>;

export const FeatureProbeSchema = z
	.object({
		surface_id: NonEmptyString,
		hermes_pin: HermesPinSchema,
		documented_seam: NonEmptyString,
		probe_command: NonEmptyString,
		expected_result: NonEmptyString,
		negative_probe: NonEmptyString,
		evidence_path: NonEmptyString,
		lockfile_key: NonEmptyString,
		security_scope: z
			.enum([
				"headless-availability-only",
				"approval-continuation",
				"api-server-containment",
				"edge-adapter",
				"model-relay",
				"nofork-proof",
				"provider-approval-binding",
				"served-mcp-containment",
				"served-mcp-provider-tools",
				"side-effect-ledger",
				"workflow-ledger",
			])
			.optional(),
		approval_equivalent: z.boolean().optional(),
		failure_outcome: z.enum(["disable", "downgrade"]),
		status: z.enum(["pass", "fail", "skip"]).optional(),
	})
	.strict();

export const FeatureProbeMatrixSchema = z
	.object({
		schemaVersion: z.literal(1),
		probes: z.array(FeatureProbeSchema),
	})
	.strict();

export type FeatureProbeMatrix = z.infer<typeof FeatureProbeMatrixSchema>;

const FeatureProbeEvidenceResultSchema = z
	.object({
		surface_id: NonEmptyString,
		status: z.enum(["pass", "fail"]),
		evidence_path: NonEmptyString,
		detail: NonEmptyString,
	})
	.strict();

export const FeatureProbeEvidenceBundleSchema = z
	.object({
		schemaVersion: z.literal(1),
		results: z.array(FeatureProbeEvidenceResultSchema),
	})
	.strict();

export type FeatureProbeEvidenceBundle = z.infer<typeof FeatureProbeEvidenceBundleSchema>;

const CliHeadlessProbeEvidenceSchema = z
	.object({
		schemaVersion: z.literal(HERMES_PROBE_RESULT_SCHEMA_VERSION),
		probeId: z.literal("execution.cli_headless"),
		status: z.enum(["pass", "fail", "pending"]),
		ran: z.boolean(),
		summary: z.string().optional(),
		exitCode: z.number().int().optional(),
		invocation: z
			.object({
				command: NonEmptyString,
				args: z.array(z.string()),
				cwd: NonEmptyString,
				envKeys: z.array(NonEmptyString),
			})
			.passthrough(),
		modelProvider: z
			.object({
				provider: z.literal("openai-codex"),
				baseUrl: NonEmptyString,
				baseUrlHost: NonEmptyString,
				model: z.string(),
				modelSource: z.enum(["env:HERMES_INFERENCE_MODEL", "missing"]),
				authLocation: z.literal("hermes-auth-store:openai-codex"),
				authScope: z.literal("relay-openai-codex-subscription-proxy"),
				tokenScoping: z.enum(["static-shared", "peer-bound"]),
				auxiliaryAuthSource: z.literal("manual:telclaude-relay").optional(),
				auxiliaryBaseUrl: z.string().optional(),
				auxiliaryBaseUrlHost: z.string().optional(),
				refreshTokenPolicy: z.literal("non-refreshable-placeholder").optional(),
			})
			.passthrough()
			.optional(),
		provenance: z
			.object({
				runner: z.literal(HERMES_CLI_HEADLESS_PROVENANCE_RUNNER),
				source: z.literal(HERMES_CLI_HEADLESS_PROVENANCE_SOURCE),
				startedAt: NonEmptyString,
				endedAt: NonEmptyString,
				expectedProofToken: NonEmptyString,
				proofTokenObserved: z.boolean(),
				invocationSha256: z.string().regex(SHA256_DIGEST_PATTERN),
				stdoutSha256: z.string().regex(SHA256_DIGEST_PATTERN),
				stderrSha256: z.string().regex(SHA256_DIGEST_PATTERN),
				runtimeSha256: z.string().regex(SHA256_DIGEST_PATTERN),
				relayProofSha256: z.string().regex(SHA256_DIGEST_PATTERN),
			})
			.strict()
			.optional(),
		stdoutPreview: z.string().optional(),
		stderrPreview: z.string().optional(),
		runtime: z
			.object({
				kind: z.literal("contained-docker"),
				containerName: NonEmptyString,
				networkName: z.literal("telclaude-hermes-relay"),
				containerId: NonEmptyString,
				image: NonEmptyString,
				imageDigest: z.string().regex(SHA256_DIGEST_PATTERN),
				hostname: NonEmptyString,
				relayHost: z.literal("telclaude"),
				relayResolvedAddress: NonEmptyString,
				containerIpAddress: NonEmptyString,
				observedPeerAddress: NonEmptyString,
				provenanceSource: z.literal(HERMES_CLI_HEADLESS_RUNTIME_PROVENANCE_SOURCE),
			})
			.strict()
			.optional(),
		relayProof: z
			.object({
				schemaVersion: z.literal(HERMES_CLI_HEADLESS_RELAY_PROOF_SCHEMA_VERSION),
				source: z.literal(HERMES_CLI_HEADLESS_RELAY_PROOF_SOURCE),
				requestId: NonEmptyString,
				method: z.literal("POST"),
				path: z.literal(HERMES_CODEX_RESPONSES_PATH),
				observedPeerAddress: NonEmptyString,
				upstreamStatus: z.number().int(),
				model: NonEmptyString,
				requestBodySha256: z.string().regex(SHA256_DIGEST_PATTERN),
				observedAt: NonEmptyString,
			})
			.strict()
			.optional(),
		findings: z.array(
			z
				.object({
					location: NonEmptyString,
					reason: NonEmptyString,
				})
				.passthrough(),
		),
	})
	.passthrough();

const API_SERVER_CONTAINMENT_SCHEMA_VERSION = "telclaude.hermes.api-server-containment.v1";
const MODEL_RELAY_SCHEMA_VERSION = "telclaude.hermes.model-relay.v1";
const REQUIRED_API_SERVER_CONTAINMENT_GATES = [
	"lifecycle.started",
	"readiness.health",
	"readiness.capabilities",
	"network.topology",
	"network.relay_only",
	"network.tamper_resistant",
] as const;
const REQUIRED_MODEL_RELAY_CONTAINED_GATES = [
	"modelRelay.allowed",
	"modelRelay.origin",
	"relay.reachable",
	"directModel.denied",
	"profile.noRawModelCredentials",
	"profile.noDirectModelHosts",
	"profile.scanComplete",
] as const;
const REQUIRED_MODEL_RELAY_AGENT_IPTABLES_GATES = [
	...REQUIRED_MODEL_RELAY_CONTAINED_GATES,
	"firewall.sentinel",
] as const;
const DIRECT_MODEL_RELAY_PROVIDER_HOSTS = new Set([
	"api.anthropic.com",
	"api.openai.com",
	"auth.openai.com",
	"chatgpt.com",
	"generativelanguage.googleapis.com",
	"openrouter.ai",
	"api.x.ai",
]);
const TELCLAUDE_OPENAI_CODEX_RELAY_PROXY_URL = "http://telclaude:8790/v1/openai-codex-proxy";
const ADAPTER_SIGNATURE_FILES: Record<string, string[]> = {
	"execution.cli_headless": [
		"src/hermes/private-runtime.ts",
		"src/commands/hermes.ts",
		"docker/hermes-contained-entrypoint.sh",
	],
	"execution.approval_continuation": [
		"src/hermes/approval-continuation.ts",
		"src/hermes/approval-continuation-runner.ts",
		"src/hermes/mcp/approval-token.ts",
		"src/hermes/mcp/side-effect-ledger.ts",
	],
	"approval.continuation": [
		"src/hermes/approval-continuation.ts",
		"src/hermes/approval-continuation-runner.ts",
		"src/hermes/mcp/approval-token.ts",
		"src/hermes/mcp/side-effect-ledger.ts",
	],
	"execution.api_server_containment": [
		"src/hermes/api-server-containment.ts",
		"src/hermes/api-adapter.ts",
		"docker/docker-compose.hermes.yml",
	],
	"execution.served_mcp_containment": [
		"src/hermes/served-mcp-containment.ts",
		"src/hermes/mcp/bridge.ts",
		"src/hermes/mcp/live-server.ts",
		"src/hermes/mcp/live-relay-clients.ts",
	],
	"model.relay": [
		"src/hermes/model-relay.ts",
		"src/hermes/network-probes.ts",
		"src/hermes/private-runtime.ts",
		"src/relay/openai-codex-proxy.ts",
	],
	"edge.whatsapp": [
		"src/hermes/edge-adapter-contract.ts",
		"src/hermes/edge-adapter-runtime.ts",
		"src/hermes/edge-adapter-probes.ts",
	],
	"edge.email": [
		"src/hermes/edge-adapter-contract.ts",
		"src/hermes/edge-adapter-runtime.ts",
		"src/hermes/edge-adapter-probes.ts",
	],
	"edge.agentmail": [
		"src/hermes/edge-adapter-contract.ts",
		"src/hermes/edge-adapter-runtime.ts",
		"src/hermes/edge-adapter-probes.ts",
	],
	"edge.social": [
		"src/hermes/edge-adapter-contract.ts",
		"src/hermes/edge-adapter-runtime.ts",
		"src/hermes/edge-adapter-probes.ts",
	],
	"identity.migration": [
		"src/hermes/edge-adapter-contract.ts",
		"src/hermes/edge-adapter-runtime.ts",
		"src/hermes/edge-adapter-probes.ts",
	],
	"household.scopes": [
		"src/hermes/edge-adapter-contract.ts",
		"src/hermes/edge-adapter-runtime.ts",
		"src/hermes/edge-adapter-probes.ts",
	],
	"attachment.quarantine": [
		"src/hermes/edge-adapter-contract.ts",
		"src/hermes/edge-adapter-runtime.ts",
		"src/hermes/edge-adapter-probes.ts",
	],
	"outbound.policy": [
		"src/hermes/edge-adapter-contract.ts",
		"src/hermes/edge-adapter-runtime.ts",
		"src/hermes/edge-adapter-probes.ts",
	],
	"public.social.isolation": [
		"src/hermes/edge-adapter-contract.ts",
		"src/hermes/edge-adapter-runtime.ts",
		"src/hermes/edge-adapter-probes.ts",
	],
	"providers.release-policy": [
		"src/hermes/edge-adapter-contract.ts",
		"src/hermes/edge-adapter-runtime.ts",
		"src/hermes/provider-release-policy-probe.ts",
		"src/hermes/mcp/authority-registry.ts",
		"src/hermes/mcp/bridge.ts",
		"src/relay/provider-proxy.ts",
	],
	"providers.bank": [
		"src/hermes/mcp/bridge.ts",
		"src/hermes/mcp/ledger-execute.ts",
		"src/hermes/mcp/live-relay-clients.ts",
		"src/hermes/provider-domain-probes.ts",
		"src/providers/catalog.ts",
		"src/providers/external-provider.ts",
		"src/relay/provider-proxy.ts",
	],
	"providers.approval-binding": [
		"src/hermes/mcp/approval-token.ts",
		"src/hermes/mcp/side-effect-ledger.ts",
		"src/hermes/mcp/ledger-execute.ts",
		"src/hermes/provider-approval-binding-probe.ts",
		"src/relay/provider-approval.ts",
	],
	"served_mcp.provider-tools": [
		"src/hermes/mcp/bridge.ts",
		"src/hermes/mcp/live-server.ts",
		"src/hermes/mcp/ledger-execute.ts",
		"src/hermes/served-mcp-containment.ts",
		"src/hermes/served-mcp-provider-tools-probe.ts",
	],
	"providers.clalit": [
		"src/hermes/mcp/bridge.ts",
		"src/hermes/mcp/ledger-execute.ts",
		"src/hermes/mcp/live-relay-clients.ts",
		"src/hermes/provider-domain-probes.ts",
		"src/providers/catalog.ts",
		"src/providers/external-provider.ts",
		"src/relay/provider-proxy.ts",
	],
	"providers.government": [
		"src/hermes/mcp/bridge.ts",
		"src/hermes/mcp/ledger-execute.ts",
		"src/hermes/mcp/live-relay-clients.ts",
		"src/hermes/provider-domain-probes.ts",
		"src/providers/catalog.ts",
		"src/providers/external-provider.ts",
		"src/relay/provider-proxy.ts",
	],
	"providers.google": [
		"src/hermes/mcp/bridge.ts",
		"src/hermes/mcp/ledger-execute.ts",
		"src/google-services/server.ts",
		"src/google-services/approval.ts",
		"src/google-services/types.ts",
	],
	"workflow.cron": [
		"src/cron/scheduler.ts",
		"src/cron/store.ts",
		"src/background/runner.ts",
		"src/background/jobs.ts",
		"src/hermes/workflow-run-ledger.ts",
		"src/hermes/workflow-probes.ts",
	],
	"workflow.longrun": [
		"src/background/runner.ts",
		"src/background/jobs.ts",
		"src/hermes/workflow-run-ledger.ts",
		"src/hermes/workflow-probes.ts",
		"src/hermes/mcp/side-effect-ledger.ts",
	],
	"sideeffect.ledger": [
		"src/hermes/mcp/side-effect-ledger.ts",
		"src/hermes/mcp/ledger-execute.ts",
		"src/hermes/mcp/approval-token.ts",
		"src/hermes/mcp/side-effect-ledger-probe.ts",
	],
	"browser.profiles": [
		"src/hermes/browser-computer-broker-probes.ts",
		"src/hermes/network-probes.ts",
		"src/hermes/edge-adapter-contract.ts",
	],
	"computer.broker": [
		"src/hermes/browser-computer-broker-probes.ts",
		"src/hermes/network-probes.ts",
		"src/hermes/edge-adapter-contract.ts",
	],
	"network.egress-broker": [
		"src/hermes/browser-computer-broker-probes.ts",
		"src/hermes/network-probes.ts",
		"src/hermes/private-runtime.ts",
		"docker/docker-compose.hermes.yml",
	],
};
const EDGE_ADAPTER_CONTRACT_UNIT_FILES = new Set([
	"src/hermes/edge-adapter-contract.ts",
	"src/hermes/edge-adapter-probes.ts",
]);
const P0_PARITY_DIGEST_FILES = [
	"docs/hermes/cutover-scope.json",
	"docs/hermes/feature-probes.json",
	"docs/hermes/fixture-results.json",
	"docs/hermes/network-probes.json",
	"docs/hermes/no-fork-proof.json",
	"docs/hermes/rollback-rehearsal.json",
	"src/hermes/edge-adapter-contract.ts",
	"src/hermes/edge-adapter-runtime.ts",
	"src/hermes/edge-adapter-probes.ts",
	"src/hermes/workflow-run-ledger.ts",
	"src/hermes/workflow-probes.ts",
	"src/hermes/browser-computer-broker-probes.ts",
	"tests/hermes/edge-adapter-contract.test.ts",
	"tests/hermes/edge-adapter-runtime.test.ts",
	"tests/hermes/edge-adapter-probes.test.ts",
	"tests/hermes/workflow-run-ledger.test.ts",
	"tests/hermes/workflow-probes.test.ts",
	"tests/hermes/browser-computer-broker-probes.test.ts",
	"tests/hermes/mcp-side-effect-ledger-probe.test.ts",
	"tests/hermes/foundation-network-evidence.test.ts",
	"tests/commands/hermes.test.ts",
];
const REQUIRED_NO_FORK_CHECK_NAMES = [
	"checkout.present",
	"checkout.head",
	"checkout.expectedRef",
	"checkout.pinned",
	"checkout.statusClean",
	"checkout.diffClean",
	"checkout.indexClean",
] as const;
const REQUIRED_ROLLBACK_REHEARSAL_CHECK_NAMES = [
	"rollback.allowed",
	"rollback.relayProofs",
	"rollback.flagBefore",
	"rollback.flagAfter",
	"rollback.fallbackPath",
	"rollback.controlSurface",
	"rollback.observedSources",
] as const;
export const HERMES_ROLLBACK_CONTROL_SURFACE =
	"relay.capabilities:/v1/hermes.private-runtime.mode" as const;
export const HERMES_ROLLBACK_OBSERVATION_SURFACE =
	"relay.capabilities:/v1/hermes.private-runtime.status" as const;
export const HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV = "OPERATOR_RPC_RELAY_PUBLIC_KEY" as const;
export const PRIVATE_TELEGRAM_FIXTURE_TEST_FILES = [
	"tests/integration/telegram-control-plane.replay.test.ts",
	"tests/telegram/command-gating.test.ts",
] as const;
export const PRIVATE_TELEGRAM_FIXTURE_DIGEST_PATHS = [
	...PRIVATE_TELEGRAM_FIXTURE_TEST_FILES,
	"tests/fixtures/integration/telegram-control-plane.json",
	"src/telegram/cards/callback-controller.ts",
	"src/telegram/cards/callback-tokens.ts",
	"src/telegram/cards/store.ts",
	"src/background/jobs.ts",
	"src/background/runner.ts",
	"src/telegram/command-gating.ts",
] as const;
export const PRIVATE_TELEGRAM_FIXTURE_REQUIREMENTS = [
	{
		id: "fixture.private.telegram.basic",
		requiredAssertions: [
			{
				file: "tests/integration/telegram-control-plane.replay.test.ts",
				fullName:
					"Telegram control-plane replay harness replays provider card callback reducers/executors with persisted state",
			},
			{
				file: "tests/integration/telegram-control-plane.replay.test.ts",
				fullName:
					"Telegram control-plane replay harness replays background completion and restart recovery semantics",
			},
		],
		requiredTests: [
			"Telegram control-plane replay harness replays provider card callback reducers/executors with persisted state",
			"Telegram control-plane replay harness replays background completion and restart recovery semantics",
		],
	},
	{
		id: "fixture.private.telegram.basic.deny",
		requiredAssertions: [
			{
				file: "tests/telegram/command-gating.test.ts",
				fullName:
					"resolveCommandAuthorizedFromAuthorizers denies when access groups are enabled and no configured authorizer allows",
			},
			{
				file: "tests/telegram/command-gating.test.ts",
				fullName: "resolveControlCommandGate blocks control commands when unauthorized",
			},
		],
		requiredTests: [
			"resolveCommandAuthorizedFromAuthorizers denies when access groups are enabled and no configured authorizer allows",
			"resolveControlCommandGate blocks control commands when unauthorized",
		],
	},
] as const;
const PROFILE_GENERATION_DECISION_ID = "D-profile-generation";
const REQUIRED_PROFILE_GENERATION_CHECK_NAMES = [
	"profile.pin",
	"profile.requiredOutputs",
	"profile.classification",
	"profile.noRawSecrets",
	"profile.noSourceReplacement",
	"profile.directoryInventory",
	"profile.lockfileDigest",
	"profile.secretOwners",
] as const;
const PROFILE_OUTPUT_DEFINITIONS = [
	{ path: "config.yaml", classification: "sensitive" },
	{ path: ".env.EXAMPLE", classification: "safe-to-diff" },
	{ path: "secret-manifest.json", classification: "sensitive" },
	{ path: "SOUL.md", classification: "safe-to-diff" },
	{ path: "guardrails/ownership.json", classification: "sensitive" },
	{ path: "guardrails/mount-plan.json", classification: "sensitive" },
	{ path: "plugins.json", classification: "derived" },
	{ path: "plugins/model-providers/README.md", classification: "safe-to-diff" },
	{ path: "mcp.json", classification: "sensitive" },
	{ path: "toolsets.json", classification: "safe-to-diff" },
	{ path: "terminal-backend.json", classification: "sensitive" },
	{ path: "gateway-platforms.json", classification: "sensitive" },
	{ path: "cron/export.json", classification: "derived" },
	{ path: "memory-provider.json", classification: "sensitive" },
	{ path: "skills-manifest.json", classification: "derived" },
	{ path: "promoted-skills/README.md", classification: "safe-to-diff" },
	{ path: "quarantine/agent-authored/README.md", classification: "safe-to-diff" },
	{ path: "provenance-manifest.json", classification: "derived" },
	{ path: "audit-cutover-manifest.json", classification: "derived" },
	{ path: DEFAULT_COMPAT_LOCKFILE_PATH, classification: "derived" },
] as const satisfies ReadonlyArray<{
	path: string;
	classification: GeneratedPathClass;
}>;

const ApiServerContainmentProbeEvidenceSchema = z
	.object({
		schemaVersion: z.literal(API_SERVER_CONTAINMENT_SCHEMA_VERSION),
		probeId: z.literal("execution.api_server_containment"),
		status: z.enum(["pass", "fail", "pending"]),
		ran: z.boolean(),
		gates: z.array(
			z
				.object({
					name: NonEmptyString,
					status: z.enum(["pass", "fail", "pending"]),
					detail: NonEmptyString,
				})
				.passthrough(),
		),
		findings: z.array(z.unknown()),
	})
	.passthrough();

const NetworkProbePostureSchema = z.enum(NETWORK_PROBE_POSTURES);

const ModelRelayProbeEvidenceSchema = z
	.object({
		schemaVersion: z.literal(MODEL_RELAY_SCHEMA_VERSION),
		probeId: z.literal("model.relay"),
		posture: NetworkProbePostureSchema.optional(),
		status: z.enum(["pass", "fail", "pending"]),
		ran: z.boolean(),
		origin: z
			.object({
				kind: z.enum(["contained-peer", "relay-self-smoke", "unknown"]),
				containerName: NonEmptyString.optional(),
				observedPeerAddress: NonEmptyString.optional(),
				observedPeerSource: z.literal("server-peer-echo").optional(),
				expectedPeerAddress: NonEmptyString.optional(),
				expectedPeerSource: z.literal("configured-contained-ip").optional(),
				detail: NonEmptyString,
			})
			.passthrough(),
		observation: z
			.object({
				relayUrl: NonEmptyString.optional(),
				directModelUrl: NonEmptyString,
				profileDir: NonEmptyString.optional(),
				scannedProfileFiles: z.array(NonEmptyString).optional(),
			})
			.passthrough(),
		gates: z.array(
			z
				.object({
					name: NonEmptyString,
					status: z.enum(["pass", "fail", "pending"]),
					detail: NonEmptyString,
				})
				.passthrough(),
		),
	})
	.passthrough();

const NetworkProbeAttemptSchema = z
	.object({
		name: NonEmptyString,
		kind: z.enum(["http", "unix_socket", "dns_guard", "firewall_sentinel", "configuration"]),
		target: NonEmptyString,
		expectation: z.enum(["allow", "deny", "present", "configured"]),
		status: z.enum(["pass", "fail"]),
		observed: NonEmptyString,
		detail: NonEmptyString,
		durationMs: z.number().nonnegative().optional(),
		httpStatus: z.number().int().nonnegative().optional(),
		errorName: NonEmptyString.optional(),
		errorCode: NonEmptyString.optional(),
		resolvedAddresses: z
			.array(
				z
					.object({
						address: NonEmptyString,
						blocked: z.boolean(),
						nonOverridable: z.boolean(),
					})
					.strict(),
			)
			.optional(),
	})
	.strict();

const NetworkProbeEvidenceSchema = z
	.object({
		schemaVersion: z.literal(NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION),
		id: NonEmptyString,
		posture: NetworkProbePostureSchema.optional(),
		status: z.enum(["pass", "fail", "pending"]),
		ran: z.boolean(),
		summary: NonEmptyString,
		generatedAt: NonEmptyString,
		evidence_path: NonEmptyString,
		attempts: z.array(NetworkProbeAttemptSchema),
	})
	.strict();

const REQUIRED_CUTOVER_NETWORK_PROBE_ID_SET = new Set<string>(REQUIRED_CUTOVER_NETWORK_PROBE_IDS);
const POSITIVE_CONTAINED_DENIAL_ERROR_CODES = new Set([
	"ECONNREFUSED",
	"EHOSTUNREACH",
	"ENETUNREACH",
	"EACCES",
	"EPERM",
]);

export const CompatibilityLockfileSchema = z
	.object({
		schemaVersion: z.literal(1),
		hermes: HermesPinSchema,
		featureProbeMatrixDigest: NonEmptyString,
		featureProbes: z.array(
			z
				.object({
					surface_id: NonEmptyString,
					status: z.enum(["pass", "fail"]),
					evidence_path: NonEmptyString,
				})
				.strict(),
		),
		adapterApiSignatures: z.record(NonEmptyString, NonEmptyString),
		capabilities: z
			.object({
				plugins: z.array(NonEmptyString),
				mcp: z.array(NonEmptyString),
				modelProviders: z.array(NonEmptyString),
				memoryProviders: z.array(NonEmptyString),
			})
			.strict(),
		requiredUpgradeTests: z.array(NonEmptyString),
		generatedProfileSchemaVersion: NonEmptyString,
		wrapperPackageVersion: NonEmptyString,
		paritySuiteDigests: z.record(NonEmptyString, NonEmptyString),
		noForkProofEvidencePath: NonEmptyString,
		sourceDriftSignals: z
			.object({
				sourceCommit: NonEmptyString.optional(),
				docsCommit: NonEmptyString.optional(),
			})
			.strict(),
	})
	.strict();

export type CompatibilityLockfile = z.infer<typeof CompatibilityLockfileSchema>;

const WorkflowScopeSchema = z
	.object({
		workflow_id: NonEmptyString,
		owner: NonEmptyString,
		trust_domain: NonEmptyString,
		current_behavior: NonEmptyString,
		hermes_target_behavior: NonEmptyString,
		cutover_class: z.enum(["P0", "P1", "P2"]),
		cutover_requirement: NonEmptyString,
		status: z.enum(["included", "excluded", "disabled"]),
		rollback_owner: NonEmptyString.optional(),
		fixture_ids: z.array(NonEmptyString).default([]),
		negative_fixture_ids: z.array(NonEmptyString).default([]),
		required_surface_ids: z.array(NonEmptyString).default([]),
		unresolved_decision_ids: z.array(NonEmptyString).default([]),
	})
	.strict();

export const CutoverScopeManifestSchema = z
	.object({
		schemaVersion: z.literal(1),
		workflows: z.array(WorkflowScopeSchema),
	})
	.strict();

export type CutoverScopeManifest = z.infer<typeof CutoverScopeManifestSchema>;

const InventoryWorkflowSchema = z
	.object({
		workflow_id: NonEmptyString,
		owner: NonEmptyString,
		trust_domain: NonEmptyString,
		active: z.boolean(),
	})
	.passthrough();

const InventorySnapshotSchema = z
	.object({
		workflows: z.array(InventoryWorkflowSchema),
	})
	.catchall(z.unknown());

const InventoryQueueEvidenceSchema = z
	.object({
		status: z.literal("complete"),
		summary: z
			.object({
				pendingQueues: z
					.object({
						approvals: z.number().int().min(0),
						planApprovals: z.number().int().min(0),
						cards: z.number().int().min(0),
						backgroundJobs: z.number().int().min(0),
						socialItems: z.number().int().min(0),
						curatorItems: z.number().int().min(0),
						pairingPendingRequests: z.number().int().min(0),
						pairingActiveLockouts: z.number().int().min(0),
					})
					.strict(),
			})
			.passthrough(),
	})
	.passthrough();

export const DecisionLogSchema = z
	.object({
		schemaVersion: z.literal(1),
		decisions: z.array(
			z
				.object({
					id: NonEmptyString,
					status: z.enum(["accepted", "unresolved", "downgrade_accepted"]),
					owner: NonEmptyString,
					deadline_phase: NonEmptyString,
					accepted_answer: NonEmptyString.optional(),
					evidence_path: NonEmptyString.optional(),
					affected_workflows: z.array(NonEmptyString).default([]),
					cutover_impact: NonEmptyString,
					downgrade_note: NonEmptyString.optional(),
				})
				.strict()
				.refine(
					(decision) => decision.status === "unresolved" || decision.accepted_answer !== undefined,
					{
						message: "accepted decisions require accepted_answer",
					},
				)
				.refine(
					(decision) =>
						decision.status !== "downgrade_accepted" || decision.downgrade_note !== undefined,
					{
						message: "downgrade decisions require downgrade_note",
					},
				),
		),
	})
	.strict();

export type DecisionLog = z.infer<typeof DecisionLogSchema>;

const GeneratedPathClassificationSchema = z.enum([
	"secret",
	"sensitive",
	"derived",
	"safe-to-diff",
]);

export const ProfileGenerationProofSchema = z
	.object({
		schemaVersion: z.literal(PROFILE_GENERATION_PROOF_SCHEMA_VERSION),
		status: z.enum(["pass", "fail"]),
		evidence_path: NonEmptyString,
		generatedAt: NonEmptyString,
		outDir: NonEmptyString,
		pin: HermesPinSchema,
		profileSchemaVersion: NonEmptyString,
		lockfileDigest: z.string().regex(SHA256_DIGEST_PATTERN),
		manifestDigest: z.string().regex(SHA256_DIGEST_PATTERN),
		treeDigest: z.string().regex(SHA256_DIGEST_PATTERN),
		outputs: z.array(
			z
				.object({
					path: NonEmptyString,
					classification: GeneratedPathClassificationSchema,
					sha256: z.string().regex(SHA256_DIGEST_PATTERN),
				})
				.strict(),
		),
		directoryInventory: z.array(
			z
				.object({
					path: NonEmptyString,
					kind: z.enum(["directory", "file"]),
					sha256: z.string().regex(SHA256_DIGEST_PATTERN).optional(),
				})
				.strict(),
		),
		secretManifest: z.array(
			z
				.object({
					id: NonEmptyString,
					owner: z.enum(["telclaude-vault", "telclaude-edge"]),
				})
				.strict(),
		),
		checks: z.array(
			z
				.object({
					name: NonEmptyString,
					status: z.enum(["pass", "fail"]),
					detail: NonEmptyString,
				})
				.strict(),
		),
	})
	.strict();

export type ProfileGenerationProof = z.infer<typeof ProfileGenerationProofSchema>;

const GuardrailSensitivitySchema = z.enum([
	"guardrail-config",
	"credential-presence",
	"prompt",
	"skill-code",
]);

export const GuardrailManifestSchema = z
	.object({
		schemaVersion: z.literal(GUARDRAIL_MANIFEST_SCHEMA_VERSION),
		generatedAt: NonEmptyString,
		profileId: NonEmptyString,
		owner: z.literal("telclaude-relay"),
		productionMutationPolicy: z.literal("deny-and-quarantine"),
		readOnlyRoots: z.array(
			z
				.object({
					path: NonEmptyString,
					owner: z.literal("telclaude-relay"),
					mutability: z.literal("read-only"),
					sensitivity: GuardrailSensitivitySchema,
				})
				.strict(),
		),
		writableRoots: z.array(
			z
				.object({
					path: NonEmptyString,
					owner: z.literal("telclaude-runtime"),
					purpose: z.literal("quarantine"),
					reviewRequired: z.literal(true),
				})
				.strict(),
		),
		mutationDenialFixtures: z.array(
			z
				.object({
					id: NonEmptyString,
					attemptedPath: NonEmptyString,
					expectedOutcome: z.literal("denied-and-copied-to-quarantine"),
				})
				.strict(),
		),
	})
	.strict();

export type GuardrailManifest = z.infer<typeof GuardrailManifestSchema>;

export const GuardrailMountPlanSchema = z
	.object({
		schemaVersion: z.literal(GUARDRAIL_MOUNT_PLAN_SCHEMA_VERSION),
		generatedAt: NonEmptyString,
		profileId: NonEmptyString,
		profileRoot: NonEmptyString,
		enforcement: z.literal("os-read-only-bind-mounts-required"),
		status: z.literal("generated-not-enforced"),
		readOnlyBindMounts: z.array(
			z
				.object({
					source: NonEmptyString,
					target: NonEmptyString,
					mode: z.literal("ro"),
					owner: z.literal("telclaude-relay"),
				})
				.strict(),
		),
		writableBindMounts: z.array(
			z
				.object({
					source: NonEmptyString,
					target: NonEmptyString,
					mode: z.literal("rw"),
					owner: z.literal("telclaude-runtime"),
					purpose: z.literal("quarantine"),
					reviewRequired: z.literal(true),
				})
				.strict(),
		),
	})
	.strict();

export type GuardrailMountPlan = z.infer<typeof GuardrailMountPlanSchema>;

export type GuardrailMutationDecision = {
	allowed: boolean;
	outcome: "denied-and-copied-to-quarantine" | "allowed-quarantine-write";
	attemptedPath: string;
	quarantinePath: string;
	reason: string;
};

export const FixtureResultBundleSchema = z
	.object({
		schemaVersion: z.literal(1),
		results: z.array(
			z
				.object({
					id: NonEmptyString,
					status: z.enum(["pass", "fail"]),
					evidence_path: NonEmptyString,
				})
				.strict(),
		),
	})
	.strict();

export type FixtureResultBundle = z.infer<typeof FixtureResultBundleSchema>;

const FixtureEvidenceSchema = z
	.object({
		schemaVersion: NonEmptyString,
		id: NonEmptyString,
		status: z.enum(["pass", "fail"]),
		ran: z.literal(true),
		evidence_path: NonEmptyString,
		generatedAt: NonEmptyString.optional(),
		observedAt: NonEmptyString.optional(),
		provenance: z
			.object({
				runner: NonEmptyString,
				command: NonEmptyString.optional(),
				source: NonEmptyString.optional(),
			})
			.passthrough(),
		testReport: z
			.object({
				path: NonEmptyString,
				sha256: z.string().regex(SHA256_DIGEST_PATTERN),
				requiredTests: z.array(NonEmptyString),
				requiredAssertions: z
					.array(
						z
							.object({
								file: NonEmptyString,
								fullName: NonEmptyString,
							})
							.strict(),
					)
					.optional(),
			})
			.strict()
			.optional(),
		invocation: z
			.object({
				command: z.array(NonEmptyString),
				cwd: NonEmptyString,
				exitCode: z.literal(0),
				startedAt: NonEmptyString,
				endedAt: NonEmptyString,
				reportPath: NonEmptyString,
				reportSha256: z.string().regex(SHA256_DIGEST_PATTERN),
				sourceDigests: z.record(NonEmptyString, z.string().regex(SHA256_DIGEST_PATTERN)),
			})
			.strict()
			.optional(),
		checks: z
			.array(
				z
					.object({
						name: NonEmptyString,
						status: z.enum(["pass", "fail"]),
						detail: NonEmptyString,
					})
					.strict(),
			)
			.optional(),
	})
	.passthrough()
	.refine((evidence) => evidence.generatedAt !== undefined || evidence.observedAt !== undefined, {
		message: "fixture evidence requires generatedAt or observedAt",
	});

export const ProbeBundleSchema = z
	.object({
		schemaVersion: z.literal(1),
		probes: z.array(
			z
				.object({
					id: NonEmptyString,
					status: z.enum(["pass", "fail"]),
					evidence_path: NonEmptyString,
				})
				.strict(),
		),
	})
	.strict();

export type ProbeBundle = z.infer<typeof ProbeBundleSchema>;

export const NoForkProofSchema = z
	.object({
		schemaVersion: z.literal(1),
		hermesCheckoutClean: z.boolean(),
		evidence_path: NonEmptyString,
		checkoutPath: NonEmptyString.optional(),
		expectedRef: NonEmptyString.optional(),
		expectedVersion: NonEmptyString.optional(),
		head: NonEmptyString.optional(),
		expectedRefCommit: NonEmptyString.optional(),
		currentBranch: NonEmptyString.optional(),
		exactTags: z.array(NonEmptyString).optional(),
		statusPorcelain: z.string().optional(),
		diffExitCode: z.number().int().optional(),
		cachedDiffExitCode: z.number().int().optional(),
		checks: z
			.array(
				z
					.object({
						name: NonEmptyString,
						status: z.enum(["pass", "fail"]),
						detail: NonEmptyString,
					})
					.strict(),
			)
			.optional(),
	})
	.strict();

export type NoForkProof = z.infer<typeof NoForkProofSchema>;

export const QueueOwnershipSnapshotSchema = z
	.object({
		unownedActiveCount: z.number().int().min(0),
	})
	.strict();

export type QueueOwnershipSnapshot = z.infer<typeof QueueOwnershipSnapshotSchema>;

const CUTOVER_PROOF_ARTIFACT_KEYS = [
	"inventory",
	"scopeManifest",
	"decisionLog",
	"compatibilityLockfile",
	"featureProbeMatrix",
	"fixtureResults",
	"noForkProof",
	"networkProbeBundle",
	"queueSnapshot",
	"rollbackEvidence",
] as const;

type CutoverProofArtifactKey = (typeof CUTOVER_PROOF_ARTIFACT_KEYS)[number];

const CutoverProofArtifactKeySchema = z.enum(CUTOVER_PROOF_ARTIFACT_KEYS);

const CutoverProofArtifactScanSchema = z
	.object({
		status: z.enum(["pass", "fail"]),
		summary: NonEmptyString,
	})
	.strict();

const CutoverProofArtifactSchema = z
	.object({
		key: CutoverProofArtifactKeySchema,
		schemaVersion: NonEmptyString,
		generatedAt: NonEmptyString,
		artifactPath: NonEmptyString,
		sha256: z.string().regex(SHA256_DIGEST_PATTERN),
		sourceCommand: NonEmptyString,
		status: z.enum(["pass", "fail"]),
		redaction: CutoverProofArtifactScanSchema,
		leakScan: CutoverProofArtifactScanSchema,
		gateIds: z.array(NonEmptyString).min(1),
		checkIds: z.array(NonEmptyString).default([]),
	})
	.strict();

const CutoverProofArtifactsSchema = z
	.object({
		inventory: CutoverProofArtifactSchema.extend({ key: z.literal("inventory") }),
		scopeManifest: CutoverProofArtifactSchema.extend({ key: z.literal("scopeManifest") }),
		decisionLog: CutoverProofArtifactSchema.extend({ key: z.literal("decisionLog") }),
		compatibilityLockfile: CutoverProofArtifactSchema.extend({
			key: z.literal("compatibilityLockfile"),
		}),
		featureProbeMatrix: CutoverProofArtifactSchema.extend({
			key: z.literal("featureProbeMatrix"),
		}),
		fixtureResults: CutoverProofArtifactSchema.extend({ key: z.literal("fixtureResults") }),
		noForkProof: CutoverProofArtifactSchema.extend({ key: z.literal("noForkProof") }),
		networkProbeBundle: CutoverProofArtifactSchema.extend({
			key: z.literal("networkProbeBundle"),
		}),
		queueSnapshot: CutoverProofArtifactSchema.extend({ key: z.literal("queueSnapshot") }),
		rollbackEvidence: CutoverProofArtifactSchema.extend({ key: z.literal("rollbackEvidence") }),
	})
	.strict();

export const CutoverProofBundleSchema = z
	.object({
		schemaVersion: z.literal(CUTOVER_PROOF_BUNDLE_SCHEMA_VERSION),
		generatedAt: NonEmptyString,
		hermes: HermesPinSchema,
		wrapper: z
			.object({
				version: NonEmptyString,
			})
			.strict(),
		artifacts: CutoverProofArtifactsSchema,
	})
	.strict();

export type CutoverProofBundle = z.infer<typeof CutoverProofBundleSchema>;

const InternalResponseProofSchema = z
	.object({
		version: z.literal("v1"),
		scope: z.string().min(1),
		timestamp: z.string().min(1),
		nonce: z.string().min(1),
		method: z.string().min(1),
		path: z.string().min(1),
		requestBodySha256: z.string().regex(/^[a-f0-9]{64}$/),
		responseBodySha256: z.string().regex(/^[a-f0-9]{64}$/),
		signature: z.string().min(1),
	})
	.strict();

const RollbackRelayPublicKeySchema = z
	.object({
		scope: z.literal("operator"),
		envKey: z.literal(HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV),
		value: NonEmptyString,
		sha256: z.string().regex(SHA256_DIGEST_PATTERN),
		source: NonEmptyString,
	})
	.strict();

const RollbackRelayStateBodySchema = z
	.object({
		ok: z.literal(true),
		effectiveMode: z.enum(["hermes", "legacy"]),
		effectiveValue: z.enum(["1", "0"]),
		rolloutAllowed: z.boolean(),
		rolloutEnvValue: z.string().optional(),
		controlMode: z.enum(["hermes", "legacy"]),
		controlSource: z.enum([
			"env-disabled",
			"runtime-config",
			"runtime-config-default",
			"runtime-config-invalid",
		]),
		fallbackPath: NonEmptyString,
	})
	.strict();

const RollbackRelayTranscriptSchema = z
	.object({
		request: z
			.object({
				method: NonEmptyString,
				path: NonEmptyString,
				body: z.string(),
			})
			.strict(),
		responseBody: NonEmptyString,
		proof: InternalResponseProofSchema,
	})
	.strict();

export const RollbackRehearsalSchema = z
	.object({
		schemaVersion: z.literal(1),
		passed: z.boolean(),
		evidence_path: NonEmptyString,
		allowedToRun: z.boolean().optional(),
		observedBeforeValue: NonEmptyString.optional(),
		observedAfterValue: NonEmptyString.optional(),
		observedFallbackPath: NonEmptyString.optional(),
		observedAt: NonEmptyString.optional(),
		controlSurface: NonEmptyString.optional(),
		observationSurface: NonEmptyString.optional(),
		observedBeforeSource: NonEmptyString.optional(),
		observedAfterSource: NonEmptyString.optional(),
		observedAfterControlSource: NonEmptyString.optional(),
		relayPublicKey: RollbackRelayPublicKeySchema.optional(),
		signedRelayTranscripts: z
			.object({
				before: RollbackRelayTranscriptSchema,
				afterControl: RollbackRelayTranscriptSchema,
				after: RollbackRelayTranscriptSchema,
			})
			.strict()
			.optional(),
		checks: z
			.array(
				z
					.object({
						name: NonEmptyString,
						status: z.enum(["pass", "fail"]),
						detail: NonEmptyString,
					})
					.strict(),
			)
			.optional(),
	})
	.strict();

export type RollbackRehearsal = z.infer<typeof RollbackRehearsalSchema>;

export const CutoverInputBundleSchema = z
	.object({
		schemaVersion: z.literal(1),
		inventory: InventorySnapshotSchema,
		scopeManifest: CutoverScopeManifestSchema,
		decisionLog: DecisionLogSchema,
		cutoverProofBundle: CutoverProofBundleSchema,
		lockfile: CompatibilityLockfileSchema,
		featureProbeMatrix: FeatureProbeMatrixSchema,
		featureProbeEvidence: FeatureProbeEvidenceBundleSchema.optional(),
		fixtureResults: FixtureResultBundleSchema,
		noForkProof: NoForkProofSchema,
		profileGenerationProof: ProfileGenerationProofSchema.optional(),
		networkProbes: ProbeBundleSchema,
		queueSnapshot: QueueOwnershipSnapshotSchema,
		rollbackRehearsal: RollbackRehearsalSchema,
	})
	.strict();

export type CutoverInputBundle = z.infer<typeof CutoverInputBundleSchema>;

export type ValidationResult = {
	valid: boolean;
	errors: string[];
};

export type HermesDoctorReport = {
	status: "pass" | "fail";
	pin: HermesPin | null;
	checks: Array<{ name: string; status: "pass" | "fail"; detail: string }>;
};

export type GeneratedPathClass = "secret" | "sensitive" | "derived" | "safe-to-diff";

export type HermesGenerateDryRun = {
	dryRun: true;
	outDir: string;
	pin: HermesPin;
	profileSchemaVersion: "1";
	outputs: Array<{ path: string; classification: GeneratedPathClass }>;
	secretManifest: Array<{ id: string; owner: "telclaude-vault" | "telclaude-edge" }>;
};

export type CutoverReport = {
	status: "safe" | "fail" | "input_error";
	exitCode: 0 | 1 | 2;
	mode: { strict: true; dryRun: boolean };
	gates: Array<{ name: string; status: "pass" | "fail"; detail: string }>;
	workflowIds: string[];
	evidencePaths: string[];
	decisionIds: string[];
	downgradeNotes: string[];
	remediationOwners: string[];
};

export function parseHermesPin(rawPin: string | undefined): HermesPin | null {
	const pin = rawPin?.trim();
	if (!pin) return null;
	if (pin.startsWith("sha256:")) return { imageDigest: pin };
	if (/^[0-9a-f]{7,40}$/i.test(pin)) return { commit: pin };
	if (pin.includes("/") || pin.includes("@")) return { package: pin };
	return { version: pin };
}

export function validateFeatureProbeMatrix(value: unknown): ValidationResult {
	return formatValidationResult(FeatureProbeMatrixSchema.safeParse(value));
}

export function validateCompatibilityLockfile(value: unknown): ValidationResult {
	return formatValidationResult(CompatibilityLockfileSchema.safeParse(value));
}

export function computeHermesArtifactDigest(value: unknown): string {
	return `sha256:${crypto.createHash("sha256").update(stableStringify(value)).digest("hex")}`;
}

function computeHermesTextDigest(value: string): string {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function isTruncatedProbePreview(value: string): boolean {
	return value.endsWith("...");
}

function computeFileSetDigest(files: readonly string[]): string {
	return computeHermesArtifactDigest(
		files.map((file) => {
			const resolved = resolveHermesArtifactPath(file);
			if (!fs.existsSync(resolved)) {
				return { file, missing: true };
			}
			return {
				file,
				sha256: crypto.createHash("sha256").update(fs.readFileSync(resolved)).digest("hex"),
			};
		}),
	);
}

function currentGitCommit(): string {
	try {
		return execFileSync("git", ["rev-parse", "--verify", "HEAD"], {
			cwd: process.cwd(),
			encoding: "utf8",
			stdio: ["ignore", "pipe", "ignore"],
		}).trim();
	} catch {
		throw new Error("Cannot generate Hermes compatibility lockfile outside a git checkout");
	}
}

export function readJsonFile(filePath: string): unknown {
	return JSON.parse(fs.readFileSync(filePath, "utf8")) as unknown;
}

export function readOptionalJsonFile(filePath: string): unknown | undefined {
	if (!fs.existsSync(filePath)) return undefined;
	return readJsonFile(filePath);
}

export type HermesArtifactWriteOptions = {
	allowTrackedSeedWrite?: boolean;
	mode?: number;
};

const trackedSeedPathCache = new Map<string, Map<string, string>>();

export function assertHermesArtifactWritesAllowed(
	filePaths: readonly string[],
	options: HermesArtifactWriteOptions = {},
): void {
	for (const filePath of filePaths) {
		assertHermesArtifactWriteAllowed(filePath, options);
	}
}

export function assertHermesArtifactWriteAllowed(
	filePath: string,
	options: HermesArtifactWriteOptions = {},
): void {
	const trackedSeedPath = trackedHermesSeedPath(filePath);
	if (!trackedSeedPath || options.allowTrackedSeedWrite === true) return;
	throw new Error(
		`Refusing to write tracked Hermes seed ${trackedSeedPath}. Write generated evidence with --out outside docs/hermes, or pass --write-tracked-seed only for deliberate seed regeneration.`,
	);
}

export function writeHermesJsonArtifact(
	filePath: string,
	value: unknown,
	options: HermesArtifactWriteOptions = {},
): void {
	writeHermesTextArtifact(filePath, `${JSON.stringify(value, null, 2)}\n`, options);
}

export function writeHermesTextArtifact(
	filePath: string,
	content: string,
	options: HermesArtifactWriteOptions = {},
): void {
	assertHermesArtifactWriteAllowed(filePath, options);
	fs.mkdirSync(path.dirname(filePath), { recursive: true });
	const tmpPath = `${filePath}.tmp.${process.pid}`;
	fs.writeFileSync(tmpPath, content, {
		encoding: "utf8",
		...(options.mode === undefined ? {} : { mode: options.mode }),
	});
	fs.renameSync(tmpPath, filePath);
}

function trackedHermesSeedPath(filePath: string): string | undefined {
	const repoRoot = gitTopLevel(process.cwd());
	if (!repoRoot) return undefined;
	const resolved = path.resolve(filePath);
	return trackedHermesSeedPaths(repoRoot).get(resolved);
}

function trackedHermesSeedPaths(repoRoot: string): Map<string, string> {
	const normalizedRoot = path.resolve(repoRoot);
	const cached = trackedSeedPathCache.get(normalizedRoot);
	if (cached) return cached;

	const paths = gitTrackedHermesSeedPaths(normalizedRoot);
	const seedPaths = paths.length > 0 ? paths : [...HERMES_TRACKED_SEED_PATHS];
	const next = new Map(
		seedPaths
			.filter((seedPath) => seedPath.startsWith("docs/hermes/") && seedPath.endsWith(".json"))
			.map((seedPath) => [path.resolve(normalizedRoot, seedPath), seedPath]),
	);
	trackedSeedPathCache.set(normalizedRoot, next);
	return next;
}

function gitTrackedHermesSeedPaths(repoRoot: string): string[] {
	try {
		const output = execFileSync("git", ["-C", repoRoot, "ls-files", "docs/hermes/*.json"], {
			encoding: "utf8",
			stdio: ["ignore", "pipe", "ignore"],
		});
		return output
			.split(/\r?\n/)
			.map((line) => line.trim())
			.filter((line) => line.length > 0);
	} catch {
		return [];
	}
}

function gitTopLevel(cwd: string): string | undefined {
	try {
		const output = execFileSync("git", ["-C", cwd, "rev-parse", "--show-toplevel"], {
			encoding: "utf8",
			stdio: ["ignore", "pipe", "ignore"],
		}).trim();
		return output.length > 0 ? output : undefined;
	} catch {
		return undefined;
	}
}

export function buildCutoverInputBundleFromArtifacts(input: {
	inventory: unknown;
	scopeManifest: unknown;
	decisionLog: unknown;
	cutoverProofBundle: unknown;
	lockfile: unknown;
	featureProbeMatrix: unknown;
	featureProbeEvidence?: unknown;
	fixtureResults: unknown;
	noForkProof: unknown;
	profileGenerationProof?: unknown;
	networkProbes: unknown;
	queueSnapshot?: unknown;
	rollbackRehearsal: unknown;
}): CutoverInputBundle {
	const bundle = {
		schemaVersion: 1,
		inventory: input.inventory,
		scopeManifest: input.scopeManifest,
		decisionLog: input.decisionLog,
		cutoverProofBundle: input.cutoverProofBundle,
		lockfile: input.lockfile,
		featureProbeMatrix: input.featureProbeMatrix,
		featureProbeEvidence: input.featureProbeEvidence,
		fixtureResults: input.fixtureResults,
		noForkProof: input.noForkProof,
		profileGenerationProof: input.profileGenerationProof,
		networkProbes: input.networkProbes,
		queueSnapshot: input.queueSnapshot ?? deriveQueueOwnershipSnapshot(input.inventory),
		rollbackRehearsal: input.rollbackRehearsal,
	};
	const parsed = CutoverInputBundleSchema.safeParse(bundle);
	if (!parsed.success) {
		throw new Error(flattenZodError(parsed.error));
	}
	return parsed.data;
}

export function buildHermesQueueSnapshot(input: { inventory: unknown }): QueueOwnershipSnapshot {
	return deriveQueueOwnershipSnapshot(input.inventory);
}

export function buildCutoverProofBundle(input: {
	hermes: HermesPin;
	wrapperVersion: string;
	artifacts: Record<
		CutoverProofArtifactKey,
		{
			artifactPath: string;
			sourceCommand: string;
			gateIds: string[];
			checkIds?: string[];
		}
	>;
	now?: Date;
}): CutoverProofBundle {
	const now = input.now ?? new Date();
	return CutoverProofBundleSchema.parse({
		schemaVersion: CUTOVER_PROOF_BUNDLE_SCHEMA_VERSION,
		generatedAt: now.toISOString(),
		hermes: input.hermes,
		wrapper: { version: input.wrapperVersion },
		artifacts: Object.fromEntries(
			CUTOVER_PROOF_ARTIFACT_KEYS.map((key) => {
				const artifact = input.artifacts[key];
				const resolvedPath = resolveHermesArtifactPath(artifact.artifactPath);
				const bytes = fs.readFileSync(resolvedPath);
				const text = bytes.toString("utf8");
				const value = JSON.parse(text) as unknown;
				const redaction = scanCutoverProofArtifactRedaction(text);
				const leakScan = scanCutoverProofArtifactLeaks(text);
				const semanticFailures = cutoverProofArtifactSemanticFailures(key, value);
				return [
					key,
					{
						key,
						schemaVersion: schemaVersionOf(value),
						generatedAt: getEvidenceTimestamp(value) ?? now.toISOString(),
						artifactPath: artifact.artifactPath,
						sha256: sha256Digest(bytes),
						sourceCommand: artifact.sourceCommand,
						status:
							redaction.status === "pass" &&
							leakScan.status === "pass" &&
							semanticFailures.length === 0
								? "pass"
								: "fail",
						redaction,
						leakScan,
						gateIds: artifact.gateIds,
						checkIds: artifact.checkIds ?? artifact.gateIds,
					},
				];
			}),
		),
	});
}

function cutoverProofArtifactSemanticFailures(
	key: CutoverProofArtifactKey,
	value: unknown,
): string[] {
	if (key === "noForkProof") {
		const parsed = NoForkProofSchema.safeParse(value);
		if (!parsed.success) {
			return [`no-fork proof schema invalid: ${flattenZodError(parsed.error)}`];
		}
		return noForkProofEvidenceFailures(parsed.data);
	}

	if (key === "networkProbeBundle") {
		const parsed = ProbeBundleSchema.safeParse(value);
		if (!parsed.success) {
			return [`network probe bundle schema invalid: ${flattenZodError(parsed.error)}`];
		}
		const probeById = new Map(parsed.data.probes.map((probe) => [probe.id, probe]));
		return [
			...(parsed.data.probes.length === 0 ? ["network probe bundle is empty"] : []),
			...findDuplicates(parsed.data.probes.map((probe) => probe.id)).map(
				(id) => `duplicate network probe ${id}`,
			),
			...REQUIRED_CUTOVER_NETWORK_PROBE_IDS.flatMap((probeId) =>
				probeById.has(probeId) ? [] : [`missing network probe ${probeId}`],
			),
			...parsed.data.probes.flatMap((probe) => networkProbeEvidenceFailures(probe)),
		];
	}

	if (key === "rollbackEvidence") {
		const parsed = RollbackRehearsalSchema.safeParse(value);
		if (!parsed.success) {
			return [`rollback rehearsal schema invalid: ${flattenZodError(parsed.error)}`];
		}
		return rollbackRehearsalEvidenceFailures(parsed.data);
	}

	return [];
}

export function collectFeatureProbeEvidence(
	featureProbeMatrix: unknown,
): FeatureProbeEvidenceBundle | undefined {
	const parsed = FeatureProbeMatrixSchema.safeParse(featureProbeMatrix);
	if (!parsed.success) return undefined;
	const results = parsed.data.probes.flatMap((probe) => {
		if (probe.surface_id === "execution.cli_headless") {
			return [collectCliHeadlessProbeEvidence(probe)];
		}
		if (probe.surface_id === "execution.served_mcp_containment") {
			return [collectServedMcpContainmentProbeEvidence(probe)];
		}
		if (probe.surface_id === "execution.api_server_containment") {
			return [collectApiServerContainmentProbeEvidence(probe)];
		}
		if (probe.surface_id === "model.relay") {
			return [collectModelRelayProbeEvidence(probe)];
		}
		if (isEdgeAdapterFeatureSurfaceId(probe.surface_id)) {
			return [collectEdgeAdapterProbeEvidence(probe)];
		}
		if (probe.surface_id === "sideeffect.ledger") {
			return [collectSideEffectLedgerProbeEvidence(probe)];
		}
		if (probe.surface_id === "providers.approval-binding") {
			return [collectProviderApprovalBindingProbeEvidence(probe)];
		}
		if (isProviderDomainSurfaceId(probe.surface_id)) {
			return [collectProviderDomainProbeEvidence(probe)];
		}
		if (probe.surface_id === "providers.release-policy") {
			return [collectProviderReleasePolicyProbeEvidence(probe)];
		}
		if (probe.surface_id === "served_mcp.provider-tools") {
			return [collectServedMcpProviderToolsProbeEvidence(probe)];
		}
		if (isBrowserComputerBrokerSurfaceId(probe.surface_id)) {
			return [collectBrowserComputerBrokerProbeEvidence(probe)];
		}
		if (isHermesWorkflowSurfaceId(probe.surface_id)) {
			return [collectWorkflowProbeEvidence(probe)];
		}
		return [];
	});
	return { schemaVersion: 1, results };
}

export function buildCutoverScopeManifestFromInventory(inventory: unknown): CutoverScopeManifest {
	const parsed = InventorySnapshotSchema.safeParse(inventory);
	if (!parsed.success) {
		throw new Error(flattenZodError(parsed.error));
	}
	return {
		schemaVersion: 1,
		workflows: parsed.data.workflows.map((workflow) => {
			const metadata = workflow as Record<string, unknown>;
			const active = workflow.active;
			return {
				workflow_id: workflow.workflow_id,
				owner: workflow.owner,
				trust_domain: workflow.trust_domain,
				current_behavior:
					typeof metadata.current_surface === "string"
						? metadata.current_surface
						: "TODO: describe current Telclaude behavior",
				hermes_target_behavior:
					typeof metadata.hermes_target === "string"
						? metadata.hermes_target
						: "TODO: describe Hermes target behavior",
				cutover_class:
					metadata.p_class === "P1" || metadata.p_class === "P2" ? metadata.p_class : "P0",
				cutover_requirement: "Resolve parity evidence before inclusion.",
				status: active ? "excluded" : "disabled",
				fixture_ids: [],
				negative_fixture_ids: [],
				required_surface_ids: [],
				unresolved_decision_ids: active ? ["D-first-cutover-workflow-set"] : [],
			};
		}),
	};
}

export function buildCompatibilityLockfileDraft(input: {
	pin: HermesPin | null;
	featureProbeMatrix: unknown;
	wrapperPackageVersion: string;
}): CompatibilityLockfile {
	if (!input.pin) {
		throw new Error(
			"Cannot generate Hermes compatibility lockfile without a pinned Hermes artifact.",
		);
	}
	const parsed = FeatureProbeMatrixSchema.safeParse(input.featureProbeMatrix);
	if (!parsed.success) {
		throw new Error(flattenZodError(parsed.error));
	}
	return {
		schemaVersion: 1,
		hermes: input.pin,
		featureProbeMatrixDigest: computeHermesArtifactDigest(parsed.data),
		featureProbes: parsed.data.probes.map((probe) => ({
			surface_id: probe.surface_id,
			status: probe.status === "pass" ? "pass" : "fail",
			evidence_path: probe.evidence_path,
		})),
		adapterApiSignatures: Object.fromEntries(
			parsed.data.probes.map((probe) => [
				probe.surface_id,
				computeHermesArtifactDigest({
					probe: {
						surface_id: probe.surface_id,
						documented_seam: probe.documented_seam,
						probe_command: probe.probe_command,
						expected_result: probe.expected_result,
						negative_probe: probe.negative_probe,
						security_scope: probe.security_scope,
						approval_equivalent: probe.approval_equivalent,
						failure_outcome: probe.failure_outcome,
					},
					files: computeFileSetDigest(
						ADAPTER_SIGNATURE_FILES[probe.surface_id] ?? ["src/hermes/foundation.ts"],
					),
				}),
			]),
		),
		capabilities: {
			plugins: ["platform-adapter", "tool-registration", "curated-skills-profile"],
			mcp: [
				"stdio",
				"http_relay_internal_network",
				"events_wait",
				"permissions_list_open",
				"permissions_respond",
			],
			modelProviders: ["openai-codex-relay", "relay-owned-provider"],
			memoryProviders: ["telclaude-memory-provider"],
		},
		requiredUpgradeTests: [
			"pnpm dev hermes doctor --probes --compat-lock --json",
			"pnpm dev hermes cutover-check --strict --dry-run --json",
			"pnpm dev hermes prove --upstream-clean --p0",
		],
		generatedProfileSchemaVersion: "1",
		wrapperPackageVersion: input.wrapperPackageVersion,
		paritySuiteDigests: {
			p0: computeFileSetDigest(P0_PARITY_DIGEST_FILES),
		},
		noForkProofEvidencePath: "artifacts/hermes/no-fork.json",
		sourceDriftSignals: {
			sourceCommit: currentGitCommit(),
			docsCommit: currentGitCommit(),
		},
	};
}

export function buildHermesDoctorReport(options: {
	pin?: HermesPin | null;
	featureProbeMatrix?: unknown;
	featureProbeMatrixMissing?: string;
	lockfile?: unknown;
	lockfileMissing?: string;
}): HermesDoctorReport {
	const checks: HermesDoctorReport["checks"] = [];
	const pin = options.pin ?? null;
	if (pin) {
		checks.push({ name: "hermes.pin", status: "pass", detail: "pinned Hermes artifact supplied" });
	} else {
		checks.push({
			name: "hermes.pin",
			status: "fail",
			detail: "production requires a pinned Hermes artifact",
		});
	}

	if (options.featureProbeMatrixMissing !== undefined) {
		checks.push({
			name: "hermes.featureProbes",
			status: "fail",
			detail: options.featureProbeMatrixMissing,
		});
	} else if (options.featureProbeMatrix !== undefined) {
		const parsed = FeatureProbeMatrixSchema.safeParse(options.featureProbeMatrix);
		const result = formatValidationResult(parsed);
		const statusFailures = parsed.success
			? [
					...(parsed.data.probes.length === 0 ? ["feature-probe matrix is empty"] : []),
					...parsed.data.probes.flatMap((probe) =>
						probe.status === "pass"
							? []
							: [`${probe.surface_id} status is ${probe.status ?? "missing"}`],
					),
				]
			: [];
		checks.push({
			name: "hermes.featureProbes",
			status: result.valid && statusFailures.length === 0 ? "pass" : "fail",
			detail: !result.valid
				? result.errors.join("; ")
				: statusFailures.length === 0
					? "feature-probe matrix schema is valid and all probes passed"
					: statusFailures.join("; "),
		});
	}

	if (options.lockfileMissing !== undefined) {
		checks.push({
			name: "hermes.compatLockfile",
			status: "fail",
			detail: options.lockfileMissing,
		});
	} else if (options.lockfile !== undefined) {
		const parsed = CompatibilityLockfileSchema.safeParse(options.lockfile);
		const result = formatValidationResult(parsed);
		const consistencyFailures =
			parsed.success === true
				? collectLockfileConsistencyFailures({
						lockfile: parsed.data,
						pin,
						featureProbeMatrix: options.featureProbeMatrix,
					})
				: [];
		checks.push({
			name: "hermes.compatLockfile",
			status: result.valid && consistencyFailures.length === 0 ? "pass" : "fail",
			detail: !result.valid
				? result.errors.join("; ")
				: consistencyFailures.length === 0
					? "compatibility lockfile schema is valid and tied to the current probe matrix"
					: consistencyFailures.join("; "),
		});
	}

	return {
		status: checks.every((check) => check.status === "pass") ? "pass" : "fail",
		pin,
		checks,
	};
}

export function buildHermesGenerateDryRun(options: {
	pin: HermesPin | null;
	outDir: string;
}): HermesGenerateDryRun {
	if (!options.pin) {
		throw new Error("Cannot generate Hermes profiles without a pinned Hermes artifact.");
	}
	return {
		dryRun: true,
		outDir: options.outDir,
		pin: options.pin,
		profileSchemaVersion: "1",
		outputs: profileOutputDefinitions(),
		secretManifest: profileSecretManifest(),
	};
}

export function writeHermesProfileGenerationProof(options: {
	pin: HermesPin | null;
	outDir: string;
	lockfile: unknown;
	evidencePath: string;
	allowTrackedSeedWrite?: boolean;
	now?: string;
}): ProfileGenerationProof {
	if (!options.pin) {
		throw new Error("Cannot generate Hermes profiles without a pinned Hermes artifact.");
	}
	const lockfile = parseCompatibilityLockfileForGeneration(options.lockfile);
	const outDir = path.resolve(options.outDir);
	const lockfileDigest = computeHermesArtifactDigest(lockfile);
	const secretManifest = profileSecretManifest();
	const generatedAt = options.now ?? new Date().toISOString();
	const files = buildProfileFileContents({
		pin: options.pin,
		lockfile,
		lockfileDigest,
		secretManifest,
		generatedAt,
	});
	const writeOptions: HermesArtifactWriteOptions =
		options.allowTrackedSeedWrite === undefined
			? {}
			: { allowTrackedSeedWrite: options.allowTrackedSeedWrite };

	assertHermesArtifactWritesAllowed(
		[
			resolveHermesArtifactPath(options.evidencePath),
			...[...files.keys()].map((relativePath) => path.join(outDir, relativePath)),
		],
		writeOptions,
	);
	assertProfileOutputDirCleanForWrite(outDir, files);
	for (const [relativePath, content] of files) {
		writeTextFileAtomic(path.join(outDir, relativePath), content, writeOptions);
	}

	const outputs = profileOutputDefinitions().map((output) => {
		const content = files.get(output.path);
		if (content === undefined) {
			throw new Error(`profile output ${output.path} was not generated`);
		}
		return {
			...output,
			sha256: sha256Digest(content),
		};
	});
	const directoryInventory = readProfileDirectoryInventory(outDir);
	const treeDigest = computeProfileTreeDigest(directoryInventory);
	const checks = profileGenerationChecks({
		pin: options.pin,
		lockfile,
		lockfileDigest,
		outputs,
		directoryInventory,
		secretManifest,
		files,
		outDir,
	});
	const proof: ProfileGenerationProof = {
		schemaVersion: PROFILE_GENERATION_PROOF_SCHEMA_VERSION,
		status: checks.every((check) => check.status === "pass") ? "pass" : "fail",
		evidence_path: options.evidencePath,
		generatedAt,
		outDir,
		pin: options.pin,
		profileSchemaVersion: "1",
		lockfileDigest,
		manifestDigest: computeProfileManifestDigest(outputs, secretManifest, treeDigest),
		treeDigest,
		outputs,
		directoryInventory,
		secretManifest,
		checks,
	};
	const parsed = ProfileGenerationProofSchema.safeParse(proof);
	if (!parsed.success) {
		throw new Error(flattenZodError(parsed.error));
	}
	writeTextFileAtomic(
		resolveHermesArtifactPath(options.evidencePath),
		`${JSON.stringify(parsed.data, null, 2)}\n`,
		writeOptions,
	);
	return parsed.data;
}

function parseCompatibilityLockfileForGeneration(value: unknown): CompatibilityLockfile {
	const parsed = CompatibilityLockfileSchema.safeParse(value);
	if (!parsed.success) {
		throw new Error(flattenZodError(parsed.error));
	}
	return parsed.data;
}

function profileOutputDefinitions(): Array<{ path: string; classification: GeneratedPathClass }> {
	return PROFILE_OUTPUT_DEFINITIONS.map((output) => ({
		path: output.path,
		classification: output.classification,
	}));
}

function profileSecretManifest(): HermesGenerateDryRun["secretManifest"] {
	return [
		{ id: "model-provider-credentials", owner: "telclaude-vault" },
		{ id: "provider-sidecar-credentials", owner: "telclaude-vault" },
		{ id: "public-channel-credentials", owner: "telclaude-edge" },
	];
}

export function buildGuardrailManifest(input: {
	profileId: string;
	now?: string | Date;
}): GuardrailManifest {
	const generatedAt =
		input.now instanceof Date ? input.now.toISOString() : (input.now ?? new Date().toISOString());
	return GuardrailManifestSchema.parse({
		schemaVersion: GUARDRAIL_MANIFEST_SCHEMA_VERSION,
		generatedAt,
		profileId: input.profileId,
		owner: "telclaude-relay",
		productionMutationPolicy: "deny-and-quarantine",
		readOnlyRoots: [
			guardrailReadOnlyRoot("config.yaml", "guardrail-config"),
			guardrailReadOnlyRoot(".env.EXAMPLE", "credential-presence"),
			guardrailReadOnlyRoot("secret-manifest.json", "credential-presence"),
			guardrailReadOnlyRoot("SOUL.md", "prompt"),
			guardrailReadOnlyRoot("guardrails/ownership.json", "guardrail-config"),
			guardrailReadOnlyRoot("guardrails/mount-plan.json", "guardrail-config"),
			guardrailReadOnlyRoot("plugins.json", "skill-code"),
			guardrailReadOnlyRoot("plugins", "skill-code"),
			guardrailReadOnlyRoot("plugins/model-providers", "skill-code"),
			guardrailReadOnlyRoot("mcp.json", "guardrail-config"),
			guardrailReadOnlyRoot("toolsets.json", "guardrail-config"),
			guardrailReadOnlyRoot("terminal-backend.json", "guardrail-config"),
			guardrailReadOnlyRoot("gateway-platforms.json", "guardrail-config"),
			guardrailReadOnlyRoot("memory-provider.json", "guardrail-config"),
			guardrailReadOnlyRoot("skills-manifest.json", "skill-code"),
			guardrailReadOnlyRoot("promoted-skills", "skill-code"),
			guardrailReadOnlyRoot("provenance-manifest.json", "guardrail-config"),
			guardrailReadOnlyRoot("audit-cutover-manifest.json", "guardrail-config"),
			guardrailReadOnlyRoot(DEFAULT_COMPAT_LOCKFILE_PATH, "guardrail-config"),
		],
		writableRoots: [
			{
				path: "quarantine/agent-authored",
				owner: "telclaude-runtime",
				purpose: "quarantine",
				reviewRequired: true,
			},
		],
		mutationDenialFixtures: [
			{
				id: "guardrails.plugin_root_write_denied",
				attemptedPath: "plugins/model-providers/malicious.py",
				expectedOutcome: "denied-and-copied-to-quarantine",
			},
			{
				id: "guardrails.mcp_config_write_denied",
				attemptedPath: "mcp.json",
				expectedOutcome: "denied-and-copied-to-quarantine",
			},
			{
				id: "guardrails.promoted_skill_write_denied",
				attemptedPath: "promoted-skills/external-provider/SKILL.md",
				expectedOutcome: "denied-and-copied-to-quarantine",
			},
			{
				id: "guardrails.hermes_source_write_denied",
				attemptedPath: "providers/__init__.py",
				expectedOutcome: "denied-and-copied-to-quarantine",
			},
		],
	});
}

function guardrailReadOnlyRoot(
	rootPath: string,
	sensitivity: z.infer<typeof GuardrailSensitivitySchema>,
): GuardrailManifest["readOnlyRoots"][number] {
	return {
		path: rootPath,
		owner: "telclaude-relay",
		mutability: "read-only",
		sensitivity,
	};
}

export function buildGuardrailMountPlan(input: {
	profileRoot: string;
	manifest: GuardrailManifest;
	now?: string | Date;
}): GuardrailMountPlan {
	const generatedAt =
		input.now instanceof Date ? input.now.toISOString() : (input.now ?? input.manifest.generatedAt);
	return GuardrailMountPlanSchema.parse({
		schemaVersion: GUARDRAIL_MOUNT_PLAN_SCHEMA_VERSION,
		generatedAt,
		profileId: input.manifest.profileId,
		profileRoot: input.profileRoot,
		enforcement: "os-read-only-bind-mounts-required",
		status: "generated-not-enforced",
		readOnlyBindMounts: input.manifest.readOnlyRoots.map((root) => ({
			source: guardrailMountSource(input.profileRoot, root.path),
			target: normalizeGeneratedProfilePath(root.path),
			mode: "ro",
			owner: "telclaude-relay",
		})),
		writableBindMounts: input.manifest.writableRoots.map((root) => ({
			source: guardrailMountSource(input.profileRoot, root.path),
			target: normalizeGeneratedProfilePath(root.path),
			mode: "rw",
			owner: "telclaude-runtime",
			purpose: "quarantine",
			reviewRequired: true,
		})),
	});
}

export function evaluateGuardrailMutation(
	manifest: GuardrailManifest,
	attemptedPath: string,
): GuardrailMutationDecision {
	const normalized = normalizeGeneratedProfilePath(attemptedPath);
	const quarantineRoot = manifest.writableRoots[0]?.path ?? "quarantine/agent-authored";
	const quarantinePath = `${quarantineRoot}/${normalized.replaceAll("/", "__")}`;
	if (
		pathMatchesGuardrailRoots(
			normalized,
			manifest.writableRoots.map((root) => root.path),
		)
	) {
		return {
			allowed: true,
			outcome: "allowed-quarantine-write",
			attemptedPath: normalized,
			quarantinePath: normalized,
			reason: "write is already inside the relay-review quarantine root",
		};
	}
	return {
		allowed: false,
		outcome: "denied-and-copied-to-quarantine",
		attemptedPath: normalized,
		quarantinePath,
		reason: pathMatchesGuardrailRoots(
			normalized,
			manifest.readOnlyRoots.map((root) => root.path),
		)
			? "target is relay-owned read-only guardrail state"
			: "production profile mutations are denied and routed to quarantine",
	};
}

function buildProfileFileContents(input: {
	pin: HermesPin;
	lockfile: CompatibilityLockfile;
	lockfileDigest: string;
	secretManifest: HermesGenerateDryRun["secretManifest"];
	generatedAt: string;
}): Map<string, string> {
	const guardrailManifest = buildGuardrailManifest({
		profileId: "tc-private-default",
		now: input.generatedAt,
	});
	const guardrailMountPlan = buildGuardrailMountPlan({
		profileRoot: "$HERMES_PROFILE_ROOT",
		manifest: guardrailManifest,
		now: input.generatedAt,
	});
	const profileContext = {
		profileSchemaVersion: "1",
		pin: input.pin,
		lockfileDigest: input.lockfileDigest,
		guardrailManifest,
		guardrailMountPlan,
	} as const;
	return new Map(
		PROFILE_OUTPUT_DEFINITIONS.map((output) => [
			output.path,
			profileFileContent(output.path, {
				...profileContext,
				lockfile: input.lockfile,
				secretManifest: input.secretManifest,
			}),
		]),
	);
}

function profileFileContent(
	relativePath: string,
	context: {
		profileSchemaVersion: "1";
		pin: HermesPin;
		lockfileDigest: string;
		lockfile: CompatibilityLockfile;
		secretManifest: HermesGenerateDryRun["secretManifest"];
		guardrailManifest: GuardrailManifest;
		guardrailMountPlan: GuardrailMountPlan;
	},
): string {
	switch (relativePath) {
		case "config.yaml":
			return [
				'profileSchemaVersion: "1"',
				"runtime:",
				"  owner: telclaude-relay",
				"  execution: contained-private",
				"model:",
				"  provider: openai-codex-relay",
				`  baseUrl: ${TELCLAUDE_OPENAI_CODEX_RELAY_PROXY_URL}`,
				"  credentialSource: telclaude-relay-auth-store",
				"memory:",
				"  provider: telclaude-relay-memory",
				"approvals:",
				"  provider: telclaude-signed-side-effect-ledger",
				"guardrails:",
				"  ownershipManifest: guardrails/ownership.json",
				"  mountPlan: guardrails/mount-plan.json",
				"  productionMutationPolicy: deny-and-quarantine",
				"  runtimeEnforcementStatus: generated-not-enforced",
				"",
			].join("\n");
		case ".env.EXAMPLE":
			return [
				"HERMES_INFERENCE_PROVIDER=openai-codex",
				`HERMES_CODEX_BASE_URL=${TELCLAUDE_OPENAI_CODEX_RELAY_PROXY_URL}`,
				"HERMES_INFERENCE_MODEL=<relay-approved-model>",
				"TELCLAUDE_RELAY_TOKEN_FILE=/run/secrets/telclaude-hermes-relay-token",
				"",
			].join("\n");
		case "secret-manifest.json":
			return jsonProfileContent({
				schemaVersion: 1,
				secrets: context.secretManifest,
				rawCredentialPolicy: "relay-owned-only",
			});
		case "guardrails/ownership.json":
			return jsonProfileContent(context.guardrailManifest);
		case "guardrails/mount-plan.json":
			return jsonProfileContent(context.guardrailMountPlan);
		case "SOUL.md":
			return [
				"# Telclaude Hermes Private Profile",
				"",
				"This profile runs behind the Telclaude relay. It must not own provider, model, banking, health, or public-channel credentials.",
				"",
			].join("\n");
		case "plugins.json":
			return jsonProfileContent({
				schemaVersion: 1,
				enabled: [
					"telclaude-mcp-bridge",
					"telclaude-platform-adapters",
					"telclaude-curated-skills",
				],
				thirdPartyPolicy: "disabled-until-reviewed",
			});
		case "plugins/model-providers/README.md":
			return "Relay-owned read-only model provider plugin root. Production model traffic routes through the Telclaude relay.\n";
		case "mcp.json":
			return jsonProfileContent({
				schemaVersion: 1,
				servers: {
					telclaudeRelay: {
						transport: "http",
						url: "http://telclaude:8790/v1/hermes/mcp",
						auth: "relay-token-file",
					},
				},
			});
		case "toolsets.json":
			return jsonProfileContent({
				schemaVersion: 1,
				toolsets: {
					private: ["file.read", "terminal.contained", "mcp.telclaudeRelay"],
					sideEffects: ["mcp.prepare", "mcp.approve", "mcp.execute"],
					publicChannels: [],
				},
			});
		case "terminal-backend.json":
			return jsonProfileContent({
				schemaVersion: 1,
				backend: "contained",
				defaultCwd: "/workspace",
				egress: "relay-and-denylist-probed",
			});
		case "gateway-platforms.json":
			return jsonProfileContent({
				schemaVersion: 1,
				platforms: {
					telegram: { ingress: "telclaude-edge", enabled: true },
					whatsapp: { ingress: "telclaude-edge", enabled: false },
					email: { ingress: "telclaude-edge", enabled: false },
				},
			});
		case "cron/export.json":
			return jsonProfileContent({
				schemaVersion: 1,
				owner: "telclaude-cron",
				jobs: [],
			});
		case "memory-provider.json":
			return jsonProfileContent({
				schemaVersion: 1,
				provider: "telclaude-relay-memory",
				url: "http://telclaude:8790/v1/hermes/memory",
				namespaces: ["private"],
			});
		case "skills-manifest.json":
			return jsonProfileContent({
				schemaVersion: 1,
				sources: ["telclaude-reviewed-catalog"],
				defaultAllowlist: ["telegram-reply", "external-provider", "security-gate"],
				thirdPartySkills: "disabled-until-reviewed",
			});
		case "promoted-skills/README.md":
			return "Relay-owned read-only promoted skills root. Agent-authored changes go to quarantine.\n";
		case "quarantine/agent-authored/README.md":
			return "Writable quarantine for agent-authored mutations pending relay review.\n";
		case "provenance-manifest.json":
			return jsonProfileContent({
				schemaVersion: 1,
				pin: context.pin,
				lockfileDigest: context.lockfileDigest,
				profileSchemaVersion: context.profileSchemaVersion,
			});
		case "audit-cutover-manifest.json":
			return jsonProfileContent({
				schemaVersion: 1,
				requiredGates: [
					"workflow.scope",
					"decisions.resolved",
					"profileGeneration.proven",
					"featureProbes.pass",
					"lockfile.consistent",
					"fixtures.pass",
					"nofork.clean",
					"networkProbes.pass",
					"queues.owned",
					"rollback.rehearsed",
				],
				proofPolicy: "fail-closed",
			});
		case DEFAULT_COMPAT_LOCKFILE_PATH:
			return `${JSON.stringify(context.lockfile, null, 2)}\n`;
		default:
			throw new Error(`unsupported profile output ${relativePath}`);
	}
}

function profileGenerationChecks(input: {
	pin: HermesPin;
	lockfile: CompatibilityLockfile;
	lockfileDigest: string;
	outputs: ProfileGenerationProof["outputs"];
	directoryInventory: ProfileGenerationProof["directoryInventory"];
	secretManifest: HermesGenerateDryRun["secretManifest"];
	files: Map<string, string>;
	outDir: string;
}): ProfileGenerationProof["checks"] {
	const requiredPaths = new Set(PROFILE_OUTPUT_DEFINITIONS.map((output) => output.path));
	const outputByPath = new Map(input.outputs.map((output) => [output.path, output]));
	const missingPaths = [...requiredPaths].filter((requiredPath) => !outputByPath.has(requiredPath));
	const classificationFailures = PROFILE_OUTPUT_DEFINITIONS.flatMap((expected) => {
		const actual = outputByPath.get(expected.path);
		if (!actual) return [];
		return actual.classification === expected.classification
			? []
			: [`${expected.path} is ${actual.classification}, expected ${expected.classification}`];
	});
	const rawSecretPaths = [...input.files.entries()]
		.filter(([, content]) => profileContentContainsRawSecret(content))
		.map(([relativePath]) => relativePath);
	const sourceReplacementPaths = generatedProfileSourceReplacementFailures(input.files);
	const expectedInventory = expectedProfileDirectoryInventory(input.files);
	const directoryInventoryFailures = sameJson(input.directoryInventory, expectedInventory)
		? []
		: ["directory inventory does not match canonical generated outputs"];
	const ownerFailures = expectedProfileSecretOwners(input.secretManifest);
	return [
		{
			name: "profile.pin",
			status: sameJson(input.pin, input.lockfile.hermes) ? "pass" : "fail",
			detail: sameJson(input.pin, input.lockfile.hermes)
				? "profile pin matches compatibility lockfile Hermes pin"
				: "profile pin does not match compatibility lockfile Hermes pin",
		},
		{
			name: "profile.requiredOutputs",
			status: missingPaths.length === 0 ? "pass" : "fail",
			detail:
				missingPaths.length === 0
					? "all required profile artifacts were generated"
					: `missing required profile artifacts: ${missingPaths.join(", ")}`,
		},
		{
			name: "profile.classification",
			status:
				classificationFailures.length === 0 &&
				input.outputs.every((output) => output.classification !== "secret")
					? "pass"
					: "fail",
			detail:
				classificationFailures.length === 0 &&
				input.outputs.every((output) => output.classification !== "secret")
					? "all generated artifacts are classified and no raw secret file is emitted"
					: [...classificationFailures, "secret-classified output emitted"].join("; "),
		},
		{
			name: "profile.noRawSecrets",
			status: rawSecretPaths.length === 0 ? "pass" : "fail",
			detail:
				rawSecretPaths.length === 0
					? "generated artifacts contain placeholders and relay references only"
					: `raw credential-like material found in ${rawSecretPaths.join(", ")}`,
		},
		{
			name: "profile.noSourceReplacement",
			status: sourceReplacementPaths.length === 0 ? "pass" : "fail",
			detail:
				sourceReplacementPaths.length === 0
					? "generated profile contains extensions only, with no Hermes source replacement, patch, or monkeypatch artifact"
					: `Hermes source replacement artifact found in ${sourceReplacementPaths.join(", ")}`,
		},
		{
			name: "profile.directoryInventory",
			status: directoryInventoryFailures.length === 0 ? "pass" : "fail",
			detail:
				directoryInventoryFailures.length === 0
					? "generated profile directory contains exactly the canonical outputs"
					: directoryInventoryFailures.join("; "),
		},
		{
			name: "profile.lockfileDigest",
			status: SHA256_DIGEST_PATTERN.test(input.lockfileDigest) ? "pass" : "fail",
			detail: `lockfile digest is ${input.lockfileDigest}`,
		},
		{
			name: "profile.secretOwners",
			status: ownerFailures.length === 0 ? "pass" : "fail",
			detail:
				ownerFailures.length === 0
					? "profile secret manifest assigns model/provider secrets to vault and public-channel secrets to edge"
					: ownerFailures.join("; "),
		},
	];
}

function expectedProfileSecretOwners(
	secretManifest: HermesGenerateDryRun["secretManifest"],
): string[] {
	const expectedOwners = new Map([
		["model-provider-credentials", "telclaude-vault"],
		["provider-sidecar-credentials", "telclaude-vault"],
		["public-channel-credentials", "telclaude-edge"],
	]);
	const actualOwners = new Map(secretManifest.map((secret) => [secret.id, secret.owner]));
	const failures = [...expectedOwners.entries()].flatMap(([id, owner]) => {
		const actual = actualOwners.get(id);
		if (actual === undefined) return [`missing secret owner ${id}`];
		return actual === owner ? [] : [`secret owner ${id} is ${actual}, expected ${owner}`];
	});
	for (const duplicate of findDuplicates(secretManifest.map((secret) => secret.id))) {
		failures.push(`duplicate secret owner ${duplicate}`);
	}
	return failures;
}

function assertProfileOutputDirCleanForWrite(outDir: string, files: Map<string, string>): void {
	if (!fs.existsSync(outDir)) return;
	const actual = readProfileDirectoryInventory(outDir);
	if (actual.length === 0) return;
	const expected = expectedProfileDirectoryInventory(files);
	const actualShape = actual.map(({ path, kind }) => ({ path, kind }));
	const expectedShape = expected.map(({ path, kind }) => ({ path, kind }));
	if (!sameJson(actualShape, expectedShape)) {
		throw new Error(
			`Refusing to write Hermes profile into non-canonical output directory: ${outDir}`,
		);
	}
}

function expectedProfileDirectoryInventory(
	files: Map<string, string>,
): ProfileGenerationProof["directoryInventory"] {
	const entries = new Map<string, ProfileGenerationProof["directoryInventory"][number]>();
	for (const [relativePath, content] of files) {
		const parts = relativePath.split("/");
		for (let index = 1; index < parts.length; index += 1) {
			const directoryPath = parts.slice(0, index).join("/");
			entries.set(directoryPath, { path: directoryPath, kind: "directory" });
		}
		entries.set(relativePath, {
			path: relativePath,
			kind: "file",
			sha256: sha256Digest(content),
		});
	}
	return [...entries.values()].sort(compareProfileInventoryEntries);
}

function readProfileDirectoryInventory(
	outDir: string,
): ProfileGenerationProof["directoryInventory"] {
	const root = fs.realpathSync(outDir);
	const entries: ProfileGenerationProof["directoryInventory"] = [];
	function visit(directory: string): void {
		const dirents = fs
			.readdirSync(directory, { withFileTypes: true })
			.sort((left, right) => left.name.localeCompare(right.name));
		for (const dirent of dirents) {
			const absolutePath = path.join(directory, dirent.name);
			const relativePath = path.relative(root, absolutePath).split(path.sep).join("/");
			const stat = fs.lstatSync(absolutePath);
			if (stat.isSymbolicLink()) {
				throw new Error(`Hermes profile output contains symlink: ${relativePath}`);
			}
			if (stat.isDirectory()) {
				entries.push({ path: relativePath, kind: "directory" });
				visit(absolutePath);
				continue;
			}
			if (!stat.isFile()) {
				throw new Error(`Hermes profile output contains unsupported entry: ${relativePath}`);
			}
			if (stat.nlink > 1) {
				throw new Error(`Hermes profile output contains hardlinked file: ${relativePath}`);
			}
			entries.push({
				path: relativePath,
				kind: "file",
				sha256: sha256Digest(fs.readFileSync(absolutePath)),
			});
		}
	}
	visit(root);
	return entries.sort(compareProfileInventoryEntries);
}

function compareProfileInventoryEntries(
	left: ProfileGenerationProof["directoryInventory"][number],
	right: ProfileGenerationProof["directoryInventory"][number],
): number {
	if (left.path === right.path) return left.kind.localeCompare(right.kind);
	return left.path.localeCompare(right.path);
}

function computeProfileTreeDigest(
	directoryInventory: ProfileGenerationProof["directoryInventory"],
): string {
	return computeHermesArtifactDigest(directoryInventory);
}

function computeProfileManifestDigest(
	outputs: ProfileGenerationProof["outputs"],
	secretManifest: ProfileGenerationProof["secretManifest"],
	treeDigest: string,
): string {
	return computeHermesArtifactDigest({
		outputs: [...outputs].sort((left, right) => left.path.localeCompare(right.path)),
		secretManifest: [...secretManifest].sort((left, right) => left.id.localeCompare(right.id)),
		treeDigest,
	});
}

function profileContentContainsRawSecret(content: string): boolean {
	if (redactSecrets(content) !== content) return true;
	return [
		/sk-[A-Za-z0-9_-]{10,}/,
		/gh[opsru]_[A-Za-z0-9_]{20,}/,
		/xox[baprs]-[A-Za-z0-9-]{20,}/,
		/-----BEGIN [A-Z ]*PRIVATE KEY-----/,
	].some((pattern) => pattern.test(content));
}

function generatedProfileSourceReplacementFailures(files: Map<string, string>): string[] {
	const failures: string[] = [];
	for (const [relativePath, content] of files) {
		const normalized = normalizeGeneratedProfilePath(relativePath);
		if (generatedProfilePathLooksLikeSourceReplacement(normalized)) {
			failures.push(normalized);
			continue;
		}
		if (/monkeypatch|sitecustomize|runtime source replacement/i.test(content)) {
			failures.push(normalized);
		}
	}
	return failures;
}

function generatedProfileInventorySourceReplacementFailures(
	outDir: string,
	inventory: ProfileGenerationProof["directoryInventory"],
): string[] {
	const failures: string[] = [];
	for (const entry of inventory) {
		const normalized = normalizeGeneratedProfilePath(entry.path);
		if (generatedProfilePathLooksLikeSourceReplacement(normalized)) {
			failures.push(normalized);
			continue;
		}
		if (entry.kind !== "file") continue;
		const resolved = path.resolve(outDir, normalized);
		const relativeToOutDir = path.relative(outDir, resolved);
		if (relativeToOutDir.startsWith("..") || path.isAbsolute(relativeToOutDir)) continue;
		const text = safeReadText(resolved);
		if (text && /monkeypatch|sitecustomize|runtime source replacement/i.test(text)) {
			failures.push(normalized);
		}
	}
	return failures;
}

function generatedProfilePathLooksLikeSourceReplacement(relativePath: string): boolean {
	const normalized = normalizeGeneratedProfilePath(relativePath);
	const forbiddenPathPrefixes = ["hermes_cli/", "gateway/", "providers/", "tools/"];
	const forbiddenPathParts = ["/site-packages/hermes/"];
	const forbiddenExtensions = [".patch", ".diff"];
	return (
		forbiddenExtensions.some((extension) => normalized.endsWith(extension)) ||
		forbiddenPathPrefixes.some((prefix) => normalized.startsWith(prefix)) ||
		forbiddenPathParts.some((part) => `/${normalized}`.includes(part))
	);
}

function safeReadText(filePath: string): string | null {
	try {
		return fs.readFileSync(filePath, "utf8");
	} catch {
		return null;
	}
}

function normalizeGeneratedProfilePath(inputPath: string): string {
	return inputPath
		.replaceAll("\\", "/")
		.split("/")
		.filter((part) => part.length > 0 && part !== ".")
		.join("/");
}

function pathMatchesGuardrailRoots(relativePath: string, roots: string[]): boolean {
	const normalized = normalizeGeneratedProfilePath(relativePath);
	return roots.some((root) => {
		const normalizedRoot = normalizeGeneratedProfilePath(root);
		return normalized === normalizedRoot || normalized.startsWith(`${normalizedRoot}/`);
	});
}

function guardrailMountSource(profileRoot: string, relativePath: string): string {
	const normalizedRoot = profileRoot.endsWith("/") ? profileRoot.slice(0, -1) : profileRoot;
	return `${normalizedRoot}/${normalizeGeneratedProfilePath(relativePath)}`;
}

function jsonProfileContent(value: unknown): string {
	return `${JSON.stringify(value, null, 2)}\n`;
}

function sha256Digest(content: string | Buffer): string {
	return `sha256:${crypto.createHash("sha256").update(content).digest("hex")}`;
}

function schemaVersionOf(value: unknown): string {
	if (
		typeof value === "object" &&
		value !== null &&
		"schemaVersion" in value &&
		(typeof value.schemaVersion === "string" || typeof value.schemaVersion === "number")
	) {
		return String(value.schemaVersion);
	}
	return "unknown";
}

function getEvidenceTimestamp(value: unknown): string | undefined {
	if (typeof value !== "object" || value === null) return undefined;
	for (const key of ["generatedAt", "observedAt", "collectedAt", "lockedAt"] as const) {
		const timestamp = (value as Record<string, unknown>)[key];
		if (typeof timestamp === "string" && timestamp.trim()) return timestamp;
	}
	return undefined;
}

function isStaleEvidenceTimestamp(timestamp: string, now: Date): boolean {
	const parsed = Date.parse(timestamp);
	if (Number.isNaN(parsed)) return true;
	const nowMs = now.getTime();
	return parsed > nowMs || nowMs - parsed > MAX_CUTOVER_PROOF_ARTIFACT_AGE_MS;
}

function scanCutoverProofArtifactRedaction(text: string): {
	status: "pass" | "fail";
	summary: string;
} {
	return redactSecrets(text) === text
		? {
				status: "pass",
				summary: "artifact bytes contain no credential-shaped text requiring redaction",
			}
		: {
				status: "fail",
				summary: "artifact bytes contain credential-shaped text requiring redaction",
			};
}

function scanCutoverProofArtifactLeaks(text: string): { status: "pass" | "fail"; summary: string } {
	const leakPatterns = [
		/\b(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|GOOGLE_CLIENT_SECRET|GITHUB_TOKEN)\s*[:=]/i,
		/\bsk-(?:ant|proj|live|test)[A-Za-z0-9_-]{12,}\b/,
		/-----BEGIN [A-Z ]*PRIVATE KEY-----/,
	];
	const leaked = leakPatterns.some((pattern) => pattern.test(text));
	return leaked
		? {
				status: "fail",
				summary: "artifact bytes contain credential-shaped material",
			}
		: {
				status: "pass",
				summary: "artifact bytes passed structured secret scan",
			};
}

function writeTextFileAtomic(
	filePath: string,
	content: string,
	options: HermesArtifactWriteOptions = {},
): void {
	writeHermesTextArtifact(filePath, content, options);
}

export function evaluateCutoverCheck(
	input: unknown,
	options: { strict?: boolean; dryRun?: boolean; liveCutover?: boolean; now?: Date } = {},
): CutoverReport {
	const dryRun = options.dryRun ?? false;
	const strict = options.strict ?? true;
	const liveCutover = options.liveCutover ?? false;
	if (!strict) {
		return {
			status: "input_error",
			exitCode: 2,
			mode: { strict: true, dryRun },
			...emptyCutoverReportMetadata(),
			gates: [
				{
					name: "inputs.strict",
					status: "fail",
					detail: "non-strict cutover evaluation is not supported",
				},
			],
		};
	}

	const parsed = CutoverInputBundleSchema.safeParse(input);
	if (!parsed.success) {
		return {
			status: "input_error",
			exitCode: 2,
			mode: { strict: true, dryRun },
			...emptyCutoverReportMetadata(),
			gates: [{ name: "inputs.valid", status: "fail", detail: flattenZodError(parsed.error) }],
		};
	}

	const bundle = parsed.data;
	const gates: CutoverReport["gates"] = [];
	const proofBundleResult = checkCutoverProofBundle({
		bundle: bundle.cutoverProofBundle,
		cutover: bundle,
		liveCutover,
		now: options.now,
	});
	const invalidEvidence = proofBundleResult.invalidEvidence;
	gates.push(...proofBundleResult.gates);
	const included = bundle.scopeManifest.workflows.filter(
		(workflow) => workflow.status === "included",
	);
	const includedWorkflowIds = new Set(included.map((workflow) => workflow.workflow_id));
	const scopedWorkflowIds = new Set(
		bundle.scopeManifest.workflows.map((workflow) => workflow.workflow_id),
	);
	const activeInventoryWorkflowIds = new Set(
		bundle.inventory.workflows
			.filter((workflow) => workflow.active)
			.map((workflow) => workflow.workflow_id),
	);
	const unmappedActiveWorkflowIds = [...activeInventoryWorkflowIds].filter(
		(workflowId) => !scopedWorkflowIds.has(workflowId),
	);
	const duplicateScopeWorkflowIds = findDuplicates(
		bundle.scopeManifest.workflows.map((workflow) => workflow.workflow_id),
	);
	const workflowScopeFailures = [
		...(included.length === 0 ? ["no included workflows"] : []),
		...duplicateScopeWorkflowIds.map((id) => `duplicate scope workflow ${id}`),
		...unmappedActiveWorkflowIds.map((id) => `active inventory workflow ${id} is unmapped`),
		...included.flatMap((workflow) => {
			const failures: string[] = [];
			if (!workflow.rollback_owner) failures.push(`${workflow.workflow_id} missing rollback_owner`);
			if (workflow.fixture_ids.length === 0)
				failures.push(`${workflow.workflow_id} missing fixtures`);
			if (workflow.negative_fixture_ids.length === 0) {
				failures.push(`${workflow.workflow_id} missing negative fixtures`);
			}
			if (workflow.required_surface_ids.length === 0) {
				failures.push(`${workflow.workflow_id} missing required surfaces`);
			}
			return failures;
		}),
	];
	const decisionById = new Map(
		bundle.decisionLog.decisions.map((decision) => [decision.id, decision]),
	);
	const unresolvedDecisionFailures = [
		...included.flatMap((workflow) =>
			workflow.unresolved_decision_ids.map((id) =>
				decisionById.has(id)
					? `${workflow.workflow_id} still lists unresolved decision ${id}`
					: `${workflow.workflow_id} references unknown unresolved decision ${id}`,
			),
		),
		...bundle.decisionLog.decisions.flatMap((decision) =>
			decision.status === "unresolved" && decision.affected_workflows.length === 0
				? [`unresolved decision ${decision.id} has no affected workflows and is treated as global`]
				: [],
		),
		...bundle.decisionLog.decisions.flatMap((decision) =>
			decision.status === "unresolved"
				? decision.affected_workflows
						.filter((workflowId) => includedWorkflowIds.has(workflowId))
						.map((workflowId) => `unresolved decision ${decision.id} affects ${workflowId}`)
				: [],
		),
	];
	const profileGenerationFailures = profileGenerationProofFailures(
		bundle,
		includedWorkflowIds,
		decisionById.get(PROFILE_GENERATION_DECISION_ID),
	);
	const requiredSurfaceIds = unique(included.flatMap((workflow) => workflow.required_surface_ids));
	const probeBySurfaceId = new Map(
		bundle.featureProbeMatrix.probes.map((probe) => [probe.surface_id, probe]),
	);
	const featureProbeEvidenceBySurfaceId = new Map(
		(bundle.featureProbeEvidence?.results ?? []).map((result) => [result.surface_id, result]),
	);
	const requiredSurfaceFailures = requiredSurfaceIds.flatMap((surfaceId) => {
		const probe = probeBySurfaceId.get(surfaceId);
		if (!probe) return [`missing feature probe ${surfaceId}`];
		const failure = featureProbeFailure(probe, featureProbeEvidenceBySurfaceId.get(surfaceId));
		if (failure) return [failure];
		return [];
	});
	const featureProbeFailures = [
		...(bundle.featureProbeMatrix.probes.length === 0 ? ["feature probe matrix is empty"] : []),
		...(requiredSurfaceIds.length === 0 ? ["no required surfaces declared"] : []),
		...requiredSurfaceFailures,
		...bundle.featureProbeMatrix.probes.flatMap((probe) => {
			const failure = featureProbeFailure(
				probe,
				featureProbeEvidenceBySurfaceId.get(probe.surface_id),
			);
			return failure ? [failure] : [];
		}),
	];
	const lockfileProbeBySurfaceId = new Map(
		bundle.lockfile.featureProbes.map((probe) => [probe.surface_id, probe]),
	);
	const matrixProbeBySurfaceId = new Map(
		bundle.featureProbeMatrix.probes.map((probe) => [probe.surface_id, probe]),
	);
	const lockfileFailures = [
		...lockfileEvidenceFailures(bundle.lockfile, bundle.noForkProof),
		...(bundle.lockfile.featureProbeMatrixDigest ===
		computeHermesArtifactDigest(bundle.featureProbeMatrix)
			? []
			: ["lockfile feature-probe matrix digest does not match current matrix"]),
		...bundle.lockfile.featureProbes.flatMap((probe) =>
			probe.status === "pass"
				? []
				: [`lockfile feature probe ${probe.surface_id} status is ${probe.status}`],
		),
		...bundle.lockfile.featureProbes.flatMap((probe) => {
			const matrixProbe = matrixProbeBySurfaceId.get(probe.surface_id);
			if (!matrixProbe) return [];
			return matrixProbe.status === probe.status
				? []
				: [
						`lockfile feature probe ${probe.surface_id} status ${probe.status} does not match feature matrix status ${matrixProbe.status ?? "missing"}`,
					];
		}),
		...bundle.featureProbeMatrix.probes.flatMap((probe) =>
			sameJson(probe.hermes_pin, bundle.lockfile.hermes)
				? []
				: [`feature probe ${probe.surface_id} is not tied to the lockfile Hermes pin`],
		),
		...requiredSurfaceIds.flatMap((surfaceId) => {
			const lockedProbe = lockfileProbeBySurfaceId.get(surfaceId);
			if (!lockedProbe) return [`lockfile is missing feature probe ${surfaceId}`];
			if (lockedProbe.status !== "pass")
				return [`lockfile feature probe ${surfaceId} status is ${lockedProbe.status}`];
			return [];
		}),
	];
	const requiredFixtureIds = unique(
		included.flatMap((workflow) => [...workflow.fixture_ids, ...workflow.negative_fixture_ids]),
	);
	const fixtureById = new Map(bundle.fixtureResults.results.map((result) => [result.id, result]));
	const fixtureFailures = [
		...(bundle.fixtureResults.results.length === 0 ? ["fixture result bundle is empty"] : []),
		...(requiredFixtureIds.length === 0 ? ["no required fixtures declared"] : []),
		...requiredFixtureIds.flatMap((fixtureId) => {
			const result = fixtureById.get(fixtureId);
			if (!result) return [`missing fixture result ${fixtureId}`];
			if (result.status !== "pass") return [`fixture ${fixtureId} status is ${result.status}`];
			const evidenceFailure = fixtureEvidenceFailure(result);
			if (evidenceFailure) return [evidenceFailure];
			return [];
		}),
		...bundle.fixtureResults.results.flatMap((result) => {
			if (result.status !== "pass") return [`fixture ${result.id} status is ${result.status}`];
			const evidenceFailure = fixtureEvidenceFailure(result);
			return evidenceFailure ? [evidenceFailure] : [];
		}),
	];
	const noForkFailures = noForkProofEvidenceFailures(bundle.noForkProof);
	const rollbackRehearsalFailures = rollbackRehearsalEvidenceFailures(bundle.rollbackRehearsal);
	const queueSnapshotFailures = queueSnapshotEvidenceFailures(
		bundle.inventory,
		bundle.queueSnapshot,
	);
	const networkProbeById = new Map(bundle.networkProbes.probes.map((probe) => [probe.id, probe]));
	const networkProbeFailures = [
		...(bundle.networkProbes.probes.length === 0 ? ["network probe bundle is empty"] : []),
		...findDuplicates(bundle.networkProbes.probes.map((probe) => probe.id)).map(
			(id) => `duplicate network probe ${id}`,
		),
		...REQUIRED_CUTOVER_NETWORK_PROBE_IDS.flatMap((probeId) => {
			const probe = networkProbeById.get(probeId);
			if (!probe) return [`missing network probe ${probeId}`];
			return [];
		}),
		...bundle.networkProbes.probes.flatMap((probe) => networkProbeEvidenceFailures(probe)),
	];

	gates.push({
		name: "workflow.scope",
		status: workflowScopeFailures.length === 0 ? "pass" : "fail",
		detail:
			workflowScopeFailures.length === 0
				? "included workflows are inventoried and have owner, trust domain, fixtures, surfaces, and rollback owners"
				: workflowScopeFailures.join("; "),
	});
	gates.push({
		name: "decisions.resolved",
		status: unresolvedDecisionFailures.length === 0 ? "pass" : "fail",
		detail:
			unresolvedDecisionFailures.length === 0
				? "included workflows do not depend on unresolved decisions"
				: unresolvedDecisionFailures.join("; "),
	});
	gates.push({
		name: "profileGeneration.proven",
		status: profileGenerationFailures.length === 0 ? "pass" : "fail",
		detail:
			profileGenerationFailures.length === 0
				? "profile generation proof is schema-valid, covers included workflows, and is tied to the lockfile"
				: unique(profileGenerationFailures).join("; "),
	});
	gates.push({
		name: "featureProbes.pass",
		status: featureProbeFailures.length === 0 ? "pass" : "fail",
		detail:
			featureProbeFailures.length === 0
				? "feature probes for included surfaces passed"
				: unique(featureProbeFailures).join("; "),
	});
	gates.push({
		name: "lockfile.consistent",
		status: lockfileFailures.length === 0 ? "pass" : "fail",
		detail:
			lockfileFailures.length === 0
				? "compatibility lockfile is tied to the pinned probes and included surfaces"
				: unique(lockfileFailures).join("; "),
	});
	gates.push({
		name: "fixtures.pass",
		status: fixtureFailures.length === 0 ? "pass" : "fail",
		detail:
			fixtureFailures.length === 0
				? "required parity and negative fixtures passed"
				: unique(fixtureFailures).join("; "),
	});
	gates.push({
		name: "nofork.clean",
		status: noForkFailures.length === 0 ? "pass" : "fail",
		detail:
			noForkFailures.length === 0
				? "pinned Hermes checkout proof passed from schema-valid evidence"
				: unique(noForkFailures).join("; "),
	});
	gates.push({
		name: "networkProbes.pass",
		status: networkProbeFailures.length === 0 ? "pass" : "fail",
		detail:
			networkProbeFailures.length === 0
				? "required network-denial probes passed"
				: unique(networkProbeFailures).join("; "),
	});
	gates.push({
		name: "queues.owned",
		status:
			queueSnapshotFailures.length === 0 && bundle.queueSnapshot.unownedActiveCount === 0
				? "pass"
				: "fail",
		detail:
			queueSnapshotFailures.length === 0 && bundle.queueSnapshot.unownedActiveCount === 0
				? "active queues, approvals, cards, cron, social, and provider work must be owned"
				: unique([
						...queueSnapshotFailures,
						...(bundle.queueSnapshot.unownedActiveCount > 0
							? [
									`${String(
										bundle.queueSnapshot.unownedActiveCount,
									)} unowned active queue item(s) remain`,
								]
							: []),
					]).join("; "),
	});
	gates.push({
		name: "rollback.rehearsed",
		status: rollbackRehearsalFailures.length === 0 ? "pass" : "fail",
		detail:
			rollbackRehearsalFailures.length === 0
				? "rollback rehearsal passed from schema-valid evidence"
				: unique(rollbackRehearsalFailures).join("; "),
	});

	const safe = gates.every((gate) => gate.status === "pass");
	return {
		status: invalidEvidence ? "input_error" : safe ? "safe" : "fail",
		exitCode: invalidEvidence ? 2 : safe ? 0 : 1,
		mode: { strict: true, dryRun },
		gates,
		...cutoverReportMetadata(bundle, included),
	};
}

function checkCutoverProofBundle(input: {
	bundle: CutoverProofBundle;
	cutover: CutoverInputBundle;
	liveCutover?: boolean;
	now?: Date;
}): { gates: CutoverReport["gates"]; invalidEvidence: boolean } {
	const gates: CutoverReport["gates"] = [];
	let invalidEvidence = false;
	const proofBundleGeneratedAtMs = Date.parse(input.bundle.generatedAt);
	const proofBundleGeneratedAt = new Date(proofBundleGeneratedAtMs);
	if (Number.isNaN(proofBundleGeneratedAtMs)) {
		invalidEvidence = true;
		gates.push({
			name: "proofBundle.generatedAt",
			status: "fail",
			detail: "proof bundle generatedAt is invalid",
		});
	} else if (
		input.liveCutover === true &&
		input.now &&
		isStaleEvidenceTimestamp(input.bundle.generatedAt, input.now)
	) {
		invalidEvidence = true;
		gates.push({
			name: "proofBundle.generatedAt.live",
			status: "fail",
			detail: "proof bundle generatedAt is stale or future-dated for live cutover",
		});
	}
	if (!sameJson(input.bundle.hermes, input.cutover.lockfile.hermes)) {
		invalidEvidence = true;
		gates.push({
			name: "proofBundle.hermes",
			status: "fail",
			detail: "proof bundle Hermes pin does not match compatibility lockfile",
		});
	}
	if (input.bundle.wrapper.version !== input.cutover.lockfile.wrapperPackageVersion) {
		invalidEvidence = true;
		gates.push({
			name: "proofBundle.wrapper",
			status: "fail",
			detail: "proof bundle wrapper version does not match compatibility lockfile",
		});
	}

	for (const key of CUTOVER_PROOF_ARTIFACT_KEYS) {
		const artifact = input.bundle.artifacts[key];
		const value = cutoverProofArtifactValue(input.cutover, key);
		const loaded = readCutoverProofArtifact(artifact);
		const failures: string[] = [];
		if (!loaded.ok) {
			failures.push(loaded.failure);
		} else {
			const semanticFailures = cutoverProofArtifactSemanticFailures(key, loaded.value);
			const expectedStatus =
				loaded.redaction.status === "pass" &&
				loaded.leakScan.status === "pass" &&
				semanticFailures.length === 0
					? "pass"
					: "fail";
			if (artifact.sha256 !== loaded.sha256) {
				failures.push("artifact hash does not match on-disk bytes");
			}
			if (artifact.schemaVersion !== schemaVersionOf(loaded.value)) {
				failures.push("artifact schema version does not match on-disk evidence");
			}
			const loadedGeneratedAt = getEvidenceTimestamp(loaded.value);
			if (loadedGeneratedAt && artifact.generatedAt !== loadedGeneratedAt) {
				failures.push("artifact generatedAt does not match on-disk evidence");
			}
			if (stableStringify(loaded.value) !== stableStringify(value)) {
				failures.push("artifact on-disk evidence does not match checker input");
			}
			if (loaded.redaction.status !== "pass") {
				failures.push("artifact byte redaction scan failed");
			}
			if (loaded.leakScan.status !== "pass") {
				failures.push("artifact byte leak scan failed");
			}
			if (
				artifact.redaction.status !== loaded.redaction.status ||
				artifact.leakScan.status !== loaded.leakScan.status
			) {
				failures.push("artifact recorded scan results do not match on-disk bytes");
			}
			if (artifact.status !== expectedStatus) {
				failures.push("artifact status does not match on-disk semantic evidence");
			}
		}
		if (artifact.checkIds.length === 0) failures.push("artifact check IDs are missing");
		if (artifact.schemaVersion !== schemaVersionOf(value)) {
			failures.push("artifact schema version does not match checker input");
		}
		if (
			!Number.isNaN(proofBundleGeneratedAtMs) &&
			isStaleEvidenceTimestamp(artifact.generatedAt, proofBundleGeneratedAt)
		) {
			failures.push("artifact is stale, future-dated, or has an invalid timestamp");
		}

		if (failures.length > 0) {
			invalidEvidence = true;
			gates.push({
				name: `proofBundle.${key}.valid`,
				status: "fail",
				detail: `proof bundle artifact ${key} invalid: ${unique(failures).join("; ")}`,
			});
		} else {
			gates.push({
				name: `proofBundle.${key}`,
				status: "pass",
				detail: `proof bundle binds ${key} to ${artifact.artifactPath}`,
			});
		}
	}

	if (!invalidEvidence) {
		gates.push({
			name: "proofBundle.complete",
			status: "pass",
			detail: "proof bundle binds all strict cutover artifacts",
		});
	}
	return { gates, invalidEvidence };
}

function cutoverProofArtifactValue(
	cutover: CutoverInputBundle,
	key: CutoverProofArtifactKey,
): unknown {
	switch (key) {
		case "inventory":
			return cutover.inventory;
		case "scopeManifest":
			return cutover.scopeManifest;
		case "decisionLog":
			return cutover.decisionLog;
		case "compatibilityLockfile":
			return cutover.lockfile;
		case "featureProbeMatrix":
			return cutover.featureProbeMatrix;
		case "fixtureResults":
			return cutover.fixtureResults;
		case "noForkProof":
			return cutover.noForkProof;
		case "networkProbeBundle":
			return cutover.networkProbes;
		case "queueSnapshot":
			return cutover.queueSnapshot;
		case "rollbackEvidence":
			return cutover.rollbackRehearsal;
	}
}

function readCutoverProofArtifact(
	artifact: CutoverProofBundle["artifacts"][CutoverProofArtifactKey],
):
	| {
			ok: true;
			value: unknown;
			sha256: string;
			redaction: { status: "pass" | "fail"; summary: string };
			leakScan: { status: "pass" | "fail"; summary: string };
	  }
	| { ok: false; failure: string } {
	try {
		const bytes = fs.readFileSync(resolveHermesArtifactPath(artifact.artifactPath));
		const text = bytes.toString("utf8");
		return {
			ok: true,
			value: JSON.parse(text) as unknown,
			sha256: sha256Digest(bytes),
			redaction: scanCutoverProofArtifactRedaction(text),
			leakScan: scanCutoverProofArtifactLeaks(text),
		};
	} catch (error) {
		return {
			ok: false,
			failure: `unreadable or malformed artifact bytes: ${redactDetail(
				error instanceof Error ? error.message : String(error),
			)}`,
		};
	}
}

function emptyCutoverReportMetadata(): Omit<
	CutoverReport,
	"status" | "exitCode" | "mode" | "gates"
> {
	return {
		workflowIds: [],
		evidencePaths: [],
		decisionIds: [],
		downgradeNotes: [],
		remediationOwners: [],
	};
}

function cutoverReportMetadata(
	bundle: CutoverInputBundle,
	included: CutoverScopeManifest["workflows"],
): Omit<CutoverReport, "status" | "exitCode" | "mode" | "gates"> {
	const includedWorkflowIds = new Set(included.map((workflow) => workflow.workflow_id));
	const relevantDecisions = bundle.decisionLog.decisions.filter(
		(decision) =>
			decision.affected_workflows.length === 0 ||
			decision.affected_workflows.some((workflowId) => includedWorkflowIds.has(workflowId)),
	);
	return {
		workflowIds: [...includedWorkflowIds].sort(),
		evidencePaths: unique([
			...bundle.featureProbeMatrix.probes.map((probe) => probe.evidence_path),
			...bundle.fixtureResults.results.map((result) => result.evidence_path),
			bundle.noForkProof.evidence_path,
			...(bundle.profileGenerationProof ? [bundle.profileGenerationProof.evidence_path] : []),
			...bundle.networkProbes.probes.map((probe) => probe.evidence_path),
			bundle.rollbackRehearsal.evidence_path,
		]).sort(),
		decisionIds: relevantDecisions.map((decision) => decision.id).sort(),
		downgradeNotes: relevantDecisions
			.flatMap((decision) => (decision.downgrade_note ? [decision.downgrade_note] : []))
			.sort(),
		remediationOwners: unique([
			...included.flatMap((workflow) => [workflow.owner, workflow.rollback_owner ?? ""]),
			...relevantDecisions.map((decision) => decision.owner),
		])
			.filter((owner) => owner.length > 0)
			.sort(),
	};
}

function profileGenerationProofFailures(
	bundle: CutoverInputBundle,
	includedWorkflowIds: ReadonlySet<string>,
	decision: DecisionLog["decisions"][number] | undefined,
): string[] {
	if (includedWorkflowIds.size === 0) {
		return [];
	}
	if (!decision) {
		return [`missing required decision ${PROFILE_GENERATION_DECISION_ID}`];
	}
	if (decision.status !== "accepted") {
		return [
			`decision ${PROFILE_GENERATION_DECISION_ID} is ${decision.status}; profile generation proof is required for included workflows`,
		];
	}
	const decisionCoversIncluded =
		decision.affected_workflows.length === 0 ||
		decision.affected_workflows.some((workflowId) => includedWorkflowIds.has(workflowId));
	if (!decisionCoversIncluded) {
		return [`decision ${PROFILE_GENERATION_DECISION_ID} does not cover included workflows`];
	}
	if (!bundle.profileGenerationProof) {
		return [`accepted decision ${PROFILE_GENERATION_DECISION_ID} has no profile-generation proof`];
	}
	const failures = profileGenerationEvidenceFailures(
		bundle.profileGenerationProof,
		bundle.lockfile,
	);
	if (
		decision.evidence_path &&
		!sameResolvedArtifactPath(decision.evidence_path, bundle.profileGenerationProof.evidence_path)
	) {
		failures.push(
			`decision ${PROFILE_GENERATION_DECISION_ID} evidence_path does not match profile-generation proof`,
		);
	}
	return failures;
}

function profileGenerationEvidenceFailures(
	proof: ProfileGenerationProof,
	lockfile: CompatibilityLockfile,
): string[] {
	const failures = placeholderFailures("profile-generation proof", proof);
	if (proof.status !== "pass") {
		failures.push(`profile-generation proof status is ${proof.status}`);
	}
	if (!sameJson(proof.pin, lockfile.hermes)) {
		failures.push("profile-generation proof pin does not match compatibility lockfile Hermes pin");
	}
	const expectedLockfileDigest = computeHermesArtifactDigest(lockfile);
	if (proof.lockfileDigest !== expectedLockfileDigest) {
		failures.push("profile-generation proof lockfileDigest does not match current lockfile");
	}
	if (proof.treeDigest !== computeProfileTreeDigest(proof.directoryInventory)) {
		failures.push("profile-generation proof treeDigest does not match directory inventory");
	}
	if (
		proof.manifestDigest !==
		computeProfileManifestDigest(proof.outputs, proof.secretManifest, proof.treeDigest)
	) {
		failures.push("profile-generation proof manifestDigest does not match outputs");
	}
	if (!sameJson(proof.secretManifest, profileSecretManifest())) {
		failures.push("profile-generation proof secret manifest does not match expected owners");
	}
	const expectedFiles = buildProfileFileContents({
		pin: proof.pin,
		lockfile,
		lockfileDigest: expectedLockfileDigest,
		secretManifest: profileSecretManifest(),
		generatedAt: proof.generatedAt,
	});
	const expectedInventory = expectedProfileDirectoryInventory(expectedFiles);
	let actualInventory: ProfileGenerationProof["directoryInventory"] | null = null;
	try {
		actualInventory = readProfileDirectoryInventory(proof.outDir);
	} catch (error) {
		failures.push(
			`profile-generation output inventory failed: ${redactDetail(
				error instanceof Error ? error.message : String(error),
			)}`,
		);
	}
	if (actualInventory && !sameJson(actualInventory, proof.directoryInventory)) {
		failures.push("profile-generation proof directoryInventory does not match output tree");
	}
	if (actualInventory && !sameJson(actualInventory, expectedInventory)) {
		failures.push("profile-generation output tree does not match canonical generated outputs");
	}
	if (actualInventory) {
		const sourceReplacementPaths = generatedProfileInventorySourceReplacementFailures(
			proof.outDir,
			actualInventory,
		);
		if (sourceReplacementPaths.length > 0) {
			failures.push(
				`profile-generation output contains Hermes source replacement artifacts: ${sourceReplacementPaths.join(", ")}`,
			);
		}
	}
	const loaded = readProfileGenerationProofEvidence(proof);
	if (!loaded.valid) {
		failures.push(loaded.failure);
	} else if (!sameJson(loaded.evidence, proof)) {
		failures.push("profile-generation proof evidence file does not match loaded proof");
	}
	const outputByPath = new Map(proof.outputs.map((output) => [output.path, output]));
	const expectedOutputByPath = new Map<string, GeneratedPathClass>(
		PROFILE_OUTPUT_DEFINITIONS.map((output) => [output.path, output.classification]),
	);
	for (const expected of PROFILE_OUTPUT_DEFINITIONS) {
		const output = outputByPath.get(expected.path);
		if (!output) {
			failures.push(`missing profile output ${expected.path}`);
			continue;
		}
		if (output.classification !== expected.classification) {
			failures.push(
				`profile output ${expected.path} classification is ${output.classification}, expected ${expected.classification}`,
			);
		}
	}
	for (const duplicate of findDuplicates(proof.outputs.map((output) => output.path))) {
		failures.push(`duplicate profile output ${duplicate}`);
	}
	for (const output of proof.outputs) {
		const expectedClassification = expectedOutputByPath.get(output.path);
		if (expectedClassification === undefined) {
			failures.push(`unexpected profile output ${output.path}`);
		}
		if (output.classification === "secret") {
			failures.push(`profile output ${output.path} is classified secret`);
		}
		const resolvedOutputPath = path.resolve(proof.outDir, output.path);
		const relativeToOutDir = path.relative(proof.outDir, resolvedOutputPath);
		if (relativeToOutDir.startsWith("..") || path.isAbsolute(relativeToOutDir)) {
			failures.push(`profile output ${output.path} escapes outDir`);
			continue;
		}
		if (!fs.existsSync(resolvedOutputPath)) {
			failures.push(`missing profile output file ${redactDetail(resolvedOutputPath)}`);
			continue;
		}
		const content = fs.readFileSync(resolvedOutputPath);
		const actualDigest = sha256Digest(content);
		if (actualDigest !== output.sha256) {
			failures.push(`profile output ${output.path} sha256 does not match file content`);
		}
		const expectedContent = expectedFiles.get(output.path);
		if (expectedContent === undefined) {
			failures.push(`profile output ${output.path} has no canonical generator template`);
		} else if (Buffer.compare(content, Buffer.from(expectedContent, "utf8")) !== 0) {
			failures.push(`profile output ${output.path} does not match canonical generator output`);
		}
		if (profileContentContainsRawSecret(content.toString("utf8"))) {
			failures.push(`profile output ${output.path} contains raw credential-like material`);
		}
	}
	const checkByName = new Map(proof.checks.map((check) => [check.name, check]));
	for (const duplicate of findDuplicates(proof.checks.map((check) => check.name))) {
		failures.push(`duplicate profile-generation check ${duplicate}`);
	}
	for (const checkName of REQUIRED_PROFILE_GENERATION_CHECK_NAMES) {
		const check = checkByName.get(checkName);
		if (!check) {
			failures.push(`missing profile-generation check ${checkName}`);
		} else if (check.status !== "pass") {
			failures.push(
				`profile-generation required check ${checkName} is fail: ${redactDetail(check.detail)}`,
			);
		}
	}
	for (const check of proof.checks) {
		if (check.status === "pass") continue;
		failures.push(
			`profile-generation check ${redactDetail(check.name)} is fail: ${redactDetail(check.detail)}`,
		);
	}
	return failures;
}

function readProfileGenerationProofEvidence(
	proof: ProfileGenerationProof,
): { valid: true; evidence: ProfileGenerationProof } | { valid: false; failure: string } {
	const resolvedPath = resolveHermesArtifactPath(proof.evidence_path);
	if (!fs.existsSync(resolvedPath)) {
		return {
			valid: false,
			failure: `missing profile-generation proof evidence: ${redactDetail(resolvedPath)}`,
		};
	}
	let evidence: unknown;
	try {
		evidence = readJsonFile(resolvedPath);
	} catch (error) {
		return {
			valid: false,
			failure: `unreadable profile-generation proof evidence: ${redactDetail(
				error instanceof Error ? error.message : String(error),
			)}`,
		};
	}
	const parsed = ProfileGenerationProofSchema.safeParse(evidence);
	if (!parsed.success) {
		return {
			valid: false,
			failure: `invalid profile-generation proof evidence: ${redactDetail(
				flattenZodError(parsed.error),
			)}`,
		};
	}
	if (!sameResolvedArtifactPath(parsed.data.evidence_path, proof.evidence_path)) {
		return {
			valid: false,
			failure: `profile-generation evidence_path is ${redactDetail(parsed.data.evidence_path)}`,
		};
	}
	return { valid: true, evidence: parsed.data };
}

function lockfileEvidenceFailures(
	lockfile: CompatibilityLockfile,
	noForkProof: NoForkProof,
): string[] {
	const failures: string[] = [];
	failures.push(...placeholderFailures("lockfile", lockfile));
	if (!SHA256_DIGEST_PATTERN.test(lockfile.featureProbeMatrixDigest)) {
		failures.push("lockfile featureProbeMatrixDigest is placeholder or invalid");
	}
	for (const [key, value] of Object.entries(lockfile.adapterApiSignatures)) {
		if (!SHA256_DIGEST_PATTERN.test(value)) {
			failures.push(`lockfile adapterApiSignatures.${key} is placeholder or invalid`);
		}
	}
	if (Object.keys(lockfile.adapterApiSignatures).length === 0) {
		failures.push("lockfile adapterApiSignatures is empty");
	}
	for (const [key, value] of Object.entries(lockfile.paritySuiteDigests)) {
		if (!SHA256_DIGEST_PATTERN.test(value)) {
			failures.push(`lockfile paritySuiteDigests.${key} is placeholder or invalid`);
		}
	}
	if (Object.keys(lockfile.paritySuiteDigests).length === 0) {
		failures.push("lockfile paritySuiteDigests is empty");
	}
	for (const [key, value] of Object.entries(lockfile.sourceDriftSignals)) {
		if (value !== undefined && !GIT_COMMIT_PATTERN.test(value)) {
			failures.push(`lockfile sourceDriftSignals.${key} is placeholder or invalid`);
		}
	}
	if (!lockfile.sourceDriftSignals.sourceCommit || !lockfile.sourceDriftSignals.docsCommit) {
		failures.push("lockfile sourceDriftSignals must include sourceCommit and docsCommit");
	}
	if (!sameResolvedArtifactPath(lockfile.noForkProofEvidencePath, noForkProof.evidence_path)) {
		failures.push("lockfile noForkProofEvidencePath does not match no-fork evidence path");
	}
	return failures;
}

function fixtureEvidenceFailure(result: FixtureResultBundle["results"][number]): string | null {
	const resultPlaceholders = placeholderFailures(`fixture result ${result.id}`, result);
	if (resultPlaceholders.length > 0) return resultPlaceholders.join("; ");
	const resolvedPath = resolveHermesArtifactPath(result.evidence_path);
	if (!fs.existsSync(resolvedPath)) {
		return `missing fixture evidence ${redactDetail(result.id)}: ${redactDetail(resolvedPath)}`;
	}
	let evidence: unknown;
	try {
		evidence = readJsonFile(resolvedPath);
	} catch (error) {
		return `unreadable fixture evidence ${redactDetail(result.id)}: ${redactDetail(
			error instanceof Error ? error.message : String(error),
		)}`;
	}
	const parsed = FixtureEvidenceSchema.safeParse(evidence);
	if (!parsed.success) {
		return `invalid fixture evidence ${redactDetail(result.id)}: ${redactDetail(
			flattenZodError(parsed.error),
		)}`;
	}
	const evidencePlaceholders = placeholderFailures(`fixture evidence ${result.id}`, parsed.data);
	if (evidencePlaceholders.length > 0) return evidencePlaceholders.join("; ");
	if (parsed.data.id !== result.id) {
		return `fixture evidence id mismatch for ${redactDetail(result.id)}`;
	}
	if (parsed.data.status !== "pass") {
		return `fixture evidence ${redactDetail(result.id)} status is ${parsed.data.status}`;
	}
	if (!sameResolvedArtifactPath(parsed.data.evidence_path, result.evidence_path)) {
		return `fixture evidence_path mismatch for ${redactDetail(result.id)}`;
	}
	const privateTelegramFailure = privateTelegramFixtureEvidenceFailure(result.id, parsed.data);
	if (privateTelegramFailure) return privateTelegramFailure;
	const providerDomainFailure = providerDomainFixtureEvidenceFailure(result.id, parsed.data);
	if (providerDomainFailure) return providerDomainFailure;
	const browserComputerFailure = browserComputerBrokerFixtureEvidenceFailure(result.id, evidence);
	if (browserComputerFailure) return browserComputerFailure;
	const workflowFailure = workflowFixtureEvidenceFailure(result.id, evidence);
	if (workflowFailure) return workflowFailure;
	return null;
}

function privateTelegramFixtureEvidenceFailure(
	fixtureId: string,
	evidence: z.infer<typeof FixtureEvidenceSchema>,
): string | null {
	const requirement = PRIVATE_TELEGRAM_FIXTURE_REQUIREMENTS.find(
		(candidate) => candidate.id === fixtureId,
	);
	if (!requirement) return null;
	const failures: string[] = [];
	if (evidence.provenance.runner !== "vitest-json") {
		failures.push(`fixture ${fixtureId} provenance runner is not vitest-json`);
	}
	if (evidence.provenance.source !== "machine-observed-test-report") {
		failures.push(`fixture ${fixtureId} provenance source is not machine-observed-test-report`);
	}
	if (!evidence.testReport) {
		failures.push(`fixture ${fixtureId} is missing machine-observed testReport`);
	} else {
		if (!sameJson(evidence.testReport.requiredTests, requirement.requiredTests)) {
			failures.push(`fixture ${fixtureId} requiredTests do not match the cutover contract`);
		}
		if (!sameJson(evidence.testReport.requiredAssertions, requirement.requiredAssertions)) {
			failures.push(`fixture ${fixtureId} requiredAssertions do not match the cutover contract`);
		}
		const reportPath = resolveHermesArtifactPath(evidence.testReport.path);
		if (!fs.existsSync(reportPath)) {
			failures.push(`fixture ${fixtureId} test report is missing`);
		} else {
			const digest = sha256Digest(fs.readFileSync(reportPath));
			if (digest !== evidence.testReport.sha256) {
				failures.push(`fixture ${fixtureId} test report sha256 does not match`);
			}
			try {
				const report = analyzeVitestFixtureReport(reportPath, requirement.requiredAssertions);
				failures.push(
					...report.failures.map(
						(failure) => `fixture ${fixtureId} test report ${redactDetail(failure)}`,
					),
				);
				for (const assertion of requirement.requiredAssertions) {
					const key = privateTelegramAssertionKey(assertion);
					const status = report.statuses.get(key);
					if (status !== "passed") {
						failures.push(
							`fixture ${fixtureId} required assertion ${redactDetail(
								assertion.fullName,
							)} status is ${status ?? "missing"}`,
						);
					}
				}
			} catch (error) {
				failures.push(
					`fixture ${fixtureId} test report is invalid: ${redactDetail(
						error instanceof Error ? error.message : String(error),
					)}`,
				);
			}
		}
	}
	if (!evidence.invocation) {
		failures.push(`fixture ${fixtureId} is missing Vitest invocation transcript`);
	} else if (evidence.testReport) {
		if (!sameResolvedArtifactPath(evidence.invocation.reportPath, evidence.testReport.path)) {
			failures.push(`fixture ${fixtureId} invocation reportPath does not match testReport.path`);
		}
		if (evidence.invocation.reportSha256 !== evidence.testReport.sha256) {
			failures.push(
				`fixture ${fixtureId} invocation reportSha256 does not match testReport.sha256`,
			);
		}
		failures.push(...privateTelegramInvocationFailures(fixtureId, evidence.invocation));
	}
	if (!evidence.checks || evidence.checks.length === 0) {
		failures.push(`fixture ${fixtureId} checks are missing`);
	} else {
		const checkByName = new Map(evidence.checks.map((check) => [check.name, check]));
		for (const duplicate of findDuplicates(evidence.checks.map((check) => check.name))) {
			failures.push(`fixture ${fixtureId} has duplicate check ${redactDetail(duplicate)}`);
		}
		for (const testName of requirement.requiredTests) {
			const check = checkByName.get(testName);
			if (!check) {
				failures.push(`fixture ${fixtureId} is missing check ${redactDetail(testName)}`);
			} else if (check.status !== "pass") {
				failures.push(`fixture ${fixtureId} check ${redactDetail(testName)} is ${check.status}`);
			}
		}
	}
	return failures.length > 0 ? failures.join("; ") : null;
}

export function privateTelegramAssertionKey(assertion: { file: string; fullName: string }): string {
	return `${path.normalize(assertion.file)}\0${assertion.fullName}`;
}

export function allPrivateTelegramRequiredAssertions(): Array<{ file: string; fullName: string }> {
	return PRIVATE_TELEGRAM_FIXTURE_REQUIREMENTS.flatMap((requirement) =>
		requirement.requiredAssertions.map((assertion) => ({ ...assertion })),
	);
}

export function analyzeVitestFixtureReport(
	testReportPath: string,
	requiredAssertions: ReadonlyArray<{ file: string; fullName: string }>,
): { statuses: Map<string, string>; failures: string[] } {
	const report = readJsonFile(testReportPath);
	if (typeof report !== "object" || report === null) {
		throw new Error("Vitest fixture report must be a JSON object");
	}
	const failures: string[] = [];
	if ((report as { success?: unknown }).success !== true) {
		failures.push("success is not true");
	}
	for (const field of ["numFailedTests", "numFailedTestSuites"] as const) {
		const value = (report as Record<string, unknown>)[field];
		if (value !== 0) failures.push(`${field} is ${String(value)}`);
	}
	const unhandledErrors = (report as { unhandledErrors?: unknown }).unhandledErrors;
	if (Array.isArray(unhandledErrors) && unhandledErrors.length > 0) {
		failures.push("unhandledErrors is not empty");
	}
	const testResults = (report as { testResults?: unknown }).testResults;
	if (!Array.isArray(testResults)) {
		throw new Error("Vitest fixture report is missing testResults");
	}
	const statusesByKey = new Map<string, string[]>();
	const requiredByFullName = new Map<string, Array<{ file: string; fullName: string }>>();
	for (const assertion of requiredAssertions) {
		const matches = requiredByFullName.get(assertion.fullName) ?? [];
		matches.push(assertion);
		requiredByFullName.set(assertion.fullName, matches);
	}
	for (const suite of testResults) {
		if (typeof suite !== "object" || suite === null) continue;
		const suiteName = (suite as { name?: unknown }).name;
		const suiteStatus = (suite as { status?: unknown }).status;
		const assertions = (suite as { assertionResults?: unknown }).assertionResults;
		if (!Array.isArray(assertions)) continue;
		for (const assertion of assertions) {
			if (typeof assertion !== "object" || assertion === null) continue;
			const fullName = (assertion as { fullName?: unknown }).fullName;
			const status = (assertion as { status?: unknown }).status;
			if (typeof fullName === "string" && typeof status === "string") {
				for (const required of requiredByFullName.get(fullName) ?? []) {
					if (typeof suiteName !== "string" || !vitestSuiteMatchesFile(suiteName, required.file)) {
						failures.push(
							`required assertion ${fullName} appeared in unexpected suite ${String(suiteName)}`,
						);
						continue;
					}
					if (suiteStatus !== "passed") {
						failures.push(`suite ${required.file} status is ${String(suiteStatus)}`);
					}
					const key = privateTelegramAssertionKey(required);
					statusesByKey.set(key, [...(statusesByKey.get(key) ?? []), status]);
				}
			}
		}
	}
	const statuses = new Map<string, string>();
	for (const assertion of requiredAssertions) {
		const key = privateTelegramAssertionKey(assertion);
		const matches = statusesByKey.get(key) ?? [];
		if (matches.length === 0) {
			failures.push(`required assertion ${assertion.fullName} is missing from ${assertion.file}`);
			continue;
		}
		if (matches.length > 1) {
			failures.push(
				`required assertion ${assertion.fullName} has duplicate matches in ${assertion.file}`,
			);
		}
		statuses.set(key, matches.at(-1) ?? "missing");
	}
	return { statuses, failures };
}

function vitestSuiteMatchesFile(suiteName: string, expectedFile: string): boolean {
	const normalizedSuite = path.normalize(suiteName);
	const normalizedExpected = path.normalize(expectedFile);
	return (
		normalizedSuite === normalizedExpected ||
		normalizedSuite.endsWith(`${path.sep}${normalizedExpected}`)
	);
}

function privateTelegramInvocationFailures(
	fixtureId: string,
	invocation: z.infer<typeof FixtureEvidenceSchema>["invocation"],
): string[] {
	if (!invocation) return [`fixture ${fixtureId} invocation is missing`];
	const failures: string[] = [];
	if (invocation.command[0] !== "pnpm" || invocation.command[1] !== "exec") {
		failures.push(`fixture ${fixtureId} invocation command is not pnpm exec`);
	}
	for (const testFile of PRIVATE_TELEGRAM_FIXTURE_TEST_FILES) {
		if (!invocation.command.includes(testFile)) {
			failures.push(`fixture ${fixtureId} invocation command is missing ${testFile}`);
		}
	}
	if (!invocation.command.includes("--reporter=json")) {
		failures.push(`fixture ${fixtureId} invocation command is missing --reporter=json`);
	}
	const outputFileArg = invocation.command.find((arg) => arg.startsWith("--outputFile="));
	if (!outputFileArg) {
		failures.push(`fixture ${fixtureId} invocation command is missing --outputFile`);
	}
	if (
		Number.isNaN(Date.parse(invocation.startedAt)) ||
		Number.isNaN(Date.parse(invocation.endedAt))
	) {
		failures.push(`fixture ${fixtureId} invocation timestamps are invalid`);
	}
	for (const sourcePath of PRIVATE_TELEGRAM_FIXTURE_DIGEST_PATHS) {
		const resolved = resolveHermesArtifactPath(sourcePath);
		const expectedDigest = invocation.sourceDigests[sourcePath];
		if (!expectedDigest) {
			failures.push(`fixture ${fixtureId} invocation source digest is missing ${sourcePath}`);
			continue;
		}
		if (!fs.existsSync(resolved)) {
			failures.push(`fixture ${fixtureId} invocation source file is missing ${sourcePath}`);
			continue;
		}
		const actualDigest = sha256Digest(fs.readFileSync(resolved));
		if (actualDigest !== expectedDigest) {
			failures.push(`fixture ${fixtureId} invocation source digest changed for ${sourcePath}`);
		}
	}
	return failures;
}

export function resolveHermesArtifactPath(relativePath: string): string {
	return path.resolve(relativePath);
}

function noForkProofEvidenceFailures(noForkProof: NoForkProof): string[] {
	const failures = noForkProof.hermesCheckoutClean
		? []
		: ["no-fork proof summary hermesCheckoutClean is false"];
	const loaded = readNoForkProofEvidence(noForkProof);
	if (!loaded.valid) return [...failures, loaded.failure];

	const evidence = loaded.evidence;
	failures.push(
		...placeholderFailures("no-fork evidence", {
			checkoutPath: evidence.checkoutPath,
			expectedRef: evidence.expectedRef,
			expectedVersion: evidence.expectedVersion,
			head: evidence.head,
			expectedRefCommit: evidence.expectedRefCommit,
			exactTags: evidence.exactTags,
			evidence_path: evidence.evidence_path,
		}),
	);
	if (!sameResolvedArtifactPath(evidence.evidence_path, noForkProof.evidence_path)) {
		failures.push(`no-fork evidence_path is ${redactDetail(evidence.evidence_path)}`);
	}
	if (evidence.hermesCheckoutClean !== true) {
		failures.push("no-fork evidence hermesCheckoutClean is false");
	}
	if (evidence.checks === undefined || evidence.checks.length === 0) {
		failures.push("no-fork evidence checks are empty");
	}
	for (const field of [
		"checkoutPath",
		"expectedRef",
		"expectedVersion",
		"head",
		"expectedRefCommit",
	]) {
		if (typeof evidence[field as keyof NoForkProof] !== "string") {
			failures.push(`no-fork evidence ${field} is missing`);
		}
	}
	if (
		typeof evidence.head === "string" &&
		typeof evidence.expectedRefCommit === "string" &&
		evidence.head !== evidence.expectedRefCommit
	) {
		failures.push("no-fork evidence HEAD does not match expectedRefCommit");
	}
	if (typeof evidence.head === "string" && !GIT_COMMIT_PATTERN.test(evidence.head)) {
		failures.push("no-fork evidence head is placeholder or invalid");
	}
	if (
		typeof evidence.expectedRefCommit === "string" &&
		!GIT_COMMIT_PATTERN.test(evidence.expectedRefCommit)
	) {
		failures.push("no-fork evidence expectedRefCommit is placeholder or invalid");
	}
	if (
		typeof evidence.expectedRef === "string" &&
		!(evidence.exactTags ?? []).includes(evidence.expectedRef)
	) {
		failures.push(
			`no-fork evidence exactTags does not include ${redactDetail(evidence.expectedRef)}`,
		);
	}
	if (evidence.statusPorcelain !== "") {
		failures.push("no-fork evidence statusPorcelain is not clean");
	}
	if (evidence.diffExitCode !== 0) {
		failures.push(`no-fork evidence diffExitCode is ${String(evidence.diffExitCode)}`);
	}
	if (evidence.cachedDiffExitCode !== 0) {
		failures.push(`no-fork evidence cachedDiffExitCode is ${String(evidence.cachedDiffExitCode)}`);
	}
	const checkByName = new Map((evidence.checks ?? []).map((check) => [check.name, check]));
	for (const duplicate of findDuplicates((evidence.checks ?? []).map((check) => check.name))) {
		failures.push(`duplicate no-fork evidence check ${redactDetail(duplicate)}`);
	}
	for (const checkName of REQUIRED_NO_FORK_CHECK_NAMES) {
		const check = checkByName.get(checkName);
		if (!check) {
			failures.push(`missing no-fork evidence check ${checkName}`);
		} else if (check.status !== "pass") {
			failures.push(
				`no-fork evidence required check ${redactDetail(checkName)} is fail: ${redactDetail(check.detail)}`,
			);
		}
	}
	for (const check of evidence.checks ?? []) {
		if (check.status === "pass") continue;
		failures.push(
			`no-fork evidence check ${redactDetail(check.name)} is fail: ${redactDetail(check.detail)}`,
		);
	}
	return failures;
}

function readNoForkProofEvidence(
	noForkProof: NoForkProof,
): { valid: true; evidence: NoForkProof } | { valid: false; failure: string } {
	const resolvedPath = resolveHermesArtifactPath(noForkProof.evidence_path);
	if (!fs.existsSync(resolvedPath)) {
		return {
			valid: false,
			failure: `missing no-fork proof evidence: ${redactDetail(resolvedPath)}`,
		};
	}
	let evidence: unknown;
	try {
		evidence = readJsonFile(resolvedPath);
	} catch (error) {
		return {
			valid: false,
			failure: `unreadable no-fork proof evidence: ${redactDetail(
				error instanceof Error ? error.message : String(error),
			)}`,
		};
	}
	const parsed = NoForkProofSchema.safeParse(evidence);
	if (!parsed.success) {
		return {
			valid: false,
			failure: `invalid no-fork proof evidence: ${redactDetail(flattenZodError(parsed.error))}`,
		};
	}
	return { valid: true, evidence: parsed.data };
}

function rollbackRehearsalEvidenceFailures(rollbackRehearsal: RollbackRehearsal): string[] {
	const failures = rollbackRehearsal.passed ? [] : ["rollback rehearsal summary passed is false"];
	const loaded = readRollbackRehearsalEvidence(rollbackRehearsal);
	if (!loaded.valid) return [...failures, loaded.failure];

	const evidence = loaded.evidence;
	if (!sameResolvedArtifactPath(evidence.evidence_path, rollbackRehearsal.evidence_path)) {
		failures.push(`rollback rehearsal evidence_path is ${redactDetail(evidence.evidence_path)}`);
	}
	if (evidence.passed !== true) {
		failures.push("rollback rehearsal evidence passed is false");
	}
	if (evidence.allowedToRun !== true) {
		failures.push("rollback rehearsal evidence allowedToRun is not true");
	}
	if (evidence.observedBeforeValue !== "1") {
		failures.push("rollback rehearsal evidence observedBeforeValue is not 1");
	}
	if (evidence.observedAfterValue !== "0") {
		failures.push("rollback rehearsal evidence observedAfterValue is not 0");
	}
	if (typeof evidence.observedFallbackPath !== "string") {
		failures.push("rollback rehearsal evidence observedFallbackPath is missing");
	}
	if (typeof evidence.observedAt !== "string") {
		failures.push("rollback rehearsal evidence observedAt is missing");
	}
	if (evidence.controlSurface !== HERMES_ROLLBACK_CONTROL_SURFACE) {
		failures.push("rollback rehearsal evidence controlSurface is not relay durable control");
	}
	if (evidence.observationSurface !== HERMES_ROLLBACK_OBSERVATION_SURFACE) {
		failures.push(
			"rollback rehearsal evidence observationSurface is not relay effective-mode status",
		);
	}
	if (evidence.observedBeforeSource !== "relay-effective-mode") {
		failures.push("rollback rehearsal evidence observedBeforeSource is not relay-effective-mode");
	}
	if (evidence.observedAfterSource !== "relay-effective-mode") {
		failures.push("rollback rehearsal evidence observedAfterSource is not relay-effective-mode");
	}
	if (evidence.observedAfterControlSource !== "runtime-config") {
		failures.push("rollback rehearsal evidence observedAfterControlSource is not runtime-config");
	}
	failures.push(...rollbackRelayPublicKeyFailures(evidence, rollbackRehearsal));
	failures.push(...rollbackRelayTranscriptFailures(evidence));
	if (evidence.checks === undefined || evidence.checks.length === 0) {
		failures.push("rollback rehearsal evidence checks are empty");
	}
	const checkNames = (evidence.checks ?? []).map((check) => check.name);
	const checkByName = new Map((evidence.checks ?? []).map((check) => [check.name, check]));
	for (const duplicate of findDuplicates(checkNames)) {
		failures.push(`duplicate rollback rehearsal evidence check ${redactDetail(duplicate)}`);
	}
	for (const checkName of REQUIRED_ROLLBACK_REHEARSAL_CHECK_NAMES) {
		const check = checkByName.get(checkName);
		if (!check) {
			failures.push(`missing rollback rehearsal evidence check ${checkName}`);
		} else if (check.status !== "pass") {
			failures.push(
				`rollback rehearsal required check ${redactDetail(checkName)} is fail: ${redactDetail(check.detail)}`,
			);
		}
	}
	for (const check of evidence.checks ?? []) {
		if (check.status === "pass") continue;
		failures.push(
			`rollback rehearsal evidence check ${redactDetail(check.name)} is fail: ${redactDetail(check.detail)}`,
		);
	}
	return failures;
}

function rollbackRelayPublicKeyFailures(
	evidence: RollbackRehearsal,
	rollbackRehearsal: RollbackRehearsal,
): string[] {
	const failures: string[] = [];
	if (!rollbackRehearsal.relayPublicKey) {
		failures.push("rollback rehearsal summary relay public key provenance is missing");
	} else if (evidence.relayPublicKey) {
		if (rollbackRehearsal.relayPublicKey.sha256 !== evidence.relayPublicKey.sha256) {
			failures.push("rollback rehearsal summary relay public key sha256 does not match evidence");
		}
		if (rollbackRehearsal.relayPublicKey.value !== evidence.relayPublicKey.value) {
			failures.push("rollback rehearsal summary relay public key value does not match evidence");
		}
		if (rollbackRehearsal.relayPublicKey.source !== evidence.relayPublicKey.source) {
			failures.push("rollback rehearsal summary relay public key source does not match evidence");
		}
	}
	if (!evidence.relayPublicKey) {
		failures.push("rollback rehearsal evidence relay public key provenance is missing");
		return failures;
	}
	const expectedDigest = sha256Digest(evidence.relayPublicKey.value);
	if (evidence.relayPublicKey.sha256 !== expectedDigest) {
		failures.push("rollback rehearsal evidence relay public key sha256 does not match value");
	}
	const trustedKey = trustedRollbackRelayPublicKey(evidence);
	if (!trustedKey.valid) {
		failures.push(trustedKey.failure);
	}
	return failures;
}

function trustedRollbackRelayPublicKey(
	evidence: RollbackRehearsal,
): { valid: true; value: string } | { valid: false; failure: string } {
	if (!evidence.relayPublicKey) {
		return {
			valid: false,
			failure: "rollback rehearsal evidence relay public key provenance is missing",
		};
	}
	const trustedValue = process.env[HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV]?.trim();
	if (!trustedValue) {
		return {
			valid: false,
			failure: `rollback rehearsal trusted relay public key env ${HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV} is missing`,
		};
	}
	if (evidence.relayPublicKey.value !== trustedValue) {
		return {
			valid: false,
			failure:
				"rollback rehearsal evidence relay public key does not match trusted relay public key",
		};
	}
	return { valid: true, value: trustedValue };
}

function rollbackRelayTranscriptFailures(evidence: RollbackRehearsal): string[] {
	const transcripts = evidence.signedRelayTranscripts;
	if (!transcripts) return ["rollback rehearsal signed relay transcripts are missing"];
	const trustedKey = trustedRollbackRelayPublicKey(evidence);
	if (!trustedKey.valid) return [trustedKey.failure];
	return [
		...rollbackRelayTranscriptFailure("before", transcripts.before, evidence, trustedKey.value, {
			method: "POST",
			path: "/v1/hermes.private-runtime.status",
			body: "{}",
			effectiveValue: "1",
			effectiveMode: "hermes",
		}),
		...rollbackRelayTranscriptFailure(
			"afterControl",
			transcripts.afterControl,
			evidence,
			trustedKey.value,
			{
				method: "POST",
				path: "/v1/hermes.private-runtime.mode",
				body: JSON.stringify({ mode: "legacy" }),
				effectiveValue: "0",
				controlMode: "legacy",
				controlSource: "runtime-config",
			},
		),
		...rollbackRelayTranscriptFailure("after", transcripts.after, evidence, trustedKey.value, {
			method: "POST",
			path: "/v1/hermes.private-runtime.status",
			body: "{}",
			effectiveValue: "0",
			effectiveMode: "legacy",
			controlSource: "runtime-config",
		}),
	];
}

function rollbackRelayTranscriptFailure(
	label: "before" | "afterControl" | "after",
	transcript: z.infer<typeof RollbackRelayTranscriptSchema>,
	evidence: RollbackRehearsal,
	trustedRelayPublicKey: string,
	expected: {
		method: string;
		path: string;
		body: string;
		effectiveValue: "1" | "0";
		effectiveMode?: "hermes" | "legacy";
		controlMode?: "hermes" | "legacy";
		controlSource?:
			| "env-disabled"
			| "runtime-config"
			| "runtime-config-default"
			| "runtime-config-invalid";
	},
): string[] {
	const failures: string[] = [];
	if (transcript.request.method !== expected.method) {
		failures.push(`rollback ${label} relay transcript method is ${transcript.request.method}`);
	}
	if (transcript.request.path !== expected.path) {
		failures.push(`rollback ${label} relay transcript path is ${transcript.request.path}`);
	}
	if (transcript.request.body !== expected.body) {
		failures.push(`rollback ${label} relay transcript body does not match`);
	}
	const proofFailure = internalResponseProofVerificationFailure(
		transcript.proof as InternalResponseProof,
		expected.method,
		expected.path,
		expected.body,
		transcript.responseBody,
		{
			scope: "operator",
			allowStale: true,
			relayPublicKey: trustedRelayPublicKey,
		},
	);
	if (proofFailure) {
		failures.push(`rollback ${label} relay transcript proof invalid: ${proofFailure}`);
		return failures;
	}
	const response = RollbackRelayStateBodySchema.safeParse(safeParseJson(transcript.responseBody));
	if (!response.success) {
		failures.push(`rollback ${label} relay transcript response body is invalid`);
		return failures;
	}
	if (response.data.effectiveValue !== expected.effectiveValue) {
		failures.push(
			`rollback ${label} relay transcript effectiveValue is ${response.data.effectiveValue}`,
		);
	}
	if (expected.effectiveMode && response.data.effectiveMode !== expected.effectiveMode) {
		failures.push(
			`rollback ${label} relay transcript effectiveMode is ${response.data.effectiveMode}`,
		);
	}
	if (expected.controlMode && response.data.controlMode !== expected.controlMode) {
		failures.push(`rollback ${label} relay transcript controlMode is ${response.data.controlMode}`);
	}
	if (expected.controlSource && response.data.controlSource !== expected.controlSource) {
		failures.push(
			`rollback ${label} relay transcript controlSource is ${response.data.controlSource}`,
		);
	}
	if (label === "before" && response.data.effectiveValue !== evidence.observedBeforeValue) {
		failures.push("rollback before relay transcript does not match observedBeforeValue");
	}
	if (label === "after" && response.data.effectiveValue !== evidence.observedAfterValue) {
		failures.push("rollback after relay transcript does not match observedAfterValue");
	}
	if (
		label === "afterControl" &&
		response.data.controlSource !== evidence.observedAfterControlSource
	) {
		failures.push(
			"rollback afterControl relay transcript does not match observedAfterControlSource",
		);
	}
	return failures;
}

function safeParseJson(value: string): unknown {
	try {
		return JSON.parse(value) as unknown;
	} catch {
		return undefined;
	}
}

function readRollbackRehearsalEvidence(
	rollbackRehearsal: RollbackRehearsal,
): { valid: true; evidence: RollbackRehearsal } | { valid: false; failure: string } {
	const resolvedPath = resolveHermesArtifactPath(rollbackRehearsal.evidence_path);
	if (!fs.existsSync(resolvedPath)) {
		return {
			valid: false,
			failure: `missing rollback rehearsal evidence: ${redactDetail(resolvedPath)}`,
		};
	}
	let evidence: unknown;
	try {
		evidence = readJsonFile(resolvedPath);
	} catch (error) {
		return {
			valid: false,
			failure: `unreadable rollback rehearsal evidence: ${redactDetail(
				error instanceof Error ? error.message : String(error),
			)}`,
		};
	}
	const parsed = RollbackRehearsalSchema.safeParse(evidence);
	if (!parsed.success) {
		return {
			valid: false,
			failure: `invalid rollback rehearsal evidence: ${redactDetail(
				flattenZodError(parsed.error),
			)}`,
		};
	}
	return { valid: true, evidence: parsed.data };
}

function networkProbeEvidenceFailures(probe: ProbeBundle["probes"][number]): string[] {
	const failures =
		probe.status === "pass" ? [] : [`network probe ${probe.id} status is ${probe.status}`];
	const loaded = readNetworkProbeEvidence(probe);
	if (!loaded.valid) return [...failures, loaded.failure];

	const evidence = loaded.evidence;
	if (evidence.id !== probe.id) {
		failures.push(`network probe evidence ${probe.id} id is ${redactDetail(evidence.id)}`);
	}
	if (!sameResolvedArtifactPath(evidence.evidence_path, probe.evidence_path)) {
		failures.push(
			`network probe evidence ${probe.id} evidence_path is ${redactDetail(evidence.evidence_path)}`,
		);
	}
	if (evidence.status !== "pass") {
		failures.push(`network probe evidence ${probe.id} status is ${evidence.status}`);
	}
	if (evidence.ran !== true) {
		failures.push(`network probe evidence ${probe.id} ran is ${String(evidence.ran)}`);
	}
	if (evidence.attempts.length === 0) {
		failures.push(`network probe evidence ${probe.id} attempts are empty`);
	}
	if (
		REQUIRED_CUTOVER_NETWORK_PROBE_ID_SET.has(probe.id) &&
		evidence.posture !== REQUIRED_CUTOVER_NETWORK_PROBE_POSTURE
	) {
		failures.push(
			`network probe evidence ${probe.id} posture is ${
				evidence.posture ?? "missing"
			}; expected ${REQUIRED_CUTOVER_NETWORK_PROBE_POSTURE}`,
		);
	}
	if (REQUIRED_CUTOVER_NETWORK_PROBE_ID_SET.has(probe.id) && !hasNetworkBoundaryProof(evidence)) {
		const posture = networkProbePosture(evidence);
		failures.push(
			posture === "contained-internal"
				? `network probe evidence ${probe.id} contained-internal denial proof is missing or not pass`
				: `network probe evidence ${probe.id} firewall_sentinel attempt is missing or not pass`,
		);
	}
	if (probe.id === "network.dns-exfil-denied" && !hasNonOverridableDnsGuard(evidence)) {
		failures.push(
			`network probe evidence ${probe.id} dns_guard lacks nonOverridable resolved address`,
		);
	}
	for (const attempt of evidence.attempts) {
		if (attempt.status === "pass") continue;
		failures.push(
			`network probe evidence ${probe.id} attempt ${redactDetail(
				attempt.name,
			)} status is ${attempt.status}: ${redactDetail(attempt.detail)}`,
		);
	}
	return failures;
}

function hasPassingFirewallSentinel(evidence: z.infer<typeof NetworkProbeEvidenceSchema>): boolean {
	return evidence.attempts.some(
		(attempt) => attempt.kind === "firewall_sentinel" && attempt.status === "pass",
	);
}

function networkProbePosture(
	evidence: z.infer<typeof NetworkProbeEvidenceSchema>,
): (typeof NETWORK_PROBE_POSTURES)[number] {
	return evidence.posture ?? "agent-iptables";
}

function hasNetworkBoundaryProof(evidence: z.infer<typeof NetworkProbeEvidenceSchema>): boolean {
	if (networkProbePosture(evidence) === "contained-internal") {
		return hasContainedInternalProof(evidence);
	}
	return hasPassingFirewallSentinel(evidence);
}

function hasContainedInternalProof(evidence: z.infer<typeof NetworkProbeEvidenceSchema>): boolean {
	switch (evidence.id) {
		case "network.relay-control-allowed":
			return evidence.attempts.some(
				(attempt) =>
					attempt.kind === "http" && attempt.expectation === "allow" && attempt.status === "pass",
			);
		case "network.direct-vault-denied":
			return evidence.attempts.some(
				(attempt) =>
					attempt.expectation === "deny" &&
					attempt.status === "pass" &&
					((attempt.kind === "unix_socket" && attempt.observed === "absent") ||
						hasPositiveContainedHttpDenial(attempt)),
			);
		default:
			return evidence.attempts.some(hasPositiveContainedHttpDenial);
	}
}

function hasPositiveContainedHttpDenial(
	attempt: z.infer<typeof NetworkProbeAttemptSchema>,
): boolean {
	return (
		(attempt.kind === "http" || attempt.kind === "dns_guard") &&
		attempt.expectation === "deny" &&
		attempt.status === "pass" &&
		attempt.observed === "denied" &&
		attempt.errorCode !== undefined &&
		POSITIVE_CONTAINED_DENIAL_ERROR_CODES.has(attempt.errorCode)
	);
}

function hasNonOverridableDnsGuard(evidence: z.infer<typeof NetworkProbeEvidenceSchema>): boolean {
	return evidence.attempts.some(
		(attempt) =>
			attempt.kind === "dns_guard" &&
			attempt.resolvedAddresses?.some((address) => address.nonOverridable) === true,
	);
}

function readNetworkProbeEvidence(
	probe: ProbeBundle["probes"][number],
):
	| { valid: true; evidence: z.infer<typeof NetworkProbeEvidenceSchema> }
	| { valid: false; failure: string } {
	const resolvedPath = resolveHermesArtifactPath(probe.evidence_path);
	if (!fs.existsSync(resolvedPath)) {
		return {
			valid: false,
			failure: `missing network probe evidence ${probe.id}: ${redactDetail(resolvedPath)}`,
		};
	}

	let evidence: unknown;
	try {
		evidence = readJsonFile(resolvedPath);
	} catch (error) {
		return {
			valid: false,
			failure: `unreadable network probe evidence ${probe.id}: ${redactDetail(
				error instanceof Error ? error.message : String(error),
			)}`,
		};
	}

	const parsed = NetworkProbeEvidenceSchema.safeParse(evidence);
	if (!parsed.success) {
		return {
			valid: false,
			failure: `invalid network probe evidence ${probe.id}: ${redactDetail(
				flattenZodError(parsed.error),
			)}`,
		};
	}
	return { valid: true, evidence: parsed.data };
}

function sameResolvedArtifactPath(left: string, right: string): boolean {
	return resolveHermesArtifactPath(left) === resolveHermesArtifactPath(right);
}

function redactDetail(detail: string): string {
	return redactSecrets(detail).replace(/\s+/g, " ").trim();
}

function placeholderFailures(label: string, value: unknown): string[] {
	const failures: string[] = [];
	collectPlaceholderFailures(label, value, failures);
	return failures;
}

function collectPlaceholderFailures(label: string, value: unknown, failures: string[]): void {
	if (typeof value === "string") {
		const normalized = value.trim().toLowerCase();
		if (PLACEHOLDER_VALUES.has(normalized) || normalized.startsWith("todo:")) {
			failures.push(`${label} is placeholder: ${redactDetail(value)}`);
		}
		return;
	}
	if (Array.isArray(value)) {
		value.forEach((item, index) => {
			collectPlaceholderFailures(`${label}[${index}]`, item, failures);
		});
		return;
	}
	if (typeof value !== "object" || value === null) return;
	for (const [key, nested] of Object.entries(value)) {
		collectPlaceholderFailures(`${label}.${key}`, nested, failures);
	}
}

function collectCliHeadlessProbeEvidence(
	probe: FeatureProbeMatrix["probes"][number],
): FeatureProbeEvidenceBundle["results"][number] {
	const resolvedPath = resolveHermesArtifactPath(probe.evidence_path);
	if (!fs.existsSync(resolvedPath)) {
		return featureProbeEvidenceFailure(
			probe,
			`missing feature probe evidence ${probe.surface_id}: ${resolvedPath}`,
		);
	}
	let evidence: unknown;
	try {
		evidence = readJsonFile(resolvedPath);
	} catch (error) {
		return featureProbeEvidenceFailure(
			probe,
			`unreadable feature probe evidence ${probe.surface_id}: ${String(
				error instanceof Error ? error.message : error,
			)}`,
		);
	}

	const parsed = CliHeadlessProbeEvidenceSchema.safeParse(evidence);
	if (!parsed.success) {
		return featureProbeEvidenceFailure(
			probe,
			`invalid feature probe evidence ${probe.surface_id}: ${flattenZodError(parsed.error)}`,
		);
	}

	const failures = [];
	if (parsed.data.status !== "pass") failures.push(`status is ${parsed.data.status}`);
	if (parsed.data.ran !== true) failures.push(`ran is ${String(parsed.data.ran)}`);
	if (parsed.data.exitCode !== 0) failures.push(`exitCode is ${parsed.data.exitCode}`);
	if (parsed.data.findings.length > 0) {
		failures.push(`findings are not empty (${parsed.data.findings.length})`);
	}
	const provenance = parsed.data.provenance;
	if (!provenance) {
		failures.push("provenance is missing");
	} else {
		if (provenance.proofTokenObserved !== true) {
			failures.push("provenance did not observe the expected proof token");
		}
		if (!parsed.data.stdoutPreview?.includes(provenance.expectedProofToken)) {
			failures.push("stdoutPreview does not contain the expected proof token");
		}
		if (provenance.invocationSha256 !== computeHermesArtifactDigest(parsed.data.invocation)) {
			failures.push("provenance invocationSha256 does not match invocation");
		}
		const stdoutPreview = parsed.data.stdoutPreview ?? "";
		const stderrPreview = parsed.data.stderrPreview ?? "";
		if (isTruncatedProbePreview(stdoutPreview)) {
			failures.push("stdoutPreview is truncated");
		}
		if (isTruncatedProbePreview(stderrPreview)) {
			failures.push("stderrPreview is truncated");
		}
		if (provenance.stdoutSha256 !== computeHermesTextDigest(stdoutPreview)) {
			failures.push("provenance stdoutSha256 does not match stdoutPreview");
		}
		if (provenance.stderrSha256 !== computeHermesTextDigest(stderrPreview)) {
			failures.push("provenance stderrSha256 does not match stderrPreview");
		}
		if (provenance.runtimeSha256 !== computeHermesArtifactDigest(parsed.data.runtime ?? null)) {
			failures.push("provenance runtimeSha256 does not match runtime");
		}
		if (
			provenance.relayProofSha256 !== computeHermesArtifactDigest(parsed.data.relayProof ?? null)
		) {
			failures.push("provenance relayProofSha256 does not match relayProof");
		}
		const startedAtMs = Date.parse(provenance.startedAt);
		const endedAtMs = Date.parse(provenance.endedAt);
		if (Number.isNaN(startedAtMs) || Number.isNaN(endedAtMs)) {
			failures.push("provenance timestamps are not parseable");
		} else if (startedAtMs > endedAtMs) {
			failures.push("provenance startedAt is after endedAt");
		}
	}
	const forbiddenEnvKeys = parsed.data.invocation.envKeys
		.filter((key) => isForbiddenCredentialKey(key))
		.sort((left, right) => left.localeCompare(right));
	if (forbiddenEnvKeys.length > 0) {
		failures.push(`forbidden credential envKeys: ${redactDetail(forbiddenEnvKeys.join(", "))}`);
	}
	if (!parsed.data.invocation.envKeys.includes("HERMES_INFERENCE_PROVIDER")) {
		failures.push("HERMES_INFERENCE_PROVIDER envKey is missing");
	}
	if (!parsed.data.invocation.envKeys.includes("HERMES_CODEX_BASE_URL")) {
		failures.push("HERMES_CODEX_BASE_URL envKey is missing");
	}
	if (!parsed.data.invocation.envKeys.includes("HERMES_INFERENCE_MODEL")) {
		failures.push("HERMES_INFERENCE_MODEL envKey is missing");
	}
	const modelProvider = parsed.data.modelProvider;
	if (!modelProvider) {
		failures.push("modelProvider is missing");
	} else {
		if (modelProvider.provider !== "openai-codex") {
			failures.push("modelProvider.provider is not openai-codex");
		}
		if (modelProvider.authScope !== "relay-openai-codex-subscription-proxy") {
			failures.push("modelProvider.authScope is not relay-openai-codex-subscription-proxy");
		}
		if (modelProvider.authLocation !== "hermes-auth-store:openai-codex") {
			failures.push("modelProvider.authLocation is not hermes-auth-store:openai-codex");
		}
		if (!modelProvider.model.trim()) {
			failures.push("modelProvider.model is missing");
		}
		if (modelProvider.modelSource !== "env:HERMES_INFERENCE_MODEL") {
			failures.push("modelProvider.modelSource is not env:HERMES_INFERENCE_MODEL");
		}
		if (!isRelayOpenAiCodexProxyUrl(modelProvider.baseUrl)) {
			failures.push("modelProvider.baseUrl is not a relay OpenAI Codex proxy URL");
		}
		if (modelProvider.auxiliaryAuthSource !== "manual:telclaude-relay") {
			failures.push("modelProvider.auxiliaryAuthSource is not manual:telclaude-relay");
		}
		if (modelProvider.refreshTokenPolicy !== "non-refreshable-placeholder") {
			failures.push("modelProvider.refreshTokenPolicy is not non-refreshable-placeholder");
		}
		if (!modelProvider.auxiliaryBaseUrl) {
			failures.push("modelProvider.auxiliaryBaseUrl is missing");
		} else if (!isRelayOpenAiCodexProxyUrl(modelProvider.auxiliaryBaseUrl)) {
			failures.push("modelProvider.auxiliaryBaseUrl is not a relay OpenAI Codex proxy URL");
		}
		if (!modelProvider.auxiliaryBaseUrlHost) {
			failures.push("modelProvider.auxiliaryBaseUrlHost is missing");
		} else {
			try {
				if (
					modelProvider.auxiliaryBaseUrl &&
					modelProvider.auxiliaryBaseUrlHost !== new URL(modelProvider.auxiliaryBaseUrl).hostname
				) {
					failures.push("modelProvider.auxiliaryBaseUrlHost does not match auxiliaryBaseUrl");
				}
			} catch {
				failures.push("modelProvider.auxiliaryBaseUrl is not parseable");
			}
		}
		try {
			if (modelProvider.baseUrlHost !== new URL(modelProvider.baseUrl).hostname) {
				failures.push("modelProvider.baseUrlHost does not match baseUrl");
			}
		} catch {
			failures.push("modelProvider.baseUrl is not parseable");
		}
	}
	const runtime = parsed.data.runtime;
	if (!runtime) {
		failures.push("runtime evidence is missing");
	} else {
		if (runtime.containerName !== "tc-hermes-contained") {
			failures.push("runtime containerName is not tc-hermes-contained");
		}
		if (!runtime.containerId.trim()) {
			failures.push("runtime containerId is missing");
		}
		if (!runtime.image.trim()) {
			failures.push("runtime image is missing");
		}
		if (!runtime.hostname.trim()) {
			failures.push("runtime hostname is missing");
		}
		if (!runtime.relayResolvedAddress.trim()) {
			failures.push("runtime relayResolvedAddress is missing");
		} else {
			const failure = runtimeContainerAddressFailure(
				"runtime relayResolvedAddress",
				runtime.relayResolvedAddress,
			);
			if (failure) failures.push(failure);
		}
		if (!runtime.containerIpAddress.trim()) {
			failures.push("runtime containerIpAddress is missing");
		} else {
			const failure = runtimeContainerAddressFailure(
				"runtime containerIpAddress",
				runtime.containerIpAddress,
			);
			if (failure) failures.push(failure);
		}
		if (!runtime.observedPeerAddress.trim()) {
			failures.push("runtime observedPeerAddress is missing");
		} else {
			const failure = runtimeContainerAddressFailure(
				"runtime observedPeerAddress",
				runtime.observedPeerAddress,
			);
			if (failure) failures.push(failure);
		}
		const expectedRelayAddress = expectedHermesRelayIp();
		const expectedContainedAddress = expectedHermesContainedIp();
		if (normalizeRuntimeAddress(runtime.relayResolvedAddress) !== expectedRelayAddress) {
			failures.push(
				`runtime relayResolvedAddress is ${runtime.relayResolvedAddress}, expected ${expectedRelayAddress}`,
			);
		}
		if (normalizeRuntimeAddress(runtime.containerIpAddress) !== expectedContainedAddress) {
			failures.push(
				`runtime containerIpAddress is ${runtime.containerIpAddress}, expected ${expectedContainedAddress}`,
			);
		}
		if (normalizeRuntimeAddress(runtime.observedPeerAddress) !== expectedContainedAddress) {
			failures.push(
				`runtime observedPeerAddress is ${runtime.observedPeerAddress}, expected ${expectedContainedAddress}`,
			);
		}
		if (
			normalizeRuntimeAddress(runtime.relayResolvedAddress) ===
			normalizeRuntimeAddress(runtime.observedPeerAddress)
		) {
			failures.push("runtime relayResolvedAddress matches observedPeerAddress");
		}
		if (
			normalizeRuntimeAddress(runtime.containerIpAddress) !==
			normalizeRuntimeAddress(runtime.observedPeerAddress)
		) {
			failures.push("runtime containerIpAddress does not match observedPeerAddress");
		}
	}
	const relayProof = parsed.data.relayProof;
	if (!relayProof) {
		failures.push("relay proof is missing");
	} else {
		if (relayProof.source !== HERMES_CLI_HEADLESS_RELAY_PROOF_SOURCE) {
			failures.push("relay proof source is not the OpenAI Codex proxy");
		}
		if (relayProof.method !== "POST") {
			failures.push("relay proof method is not POST");
		}
		if (relayProof.path !== HERMES_CODEX_RESPONSES_PATH) {
			failures.push("relay proof path is not the Codex responses endpoint");
		}
		if (relayProof.upstreamStatus < 200 || relayProof.upstreamStatus >= 300) {
			failures.push(`relay proof upstreamStatus is ${relayProof.upstreamStatus}`);
		}
		if (modelProvider && relayProof.model !== modelProvider.model) {
			failures.push("relay proof model does not match modelProvider model");
		}
		if (runtime) {
			if (
				normalizeRuntimeAddress(relayProof.observedPeerAddress) !==
				normalizeRuntimeAddress(runtime.observedPeerAddress)
			) {
				failures.push("relay proof observedPeerAddress does not match runtime observedPeerAddress");
			}
			if (
				normalizeRuntimeAddress(relayProof.observedPeerAddress) !==
				normalizeRuntimeAddress(runtime.containerIpAddress)
			) {
				failures.push("relay proof observedPeerAddress does not match containerIpAddress");
			}
		}
		const observedAtMs = Date.parse(relayProof.observedAt);
		const startedAtMs = provenance ? Date.parse(provenance.startedAt) : Number.NaN;
		const endedAtMs = provenance ? Date.parse(provenance.endedAt) : Number.NaN;
		if (Number.isNaN(observedAtMs)) {
			failures.push("relay proof observedAt is not parseable");
		} else if (
			!Number.isNaN(startedAtMs) &&
			!Number.isNaN(endedAtMs) &&
			(observedAtMs < startedAtMs || observedAtMs > endedAtMs)
		) {
			failures.push("relay proof observedAt is outside the probe window");
		}
	}
	if (failures.length > 0) {
		return featureProbeEvidenceFailure(
			probe,
			`feature probe evidence ${probe.surface_id} did not pass: ${failures.join("; ")}`,
		);
	}

	return {
		surface_id: probe.surface_id,
		status: "pass",
		evidence_path: probe.evidence_path,
		detail: `feature probe evidence ${probe.surface_id} observed pass, ran=true, exitCode=0, contained Docker runtime, and relay OpenAI Codex subscription proxy wiring`,
	};
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

function collectServedMcpContainmentProbeEvidence(
	probe: FeatureProbeMatrix["probes"][number],
): FeatureProbeEvidenceBundle["results"][number] {
	const resolvedPath = resolveHermesArtifactPath(probe.evidence_path);
	let evidence: unknown;
	try {
		evidence = readOptionalJsonFile(resolvedPath);
	} catch (error) {
		return featureProbeEvidenceFailure(
			probe,
			`unreadable feature probe evidence ${probe.surface_id}: ${redactDetail(
				String(error instanceof Error ? error.message : error),
			)}`,
		);
	}
	const report = evaluateServedMcpContainmentEvidence(evidence, { missingPath: resolvedPath });
	const failingGates = report.gates.filter((gate) => gate.status !== "pass");
	if (report.status !== "pass" || !report.productionEnable || failingGates.length > 0) {
		return featureProbeEvidenceFailure(
			probe,
			failingGates.map((gate) => gate.detail).join("; ") ||
				`served-MCP containment evidence status is ${report.status}`,
		);
	}
	return {
		surface_id: probe.surface_id,
		status: "pass",
		evidence_path: probe.evidence_path,
		detail: `feature probe evidence ${probe.surface_id} observed all served-MCP containment properties`,
	};
}

function collectEdgeAdapterProbeEvidence(
	probe: FeatureProbeMatrix["probes"][number],
): FeatureProbeEvidenceBundle["results"][number] {
	const resolvedPath = resolveHermesArtifactPath(probe.evidence_path);
	let evidence: unknown;
	try {
		evidence = readOptionalJsonFile(resolvedPath);
	} catch (error) {
		return featureProbeEvidenceFailure(
			probe,
			`unreadable feature probe evidence ${probe.surface_id}: ${redactDetail(
				String(error instanceof Error ? error.message : error),
			)}`,
		);
	}
	if (evidence === undefined) {
		return featureProbeEvidenceFailure(
			probe,
			`missing feature probe evidence ${probe.surface_id}: ${resolvedPath}`,
		);
	}
	const failure = edgeAdapterProbeEvidenceFailure(probe.surface_id, evidence);
	if (failure) {
		return featureProbeEvidenceFailure(
			probe,
			`feature probe evidence ${probe.surface_id} did not pass: ${redactDetail(failure)}`,
		);
	}
	const schemaOnlyFailure = schemaOnlyEdgeAdapterEnforcementFailure(probe.surface_id);
	if (schemaOnlyFailure) {
		return featureProbeEvidenceFailure(probe, schemaOnlyFailure);
	}
	return {
		surface_id: probe.surface_id,
		status: "pass",
		evidence_path: probe.evidence_path,
		detail: `feature probe evidence ${probe.surface_id} observed edge adapter contract controls`,
	};
}

function schemaOnlyEdgeAdapterEnforcementFailure(surfaceId: string): string | null {
	const signatureFiles = ADAPTER_SIGNATURE_FILES[surfaceId] ?? [];
	if (signatureFiles.length === 0) return null;
	const schemaOnly = signatureFiles.every((file) => EDGE_ADAPTER_CONTRACT_UNIT_FILES.has(file));
	if (!schemaOnly) return null;
	return `feature probe evidence ${surfaceId} is schema-only edge contract-unit evidence; runtime consumer/authorizer enforcement evidence is required before cutover pass`;
}

function collectSideEffectLedgerProbeEvidence(
	probe: FeatureProbeMatrix["probes"][number],
): FeatureProbeEvidenceBundle["results"][number] {
	const resolvedPath = resolveHermesArtifactPath(probe.evidence_path);
	let evidence: unknown;
	try {
		evidence = readOptionalJsonFile(resolvedPath);
	} catch (error) {
		return featureProbeEvidenceFailure(
			probe,
			`unreadable feature probe evidence ${probe.surface_id}: ${redactDetail(
				String(error instanceof Error ? error.message : error),
			)}`,
		);
	}
	if (evidence === undefined) {
		return featureProbeEvidenceFailure(
			probe,
			`missing feature probe evidence ${probe.surface_id}: ${resolvedPath}`,
		);
	}
	const failure = sideEffectLedgerProbeEvidenceFailure(probe.surface_id, evidence);
	if (failure) {
		return featureProbeEvidenceFailure(
			probe,
			`feature probe evidence ${probe.surface_id} did not pass: ${redactDetail(failure)}`,
		);
	}
	return {
		surface_id: probe.surface_id,
		status: "pass",
		evidence_path: probe.evidence_path,
		detail: `feature probe evidence ${probe.surface_id} observed MCP side-effect ledger controls`,
	};
}

function collectProviderApprovalBindingProbeEvidence(
	probe: FeatureProbeMatrix["probes"][number],
): FeatureProbeEvidenceBundle["results"][number] {
	const resolvedPath = resolveHermesArtifactPath(probe.evidence_path);
	let evidence: unknown;
	try {
		evidence = readOptionalJsonFile(resolvedPath);
	} catch (error) {
		return featureProbeEvidenceFailure(
			probe,
			`unreadable feature probe evidence ${probe.surface_id}: ${redactDetail(
				String(error instanceof Error ? error.message : error),
			)}`,
		);
	}
	if (evidence === undefined) {
		return featureProbeEvidenceFailure(
			probe,
			`missing feature probe evidence ${probe.surface_id}: ${resolvedPath}`,
		);
	}
	const failure = providerApprovalBindingProbeEvidenceFailure(evidence);
	if (failure) {
		return featureProbeEvidenceFailure(
			probe,
			`feature probe evidence ${probe.surface_id} did not pass: ${redactDetail(failure)}`,
		);
	}
	return {
		surface_id: probe.surface_id,
		status: "pass",
		evidence_path: probe.evidence_path,
		detail: `feature probe evidence ${probe.surface_id} observed provider approval-binding controls`,
	};
}

function collectProviderDomainProbeEvidence(
	probe: FeatureProbeMatrix["probes"][number],
): FeatureProbeEvidenceBundle["results"][number] {
	if (!isProviderDomainSurfaceId(probe.surface_id)) {
		return featureProbeEvidenceFailure(
			probe,
			`feature probe evidence ${probe.surface_id} is not a provider-domain surface`,
		);
	}
	const resolvedPath = resolveHermesArtifactPath(probe.evidence_path);
	let evidence: unknown;
	try {
		evidence = readOptionalJsonFile(resolvedPath);
	} catch (error) {
		return featureProbeEvidenceFailure(
			probe,
			`unreadable feature probe evidence ${probe.surface_id}: ${redactDetail(
				String(error instanceof Error ? error.message : error),
			)}`,
		);
	}
	if (evidence === undefined) {
		return featureProbeEvidenceFailure(
			probe,
			`missing feature probe evidence ${probe.surface_id}: ${resolvedPath}`,
		);
	}
	const failure = providerDomainProbeEvidenceFailure(probe.surface_id, evidence);
	if (failure) {
		return featureProbeEvidenceFailure(
			probe,
			`feature probe evidence ${probe.surface_id} did not pass: ${redactDetail(failure)}`,
		);
	}
	return {
		surface_id: probe.surface_id,
		status: "pass",
		evidence_path: probe.evidence_path,
		detail: `feature probe evidence ${probe.surface_id} observed provider-domain MCP/proxy controls`,
	};
}

function collectProviderReleasePolicyProbeEvidence(
	probe: FeatureProbeMatrix["probes"][number],
): FeatureProbeEvidenceBundle["results"][number] {
	const resolvedPath = resolveHermesArtifactPath(probe.evidence_path);
	let evidence: unknown;
	try {
		evidence = readOptionalJsonFile(resolvedPath);
	} catch (error) {
		return featureProbeEvidenceFailure(
			probe,
			`unreadable feature probe evidence ${probe.surface_id}: ${redactDetail(
				String(error instanceof Error ? error.message : error),
			)}`,
		);
	}
	if (evidence === undefined) {
		return featureProbeEvidenceFailure(
			probe,
			`missing feature probe evidence ${probe.surface_id}: ${resolvedPath}`,
		);
	}
	const failure = providerReleasePolicyProbeEvidenceFailure(evidence);
	if (failure) {
		return featureProbeEvidenceFailure(
			probe,
			`feature probe evidence ${probe.surface_id} did not pass: ${redactDetail(failure)}`,
		);
	}
	return {
		surface_id: probe.surface_id,
		status: "pass",
		evidence_path: probe.evidence_path,
		detail: `feature probe evidence ${probe.surface_id} observed provider release-policy controls`,
	};
}

function collectBrowserComputerBrokerProbeEvidence(
	probe: FeatureProbeMatrix["probes"][number],
): FeatureProbeEvidenceBundle["results"][number] {
	if (!isBrowserComputerBrokerSurfaceId(probe.surface_id)) {
		return featureProbeEvidenceFailure(
			probe,
			`feature probe evidence ${probe.surface_id} is not a browser/computer broker surface`,
		);
	}
	const resolvedPath = resolveHermesArtifactPath(probe.evidence_path);
	let evidence: unknown;
	try {
		evidence = readOptionalJsonFile(resolvedPath);
	} catch (error) {
		return featureProbeEvidenceFailure(
			probe,
			`unreadable feature probe evidence ${probe.surface_id}: ${redactDetail(
				String(error instanceof Error ? error.message : error),
			)}`,
		);
	}
	if (evidence === undefined) {
		return featureProbeEvidenceFailure(
			probe,
			`missing feature probe evidence ${probe.surface_id}: ${resolvedPath}`,
		);
	}
	const failure = browserComputerBrokerProbeEvidenceFailure(probe.surface_id, evidence);
	if (failure) {
		return featureProbeEvidenceFailure(
			probe,
			`feature probe evidence ${probe.surface_id} did not pass: ${redactDetail(failure)}`,
		);
	}
	return {
		surface_id: probe.surface_id,
		status: "pass",
		evidence_path: probe.evidence_path,
		detail: `feature probe evidence ${probe.surface_id} observed browser/computer broker controls`,
	};
}

function collectWorkflowProbeEvidence(
	probe: FeatureProbeMatrix["probes"][number],
): FeatureProbeEvidenceBundle["results"][number] {
	if (!isHermesWorkflowSurfaceId(probe.surface_id)) {
		return featureProbeEvidenceFailure(
			probe,
			`feature probe evidence ${probe.surface_id} is not a workflow surface`,
		);
	}
	const resolvedPath = resolveHermesArtifactPath(probe.evidence_path);
	let evidence: unknown;
	try {
		evidence = readOptionalJsonFile(resolvedPath);
	} catch (error) {
		return featureProbeEvidenceFailure(
			probe,
			`unreadable feature probe evidence ${probe.surface_id}: ${redactDetail(
				String(error instanceof Error ? error.message : error),
			)}`,
		);
	}
	if (evidence === undefined) {
		return featureProbeEvidenceFailure(
			probe,
			`missing feature probe evidence ${probe.surface_id}: ${resolvedPath}`,
		);
	}
	const failure = workflowProbeEvidenceFailure(probe.surface_id, evidence);
	if (failure) {
		return featureProbeEvidenceFailure(
			probe,
			`feature probe evidence ${probe.surface_id} did not pass: ${redactDetail(failure)}`,
		);
	}
	return {
		surface_id: probe.surface_id,
		status: "pass",
		evidence_path: probe.evidence_path,
		detail: `feature probe evidence ${probe.surface_id} observed workflow ledger controls`,
	};
}

function collectServedMcpProviderToolsProbeEvidence(
	probe: FeatureProbeMatrix["probes"][number],
): FeatureProbeEvidenceBundle["results"][number] {
	const resolvedPath = resolveHermesArtifactPath(probe.evidence_path);
	let evidence: unknown;
	try {
		evidence = readOptionalJsonFile(resolvedPath);
	} catch (error) {
		return featureProbeEvidenceFailure(
			probe,
			`unreadable feature probe evidence ${probe.surface_id}: ${redactDetail(
				String(error instanceof Error ? error.message : error),
			)}`,
		);
	}
	if (evidence === undefined) {
		return featureProbeEvidenceFailure(
			probe,
			`missing feature probe evidence ${probe.surface_id}: ${resolvedPath}`,
		);
	}
	const failure = servedMcpProviderToolsProbeEvidenceFailure(evidence);
	if (failure) {
		return featureProbeEvidenceFailure(
			probe,
			`feature probe evidence ${probe.surface_id} did not pass: ${redactDetail(failure)}`,
		);
	}
	return {
		surface_id: probe.surface_id,
		status: "pass",
		evidence_path: probe.evidence_path,
		detail: `feature probe evidence ${probe.surface_id} observed served-MCP provider tool controls`,
	};
}

function collectApiServerContainmentProbeEvidence(
	probe: FeatureProbeMatrix["probes"][number],
): FeatureProbeEvidenceBundle["results"][number] {
	const resolvedPath = resolveHermesArtifactPath(probe.evidence_path);
	let evidence: unknown;
	try {
		evidence = readOptionalJsonFile(resolvedPath);
	} catch (error) {
		return featureProbeEvidenceFailure(
			probe,
			`unreadable feature probe evidence ${probe.surface_id}: ${redactDetail(
				String(error instanceof Error ? error.message : error),
			)}`,
		);
	}
	if (evidence === undefined) {
		return featureProbeEvidenceFailure(
			probe,
			`missing feature probe evidence ${probe.surface_id}: ${resolvedPath}`,
		);
	}

	const parsed = ApiServerContainmentProbeEvidenceSchema.safeParse(evidence);
	if (!parsed.success) {
		return featureProbeEvidenceFailure(
			probe,
			`invalid feature probe evidence ${probe.surface_id}: ${flattenZodError(parsed.error)}`,
		);
	}

	const failures: string[] = [];
	if (parsed.data.status !== "pass") failures.push(`status is ${parsed.data.status}`);
	if (parsed.data.ran !== true) failures.push(`ran is ${String(parsed.data.ran)}`);
	if (parsed.data.findings.length > 0) {
		failures.push(`findings are not empty (${parsed.data.findings.length})`);
	}

	const gateByName = new Map(parsed.data.gates.map((gate) => [gate.name, gate]));
	for (const gateName of REQUIRED_API_SERVER_CONTAINMENT_GATES) {
		const gate = gateByName.get(gateName);
		if (!gate) {
			failures.push(`gate ${gateName} is missing`);
		} else if (gate.status !== "pass") {
			failures.push(`gate ${gateName} is ${gate.status}: ${redactDetail(gate.detail)}`);
		}
	}
	if (failures.length > 0) {
		return featureProbeEvidenceFailure(
			probe,
			`feature probe evidence ${probe.surface_id} did not pass: ${failures.join("; ")}`,
		);
	}

	return {
		surface_id: probe.surface_id,
		status: "pass",
		evidence_path: probe.evidence_path,
		detail: `feature probe evidence ${probe.surface_id} observed live API-server containment gates`,
	};
}

function collectModelRelayProbeEvidence(
	probe: FeatureProbeMatrix["probes"][number],
): FeatureProbeEvidenceBundle["results"][number] {
	const resolvedPath = resolveHermesArtifactPath(probe.evidence_path);
	let evidence: unknown;
	try {
		evidence = readOptionalJsonFile(resolvedPath);
	} catch (error) {
		return featureProbeEvidenceFailure(
			probe,
			`unreadable feature probe evidence ${probe.surface_id}: ${redactDetail(
				String(error instanceof Error ? error.message : error),
			)}`,
		);
	}
	if (evidence === undefined) {
		return featureProbeEvidenceFailure(
			probe,
			`missing feature probe evidence ${probe.surface_id}: ${resolvedPath}`,
		);
	}

	const parsed = ModelRelayProbeEvidenceSchema.safeParse(evidence);
	if (!parsed.success) {
		return featureProbeEvidenceFailure(
			probe,
			`invalid feature probe evidence ${probe.surface_id}: ${flattenZodError(parsed.error)}`,
		);
	}

	const failures: string[] = [];
	if (parsed.data.status !== "pass") failures.push(`status is ${parsed.data.status}`);
	if (parsed.data.ran !== true) failures.push(`ran is ${String(parsed.data.ran)}`);
	if (parsed.data.posture !== REQUIRED_CUTOVER_NETWORK_PROBE_POSTURE) {
		failures.push(
			`posture is ${parsed.data.posture ?? "missing"}; expected ${REQUIRED_CUTOVER_NETWORK_PROBE_POSTURE}`,
		);
	}
	if (!parsed.data.observation.relayUrl) {
		failures.push("observation.relayUrl is missing");
	} else if (isDirectModelRelayProviderUrl(parsed.data.observation.relayUrl)) {
		failures.push("observation.relayUrl points at a direct model-provider host");
	}
	if (!isDirectModelRelayProviderUrl(parsed.data.observation.directModelUrl)) {
		failures.push("observation.directModelUrl is not a recognized direct model-provider URL");
	}
	const origin = parsed.data.origin;
	if (origin.kind === "relay-self-smoke") {
		failures.push("origin is relay-self-smoke");
	}
	const originMatches =
		origin.kind === "contained-peer" &&
		origin.containerName === "tc-hermes-contained" &&
		origin.observedPeerAddress !== undefined &&
		origin.expectedPeerAddress !== undefined &&
		origin.observedPeerSource === "server-peer-echo" &&
		origin.expectedPeerSource === "configured-contained-ip" &&
		net.isIP(origin.observedPeerAddress) !== 0 &&
		net.isIP(origin.expectedPeerAddress) !== 0 &&
		origin.observedPeerAddress === origin.expectedPeerAddress;
	if (!originMatches) {
		failures.push(
			"origin is not a server-observed tc-hermes-contained peer matching the configured contained IP",
		);
	}
	if (!parsed.data.observation.profileDir) {
		failures.push("observation.profileDir is missing");
	}
	if ((parsed.data.observation.scannedProfileFiles ?? []).length === 0) {
		failures.push("observation.scannedProfileFiles is empty");
	}

	const gateByName = new Map(parsed.data.gates.map((gate) => [gate.name, gate]));
	for (const gateName of requiredModelRelayGateNames(parsed.data.posture)) {
		const gate = gateByName.get(gateName);
		if (!gate) {
			failures.push(`gate ${gateName} is missing`);
		} else if (gate.status !== "pass") {
			failures.push(`gate ${gateName} is ${gate.status}: ${redactDetail(gate.detail)}`);
		}
	}
	if (failures.length > 0) {
		return featureProbeEvidenceFailure(
			probe,
			`feature probe evidence ${probe.surface_id} did not pass: ${failures.join("; ")}`,
		);
	}

	return {
		surface_id: probe.surface_id,
		status: "pass",
		evidence_path: probe.evidence_path,
		detail: `feature probe evidence ${probe.surface_id} observed model relay reachability, direct-model denial, and profile credential absence`,
	};
}

function requiredModelRelayGateNames(
	posture: z.infer<typeof NetworkProbePostureSchema> | undefined,
): readonly string[] {
	return posture === "agent-iptables"
		? REQUIRED_MODEL_RELAY_AGENT_IPTABLES_GATES
		: REQUIRED_MODEL_RELAY_CONTAINED_GATES;
}

function isDirectModelRelayProviderUrl(value: string): boolean {
	try {
		return DIRECT_MODEL_RELAY_PROVIDER_HOSTS.has(new URL(value).hostname.toLowerCase());
	} catch {
		return false;
	}
}

function isRelayOpenAiCodexProxyUrl(value: string): boolean {
	try {
		const parsed = new URL(value);
		return (
			parsed.protocol === "http:" &&
			parsed.hostname === "telclaude" &&
			parsed.port === "8790" &&
			parsed.pathname.replace(/\/+$/, "") === "/v1/openai-codex-proxy" &&
			parsed.search === "" &&
			parsed.hash === "" &&
			value.replace(/\/+$/, "") === TELCLAUDE_OPENAI_CODEX_RELAY_PROXY_URL
		);
	} catch {
		return false;
	}
}

function isForbiddenCredentialKey(key: string): boolean {
	return /(^|_)(API_KEY|AUTH_TOKEN|OAUTH_TOKEN|TOKEN|KEY|PASSWORD|SECRET|COOKIE|CREDENTIALS?)(_|$)/i.test(
		key,
	);
}

function featureProbeEvidenceFailure(
	probe: FeatureProbeMatrix["probes"][number],
	detail: string,
): FeatureProbeEvidenceBundle["results"][number] {
	return {
		surface_id: probe.surface_id,
		status: "fail",
		evidence_path: probe.evidence_path,
		detail,
	};
}

function featureProbeFailure(
	probe: FeatureProbeMatrix["probes"][number],
	evidence: FeatureProbeEvidenceBundle["results"][number] | undefined,
): string | null {
	if (probe.status !== "pass") {
		return `feature probe ${probe.surface_id} status is ${probe.status ?? "missing"}`;
	}
	if (evidence) {
		return evidence.status === "pass"
			? null
			: `feature probe ${probe.surface_id} evidence failed: ${evidence.detail}`;
	}
	return `feature probe ${probe.surface_id} requires observed evidence`;
}

function formatValidationResult(
	result: { success: true } | { success: false; error: z.ZodError },
): ValidationResult {
	if (result.success) return { valid: true, errors: [] };
	return { valid: false, errors: [flattenZodError(result.error)] };
}

function flattenZodError(error: z.ZodError): string {
	return error.issues
		.map((issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`)
		.join("; ");
}

function unique(values: string[]): string[] {
	return [...new Set(values)];
}

function findDuplicates(values: string[]): string[] {
	const seen = new Set<string>();
	const duplicates = new Set<string>();
	for (const value of values) {
		if (seen.has(value)) {
			duplicates.add(value);
		} else {
			seen.add(value);
		}
	}
	return [...duplicates];
}

function sameJson(left: unknown, right: unknown): boolean {
	return JSON.stringify(left) === JSON.stringify(right);
}

function deriveQueueOwnershipSnapshot(inventory: unknown): QueueOwnershipSnapshot {
	const parsed = InventoryQueueEvidenceSchema.safeParse(inventory);
	if (!parsed.success) {
		throw new Error(
			`inventory queue evidence is missing or incomplete: ${flattenZodError(parsed.error)}`,
		);
	}
	const unownedActiveCount = Object.values(parsed.data.summary.pendingQueues).reduce<number>(
		(total, value) => total + value,
		0,
	);
	return { unownedActiveCount };
}

function queueSnapshotEvidenceFailures(
	inventory: unknown,
	queueSnapshot: QueueOwnershipSnapshot,
): string[] {
	let derived: QueueOwnershipSnapshot;
	try {
		derived = deriveQueueOwnershipSnapshot(inventory);
	} catch (error) {
		return [String(error instanceof Error ? error.message : error)];
	}
	if (sameJson(derived, queueSnapshot)) return [];
	return [
		`queue snapshot does not match inventory pendingQueues: expected ${String(
			derived.unownedActiveCount,
		)}, got ${String(queueSnapshot.unownedActiveCount)}`,
	];
}

function collectLockfileConsistencyFailures(input: {
	lockfile: CompatibilityLockfile;
	pin: HermesPin | null;
	featureProbeMatrix?: unknown;
}): string[] {
	const failures: string[] = [];
	if (input.pin && !sameJson(input.lockfile.hermes, input.pin)) {
		failures.push("lockfile Hermes pin does not match requested pin");
	}
	for (const probe of input.lockfile.featureProbes) {
		if (probe.status !== "pass") {
			failures.push(`lockfile feature probe ${probe.surface_id} status is ${probe.status}`);
		}
	}
	if (input.featureProbeMatrix !== undefined) {
		const parsed = FeatureProbeMatrixSchema.safeParse(input.featureProbeMatrix);
		if (parsed.success) {
			const digest = computeHermesArtifactDigest(parsed.data);
			if (input.lockfile.featureProbeMatrixDigest !== digest) {
				failures.push("lockfile feature-probe matrix digest does not match current matrix");
			}
		}
	}
	return unique(failures);
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
