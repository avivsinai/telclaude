import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { z } from "zod";
import {
	OPENAI_CODEX_RELAY_PROOF_SCHEMA_VERSION,
	OPENAI_CODEX_RELAY_PROOF_SOURCE,
	OPENAI_CODEX_RESPONSES_PATH,
	type OpenAiCodexRelayProof,
	openAiCodexRelayProofSignatureFailure,
	openAiCodexRelayProofTokenSha256,
} from "../relay/openai-codex-relay-proof.js";
import { redactSecrets } from "../security/output-filter.js";
import {
	HERMES_EVIDENCE_PROOF_MAX_SKEW_MS,
	type HermesSignedEvidenceValidationOptions,
	hermesAllowsStaleAttestations,
	hermesAttestationFreshnessFailure,
} from "./attestation-validation.js";
import {
	browserComputerBrokerProbeEvidenceFailure,
	isBrowserComputerBrokerSurfaceId,
} from "./browser-computer-broker-probes.js";
import {
	EDGE_ADAPTER_CONTRACT_PROBE_SOURCE,
	edgeAdapterProbeEvidenceFailure,
	isEdgeAdapterFeatureSurfaceId,
} from "./edge-adapter-probes.js";
import { HOSTILE_PEER_PROBE_ID, hostilePeerProbeEvidenceFailure } from "./hostile-peer-probes.js";
import { householdReminderProbeEvidenceFailure } from "./household-reminder-probe.js";
import { sideEffectLedgerProbeEvidenceFailure } from "./mcp/side-effect-ledger-probe.js";
import {
	NO_FORK_RUNNER_ATTESTATION_RUNNER,
	NO_FORK_RUNNER_ATTESTATION_SCHEMA_VERSION,
	NO_FORK_RUNNER_ATTESTATION_SOURCE,
} from "./no-fork-attestation.js";
import { providerApprovalBindingProbeEvidenceFailure } from "./provider-approval-binding-probe.js";
import {
	isProviderDomainSurfaceId,
	providerDomainProbeEvidenceFailure,
} from "./provider-domain-probes.js";
import { googleProviderProbeEvidenceFailure } from "./provider-google-probe.js";
import { providerReleasePolicyProbeEvidenceFailure } from "./provider-release-policy-probe.js";
import { DEFAULT_HERMES_CONTAINED_IP, DEFAULT_HERMES_RELAY_IP } from "./runtime-network.js";
import { evaluateServedMcpContainmentEvidence } from "./served-mcp-containment.js";
import { evaluateServedMcpMemoryEvidence } from "./served-mcp-memory.js";
import { servedMcpProviderToolsProbeEvidenceFailure } from "./served-mcp-provider-tools-probe.js";
import { evaluateSkillsAllowlistEvidence } from "./skills-allowlist-probe.js";
import { isHermesWorkflowSurfaceId, workflowProbeEvidenceFailure } from "./workflow-probes.js";

export { NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION } from "./network-probe-schema.js";

export const DEFAULT_FEATURE_PROBE_MATRIX_PATH = "docs/hermes/feature-probes.json";
export const DEFAULT_COMPAT_LOCKFILE_PATH = "docs/hermes/hermes-compat.lock.json";
export const DEFAULT_NETWORK_PROBES_PATH = "docs/hermes/network-probes.json";
export const DEFAULT_NO_FORK_PROOF_PATH = "docs/hermes/no-fork-proof.json";
export const HERMES_TRACKED_SEED_PATHS = [
	DEFAULT_FEATURE_PROBE_MATRIX_PATH,
	DEFAULT_COMPAT_LOCKFILE_PATH,
	DEFAULT_NETWORK_PROBES_PATH,
	DEFAULT_NO_FORK_PROOF_PATH,
] as const;
export const HERMES_PROBE_RESULT_SCHEMA_VERSION = "telclaude.hermes.probe-result.v1";
export const HERMES_HEADLESS_ENTRYPOINT_SURFACE_ID = "execution.headless_entrypoint";
export const HERMES_HEADLESS_ENTRYPOINT_PROOF_SCHEMA_VERSION =
	"telclaude.hermes.headless-entrypoint-proof.v1";
const HERMES_CLI_HEADLESS_PROVENANCE_RUNNER = "telclaude-hermes-cli-probe";
const HERMES_CLI_HEADLESS_PROVENANCE_SOURCE = "live-allow-run";
const HERMES_CLI_HEADLESS_RUNTIME_PROVENANCE_SOURCE = "docker-inspect-container-dns-and-relay-peer";
const HERMES_CLI_HEADLESS_RELAY_PROOF_SCHEMA_VERSION = OPENAI_CODEX_RELAY_PROOF_SCHEMA_VERSION;
const HERMES_CLI_HEADLESS_RELAY_PROOF_SOURCE = OPENAI_CODEX_RELAY_PROOF_SOURCE;
const REQUIRED_MODEL_RELAY_PROFILE_DIR = "/home/hermes/.hermes";
const REQUIRED_MODEL_RELAY_SCANNED_PROFILE_FILES = [
	`${REQUIRED_MODEL_RELAY_PROFILE_DIR}/auth.json`,
	`${REQUIRED_MODEL_RELAY_PROFILE_DIR}/config.yaml`,
	`${REQUIRED_MODEL_RELAY_PROFILE_DIR}/secret-manifest.json`,
] as const;
const HERMES_CODEX_RESPONSES_PATH = OPENAI_CODEX_RESPONSES_PATH;
const HERMES_HEADLESS_ENTRYPOINT_REQUIRED_CHECKS = [
	"stream.delta_before_done",
	"stream.terminal_event",
	"session.initial",
	"session.resume",
	"session.new_clears_resume",
	"session.concurrent_isolation",
	"tool.result_returned",
	"approval.fallback_or_wait_resume",
	"cancellation.stop",
	"errors.deterministic",
	"redaction.secret_outputs",
] as const;
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
const Sha256DigestSchema = z.string().regex(SHA256_DIGEST_PATTERN);
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
				"api-server-containment",
				"headless-entrypoint-semantics",
				"edge-adapter",
				"model-relay",
				"nofork-proof",
				"provider-approval-binding",
				"runtime-hostile-peer",
				"served-mcp-containment",
				"served-mcp-provider-tools",
				"side-effect-ledger",
				"workflow-ledger",
				"household-reminder",
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
			.strict()
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
				networkName: z.literal("telclaude-hermes-private"),
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
				proofTokenSha256: z.string().regex(SHA256_DIGEST_PATTERN).optional(),
				observedAt: NonEmptyString,
				signature: InternalResponseProofSchema,
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

const HeadlessEntrypointProofSchema = z
	.object({
		schemaVersion: z.literal(HERMES_HEADLESS_ENTRYPOINT_PROOF_SCHEMA_VERSION),
		probeId: z.literal(HERMES_HEADLESS_ENTRYPOINT_SURFACE_ID),
		status: z.enum(["pass", "fail"]),
		ran: z.boolean(),
		generatedAt: NonEmptyString,
		summary: NonEmptyString,
		testReport: z
			.object({
				runner: z.literal("vitest-json"),
				command: z.array(NonEmptyString).min(1),
				cwd: NonEmptyString,
				exitCode: z.literal(0),
				reportPath: NonEmptyString,
				reportSha256: Sha256DigestSchema,
				sourceDigests: z.record(NonEmptyString, Sha256DigestSchema),
			})
			.strict()
			.optional(),
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
	"modelRelay.modelProvider",
	"modelRelay.origin",
	"relay.reachable",
	"directModel.denied",
	"profile.relayCredentialReference",
	"profile.runtimeCustody",
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
const TELCLAUDE_MODEL_RELAY_PROBE_URL = "http://telclaude:8790/v1/models";
const ADAPTER_SIGNATURE_FILES: Record<string, string[]> = {
	"execution.cli_headless": [
		"src/hermes/private-runtime.ts",
		"src/commands/hermes.ts",
		"src/relay/openai-codex-proxy.ts",
		"src/relay/openai-codex-relay-proof.ts",
		"docker/hermes-contained-entrypoint.sh",
		"scripts/hermes-contained-cli-probe.sh",
	],
	[HERMES_HEADLESS_ENTRYPOINT_SURFACE_ID]: [
		"src/hermes/api-adapter.ts",
		"src/hermes/private-runtime.ts",
		"src/hermes/session-map.ts",
		"tests/hermes/api-adapter.test.ts",
		"tests/hermes/private-runtime.test.ts",
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
	[HOSTILE_PEER_PROBE_ID]: [
		"docker/hermes-contained-entrypoint.sh",
		"src/hermes/hostile-peer-probes.ts",
		"src/hermes/verify-live.ts",
		"src/hermes/mcp/live-connection-resolver.ts",
		"src/hermes/mcp/live-server.ts",
		"src/relay/openai-codex-proxy.ts",
	],
	"model.relay": [
		"src/hermes/model-relay.ts",
		"src/hermes/network-probe-attestation.ts",
		"src/hermes/network-probes.ts",
		"src/hermes/private-runtime.ts",
		"src/relay/capabilities.ts",
		"src/relay/openai-codex-proxy.ts",
		"src/relay/openai-codex-relay-proof.ts",
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
		"src/hermes/mcp/live-relay-clients.ts",
		"src/hermes/mcp/provider-routing.ts",
		"src/hermes/mcp/provider-sidecar-token.ts",
		"src/hermes/provider-google-probe.ts",
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
	"household.reminders": [
		"src/config/config.ts",
		"src/config/profiles.ts",
		"src/storage/db.ts",
		"src/cron/types.ts",
		"src/cron/store.ts",
		"src/cron/actions.ts",
		"src/cron/scheduler.ts",
		"src/cron/index.ts",
		"src/household-reminders/types.ts",
		"src/household-reminders/binding.ts",
		"src/household-reminders/copy.ts",
		"src/household-reminders/store.ts",
		"src/household-reminders/time.ts",
		"src/household-reminders/render.ts",
		"src/household-reminders/fire-executor.ts",
		"src/household-reminders/system-origin-authorizer.ts",
		"src/household-reminders/system-origin-policy.ts",
		"src/hermes/mcp/side-effect-ledger.ts",
		"src/hermes/mcp/ledger-execute.ts",
		"src/relay/outbound-delivery-dispatcher.ts",
		"src/relay/whatsapp-reminder-confirmation-interceptor.ts",
		"src/relay/reminder-confirmation-control-policy.ts",
		"src/relay/reminder-confirmation-control-sender.ts",
		"src/whatsapp-bridge/contract.ts",
		"src/whatsapp-bridge/idempotency-journal.ts",
		"src/whatsapp-bridge/index.ts",
		"src/hermes/household-reminder-probe.ts",
		"src/hermes/household-reminder-attestation.ts",
	],
	"browser.profiles": [
		"src/hermes/browser-computer-broker-probes.ts",
		"src/hermes/edge-adapter-contract.ts",
	],
	"computer.broker": [
		"src/hermes/browser-computer-broker-probes.ts",
		"src/hermes/edge-adapter-contract.ts",
	],
	"network.egress-broker": [
		"src/hermes/browser-computer-broker-attestation.ts",
		"src/hermes/browser-computer-broker-probes.ts",
		"src/hermes/network-probe-attestation.ts",
		"src/hermes/network-probes.ts",
		"src/hermes/private-runtime.ts",
		"docker/docker-compose.hermes.yml",
	],
};
export function hermesAdapterSignatureFilesForSurface(surfaceId: string): readonly string[] {
	return ADAPTER_SIGNATURE_FILES[surfaceId] ?? ["src/hermes/foundation.ts"];
}
const P0_PARITY_DIGEST_FILES = [
	"docs/hermes/feature-probes.json",
	"docs/hermes/network-probes.json",
	"docs/hermes/no-fork-proof.json",
	"src/hermes/network-probe-attestation.ts",
	"src/hermes/network-probe-schema.ts",
	"src/hermes/network-probes.ts",
	"src/hermes/no-fork-attestation.ts",
	"src/hermes/no-fork-proof.ts",
	"src/hermes/edge-adapter-contract.ts",
	"src/hermes/edge-adapter-runtime.ts",
	"src/hermes/edge-adapter-probes.ts",
	"src/hermes/household-reminder-probe.ts",
	"src/hermes/household-reminder-attestation.ts",
	"tests/hermes/household-reminder-probe.test.ts",
	"tests/hermes/household-reminder-attestation.test.ts",
	"tests/integration/household-reminder-phase0.test.ts",
	"tests/household-reminders/time.test.ts",
	"src/hermes/workflow-run-ledger.ts",
	"src/hermes/workflow-probes.ts",
	"src/hermes/browser-computer-broker-probes.ts",
	"src/hermes/private-runtime.ts",
	"src/relay/openai-codex-proxy.ts",
	"src/relay/openai-codex-relay-proof.ts",
	"tests/hermes/edge-adapter-contract.test.ts",
	"tests/hermes/edge-adapter-runtime.test.ts",
	"tests/hermes/edge-adapter-probes.test.ts",
	"tests/hermes/workflow-run-ledger.test.ts",
	"tests/hermes/workflow-probes.test.ts",
	"tests/hermes/browser-computer-broker-probes.test.ts",
	"tests/hermes/network-probes.test.ts",
	"tests/hermes/no-fork-proof.test.ts",
	"tests/hermes/private-runtime.test.ts",
	"tests/integration/telegram-control-plane.replay.test.ts",
	"tests/telegram/command-gating.test.ts",
	"tests/relay/openai-codex-proxy.test.ts",
	"tests/hermes/mcp-side-effect-ledger-probe.test.ts",
	"tests/commands/hermes.test.ts",
];
export const HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV = "OPERATOR_RPC_RELAY_PUBLIC_KEY" as const;
export const HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK_ENV =
	"TELCLAUDE_HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK" as const;
export const HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK_PATH =
	"docs/hermes/rollback-relay-public-key.lock.json" as const;
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
		summary: NonEmptyString.optional(),
		generatedAt: NonEmptyString,
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
			.strict(),
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
			.strict()
			.optional(),
		observation: z
			.object({
				relayUrl: NonEmptyString.optional(),
				directModelUrl: NonEmptyString,
				profileDir: NonEmptyString.optional(),
				scannedProfileFiles: z.array(NonEmptyString).optional(),
			})
			.strict(),
		gates: z.array(
			z
				.object({
					name: NonEmptyString,
					status: z.enum(["pass", "fail", "pending"]),
					detail: NonEmptyString,
				})
				.strict(),
		),
	})
	.strict();

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
		runnerAttestation: z
			.object({
				schemaVersion: z.literal(NO_FORK_RUNNER_ATTESTATION_SCHEMA_VERSION),
				source: z.literal(NO_FORK_RUNNER_ATTESTATION_SOURCE),
				runner: z.literal(NO_FORK_RUNNER_ATTESTATION_RUNNER),
				startedAt: NonEmptyString,
				endedAt: NonEmptyString,
				checkoutPath: NonEmptyString,
				expectedRef: NonEmptyString,
				expectedVersion: NonEmptyString,
				head: NonEmptyString,
				expectedRefCommit: NonEmptyString,
				wrapperPackageSha256: z.string().regex(SHA256_DIGEST_PATTERN),
				profileGenerationSha256: z.string().regex(SHA256_DIGEST_PATTERN),
				fixtureResultsSha256: z.string().regex(SHA256_DIGEST_PATTERN),
				transcriptSha256: z.string().regex(SHA256_DIGEST_PATTERN),
				checksSha256: z.string().regex(SHA256_DIGEST_PATTERN),
				evidenceSha256: z.string().regex(SHA256_DIGEST_PATTERN),
				p0Command: z.array(NonEmptyString),
				p0ExitCode: z.number().int(),
				p0Status: z.enum(["pass", "fail"]),
				runtimeSourceReplacementDenied: z.boolean(),
				monkeypatchDenied: z.boolean(),
				postRunStatusPorcelain: z.string(),
				postRunDiffExitCode: z.number().int(),
				postRunCachedDiffExitCode: z.number().int(),
				signature: InternalResponseProofSchema,
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

export type NoForkProof = z.infer<typeof NoForkProofSchema>;

const RollbackRelayPublicKeySchema = z
	.object({
		scope: z.literal("operator"),
		envKey: z.literal(HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV),
		value: NonEmptyString,
		sha256: z.string().regex(SHA256_DIGEST_PATTERN),
		source: NonEmptyString,
	})
	.strict();

const RollbackRelayPublicKeyLockEntrySchema = RollbackRelayPublicKeySchema.extend({
	sourceSha256: z.string().regex(SHA256_DIGEST_PATTERN),
}).strict();

const RollbackRelayPublicKeySourceEntrySchema = z
	.object({
		scope: z.literal("operator"),
		envKey: z.literal(HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV),
		value: NonEmptyString,
		sha256: z.string().regex(SHA256_DIGEST_PATTERN),
	})
	.strict();

const RollbackRelayPublicKeySourceSchema = z
	.object({
		schemaVersion: z.literal("telclaude.hermes.rollback-relay-public-key-source.v1"),
		keys: z.array(RollbackRelayPublicKeySourceEntrySchema).min(1),
	})
	.strict();

const RollbackRelayPublicKeyLockSchema = z
	.object({
		schemaVersion: z.literal("telclaude.hermes.rollback-relay-public-key-lock.v1"),
		keys: z.array(RollbackRelayPublicKeyLockEntrySchema).min(1),
	})
	.strict();

export type ValidationResult = {
	valid: boolean;
	errors: string[];
};

export type HermesDoctorReport = {
	status: "pass" | "fail";
	pin: HermesPin | null;
	checks: Array<{ name: string; status: "pass" | "fail"; detail: string }>;
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
const HERMES_RED_ONLY_TRACKED_SEED_PATHS = new Set<string>(HERMES_TRACKED_SEED_PATHS);

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
	assertTrackedHermesSeedValueIsRed(filePath, value, options);
	writeHermesTextArtifact(filePath, `${JSON.stringify(value, null, 2)}\n`, options);
}

export function writeHermesTextArtifact(
	filePath: string,
	content: string,
	options: HermesArtifactWriteOptions = {},
): void {
	const trackedSeedPath = trackedHermesSeedPath(filePath);
	if (
		trackedSeedPath &&
		HERMES_RED_ONLY_TRACKED_SEED_PATHS.has(trackedSeedPath) &&
		options.allowTrackedSeedWrite === true
	) {
		assertTrackedHermesSeedValueIsRed(filePath, JSON.parse(content) as unknown, options);
	}
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
	const resolved = resolvePossiblyMissingPath(filePath);
	const repoRoot = gitTopLevelForPath(resolved);
	if (!repoRoot) return undefined;
	return trackedHermesSeedPaths(repoRoot).get(resolved);
}

function trackedHermesSeedPaths(repoRoot: string): Map<string, string> {
	const normalizedRoot = resolvePossiblyMissingPath(repoRoot);
	const cached = trackedSeedPathCache.get(normalizedRoot);
	if (cached) return cached;

	const seedPaths = unique([
		...HERMES_TRACKED_SEED_PATHS,
		...gitTrackedHermesSeedPaths(normalizedRoot),
	]);
	const next = new Map(
		seedPaths
			.filter((seedPath) => seedPath.startsWith("docs/hermes/") && seedPath.endsWith(".json"))
			.map((seedPath) => [path.resolve(normalizedRoot, seedPath), seedPath]),
	);
	trackedSeedPathCache.set(normalizedRoot, next);
	return next;
}

function resolvePossiblyMissingPath(filePath: string): string {
	const resolved = path.resolve(filePath);
	if (fs.existsSync(resolved)) return fs.realpathSync.native(resolved);
	let current = path.dirname(resolved);
	const segments: string[] = [path.basename(resolved)];
	while (!fs.existsSync(current)) {
		const parent = path.dirname(current);
		if (parent === current) return resolved;
		segments.unshift(path.basename(current));
		current = parent;
	}
	return path.join(fs.realpathSync.native(current), ...segments);
}

function gitTopLevelForPath(filePath: string): string | undefined {
	let current = fs.existsSync(filePath)
		? fs.statSync(filePath).isDirectory()
			? filePath
			: path.dirname(filePath)
		: path.dirname(filePath);
	while (!fs.existsSync(current)) {
		const parent = path.dirname(current);
		if (parent === current) return undefined;
		current = parent;
	}
	return gitTopLevel(current);
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

function assertTrackedHermesSeedValueIsRed(
	filePath: string,
	value: unknown,
	options: HermesArtifactWriteOptions = {},
): void {
	const trackedSeedPath = trackedHermesSeedPath(filePath);
	if (
		!trackedSeedPath ||
		!HERMES_RED_ONLY_TRACKED_SEED_PATHS.has(trackedSeedPath) ||
		options.allowTrackedSeedWrite !== true
	) {
		return;
	}
	if (trackedHermesSeedValueIsRed(trackedSeedPath, value)) return;
	throw new Error(
		`Refusing to write green tracked Hermes seed ${trackedSeedPath}. Tracked cutover seeds must stay fail-closed/red; write green evidence outside docs/hermes or after an explicit seed-promotion decision.`,
	);
}

function trackedHermesSeedValueIsRed(seedPath: string, value: unknown): boolean {
	if (!isRecord(value)) return true;
	switch (seedPath) {
		case DEFAULT_FEATURE_PROBE_MATRIX_PATH:
			return !nonEmptyArrayEvery(value.probes, (probe) => recordString(probe, "status") === "pass");
		case DEFAULT_COMPAT_LOCKFILE_PATH:
			return !nonEmptyArrayEvery(
				value.featureProbes,
				(probe) => recordString(probe, "status") === "pass",
			);
		case DEFAULT_NETWORK_PROBES_PATH:
			return !nonEmptyArrayEvery(value.probes, (probe) => recordString(probe, "status") === "pass");
		case DEFAULT_NO_FORK_PROOF_PATH:
			return !(
				value.hermesCheckoutClean === true &&
				nonEmptyArrayEvery(value.checks, (check) => recordString(check, "status") === "pass")
			);
		default:
			return false;
	}
}

function nonEmptyArrayEvery(value: unknown, predicate: (item: unknown) => boolean): boolean {
	return Array.isArray(value) && value.length > 0 && value.every(predicate);
}

function recordString(value: unknown, key: string): string | undefined {
	const record = asRecord(value);
	const field = record?.[key];
	return typeof field === "string" ? field : undefined;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
	return isRecord(value) ? value : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function collectFeatureProbeEvidence(
	featureProbeMatrix: unknown,
	options: HermesSignedEvidenceValidationOptions = {},
): FeatureProbeEvidenceBundle | undefined {
	const parsed = FeatureProbeMatrixSchema.safeParse(featureProbeMatrix);
	if (!parsed.success) return undefined;
	const results = parsed.data.probes.flatMap((probe) => {
		if (probe.surface_id === "execution.cli_headless") {
			return [collectCliHeadlessProbeEvidence(probe, options)];
		}
		if (probe.surface_id === HERMES_HEADLESS_ENTRYPOINT_SURFACE_ID) {
			return [collectHeadlessEntrypointProbeEvidence(probe, options)];
		}
		if (probe.surface_id === "execution.served_mcp_containment") {
			return [collectServedMcpContainmentProbeEvidence(probe)];
		}
		if (probe.surface_id === "execution.api_server_containment") {
			return [collectApiServerContainmentProbeEvidence(probe)];
		}
		if (probe.surface_id === HOSTILE_PEER_PROBE_ID) {
			return [collectHostilePeerProbeEvidence(probe)];
		}
		if (probe.surface_id === "model.relay") {
			return [collectModelRelayProbeEvidence(probe, options)];
		}
		if (isEdgeAdapterFeatureSurfaceId(probe.surface_id)) {
			return [collectEdgeAdapterProbeEvidence(probe, options)];
		}
		if (probe.surface_id === "sideeffect.ledger") {
			return [collectSideEffectLedgerProbeEvidence(probe, options)];
		}
		if (probe.surface_id === "household.reminders") {
			return [collectHouseholdReminderProbeEvidence(probe, options)];
		}
		if (probe.surface_id === "providers.approval-binding") {
			return [collectProviderApprovalBindingProbeEvidence(probe, options)];
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
		if (probe.surface_id === "served_mcp.memory") {
			return [collectServedMcpMemoryProbeEvidence(probe, options)];
		}
		if (probe.surface_id === "skills.allowlist") {
			return [collectSkillsAllowlistProbeEvidence(probe, options)];
		}
		if (probe.surface_id === "providers.google") {
			return [collectGoogleProviderProbeEvidence(probe)];
		}
		if (isBrowserComputerBrokerSurfaceId(probe.surface_id)) {
			return [collectBrowserComputerBrokerProbeEvidence(probe, options)];
		}
		if (isHermesWorkflowSurfaceId(probe.surface_id)) {
			return [collectWorkflowProbeEvidence(probe, options)];
		}
		return [];
	});
	return { schemaVersion: 1, results };
}

export function buildCompatibilityLockfileDraft(input: {
	pin: HermesPin | null;
	featureProbeMatrix: unknown;
	wrapperPackageVersion: string;
	noForkProofEvidencePath?: string;
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
					files: computeFileSetDigest(hermesAdapterSignatureFilesForSurface(probe.surface_id)),
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
			"pnpm dev hermes prove --upstream-clean",
			"pnpm dev hermes verify-live",
		],
		generatedProfileSchemaVersion: "1",
		wrapperPackageVersion: input.wrapperPackageVersion,
		paritySuiteDigests: {
			p0: computeFileSetDigest(P0_PARITY_DIGEST_FILES),
		},
		noForkProofEvidencePath: input.noForkProofEvidencePath ?? DEFAULT_NO_FORK_PROOF_PATH,
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

function sha256Digest(content: string | Buffer): string {
	return `sha256:${crypto.createHash("sha256").update(content).digest("hex")}`;
}

export function archivedHermesEvidenceValidationOptions(): HermesSignedEvidenceValidationOptions {
	const trustedRelayPublicKey = trustedRelayPublicKeyForValidation({ liveCutover: false });
	return {
		allowStaleAttestations: true,
		...(trustedRelayPublicKey.valid ? { relayPublicKey: trustedRelayPublicKey.value } : {}),
	};
}

export function resolveHermesArtifactPath(relativePath: string): string {
	return path.resolve(relativePath);
}

export function trustedRelayPublicKeyForValidation(
	input: {
		readonly liveCutover?: boolean;
		readonly evidenceKey?: z.infer<typeof RollbackRelayPublicKeySchema>;
	} = {},
): { valid: true; value: string; source: "env" | "lockfile" } | { valid: false; failure: string } {
	const liveCutover = input.liveCutover ?? true;
	const trustedValue = process.env[HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV]?.trim();
	if (trustedValue) {
		if (input.evidenceKey && input.evidenceKey.value !== trustedValue) {
			return {
				valid: false,
				failure:
					"rollback rehearsal evidence relay public key does not match trusted relay public key",
			};
		}
		return { valid: true, value: trustedValue, source: "env" };
	}
	if (liveCutover) {
		return {
			valid: false,
			failure: `trusted operator relay public key env ${HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV} is missing for live validation`,
		};
	}
	return trustedRelayPublicKeyFromLock(input.evidenceKey);
}

function trustedRelayPublicKeyFromLock(
	evidenceKey?: z.infer<typeof RollbackRelayPublicKeySchema>,
): { valid: true; value: string; source: "lockfile" } | { valid: false; failure: string } {
	const lockPath =
		process.env[HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK_ENV]?.trim() ||
		HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK_PATH;
	const resolvedLockPath = resolveHermesArtifactPath(lockPath);
	if (!fs.existsSync(resolvedLockPath)) {
		return {
			valid: false,
			failure: `rollback rehearsal trusted relay public key env ${HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV} is missing and lockfile ${lockPath} is missing`,
		};
	}
	let lock: z.infer<typeof RollbackRelayPublicKeyLockSchema>;
	try {
		lock = RollbackRelayPublicKeyLockSchema.parse(
			safeParseJson(fs.readFileSync(resolvedLockPath, "utf8")),
		);
	} catch (error) {
		return {
			valid: false,
			failure: `rollback rehearsal trusted relay public key lockfile is invalid: ${
				error instanceof Error ? error.message : String(error)
			}`,
		};
	}
	const locked = evidenceKey
		? lock.keys.find(
				(key) =>
					key.scope === evidenceKey.scope &&
					key.envKey === evidenceKey.envKey &&
					key.value === evidenceKey.value &&
					key.sha256 === evidenceKey.sha256 &&
					key.source === evidenceKey.source,
			)
		: lock.keys.find(
				(key) => key.scope === "operator" && key.envKey === HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV,
			);
	if (!locked) {
		return {
			valid: false,
			failure: evidenceKey
				? "rollback rehearsal evidence relay public key is not pinned in the trusted lockfile"
				: "trusted relay public key lockfile has no operator key",
		};
	}
	const expectedDigest = sha256Digest(locked.value);
	if (locked.sha256 !== expectedDigest) {
		return {
			valid: false,
			failure: "rollback rehearsal trusted relay public key lockfile sha256 does not match value",
		};
	}
	const resolvedSourcePath = resolveHermesArtifactPath(locked.source);
	if (!fs.existsSync(resolvedSourcePath)) {
		return {
			valid: false,
			failure: `rollback rehearsal relay public key source artifact is missing: ${redactDetail(
				locked.source,
			)}`,
		};
	}
	const sourceBytes = fs.readFileSync(resolvedSourcePath);
	const sourceDigest = `sha256:${crypto.createHash("sha256").update(sourceBytes).digest("hex")}`;
	if (sourceDigest !== locked.sourceSha256) {
		return {
			valid: false,
			failure: "rollback rehearsal relay public key source artifact sha256 does not match lockfile",
		};
	}
	const sourceText = sourceBytes.toString("utf8");
	const sourceFailure = rollbackRelayPublicKeySourceArtifactFailure(sourceText, locked);
	if (sourceFailure) {
		return {
			valid: false,
			failure: sourceFailure,
		};
	}
	return { valid: true, value: locked.value, source: "lockfile" };
}

function rollbackRelayPublicKeySourceArtifactFailure(
	sourceText: string,
	locked: z.infer<typeof RollbackRelayPublicKeyLockEntrySchema>,
): string | undefined {
	let source: z.infer<typeof RollbackRelayPublicKeySourceSchema>;
	try {
		source = RollbackRelayPublicKeySourceSchema.parse(safeParseJson(sourceText));
	} catch (error) {
		return `rollback rehearsal relay public key source artifact is invalid: ${
			error instanceof Error ? error.message : String(error)
		}`;
	}
	const sourceKey = source.keys.find(
		(key) =>
			key.scope === locked.scope &&
			key.envKey === locked.envKey &&
			key.value === locked.value &&
			key.sha256 === locked.sha256,
	);
	if (!sourceKey) {
		return "rollback rehearsal relay public key source artifact does not contain the pinned key";
	}
	if (sourceKey.sha256 !== sha256Digest(sourceKey.value)) {
		return "rollback rehearsal relay public key source artifact sha256 does not match value";
	}
	return undefined;
}

function safeParseJson(value: string): unknown {
	try {
		return JSON.parse(value) as unknown;
	} catch {
		return undefined;
	}
}

function redactDetail(detail: string): string {
	return redactSecrets(detail).replace(/\s+/g, " ").trim();
}

function collectCliHeadlessProbeEvidence(
	probe: FeatureProbeMatrix["probes"][number],
	options: HermesSignedEvidenceValidationOptions = {},
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
		if (modelProvider.tokenScoping !== "peer-bound") {
			failures.push("modelProvider.tokenScoping is not peer-bound");
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
		const signatureFailure = openAiCodexRelayProofSignatureFailure(
			relayProof as OpenAiCodexRelayProof,
			{
				allowStale: hermesAllowsStaleAttestations(options),
				maxSkewMs: HERMES_EVIDENCE_PROOF_MAX_SKEW_MS,
				relayPublicKey: options.relayPublicKey,
			},
		);
		if (signatureFailure) {
			failures.push(`relay proof signature is invalid: ${signatureFailure}`);
		}
		const freshnessFailure = hermesAttestationFreshnessFailure(
			"relay proof observedAt",
			relayProof.observedAt,
			options,
		);
		if (freshnessFailure) failures.push(freshnessFailure);
		if (!provenance?.expectedProofToken) {
			failures.push("relay proof cannot be bound because expectedProofToken is missing");
		} else {
			const expectedProofTokenSha256 = openAiCodexRelayProofTokenSha256(
				provenance.expectedProofToken,
			);
			if (!relayProof.proofTokenSha256) {
				failures.push("relay proof proofTokenSha256 is missing");
			} else if (relayProof.proofTokenSha256 !== expectedProofTokenSha256) {
				failures.push("relay proof proofTokenSha256 does not match expected proof token");
			}
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

function collectHeadlessEntrypointProbeEvidence(
	probe: FeatureProbeMatrix["probes"][number],
	options: HermesSignedEvidenceValidationOptions = {},
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

	const parsed = HeadlessEntrypointProofSchema.safeParse(evidence);
	if (!parsed.success) {
		return featureProbeEvidenceFailure(
			probe,
			`invalid feature probe evidence ${probe.surface_id}: ${flattenZodError(parsed.error)}`,
		);
	}

	const failures: string[] = [];
	if (parsed.data.status !== "pass") failures.push(`status is ${parsed.data.status}`);
	if (parsed.data.ran !== true) failures.push(`ran is ${String(parsed.data.ran)}`);
	if (!parsed.data.testReport) {
		failures.push("testReport is missing");
	} else {
		const reportPath = resolveHermesArtifactPath(parsed.data.testReport.reportPath);
		if (!fs.existsSync(reportPath)) {
			failures.push(`testReport.reportPath is missing: ${parsed.data.testReport.reportPath}`);
		} else {
			const actualDigest = sha256Digest(fs.readFileSync(reportPath));
			if (actualDigest !== parsed.data.testReport.reportSha256) {
				failures.push(
					`testReport.reportSha256 is ${parsed.data.testReport.reportSha256}, expected ${actualDigest}`,
				);
			}
		}
		for (const [sourcePath, expectedDigest] of Object.entries(
			parsed.data.testReport.sourceDigests,
		)) {
			const resolvedSource = resolveHermesArtifactPath(sourcePath);
			if (!fs.existsSync(resolvedSource)) {
				failures.push(`testReport source digest path is missing: ${sourcePath}`);
				continue;
			}
			const actualDigest = sha256Digest(fs.readFileSync(resolvedSource));
			if (actualDigest !== expectedDigest) {
				failures.push(
					`testReport source digest ${sourcePath} is ${expectedDigest}, expected ${actualDigest}`,
				);
			}
		}
	}
	const checkByName = new Map(parsed.data.checks.map((check) => [check.name, check]));
	for (const checkName of HERMES_HEADLESS_ENTRYPOINT_REQUIRED_CHECKS) {
		const check = checkByName.get(checkName);
		if (!check) {
			failures.push(`missing headless entrypoint check ${checkName}`);
		} else if (check.status !== "pass") {
			failures.push(`headless entrypoint check ${checkName} is ${check.status}`);
		}
	}
	const duplicateChecks = findDuplicates(parsed.data.checks.map((check) => check.name));
	if (duplicateChecks.length > 0) {
		failures.push(`duplicate headless entrypoint checks: ${duplicateChecks.join(", ")}`);
	}
	if (parsed.data.checks.length === 0) failures.push("headless entrypoint checks are empty");
	const generatedAtFailure = hermesAttestationFreshnessFailure(
		"headless entrypoint generatedAt",
		parsed.data.generatedAt,
		options,
	);
	if (generatedAtFailure) failures.push(generatedAtFailure);

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
		detail:
			"feature probe evidence execution.headless_entrypoint observed pass across streaming, terminal, session, tool, approval, cancellation, deterministic error, and redaction semantics",
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
	options: HermesSignedEvidenceValidationOptions = {},
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
	const schemaOnlyFailure = schemaOnlyEdgeAdapterEnforcementFailure(probe.surface_id, evidence);
	if (schemaOnlyFailure) {
		return featureProbeEvidenceFailure(probe, schemaOnlyFailure);
	}
	const failure = edgeAdapterProbeEvidenceFailure(probe.surface_id, evidence, options);
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
		detail: `feature probe evidence ${probe.surface_id} observed edge adapter contract controls`,
	};
}

function schemaOnlyEdgeAdapterEnforcementFailure(
	surfaceId: string,
	evidence: unknown,
): string | null {
	if (!isEdgeAdapterFeatureSurfaceId(surfaceId)) return null;
	if (!isPlainRecord(evidence)) return null;
	const schemaOnly =
		evidence.source === EDGE_ADAPTER_CONTRACT_PROBE_SOURCE || !("runtime" in evidence);
	if (!schemaOnly) return null;
	return `feature probe evidence ${surfaceId} runtime harness evidence is missing; schema-only edge contract-unit evidence cannot prove runtime consumer/authorizer enforcement before cutover pass`;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function collectSideEffectLedgerProbeEvidence(
	probe: FeatureProbeMatrix["probes"][number],
	options: HermesSignedEvidenceValidationOptions = {},
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
	const failure = sideEffectLedgerProbeEvidenceFailure(probe.surface_id, evidence, options);
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

function collectHostilePeerProbeEvidence(
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
	const failure = hostilePeerProbeEvidenceFailure(probe.surface_id, evidence);
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
		detail: `feature probe evidence ${probe.surface_id} observed hostile contained-peer controls`,
	};
}

function collectProviderApprovalBindingProbeEvidence(
	probe: FeatureProbeMatrix["probes"][number],
	options: HermesSignedEvidenceValidationOptions = {},
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
	const failure = providerApprovalBindingProbeEvidenceFailure(evidence, options);
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

function collectHouseholdReminderProbeEvidence(
	probe: FeatureProbeMatrix["probes"][number],
	options: HermesSignedEvidenceValidationOptions = {},
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
	const failure = householdReminderProbeEvidenceFailure(evidence, options);
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
		detail: `feature probe evidence ${probe.surface_id} observed the signed Phase 0 acceptance matrix`,
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

function collectGoogleProviderProbeEvidence(
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
	const failure = googleProviderProbeEvidenceFailure(evidence);
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
		detail: `feature probe evidence ${probe.surface_id} observed Google provider custody and approval controls`,
	};
}

function collectBrowserComputerBrokerProbeEvidence(
	probe: FeatureProbeMatrix["probes"][number],
	options: HermesSignedEvidenceValidationOptions = {},
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
	const failure = browserComputerBrokerProbeEvidenceFailure(probe.surface_id, evidence, options);
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
	options: HermesSignedEvidenceValidationOptions = {},
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
	const failure = workflowProbeEvidenceFailure(probe.surface_id, evidence, options);
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

function collectServedMcpMemoryProbeEvidence(
	probe: FeatureProbeMatrix["probes"][number],
	options: HermesSignedEvidenceValidationOptions = {},
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
	const report = evaluateServedMcpMemoryEvidence(evidence, {
		...options,
		missingPath: resolvedPath,
	});
	if (report.status !== "pass" || !report.productionEnable) {
		return featureProbeEvidenceFailure(
			probe,
			`feature probe evidence ${probe.surface_id} did not pass: ${redactDetail(
				report.gates
					.filter((gate) => gate.status !== "pass")
					.map((gate) => gate.detail)
					.join("; ") || report.status,
			)}`,
		);
	}
	return {
		surface_id: probe.surface_id,
		status: "pass",
		evidence_path: probe.evidence_path,
		detail: `feature probe evidence ${probe.surface_id} observed served-MCP memory controls`,
	};
}

function collectSkillsAllowlistProbeEvidence(
	probe: FeatureProbeMatrix["probes"][number],
	options: HermesSignedEvidenceValidationOptions = {},
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
	const report = evaluateSkillsAllowlistEvidence(evidence, {
		...options,
		missingPath: resolvedPath,
	});
	if (report.status !== "pass" || !report.productionEnable) {
		return featureProbeEvidenceFailure(
			probe,
			`feature probe evidence ${probe.surface_id} did not pass: ${redactDetail(
				report.gates
					.filter((gate) => gate.status !== "pass")
					.map((gate) => gate.detail)
					.join("; ") || report.status,
			)}`,
		);
	}
	return {
		surface_id: probe.surface_id,
		status: "pass",
		evidence_path: probe.evidence_path,
		detail: `feature probe evidence ${probe.surface_id} observed contained skills allowlist controls`,
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
	options: HermesSignedEvidenceValidationOptions = {},
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

	const failures = modelRelayProbeEvidenceFailures(parsed.data, options);
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

function modelRelayProbeEvidenceFailures(
	evidence: z.infer<typeof ModelRelayProbeEvidenceSchema>,
	options: HermesSignedEvidenceValidationOptions,
): string[] {
	const failures: string[] = [];
	if (evidence.status !== "pass") failures.push(`status is ${evidence.status}`);
	if (evidence.ran !== true) failures.push(`ran is ${String(evidence.ran)}`);
	const freshnessFailure = hermesAttestationFreshnessFailure(
		"model-relay evidence generatedAt",
		evidence.generatedAt,
		options,
	);
	if (freshnessFailure) failures.push(freshnessFailure);
	if (evidence.posture !== REQUIRED_CUTOVER_NETWORK_PROBE_POSTURE) {
		failures.push(
			`posture is ${evidence.posture ?? "missing"}; expected ${REQUIRED_CUTOVER_NETWORK_PROBE_POSTURE}`,
		);
	}
	if (!evidence.observation.relayUrl) {
		failures.push("observation.relayUrl is missing");
	} else if (isDirectModelRelayProviderUrl(evidence.observation.relayUrl)) {
		failures.push("observation.relayUrl points at a direct model-provider host");
	} else if (!isRelayModelProbeUrl(evidence.observation.relayUrl)) {
		failures.push("observation.relayUrl is not the Telclaude model relay probe endpoint");
	}
	if (!isDirectModelRelayProviderUrl(evidence.observation.directModelUrl)) {
		failures.push("observation.directModelUrl is not a recognized direct model-provider URL");
	}
	const origin = evidence.origin;
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
	failures.push(
		...modelRelayModelProviderFailures(evidence.modelProvider, evidence.observation.relayUrl),
	);
	if (!evidence.observation.profileDir) {
		failures.push("observation.profileDir is missing");
	} else if (
		normalizeHermesProfilePath(evidence.observation.profileDir) !== REQUIRED_MODEL_RELAY_PROFILE_DIR
	) {
		failures.push(
			`observation.profileDir is ${evidence.observation.profileDir}; expected ${REQUIRED_MODEL_RELAY_PROFILE_DIR}`,
		);
	}
	const scannedProfileFiles = (evidence.observation.scannedProfileFiles ?? []).map(
		normalizeHermesProfilePath,
	);
	if (scannedProfileFiles.length === 0) {
		failures.push("observation.scannedProfileFiles is empty");
	}
	for (const requiredPath of REQUIRED_MODEL_RELAY_SCANNED_PROFILE_FILES) {
		if (!scannedProfileFiles.includes(requiredPath)) {
			failures.push(`observation.scannedProfileFiles is missing ${requiredPath}`);
		}
	}

	const gateByName = new Map(evidence.gates.map((gate) => [gate.name, gate]));
	for (const gateName of requiredModelRelayGateNames(evidence.posture)) {
		const gate = gateByName.get(gateName);
		if (!gate) {
			failures.push(`gate ${gateName} is missing`);
		} else if (gate.status !== "pass") {
			failures.push(`gate ${gateName} is ${gate.status}: ${redactDetail(gate.detail)}`);
		}
	}
	return failures;
}

function normalizeHermesProfilePath(value: string): string {
	const normalized = value.replace(/\\/g, "/").replace(/\/+$/, "");
	return normalized.startsWith("./") ? normalized.slice(2) : normalized;
}

function modelRelayModelProviderFailures(
	modelProvider: z.infer<typeof ModelRelayProbeEvidenceSchema>["modelProvider"],
	relayUrl: string | undefined,
): string[] {
	const failures: string[] = [];
	if (!modelProvider) return ["modelProvider is missing"];
	if (modelProvider.provider !== "openai-codex") {
		failures.push("modelProvider.provider is not openai-codex");
	}
	if (modelProvider.authScope !== "relay-openai-codex-subscription-proxy") {
		failures.push("modelProvider.authScope is not relay-openai-codex-subscription-proxy");
	}
	if (modelProvider.authLocation !== "hermes-auth-store:openai-codex") {
		failures.push("modelProvider.authLocation is not hermes-auth-store:openai-codex");
	}
	if (modelProvider.tokenScoping !== "peer-bound") {
		failures.push("modelProvider.tokenScoping is not peer-bound");
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
	if (relayUrl && !sameRelayOrigin(modelProvider.baseUrl, relayUrl)) {
		failures.push("modelProvider.baseUrl is not bound to observation.relayUrl origin");
	}
	try {
		if (modelProvider.baseUrlHost !== new URL(modelProvider.baseUrl).hostname) {
			failures.push("modelProvider.baseUrlHost does not match baseUrl");
		}
	} catch {
		failures.push("modelProvider.baseUrl is not parseable");
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
	} else if (relayUrl && !sameRelayOrigin(modelProvider.auxiliaryBaseUrl, relayUrl)) {
		failures.push("modelProvider.auxiliaryBaseUrl is not bound to observation.relayUrl origin");
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
	return failures;
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

function isRelayModelProbeUrl(value: string): boolean {
	try {
		const parsed = new URL(value);
		return (
			parsed.protocol === "http:" &&
			parsed.hostname === "telclaude" &&
			parsed.port === "8790" &&
			parsed.pathname.replace(/\/+$/, "") === "/v1/models" &&
			parsed.search === "" &&
			parsed.hash === "" &&
			value.replace(/\/+$/, "") === TELCLAUDE_MODEL_RELAY_PROBE_URL
		);
	} catch {
		return false;
	}
}

function sameRelayOrigin(left: string, right: string): boolean {
	try {
		const leftUrl = new URL(left);
		const rightUrl = new URL(right);
		return (
			leftUrl.protocol === rightUrl.protocol &&
			leftUrl.hostname === rightUrl.hostname &&
			leftUrl.port === rightUrl.port
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
