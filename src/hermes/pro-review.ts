import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { z } from "zod";
import { filterOutput } from "../security/output-filter.js";
import type { HermesSignedEvidenceValidationOptions } from "./attestation-validation.js";
import {
	type BrowserComputerBrokerSurfaceId,
	browserComputerBrokerProbeEvidenceFailure,
} from "./browser-computer-broker-probes.js";
import { edgeAdapterProbeEvidenceFailure } from "./edge-adapter-probes.js";
import {
	archivedHermesEvidenceValidationOptions,
	collectFeatureProbeEvidence,
	type FeatureProbeMatrix,
	HERMES_HEADLESS_ENTRYPOINT_SURFACE_ID,
	hermesFixtureEvidenceFileFailure,
	modelRelayProbeEvidenceFailure,
	REQUIRED_CUTOVER_NETWORK_PROBE_POSTURE,
	resolveHermesArtifactPath,
} from "./foundation.js";
import { sideEffectLedgerProbeEvidenceFailure } from "./mcp/side-effect-ledger-probe.js";
import {
	type NetworkProbeId,
	networkProbeEvidenceFailure,
} from "./network-probe-evidence-validation.js";
import { readHermesCliHeadlessProbeReport } from "./private-runtime.js";
import { providerApprovalBindingProbeEvidenceFailure } from "./provider-approval-binding-probe.js";
import {
	type ProviderDomainSurfaceId,
	providerDomainProbeEvidenceFailure,
} from "./provider-domain-probes.js";
import { googleProviderProbeEvidenceFailure } from "./provider-google-probe.js";
import { providerReleasePolicyProbeEvidenceFailure } from "./provider-release-policy-probe.js";
import { servedMcpProviderToolsProbeEvidenceFailure } from "./served-mcp-provider-tools-probe.js";
import { workflowProbeEvidenceFailure } from "./workflow-probes.js";

export const DEFAULT_PRO_REVIEW_REQUEST_PATH = "docs/hermes/pro-review-request.json";
export const DEFAULT_PRO_REVIEW_NATIVE_CANARY_PATH =
	"artifacts/hermes/pro-review-native-canary.json";
const PRO_REVIEW_CUTOVER_PROOF_BUNDLE_PATH = "docs/hermes/cutover-proof-bundle.json";
const PRO_REVIEW_CURRENT_CUTOVER_CHECK_PATH =
	"artifacts/hermes/pro-review-current-cutover-check.json";
export const PRO_REVIEW_REQUEST_SCHEMA_VERSION = "telclaude.hermes.pro-review-request.v1";
export const PRO_REVIEW_NATIVE_CANARY_SCHEMA_VERSION =
	"telclaude.hermes.pro-review-native-canary.v1";
export const PRO_REVIEW_SHARD_PLAN_SCHEMA_VERSION = "telclaude.hermes.pro-review-shard-plan.v1";
export const PRO_REVIEW_NATIVE_CANARY_MAX_AGE_MS = 15 * 60 * 1000;
const PRO_REVIEW_MIN_YOETZ_NATIVE_VERSION = "0.5.26";
const PRO_REVIEW_CURRENT_CUTOVER_CHECK_MAX_AGE_MS = 15 * 60 * 1000;
const PRO_REVIEW_PAYLOAD_BINDING_FIELDS = [
	"reviewer",
	"transport",
	"model",
	"fallbackAllowed",
	"transportEvidence",
	"blockedFallbacks",
	"prompt",
	"selectedFiles",
	"selectedFileContentsSha256",
	"transportEvidenceSha256",
] as const;
const PRO_REVIEW_SHARDED_PAYLOAD_BINDING_FIELDS = [
	...PRO_REVIEW_PAYLOAD_BINDING_FIELDS,
	"reviewMode",
	"shardPlanSha256",
] as const;
const REQUIRED_PRO_REVIEW_BLOCKED_FALLBACKS = [
	"cdp",
	"api-key",
	"manual-browser",
	"claude-substitution",
	"amq-substitution",
] as const;
const PRO_REVIEW_EDGE_PROBE_PATHS = {
	"artifacts/hermes/probes/edge-whatsapp.json": "edge.whatsapp",
	"artifacts/hermes/probes/edge-email.json": "edge.email",
	"artifacts/hermes/probes/edge-agentmail.json": "edge.agentmail",
	"artifacts/hermes/probes/edge-social.json": "edge.social",
	"artifacts/hermes/probes/identity-migration.json": "identity.migration",
	"artifacts/hermes/probes/household-scopes.json": "household.scopes",
	"artifacts/hermes/probes/attachment-quarantine.json": "attachment.quarantine",
	"artifacts/hermes/probes/outbound-policy.json": "outbound.policy",
	"artifacts/hermes/probes/public-social-isolation.json": "public.social.isolation",
} as const;
const PRO_REVIEW_SIGNED_PROBE_PATHS = {
	...PRO_REVIEW_EDGE_PROBE_PATHS,
	"artifacts/hermes/probes/sideeffect-ledger.json": "sideeffect.ledger",
	"artifacts/hermes/probes/providers-approval-binding.json": "providers.approval-binding",
	"artifacts/hermes/probes/workflow-cron.json": "workflow.cron",
	"artifacts/hermes/probes/workflow-longrun.json": "workflow.longrun",
} as const;
const PRO_REVIEW_BROWSER_COMPUTER_PROBE_PATHS = {
	"artifacts/hermes/probes/browser-profiles.json": "browser.profiles",
	"artifacts/hermes/probes/computer-broker.json": "computer.broker",
	"artifacts/hermes/probes/network-egress-broker.json": "network.egress-broker",
} as const satisfies Record<string, BrowserComputerBrokerSurfaceId>;
const PRO_REVIEW_PROVIDER_DOMAIN_PROBE_PATHS = {
	"artifacts/hermes/probes/providers-bank.json": "providers.bank",
	"artifacts/hermes/probes/providers-clalit.json": "providers.clalit",
	"artifacts/hermes/probes/providers-government.json": "providers.government",
} as const satisfies Record<string, ProviderDomainSurfaceId>;
const PRO_REVIEW_NETWORK_PROBE_PATHS = {
	"artifacts/hermes/network/relay-control-allowed.json": "network.relay-control-allowed",
	"artifacts/hermes/network/direct-provider-denied.json": "network.direct-provider-denied",
	"artifacts/hermes/network/direct-vault-denied.json": "network.direct-vault-denied",
	"artifacts/hermes/network/direct-model-provider-denied.json":
		"network.direct-model-provider-denied",
	"artifacts/hermes/network/dns-exfil-denied.json": "network.dns-exfil-denied",
} as const satisfies Record<string, NetworkProbeId>;
const PRO_REVIEW_GOOGLE_PROVIDER_PROBE_PATH = "artifacts/hermes/probes/providers-google.json";
const PRO_REVIEW_PROVIDER_RELEASE_POLICY_PROBE_PATH =
	"artifacts/hermes/probes/providers-release-policy.json";
const PRO_REVIEW_SERVED_MCP_PROVIDER_TOOLS_PROBE_PATH =
	"artifacts/hermes/probes/served-mcp-provider-tools.json";
const PRO_REVIEW_CLI_HEADLESS_PROBE_PATH = "artifacts/hermes/probes/execution-cli-headless.json";
const PRO_REVIEW_HEADLESS_ENTRYPOINT_PROBE_PATH =
	"artifacts/hermes/probes/execution-headless-entrypoint.json";
const PRO_REVIEW_HEADLESS_ENTRYPOINT_TEST_REPORT_PATH =
	"artifacts/hermes/probes/execution-headless-entrypoint.vitest.json";
const PRO_REVIEW_MODEL_RELAY_PROBE_PATH = "artifacts/hermes/probes/model-relay.json";
const PRO_REVIEW_KNOWN_PROBE_ARTIFACT_PATHS = new Set<string>([
	PRO_REVIEW_CLI_HEADLESS_PROBE_PATH,
	PRO_REVIEW_HEADLESS_ENTRYPOINT_PROBE_PATH,
	PRO_REVIEW_MODEL_RELAY_PROBE_PATH,
	...Object.keys(PRO_REVIEW_SIGNED_PROBE_PATHS),
	...Object.keys(PRO_REVIEW_BROWSER_COMPUTER_PROBE_PATHS),
	...Object.keys(PRO_REVIEW_PROVIDER_DOMAIN_PROBE_PATHS),
	PRO_REVIEW_GOOGLE_PROVIDER_PROBE_PATH,
	PRO_REVIEW_PROVIDER_RELEASE_POLICY_PROBE_PATH,
	PRO_REVIEW_SERVED_MCP_PROVIDER_TOOLS_PROBE_PATH,
]);
const PRO_REVIEW_SEMANTIC_DEPENDENCY_ARTIFACT_PATHS = new Set<string>([
	"artifacts/hermes/probes/execution-served-mcp-containment.json",
]);
export const REQUIRED_PRO_REVIEW_FILES = [
	"CLAUDE.md",
	"SECURITY.md",
	"docs/architecture.md",
	PRO_REVIEW_CUTOVER_PROOF_BUNDLE_PATH,
	"docs/hermes/cutover-scope.json",
	"docs/hermes/decisions.json",
	"docs/hermes/feature-probes.json",
	"docs/hermes/hermes-compat.lock.json",
	"docs/hermes/inventory.json",
	"docs/hermes/no-fork-proof.json",
	"docs/hermes/profile-generation-proof.json",
	"docs/hermes/queue-snapshot.json",
	"docs/hermes/rollback-relay-public-key.lock.json",
	"docs/hermes/rollback-relay-public-key-source.82ac7ed-egress.json",
	"src/hermes/pro-review.ts",
	"src/hermes/api-adapter.ts",
	"src/hermes/api-server-containment.ts",
	"src/hermes/approval-continuation-runner.ts",
	"src/hermes/approval-continuation.ts",
	"src/hermes/attestation-validation.ts",
	"src/hermes/edge-adapter-contract.ts",
	"src/hermes/edge-adapter-runtime.ts",
	"src/hermes/edge-adapter-probes.ts",
	"src/hermes/edge-adapter-attestation.ts",
	"src/hermes/browser-computer-broker-attestation.ts",
	"src/hermes/browser-computer-broker-probes.ts",
	"src/hermes/inventory.ts",
	"src/hermes/private-runtime.ts",
	"src/hermes/foundation.ts",
	"src/hermes/model-relay.ts",
	"src/hermes/private-telegram-fixture-attestation.ts",
	"src/hermes/network-probe-evidence-validation.ts",
	"src/hermes/network-probe-schema.ts",
	"src/hermes/network-probe-attestation.ts",
	"src/hermes/network-probe-semantic-proof.ts",
	"src/hermes/no-fork-proof.ts",
	"src/hermes/no-fork-attestation.ts",
	"src/hermes/network-probes.ts",
	"src/hermes/private-execute.ts",
	"src/hermes/private-runtime-control.ts",
	"src/hermes/provider-approval-binding-probe.ts",
	"src/hermes/provider-approval-binding-attestation.ts",
	"src/hermes/provider-domain-probes.ts",
	"src/hermes/provider-google-probe.ts",
	"src/hermes/provider-release-policy-probe.ts",
	"src/hermes/relay-conversation-store.ts",
	"src/hermes/rollback-rehearsal.ts",
	"src/hermes/runtime-network.ts",
	"src/hermes/served-mcp-provider-tools-probe.ts",
	"src/hermes/served-mcp-containment-schema.ts",
	"src/hermes/served-mcp-containment.ts",
	"src/hermes/session-map.ts",
	"src/hermes/workflow-probes.ts",
	"src/hermes/workflow-run-ledger.ts",
	"src/hermes/workflow-run-ledger-attestation.ts",
	"src/providers/catalog.json",
	"src/providers/catalog.ts",
	"src/providers/external-provider.ts",
	"src/providers/index.ts",
	"src/providers/provider-health.ts",
	"src/providers/provider-skill.ts",
	"src/providers/provider-validation.ts",
	"src/google-services/actions.ts",
	"src/google-services/approval.ts",
	"src/google-services/config.ts",
	"src/google-services/handler-utils.ts",
	"src/google-services/handlers/calendar.ts",
	"src/google-services/handlers/contacts.ts",
	"src/google-services/handlers/drive.ts",
	"src/google-services/handlers/gmail.ts",
	"src/google-services/health.ts",
	"src/google-services/index.ts",
	"src/google-services/server.ts",
	"src/google-services/token-manager.ts",
	"src/google-services/types.ts",
	"src/cron/actions.ts",
	"src/cron/agent-action.ts",
	"src/cron/index.ts",
	"src/cron/parse.ts",
	"src/cron/preprocess.ts",
	"src/cron/scheduler.ts",
	"src/cron/store.ts",
	"src/cron/suppression.ts",
	"src/cron/types.ts",
	"src/background/cron-run-executor.ts",
	"src/background/host.ts",
	"src/background/index.ts",
	"src/background/jobs.ts",
	"src/background/notifier.ts",
	"src/background/runner.ts",
	"src/background/types.ts",
	"src/hermes/mcp/authority-registry.ts",
	"src/hermes/mcp/bridge.ts",
	"src/hermes/mcp/policy.ts",
	"src/hermes/mcp/side-effect-ledger-probe.ts",
	"src/hermes/mcp/side-effect-ledger-attestation.ts",
	"src/hermes/mcp/provider-routing.ts",
	"src/hermes/mcp/provider-sidecar-token.ts",
	"src/hermes/mcp/side-effect-ledger.ts",
	"src/hermes/mcp/side-effect-human-approval.ts",
	"src/hermes/mcp/approval-token.ts",
	"src/hermes/mcp/ledger-execute.ts",
	"src/hermes/mcp/live-admin.ts",
	"src/hermes/mcp/live-connection-resolver.ts",
	"src/hermes/mcp/live-listen.ts",
	"src/hermes/mcp/live-probe-tokens.ts",
	"src/hermes/mcp/live-side-effect-approvals.ts",
	"src/hermes/mcp/live-relay-clients.ts",
	"src/hermes/mcp/live-server.ts",
	"src/hermes/mcp/live-runtime.ts",
	"src/commands/hermes.ts",
	"src/relay/capabilities.ts",
	"src/relay/provider-approval.ts",
	"src/relay/provider-proxy.ts",
	"src/relay/openai-codex-proxy.ts",
	"src/relay/openai-codex-relay-proof.ts",
	"docker/docker-compose.hermes.yml",
	"docker/hermes-contained-entrypoint.sh",
	"scripts/hermes-contained-cli-probe.sh",
	"artifacts/hermes/probes/edge-whatsapp.json",
	"artifacts/hermes/probes/edge-email.json",
	"artifacts/hermes/probes/edge-agentmail.json",
	"artifacts/hermes/probes/edge-social.json",
	"artifacts/hermes/probes/identity-migration.json",
	"artifacts/hermes/probes/household-scopes.json",
	"artifacts/hermes/probes/attachment-quarantine.json",
	"artifacts/hermes/probes/outbound-policy.json",
	"artifacts/hermes/probes/public-social-isolation.json",
	"artifacts/hermes/fixtures/fixture.public.whatsapp.basic.json",
	"artifacts/hermes/fixtures/fixture.household.whatsapp.benign.json",
	"artifacts/hermes/fixtures/fixture.public.whatsapp.unknown-deny.json",
	"artifacts/hermes/fixtures/fixture.household.whatsapp.provider-unscoped-deny.json",
	"artifacts/hermes/fixtures/fixture.public.email.basic.json",
	"artifacts/hermes/fixtures/fixture.household.email.scoped.json",
	"artifacts/hermes/fixtures/fixture.public.email.wrong-thread-deny.json",
	"artifacts/hermes/fixtures/fixture.household.email.private-memory-deny.json",
	"artifacts/hermes/fixtures/fixture.public.agentmail.basic.json",
	"artifacts/hermes/fixtures/fixture.public.agentmail.direct-key-deny.json",
	"artifacts/hermes/fixtures/fixture.public.social.timeline.json",
	"artifacts/hermes/fixtures/fixture.public.social.reply.json",
	"artifacts/hermes/fixtures/fixture.public.social.private-leak-deny.json",
	"artifacts/hermes/fixtures/fixture.public.social.budget-deny.json",
	"artifacts/hermes/fixtures/fixture.household.provider.strong-link-read.json",
	"artifacts/hermes/fixtures/fixture.household.private-memory-deny.json",
	"artifacts/hermes/fixtures/fixture.household.provider-number-only-deny.json",
	"artifacts/hermes/fixtures/fixture.household.cross-recipient-deny.json",
	"artifacts/hermes/probes/browser-profiles.json",
	"artifacts/hermes/probes/computer-broker.json",
	"artifacts/hermes/probes/network-egress-broker.json",
	"artifacts/hermes/probes/providers-approval-binding.json",
	"artifacts/hermes/probes/providers-bank.json",
	"artifacts/hermes/probes/providers-clalit.json",
	"artifacts/hermes/probes/providers-government.json",
	"artifacts/hermes/probes/providers-google.json",
	"artifacts/hermes/probes/providers-release-policy.json",
	"artifacts/hermes/probes/served-mcp-provider-tools.json",
	"artifacts/hermes/probes/sideeffect-ledger.json",
	"artifacts/hermes/probes/workflow-cron.json",
	"artifacts/hermes/probes/workflow-longrun.json",
	"artifacts/hermes/probes/model-relay.json",
	"artifacts/hermes/fixtures/fixture.providers.bank.read.json",
	"artifacts/hermes/fixtures/fixture.providers.bank.prepare-transfer.json",
	"artifacts/hermes/fixtures/fixture.providers.bank.approved-transfer.json",
	"artifacts/hermes/fixtures/fixture.providers.bank.wrong-actor-deny.json",
	"artifacts/hermes/fixtures/fixture.providers.bank.replay-deny.json",
	"artifacts/hermes/fixtures/fixture.providers.bank.direct-provider-deny.json",
	"artifacts/hermes/fixtures/fixture.providers.clalit.read.json",
	"artifacts/hermes/fixtures/fixture.providers.clalit.prepare-message.json",
	"artifacts/hermes/fixtures/fixture.providers.clalit.approved-booking.json",
	"artifacts/hermes/fixtures/fixture.providers.clalit.wrong-actor-deny.json",
	"artifacts/hermes/fixtures/fixture.providers.clalit.emergency-escalate.json",
	"artifacts/hermes/fixtures/fixture.providers.clalit.direct-provider-deny.json",
	"artifacts/hermes/fixtures/fixture.providers.government.read.json",
	"artifacts/hermes/fixtures/fixture.providers.government.prepare-form.json",
	"artifacts/hermes/fixtures/fixture.providers.government.approved-submit.json",
	"artifacts/hermes/fixtures/fixture.providers.government.wrong-actor-deny.json",
	"artifacts/hermes/fixtures/fixture.providers.government.replay-deny.json",
	"artifacts/hermes/fixtures/fixture.providers.government.direct-provider-deny.json",
	"artifacts/hermes/fixtures/fixture.providers.google.read.json",
	"artifacts/hermes/fixtures/fixture.providers.google.prepare-write.json",
	"artifacts/hermes/fixtures/fixture.providers.google.approved-write.json",
	"artifacts/hermes/fixtures/fixture.providers.google.wrong-actor-deny.json",
	"artifacts/hermes/fixtures/fixture.providers.google.replay-deny.json",
	"artifacts/hermes/fixtures/fixture.providers.google.direct-provider-deny.json",
	"artifacts/hermes/fixtures/fixture.cron.background.delivery.json",
	"artifacts/hermes/fixtures/fixture.cron.duplicate-deny.json",
	"artifacts/hermes/fixtures/fixture.longrun.approval-resume.json",
	"artifacts/hermes/fixtures/fixture.longrun.stale-resume-deny.json",
	"artifacts/hermes/fixtures/fixture.browser.allowed-research.json",
	"artifacts/hermes/fixtures/fixture.browser.cross-domain-deny.json",
	"artifacts/hermes/fixtures/fixture.browser.cookie-leak-deny.json",
	"artifacts/hermes/fixtures/fixture.computer.allowed-target.json",
	"artifacts/hermes/fixtures/fixture.computer.unauthorized-target-deny.json",
	"artifacts/hermes/probes/execution-cli-headless.json",
	PRO_REVIEW_HEADLESS_ENTRYPOINT_PROBE_PATH,
	PRO_REVIEW_HEADLESS_ENTRYPOINT_TEST_REPORT_PATH,
	"artifacts/hermes/network/relay-control-allowed.json",
	"artifacts/hermes/network/direct-provider-denied.json",
	"artifacts/hermes/network/direct-vault-denied.json",
	"artifacts/hermes/network/direct-model-provider-denied.json",
	"artifacts/hermes/network/dns-exfil-denied.json",
	"artifacts/hermes/pro-review-native-canary.json",
	PRO_REVIEW_CURRENT_CUTOVER_CHECK_PATH,
	"tests/hermes/edge-adapter-contract.test.ts",
	"tests/hermes/edge-adapter-runtime.test.ts",
	"tests/hermes/edge-adapter-probes.test.ts",
	"tests/hermes/browser-computer-broker-probes.test.ts",
	"tests/hermes/network-probes.test.ts",
	"tests/hermes/foundation-network-evidence.test.ts",
	"tests/hermes/model-relay.test.ts",
	"tests/integration/telegram-control-plane.replay.test.ts",
	"tests/telegram/command-gating.test.ts",
	"tests/hermes/provider-approval-binding-probe.test.ts",
	"tests/hermes/provider-domain-probes.test.ts",
	"tests/hermes/provider-google-probe.test.ts",
	"tests/hermes/provider-release-policy-probe.test.ts",
	"tests/hermes/served-mcp-provider-tools-probe.test.ts",
	"tests/hermes/workflow-probes.test.ts",
	"tests/hermes/workflow-run-ledger.test.ts",
	"tests/providers/provider-runtime-sync.integration.test.ts",
	"tests/providers/provider-validation.test.ts",
	"tests/google-services/actions.test.ts",
	"tests/google-services/approval.test.ts",
	"tests/google-services/gmail-base64.test.ts",
	"tests/google-services/input-sanitization.test.ts",
	"tests/google-services/server.test.ts",
	"tests/cron/actions.test.ts",
	"tests/cron/agent-action.test.ts",
	"tests/cron/parse.test.ts",
	"tests/cron/preprocess.test.ts",
	"tests/cron/store.test.ts",
	"tests/background/cron-run-executor.test.ts",
	"tests/background/jobs.test.ts",
	"tests/background/notifier.test.ts",
	"tests/background/runner.test.ts",
	"tests/hermes/pro-review.test.ts",
	"tests/hermes/pro-review-semantic-artifacts.test.ts",
	"tests/hermes/mcp-approval-token.test.ts",
	"tests/hermes/mcp-authority-registry.test.ts",
	"tests/hermes/mcp-bridge.test.ts",
	"tests/hermes/mcp-side-effect-ledger-probe.test.ts",
	"tests/hermes/mcp-side-effect-ledger.test.ts",
	"tests/hermes/mcp-side-effect-human-approval.test.ts",
	"tests/hermes/mcp-ledger-execute.test.ts",
	"tests/hermes/mcp-live-admin.test.ts",
	"tests/hermes/mcp-live-connection-resolver.test.ts",
	"tests/hermes/mcp-live-listen.test.ts",
	"tests/hermes/mcp-live-probe-tokens.test.ts",
	"tests/hermes/mcp-live-relay-clients.test.ts",
	"tests/hermes/mcp-live-server.test.ts",
	"tests/hermes/mcp-live-runtime.test.ts",
	"tests/hermes/no-fork-proof.test.ts",
	"tests/hermes/private-runtime-control.test.ts",
	"tests/hermes/provider-sidecar-token.test.ts",
	"tests/hermes/rollback-rehearsal.test.ts",
	"tests/hermes/served-mcp-containment.test.ts",
	"tests/commands/hermes.test.ts",
	"tests/commands/hermes-live-mcp-admin.test.ts",
	"tests/relay/model-relay-peer-echo.test.ts",
	"tests/relay/provider-approval.test.ts",
	"tests/relay/provider-proxy.test.ts",
	"tests/hermes/private-runtime.test.ts",
	"tests/sandbox/validate-config.test.ts",
	"tests/relay/openai-codex-proxy.test.ts",
] as const;

type ProReviewGate = {
	readonly name: string;
	readonly status: "pass" | "fail" | "pending";
	readonly detail: string;
};

export type ProReviewCheckReport = {
	readonly schemaVersion: "telclaude.hermes.pro-review-check.v1";
	readonly status: "pass" | "fail" | "pending";
	readonly requestPath: string;
	readonly canaryPath: string;
	readonly gates: readonly ProReviewGate[];
	readonly selectedFiles: readonly string[];
	readonly payloadSha256?: string;
	readonly approval?: {
		readonly required: boolean;
		readonly approved: boolean;
		readonly approvalId?: string;
		readonly operator?: string;
		readonly approvedAt?: string;
	};
};

const SHA256_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const Sha256DigestSchema = z.string().regex(SHA256_DIGEST_PATTERN);
const NonEmptyString = z.string().min(1);
const PositiveInteger = z.number().int().positive();

const ProReviewShardItemSchema = z
	.object({
		path: NonEmptyString,
		startLine: PositiveInteger,
		endLine: PositiveInteger,
		bytes: z.number().int().nonnegative(),
		sha256: Sha256DigestSchema,
	})
	.strict();

const ProReviewShardSchema = z
	.object({
		shardId: NonEmptyString,
		index: z.number().int().nonnegative(),
		count: PositiveInteger,
		selectedFiles: z.array(NonEmptyString).min(1),
		selectedFilesSha256: Sha256DigestSchema,
		itemContentsSha256: Sha256DigestSchema,
		sourceBytes: z.number().int().nonnegative(),
		focus: NonEmptyString,
		items: z.array(ProReviewShardItemSchema).min(1),
		shardSha256: Sha256DigestSchema,
	})
	.strict();

const ProReviewShardPlanSchema = z
	.object({
		schemaVersion: z.literal(PRO_REVIEW_SHARD_PLAN_SCHEMA_VERSION),
		strategy: z.literal("selected-file-line-byte-budget-v1"),
		maxShardSourceBytes: PositiveInteger,
		bundleTemplateVersion: z.literal("pro-review-shard-bundle.v1"),
		shards: z.array(ProReviewShardSchema).min(1),
	})
	.strict();

const ProReviewRequestSchema = z
	.object({
		schemaVersion: z.literal(PRO_REVIEW_REQUEST_SCHEMA_VERSION),
		status: z.enum(["pending_operator_disclosure_approval", "approved", "sent", "reviewed"]),
		reviewer: NonEmptyString,
		transport: z.literal("chrome-extension-native"),
		model: z.literal("Extended Pro"),
		fallbackAllowed: z.literal(false),
		transportEvidence: NonEmptyString,
		prompt: NonEmptyString,
		privateWorkspaceDisclosure: z
			.object({
				required: z.literal(true),
				approved: z.boolean(),
				approvalReason: NonEmptyString,
				approvalBindingRequired: z.literal(true),
				approvalId: z.string().nullable(),
				operator: z.string().nullable(),
				approvedAt: z.string().nullable(),
				payloadSha256: Sha256DigestSchema.nullable(),
			})
			.strict(),
		payloadBinding: z
			.object({
				digestAlgorithm: z.literal("sha256"),
				canonicalJsonFields: z
					.tuple([
						z.literal("reviewer"),
						z.literal("transport"),
						z.literal("model"),
						z.literal("fallbackAllowed"),
						z.literal("transportEvidence"),
						z.literal("blockedFallbacks"),
						z.literal("prompt"),
						z.literal("selectedFiles"),
						z.literal("selectedFileContentsSha256"),
						z.literal("transportEvidenceSha256"),
					])
					.or(
						z.tuple([
							z.literal("reviewer"),
							z.literal("transport"),
							z.literal("model"),
							z.literal("fallbackAllowed"),
							z.literal("transportEvidence"),
							z.literal("blockedFallbacks"),
							z.literal("prompt"),
							z.literal("selectedFiles"),
							z.literal("selectedFileContentsSha256"),
							z.literal("transportEvidenceSha256"),
							z.literal("reviewMode"),
							z.literal("shardPlanSha256"),
						]),
					),
				payloadSha256: Sha256DigestSchema,
				promptSha256: Sha256DigestSchema,
				selectedFilesSha256: Sha256DigestSchema,
				selectedFileContentsSha256: Sha256DigestSchema,
				transportEvidenceSha256: Sha256DigestSchema,
				shardPlanSha256: Sha256DigestSchema.nullable().optional(),
				notes: NonEmptyString,
			})
			.strict(),
		selectedFiles: z.array(NonEmptyString).min(1),
		blockedFallbacks: z.array(NonEmptyString),
		reviewMode: z.enum(["single", "sharded"]).optional(),
		shardPlan: ProReviewShardPlanSchema.optional(),
	})
	.strict();

const ProReviewNativeCanarySchema = z
	.object({
		schemaVersion: z.literal(PRO_REVIEW_NATIVE_CANARY_SCHEMA_VERSION),
		status: z.literal("pass"),
		transport: z.literal("chrome-extension-native"),
		recipe: z.literal("chatgpt"),
		modelSelectionStatus: z.literal("selected"),
		modelUsed: z.literal("Extended Pro"),
		live: z.literal(true),
		runId: NonEmptyString,
		conversationId: NonEmptyString,
		conversationUrl: NonEmptyString,
		extensionInstanceId: NonEmptyString,
		extensionVersion: NonEmptyString,
		promptClass: NonEmptyString,
		expectedResponse: z.literal("OK"),
		response: z.literal("OK"),
		warnings: z.array(z.string()),
		observedAt: NonEmptyString,
		reverifiedAt: NonEmptyString,
		dryCanary: z
			.object({
				command: NonEmptyString,
				exitCode: z.literal(0),
				status: z.literal("ok"),
				transport: z.literal("chrome-extension-native"),
				live: z.literal(false),
			})
			.strict(),
		liveCanary: z
			.object({
				command: NonEmptyString,
				exitCode: z.literal(0),
				status: z.literal("ok"),
				transport: z.literal("chrome-extension-native"),
				live: z.literal(true),
				modelUsed: z.literal("Extended Pro"),
				response: z.literal("OK"),
			})
			.strict(),
		nativeStatus: z
			.object({
				command: NonEmptyString,
				exitCode: z.literal(0),
				status: z.literal("connected"),
				detail: NonEmptyString,
				extensionId: NonEmptyString,
				extensionInstanceId: NonEmptyString,
				extensionVersion: NonEmptyString,
				nativeHostName: z.literal("com.yoetz.chatgpt_native"),
				protocolVersion: z.number().int().positive(),
				socketReachable: z.literal(true),
				transport: z.literal("chrome-extension-native"),
			})
			.strict(),
		checks: z.array(
			z
				.object({
					name: NonEmptyString,
					status: z.literal("pass"),
					detail: NonEmptyString,
				})
				.strict(),
		),
	})
	.strict();

export type ProReviewRequest = z.infer<typeof ProReviewRequestSchema>;
export type ProReviewNativeCanary = z.infer<typeof ProReviewNativeCanarySchema>;
export type ProReviewShardPlan = z.infer<typeof ProReviewShardPlanSchema>;
export type ProReviewShard = ProReviewShardPlan["shards"][number];
export type ProReviewSelectedFileDigestEntry =
	| {
			readonly file: string;
			readonly sha256: string;
	  }
	| {
			readonly file: string;
			readonly missing: true;
	  };

export type ProReviewComputedPayloadBinding = {
	readonly payloadSha256: string;
	readonly promptSha256: string;
	readonly selectedFilesSha256: string;
	readonly selectedFileContentsSha256: string;
	readonly transportEvidenceSha256: string;
	readonly shardPlanSha256: string | null;
};

export type ProReviewYoetzSendValidation = {
	readonly status: "pass" | "fail";
	readonly detail: string;
};

export type BuildProReviewRequestInput = {
	readonly existingRequestPath?: string;
	readonly canaryPath?: string;
	readonly prompt?: string;
	readonly selectedFiles?: readonly string[];
	readonly includeExistingSelectedFiles?: boolean;
	readonly shardMaxSourceBytes?: number;
};

export type ApproveProReviewRequestInput = {
	readonly requestPath?: string;
	readonly approvalId: string;
	readonly operator: string;
	readonly approvedAt?: Date | string;
	readonly expectedPayloadSha256?: string;
};

const PRO_REVIEW_NATIVE_YOETZ_ENV_ALLOWED_KEYS = new Set([
	"PATH",
	"HOME",
	"USER",
	"LOGNAME",
	"SHELL",
	"TMPDIR",
	"TMP",
	"TEMP",
	"LANG",
	"LC_ALL",
	"LC_CTYPE",
	"TERM",
	"NO_COLOR",
	"FORCE_COLOR",
	"CLICOLOR",
	"CLICOLOR_FORCE",
	"XDG_CONFIG_HOME",
	"XDG_DATA_HOME",
	"XDG_STATE_HOME",
	"XDG_CACHE_HOME",
	"YOETZ_DIR",
	"YOETZ_HOME",
	"YOETZ_CHATGPT_NATIVE_EXTENSION_DIR",
	"YOETZ_CHROME_NATIVE_MESSAGING_DIR",
	"YOETZ_CHROME_EXTENSION_NATIVE_SOCKET",
]);

export function evaluateProReviewCheck(
	input: {
		readonly requestPath?: string;
		readonly canaryPath?: string;
		readonly requireApproval?: boolean;
		readonly now?: Date;
	} = {},
): ProReviewCheckReport {
	const requestPath = input.requestPath ?? DEFAULT_PRO_REVIEW_REQUEST_PATH;
	const canaryPath = input.canaryPath ?? DEFAULT_PRO_REVIEW_NATIVE_CANARY_PATH;
	const gates: ProReviewGate[] = [];
	const request = readRequest(requestPath, gates);
	const canary = readCanary(canaryPath, gates);

	if (request) {
		gates.push(
			...requestPolicyGates(request, requestPath, canaryPath, {
				now: input.now,
				requireApproval: input.requireApproval,
			}),
		);
	}
	if (request && canary) {
		gates.push(...canaryPolicyGates(canary, request, input));
	}

	const status = gates.some((gate) => gate.status === "fail")
		? "fail"
		: gates.some((gate) => gate.status === "pending")
			? "pending"
			: "pass";

	return {
		schemaVersion: "telclaude.hermes.pro-review-check.v1",
		status,
		requestPath,
		canaryPath,
		gates,
		selectedFiles: request?.selectedFiles ?? [],
		...(request ? { payloadSha256: request.payloadBinding.payloadSha256 } : {}),
		...(request
			? {
					approval: {
						required: request.privateWorkspaceDisclosure.required,
						approved: request.privateWorkspaceDisclosure.approved,
						...(request.privateWorkspaceDisclosure.approvalId
							? { approvalId: request.privateWorkspaceDisclosure.approvalId }
							: {}),
						...(request.privateWorkspaceDisclosure.operator
							? { operator: request.privateWorkspaceDisclosure.operator }
							: {}),
						...(request.privateWorkspaceDisclosure.approvedAt
							? { approvedAt: request.privateWorkspaceDisclosure.approvedAt }
							: {}),
					},
				}
			: {}),
	};
}

export function readProReviewRequest(
	requestPath = DEFAULT_PRO_REVIEW_REQUEST_PATH,
): ProReviewRequest {
	const raw = JSON.parse(
		fs.readFileSync(resolveHermesArtifactPath(requestPath), "utf8"),
	) as unknown;
	return ProReviewRequestSchema.parse(raw);
}

export function parseProReviewNativeCanary(value: unknown): ProReviewNativeCanary {
	return ProReviewNativeCanarySchema.parse(value);
}

export function digestProReviewFile(file: string): string {
	return digestFile(file);
}

export function digestProReviewFileEntry(entry: ProReviewSelectedFileDigestEntry): string {
	if ("missing" in entry) return digestJson({ file: entry.file, missing: true });
	return `sha256:${entry.sha256}`;
}

export function digestProReviewSelectedFileEntries(
	entries: readonly ProReviewSelectedFileDigestEntry[],
): string {
	return digestJson(entries);
}

export function computeProReviewPayloadBinding(
	request: ProReviewRequest,
	snapshot: {
		readonly selectedFileContentsSha256?: string;
		readonly transportEvidenceSha256?: string;
	} = {},
): ProReviewComputedPayloadBinding {
	const selectedFileContentsSha256 =
		snapshot.selectedFileContentsSha256 ?? digestSelectedFileContents(request.selectedFiles);
	const transportEvidenceSha256 =
		snapshot.transportEvidenceSha256 ?? digestFile(request.transportEvidence);
	const reviewMode = request.reviewMode ?? "single";
	const shardPlanSha256 = request.shardPlan ? digestJson(request.shardPlan) : null;
	const payload = {
		reviewer: request.reviewer,
		transport: request.transport,
		model: request.model,
		fallbackAllowed: request.fallbackAllowed,
		transportEvidence: request.transportEvidence,
		blockedFallbacks: request.blockedFallbacks,
		prompt: request.prompt,
		selectedFiles: request.selectedFiles,
		selectedFileContentsSha256,
		transportEvidenceSha256,
		...(reviewMode === "sharded" ? { reviewMode, shardPlanSha256 } : {}),
	};
	return {
		payloadSha256: digestJson(payload),
		promptSha256: digestText(request.prompt),
		selectedFilesSha256: digestJson(request.selectedFiles),
		selectedFileContentsSha256,
		transportEvidenceSha256,
		shardPlanSha256,
	};
}

export function approveProReviewRequest(input: ApproveProReviewRequestInput): ProReviewRequest {
	const request = readProReviewRequest(input.requestPath);
	const approvalId = input.approvalId.trim();
	const operator = input.operator.trim();
	if (!approvalId) throw new Error("Pro review approval requires a non-empty approvalId.");
	if (!operator) throw new Error("Pro review approval requires a non-empty operator.");
	if (request.status !== "pending_operator_disclosure_approval" && request.status !== "approved") {
		throw new Error(`Pro review request status ${request.status} cannot be approved.`);
	}
	const digestFailures = payloadDigestFailures(request);
	if (digestFailures.length > 0) {
		throw new Error(`Cannot approve stale Pro review request: ${digestFailures.join("; ")}`);
	}
	if (
		input.expectedPayloadSha256 !== undefined &&
		input.expectedPayloadSha256 !== request.payloadBinding.payloadSha256
	) {
		throw new Error(
			`Approval payload ${input.expectedPayloadSha256} does not match request payload ${request.payloadBinding.payloadSha256}.`,
		);
	}
	const approvedAt = normalizeApprovalTimestamp(input.approvedAt ?? new Date());
	return ProReviewRequestSchema.parse({
		...request,
		status: "approved",
		privateWorkspaceDisclosure: {
			...request.privateWorkspaceDisclosure,
			approved: true,
			approvalId,
			operator,
			approvedAt,
			payloadSha256: request.payloadBinding.payloadSha256,
		},
	});
}

export function buildProReviewRequestDraft(
	input: BuildProReviewRequestInput = {},
): ProReviewRequest {
	if (input.shardMaxSourceBytes !== undefined) {
		throw new Error(
			"sharded Pro review request generation is disabled; use one complete full-context native bundle",
		);
	}
	const existing = readOptionalProReviewRequest(input.existingRequestPath);
	const prompt = input.prompt ?? existing?.prompt;
	if (!prompt) {
		throw new Error("Pro review request refresh requires an existing request or --prompt.");
	}
	const transportEvidence =
		input.canaryPath ?? existing?.transportEvidence ?? DEFAULT_PRO_REVIEW_NATIVE_CANARY_PATH;
	const selectedFiles = uniqueStrings([
		...requiredProReviewFiles(),
		transportEvidence,
		...(input.includeExistingSelectedFiles === false ? [] : (existing?.selectedFiles ?? [])),
		...(input.selectedFiles ?? []),
	]);
	const blockedFallbacks = uniqueStrings([
		...REQUIRED_PRO_REVIEW_BLOCKED_FALLBACKS,
		...(existing?.blockedFallbacks ?? []),
	]);
	const selectedFileContentsSha256 = digestSelectedFileContents(selectedFiles);
	const transportEvidenceSha256 = digestFile(transportEvidence);
	const payload = {
		reviewer: "ChatGPT Pro Extended via Yoetz native extension",
		transport: "chrome-extension-native",
		model: "Extended Pro",
		fallbackAllowed: false,
		transportEvidence,
		blockedFallbacks,
		prompt,
		selectedFiles,
		selectedFileContentsSha256,
		transportEvidenceSha256,
	};
	return {
		schemaVersion: PRO_REVIEW_REQUEST_SCHEMA_VERSION,
		status: "pending_operator_disclosure_approval",
		reviewer: "ChatGPT Pro Extended via Yoetz native extension",
		transport: "chrome-extension-native",
		model: "Extended Pro",
		fallbackAllowed: false,
		transportEvidence,
		prompt,
		privateWorkspaceDisclosure: {
			required: true,
			approved: false,
			approvalReason:
				existing?.privateWorkspaceDisclosure.approvalReason ??
				"The payload includes private repo code, tests, docs, and local evidence artifacts.",
			approvalBindingRequired: true,
			approvalId: null,
			operator: null,
			approvedAt: null,
			payloadSha256: null,
		},
		payloadBinding: {
			digestAlgorithm: "sha256",
			canonicalJsonFields: [...PRO_REVIEW_PAYLOAD_BINDING_FIELDS],
			payloadSha256: digestJson(payload),
			promptSha256: digestText(prompt),
			selectedFilesSha256: digestJson(selectedFiles),
			selectedFileContentsSha256,
			transportEvidenceSha256,
			notes:
				existing?.payloadBinding.notes ??
				"A future approval is valid only for this exact prompt, selectedFiles list, selected file contents digest, and native-extension evidence digest.",
		},
		selectedFiles,
		blockedFallbacks,
		reviewMode: "single",
	};
}

export function requiredProReviewFiles(): string[] {
	return uniqueStrings([...REQUIRED_PRO_REVIEW_FILES, ...proReviewCutoverProofArtifactPaths()]);
}

function proReviewCutoverProofArtifactPaths(): string[] {
	const resolved = resolveHermesArtifactPath(PRO_REVIEW_CUTOVER_PROOF_BUNDLE_PATH);
	if (!fs.existsSync(resolved)) return [];
	let parsed: unknown;
	try {
		parsed = JSON.parse(fs.readFileSync(resolved, "utf8")) as unknown;
	} catch {
		return [];
	}
	if (!isRecord(parsed) || !isRecord(parsed.artifacts)) return [];
	return Object.values(parsed.artifacts)
		.flatMap((artifact) =>
			isRecord(artifact) && typeof artifact.artifactPath === "string"
				? [artifact.artifactPath]
				: [],
		)
		.filter((artifactPath) => artifactPath.trim().length > 0);
}

function readOptionalProReviewRequest(requestPath: string | undefined): ProReviewRequest | null {
	const resolved = resolveHermesArtifactPath(requestPath ?? DEFAULT_PRO_REVIEW_REQUEST_PATH);
	if (!fs.existsSync(resolved)) return null;
	const raw = JSON.parse(fs.readFileSync(resolved, "utf8")) as unknown;
	return ProReviewRequestSchema.parse(raw);
}

export function buildProReviewShardPlan(
	selectedFiles: readonly string[],
	maxShardSourceBytes: number,
): ProReviewShardPlan {
	if (!Number.isInteger(maxShardSourceBytes) || maxShardSourceBytes <= 0) {
		throw new Error("--shard-max-source-bytes must be a positive integer");
	}
	const items = selectedFiles.flatMap((file) =>
		proReviewShardItemsForFile(file, maxShardSourceBytes),
	);
	const buckets: Array<typeof items> = [];
	let current: typeof items = [];
	let currentBytes = 0;
	for (const item of items) {
		if (current.length > 0 && currentBytes + item.bytes > maxShardSourceBytes) {
			buckets.push(current);
			current = [];
			currentBytes = 0;
		}
		current.push(item);
		currentBytes += item.bytes;
	}
	if (current.length > 0) buckets.push(current);
	const count = buckets.length;
	const shards = buckets.map((bucket, index) => {
		const selected = uniqueStrings(bucket.map((item) => item.path));
		const sourceBytes = bucket.reduce((sum, item) => sum + item.bytes, 0);
		const base = {
			shardId: `shard-${String(index + 1).padStart(3, "0")}`,
			index,
			count,
			selectedFiles: selected,
			selectedFilesSha256: digestJson(selected),
			itemContentsSha256: digestJson(
				bucket.map((item) => ({
					path: item.path,
					startLine: item.startLine,
					endLine: item.endLine,
					sha256: item.sha256,
				})),
			),
			sourceBytes,
			focus: proReviewShardFocus(selected),
			items: bucket,
		};
		return {
			...base,
			shardSha256: digestJson(base),
		};
	});
	return {
		schemaVersion: PRO_REVIEW_SHARD_PLAN_SCHEMA_VERSION,
		strategy: "selected-file-line-byte-budget-v1",
		maxShardSourceBytes,
		bundleTemplateVersion: "pro-review-shard-bundle.v1",
		shards,
	};
}

function proReviewShardItemsForFile(file: string, maxShardSourceBytes: number) {
	const content = fs.readFileSync(resolveHermesArtifactPath(file), "utf8");
	const lines = splitLinesPreservingNewline(content);
	const items: Array<{
		path: string;
		startLine: number;
		endLine: number;
		bytes: number;
		sha256: string;
	}> = [];
	let chunk = "";
	let startLine = 1;
	let lineNumber = 1;
	for (const line of lines) {
		const lineBytes = Buffer.byteLength(line);
		if (lineBytes > maxShardSourceBytes) {
			throw new Error(
				`${file}:${lineNumber} is ${lineBytes} byte(s), exceeding --shard-max-source-bytes ${maxShardSourceBytes}; split the line or choose a larger shard budget`,
			);
		}
		if (chunk && Buffer.byteLength(chunk) + lineBytes > maxShardSourceBytes) {
			items.push(proReviewShardItem(file, startLine, lineNumber - 1, chunk));
			chunk = "";
			startLine = lineNumber;
		}
		chunk += line;
		lineNumber += 1;
	}
	if (chunk || lines.length === 0) {
		items.push(proReviewShardItem(file, startLine, Math.max(startLine, lineNumber - 1), chunk));
	}
	return items;
}

function proReviewShardItem(file: string, startLine: number, endLine: number, content: string) {
	return {
		path: file,
		startLine,
		endLine,
		bytes: Buffer.byteLength(content),
		sha256: digestText(content),
	};
}

function splitLinesPreservingNewline(content: string): string[] {
	return content.match(/[^\n]*\n|[^\n]+/g) ?? [];
}

function proReviewShardFocus(selectedFiles: readonly string[]): string {
	if (selectedFiles.some((file) => file.includes("pro-review"))) return "native Pro review gate";
	if (selectedFiles.some((file) => file.includes("model-relay") || file.includes("openai-codex"))) {
		return "model relay custody";
	}
	if (selectedFiles.some((file) => file.includes("network"))) return "network containment";
	if (selectedFiles.some((file) => file.includes("fixture"))) return "fixture evidence";
	if (selectedFiles.some((file) => file.includes("rollback"))) return "rollback proof";
	if (selectedFiles.some((file) => file.includes("no-fork"))) return "no-fork proof";
	return "Hermes cutover proof evidence";
}

function uniqueStrings(values: readonly string[]): string[] {
	return Array.from(new Set(values));
}

function normalizeApprovalTimestamp(value: Date | string): string {
	const date = value instanceof Date ? value : new Date(value);
	if (Number.isNaN(date.getTime())) {
		throw new Error("Pro review approval timestamp is invalid.");
	}
	return date.toISOString();
}

function readRequest(pathname: string, gates: ProReviewGate[]): ProReviewRequest | null {
	const parsed = readAndParse(pathname, ProReviewRequestSchema);
	if (!parsed.ok) {
		gates.push(fail("request.schema", parsed.error));
		return null;
	}
	gates.push(pass("request.schema", "Pro review request schema is valid"));
	return parsed.value;
}

function readCanary(pathname: string, gates: ProReviewGate[]): ProReviewNativeCanary | null {
	const parsed = readAndParse(pathname, ProReviewNativeCanarySchema);
	if (!parsed.ok) {
		gates.push(fail("nativeCanary.schema", parsed.error));
		return null;
	}
	gates.push(pass("nativeCanary.schema", "Yoetz native canary schema is valid"));
	return parsed.value;
}

function requestPolicyGates(
	request: ProReviewRequest,
	requestPath: string,
	canaryPath: string,
	options: { readonly requireApproval?: boolean; readonly now?: Date },
): ProReviewGate[] {
	const gates: ProReviewGate[] = [];
	const requireGreenEvidence = requiresSendReadyProReviewEvidence(request, options.requireApproval);
	gates.push(
		request.reviewer === "ChatGPT Pro Extended via Yoetz native extension"
			? pass("request.reviewer", "reviewer is ChatGPT Pro Extended via Yoetz native extension")
			: fail("request.reviewer", `reviewer is ${request.reviewer}`),
	);
	gates.push(pass("request.transport", "transport is chrome-extension-native"));
	gates.push(pass("request.model", "model is Extended Pro"));
	gates.push(pass("request.fallback", "fallbackAllowed is false"));

	const blockedFallbacks = new Set(request.blockedFallbacks);
	const missingFallbacks = [
		"cdp",
		"api-key",
		"manual-browser",
		"claude-substitution",
		"amq-substitution",
	].filter((fallback) => !blockedFallbacks.has(fallback));
	gates.push(
		missingFallbacks.length === 0
			? pass("request.blockedFallbacks", "CDP/API/manual/Claude/AMQ fallbacks are blocked")
			: fail(
					"request.blockedFallbacks",
					`missing blocked fallback(s): ${missingFallbacks.join(", ")}`,
				),
	);

	const expectedCanary = normalizeArtifactPath(canaryPath);
	const declaredCanary = normalizeArtifactPath(request.transportEvidence);
	gates.push(
		declaredCanary === expectedCanary
			? pass("request.transportEvidence", "transport evidence path matches canary path")
			: fail(
					"request.transportEvidence",
					`transport evidence path ${request.transportEvidence} does not match ${canaryPath}`,
				),
	);

	const digestFailures = payloadDigestFailures(request);
	gates.push(
		digestFailures.length === 0
			? pass("request.payloadBinding", "payload digest matches review content and native evidence")
			: fail("request.payloadBinding", digestFailures.join("; ")),
	);

	const missingRequiredFiles = requiredProReviewFiles().filter(
		(file) => !request.selectedFiles.includes(file),
	);
	gates.push(
		missingRequiredFiles.length === 0
			? pass("request.requiredFiles", "all required Pro review files are selected")
			: fail(
					"request.requiredFiles",
					`required Pro review file(s) missing from selectedFiles: ${missingRequiredFiles.join(", ")}`,
				),
	);

	const missingFiles = request.selectedFiles.filter(
		(file) => !fs.existsSync(resolveHermesArtifactPath(file)),
	);
	gates.push(
		missingFiles.length === 0
			? pass("request.selectedFiles", "all selected Pro review files exist")
			: fail("request.selectedFiles", `selected file(s) missing: ${missingFiles.join(", ")}`),
	);
	gates.push(...shardPlanGates(request));
	gates.push(...semanticEvidenceGates(request, { requireGreenEvidence, now: options.now }));

	const approval = request.privateWorkspaceDisclosure;
	if (approval.approved) {
		const approvalFailures = [];
		if (request.status === "pending_operator_disclosure_approval") {
			approvalFailures.push("request status is still pending disclosure approval");
		}
		if (!approval.approvalId?.trim()) approvalFailures.push("approvalId is missing");
		if (!approval.operator?.trim()) approvalFailures.push("operator is missing");
		if (!approval.approvedAt?.trim()) approvalFailures.push("approvedAt is missing");
		else if (Number.isNaN(Date.parse(approval.approvedAt)))
			approvalFailures.push("approvedAt is invalid");
		if (approval.payloadSha256 !== request.payloadBinding.payloadSha256) {
			approvalFailures.push("approval payloadSha256 does not match payloadBinding.payloadSha256");
		}
		gates.push(
			approvalFailures.length === 0
				? pass("disclosure.approved", "private workspace disclosure approval is payload-bound")
				: fail("disclosure.approved", approvalFailures.join("; ")),
		);
	} else {
		if (approval.payloadSha256 !== null) {
			gates.push(
				fail(
					"disclosure.payloadBinding",
					"unapproved private workspace disclosure must not carry approval payloadSha256",
				),
			);
		}
		gates.push(
			options.requireApproval
				? fail("disclosure.approved", "private workspace disclosure is not approved")
				: pending("disclosure.approved", "private workspace disclosure is pending exact approval"),
		);
		if (request.status !== "pending_operator_disclosure_approval") {
			gates.push(
				fail(
					"request.status",
					`request status is ${request.status} while disclosure is unapproved`,
				),
			);
		} else {
			gates.push(pass("request.status", "request is pending operator disclosure approval"));
		}
	}

	gates.push(
		requestPath.trim()
			? pass("request.path", "request path is explicit")
			: fail("request.path", "request path is empty"),
	);
	return gates;
}

function shardPlanGates(request: ProReviewRequest): ProReviewGate[] {
	const reviewMode = request.reviewMode ?? "single";
	if (reviewMode !== "single") {
		return [
			fail(
				"request.shardPlan",
				`Pro review request mode ${reviewMode} is disabled; use one complete full-context native bundle`,
			),
		];
	}
	return request.shardPlan
		? [fail("request.shardPlan", "single Pro review request must not include shardPlan")]
		: [pass("request.shardPlan", "single Pro review request has no shard plan")];
}

function requiresSendReadyProReviewEvidence(
	request: ProReviewRequest,
	requireApproval: boolean | undefined,
): boolean {
	return (
		requireApproval === true ||
		request.privateWorkspaceDisclosure.approved === true ||
		request.status !== "pending_operator_disclosure_approval"
	);
}

function canaryPolicyGates(
	canary: ProReviewNativeCanary,
	request: ProReviewRequest,
	options: { readonly requireApproval?: boolean; readonly now?: Date },
): ProReviewGate[] {
	const gates: ProReviewGate[] = [];
	gates.push(pass("nativeCanary.transport", "live canary transport is chrome-extension-native"));
	gates.push(pass("nativeCanary.model", "live canary selected Extended Pro"));
	gates.push(pass("nativeCanary.response", "live canary returned OK"));
	gates.push(
		canary.nativeStatus.extensionInstanceId === canary.extensionInstanceId
			? pass(
					"nativeCanary.extensionBinding",
					"native status and live canary share extension instance",
				)
			: fail(
					"nativeCanary.extensionBinding",
					"native status extension instance differs from canary",
				),
	);
	gates.push(
		canary.nativeStatus.extensionVersion === canary.extensionVersion
			? pass(
					"nativeCanary.extensionVersion",
					"native status and live canary share extension version",
				)
			: fail(
					"nativeCanary.extensionVersion",
					"native status extension version differs from canary",
				),
	);
	const yoetzVersionFailures = yoetzNativeContractVersionFailures(canary);
	gates.push(
		yoetzVersionFailures.length === 0
			? pass(
					"nativeCanary.yoetzVersion",
					`Yoetz native extension is at or above ${PRO_REVIEW_MIN_YOETZ_NATIVE_VERSION}`,
				)
			: fail("nativeCanary.yoetzVersion", yoetzVersionFailures.join("; ")),
	);
	gates.push(
		canary.warnings.length === 0
			? pass("nativeCanary.warnings", "native canary emitted no warnings")
			: fail("nativeCanary.warnings", `native canary emitted ${canary.warnings.length} warning(s)`),
	);
	const requiredCheckFailures = requiredCanaryCheckFailures(canary);
	gates.push(
		requiredCheckFailures.length === 0
			? pass(
					"nativeCanary.requiredChecks",
					"native status, live canary, model, and no-fallback checks passed",
				)
			: fail("nativeCanary.requiredChecks", requiredCheckFailures.join("; ")),
	);
	const observedAtMs = Date.parse(canary.observedAt);
	const reverifiedAtMs = Date.parse(canary.reverifiedAt);
	gates.push(
		!Number.isNaN(observedAtMs) && !Number.isNaN(reverifiedAtMs) && observedAtMs <= reverifiedAtMs
			? pass("nativeCanary.timestamps", "native canary timestamps are parseable and ordered")
			: fail("nativeCanary.timestamps", "native canary timestamps are invalid or out of order"),
	);
	if (
		options.requireApproval === true ||
		request.privateWorkspaceDisclosure.approved === true ||
		request.status !== "pending_operator_disclosure_approval"
	) {
		gates.push(nativeCanaryFreshnessGate(reverifiedAtMs, options.now ?? new Date()));
	}
	gates.push(
		request.fallbackAllowed === false
			? pass("nativeCanary.noFallback", "canary evidence is compatible with no-fallback request")
			: fail("nativeCanary.noFallback", "request allows fallback"),
	);
	return gates;
}

function yoetzNativeContractVersionFailures(canary: ProReviewNativeCanary): string[] {
	const fields = [
		["extensionVersion", canary.extensionVersion],
		["nativeStatus.extensionVersion", canary.nativeStatus.extensionVersion],
	] as const;
	return fields.flatMap(([field, version]) =>
		yoetzVersionAtLeast(version, PRO_REVIEW_MIN_YOETZ_NATIVE_VERSION)
			? []
			: [
					`${field} ${version} is below required Yoetz ${PRO_REVIEW_MIN_YOETZ_NATIVE_VERSION} interim-turn/final-response contract`,
				],
	);
}

function yoetzVersionAtLeast(actual: string, minimum: string): boolean {
	const actualParts = parseYoetzVersion(actual);
	const minimumParts = parseYoetzVersion(minimum);
	if (!actualParts || !minimumParts) return false;
	for (let index = 0; index < minimumParts.length; index += 1) {
		const actualPart = actualParts[index] ?? 0;
		const minimumPart = minimumParts[index] ?? 0;
		if (actualPart > minimumPart) return true;
		if (actualPart < minimumPart) return false;
	}
	return true;
}

function parseYoetzVersion(value: string): readonly number[] | null {
	const normalized = value.trim().replace(/^v/i, "");
	if (!/^\d+(?:\.\d+){1,3}$/.test(normalized)) return null;
	return normalized.split(".").map((part) => Number(part));
}

function nativeCanaryFreshnessGate(reverifiedAtMs: number, now: Date): ProReviewGate {
	if (Number.isNaN(reverifiedAtMs)) {
		return fail("nativeCanary.freshness", "native canary reverifiedAt timestamp is invalid");
	}
	const nowMs = now.getTime();
	if (!Number.isFinite(nowMs)) {
		return fail("nativeCanary.freshness", "current time is invalid");
	}
	const ageMs = nowMs - reverifiedAtMs;
	if (ageMs < 0) {
		return fail("nativeCanary.freshness", "native canary reverifiedAt is in the future");
	}
	if (ageMs > PRO_REVIEW_NATIVE_CANARY_MAX_AGE_MS) {
		const ageMinutes = Math.floor(ageMs / 60_000);
		return fail(
			"nativeCanary.freshness",
			`native canary reverification is stale at ${ageMinutes} minute(s) old`,
		);
	}
	return pass("nativeCanary.freshness", "native canary reverification is fresh");
}

function payloadDigestFailures(request: ProReviewRequest): string[] {
	const failures = [];
	const reviewMode = request.reviewMode ?? "single";
	const expected = computeProReviewPayloadBinding(request);
	const expectedCanonicalFields =
		reviewMode === "sharded"
			? [...PRO_REVIEW_SHARDED_PAYLOAD_BINDING_FIELDS]
			: [...PRO_REVIEW_PAYLOAD_BINDING_FIELDS];
	if (
		JSON.stringify(request.payloadBinding.canonicalJsonFields) !==
		JSON.stringify(expectedCanonicalFields)
	) {
		failures.push("canonicalJsonFields do not match review mode");
	}
	if (request.payloadBinding.payloadSha256 !== expected.payloadSha256) {
		failures.push(
			"payloadSha256 does not match review content, selected files, and native evidence",
		);
	}
	if (request.payloadBinding.promptSha256 !== expected.promptSha256) {
		failures.push("promptSha256 does not match prompt");
	}
	if (request.payloadBinding.selectedFilesSha256 !== expected.selectedFilesSha256) {
		failures.push("selectedFilesSha256 does not match selectedFiles");
	}
	if (request.payloadBinding.selectedFileContentsSha256 !== expected.selectedFileContentsSha256) {
		failures.push("selectedFileContentsSha256 does not match selected file contents");
	}
	if (request.payloadBinding.transportEvidenceSha256 !== expected.transportEvidenceSha256) {
		failures.push("transportEvidenceSha256 does not match transport evidence file");
	}
	if (reviewMode === "sharded") {
		if (!request.shardPlan) {
			failures.push("sharded review request is missing shardPlan");
		}
		if (request.payloadBinding.shardPlanSha256 !== expected.shardPlanSha256) {
			failures.push("shardPlanSha256 does not match shardPlan");
		}
	} else if (request.shardPlan) {
		failures.push("single review request must not include shardPlan");
	}
	return failures;
}

function digestSelectedFileContents(selectedFiles: readonly string[]): string {
	return digestJson(
		selectedFiles.map((file) => {
			const resolved = resolveHermesArtifactPath(file);
			if (!fs.existsSync(resolved)) return { file, missing: true };
			return {
				file,
				sha256: crypto.createHash("sha256").update(fs.readFileSync(resolved)).digest("hex"),
			};
		}),
	);
}

function digestFile(file: string): string {
	const resolved = resolveHermesArtifactPath(file);
	if (!fs.existsSync(resolved)) return digestJson({ file, missing: true });
	return `sha256:${crypto.createHash("sha256").update(fs.readFileSync(resolved)).digest("hex")}`;
}

function semanticEvidenceGates(
	request: ProReviewRequest,
	options: { readonly requireGreenEvidence: boolean; readonly now?: Date },
): ProReviewGate[] {
	const gates: ProReviewGate[] = [];
	const validationOptions = archivedHermesEvidenceValidationOptions();
	gates.push(semanticEvidenceCoverageGate(request.selectedFiles));
	if (request.selectedFiles.includes(PRO_REVIEW_CLI_HEADLESS_PROBE_PATH)) {
		gates.push(
			cliHeadlessEvidenceGate(
				PRO_REVIEW_CLI_HEADLESS_PROBE_PATH,
				options.requireGreenEvidence,
				validationOptions,
			),
		);
	}
	if (request.selectedFiles.includes(PRO_REVIEW_HEADLESS_ENTRYPOINT_PROBE_PATH)) {
		gates.push(
			headlessEntrypointEvidenceGate(
				PRO_REVIEW_HEADLESS_ENTRYPOINT_PROBE_PATH,
				options.requireGreenEvidence,
				validationOptions,
			),
		);
	}
	if (request.selectedFiles.includes(PRO_REVIEW_MODEL_RELAY_PROBE_PATH)) {
		gates.push(
			jsonSemanticEvidenceGate(
				PRO_REVIEW_MODEL_RELAY_PROBE_PATH,
				"model.relay",
				options.requireGreenEvidence,
				(evidence) => modelRelayProbeEvidenceFailure(evidence, validationOptions),
			),
		);
	}
	for (const [reportPath, surfaceId] of Object.entries(PRO_REVIEW_SIGNED_PROBE_PATHS)) {
		if (request.selectedFiles.includes(reportPath)) {
			gates.push(
				signedProbeEvidenceGate(
					reportPath,
					surfaceId,
					options.requireGreenEvidence,
					validationOptions,
				),
			);
		}
	}
	for (const [reportPath, surfaceId] of Object.entries(PRO_REVIEW_BROWSER_COMPUTER_PROBE_PATHS)) {
		if (request.selectedFiles.includes(reportPath)) {
			gates.push(
				jsonSemanticEvidenceGate(reportPath, surfaceId, options.requireGreenEvidence, (evidence) =>
					browserComputerBrokerProbeEvidenceFailure(surfaceId, evidence, validationOptions),
				),
			);
		}
	}
	for (const [reportPath, surfaceId] of Object.entries(PRO_REVIEW_PROVIDER_DOMAIN_PROBE_PATHS)) {
		if (request.selectedFiles.includes(reportPath)) {
			gates.push(
				jsonSemanticEvidenceGate(reportPath, surfaceId, options.requireGreenEvidence, (evidence) =>
					providerDomainProbeEvidenceFailure(surfaceId, evidence),
				),
			);
		}
	}
	if (request.selectedFiles.includes(PRO_REVIEW_GOOGLE_PROVIDER_PROBE_PATH)) {
		gates.push(
			jsonSemanticEvidenceGate(
				PRO_REVIEW_GOOGLE_PROVIDER_PROBE_PATH,
				"providers.google",
				options.requireGreenEvidence,
				googleProviderProbeEvidenceFailure,
			),
		);
	}
	if (request.selectedFiles.includes(PRO_REVIEW_PROVIDER_RELEASE_POLICY_PROBE_PATH)) {
		gates.push(
			jsonSemanticEvidenceGate(
				PRO_REVIEW_PROVIDER_RELEASE_POLICY_PROBE_PATH,
				"providers.release-policy",
				options.requireGreenEvidence,
				providerReleasePolicyProbeEvidenceFailure,
			),
		);
	}
	if (request.selectedFiles.includes(PRO_REVIEW_SERVED_MCP_PROVIDER_TOOLS_PROBE_PATH)) {
		gates.push(
			jsonSemanticEvidenceGate(
				PRO_REVIEW_SERVED_MCP_PROVIDER_TOOLS_PROBE_PATH,
				"served_mcp.provider-tools",
				options.requireGreenEvidence,
				servedMcpProviderToolsProbeEvidenceFailure,
			),
		);
	}
	for (const [reportPath, probeId] of Object.entries(PRO_REVIEW_NETWORK_PROBE_PATHS)) {
		if (request.selectedFiles.includes(reportPath)) {
			gates.push(
				jsonSemanticEvidenceGate(reportPath, probeId, options.requireGreenEvidence, (evidence) =>
					networkProbeEvidenceFailure(evidence, {
						expectedId: probeId,
						requiredPosture: REQUIRED_CUTOVER_NETWORK_PROBE_POSTURE,
						...validationOptions,
					}),
				),
			);
		}
	}
	for (const reportPath of request.selectedFiles.filter(isProReviewFixtureArtifactPath)) {
		const fixtureId = path.basename(reportPath, ".json");
		gates.push(
			jsonSemanticEvidenceGate(reportPath, fixtureId, options.requireGreenEvidence, () =>
				hermesFixtureEvidenceFileFailure(reportPath, validationOptions),
			),
		);
	}
	if (request.selectedFiles.includes(PRO_REVIEW_CURRENT_CUTOVER_CHECK_PATH)) {
		gates.push(
			currentCutoverCheckContextGate(PRO_REVIEW_CURRENT_CUTOVER_CHECK_PATH, {
				now: options.now ?? new Date(),
			}),
		);
	}
	return gates;
}

function semanticEvidenceCoverageGate(selectedFiles: readonly string[]): ProReviewGate {
	const uncovered = selectedFiles.filter(isUncoveredProReviewSemanticArtifactPath);
	return uncovered.length === 0
		? pass(
				"request.semanticEvidence.coverage",
				"all selected Hermes semantic evidence artifacts have validators",
			)
		: fail(
				"request.semanticEvidence.coverage",
				`selected Hermes semantic evidence artifact(s) lack validators: ${uncovered.join(", ")}`,
			);
}

function isUncoveredProReviewSemanticArtifactPath(file: string): boolean {
	if (file === DEFAULT_PRO_REVIEW_NATIVE_CANARY_PATH) return false;
	if (file === PRO_REVIEW_CURRENT_CUTOVER_CHECK_PATH) return false;
	if (file === PRO_REVIEW_HEADLESS_ENTRYPOINT_TEST_REPORT_PATH) return false;
	if (PRO_REVIEW_SEMANTIC_DEPENDENCY_ARTIFACT_PATHS.has(file)) return false;
	if (isRunLocalCutoverProofBundlePath(file)) return false;
	if (isRunLocalNetworkSignedArtifactPath(file)) return false;
	if (proReviewCutoverProofArtifactPaths().includes(file)) return false;
	if (isProReviewFixtureArtifactPath(file)) return false;
	if (file.startsWith("artifacts/hermes/network/") && file.endsWith(".json")) {
		return !Object.hasOwn(PRO_REVIEW_NETWORK_PROBE_PATHS, file);
	}
	if (file.startsWith("artifacts/hermes/probes/") && file.endsWith(".json")) {
		return !PRO_REVIEW_KNOWN_PROBE_ARTIFACT_PATHS.has(file);
	}
	if (file.startsWith("artifacts/hermes/") && file.endsWith(".json")) {
		return true;
	}
	return false;
}

function isRunLocalCutoverProofBundlePath(file: string): boolean {
	return /^artifacts\/hermes\/no-fork-run-[^/]+\/cutover-proof-bundle(?:\.[^/]+)?\.json$/.test(
		file,
	);
}

function isRunLocalNetworkSignedArtifactPath(file: string): boolean {
	return /^artifacts\/hermes\/no-fork-run-[^/]+\/network-signed\/[^/]+\.json$/.test(file);
}

function isProReviewFixtureArtifactPath(file: string): boolean {
	return file.startsWith("artifacts/hermes/fixtures/") && file.endsWith(".json");
}

function currentCutoverCheckContextGate(
	reportPath: string,
	options: { readonly now: Date },
): ProReviewGate {
	const read = readJsonObject(reportPath);
	const name = "request.semanticEvidence.currentCutoverCheck";
	if (!read.ok) return fail(name, `current cutover-check report cannot be read: ${read.error}`);
	const failure = currentCutoverCheckContextFailure(read.value, options.now);
	return failure
		? fail(name, `current cutover-check report is not accepted: ${failure}`)
		: pass(name, "current cutover-check report is fresh schema-valid diagnostic context");
}

function currentCutoverCheckContextFailure(
	value: Record<string, unknown>,
	now: Date,
): string | null {
	if (
		value.status !== "safe" &&
		value.status !== "input_error" &&
		value.status !== "pass" &&
		value.status !== "fail"
	) {
		return "status must be safe, input_error, pass, or fail";
	}
	if (value.status === "safe" || value.status === "pass") {
		if (value.exitCode !== 0) return `${value.status} report exitCode must be 0`;
	}
	if ((value.status === "fail" || value.status === "input_error") && value.exitCode === 0) {
		return `${value.status} report exitCode must be non-zero`;
	}
	if (!isRecord(value.mode)) return "mode object is missing";
	if (value.mode.strict !== true) return "mode.strict must be true";
	if (typeof value.mode.dryRun !== "boolean") return "mode.dryRun must be boolean";
	if (value.mode.completeParityCutover !== true) {
		return "mode.completeParityCutover must be true";
	}
	if (value.status === "pass" && value.mode.dryRun !== true) {
		return "mode.dryRun must be true for diagnostic pass reports";
	}
	if (!Array.isArray(value.gates) || value.gates.length === 0) {
		return "gates must be a non-empty array";
	}
	for (const [index, gate] of value.gates.entries()) {
		if (!isRecord(gate)) return `gate ${index} must be an object`;
		if (typeof gate.name !== "string" || gate.name.length === 0) {
			return `gate ${index} is missing name`;
		}
		if (gate.status !== "pass" && gate.status !== "fail" && gate.status !== "pending") {
			return `gate ${index} has invalid status`;
		}
		if (typeof gate.detail !== "string" || gate.detail.length === 0) {
			return `gate ${index} is missing detail`;
		}
	}
	const parityGate = value.gates.find(
		(gate) => isRecord(gate) && gate.name === "parity.rosterCovered",
	);
	if (!parityGate) return "parity.rosterCovered gate is missing";
	if ((value.status === "safe" || value.status === "pass") && parityGate.status !== "pass") {
		return "parity.rosterCovered gate must pass for accepted safe/pass reports";
	}
	if (value.status === "safe") {
		const nonPassGate = value.gates.find((gate) => isRecord(gate) && gate.status !== "pass");
		if (nonPassGate) return "safe report contains a non-pass gate";
	}
	const generatedAtFailure = currentCutoverCheckGeneratedAtFailure(value.generatedAt, now);
	if (generatedAtFailure) return generatedAtFailure;
	return null;
}

function currentCutoverCheckGeneratedAtFailure(value: unknown, now: Date): string | null {
	if (typeof value !== "string" || value.trim().length === 0) return "generatedAt is missing";
	const generatedAtMs = Date.parse(value);
	if (Number.isNaN(generatedAtMs)) return "generatedAt is invalid";
	const nowMs = now.getTime();
	if (!Number.isFinite(nowMs)) return "current time is invalid";
	const ageMs = nowMs - generatedAtMs;
	if (ageMs < 0) return "generatedAt is in the future";
	if (ageMs > PRO_REVIEW_CURRENT_CUTOVER_CHECK_MAX_AGE_MS) {
		const ageMinutes = Math.floor(ageMs / 60_000);
		return `generatedAt is stale at ${ageMinutes} minute(s) old`;
	}
	return null;
}

function jsonSemanticEvidenceGate(
	reportPath: string,
	surfaceId: string,
	requireGreenEvidence: boolean,
	validator: (evidence: unknown) => string | null,
): ProReviewGate {
	const name = `request.semanticEvidence.${surfaceId}`;
	const read = readJsonObject(reportPath);
	if (!read.ok) return fail(name, `${surfaceId} evidence cannot be read: ${read.error}`);
	if (read.value.status !== "pass") {
		if (read.value.status !== "fail") {
			return fail(name, `${surfaceId} evidence status is ${String(read.value.status)}`);
		}
		if (requireGreenEvidence) {
			return fail(name, `${surfaceId} evidence is explicitly red and cannot be sent`);
		}
		return pass(name, `${surfaceId} evidence is explicitly red`);
	}
	const failure = validator(read.value);
	return failure
		? fail(name, `${surfaceId} pass evidence is not accepted by the current validator: ${failure}`)
		: pass(name, `${surfaceId} pass evidence passes current semantic validator`);
}

function cliHeadlessEvidenceGate(
	reportPath: string,
	requireGreenEvidence: boolean,
	validationOptions: HermesSignedEvidenceValidationOptions,
): ProReviewGate {
	const resolved = resolveHermesArtifactPath(reportPath);
	let raw: unknown;
	try {
		raw = JSON.parse(fs.readFileSync(resolved, "utf8")) as unknown;
	} catch (error) {
		return fail(
			"request.cliHeadlessEvidence",
			`cli_headless evidence cannot be read: ${
				error instanceof Error ? error.message : String(error)
			}`,
		);
	}
	if (!isRecord(raw)) {
		return fail("request.cliHeadlessEvidence", "cli_headless evidence must be a JSON object");
	}
	if (raw.status === "pass") {
		try {
			readHermesCliHeadlessProbeReport(resolved, validationOptions);
			return pass(
				"request.cliHeadlessEvidence",
				"cli_headless pass evidence passes current semantic validator",
			);
		} catch (error) {
			return fail(
				"request.cliHeadlessEvidence",
				`cli_headless pass evidence is not accepted by the current validator: ${
					error instanceof Error ? error.message : String(error)
				}`,
			);
		}
	}
	const explicitRedFailure = explicitCliHeadlessRedFailure(raw);
	if (explicitRedFailure) {
		return fail("request.cliHeadlessEvidence", explicitRedFailure);
	}
	if (requireGreenEvidence) {
		return fail(
			"request.cliHeadlessEvidence",
			`cli_headless evidence is explicitly red and cannot be sent: ${String(
				raw.summary ?? "readiness failed",
			)}`,
		);
	}
	return pass(
		"request.cliHeadlessEvidence",
		`cli_headless evidence is explicitly red: ${String(raw.summary ?? "readiness failed")}`,
	);
}

function headlessEntrypointEvidenceGate(
	reportPath: string,
	requireGreenEvidence: boolean,
	validationOptions: HermesSignedEvidenceValidationOptions,
): ProReviewGate {
	const surfaceId = HERMES_HEADLESS_ENTRYPOINT_SURFACE_ID;
	const name = `request.semanticEvidence.${surfaceId}`;
	const probe: FeatureProbeMatrix["probes"][number] = {
		surface_id: surfaceId,
		hermes_pin: { version: "0.15.1" },
		documented_seam:
			"Telclaude Hermes private API runtime adapter and session map semantic headless entrypoint",
		probe_command: `pnpm dev hermes probe ${surfaceId} --allow-run --out ${reportPath}`,
		expected_result:
			"Focused adapter/runtime tests prove streaming, terminal, session, tool, approval, cancellation, deterministic error, and redaction semantics",
		negative_probe:
			"CLI availability proof alone, missing terminal events, missing stop-on-abort, stale sessions, and unredacted output fail closed",
		evidence_path: reportPath,
		lockfile_key: "featureProbes.execution.headlessEntrypoint",
		security_scope: "headless-entrypoint-semantics",
		approval_equivalent: false,
		failure_outcome: "disable",
		status: "pass",
	};
	const evidenceBundle = collectFeatureProbeEvidence(
		{ schemaVersion: 1, probes: [probe] },
		validationOptions,
	);
	if (!evidenceBundle) return fail(name, `${surfaceId} evidence bundle was not evaluated`);
	const result = evidenceBundle.results[0];
	if (!result) return fail(name, `${surfaceId} evidence was not evaluated`);
	if (result.status === "pass") {
		return pass(name, `${surfaceId} pass evidence passes current semantic validator`);
	}
	if (requireGreenEvidence) {
		return fail(
			name,
			`${surfaceId} evidence is explicitly red and cannot be sent: ${result.detail}`,
		);
	}
	return pass(name, `${surfaceId} evidence is explicitly red: ${result.detail}`);
}

function signedProbeEvidenceGate(
	reportPath: string,
	surfaceId: string,
	requireGreenEvidence: boolean,
	validationOptions: HermesSignedEvidenceValidationOptions,
): ProReviewGate {
	const name = `request.semanticEvidence.${surfaceId}`;
	const read = readJsonObject(reportPath);
	if (!read.ok) return fail(name, `${surfaceId} evidence cannot be read: ${read.error}`);
	if (read.value.status !== "pass") {
		if (read.value.status !== "fail") {
			return fail(name, `${surfaceId} evidence status is ${String(read.value.status)}`);
		}
		if (!isExplicitSignedProbeRedReadinessEvidence(read.value, reportPath)) {
			const failure = signedProbeSemanticFailure(surfaceId, read.value, validationOptions);
			return fail(
				name,
				`${surfaceId} non-pass evidence is not accepted by the current validator: ${failure}`,
			);
		}
		if (requireGreenEvidence) {
			return fail(name, `${surfaceId} evidence is explicitly red and cannot be sent`);
		}
		return pass(name, `${surfaceId} evidence is explicitly red`);
	}
	const failure = signedProbeSemanticFailure(surfaceId, read.value, validationOptions);
	return failure
		? fail(name, `${surfaceId} pass evidence is not accepted by the current validator: ${failure}`)
		: pass(name, `${surfaceId} pass evidence passes current semantic validator`);
}

function isExplicitSignedProbeRedReadinessEvidence(
	evidence: Record<string, unknown>,
	reportPath: string,
): boolean {
	return (
		evidence.schemaVersion === "telclaude.hermes.pro-review-red-probe-fixture.v1" &&
		evidence.status === "fail" &&
		evidence.ran === false &&
		evidence.probeId === path.basename(reportPath, ".json")
	);
}

function signedProbeSemanticFailure(
	surfaceId: string,
	evidence: unknown,
	validationOptions: HermesSignedEvidenceValidationOptions,
): string | null {
	return surfaceId === "sideeffect.ledger"
		? sideEffectLedgerProbeEvidenceFailure(surfaceId, evidence, validationOptions)
		: surfaceId === "providers.approval-binding"
			? providerApprovalBindingProbeEvidenceFailure(evidence, validationOptions)
			: surfaceId === "workflow.cron" || surfaceId === "workflow.longrun"
				? workflowProbeEvidenceFailure(surfaceId, evidence, validationOptions)
				: edgeAdapterProbeEvidenceFailure(surfaceId, evidence, validationOptions);
}

function explicitCliHeadlessRedFailure(raw: Record<string, unknown>): string | null {
	if (raw.schemaVersion !== "telclaude.hermes.probe-result.v1") {
		return "cli_headless evidence has an unsupported schemaVersion";
	}
	if (raw.probeId !== "execution.cli_headless") {
		return `cli_headless evidence probeId is ${String(raw.probeId)}`;
	}
	if (raw.status !== "fail") {
		return `cli_headless evidence status is ${String(raw.status)}`;
	}
	if (raw.ran !== false) {
		return "red cli_headless evidence must be a pre-run readiness failure";
	}
	if ("exitCode" in raw || "provenance" in raw) {
		return "pre-run cli_headless readiness failure must not carry run provenance";
	}
	if (!isRecord(raw.readiness)) {
		return "red cli_headless evidence readiness is missing";
	}
	if (raw.readiness.status !== "fail") {
		return "red cli_headless evidence readiness status is not fail";
	}
	if (!Array.isArray(raw.readiness.gates)) {
		return "red cli_headless evidence readiness gates are missing";
	}
	if (!raw.readiness.gates.some((gate) => isRecord(gate) && gate.status === "fail")) {
		return "red cli_headless evidence has no failed readiness gate";
	}
	return null;
}

function requiredCanaryCheckFailures(canary: ProReviewNativeCanary): string[] {
	const checks = new Map(canary.checks.map((check) => [check.name, check]));
	const failures = [
		"native.status",
		"native.liveCanary",
		"model.extendedPro",
		"fallback.disabled",
	].flatMap((name) => {
		const check = checks.get(name);
		return check?.status === "pass" ? [] : [`${name} check is missing or not pass`];
	});
	failures.push(
		...nativeStatusCommandFailures(canary.nativeStatus.command, canary.extensionInstanceId),
	);
	failures.push(...dryCanaryCommandFailures(canary.dryCanary.command, canary.extensionInstanceId));
	failures.push(
		...liveCanaryCommandFailures(canary.liveCanary.command, canary.extensionInstanceId),
	);
	for (const [label, command] of [
		["native status", canary.nativeStatus.command],
		["dry canary", canary.dryCanary.command],
		["live canary", canary.liveCanary.command],
	] as const) {
		if (containsBlockedFallback(command)) {
			failures.push(`${label} command contains a blocked fallback`);
		}
	}
	return failures;
}

function nativeStatusCommandFailures(
	command: string,
	expectedExtensionInstanceId: string,
): string[] {
	const allowed =
		command.startsWith("YOETZ_AGENT=1 yoetz browser extension status --chatgpt") ||
		command.startsWith("YOETZ_AGENT=1 yoetz browser extension reconnect --chatgpt");
	if (!allowed) {
		return ["native status command is not the Yoetz extension status/reconnect command"];
	}
	return nativeExtensionCommandShapeFailures(
		command,
		"native status",
		expectedExtensionInstanceId,
		{
			allowedVerbs: ["status", "reconnect"],
			extensionBinding: nativeExtensionCommandVerb(command) === "status" ? "optional" : "required",
			live: "forbidden",
		},
	);
}

function dryCanaryCommandFailures(command: string, expectedExtensionInstanceId: string): string[] {
	if (!command.startsWith("YOETZ_AGENT=1 yoetz browser extension canary --chatgpt")) {
		return ["dry canary command is not the Yoetz extension dry canary command"];
	}
	return nativeExtensionCommandShapeFailures(command, "dry canary", expectedExtensionInstanceId, {
		allowedVerbs: ["canary"],
		extensionBinding: "required",
		live: "forbidden",
	});
}

function liveCanaryCommandFailures(command: string, expectedExtensionInstanceId: string): string[] {
	if (!command.startsWith("YOETZ_AGENT=1 yoetz browser extension canary --chatgpt")) {
		return ["live canary command is not the Yoetz extension live canary command"];
	}
	return nativeExtensionCommandShapeFailures(command, "live canary", expectedExtensionInstanceId, {
		allowedVerbs: ["canary"],
		extensionBinding: "required",
		live: "required",
	});
}

function nativeExtensionCommandShapeFailures(
	command: string,
	label: string,
	expectedExtensionInstanceId: string,
	options: {
		readonly allowedVerbs: readonly string[];
		readonly extensionBinding: "required" | "optional";
		readonly live: "required" | "forbidden";
	},
): string[] {
	const failures = [];
	const tokens = command.trim().split(/\s+/).filter(Boolean);
	const expectedPrefix = ["YOETZ_AGENT=1", "yoetz", "browser", "extension"];
	for (const [index, expected] of expectedPrefix.entries()) {
		if (tokens[index] !== expected) {
			failures.push(`${label} command does not use the Yoetz native extension command`);
			return failures;
		}
	}
	const verb = tokens[4];
	if (!verb || !options.allowedVerbs.includes(verb)) {
		failures.push(`${label} command uses unexpected Yoetz extension verb ${String(verb)}`);
		return failures;
	}
	const parsed = parseNativeExtensionFlags(tokens.slice(5));
	failures.push(...parsed.failures.map((failure) => `${label} command ${failure}`));

	if (parsed.flagCounts.chatgpt !== 1) {
		failures.push(`${label} command must include exactly one --chatgpt`);
	}
	if (parsed.flagCounts.extensionInstanceId > 1) {
		failures.push(`${label} command includes multiple --extension-instance-id flags`);
	}
	if (parsed.flagCounts.format > 1) {
		failures.push(`${label} command includes multiple --format flags`);
	}
	const boundExtensionInstance = parsed.extensionInstanceId;
	if (!boundExtensionInstance && options.extensionBinding === "required") {
		failures.push(`${label} command does not bind an extension instance`);
	} else if (boundExtensionInstance && boundExtensionInstance !== expectedExtensionInstanceId) {
		failures.push(
			`${label} command binds extension instance ${boundExtensionInstance}, expected ${expectedExtensionInstanceId}`,
		);
	}
	if (!parsed.format) {
		failures.push(`${label} command does not request JSON output`);
	} else if (parsed.format !== "json") {
		failures.push(`${label} command requests ${parsed.format} output instead of json`);
	}
	if (options.live === "required" && parsed.flagCounts.live !== 1) {
		failures.push(`${label} command does not include --live`);
	}
	if (options.live === "forbidden" && parsed.flagCounts.live > 0) {
		failures.push(`${label} command includes --live`);
	}
	if (parsed.flagCounts.live > 1) {
		failures.push(`${label} command includes multiple --live flags`);
	}
	return failures;
}

function nativeExtensionCommandVerb(command: string): string | null {
	return command.trim().split(/\s+/).filter(Boolean)[4] ?? null;
}

function parseNativeExtensionFlags(tokens: readonly string[]): {
	readonly extensionInstanceId: string | null;
	readonly format: string | null;
	readonly flagCounts: {
		readonly chatgpt: number;
		readonly live: number;
		readonly extensionInstanceId: number;
		readonly format: number;
	};
	readonly failures: readonly string[];
} {
	let chatgpt = 0;
	let live = 0;
	let extensionInstanceIdCount = 0;
	let formatCount = 0;
	let extensionInstanceId: string | null = null;
	let format: string | null = null;
	const failures: string[] = [];
	for (let index = 0; index < tokens.length; index += 1) {
		const token = tokens[index];
		if (token === "--chatgpt") {
			chatgpt += 1;
			continue;
		}
		if (token === "--live") {
			live += 1;
			continue;
		}
		if (token === "--extension-instance-id") {
			extensionInstanceIdCount += 1;
			const value = tokens[index + 1];
			if (!value || value.startsWith("--")) {
				failures.push("--extension-instance-id is missing a value");
			} else {
				extensionInstanceId = value;
				index += 1;
			}
			continue;
		}
		if (token === "--format") {
			formatCount += 1;
			const value = tokens[index + 1];
			if (!value || value.startsWith("--")) {
				failures.push("--format is missing a value");
			} else {
				format = value;
				index += 1;
			}
			continue;
		}
		failures.push(`includes unexpected token ${token}`);
	}
	return {
		extensionInstanceId,
		format,
		flagCounts: {
			chatgpt,
			live,
			extensionInstanceId: extensionInstanceIdCount,
			format: formatCount,
		},
		failures,
	};
}

function containsBlockedFallback(command: string): boolean {
	return [
		/(?:^|\s)--cdp(?:\s|=|$)/i,
		/(?:^|\s)--api-key(?:\s|=|$)/i,
		/(?:^|\s)--transport\s+(?!chrome-extension-native(?:\s|$))/i,
		/(?:^|\s)--allow-[\w-]*fallback(?:\s|=|$)/i,
		/(?:^|\s)--fallback(?:\s|=|$)/i,
		/\bbrowser\s+recipe\b/i,
		/\bdev-browser\b/i,
		/\bagent-browser\b/i,
		/\bmanual\b/i,
		/\bclaude\b/i,
		/\bamq\b/i,
	].some((pattern) => pattern.test(command));
}

export function readProReviewNativeCanary(
	pathname = DEFAULT_PRO_REVIEW_NATIVE_CANARY_PATH,
): ProReviewNativeCanary {
	const parsed = readAndParse(pathname, ProReviewNativeCanarySchema);
	if (!parsed.ok) {
		throw new Error(`invalid Yoetz native canary evidence: ${parsed.error}`);
	}
	const failures = requiredCanaryCheckFailures(parsed.value);
	if (failures.length > 0) {
		throw new Error(`invalid Yoetz native canary commands: ${failures.join("; ")}`);
	}
	return parsed.value;
}

type BuildProReviewYoetzCommandInput = {
	readonly canary: ProReviewNativeCanary;
	readonly bundlePath: string;
	readonly payloadSha256?: string;
	readonly bundleSha256?: string;
	readonly runId?: string;
	readonly conversation?: string;
	readonly waitTimeoutMs?: number;
	readonly shard?: ProReviewShard;
	readonly shardPlanSha256?: string;
};

export function buildProReviewYoetzCommand(input: BuildProReviewYoetzCommandInput): string[] {
	if (input.shard || input.shardPlanSha256) {
		throw new Error(
			"sharded Yoetz Pro review sends are disabled; send one complete full-context native bundle",
		);
	}
	const command = [
		"yoetz",
		"browser",
		"recipe",
		"--recipe",
		"chatgpt",
		"--transport",
		"chrome-extension-native",
		"--bundle",
		input.bundlePath,
		"--format",
		"json",
		"--var",
		`extension_instance_id=${input.canary.extensionInstanceId}`,
		"--var",
		`prompt=${buildProReviewYoetzPrompt(input)}`,
	];
	if (input.payloadSha256) {
		command.push("--var", `payload_sha256=${input.payloadSha256}`);
	}
	if (input.bundleSha256) {
		command.push("--var", `bundle_sha256=${input.bundleSha256}`);
	}
	if (input.runId) {
		command.push("--var", `run_id=${input.runId}`);
	}
	if (input.conversation) {
		command.push("--var", `conversation=${input.conversation}`);
	}
	if (input.waitTimeoutMs !== undefined) {
		command.push("--var", `wait_timeout_ms=${String(input.waitTimeoutMs)}`);
	}
	return command;
}

function buildProReviewYoetzPrompt(input: BuildProReviewYoetzCommandInput): string {
	return [
		"Read the attached Hermes Pro-review bundle as one complete full-context, non-sharded source and evidence review.",
		"The attachment contains the code and artifacts; do not treat this as a summary, sample, or privacy-trimmed shard.",
		input.conversation
			? "This is a retry in the same owned ChatGPT conversation after an invalid, incomplete, or blocked answer; ignore prior conclusions unless they remain grounded in the newly attached full bundle."
			: "This is a fresh native review run.",
		"Return a real bounded engineering review with grounded P0/P1/P2 findings only. If the attachment is unreadable or incomplete, say BLOCKER instead of guessing.",
		"Do not draft prose before the template. Do not answer with a fragment or one-letter response.",
		"Start with this exact binding line:",
		`payloadSha256: ${input.payloadSha256 ?? ""}`,
		"Then use exactly these section labels:",
		"Findings:",
		"Residual risk:",
		'If no grounded P0/P1/P2 issue is visible in this bundle, write "Findings: none" and give a brief residual-risk note.',
	].join("\n");
}

export function buildProReviewNativeYoetzEnv(
	source: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv {
	const env: NodeJS.ProcessEnv = {};
	for (const [key, value] of Object.entries(source)) {
		if (value === undefined) continue;
		if (key === "YOETZ_AGENT") continue;
		if (!PRO_REVIEW_NATIVE_YOETZ_ENV_ALLOWED_KEYS.has(key)) continue;
		if (proReviewNativeYoetzEnvValueLooksSecret(key, value)) continue;
		env[key] = value;
	}
	env.YOETZ_AGENT = "1";
	return env;
}

function proReviewNativeYoetzEnvValueLooksSecret(key: string, value: string): boolean {
	return filterOutput(`${key}=${value}`).blocked;
}

function readJsonObject(
	reportPath: string,
): { ok: true; value: Record<string, unknown> } | { ok: false; error: string } {
	const resolved = resolveHermesArtifactPath(reportPath);
	try {
		const raw = JSON.parse(fs.readFileSync(resolved, "utf8")) as unknown;
		if (!isRecord(raw)) return { ok: false, error: "evidence must be a JSON object" };
		return { ok: true, value: raw };
	} catch (error) {
		return { ok: false, error: error instanceof Error ? error.message : String(error) };
	}
}

export function validateProReviewYoetzSendOutput(input: {
	readonly stdout: string;
	readonly expectedExtensionInstanceId: string;
	readonly expectedBundlePath: string;
	readonly expectedPayloadSha256?: string;
	readonly expectedBundleSha256?: string;
	readonly expectedShard?: ProReviewShard;
	readonly expectedShardPlanSha256?: string;
}): ProReviewYoetzSendValidation {
	if (input.expectedShard || input.expectedShardPlanSha256) {
		return {
			status: "fail",
			detail:
				"sharded Yoetz Pro review output validation is disabled; require one complete full-context native bundle",
		};
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(input.stdout);
	} catch (error) {
		return {
			status: "fail",
			detail: `Yoetz native send stdout is not JSON: ${
				error instanceof Error ? error.message : String(error)
			}`,
		};
	}
	if (!isRecord(parsed)) {
		return { status: "fail", detail: "Yoetz native send stdout is not a JSON object" };
	}
	const failures: string[] = [...proReviewYoetzFinalContractFailures(parsed)];
	if (parsed.status !== "ok") {
		failures.push(`status is ${String(parsed.status)}`);
	}
	if (parsed.transport !== "chrome-extension-native") {
		failures.push(`transport is ${String(parsed.transport)}`);
	}
	if (parsed.model_selection_status !== "selected") {
		failures.push(`model_selection_status is ${String(parsed.model_selection_status)}`);
	}
	if (!isExtendedProModel(parsed.model_used)) {
		failures.push(`model_used is ${String(parsed.model_used)}`);
	}
	if (parsed.fallback_used !== false) {
		failures.push(`fallback_used is ${String(parsed.fallback_used)}`);
	}
	if (parsed.auto_paste_fallback !== false) {
		failures.push(`auto_paste_fallback is ${String(parsed.auto_paste_fallback)}`);
	}
	if (Array.isArray(parsed.warnings) && parsed.warnings.length > 0) {
		failures.push(`warnings are not empty (${parsed.warnings.length})`);
	} else if (!Array.isArray(parsed.warnings)) {
		failures.push("warnings is not an array");
	}
	failures.push(...optionalBundleArtifactPathFailures(parsed, input.expectedBundlePath));
	const extensionInstanceId = parsed.extension_instance_id ?? parsed.extensionInstanceId;
	failures.push(
		...optionalStringEchoFailures(
			"extension_instance_id",
			extensionInstanceId,
			input.expectedExtensionInstanceId,
		),
	);
	failures.push(
		...optionalDigestEchoFailures(
			"payloadSha256",
			digestEchoValue(parsed, "payloadSha256", "payload_sha256"),
			input.expectedPayloadSha256,
		),
	);
	failures.push(
		...optionalDigestEchoFailures(
			"bundleSha256",
			digestEchoValue(parsed, "bundleSha256", "bundle_sha256"),
			input.expectedBundleSha256,
		),
	);
	failures.push(
		...proReviewResponseFailures(parsed.response, {
			expectedPayloadSha256: input.expectedPayloadSha256,
		}),
	);
	return failures.length === 0
		? {
				status: "pass",
				detail:
					"Yoetz native send reported Extended Pro without fallback, optional echoes matched, and response looked like a review",
			}
		: { status: "fail", detail: failures.join("; ") };
}

export function validateProReviewYoetzInspectOutput(input: {
	readonly stdout: string;
	readonly expectedRunId: string;
}): ProReviewYoetzSendValidation {
	let parsed: unknown;
	try {
		parsed = JSON.parse(input.stdout);
	} catch (error) {
		return {
			status: "fail",
			detail: `Yoetz native inspect stdout is not JSON: ${
				error instanceof Error ? error.message : String(error)
			}`,
		};
	}
	if (!isRecord(parsed)) {
		return { status: "fail", detail: "Yoetz native inspect stdout is not a JSON object" };
	}
	const failures: string[] = [];
	if (parsed.status !== "ok") {
		failures.push(`status is ${String(parsed.status)}`);
	}
	if (parsed.transport !== "chrome-extension-native") {
		failures.push(`transport is ${String(parsed.transport)}`);
	}
	const response = parsed.response;
	if (!isRecord(response)) {
		failures.push("response is missing or not an object");
	} else {
		failures.push(
			...stringEchoFailures("runId", response.run_id ?? response.runId, input.expectedRunId),
		);
		if (!Array.isArray(response.tabs) || response.tabs.length < 1) {
			failures.push("response.tabs is missing or empty");
		}
	}
	return failures.length === 0
		? {
				status: "pass",
				detail: "Yoetz native inspect found the generated run id in an owned ChatGPT tab",
			}
		: { status: "fail", detail: failures.join("; ") };
}

export function validateProReviewYoetzInspectCompletedResponseOutput(input: {
	readonly stdout: string;
	readonly expectedRunId: string;
	readonly expectedPayloadSha256?: string;
	readonly expectedShard?: ProReviewShard;
	readonly expectedShardPlanSha256?: string;
}): ProReviewYoetzSendValidation {
	if (input.expectedShard || input.expectedShardPlanSha256) {
		return {
			status: "fail",
			detail:
				"sharded Yoetz Pro review inspect recovery is disabled; require one complete full-context native bundle",
		};
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(input.stdout);
	} catch (error) {
		return {
			status: "fail",
			detail: `Yoetz native inspect stdout is not JSON: ${
				error instanceof Error ? error.message : String(error)
			}`,
		};
	}
	if (!isRecord(parsed)) {
		return { status: "fail", detail: "Yoetz native inspect stdout is not a JSON object" };
	}
	const failures: string[] = [];
	if (parsed.status !== "ok") failures.push(`status is ${String(parsed.status)}`);
	if (parsed.transport !== "chrome-extension-native") {
		failures.push(`transport is ${String(parsed.transport)}`);
	}
	const response = parsed.response;
	if (!isRecord(response)) {
		failures.push("response is missing or not an object");
	} else {
		failures.push(
			...stringEchoFailures("runId", response.run_id ?? response.runId, input.expectedRunId),
		);
		const tabs = response.tabs;
		if (!Array.isArray(tabs) || tabs.length < 1) {
			failures.push("response.tabs is missing or empty");
		} else {
			const matchingTab = tabs.find(
				(tab): tab is Record<string, unknown> =>
					isRecord(tab) && inspectTabOwnershipRunId(tab) === input.expectedRunId,
			);
			if (!matchingTab) {
				failures.push("no inspected tab has ownership.run_id matching expected run");
			} else {
				failures.push(
					...inspectTabCompletedResponseFailures(matchingTab, {
						expectedRunId: input.expectedRunId,
						expectedPayloadSha256: input.expectedPayloadSha256,
					}),
				);
			}
		}
	}
	return failures.length === 0
		? {
				status: "pass",
				detail:
					"Yoetz native inspect recovered a completed Extended Pro response bound to the expected run",
			}
		: { status: "fail", detail: failures.join("; ") };
}

function proReviewYoetzFinalContractFailures(parsed: Record<string, unknown>): string[] {
	const failures: string[] = [];
	const envelopeType = parsed.type ?? parsed.kind;
	if (envelopeType === "job_progress") {
		failures.push("Yoetz output is job_progress, not final job_complete");
	}
	if (parsed.is_final === false) {
		failures.push("is_final is false");
	}
	if (parsed.response_in_progress === true) {
		failures.push("response_in_progress is true");
	}
	if (parsed.interim_assistant_turn === true) {
		failures.push("interim_assistant_turn is true");
	}
	const payload = parsed.payload;
	if (isRecord(payload)) {
		if (payload.is_final === false) {
			failures.push("payload.is_final is false");
		}
		if (payload.response_in_progress === true) {
			failures.push("payload.response_in_progress is true");
		}
		if (payload.interim_assistant_turn === true) {
			failures.push("payload.interim_assistant_turn is true");
		}
	}
	return failures;
}

function proReviewInspectInProgressFailures(
	tab: Record<string, unknown>,
	extraction: Record<string, unknown> | null,
): string[] {
	const failures: string[] = [];
	if (tab.response_in_progress === true) {
		failures.push("response_in_progress is true");
	}
	if (tab.interim_assistant_turn === true) {
		failures.push("interim_assistant_turn is true");
	}
	if (extraction?.is_generating === true) {
		failures.push("inspection extraction is_generating is true");
	}
	return failures;
}

function inspectTabCompletedResponseFailures(
	tab: Record<string, unknown>,
	binding: {
		readonly expectedRunId: string;
		readonly expectedPayloadSha256?: string;
	},
): string[] {
	const failures: string[] = [];
	const inspection = tab.inspection;
	if (!isRecord(inspection)) return ["response.tabs[0].inspection is missing or not an object"];
	failures.push(...inspectTabOwnershipFailures(inspection, binding.expectedRunId));
	const extraction = inspection.extraction;
	failures.push(
		...proReviewInspectInProgressFailures(tab, isRecord(extraction) ? extraction : null),
	);
	const extractionText = isRecord(extraction) ? extraction.text : undefined;
	if (!isRecord(extraction)) {
		failures.push("response.tabs[0].inspection.extraction is missing or not an object");
	} else {
		if (extraction.is_generating !== false && extraction.is_generating !== true) {
			failures.push(`inspection extraction is_generating is ${String(extraction.is_generating)}`);
		}
		failures.push(
			...proReviewResponseFailures(extraction.text, {
				expectedPayloadSha256: binding.expectedPayloadSha256,
			}),
		);
	}
	const modelSelection = inspection.model_selection;
	if (!isRecord(modelSelection)) {
		failures.push("response.tabs[0].inspection.model_selection is missing or not an object");
	} else if (!inspectModelSelectionLooksExtendedPro(modelSelection, extractionText)) {
		failures.push(
			`inspection model current_model_label is ${String(modelSelection.current_model_label)}`,
		);
	}
	return failures;
}

function inspectModelSelectionLooksExtendedPro(
	modelSelection: Record<string, unknown>,
	extractionText: unknown,
): boolean {
	if (isExtendedProModel(modelSelection.current_model_label)) return true;
	return (
		modelSelection.requested_model === "extended-pro" &&
		typeof extractionText === "string" &&
		/(^|\n)Extended Pro(\n|$)/.test(extractionText)
	);
}

function inspectTabOwnershipRunId(tab: Record<string, unknown>): string | null {
	const inspection = tab.inspection;
	if (!isRecord(inspection)) return null;
	const ownership = inspection.ownership;
	if (!isRecord(ownership)) return null;
	return typeof ownership.run_id === "string" ? ownership.run_id : null;
}

function inspectTabOwnershipFailures(
	inspection: Record<string, unknown>,
	expectedRunId: string,
): string[] {
	const ownership = inspection.ownership;
	if (!isRecord(ownership)) return ["inspection ownership is missing or not an object"];
	const failures: string[] = [];
	const runId = ownership.run_id ?? ownership.runId;
	if (runId !== expectedRunId) {
		failures.push(`inspection ownership run_id is ${String(runId)}, expected ${expectedRunId}`);
	}
	const windowName = inspection.window_name ?? inspection.windowName;
	if (typeof windowName !== "string" || !windowName.includes(expectedRunId)) {
		failures.push("inspection window_name does not contain expected run id");
	}
	return failures;
}

function isExtendedProModel(value: unknown): boolean {
	return value === "Extended Pro" || value === "extended-pro";
}

function digestEchoValue(
	parsed: Record<string, unknown>,
	camelKey: "payloadSha256" | "bundleSha256" | "shardPlanSha256" | "shardSha256",
	snakeKey: "payload_sha256" | "bundle_sha256" | "shard_plan_sha256" | "shard_sha256",
): unknown {
	return parsed[camelKey] ?? parsed[snakeKey];
}

function optionalBundleArtifactPathFailures(
	parsed: Record<string, unknown>,
	expectedBundlePath: string | undefined,
): string[] {
	const artifacts = parsed.artifacts;
	if (artifacts === undefined || artifacts === null) return [];
	if (expectedBundlePath === undefined || !expectedBundlePath.trim()) {
		return ["expected bundle artifact path is missing"];
	}
	if (!isRecord(artifacts)) return ["artifacts is missing or not an object"];
	const actual = artifacts.bundle_md ?? artifacts.bundleMd;
	if (typeof actual !== "string" || !actual.trim()) {
		return ["artifacts.bundle_md is missing or not a string"];
	}
	const normalizedActual = path.resolve(actual);
	const normalizedExpected = path.resolve(expectedBundlePath);
	if (normalizedActual !== normalizedExpected) {
		return [`artifacts.bundle_md is ${actual}, expected ${expectedBundlePath}`];
	}
	return [];
}

function optionalDigestEchoFailures(
	field: "payloadSha256" | "bundleSha256" | "shardPlanSha256" | "shardSha256",
	actual: unknown,
	expected: string | undefined,
): string[] {
	if (actual === undefined || actual === null) return [];
	if (typeof actual !== "string") return [`${field} is missing or not a string`];
	if (!SHA256_DIGEST_PATTERN.test(actual)) return [`${field} is not a sha256 digest`];
	if (expected === undefined) return [`expected ${field} is missing`];
	if (!SHA256_DIGEST_PATTERN.test(expected)) return [`expected ${field} is not a sha256 digest`];
	if (actual !== expected) return [`${field} is ${actual}, expected ${expected}`];
	return [];
}

function optionalStringEchoFailures(
	field: "extension_instance_id" | "shard_id",
	actual: unknown,
	expected: string | undefined,
): string[] {
	if (actual === undefined || actual === null) return [];
	if (typeof actual !== "string" || !actual.trim()) return [`${field} is missing or not a string`];
	if (expected === undefined || !expected.trim()) return [`expected ${field} is missing`];
	if (actual !== expected) return [`${field} is ${actual}, expected ${expected}`];
	return [];
}

function proReviewResponseFailures(
	response: unknown,
	binding: {
		readonly expectedPayloadSha256?: string;
	} = {},
): string[] {
	if (typeof response !== "string") return ["response is missing or not a string"];
	const trimmed = response.trim();
	if (trimmed.length < 80) {
		return [`response is too short to be a review (${trimmed.length} character(s))`];
	}
	if (trimmed === "I") return ["response is the known one-character ChatGPT truncation"];
	const failures: string[] = [];
	if (!/\bFindings\s*:/i.test(trimmed))
		failures.push("response does not contain a Findings section");
	if (!/\bResidual risk\s*:/i.test(trimmed)) {
		failures.push("response does not contain a Residual risk section");
	}
	if (binding.expectedPayloadSha256) {
		failures.push(
			...responseBindingLineFailures(trimmed, "payloadSha256", binding.expectedPayloadSha256),
		);
	}
	return failures;
}

function responseBindingLineFailures(
	response: string,
	field: "payloadSha256" | "shardPlanSha256" | "shardId" | "shardSha256",
	expected: string | undefined,
): string[] {
	if (expected === undefined || !expected.trim()) return [`expected ${field} is missing`];
	if (!response.includes(`${field}: ${expected}`)) {
		return [`response does not echo ${field}: ${expected}`];
	}
	return [];
}

function stringEchoFailures(
	field: "runId",
	actual: unknown,
	expected: string | undefined,
): string[] {
	if (typeof actual !== "string" || !actual.trim()) return [`${field} is missing or not a string`];
	if (expected === undefined || !expected.trim()) return [`expected ${field} is missing`];
	if (actual !== expected) return [`${field} is ${actual}, expected ${expected}`];
	return [];
}

function readAndParse<T>(
	pathname: string,
	schema: z.ZodType<T>,
): { ok: true; value: T } | { ok: false; error: string } {
	const resolved = resolveHermesArtifactPath(pathname);
	try {
		const raw = JSON.parse(fs.readFileSync(resolved, "utf8")) as unknown;
		const parsed = schema.safeParse(raw);
		if (!parsed.success) {
			return { ok: false, error: flattenZodError(parsed.error) };
		}
		return { ok: true, value: parsed.data };
	} catch (error) {
		return {
			ok: false,
			error: String(error instanceof Error ? error.message : error),
		};
	}
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function digestJson(value: unknown): string {
	return digestText(JSON.stringify(value));
}

function digestText(value: string): string {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function normalizeArtifactPath(value: string): string {
	return path.relative(process.cwd(), resolveHermesArtifactPath(value));
}

function flattenZodError(error: z.ZodError): string {
	return error.issues
		.map((issue) => {
			const pathLabel = issue.path.length > 0 ? issue.path.join(".") : "<root>";
			return `${pathLabel}: ${issue.message}`;
		})
		.join("; ");
}

function pass(name: string, detail: string): ProReviewGate {
	return { name, status: "pass", detail };
}

function fail(name: string, detail: string): ProReviewGate {
	return { name, status: "fail", detail };
}

function pending(name: string, detail: string): ProReviewGate {
	return { name, status: "pending", detail };
}
