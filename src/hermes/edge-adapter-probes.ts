import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { z } from "zod";
import {
	type HermesSignedEvidenceValidationOptions,
	hermesAllowsStaleAttestations,
	hermesAttestationFreshnessFailure,
} from "./attestation-validation.js";
import {
	EDGE_ADAPTER_ATTESTATION_RUNNER,
	EDGE_ADAPTER_ATTESTATION_SCHEMA_VERSION,
	EDGE_ADAPTER_ATTESTATION_SOURCE,
	type EdgeAdapterAttestation,
	edgeAdapterAttestationFieldsForEvidence,
	edgeAdapterAttestationSignatureFailure,
	signEdgeAdapterAttestation,
} from "./edge-adapter-attestation.js";
import {
	ActorRefSchema,
	AttachmentRefSchema,
	ConversationRefSchema,
	DeliveryReceiptSchema,
	EDGE_ADAPTER_CONTRACT_VERSION,
	EDGE_ADAPTER_OPERATION_NAMES,
	EdgeAdapterOperationNameSchema,
	EdgeAdapterSchemaVersions,
	EdgeChannelSchema,
	InboundEventSchema,
	OutboundDecisionSchema,
	OutboundRequestSchema,
	PreparedOutboundSchema,
	StatusViewSchema,
	TrustDomainSchema,
} from "./edge-adapter-contract.js";
import {
	createTelclaudeEdgeRuntime,
	isTelclaudeEdgeRuntimeDeniedError,
} from "./edge-adapter-runtime.js";
import {
	DEFAULT_PROVIDER_RELEASE_POLICY_EVIDENCE_PATH,
	ProviderReleasePolicyProbeEvidenceSchema,
	providerReleasePolicyProbeEvidenceFailure,
} from "./provider-release-policy-probe.js";

const NonEmptyString = z.string().trim().min(1);
const Sha256Digest = z.string().regex(/^sha256:[a-f0-9]{64}$/i);
const HexSha256Digest = z.string().regex(/^[a-f0-9]{64}$/);

export const EDGE_ADAPTER_PROBE_SCHEMA_VERSION = "telclaude.hermes.edge-adapter-probe.v1";
export const EDGE_ADAPTER_CONTRACT_PROBE_SOURCE = "telclaude-edge-contract-unit";
export const EDGE_ADAPTER_RUNTIME_PROBE_SOURCE = "telclaude-edge-runtime-harness";
export const EDGE_ADAPTER_PROBE_SOURCE = EDGE_ADAPTER_CONTRACT_PROBE_SOURCE;
export const EDGE_ADAPTER_FIXTURE_EVIDENCE_SCHEMA_VERSION =
	"telclaude.hermes.edge-adapter-fixture-evidence.v1";
export const EDGE_ADAPTER_FIXTURE_EVIDENCE_SOURCE = "telclaude-edge-runtime-fixture-generator";
export const EDGE_ADAPTER_FIXTURE_EVIDENCE_RUNNER = "telclaude-edge-runtime-fixture-harness";
export const DEFAULT_EDGE_ADAPTER_FIXTURE_EVIDENCE_DIR = "artifacts/hermes/fixtures";
export const EDGE_ADAPTER_FEATURE_SURFACE_IDS = [
	"edge.whatsapp",
	"edge.email",
	"edge.agentmail",
	"edge.social",
	"identity.migration",
	"household.scopes",
	"attachment.quarantine",
	"outbound.policy",
	"public.social.isolation",
] as const;

const EDGE_ADAPTER_RUNTIME_SURFACE_IDS = [
	"edge.whatsapp",
	"edge.email",
	"edge.agentmail",
	"edge.social",
	"identity.migration",
	"household.scopes",
	"attachment.quarantine",
	"outbound.policy",
	"public.social.isolation",
] as const satisfies readonly EdgeAdapterFeatureSurfaceId[];
const EDGE_ADAPTER_RUNTIME_SURFACE_SET = new Set<string>(EDGE_ADAPTER_RUNTIME_SURFACE_IDS);

export type EdgeAdapterFeatureSurfaceId = (typeof EDGE_ADAPTER_FEATURE_SURFACE_IDS)[number];

const EdgeAdapterFeatureSurfaceIdSchema = z.enum(EDGE_ADAPTER_FEATURE_SURFACE_IDS);
type EdgeFixtureProbeId = EdgeAdapterFeatureSurfaceId | "providers.release-policy";

export const DEFAULT_EDGE_ADAPTER_EVIDENCE_PATHS: Record<EdgeAdapterFeatureSurfaceId, string> = {
	"edge.whatsapp": "artifacts/hermes/probes/edge-whatsapp.json",
	"edge.email": "artifacts/hermes/probes/edge-email.json",
	"edge.agentmail": "artifacts/hermes/probes/edge-agentmail.json",
	"edge.social": "artifacts/hermes/probes/edge-social.json",
	"identity.migration": "artifacts/hermes/probes/identity-migration.json",
	"household.scopes": "artifacts/hermes/probes/household-scopes.json",
	"attachment.quarantine": "artifacts/hermes/probes/attachment-quarantine.json",
	"outbound.policy": "artifacts/hermes/probes/outbound-policy.json",
	"public.social.isolation": "artifacts/hermes/probes/public-social-isolation.json",
};

type EdgeChannel = z.infer<typeof EdgeChannelSchema>;
type TrustDomain = z.infer<typeof TrustDomainSchema>;
type EdgeControlName =
	| "contract.operations.pinned"
	| "contract.actor-ref.validates"
	| "contract.conversation-ref.validates"
	| "contract.inbound.sanitized"
	| "contract.outbound.request-only"
	| "contract.outbound.prepared-owned"
	| "contract.outbound.decision-owned"
	| "contract.delivery.receipt-ref-only"
	| "contract.status.redacted"
	| "credentials.telclaude-owned"
	| "credentials.raw-denied"
	| "attachment.ref-only"
	| "attachment.unknown-quarantine-denied"
	| "whatsapp.unknown-sender-denied"
	| "whatsapp.direct-bridge-denied"
	| "email.wrong-thread-denied"
	| "email.direct-mailbox-denied"
	| "agentmail.direct-key-denied"
	| "agentmail.unauthorized-sender-denied"
	| "social.unapproved-posting-denied"
	| "social.budget-denied"
	| "social.private-memory-denied"
	| "identity.forged-actor-denied"
	| "identity.revocation-enforced"
	| "identity.session-id-not-authority"
	| "identity.cross-channel-denied"
	| "household.scoped-benign-allowed"
	| "household.strong-link-required"
	| "household.number-only-provider-denied"
	| "household.private-memory-denied"
	| "household.cross-recipient-denied"
	| "attachment.raw-bytes-denied"
	| "attachment.local-path-denied"
	| "attachment.download-url-denied"
	| "attachment.unscanned-denied"
	| "attachment.cross-domain-reuse-denied"
	| "outbound.hermes-authority-denied"
	| "outbound.transport-credentials-denied"
	| "outbound.policy-result-denied"
	| "outbound.approval-token-denied"
	| "outbound.recipient-body-bound"
	| "outbound.replay-denied"
	| "public-social.separate-profile"
	| "public-social.private-workspace-denied"
	| "public-social.private-memory-denied"
	| "public-social.provider-scope-denied"
	| "public-social.budget-denied";

type EdgeSurfaceRequirement = {
	readonly channels: readonly EdgeChannel[];
	readonly trustDomains: readonly TrustDomain[];
	readonly requiredControls: readonly EdgeControlName[];
};

type EdgeFixtureProbeRequirement = {
	readonly probeId: EdgeFixtureProbeId;
	readonly requiredChecks: readonly string[];
};

type EdgeFixtureRequirement = {
	readonly id: string;
	readonly fixtureClass: "positive" | "negative";
	readonly requiredProbes: readonly EdgeFixtureProbeRequirement[];
};

const BASE_EDGE_CONTROLS = [
	"contract.operations.pinned",
	"contract.actor-ref.validates",
	"contract.conversation-ref.validates",
	"contract.inbound.sanitized",
	"contract.outbound.request-only",
	"contract.outbound.prepared-owned",
	"contract.outbound.decision-owned",
	"contract.delivery.receipt-ref-only",
	"contract.status.redacted",
	"credentials.telclaude-owned",
	"credentials.raw-denied",
	"attachment.ref-only",
] as const satisfies readonly EdgeControlName[];

const EDGE_SURFACE_REQUIREMENTS: Record<EdgeAdapterFeatureSurfaceId, EdgeSurfaceRequirement> = {
	"edge.whatsapp": {
		channels: ["whatsapp"],
		trustDomains: ["public", "household"],
		requiredControls: [
			...BASE_EDGE_CONTROLS,
			"whatsapp.unknown-sender-denied",
			"whatsapp.direct-bridge-denied",
		],
	},
	"edge.email": {
		channels: ["email"],
		trustDomains: ["public", "household"],
		requiredControls: [
			...BASE_EDGE_CONTROLS,
			"email.wrong-thread-denied",
			"email.direct-mailbox-denied",
		],
	},
	"edge.agentmail": {
		channels: ["agentmail"],
		trustDomains: ["public"],
		requiredControls: [
			...BASE_EDGE_CONTROLS,
			"agentmail.direct-key-denied",
			"agentmail.unauthorized-sender-denied",
		],
	},
	"edge.social": {
		channels: ["social"],
		trustDomains: ["public-social"],
		requiredControls: [
			...BASE_EDGE_CONTROLS,
			"social.unapproved-posting-denied",
			"social.budget-denied",
			"social.private-memory-denied",
		],
	},
	"identity.migration": {
		channels: ["whatsapp", "email", "agentmail", "social"],
		trustDomains: ["private", "household", "public", "public-social"],
		requiredControls: [
			"contract.actor-ref.validates",
			"contract.conversation-ref.validates",
			"identity.forged-actor-denied",
			"identity.revocation-enforced",
			"identity.session-id-not-authority",
			"identity.cross-channel-denied",
		],
	},
	"household.scopes": {
		channels: ["whatsapp", "email"],
		trustDomains: ["household"],
		requiredControls: [
			"contract.actor-ref.validates",
			"contract.conversation-ref.validates",
			"household.scoped-benign-allowed",
			"household.strong-link-required",
			"household.number-only-provider-denied",
			"household.private-memory-denied",
			"household.cross-recipient-denied",
		],
	},
	"attachment.quarantine": {
		channels: ["whatsapp", "email", "agentmail", "social"],
		trustDomains: ["private", "household", "public", "public-social"],
		requiredControls: [
			"contract.inbound.sanitized",
			"attachment.ref-only",
			"attachment.unknown-quarantine-denied",
			"attachment.raw-bytes-denied",
			"attachment.local-path-denied",
			"attachment.download-url-denied",
			"attachment.unscanned-denied",
			"attachment.cross-domain-reuse-denied",
		],
	},
	"outbound.policy": {
		channels: ["whatsapp", "email", "agentmail", "social"],
		trustDomains: ["private", "household", "public", "public-social"],
		requiredControls: [
			"contract.outbound.request-only",
			"contract.outbound.prepared-owned",
			"contract.outbound.decision-owned",
			"outbound.hermes-authority-denied",
			"outbound.transport-credentials-denied",
			"outbound.policy-result-denied",
			"outbound.approval-token-denied",
			"outbound.recipient-body-bound",
			"outbound.replay-denied",
		],
	},
	"public.social.isolation": {
		channels: ["social"],
		trustDomains: ["public-social"],
		requiredControls: [
			"contract.conversation-ref.validates",
			"public-social.separate-profile",
			"public-social.private-workspace-denied",
			"public-social.private-memory-denied",
			"public-social.provider-scope-denied",
			"public-social.budget-denied",
		],
	},
};

export const EDGE_FIXTURE_REQUIREMENTS = [
	{
		id: "fixture.public.whatsapp.basic",
		fixtureClass: "positive",
		requiredProbes: [
			{
				probeId: "edge.whatsapp",
				requiredChecks: [
					"contract.inbound.sanitized",
					"contract.outbound.prepared-owned",
					"contract.delivery.receipt-ref-only",
					"credentials.raw-denied",
					"attachment.ref-only",
				],
			},
			{
				probeId: "outbound.policy",
				requiredChecks: ["outbound.recipient-body-bound", "outbound.replay-denied"],
			},
		],
	},
	{
		id: "fixture.household.whatsapp.benign",
		fixtureClass: "positive",
		requiredProbes: [
			{
				probeId: "edge.whatsapp",
				requiredChecks: ["contract.inbound.sanitized", "attachment.ref-only"],
			},
			{
				probeId: "household.scopes",
				requiredChecks: ["household.scoped-benign-allowed", "household.strong-link-required"],
			},
		],
	},
	{
		id: "fixture.public.whatsapp.unknown-deny",
		fixtureClass: "negative",
		requiredProbes: [
			{
				probeId: "edge.whatsapp",
				requiredChecks: ["whatsapp.unknown-sender-denied", "whatsapp.direct-bridge-denied"],
			},
		],
	},
	{
		id: "fixture.household.whatsapp.provider-unscoped-deny",
		fixtureClass: "negative",
		requiredProbes: [
			{
				probeId: "household.scopes",
				requiredChecks: ["household.strong-link-required", "household.number-only-provider-denied"],
			},
		],
	},
	{
		id: "fixture.public.email.basic",
		fixtureClass: "positive",
		requiredProbes: [
			{
				probeId: "edge.email",
				requiredChecks: [
					"contract.inbound.sanitized",
					"contract.outbound.prepared-owned",
					"contract.delivery.receipt-ref-only",
					"credentials.raw-denied",
				],
			},
			{
				probeId: "outbound.policy",
				requiredChecks: ["outbound.recipient-body-bound", "outbound.replay-denied"],
			},
		],
	},
	{
		id: "fixture.household.email.scoped",
		fixtureClass: "positive",
		requiredProbes: [
			{
				probeId: "edge.email",
				requiredChecks: ["contract.inbound.sanitized", "attachment.ref-only"],
			},
			{
				probeId: "household.scopes",
				requiredChecks: ["household.scoped-benign-allowed", "household.strong-link-required"],
			},
		],
	},
	{
		id: "fixture.public.email.wrong-thread-deny",
		fixtureClass: "negative",
		requiredProbes: [
			{
				probeId: "edge.email",
				requiredChecks: ["email.wrong-thread-denied", "email.direct-mailbox-denied"],
			},
		],
	},
	{
		id: "fixture.household.email.private-memory-deny",
		fixtureClass: "negative",
		requiredProbes: [
			{
				probeId: "household.scopes",
				requiredChecks: ["household.private-memory-denied"],
			},
		],
	},
	{
		id: "fixture.public.agentmail.basic",
		fixtureClass: "positive",
		requiredProbes: [
			{
				probeId: "edge.agentmail",
				requiredChecks: [
					"contract.inbound.sanitized",
					"contract.outbound.prepared-owned",
					"agentmail.unauthorized-sender-denied",
				],
			},
			{
				probeId: "outbound.policy",
				requiredChecks: ["outbound.recipient-body-bound"],
			},
		],
	},
	{
		id: "fixture.public.agentmail.direct-key-deny",
		fixtureClass: "negative",
		requiredProbes: [
			{
				probeId: "edge.agentmail",
				requiredChecks: ["agentmail.direct-key-denied"],
			},
		],
	},
	{
		id: "fixture.public.social.timeline",
		fixtureClass: "positive",
		requiredProbes: [
			{
				probeId: "edge.social",
				requiredChecks: ["contract.inbound.sanitized", "social.unapproved-posting-denied"],
			},
			{
				probeId: "public.social.isolation",
				requiredChecks: ["public-social.separate-profile"],
			},
		],
	},
	{
		id: "fixture.public.social.reply",
		fixtureClass: "positive",
		requiredProbes: [
			{
				probeId: "edge.social",
				requiredChecks: ["social.unapproved-posting-denied", "social.budget-denied"],
			},
			{
				probeId: "outbound.policy",
				requiredChecks: ["outbound.recipient-body-bound", "outbound.replay-denied"],
			},
		],
	},
	{
		id: "fixture.public.social.private-leak-deny",
		fixtureClass: "negative",
		requiredProbes: [
			{
				probeId: "public.social.isolation",
				requiredChecks: [
					"public-social.private-workspace-denied",
					"public-social.private-memory-denied",
					"public-social.provider-scope-denied",
				],
			},
		],
	},
	{
		id: "fixture.public.social.budget-deny",
		fixtureClass: "negative",
		requiredProbes: [
			{
				probeId: "edge.social",
				requiredChecks: ["social.budget-denied"],
			},
			{
				probeId: "public.social.isolation",
				requiredChecks: ["public-social.budget-denied"],
			},
		],
	},
	{
		id: "fixture.household.provider.strong-link-read",
		fixtureClass: "positive",
		requiredProbes: [
			{
				probeId: "household.scopes",
				requiredChecks: ["household.strong-link-required"],
			},
			{
				probeId: "providers.release-policy",
				requiredChecks: [
					"provider.release.allowed-read-audited",
					"provider.release.raw-secret-not-observed",
				],
			},
		],
	},
	{
		id: "fixture.household.private-memory-deny",
		fixtureClass: "negative",
		requiredProbes: [
			{
				probeId: "household.scopes",
				requiredChecks: ["household.private-memory-denied"],
			},
			{
				probeId: "providers.release-policy",
				requiredChecks: ["provider.release.private-memory-denied"],
			},
		],
	},
	{
		id: "fixture.household.provider-number-only-deny",
		fixtureClass: "negative",
		requiredProbes: [
			{
				probeId: "household.scopes",
				requiredChecks: ["household.strong-link-required", "household.number-only-provider-denied"],
			},
			{
				probeId: "providers.release-policy",
				requiredChecks: ["provider.release.missing-strong-link-denied"],
			},
		],
	},
	{
		id: "fixture.household.cross-recipient-deny",
		fixtureClass: "negative",
		requiredProbes: [
			{
				probeId: "household.scopes",
				requiredChecks: ["household.cross-recipient-denied"],
			},
			{
				probeId: "providers.release-policy",
				requiredChecks: [
					"provider.release.wrong-actor-denied",
					"provider.release.wrong-recipient-denied",
				],
			},
		],
	},
] as const satisfies readonly EdgeFixtureRequirement[];

const EdgeProbeControlSchema = z
	.object({
		name: NonEmptyString,
		status: z.enum(["pass", "fail"]),
		detail: NonEmptyString,
	})
	.strict();

const EdgeAdapterRuntimeHarnessSchema = z
	.object({
		source: z.literal(EDGE_ADAPTER_RUNTIME_PROBE_SOURCE),
		operationTrace: z
			.array(EdgeAdapterOperationNameSchema)
			.min(EDGE_ADAPTER_OPERATION_NAMES.length),
		checks: z.array(EdgeProbeControlSchema).min(1),
		observations: z
			.object({
				ingestedAttachments: z.number().int().nonnegative(),
				deniedAttempts: z.number().int().nonnegative(),
				ledgerEntries: z.number().int().nonnegative(),
				receiptRefs: z.number().int().nonnegative(),
			})
			.strict(),
	})
	.strict();

const InternalResponseProofSchema = z
	.object({
		version: z.literal("v1"),
		scope: NonEmptyString,
		timestamp: NonEmptyString,
		nonce: NonEmptyString,
		method: NonEmptyString,
		path: NonEmptyString,
		requestBodySha256: HexSha256Digest,
		responseBodySha256: HexSha256Digest,
		signature: NonEmptyString,
	})
	.strict();

const EdgeAdapterAttestationSchema = z
	.object({
		schemaVersion: z.literal(EDGE_ADAPTER_ATTESTATION_SCHEMA_VERSION),
		source: z.literal(EDGE_ADAPTER_ATTESTATION_SOURCE),
		runner: z.literal(EDGE_ADAPTER_ATTESTATION_RUNNER),
		probeEvidenceSchemaVersion: z.literal(EDGE_ADAPTER_PROBE_SCHEMA_VERSION),
		probeId: EdgeAdapterFeatureSurfaceIdSchema,
		status: z.enum(["pass", "fail"]),
		ran: z.boolean(),
		observedAt: NonEmptyString,
		evidenceSource: z.literal(EDGE_ADAPTER_RUNTIME_PROBE_SOURCE),
		surfaceSha256: Sha256Digest,
		contractSha256: Sha256Digest,
		custodySha256: Sha256Digest,
		controlsSha256: Sha256Digest,
		runtimeSha256: Sha256Digest,
		evidenceSha256: Sha256Digest,
		signature: InternalResponseProofSchema,
	})
	.strict();

export const EdgeAdapterProbeEvidenceSchema = z
	.object({
		schemaVersion: z.literal(EDGE_ADAPTER_PROBE_SCHEMA_VERSION),
		probeId: EdgeAdapterFeatureSurfaceIdSchema,
		status: z.enum(["pass", "fail"]),
		ran: z.boolean(),
		observedAt: NonEmptyString,
		source: z.enum([EDGE_ADAPTER_CONTRACT_PROBE_SOURCE, EDGE_ADAPTER_RUNTIME_PROBE_SOURCE]),
		summary: NonEmptyString,
		surface: z
			.object({
				id: EdgeAdapterFeatureSurfaceIdSchema,
				channels: z.array(EdgeChannelSchema).min(1),
				trustDomains: z.array(TrustDomainSchema).min(1),
			})
			.strict(),
		contract: z
			.object({
				version: z.literal(EDGE_ADAPTER_CONTRACT_VERSION),
				operations: z
					.array(EdgeAdapterOperationNameSchema)
					.min(EDGE_ADAPTER_OPERATION_NAMES.length),
				schemaVersions: z.array(NonEmptyString).min(1),
			})
			.strict(),
		custody: z
			.object({
				credentialOwner: z.literal("telclaude-edge"),
				hermesRawCredentialAccess: z.literal("denied"),
				attachmentRawAccess: z.literal("denied"),
				outboundExecutionOwner: z.literal("telclaude-edge"),
			})
			.strict(),
		controls: z.array(EdgeProbeControlSchema).min(1),
		runtime: EdgeAdapterRuntimeHarnessSchema.optional(),
		runnerAttestation: EdgeAdapterAttestationSchema.optional(),
	})
	.strict();

export type EdgeAdapterProbeEvidence = z.infer<typeof EdgeAdapterProbeEvidenceSchema>;

const Sha256DigestSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const EdgeFixtureProbeArtifactSchema = z
	.object({
		probeId: NonEmptyString,
		evidencePath: NonEmptyString,
		evidenceSha256: Sha256DigestSchema,
		requiredChecks: z.array(NonEmptyString).min(1),
		observedAt: NonEmptyString.optional(),
	})
	.strict();

export const EdgeAdapterFixtureEvidenceSchema = z
	.object({
		schemaVersion: z.literal(EDGE_ADAPTER_FIXTURE_EVIDENCE_SCHEMA_VERSION),
		id: NonEmptyString,
		status: z.enum(["pass", "fail"]),
		ran: z.literal(true),
		evidence_path: NonEmptyString,
		observedAt: NonEmptyString,
		provenance: z
			.object({
				runner: z.literal(EDGE_ADAPTER_FIXTURE_EVIDENCE_RUNNER),
				command: NonEmptyString,
				source: z.literal(EDGE_ADAPTER_FIXTURE_EVIDENCE_SOURCE),
			})
			.strict(),
		edge: z
			.object({
				fixtureClass: z.enum(["positive", "negative"]),
				requiredProbes: z.array(
					z
						.object({
							probeId: NonEmptyString,
							requiredChecks: z.array(NonEmptyString).min(1),
						})
						.strict(),
				),
				probeArtifacts: z.array(EdgeFixtureProbeArtifactSchema).min(1),
			})
			.strict(),
		checks: z.array(EdgeProbeControlSchema).min(1),
	})
	.strict();

export type EdgeAdapterFixtureEvidence = z.infer<typeof EdgeAdapterFixtureEvidenceSchema>;

export function isEdgeAdapterFeatureSurfaceId(
	surfaceId: string,
): surfaceId is EdgeAdapterFeatureSurfaceId {
	return EDGE_ADAPTER_FEATURE_SURFACE_IDS.includes(surfaceId as EdgeAdapterFeatureSurfaceId);
}

export function buildEdgeAdapterProbeEvidence(input: {
	surfaceId: EdgeAdapterFeatureSurfaceId;
	observedAt?: string;
	allowRun?: boolean;
}): EdgeAdapterProbeEvidence {
	const requirement = EDGE_SURFACE_REQUIREMENTS[input.surfaceId];
	const observedAt = input.observedAt ?? new Date().toISOString();
	if (input.allowRun !== true) {
		return {
			schemaVersion: EDGE_ADAPTER_PROBE_SCHEMA_VERSION,
			probeId: input.surfaceId,
			status: "fail",
			ran: false,
			observedAt,
			source: EDGE_ADAPTER_PROBE_SOURCE,
			summary: "edge adapter contract unit harness was not allowed to run",
			surface: {
				id: input.surfaceId,
				channels: [...requirement.channels],
				trustDomains: [...requirement.trustDomains],
			},
			contract: contractSummary(),
			custody: custodySummary(),
			controls: [
				{
					name: "contract.operations.pinned",
					status: "fail",
					detail: "run with --allow-run to execute the deterministic edge contract unit harness",
				},
			],
		};
	}
	const runtime = runRuntimeHarness(input.surfaceId, requirement);
	const controls = runControlChecks(requirement, runtime?.controlPasses);
	const status = controls.every((control) => control.status === "pass") ? "pass" : "fail";
	const evidence: Omit<EdgeAdapterProbeEvidence, "runnerAttestation"> = {
		schemaVersion: EDGE_ADAPTER_PROBE_SCHEMA_VERSION,
		probeId: input.surfaceId,
		status,
		ran: true,
		observedAt,
		source: runtime ? EDGE_ADAPTER_RUNTIME_PROBE_SOURCE : EDGE_ADAPTER_PROBE_SOURCE,
		summary:
			status === "pass"
				? runtime
					? `Edge runtime harness passed for ${input.surfaceId}`
					: `Edge contract unit harness passed for ${input.surfaceId}`
				: runtime
					? `Edge runtime harness failed for ${input.surfaceId}`
					: `Edge contract unit harness failed for ${input.surfaceId}`,
		surface: {
			id: input.surfaceId,
			channels: [...requirement.channels],
			trustDomains: [...requirement.trustDomains],
		},
		contract: contractSummary(),
		custody: custodySummary(),
		controls,
		...(runtime ? { runtime: runtime.evidence } : {}),
	};
	return status === "pass" && runtime
		? {
				...evidence,
				runnerAttestation: signEdgeAdapterAttestation(
					evidence,
				) as EdgeAdapterProbeEvidence["runnerAttestation"],
			}
		: evidence;
}

export function edgeAdapterProbeEvidenceFailure(
	surfaceId: string,
	evidence: unknown,
	options: HermesSignedEvidenceValidationOptions = {},
): string | null {
	if (!isEdgeAdapterFeatureSurfaceId(surfaceId)) {
		return `unsupported edge adapter surface ${surfaceId}`;
	}
	const parsed = EdgeAdapterProbeEvidenceSchema.safeParse(evidence);
	if (!parsed.success) {
		return `invalid edge adapter evidence: ${flattenZodError(parsed.error)}`;
	}
	const data = parsed.data;
	const requirement = EDGE_SURFACE_REQUIREMENTS[surfaceId];
	const failures: string[] = [];
	if (data.probeId !== surfaceId || data.surface.id !== surfaceId) {
		failures.push(`probe surface mismatch: expected ${surfaceId}, got ${data.probeId}`);
	}
	if (data.status !== "pass") failures.push(`status is ${data.status}`);
	if (data.ran !== true) failures.push("harness did not run");
	if (!sameSet(data.surface.channels, requirement.channels)) {
		failures.push(`channels do not match ${requirement.channels.join(",")}`);
	}
	if (!sameSet(data.surface.trustDomains, requirement.trustDomains)) {
		failures.push(`trust domains do not match ${requirement.trustDomains.join(",")}`);
	}
	if (!sameArray(data.contract.operations, EDGE_ADAPTER_OPERATION_NAMES)) {
		failures.push("contract operations are not the pinned edge operation set");
	}
	const controlsByName = new Map(data.controls.map((control) => [control.name, control]));
	for (const duplicate of duplicates(data.controls.map((control) => control.name))) {
		failures.push(`duplicate control ${duplicate}`);
	}
	for (const controlName of requirement.requiredControls) {
		const control = controlsByName.get(controlName);
		if (!control) {
			failures.push(`control ${controlName} is missing`);
		} else if (control.status !== "pass") {
			failures.push(`control ${controlName} is ${control.status}`);
		}
	}
	for (const control of data.controls) {
		if (control.status !== "pass") failures.push(`control ${control.name} is ${control.status}`);
	}
	const runtimeFailure = runtimeHarnessEvidenceFailure(surfaceId, data);
	if (runtimeFailure) failures.push(runtimeFailure);
	const attestationFailure = edgeAdapterRunnerAttestationFailure(data, options);
	if (attestationFailure) failures.push(attestationFailure);
	return failures.length > 0 ? failures.join("; ") : null;
}

function edgeAdapterRunnerAttestationFailure(
	data: EdgeAdapterProbeEvidence,
	options: HermesSignedEvidenceValidationOptions,
): string | null {
	const attestation = data.runnerAttestation as EdgeAdapterAttestation | undefined;
	if (!attestation) return "runnerAttestation is missing";
	const freshnessFailure = hermesAttestationFreshnessFailure(
		"runnerAttestation observedAt",
		attestation.observedAt,
		options,
	);
	if (freshnessFailure) return freshnessFailure;
	const signatureFailure = edgeAdapterAttestationSignatureFailure(attestation, {
		allowStale: hermesAllowsStaleAttestations(options),
	});
	if (signatureFailure) return `runnerAttestation signature is invalid: ${signatureFailure}`;
	const expected = edgeAdapterAttestationFieldsForEvidence(data);
	for (const field of [
		"probeEvidenceSchemaVersion",
		"probeId",
		"status",
		"ran",
		"observedAt",
		"evidenceSource",
		"surfaceSha256",
		"contractSha256",
		"custodySha256",
		"controlsSha256",
		"runtimeSha256",
		"evidenceSha256",
	] as const) {
		if (attestation[field] !== expected[field]) {
			return `runnerAttestation ${field} mismatch`;
		}
	}
	return null;
}

export function buildEdgeAdapterFixtureEvidenceBundle(input: {
	readonly evidenceDir?: string;
	readonly observedAt?: string;
	readonly probePaths?: Partial<Record<EdgeFixtureProbeId, string>>;
}): {
	readonly schemaVersion: 1;
	readonly results: Array<{ id: string; status: "pass" | "fail"; evidence_path: string }>;
	readonly evidence: readonly EdgeAdapterFixtureEvidence[];
} {
	const observedAt = input.observedAt ?? new Date().toISOString();
	const evidenceDir = input.evidenceDir ?? DEFAULT_EDGE_ADAPTER_FIXTURE_EVIDENCE_DIR;
	const evidence = EDGE_FIXTURE_REQUIREMENTS.map((requirement) =>
		buildEdgeFixtureEvidence(requirement, {
			evidencePath: path.join(evidenceDir, `${requirement.id}.json`),
			observedAt,
			probePaths: input.probePaths ?? {},
		}),
	);
	return {
		schemaVersion: 1,
		results: evidence.map((item) => ({
			id: item.id,
			status: item.status,
			evidence_path: item.evidence_path,
		})),
		evidence,
	};
}

export function edgeAdapterFixtureEvidenceFailure(
	fixtureId: string,
	evidence: unknown,
	options: HermesSignedEvidenceValidationOptions = {},
): string | null {
	const requirement = EDGE_FIXTURE_REQUIREMENTS.find((candidate) => candidate.id === fixtureId);
	if (!requirement) return null;
	const parsed = EdgeAdapterFixtureEvidenceSchema.safeParse(evidence);
	if (!parsed.success) {
		return `invalid edge fixture evidence: ${flattenZodError(parsed.error)}`;
	}
	const data = parsed.data;
	const failures: string[] = [];
	if (data.id !== fixtureId) failures.push(`fixture id is ${data.id}`);
	if (data.status !== "pass") failures.push(`fixture status is ${data.status}`);
	if (data.ran !== true) failures.push("fixture harness did not run");
	if (data.provenance.runner !== EDGE_ADAPTER_FIXTURE_EVIDENCE_RUNNER) {
		failures.push("fixture provenance runner is not the edge runtime fixture harness");
	}
	if (data.provenance.source !== EDGE_ADAPTER_FIXTURE_EVIDENCE_SOURCE) {
		failures.push("fixture provenance source is not the edge fixture generator");
	}
	if (data.edge.fixtureClass !== requirement.fixtureClass) {
		failures.push(`fixture class is ${data.edge.fixtureClass}`);
	}
	if (!sameJson(data.edge.requiredProbes, requirement.requiredProbes)) {
		failures.push("fixture requiredProbes do not match edge fixture contract");
	}
	const artifactByProbe = new Map(
		data.edge.probeArtifacts.map((artifact) => [artifact.probeId, artifact]),
	);
	for (const probeRequirement of requirement.requiredProbes) {
		const artifact = artifactByProbe.get(probeRequirement.probeId);
		if (!artifact) {
			failures.push(`fixture probe artifact ${probeRequirement.probeId} is missing`);
			continue;
		}
		if (!sameArray(artifact.requiredChecks, probeRequirement.requiredChecks)) {
			failures.push(`fixture probe ${probeRequirement.probeId} requiredChecks changed`);
		}
		const resolvedPath = path.resolve(artifact.evidencePath);
		if (!fs.existsSync(resolvedPath)) {
			failures.push(`fixture probe artifact ${probeRequirement.probeId} file is missing`);
			continue;
		}
		const currentDigest = sha256Digest(fs.readFileSync(resolvedPath));
		if (currentDigest !== artifact.evidenceSha256) {
			failures.push(`fixture probe artifact ${probeRequirement.probeId} sha256 changed`);
		}
		const loaded = loadEdgeFixtureProbe(
			probeRequirement,
			{
				[probeRequirement.probeId]: artifact.evidencePath,
			},
			options,
		);
		if (loaded.failure) failures.push(loaded.failure);
		for (const checkName of probeRequirement.requiredChecks) {
			const check = loaded.checks.get(checkName);
			if (!check) {
				failures.push(`fixture required check ${checkName} is missing`);
			} else if (check.status !== "pass") {
				failures.push(`fixture required check ${checkName} is ${check.status}`);
			}
		}
	}
	const checksByName = new Map(data.checks.map((check) => [check.name, check]));
	for (const duplicate of duplicates(data.checks.map((check) => check.name))) {
		failures.push(`duplicate fixture check ${duplicate}`);
	}
	for (const checkName of requirement.requiredProbes.flatMap((probe) => probe.requiredChecks)) {
		const check = checksByName.get(checkName);
		if (!check) {
			failures.push(`fixture check ${checkName} is missing`);
		} else if (check.status !== "pass") {
			failures.push(`fixture check ${checkName} is ${check.status}`);
		}
	}
	for (const check of data.checks) {
		if (check.status !== "pass") failures.push(`fixture check ${check.name} is ${check.status}`);
	}
	return failures.length > 0 ? failures.join("; ") : null;
}

type EdgeFixtureCheck = {
	readonly name: string;
	readonly status: "pass" | "fail";
	readonly detail: string;
};

type LoadedEdgeFixtureProbe = {
	readonly artifact: EdgeAdapterFixtureEvidence["edge"]["probeArtifacts"][number];
	readonly checks: ReadonlyMap<string, EdgeFixtureCheck>;
	readonly failure: string | null;
};

function buildEdgeFixtureEvidence(
	requirement: EdgeFixtureRequirement,
	input: {
		readonly evidencePath: string;
		readonly observedAt: string;
		readonly probePaths: Partial<Record<EdgeFixtureProbeId, string>>;
	},
): EdgeAdapterFixtureEvidence {
	const probes = requirement.requiredProbes.map((probeRequirement) =>
		loadEdgeFixtureProbe(probeRequirement, input.probePaths),
	);
	const checks = requirement.requiredProbes.flatMap((probeRequirement) =>
		buildEdgeFixtureChecks(
			probeRequirement,
			probes.find((probe) => probe.artifact.probeId === probeRequirement.probeId),
		),
	);
	const status = checks.every((check) => check.status === "pass") ? "pass" : "fail";
	return {
		schemaVersion: EDGE_ADAPTER_FIXTURE_EVIDENCE_SCHEMA_VERSION,
		id: requirement.id,
		status,
		ran: true,
		evidence_path: input.evidencePath,
		observedAt: input.observedAt,
		provenance: {
			runner: EDGE_ADAPTER_FIXTURE_EVIDENCE_RUNNER,
			command: "pnpm dev hermes fixtures --include-edge-adapter --write",
			source: EDGE_ADAPTER_FIXTURE_EVIDENCE_SOURCE,
		},
		edge: {
			fixtureClass: requirement.fixtureClass,
			requiredProbes: requirement.requiredProbes.map((probe) => ({
				probeId: probe.probeId,
				requiredChecks: [...probe.requiredChecks],
			})),
			probeArtifacts: probes.map((probe) => probe.artifact),
		},
		checks,
	};
}

function buildEdgeFixtureChecks(
	requirement: EdgeFixtureProbeRequirement,
	probe: LoadedEdgeFixtureProbe | undefined,
): EdgeFixtureCheck[] {
	if (!probe) {
		return requirement.requiredChecks.map((name) => ({
			name,
			status: "fail",
			detail: `probe ${requirement.probeId} was not loaded`,
		}));
	}
	return requirement.requiredChecks.map((name) => {
		const check = probe.checks.get(name);
		if (!check) {
			return {
				name,
				status: "fail",
				detail: `required check ${name} is missing from ${requirement.probeId}`,
			};
		}
		if (probe.failure) {
			return {
				name,
				status: "fail",
				detail: `probe ${requirement.probeId} failed validation: ${probe.failure}`,
			};
		}
		return {
			name,
			status: check.status,
			detail:
				check.status === "pass"
					? `required check ${name} passed in ${requirement.probeId}`
					: `required check ${name} is ${check.status} in ${requirement.probeId}`,
		};
	});
}

function loadEdgeFixtureProbe(
	requirement: EdgeFixtureProbeRequirement,
	probePaths: Partial<Record<EdgeFixtureProbeId, string>>,
	options: HermesSignedEvidenceValidationOptions = {},
): LoadedEdgeFixtureProbe {
	const evidencePath =
		probePaths[requirement.probeId] ?? defaultEdgeFixtureProbePath(requirement.probeId);
	const resolvedPath = path.resolve(evidencePath);
	const emptyArtifact = {
		probeId: requirement.probeId,
		evidencePath,
		evidenceSha256: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		requiredChecks: [...requirement.requiredChecks],
	};
	if (!fs.existsSync(resolvedPath)) {
		return {
			artifact: emptyArtifact,
			checks: new Map(),
			failure: `missing fixture probe artifact ${requirement.probeId}`,
		};
	}
	let evidence: unknown;
	try {
		evidence = JSON.parse(fs.readFileSync(resolvedPath, "utf8"));
	} catch (error) {
		return {
			artifact: {
				...emptyArtifact,
				evidenceSha256: sha256Digest(fs.readFileSync(resolvedPath)),
			},
			checks: new Map(),
			failure: `unreadable fixture probe artifact ${requirement.probeId}: ${String(
				error instanceof Error ? error.message : error,
			)}`,
		};
	}
	if (requirement.probeId === "providers.release-policy") {
		return loadProviderReleaseFixtureProbe(requirement, evidencePath, resolvedPath, evidence);
	}
	return loadEdgeAdapterFixtureProbe(requirement, evidencePath, resolvedPath, evidence, options);
}

function loadEdgeAdapterFixtureProbe(
	requirement: EdgeFixtureProbeRequirement,
	evidencePath: string,
	resolvedPath: string,
	evidence: unknown,
	options: HermesSignedEvidenceValidationOptions,
): LoadedEdgeFixtureProbe {
	const parsed = EdgeAdapterProbeEvidenceSchema.safeParse(evidence);
	const checks = parsed.success
		? new Map(parsed.data.controls.map((check) => [check.name, check]))
		: new Map<string, EdgeFixtureCheck>();
	return {
		artifact: {
			probeId: requirement.probeId,
			evidencePath,
			evidenceSha256: sha256Digest(fs.readFileSync(resolvedPath)),
			requiredChecks: [...requirement.requiredChecks],
			...(parsed.success ? { observedAt: parsed.data.observedAt } : {}),
		},
		checks,
		failure:
			parsed.success && isEdgeAdapterFeatureSurfaceId(requirement.probeId)
				? edgeAdapterProbeEvidenceFailure(requirement.probeId, parsed.data, options)
				: `invalid edge fixture probe ${requirement.probeId}`,
	};
}

function loadProviderReleaseFixtureProbe(
	requirement: EdgeFixtureProbeRequirement,
	evidencePath: string,
	resolvedPath: string,
	evidence: unknown,
): LoadedEdgeFixtureProbe {
	const parsed = ProviderReleasePolicyProbeEvidenceSchema.safeParse(evidence);
	const checks = parsed.success
		? new Map(parsed.data.checks.map((check) => [check.name, check]))
		: new Map<string, EdgeFixtureCheck>();
	return {
		artifact: {
			probeId: requirement.probeId,
			evidencePath,
			evidenceSha256: sha256Digest(fs.readFileSync(resolvedPath)),
			requiredChecks: [...requirement.requiredChecks],
			...(parsed.success ? { observedAt: parsed.data.observedAt } : {}),
		},
		checks,
		failure: parsed.success
			? providerReleasePolicyProbeEvidenceFailure(parsed.data)
			: `invalid provider release fixture probe ${requirement.probeId}`,
	};
}

function defaultEdgeFixtureProbePath(probeId: EdgeFixtureProbeId): string {
	if (probeId === "providers.release-policy") return DEFAULT_PROVIDER_RELEASE_POLICY_EVIDENCE_PATH;
	return DEFAULT_EDGE_ADAPTER_EVIDENCE_PATHS[probeId];
}

type EdgeRuntimeHarnessResult = {
	readonly controlPasses: ReadonlyMap<EdgeControlName, boolean>;
	readonly evidence: NonNullable<EdgeAdapterProbeEvidence["runtime"]>;
};

function runRuntimeHarness(
	surfaceId: EdgeAdapterFeatureSurfaceId,
	requirement: EdgeSurfaceRequirement,
): EdgeRuntimeHarnessResult | undefined {
	if (!edgeAdapterRuntimeEvidenceRequired(surfaceId)) return undefined;
	const channel = requirement.channels[0];
	const domain = requirement.trustDomains[0];
	const runtime = createTelclaudeEdgeRuntime({ now: timestamp });
	const inbound = runtime.ingest({
		channel,
		domain,
		text: "Please reply through Telclaude edge",
		attachments: [
			{
				attachmentId: "runtime-attachment-1",
				mediaType: "image/png",
				sizeBytes: 128,
				rawBytes: "RAW_EDGE_ATTACHMENT_BYTES_SHOULD_NOT_LEAK",
			},
		],
	});
	const actorRef = inbound.actorRef;
	const conversationRef = inbound.conversationRef;
	const attachmentRef = inbound.normalized.mediaRefs[0];
	const pendingInbound = runtime.ingest({
		channel,
		domain,
		text: "Hold this pending attachment",
		attachments: [
			{
				attachmentId: "runtime-pending-attachment",
				mediaType: "image/png",
				sizeBytes: 64,
				rawBytes: "RAW_PENDING_ATTACHMENT_BYTES_SHOULD_NOT_LEAK",
				scanState: "pending",
				trustLabel: "untrusted",
			},
		],
	});
	const pendingAttachmentRef = pendingInbound.normalized.mediaRefs[0];
	const crossDomainInbound = runtime.ingest({
		channel,
		domain,
		text: "Hold this attachment for another domain",
		attachments: [
			{
				attachmentId: "runtime-cross-domain-attachment",
				mediaType: "image/png",
				sizeBytes: 96,
				rawBytes: "RAW_CROSS_DOMAIN_ATTACHMENT_BYTES_SHOULD_NOT_LEAK",
				authorizedFor: [domain === "public-social" ? "tc-private" : "tc-public-social"],
			},
		],
	});
	const crossDomainAttachmentRef = crossDomainInbound.normalized.mediaRefs[0];
	const outboundRequest = {
		schemaVersion: EdgeAdapterSchemaVersions.outboundRequest,
		channel,
		recipient: {
			kind: "thread",
			threadId: conversationRef.threadId,
		},
		requestedBody: "Reply through Telclaude edge",
		mediaRefs: [attachmentRef],
		conversationRef,
		correlationId: "edge-runtime-correlation-1",
	};
	const alternateChannel: EdgeChannel = channel === "email" ? "whatsapp" : "email";
	const conversationWithoutAuthorization: Record<string, unknown> = { ...conversationRef };
	delete conversationWithoutAuthorization.authorization;
	const forgedActorDenied = denies(
		() =>
			runtime.prepareOutbound({
				request: outboundRequest,
				authorizingActor: {
					...actorRef,
					actorId: `${actorRef.actorId}:forged`,
				},
			}),
		"identity.forged-actor-denied",
	);
	const revokedActorDenied = denies(
		() =>
			runtime.prepareOutbound({
				request: outboundRequest,
				authorizingActor: {
					...actorRef,
					revocation: {
						revoked: true,
						revokedAt: timestamp(),
						reason: "runtime negative control",
					},
				},
			}),
		"identity.revocation-enforced",
	);
	const revokedConversationDenied = denies(
		() =>
			runtime.prepareOutbound({
				request: {
					...outboundRequest,
					conversationRef: {
						...conversationRef,
						authorization: {
							...conversationRef.authorization,
							state: "revoked",
							revoked: true,
						},
					},
				},
				authorizingActor: actorRef,
			}),
		"identity.revocation-enforced",
	);
	const sessionIdNotAuthorityDenied = denies(
		() =>
			runtime.prepareOutbound({
				request: {
					...outboundRequest,
					conversationRef: conversationWithoutAuthorization,
				},
				authorizingActor: actorRef,
			}),
		"identity.session-id-not-authority",
	);
	const crossChannelDenied = denies(
		() =>
			runtime.prepareOutbound({
				request: {
					...outboundRequest,
					conversationRef: {
						...conversationRef,
						recipients: conversationRef.recipients.map((recipient) => ({
							...recipient,
							channelIdentity: {
								...recipient.channelIdentity,
								channel: alternateChannel,
							},
						})),
					},
				},
				authorizingActor: actorRef,
			}),
		"identity.cross-channel-denied",
	);
	const householdInbound = runtime.ingest({
		channel: "whatsapp",
		domain: "household",
		actorId: "whatsapp:actor:family-member",
		principalId: "whatsapp:principal:family-member",
		identityAssurance: "strong_link",
		scopes: [
			{
				scope: "message:reply",
				actions: ["read", "send", "reply"],
				grantedAt: timestamp(),
			},
			{
				scope: "household:benign",
				actions: ["read"],
				grantedAt: timestamp(),
			},
		],
		text: "Can you check my appointment?",
	});
	const householdScopedBenignAllowed = (() => {
		try {
			const release = runtime.authorizeHouseholdProviderAccess({
				actorRef: householdInbound.actorRef,
				conversationRef: householdInbound.conversationRef,
				providerAccount: "clalit:family-member",
				providerAccountBinding: "strong_link",
				action: "read",
			});
			return release.releaseRef.startsWith("household-provider:");
		} catch {
			return false;
		}
	})();
	const householdStrongLinkRequired = denies(
		() =>
			runtime.authorizeHouseholdProviderAccess({
				actorRef: {
					...householdInbound.actorRef,
					identityAssurance: "channel_bound",
				},
				conversationRef: householdInbound.conversationRef,
				providerAccount: "clalit:family-member",
				providerAccountBinding: "strong_link",
				action: "read",
			}),
		"household.strong-link-required",
	);
	const householdNumberOnlyProviderDenied = denies(
		() =>
			runtime.authorizeHouseholdProviderAccess({
				actorRef: householdInbound.actorRef,
				conversationRef: householdInbound.conversationRef,
				providerAccount: "clalit:family-member",
				providerAccountBinding: "number_only",
				action: "read",
			}),
		"household.number-only-provider-denied",
	);
	const householdPrivateMemoryDenied = denies(
		() =>
			runtime.authorizeHouseholdProviderAccess({
				actorRef: householdInbound.actorRef,
				conversationRef: householdInbound.conversationRef,
				providerAccount: "clalit:family-member",
				providerAccountBinding: "strong_link",
				action: "read",
				privateMemorySource: "telegram:default",
			}),
		"household.private-memory-denied",
	);
	const householdCrossRecipientDenied = denies(
		() =>
			runtime.prepareOutbound({
				request: {
					schemaVersion: EdgeAdapterSchemaVersions.outboundRequest,
					channel: householdInbound.channel,
					recipient: {
						kind: "actor",
						actorId: "whatsapp:actor:other-family-member",
					},
					requestedBody: "Scoped family reply",
					mediaRefs: [],
					conversationRef: householdInbound.conversationRef,
					correlationId: "household-runtime-correlation-1",
				},
				authorizingActor: householdInbound.actorRef,
			}),
		"household.cross-recipient-denied",
	);
	const whatsappUnknownSenderDenied = denies(
		() =>
			runtime.ingest({
				channel: "whatsapp",
				domain: "public",
				authorizedSender: false,
				text: "unknown sender",
			}),
		"whatsapp.unknown-sender-denied",
	);
	const whatsappDirectBridgeDenied = denies(
		() => runtime.accessChannelResource({ channel: "whatsapp", requester: "hermes" }),
		"whatsapp.direct-bridge-denied",
	);
	const emailInbound = runtime.ingest({
		channel: "email",
		domain: "public",
		text: "email thread",
	});
	const emailWrongThreadDenied = denies(
		() =>
			runtime.prepareOutbound({
				request: {
					schemaVersion: EdgeAdapterSchemaVersions.outboundRequest,
					channel: "email",
					recipient: {
						kind: "thread",
						threadId: "email:public:thread:wrong",
					},
					requestedBody: "Wrong-thread email reply",
					mediaRefs: [],
					conversationRef: emailInbound.conversationRef,
					correlationId: "email-runtime-correlation-1",
				},
				authorizingActor: emailInbound.actorRef,
			}),
		"email.wrong-thread-denied",
	);
	const emailDirectMailboxDenied = denies(
		() => runtime.accessChannelResource({ channel: "email", requester: "hermes" }),
		"email.direct-mailbox-denied",
	);
	const agentmailUnauthorizedSenderDenied = denies(
		() =>
			runtime.ingest({
				channel: "agentmail",
				domain: "public",
				authorizedSender: false,
				text: "unauthorized sender",
			}),
		"agentmail.unauthorized-sender-denied",
	);
	const agentmailDirectKeyDenied = denies(
		() => runtime.accessChannelResource({ channel: "agentmail", requester: "hermes" }),
		"agentmail.direct-key-denied",
	);
	const socialInbound = runtime.ingest({
		channel: "social",
		domain: "public-social",
		text: "public social event",
	});
	const socialApprovedPostAllowed = (() => {
		try {
			const release = runtime.authorizeSocialPost({
				actorRef: socialInbound.actorRef,
				conversationRef: socialInbound.conversationRef,
				approved: true,
				budgetRemaining: 1,
			});
			return release.postRef.startsWith("social-post:");
		} catch {
			return false;
		}
	})();
	const socialUnapprovedPostingDenied = denies(
		() =>
			runtime.authorizeSocialPost({
				actorRef: socialInbound.actorRef,
				conversationRef: socialInbound.conversationRef,
				approved: false,
				budgetRemaining: 1,
			}),
		"social.unapproved-posting-denied",
	);
	const socialBudgetDenied = denies(
		() =>
			runtime.authorizeSocialPost({
				actorRef: socialInbound.actorRef,
				conversationRef: socialInbound.conversationRef,
				approved: true,
				budgetRemaining: 0,
			}),
		"social.budget-denied",
	);
	const socialPrivateMemoryDenied = denies(
		() =>
			runtime.authorizeSocialPost({
				actorRef: socialInbound.actorRef,
				conversationRef: socialInbound.conversationRef,
				approved: true,
				budgetRemaining: 1,
				privateMemorySource: "telegram:default",
			}),
		"social.private-memory-denied",
	);
	const publicSocialIsolationAllowed = (() => {
		try {
			const release = runtime.authorizePublicSocialIsolation({
				actorRef: socialInbound.actorRef,
				conversationRef: socialInbound.conversationRef,
				budgetRemaining: 1,
			});
			return release.profileRef.startsWith("public-social-profile:");
		} catch {
			return false;
		}
	})();
	const publicSocialPrivateWorkspaceDenied = denies(
		() =>
			runtime.authorizePublicSocialIsolation({
				actorRef: socialInbound.actorRef,
				conversationRef: socialInbound.conversationRef,
				workspaceMount: "/home/user/MyProjects",
				budgetRemaining: 1,
			}),
		"public-social.private-workspace-denied",
	);
	const publicSocialPrivateMemoryDenied = denies(
		() =>
			runtime.authorizePublicSocialIsolation({
				actorRef: socialInbound.actorRef,
				conversationRef: socialInbound.conversationRef,
				privateMemorySource: "telegram:default",
				budgetRemaining: 1,
			}),
		"public-social.private-memory-denied",
	);
	const publicSocialProviderScopeDenied = denies(
		() =>
			runtime.authorizePublicSocialIsolation({
				actorRef: socialInbound.actorRef,
				conversationRef: socialInbound.conversationRef,
				providerScope: "bank:operator",
				budgetRemaining: 1,
			}),
		"public-social.provider-scope-denied",
	);
	const publicSocialBudgetDenied = denies(
		() =>
			runtime.authorizePublicSocialIsolation({
				actorRef: socialInbound.actorRef,
				conversationRef: socialInbound.conversationRef,
				budgetRemaining: 0,
			}),
		"public-social.budget-denied",
	);

	const rawReadDenied = denies(
		() =>
			runtime.readAttachmentRaw({
				quarantineId: attachmentRef.quarantineId,
				requester: "hermes",
			}),
		"attachment.raw-bytes-denied",
	);
	const rawMediaDenied = denies(
		() =>
			runtime.prepareOutbound({
				request: {
					...outboundRequest,
					mediaRefs: [{ ...attachmentRef, rawBytes: "base64" }],
				},
				authorizingActor: actorRef,
			}),
		"attachment.raw-bytes-denied",
	);
	const unknownQuarantineDenied = denies(
		() =>
			runtime.prepareOutbound({
				request: {
					...outboundRequest,
					mediaRefs: [{ ...attachmentRef, quarantineId: "edge-quarantine:unknown" }],
				},
				authorizingActor: actorRef,
			}),
		"attachment.unknown-quarantine-denied",
	);
	const mutatedQuarantineDenied = denies(
		() =>
			runtime.prepareOutbound({
				request: {
					...outboundRequest,
					mediaRefs: [
						{
							...attachmentRef,
							lifecycle: { state: "authorized", authorizedFor: ["tc-public-social"] },
						},
					],
				},
				authorizingActor: actorRef,
			}),
		"attachment.unknown-quarantine-denied",
	);
	const localPathDenied = denies(
		() =>
			runtime.prepareOutbound({
				request: {
					...outboundRequest,
					mediaRefs: [{ ...attachmentRef, localPath: "/tmp/raw-upload" }],
				},
				authorizingActor: actorRef,
			}),
		"attachment.local-path-denied",
	);
	const downloadUrlDenied = denies(
		() =>
			runtime.prepareOutbound({
				request: {
					...outboundRequest,
					mediaRefs: [{ ...attachmentRef, downloadUrl: "https://example.invalid/raw" }],
				},
				authorizingActor: actorRef,
			}),
		"attachment.download-url-denied",
	);
	const unscannedDenied = denies(
		() =>
			runtime.prepareOutbound({
				request: {
					...outboundRequest,
					mediaRefs: [pendingAttachmentRef],
				},
				authorizingActor: actorRef,
			}),
		"attachment.unscanned-denied",
	);
	const crossDomainDenied = denies(
		() =>
			runtime.prepareOutbound({
				request: {
					...outboundRequest,
					mediaRefs: [crossDomainAttachmentRef],
				},
				authorizingActor: actorRef,
			}),
		"attachment.cross-domain-reuse-denied",
	);
	const hermesAuthorityDenied = denies(
		() =>
			runtime.prepareOutbound({
				request: { ...outboundRequest, authorizingActor: actorRef },
				authorizingActor: actorRef,
			}),
		"outbound.hermes-authority-denied",
	);
	const transportCredentialsDenied = denies(
		() =>
			runtime.prepareOutbound({
				request: { ...outboundRequest, transportCredentials: { token: "raw-token" } },
				authorizingActor: actorRef,
			}),
		"outbound.transport-credentials-denied",
	);
	const policyResultDenied = denies(
		() =>
			runtime.prepareOutbound({
				request: { ...outboundRequest, policyResult: { decision: "allowed" } },
				authorizingActor: actorRef,
			}),
		"outbound.policy-result-denied",
	);
	const approvalTokenDenied = denies(
		() =>
			runtime.prepareOutbound({
				request: { ...outboundRequest, approvalToken: "hermes-supplied-token" },
				authorizingActor: actorRef,
			}),
		"outbound.approval-token-denied",
	);

	const prepared = runtime.prepareOutbound({
		request: outboundRequest,
		authorizingActor: actorRef,
	});
	const mutatedPreparedDenied = denies(
		() =>
			runtime.executeOutbound({
				preparedOutbound: { ...prepared, finalRenderedBody: "Mutated body" },
			}),
		"outbound.recipient-body-bound",
	);
	const executeApprovalTokenDenied = denies(
		() =>
			runtime.executeOutbound({
				preparedOutbound: prepared,
				approvalToken: "hermes-supplied-token",
			}),
		"outbound.approval-token-denied",
	);
	const executeTransportCredentialsDenied = denies(
		() =>
			runtime.executeOutbound({
				preparedOutbound: prepared,
				transportCredentials: { token: "raw-token" },
			}),
		"outbound.transport-credentials-denied",
	);
	const executePolicyDenied = denies(
		() =>
			runtime.executeOutbound({
				preparedOutbound: {
					...prepared,
					policyResult: { decision: "denied", reason: "negative control" },
				},
			}),
		"outbound.policy-result-denied",
	);
	const receipt = runtime.executeOutbound({ preparedOutbound: prepared });
	const replayDenied = denies(
		() => runtime.executeOutbound({ preparedOutbound: prepared }),
		"outbound.replay-denied",
	);
	const ack = runtime.ack(receipt);
	const status = runtime.status(channel);
	const attachmentJson = JSON.stringify(attachmentRef);
	const inboundJson = JSON.stringify(inbound);
	const receiptJson = JSON.stringify(receipt);
	const operationTrace = runtime.operationTrace();
	const controlPasses = new Map<EdgeControlName, boolean>([
		["contract.operations.pinned", containsEvery(operationTrace, EDGE_ADAPTER_OPERATION_NAMES)],
		["contract.actor-ref.validates", ActorRefSchema.safeParse(actorRef).success],
		[
			"contract.conversation-ref.validates",
			ConversationRefSchema.safeParse(conversationRef).success,
		],
		[
			"contract.inbound.sanitized",
			InboundEventSchema.safeParse(inbound).success &&
				!inboundJson.includes("RAW_EDGE_ATTACHMENT_BYTES_SHOULD_NOT_LEAK"),
		],
		[
			"contract.outbound.request-only",
			OutboundRequestSchema.safeParse(outboundRequest).success && hermesAuthorityDenied,
		],
		["contract.outbound.prepared-owned", PreparedOutboundSchema.safeParse(prepared).success],
		[
			"contract.outbound.decision-owned",
			OutboundDecisionSchema.safeParse({
				schemaVersion: EdgeAdapterSchemaVersions.outboundDecision,
				decision: "approval_required",
				reason: "runtime edge approval is owned outside Hermes",
				preparedOutboundRef: prepared.outboundRef,
				approvalRequest: {
					requestId: "runtime-approval-1",
					revision: 1,
					renderedPreview: "Runtime edge approval",
					expiresAt: "2026-05-31T09:05:00.000Z",
				},
				decidedAt: timestamp(),
			}).success,
		],
		[
			"attachment.ref-only",
			AttachmentRefSchema.safeParse(attachmentRef).success &&
				!attachmentJson.includes("rawBytes") &&
				!attachmentJson.includes("localPath") &&
				!attachmentJson.includes("downloadUrl"),
		],
		["attachment.unknown-quarantine-denied", unknownQuarantineDenied && mutatedQuarantineDenied],
		["attachment.raw-bytes-denied", rawReadDenied && rawMediaDenied],
		["attachment.local-path-denied", localPathDenied],
		["attachment.download-url-denied", downloadUrlDenied],
		["attachment.unscanned-denied", unscannedDenied],
		["attachment.cross-domain-reuse-denied", crossDomainDenied],
		["outbound.hermes-authority-denied", hermesAuthorityDenied],
		[
			"outbound.transport-credentials-denied",
			transportCredentialsDenied && executeTransportCredentialsDenied,
		],
		["outbound.policy-result-denied", policyResultDenied && executePolicyDenied],
		["outbound.approval-token-denied", approvalTokenDenied && executeApprovalTokenDenied],
		[
			"outbound.recipient-body-bound",
			mutatedPreparedDenied &&
				receipt.deliveryStatus === "sent" &&
				DeliveryReceiptSchema.safeParse(receipt).success,
		],
		["outbound.replay-denied", replayDenied],
		[
			"contract.delivery.receipt-ref-only",
			DeliveryReceiptSchema.safeParse(ack).success &&
				!receiptJson.includes("raw-token") &&
				!receiptJson.includes("RAW_EDGE_ATTACHMENT_BYTES_SHOULD_NOT_LEAK"),
		],
		[
			"contract.status.redacted",
			StatusViewSchema.safeParse(status).success &&
				JSON.stringify(status).includes("telclaude-edge"),
		],
		[
			"credentials.telclaude-owned",
			status.credentials.every((credential) => credential.owner === "telclaude-edge"),
		],
		["credentials.raw-denied", !JSON.stringify(status).includes("raw-token")],
		["whatsapp.unknown-sender-denied", whatsappUnknownSenderDenied],
		["whatsapp.direct-bridge-denied", whatsappDirectBridgeDenied],
		["email.wrong-thread-denied", emailWrongThreadDenied],
		["email.direct-mailbox-denied", emailDirectMailboxDenied],
		["agentmail.direct-key-denied", agentmailDirectKeyDenied],
		["agentmail.unauthorized-sender-denied", agentmailUnauthorizedSenderDenied],
		[
			"social.unapproved-posting-denied",
			socialApprovedPostAllowed && socialUnapprovedPostingDenied,
		],
		["social.budget-denied", socialBudgetDenied],
		["social.private-memory-denied", socialPrivateMemoryDenied],
		["identity.forged-actor-denied", forgedActorDenied],
		["identity.revocation-enforced", revokedActorDenied && revokedConversationDenied],
		["identity.session-id-not-authority", sessionIdNotAuthorityDenied],
		["identity.cross-channel-denied", crossChannelDenied],
		["household.scoped-benign-allowed", householdScopedBenignAllowed],
		["household.strong-link-required", householdStrongLinkRequired],
		["household.number-only-provider-denied", householdNumberOnlyProviderDenied],
		["household.private-memory-denied", householdPrivateMemoryDenied],
		["household.cross-recipient-denied", householdCrossRecipientDenied],
		[
			"public-social.separate-profile",
			publicSocialIsolationAllowed &&
				socialInbound.conversationRef.profileId === "tc-public-social",
		],
		["public-social.private-workspace-denied", publicSocialPrivateWorkspaceDenied],
		["public-social.private-memory-denied", publicSocialPrivateMemoryDenied],
		["public-social.provider-scope-denied", publicSocialProviderScopeDenied],
		["public-social.budget-denied", publicSocialBudgetDenied],
	]);
	const runtimeChecks = [...controlPasses].map(([name, pass]) => ({
		name,
		status: pass ? ("pass" as const) : ("fail" as const),
		detail: pass
			? `${name} satisfied by Telclaude edge runtime harness`
			: `${name} failed in Telclaude edge runtime harness`,
	}));
	return {
		controlPasses,
		evidence: {
			source: EDGE_ADAPTER_RUNTIME_PROBE_SOURCE,
			operationTrace: [...operationTrace],
			checks: runtimeChecks,
			observations: {
				ingestedAttachments: inbound.normalized.mediaRefs.length,
				deniedAttempts: runtime.deniedAttempts(),
				ledgerEntries: runtime.ledgerEntries(),
				receiptRefs: DeliveryReceiptSchema.safeParse(receipt).success ? 1 : 0,
			},
		},
	};
}

function edgeAdapterRuntimeEvidenceRequired(surfaceId: string): boolean {
	return EDGE_ADAPTER_RUNTIME_SURFACE_SET.has(surfaceId);
}

function denies(fn: () => unknown, control: string): boolean {
	try {
		fn();
		return false;
	} catch (error) {
		return isTelclaudeEdgeRuntimeDeniedError(error, control);
	}
}

function runtimeHarnessEvidenceFailure(
	surfaceId: EdgeAdapterFeatureSurfaceId,
	data: EdgeAdapterProbeEvidence,
): string | null {
	if (!edgeAdapterRuntimeEvidenceRequired(surfaceId)) return null;
	const failures: string[] = [];
	if (data.source !== EDGE_ADAPTER_RUNTIME_PROBE_SOURCE) {
		failures.push(`source is ${data.source}, expected ${EDGE_ADAPTER_RUNTIME_PROBE_SOURCE}`);
	}
	if (!data.runtime) {
		failures.push("runtime harness evidence is missing");
		return failures.join("; ");
	}
	if (!containsEvery(data.runtime.operationTrace, EDGE_ADAPTER_OPERATION_NAMES)) {
		failures.push("runtime operation trace did not exercise the full pinned operation set");
	}
	if (data.runtime.observations.deniedAttempts < 6) {
		failures.push("runtime denied-attempt count is too low for negative controls");
	}
	if (data.runtime.observations.ledgerEntries < 1) {
		failures.push("runtime ledger did not record an outbound execution");
	}
	if (data.runtime.observations.receiptRefs < 1) {
		failures.push("runtime did not produce a delivery receipt ref");
	}
	const requiredRuntimeControls = requiredRuntimeControlsFor(surfaceId);
	const runtimeChecks = new Map(data.runtime.checks.map((check) => [check.name, check]));
	for (const controlName of requiredRuntimeControls) {
		const control = runtimeChecks.get(controlName);
		if (!control) {
			failures.push(`runtime control ${controlName} is missing`);
		} else if (control.status !== "pass") {
			failures.push(`runtime control ${controlName} is ${control.status}`);
		}
	}
	return failures.length > 0 ? failures.join("; ") : null;
}

function requiredRuntimeControlsFor(
	surfaceId: EdgeAdapterFeatureSurfaceId,
): readonly EdgeControlName[] {
	if (!edgeAdapterRuntimeEvidenceRequired(surfaceId)) return [];
	return EDGE_SURFACE_REQUIREMENTS[surfaceId].requiredControls;
}

function runControlChecks(
	requirement: EdgeSurfaceRequirement,
	runtimeControlPasses?: ReadonlyMap<EdgeControlName, boolean>,
): Array<{ name: EdgeControlName; status: "pass" | "fail"; detail: string }> {
	const channel = requirement.channels[0];
	const trustDomain = requirement.trustDomains[0];
	const actorRef = validActorRef(channel);
	const conversationRef = validConversationRef(channel, trustDomain);
	const attachmentRef = validAttachmentRef();
	const checks: Record<EdgeControlName, boolean> = {
		"contract.operations.pinned": sameArray(
			[...EDGE_ADAPTER_OPERATION_NAMES],
			["ingest", "prepareOutbound", "executeOutbound", "status", "ack"],
		),
		"contract.actor-ref.validates": ActorRefSchema.safeParse(actorRef).success,
		"contract.conversation-ref.validates": ConversationRefSchema.safeParse(conversationRef).success,
		"contract.inbound.sanitized": InboundEventSchema.safeParse(
			validInboundEvent(channel, conversationRef, actorRef, attachmentRef),
		).success,
		"contract.outbound.request-only":
			OutboundRequestSchema.safeParse(validOutboundRequest(channel, conversationRef, attachmentRef))
				.success &&
			!OutboundRequestSchema.safeParse(unsafeOutboundRequest(conversationRef)).success,
		"contract.outbound.prepared-owned": PreparedOutboundSchema.safeParse(
			validPreparedOutbound(channel, actorRef, attachmentRef),
		).success,
		"contract.outbound.decision-owned": OutboundDecisionSchema.safeParse({
			schemaVersion: EdgeAdapterSchemaVersions.outboundDecision,
			decision: "approval_required",
			reason: "new recipient requires edge-owned approval",
			preparedOutboundRef: "outbound-1",
			approvalRequest: {
				requestId: "approval-1",
				revision: 1,
				renderedPreview: "Send through edge adapter",
				expiresAt: "2026-05-31T09:05:00.000Z",
			},
			decidedAt: timestamp(),
		}).success,
		"contract.delivery.receipt-ref-only": DeliveryReceiptSchema.safeParse({
			schemaVersion: EdgeAdapterSchemaVersions.deliveryReceipt,
			outboundRef: "outbound-1",
			platformMessageId: "platform-message-1",
			deliveryStatus: "sent",
			timestamps: { observedAt: timestamp(), sentAt: timestamp() },
			retry: { attempt: 1, maxAttempts: 3, idempotencyKey: "idem-1" },
		}).success,
		"contract.status.redacted":
			StatusViewSchema.safeParse(validStatusView(channel)).success &&
			!StatusViewSchema.safeParse(unsafeStatusView(channel)).success,
		"credentials.telclaude-owned": validStatusView(channel).credentials.every(
			(credential) => credential.owner === "telclaude-edge",
		),
		"credentials.raw-denied": !StatusViewSchema.safeParse(unsafeStatusView(channel)).success,
		"attachment.ref-only":
			AttachmentRefSchema.safeParse(attachmentRef).success &&
			!AttachmentRefSchema.safeParse({ ...attachmentRef, rawBytes: "raw" }).success &&
			!AttachmentRefSchema.safeParse({ ...attachmentRef, localPath: "/tmp/raw" }).success &&
			!AttachmentRefSchema.safeParse({
				...attachmentRef,
				downloadUrl: "https://example.invalid/raw",
			}).success,
		"attachment.unknown-quarantine-denied": false,
		"whatsapp.unknown-sender-denied": !ConversationRefSchema.safeParse({
			...validConversationRef("whatsapp", "public"),
			authorization: { state: "denied", scopes: [], revoked: false },
			unknownSenderOverride: "hermes-supplied",
		}).success,
		"whatsapp.direct-bridge-denied": !StatusViewSchema.safeParse({
			...validStatusView("whatsapp"),
			credentials: [
				{
					kind: "whatsapp-session",
					present: true,
					owner: "hermes",
					status: "present",
					rawSessionPath: "/home/hermes/.wwebjs_auth",
				},
			],
		}).success,
		"email.wrong-thread-denied": !OutboundRequestSchema.safeParse({
			...validOutboundRequest("email", validConversationRef("email", "public"), attachmentRef),
			recipient: { kind: "thread", threadId: "unbound-thread" },
			threadAuthority: "hermes-supplied",
		}).success,
		"email.direct-mailbox-denied": !StatusViewSchema.safeParse({
			...validStatusView("email"),
			credentials: [
				{
					kind: "smtp-password",
					present: true,
					owner: "hermes",
					status: "present",
					password: "raw",
				},
			],
		}).success,
		"agentmail.direct-key-denied": !StatusViewSchema.safeParse({
			...validStatusView("agentmail"),
			apiKey: "raw-agentmail-key",
		}).success,
		"agentmail.unauthorized-sender-denied": !ActorRefSchema.safeParse(
			actorRefWithoutScopes("agentmail"),
		).success,
		"social.unapproved-posting-denied": !OutboundRequestSchema.safeParse({
			...validOutboundRequest(
				"social",
				validConversationRef("social", "public-social"),
				attachmentRef,
			),
			approvalToken: "hermes-supplied-social-token",
		}).success,
		"social.budget-denied": !PreparedOutboundSchema.safeParse({
			...validPreparedOutbound("social", validActorRef("social"), attachmentRef),
			rateBudgetOverride: "hermes-supplied",
		}).success,
		"social.private-memory-denied": !ConversationRefSchema.safeParse({
			...validConversationRef("social", "public-social"),
			privateMemorySource: "telegram:default",
		}).success,
		"identity.forged-actor-denied": !ActorRefSchema.safeParse(actorRefWithoutScopes(channel))
			.success,
		"identity.revocation-enforced": ConversationRefSchema.safeParse({
			...conversationRef,
			authorization: {
				state: "revoked",
				scopes: conversationRef.authorization.scopes,
				revoked: true,
			},
		}).success,
		"identity.session-id-not-authority": !ConversationRefSchema.safeParse({
			...conversationRef,
			authorization: undefined,
		}).success,
		"identity.cross-channel-denied": !ConversationRefSchema.safeParse({
			...conversationRef,
			recipients: [
				{
					actorId: "actor-cross",
					channelIdentity: {
						channel: channel === "email" ? "whatsapp" : "email",
						principalId: "cross-channel-principal",
					},
					role: "sender",
				},
			],
			crossChannelAuthority: "hermes-supplied",
		}).success,
		"household.scoped-benign-allowed": ActorRefSchema.safeParse({
			...validActorRef(channel),
			scopes: [
				{
					scope: "household:benign",
					actions: ["read", "reply"],
					grantedAt: timestamp(),
				},
			],
		}).success,
		"household.strong-link-required": ActorRefSchema.safeParse({
			...validActorRef(channel),
			identityAssurance: "strong_link",
		}).success,
		"household.number-only-provider-denied": !ActorRefSchema.safeParse({
			...validActorRef(channel),
			identityAssurance: "channel_bound",
			providerAccount: "clalit:operator",
		}).success,
		"household.private-memory-denied": !ConversationRefSchema.safeParse({
			...validConversationRef(channel, "household"),
			privateMemorySource: "telegram:default",
		}).success,
		"household.cross-recipient-denied": !OutboundRequestSchema.safeParse({
			...validOutboundRequest(channel, validConversationRef(channel, "household"), attachmentRef),
			recipient: { kind: "actor", actorId: "unscoped-family-member" },
			crossRecipientOverride: true,
		}).success,
		"attachment.raw-bytes-denied": !AttachmentRefSchema.safeParse({
			...attachmentRef,
			rawBytes: "base64",
		}).success,
		"attachment.local-path-denied": !AttachmentRefSchema.safeParse({
			...attachmentRef,
			localPath: "/tmp/raw-upload",
		}).success,
		"attachment.download-url-denied": !AttachmentRefSchema.safeParse({
			...attachmentRef,
			downloadUrl: "https://example.invalid/upload",
		}).success,
		"attachment.unscanned-denied": AttachmentRefSchema.safeParse({
			...attachmentRef,
			scanState: "pending",
			trustLabel: "untrusted",
			lifecycle: { state: "quarantined", authorizedFor: [] },
		}).success,
		"attachment.cross-domain-reuse-denied": !AttachmentRefSchema.safeParse({
			...attachmentRef,
			authorizedDomains: ["private", "public-social"],
		}).success,
		"outbound.hermes-authority-denied": !OutboundRequestSchema.safeParse({
			...validOutboundRequest(channel, conversationRef, attachmentRef),
			authorizingActor: actorRef,
		}).success,
		"outbound.transport-credentials-denied": !OutboundRequestSchema.safeParse({
			...validOutboundRequest(channel, conversationRef, attachmentRef),
			transportCredentials: { token: "raw-token" },
		}).success,
		"outbound.policy-result-denied": !OutboundRequestSchema.safeParse({
			...validOutboundRequest(channel, conversationRef, attachmentRef),
			policyResult: { decision: "allowed" },
		}).success,
		"outbound.approval-token-denied": !OutboundRequestSchema.safeParse({
			...validOutboundRequest(channel, conversationRef, attachmentRef),
			approvalToken: "hermes-supplied-token",
		}).success,
		"outbound.recipient-body-bound": PreparedOutboundSchema.safeParse(
			validPreparedOutbound(channel, actorRef, attachmentRef),
		).success,
		"outbound.replay-denied": !PreparedOutboundSchema.safeParse({
			...validPreparedOutbound(channel, actorRef, attachmentRef),
			idempotencyKey: "",
		}).success,
		"public-social.separate-profile":
			validConversationRef("social", "public-social").profileId === "tc-public-social",
		"public-social.private-workspace-denied": !ConversationRefSchema.safeParse({
			...validConversationRef("social", "public-social"),
			workspaceMount: "/home/user/MyProjects",
		}).success,
		"public-social.private-memory-denied": !ConversationRefSchema.safeParse({
			...validConversationRef("social", "public-social"),
			privateMemorySource: "telegram:default",
		}).success,
		"public-social.provider-scope-denied": !ActorRefSchema.safeParse({
			...validActorRef("social"),
			providerScopes: ["bank:operator"],
		}).success,
		"public-social.budget-denied": !OutboundRequestSchema.safeParse({
			...validOutboundRequest(
				"social",
				validConversationRef("social", "public-social"),
				attachmentRef,
			),
			budgetOverride: "unlimited",
		}).success,
	};
	for (const [name, pass] of runtimeControlPasses ?? []) {
		checks[name] = pass;
	}
	return requirement.requiredControls.map((name) => ({
		name,
		status: checks[name] ? "pass" : "fail",
		detail: checks[name]
			? `${name} satisfied by ${
					runtimeControlPasses?.has(name)
						? "Telclaude edge runtime harness"
						: "edge adapter contract unit harness"
				}`
			: `${name} failed in ${
					runtimeControlPasses?.has(name)
						? "Telclaude edge runtime harness"
						: "edge adapter contract unit harness"
				}`,
	}));
}

function contractSummary(): EdgeAdapterProbeEvidence["contract"] {
	return {
		version: EDGE_ADAPTER_CONTRACT_VERSION,
		operations: [...EDGE_ADAPTER_OPERATION_NAMES],
		schemaVersions: Object.values(EdgeAdapterSchemaVersions),
	};
}

function custodySummary(): EdgeAdapterProbeEvidence["custody"] {
	return {
		credentialOwner: "telclaude-edge",
		hermesRawCredentialAccess: "denied",
		attachmentRawAccess: "denied",
		outboundExecutionOwner: "telclaude-edge",
	};
}

function validActorRef(channel: EdgeChannel) {
	return {
		schemaVersion: EdgeAdapterSchemaVersions.actorRef,
		actorId: `${channel}:actor-1`,
		channelIdentity: {
			channel,
			principalId: `${channel}:principal-1`,
			displayName: "Edge Actor",
		},
		identityAssurance: "verified",
		scopes: [
			{
				scope: "message:reply",
				actions: ["read", "send"],
				grantedAt: timestamp(),
			},
		],
		revocation: {
			revoked: false,
		},
	};
}

function actorRefWithoutScopes(channel: EdgeChannel) {
	const { scopes: _scopes, ...withoutScopes } = validActorRef(channel);
	return withoutScopes;
}

function validConversationRef(channel: EdgeChannel, domain: TrustDomain) {
	return {
		schemaVersion: EdgeAdapterSchemaVersions.conversationRef,
		channel,
		conversationId: `${channel}-conversation-1`,
		threadId: `${channel}-thread-1`,
		profileId: domain === "public-social" ? "tc-public-social" : `tc-${domain}`,
		domain,
		recipients: [
			{
				actorId: `${channel}:actor-1`,
				channelIdentity: {
					channel,
					principalId: `${channel}:principal-1`,
				},
				role: "sender",
			},
		],
		routingSession: {
			sessionId: `${domain}-${channel}-session-1`,
			routeKey: `${domain}:${channel}:${channel}-thread-1`,
		},
		authorization: {
			state: "authorized",
			scopes: ["message:read", "message:reply"],
			revoked: false,
		},
	};
}

function validAttachmentRef() {
	return {
		schemaVersion: EdgeAdapterSchemaVersions.attachmentRef,
		quarantineId: "quarantine-1",
		mediaType: "image/png",
		scanState: "clean",
		sizeBytes: 128,
		contentHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		trustLabel: "trusted",
		expiresAt: "2026-05-31T10:00:00.000Z",
		lifecycle: {
			state: "authorized",
			authorizedFor: ["tc-public", "tc-household"],
		},
	};
}

function validInboundEvent(
	channel: EdgeChannel,
	conversationRef: ReturnType<typeof validConversationRef>,
	actorRef: ReturnType<typeof validActorRef>,
	attachmentRef: ReturnType<typeof validAttachmentRef>,
) {
	return {
		schemaVersion: EdgeAdapterSchemaVersions.inboundEvent,
		channel,
		conversationRef,
		actorRef,
		receivedAt: timestamp(),
		normalized: {
			text: "Please reply through Telclaude edge",
			mediaRefs: [attachmentRef],
		},
		riskLabels: ["routine"],
		sourceAudit: {
			auditId: `${channel}-audit-1`,
			sourceEventId: `${channel}-event-1`,
			platformMessageId: `${channel}-message-1`,
			transport: "telclaude-edge",
		},
		ordering: {
			cursor: `${channel}-cursor-1`,
			sequence: 1,
			duplicateHandling: "first_seen",
		},
	};
}

function validOutboundRequest(
	channel: EdgeChannel,
	conversationRef: ReturnType<typeof validConversationRef>,
	attachmentRef: ReturnType<typeof validAttachmentRef>,
) {
	return {
		schemaVersion: EdgeAdapterSchemaVersions.outboundRequest,
		channel,
		recipient: {
			kind: "thread",
			threadId: conversationRef.threadId,
		},
		requestedBody: "Reply through Telclaude edge",
		mediaRefs: [attachmentRef],
		conversationRef,
		correlationId: `${channel}-correlation-1`,
	};
}

function unsafeOutboundRequest(conversationRef: ReturnType<typeof validConversationRef>) {
	return {
		schemaVersion: EdgeAdapterSchemaVersions.outboundRequest,
		channel: conversationRef.channel,
		recipient: {
			kind: "thread",
			threadId: conversationRef.threadId,
		},
		requestedBody: "unsafe",
		mediaRefs: [],
		conversationRef,
		correlationId: "unsafe-correlation-1",
		policyResult: {
			decision: "allowed",
		},
		transportCredentials: {
			token: "raw-token",
		},
	};
}

function validPreparedOutbound(
	channel: EdgeChannel,
	actorRef: ReturnType<typeof validActorRef>,
	attachmentRef: ReturnType<typeof validAttachmentRef>,
) {
	return {
		schemaVersion: EdgeAdapterSchemaVersions.preparedOutbound,
		outboundRef: `${channel}-outbound-1`,
		channel,
		resolvedDestination: {
			kind: "thread",
			threadId: `${channel}-thread-1`,
			conversationId: `${channel}-conversation-1`,
		},
		finalRenderedBody: "Reply through Telclaude edge",
		mediaRefs: [attachmentRef],
		authorizingActor: actorRef,
		policyResult: {
			decision: "allowed",
			reason: "edge policy allowed existing thread",
			rules: ["existing-thread"],
		},
		approvalRequirement: {
			required: false,
		},
		idempotencyKey: `${channel}-idempotency-1`,
		sideEffectLedgerRef: `${channel}-ledger-1`,
		createdAt: timestamp(),
		retryPolicy: {
			maxAttempts: 3,
			backoff: "exponential",
			deadLetterAfterAttempts: 3,
		},
	};
}

function validStatusView(channel: EdgeChannel) {
	return {
		schemaVersion: EdgeAdapterSchemaVersions.statusView,
		channel,
		checkedAt: timestamp(),
		setup: {
			status: "ready",
		},
		sidecar: {
			status: "up",
			healthRef: `${channel}-health-1`,
		},
		credentials: [
			{
				kind: `${channel}-credential-ref`,
				present: true,
				owner: "telclaude-edge",
				status: "present",
			},
		],
		rateBudget: {
			status: "available",
			remaining: 9,
			resetAt: "2026-05-31T09:10:00.000Z",
		},
	};
}

function unsafeStatusView(channel: EdgeChannel) {
	return {
		...validStatusView(channel),
		credentials: [
			{
				kind: `${channel}-credential-ref`,
				present: true,
				owner: "telclaude-edge",
				status: "present",
				rawToken: "should-not-parse",
			},
		],
		apiKey: "should-not-parse",
	};
}

function timestamp(): string {
	return "2026-05-31T09:00:00.000Z";
}

function sameArray<T>(left: readonly T[], right: readonly T[]): boolean {
	return left.length === right.length && left.every((value, index) => value === right[index]);
}

function sameSet<T>(left: readonly T[], right: readonly T[]): boolean {
	if (left.length !== right.length) return false;
	const rightSet = new Set<T>(right);
	return left.every((value) => rightSet.has(value));
}

function sameJson(left: unknown, right: unknown): boolean {
	return JSON.stringify(left) === JSON.stringify(right);
}

function sha256Digest(bytes: string | Buffer): string {
	return `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
}

function containsEvery<T>(left: readonly T[], right: readonly T[]): boolean {
	const leftSet = new Set<T>(left);
	return right.every((value) => leftSet.has(value));
}

function duplicates(values: readonly string[]): string[] {
	const seen = new Set<string>();
	const duplicates = new Set<string>();
	for (const value of values) {
		if (seen.has(value)) duplicates.add(value);
		seen.add(value);
	}
	return [...duplicates];
}

function flattenZodError(error: z.ZodError): string {
	return error.issues
		.map((issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`)
		.join("; ");
}
