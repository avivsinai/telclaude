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
export const PRO_REVIEW_REQUEST_SCHEMA_VERSION = "telclaude.hermes.pro-review-request.v1";
export const PRO_REVIEW_NATIVE_CANARY_SCHEMA_VERSION =
	"telclaude.hermes.pro-review-native-canary.v1";
export const PRO_REVIEW_NATIVE_CANARY_MAX_AGE_MS = 15 * 60 * 1000;
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
const PRO_REVIEW_MODEL_RELAY_PROBE_PATH = "artifacts/hermes/probes/model-relay.json";
const PRO_REVIEW_KNOWN_PROBE_ARTIFACT_PATHS = new Set<string>([
	PRO_REVIEW_CLI_HEADLESS_PROBE_PATH,
	PRO_REVIEW_MODEL_RELAY_PROBE_PATH,
	...Object.keys(PRO_REVIEW_SIGNED_PROBE_PATHS),
	...Object.keys(PRO_REVIEW_BROWSER_COMPUTER_PROBE_PATHS),
	...Object.keys(PRO_REVIEW_PROVIDER_DOMAIN_PROBE_PATHS),
	PRO_REVIEW_GOOGLE_PROVIDER_PROBE_PATH,
	PRO_REVIEW_PROVIDER_RELEASE_POLICY_PROBE_PATH,
	PRO_REVIEW_SERVED_MCP_PROVIDER_TOOLS_PROBE_PATH,
]);
export const REQUIRED_PRO_REVIEW_FILES = [
	"CLAUDE.md",
	"SECURITY.md",
	"docs/architecture.md",
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
	"src/hermes/edge-adapter-contract.ts",
	"src/hermes/edge-adapter-runtime.ts",
	"src/hermes/edge-adapter-probes.ts",
	"src/hermes/edge-adapter-attestation.ts",
	"src/hermes/browser-computer-broker-attestation.ts",
	"src/hermes/browser-computer-broker-probes.ts",
	"src/hermes/private-runtime.ts",
	"src/hermes/foundation.ts",
	"src/hermes/model-relay.ts",
	"src/hermes/private-telegram-fixture-attestation.ts",
	"src/hermes/network-probe-schema.ts",
	"src/hermes/network-probe-attestation.ts",
	"src/hermes/no-fork-attestation.ts",
	"src/hermes/network-probes.ts",
	"src/hermes/provider-approval-binding-probe.ts",
	"src/hermes/provider-approval-binding-attestation.ts",
	"src/hermes/provider-domain-probes.ts",
	"src/hermes/provider-google-probe.ts",
	"src/hermes/provider-release-policy-probe.ts",
	"src/hermes/served-mcp-provider-tools-probe.ts",
	"src/hermes/workflow-probes.ts",
	"src/hermes/workflow-run-ledger.ts",
	"src/hermes/workflow-run-ledger-attestation.ts",
	"src/hermes/mcp/side-effect-ledger-probe.ts",
	"src/hermes/mcp/side-effect-ledger-attestation.ts",
	"src/hermes/mcp/provider-routing.ts",
	"src/hermes/mcp/side-effect-ledger.ts",
	"src/hermes/mcp/side-effect-human-approval.ts",
	"src/hermes/mcp/approval-token.ts",
	"src/hermes/mcp/ledger-execute.ts",
	"src/hermes/mcp/live-relay-clients.ts",
	"src/hermes/mcp/live-server.ts",
	"src/hermes/mcp/live-runtime.ts",
	"src/commands/hermes.ts",
	"src/relay/capabilities.ts",
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
	"artifacts/hermes/network/relay-control-allowed.json",
	"artifacts/hermes/network/direct-provider-denied.json",
	"artifacts/hermes/network/direct-vault-denied.json",
	"artifacts/hermes/network/direct-model-provider-denied.json",
	"artifacts/hermes/network/dns-exfil-denied.json",
	"artifacts/hermes/pro-review-native-canary.json",
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
	"tests/hermes/pro-review.test.ts",
	"tests/hermes/pro-review-semantic-artifacts.test.ts",
	"tests/hermes/mcp-side-effect-ledger-probe.test.ts",
	"tests/hermes/mcp-side-effect-human-approval.test.ts",
	"tests/hermes/mcp-ledger-execute.test.ts",
	"tests/hermes/mcp-live-relay-clients.test.ts",
	"tests/hermes/mcp-live-server.test.ts",
	"tests/commands/hermes.test.ts",
	"tests/relay/model-relay-peer-echo.test.ts",
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
				canonicalJsonFields: z.tuple([
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
				]),
				payloadSha256: Sha256DigestSchema,
				promptSha256: Sha256DigestSchema,
				selectedFilesSha256: Sha256DigestSchema,
				selectedFileContentsSha256: Sha256DigestSchema,
				transportEvidenceSha256: Sha256DigestSchema,
				notes: NonEmptyString,
			})
			.strict(),
		selectedFiles: z.array(NonEmptyString).min(1),
		blockedFallbacks: z.array(NonEmptyString),
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
		gates.push(...requestPolicyGates(request, requestPath, canaryPath, input.requireApproval));
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
	const existing = readOptionalProReviewRequest(input.existingRequestPath);
	const prompt = input.prompt ?? existing?.prompt;
	if (!prompt) {
		throw new Error("Pro review request refresh requires an existing request or --prompt.");
	}
	const transportEvidence =
		input.canaryPath ?? existing?.transportEvidence ?? DEFAULT_PRO_REVIEW_NATIVE_CANARY_PATH;
	const selectedFiles = uniqueStrings([
		...REQUIRED_PRO_REVIEW_FILES,
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
	};
}

function readOptionalProReviewRequest(requestPath: string | undefined): ProReviewRequest | null {
	const resolved = resolveHermesArtifactPath(requestPath ?? DEFAULT_PRO_REVIEW_REQUEST_PATH);
	if (!fs.existsSync(resolved)) return null;
	const raw = JSON.parse(fs.readFileSync(resolved, "utf8")) as unknown;
	return ProReviewRequestSchema.parse(raw);
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
	requireApproval: boolean | undefined,
): ProReviewGate[] {
	const gates: ProReviewGate[] = [];
	const requireGreenEvidence = requiresSendReadyProReviewEvidence(request, requireApproval);
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

	const missingRequiredFiles = REQUIRED_PRO_REVIEW_FILES.filter(
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
	gates.push(...semanticEvidenceGates(request, { requireGreenEvidence }));

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
			requireApproval
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
		path.basename(requestPath) === "pro-review-request.json"
			? pass("request.path", "request path is explicit")
			: pending("request.path", "request path is nonstandard but explicit"),
	);
	return gates;
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
	const selectedFileContentsSha256 = digestSelectedFileContents(request.selectedFiles);
	const transportEvidenceSha256 = digestFile(request.transportEvidence);
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
	};
	const expectedPayload = digestJson(payload);
	const expectedPrompt = digestText(request.prompt);
	const expectedSelectedFiles = digestJson(request.selectedFiles);
	if (request.payloadBinding.payloadSha256 !== expectedPayload) {
		failures.push(
			"payloadSha256 does not match review content, selected files, and native evidence",
		);
	}
	if (request.payloadBinding.promptSha256 !== expectedPrompt) {
		failures.push("promptSha256 does not match prompt");
	}
	if (request.payloadBinding.selectedFilesSha256 !== expectedSelectedFiles) {
		failures.push("selectedFilesSha256 does not match selectedFiles");
	}
	if (request.payloadBinding.selectedFileContentsSha256 !== selectedFileContentsSha256) {
		failures.push("selectedFileContentsSha256 does not match selected file contents");
	}
	if (request.payloadBinding.transportEvidenceSha256 !== transportEvidenceSha256) {
		failures.push("transportEvidenceSha256 does not match transport evidence file");
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
	options: { readonly requireGreenEvidence: boolean },
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

function isProReviewFixtureArtifactPath(file: string): boolean {
	return file.startsWith("artifacts/hermes/fixtures/") && file.endsWith(".json");
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
		if (requireGreenEvidence) {
			return fail(name, `${surfaceId} evidence is explicitly red and cannot be sent`);
		}
		return pass(name, `${surfaceId} evidence is explicitly red`);
	}
	const failure =
		surfaceId === "sideeffect.ledger"
			? sideEffectLedgerProbeEvidenceFailure(surfaceId, read.value, validationOptions)
			: surfaceId === "providers.approval-binding"
				? providerApprovalBindingProbeEvidenceFailure(read.value, validationOptions)
				: surfaceId === "workflow.cron" || surfaceId === "workflow.longrun"
					? workflowProbeEvidenceFailure(surfaceId, read.value, validationOptions)
					: edgeAdapterProbeEvidenceFailure(surfaceId, read.value, validationOptions);
	return failure
		? fail(name, `${surfaceId} pass evidence is not accepted by the current validator: ${failure}`)
		: pass(name, `${surfaceId} pass evidence passes current semantic validator`);
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
		live: "forbidden",
	});
}

function liveCanaryCommandFailures(command: string, expectedExtensionInstanceId: string): string[] {
	if (!command.startsWith("YOETZ_AGENT=1 yoetz browser extension canary --chatgpt")) {
		return ["live canary command is not the Yoetz extension live canary command"];
	}
	return nativeExtensionCommandShapeFailures(command, "live canary", expectedExtensionInstanceId, {
		allowedVerbs: ["canary"],
		live: "required",
	});
}

function nativeExtensionCommandShapeFailures(
	command: string,
	label: string,
	expectedExtensionInstanceId: string,
	options: {
		readonly allowedVerbs: readonly string[];
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
	if (!boundExtensionInstance) {
		failures.push(`${label} command does not bind an extension instance`);
	} else if (boundExtensionInstance !== expectedExtensionInstanceId) {
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

export function buildProReviewYoetzCommand(input: {
	readonly canary: ProReviewNativeCanary;
	readonly bundlePath: string;
	readonly payloadSha256?: string;
	readonly bundleSha256?: string;
}): string[] {
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
	];
	if (input.payloadSha256) {
		command.push("--var", `payload_sha256=${input.payloadSha256}`);
	}
	if (input.bundleSha256) {
		command.push("--var", `bundle_sha256=${input.bundleSha256}`);
	}
	return command;
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
	readonly expectedPayloadSha256?: string;
	readonly expectedBundleSha256?: string;
}): ProReviewYoetzSendValidation {
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
	const failures: string[] = [];
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
	const extensionInstanceId = parsed.extension_instance_id;
	if (typeof extensionInstanceId !== "string") {
		failures.push("extension_instance_id is missing or not a string");
	} else if (extensionInstanceId !== input.expectedExtensionInstanceId) {
		failures.push(
			`extension_instance_id is ${String(
				extensionInstanceId,
			)}, expected ${input.expectedExtensionInstanceId}`,
		);
	}
	failures.push(
		...digestEchoFailures(
			"payloadSha256",
			digestEchoValue(parsed, "payloadSha256", "payload_sha256"),
			input.expectedPayloadSha256,
		),
	);
	failures.push(
		...digestEchoFailures(
			"bundleSha256",
			digestEchoValue(parsed, "bundleSha256", "bundle_sha256"),
			input.expectedBundleSha256,
		),
	);
	return failures.length === 0
		? {
				status: "pass",
				detail:
					"Yoetz native send reported Extended Pro without fallback and matched payload/bundle digests",
			}
		: { status: "fail", detail: failures.join("; ") };
}

function isExtendedProModel(value: unknown): boolean {
	return value === "Extended Pro" || value === "extended-pro";
}

function digestEchoValue(
	parsed: Record<string, unknown>,
	camelKey: "payloadSha256" | "bundleSha256",
	snakeKey: "payload_sha256" | "bundle_sha256",
): unknown {
	return parsed[camelKey] ?? parsed[snakeKey];
}

function digestEchoFailures(
	field: "payloadSha256" | "bundleSha256",
	actual: unknown,
	expected: string | undefined,
): string[] {
	if (typeof actual !== "string") return [`${field} is missing or not a string`];
	if (!SHA256_DIGEST_PATTERN.test(actual)) return [`${field} is not a sha256 digest`];
	if (expected === undefined) return [`expected ${field} is missing`];
	if (!SHA256_DIGEST_PATTERN.test(expected)) return [`expected ${field} is not a sha256 digest`];
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
