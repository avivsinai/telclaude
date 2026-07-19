import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { z } from "zod";
import { sortKeysDeep } from "../../crypto/canonical-hash.js";
import {
	assertHouseholdPhase0ProviderActionAllowed,
	HOUSEHOLD_PHASE0_CLALIT_READ_ACTIONS,
} from "../../providers/household-clalit-policy.js";
import {
	createPendingProviderChallengeRegistry,
	type PendingProviderChallengeBindingEvidence,
} from "../../relay/pending-provider-challenge.js";
import { createProviderChallengeTurnControl } from "../../relay/provider-challenge-turn-control.js";
import type { ResolvedWhatsAppHouseholdReplyBinding } from "../../relay/whatsapp-household-bindings.js";
import type { WhatsAppIdentityResolution } from "../../relay/whatsapp-inbound-cl1.js";
import { createWhatsAppProviderChallengeInterceptor } from "../../relay/whatsapp-provider-challenge-interceptor.js";
import { redactSecrets } from "../../security/output-filter.js";
import { closeDb, resetDatabase } from "../../storage/db.js";
import {
	type HermesSignedEvidenceValidationOptions,
	hermesAllowsStaleAttestations,
	hermesAttestationFreshnessFailure,
} from "../attestation-validation.js";
import { EdgeAdapterSchemaVersions } from "../edge-adapter-contract.js";
import { edgePreparedPayloadHash } from "../edge-adapter-runtime.js";
import type {
	RelayConversation,
	RelayConversationInboundTurn,
} from "../relay-conversation-store.js";
import {
	createTelclaudeMcpSideEffectApprovalVerifier,
	generateTelclaudeMcpSideEffectApprovalToken,
	type TelclaudeMcpSideEffectApprovalSignatureVerifier,
	type TelclaudeMcpSideEffectApprovalSigner,
	TelclaudeMcpSideEffectJtiStore,
} from "./approval-token.js";
import {
	createTelclaudeMcpBridge,
	type TelclaudeMcpAuthority,
	type TelclaudeMcpBridgeDependencies,
} from "./bridge.js";
import {
	createTelclaudeMcpLedgerExecuteDependencies,
	type TelclaudeMcpInboundTurnAuthorityResolver,
} from "./ledger-execute.js";
import { createNotConfiguredTelclaudeMcpCapabilityClients } from "./live-relay-clients.js";
import {
	createProviderSidecarApprovalTokenIssuer,
	type ProviderSidecarApprovalTokenSigner,
} from "./provider-sidecar-token.js";
import { createSideEffectHumanApprovalController } from "./side-effect-human-approval.js";
import {
	createTelclaudeMcpSideEffectLedger,
	getTelclaudeMcpSideEffectApprovalBinding,
	type TelclaudeMcpOutboundSideEffectPrepareInput,
	type TelclaudeMcpOutboundSideEffectRecord,
	type TelclaudeMcpProviderSideEffectPrepareInput,
	type TelclaudeMcpProviderSideEffectRecord,
	type TelclaudeMcpSideEffectLedger,
	type TelclaudeMcpSideEffectRecord,
} from "./side-effect-ledger.js";
import {
	SIDE_EFFECT_LEDGER_ATTESTATION_RUNNER,
	SIDE_EFFECT_LEDGER_ATTESTATION_SCHEMA_VERSION,
	SIDE_EFFECT_LEDGER_ATTESTATION_SOURCE,
	type SideEffectLedgerAttestation,
	sideEffectLedgerAttestationFieldsForEvidence,
	sideEffectLedgerAttestationSignatureFailure,
	signSideEffectLedgerAttestation,
} from "./side-effect-ledger-attestation.js";

export const DEFAULT_SIDE_EFFECT_LEDGER_EVIDENCE_PATH =
	"artifacts/hermes/probes/sideeffect-ledger.json";
export const SIDE_EFFECT_LEDGER_PROBE_SCHEMA_VERSION =
	"telclaude.hermes.sideeffect-ledger-probe.v1";
export const SIDE_EFFECT_LEDGER_PROBE_SOURCE = "telclaude-mcp-side-effect-ledger-harness";

const NonEmptyString = z.string().trim().min(1);
const Sha256Digest = z.string().regex(/^sha256:[a-f0-9]{64}$/i);
const HexSha256Digest = z.string().regex(/^[a-f0-9]{64}$/);

const SideEffectLedgerProbeCheckSchema = z
	.object({
		name: NonEmptyString,
		status: z.enum(["pass", "fail"]),
		detail: NonEmptyString,
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

const SideEffectLedgerAttestationSchema = z
	.object({
		schemaVersion: z.literal(SIDE_EFFECT_LEDGER_ATTESTATION_SCHEMA_VERSION),
		source: z.literal(SIDE_EFFECT_LEDGER_ATTESTATION_SOURCE),
		runner: z.literal(SIDE_EFFECT_LEDGER_ATTESTATION_RUNNER),
		probeEvidenceSchemaVersion: z.literal(SIDE_EFFECT_LEDGER_PROBE_SCHEMA_VERSION),
		probeId: z.literal("sideeffect.ledger"),
		status: z.enum(["pass", "fail"]),
		ran: z.boolean(),
		observedAt: NonEmptyString,
		checksSha256: Sha256Digest,
		observationsSha256: Sha256Digest,
		evidenceSha256: Sha256Digest,
		signature: InternalResponseProofSchema,
	})
	.strict();

export const SideEffectLedgerProbeEvidenceSchema = z
	.object({
		schemaVersion: z.literal(SIDE_EFFECT_LEDGER_PROBE_SCHEMA_VERSION),
		probeId: z.literal("sideeffect.ledger"),
		status: z.enum(["pass", "fail"]),
		ran: z.boolean(),
		observedAt: NonEmptyString,
		source: z.literal(SIDE_EFFECT_LEDGER_PROBE_SOURCE),
		summary: NonEmptyString,
		checks: z.array(SideEffectLedgerProbeCheckSchema).min(1),
		observations: z
			.object({
				providerRef: NonEmptyString.optional(),
				outboundRef: NonEmptyString.optional(),
				providerParamsHash: Sha256Digest.optional(),
				providerBodyHash: Sha256Digest.optional(),
				providerContentHash: Sha256Digest.optional(),
				outboundParamsHash: Sha256Digest.optional(),
				outboundBodyHash: Sha256Digest.optional(),
				outboundContentHash: Sha256Digest.optional(),
				mutatedProviderContentHash: Sha256Digest.optional(),
				verifierCallCount: z.number().int().nonnegative(),
				providerProxyCallCount: z.number().int().nonnegative(),
				outboundDeliveryCallCount: z.number().int().nonnegative(),
				outboundEdgePreparedRef: NonEmptyString.optional(),
				outboundDeliveryOutboundRef: NonEmptyString.optional(),
				outboundDeliveryIdempotencyKey: NonEmptyString.optional(),
				householdParentARef: NonEmptyString.optional(),
				householdParentBRef: NonEmptyString.optional(),
				householdParentAContentHash: Sha256Digest.optional(),
				householdParentBContentHash: Sha256Digest.optional(),
				householdDeliveryCallCount: z.number().int().nonnegative().optional(),
				householdBindingResolverCallCount: z.number().int().nonnegative().optional(),
				householdClalitParentARef: NonEmptyString.optional(),
				householdClalitParentBRef: NonEmptyString.optional(),
				householdClalitParentAContentHash: Sha256Digest.optional(),
				householdClalitParentBContentHash: Sha256Digest.optional(),
				householdClalitWriteCallCount: z.number().int().nonnegative().optional(),
				challengeResponderCallCount: z.number().int().nonnegative().optional(),
				challengeControlSendCount: z.number().int().nonnegative().optional(),
			})
			.strict(),
		runnerAttestation: SideEffectLedgerAttestationSchema.optional(),
	})
	.strict();

export type SideEffectLedgerProbeEvidence = z.infer<typeof SideEffectLedgerProbeEvidenceSchema>;
type ProbeCheck = z.infer<typeof SideEffectLedgerProbeCheckSchema>;

export const HOUSEHOLD_REPLY_PROBE_REQUIRED_CHECKS = [
	"ledger.household.binding-evidence-hash-bound",
	"ledger.household.same-subject-delivery",
	"ledger.household.parent-isolation-denied",
	"ledger.household.binding-revocation-denied",
	"ledger.household.step-up-escalation-denied",
	"ledger.household.artifact-redacted",
] as const;

export const PROVIDER_CHALLENGE_PROBE_REQUIRED_CHECKS = [
	"challenge.turn.abort-and-block",
	"challenge.audio.stays-armed",
	"challenge.parent-isolation",
	"challenge.claim-one-shot",
	"challenge.artifact-redacted",
] as const;

export const HOUSEHOLD_CLALIT_PROBE_REQUIRED_CHECKS = [
	"clalit.household.action-allowlist-enforced",
	"clalit.household.two-parent-binding-isolated",
	"clalit.household.wrong-parent-denied",
	"clalit.household.renewal-approved-once",
	"clalit.household.changed-params-denied",
	"clalit.household.expired-denied",
	"clalit.household.self-approval-denied",
	"clalit.household.artifact-redacted",
] as const;

const REQUIRED_SIDE_EFFECT_LEDGER_CHECKS = [
	"ledger.provider.prepare-hashes",
	"ledger.outbound.prepare-hashes",
	"ledger.approval-binding.content-hash",
	"ledger.provider.hermes-approval-token-input-denied",
	"ledger.provider.execute-authorized",
	"ledger.outbound.execute-authorized",
	"ledger.provider.proxy-relay",
	"ledger.mutated-binding-denied",
	"ledger.replay-denied",
	"ledger.revoked-denied",
	"ledger.expired-denied",
	"ledger.kind-mismatch-denied",
	"ledger.authority-mismatch-denied",
	"ledger.provider-scope-mismatch-denied",
	...HOUSEHOLD_REPLY_PROBE_REQUIRED_CHECKS,
	...PROVIDER_CHALLENGE_PROBE_REQUIRED_CHECKS,
	...HOUSEHOLD_CLALIT_PROBE_REQUIRED_CHECKS,
] as const;

export function runTelclaudeMcpSideEffectLedgerProbe(input: {
	readonly allowRun: boolean;
	readonly observedAt?: string;
}): Promise<SideEffectLedgerProbeEvidence> {
	if (input.allowRun !== true) return runProbe(input);

	return runProbeWithIsolatedDataDir(input);
}

async function runProbeWithIsolatedDataDir(input: {
	readonly allowRun: boolean;
	readonly observedAt?: string;
}): Promise<SideEffectLedgerProbeEvidence> {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-hermes-ledger-probe-"));
	const originalDataDir = process.env.TELCLAUDE_DATA_DIR;
	closeDb();
	process.env.TELCLAUDE_DATA_DIR = path.join(tempDir, "relay-data");
	resetDatabase();

	try {
		return await runProbe(input);
	} finally {
		closeDb();
		if (originalDataDir === undefined) delete process.env.TELCLAUDE_DATA_DIR;
		else process.env.TELCLAUDE_DATA_DIR = originalDataDir;
		fs.rmSync(tempDir, { recursive: true, force: true });
	}
}

export function sideEffectLedgerProbeEvidenceFailure(
	surfaceId: string,
	evidence: unknown,
	options: HermesSignedEvidenceValidationOptions = {},
): string | null {
	if (surfaceId !== "sideeffect.ledger") {
		return `unsupported side-effect ledger surface ${surfaceId}`;
	}
	const parsed = SideEffectLedgerProbeEvidenceSchema.safeParse(evidence);
	if (!parsed.success) {
		return `invalid side-effect ledger evidence: ${flattenZodError(parsed.error)}`;
	}
	const data = parsed.data;
	const failures: string[] = [];
	if (data.status !== "pass") failures.push(`status is ${data.status}`);
	if (data.ran !== true) failures.push("harness did not run");
	if (data.probeId !== "sideeffect.ledger") failures.push(`probeId is ${data.probeId}`);
	const attestationFailure = sideEffectLedgerRunnerAttestationFailure(data, options);
	if (attestationFailure) failures.push(attestationFailure);
	const checksByName = new Map(data.checks.map((check) => [check.name, check]));
	for (const duplicate of duplicates(data.checks.map((check) => check.name))) {
		failures.push(`duplicate check ${duplicate}`);
	}
	for (const name of REQUIRED_SIDE_EFFECT_LEDGER_CHECKS) {
		const check = checksByName.get(name);
		if (!check) {
			failures.push(`check ${name} is missing`);
		} else if (check.status !== "pass") {
			failures.push(`check ${name} is ${check.status}`);
		}
	}
	if (data.observations.verifierCallCount < 3) {
		failures.push("verifierCallCount is too low to prove authorization and mismatch paths");
	}
	if (data.observations.providerProxyCallCount !== 1) {
		failures.push(`providerProxyCallCount is ${data.observations.providerProxyCallCount}`);
	}
	if (data.observations.outboundDeliveryCallCount !== 1) {
		failures.push(`outboundDeliveryCallCount is ${data.observations.outboundDeliveryCallCount}`);
	}
	if (data.observations.householdDeliveryCallCount !== 1) {
		failures.push(
			`householdDeliveryCallCount is ${String(data.observations.householdDeliveryCallCount)}`,
		);
	}
	if ((data.observations.householdBindingResolverCallCount ?? 0) < 3) {
		failures.push("householdBindingResolverCallCount is too low");
	}
	if (
		!data.observations.householdParentAContentHash ||
		!data.observations.householdParentBContentHash ||
		data.observations.householdParentAContentHash === data.observations.householdParentBContentHash
	) {
		failures.push("household parent approval bindings are not independently hash-bound");
	}
	if (
		!data.observations.householdClalitParentAContentHash ||
		!data.observations.householdClalitParentBContentHash ||
		data.observations.householdClalitParentAContentHash ===
			data.observations.householdClalitParentBContentHash
	) {
		failures.push("household Clalit renewal bindings are not independently hash-bound");
	}
	if (data.observations.householdClalitWriteCallCount !== 1) {
		failures.push(
			`householdClalitWriteCallCount is ${String(data.observations.householdClalitWriteCallCount)}`,
		);
	}
	if (!data.observations.outboundEdgePreparedRef) {
		failures.push("outboundEdgePreparedRef is missing");
	}
	if (!data.observations.outboundDeliveryOutboundRef) {
		failures.push("outboundDeliveryOutboundRef is missing");
	} else if (
		data.observations.outboundEdgePreparedRef &&
		data.observations.outboundDeliveryOutboundRef !== data.observations.outboundEdgePreparedRef
	) {
		failures.push(
			`outboundDeliveryOutboundRef is ${data.observations.outboundDeliveryOutboundRef}, expected ${data.observations.outboundEdgePreparedRef}`,
		);
	}
	for (const [label, paramsHash, bodyHash, contentHash] of [
		[
			"provider",
			data.observations.providerParamsHash,
			data.observations.providerBodyHash,
			data.observations.providerContentHash,
		],
		[
			"outbound",
			data.observations.outboundParamsHash,
			data.observations.outboundBodyHash,
			data.observations.outboundContentHash,
		],
	] as const) {
		if (!paramsHash || !bodyHash || !contentHash) {
			failures.push(`${label} hash observations are incomplete`);
		} else if (contentHash === bodyHash || contentHash === paramsHash) {
			failures.push(`${label} contentHash is not domain-separated from params/body hashes`);
		}
	}
	return failures.length > 0 ? failures.join("; ") : null;
}

function sideEffectLedgerRunnerAttestationFailure(
	evidence: SideEffectLedgerProbeEvidence,
	options: HermesSignedEvidenceValidationOptions,
): string | null {
	const attestation = evidence.runnerAttestation as SideEffectLedgerAttestation | undefined;
	if (!attestation) return "runnerAttestation is missing";
	const freshnessFailure = hermesAttestationFreshnessFailure(
		"runnerAttestation observedAt",
		attestation.observedAt,
		options,
	);
	if (freshnessFailure) return freshnessFailure;
	const signatureFailure = sideEffectLedgerAttestationSignatureFailure(attestation, {
		allowStale: hermesAllowsStaleAttestations(options),
		relayPublicKey: options.relayPublicKey,
	});
	if (signatureFailure) return `runnerAttestation signature is invalid: ${signatureFailure}`;
	const expected = sideEffectLedgerAttestationFieldsForEvidence(evidence);
	for (const field of [
		"probeEvidenceSchemaVersion",
		"probeId",
		"status",
		"ran",
		"observedAt",
		"checksSha256",
		"observationsSha256",
		"evidenceSha256",
	] as const) {
		if (attestation[field] !== expected[field]) {
			return `runnerAttestation ${field} mismatch`;
		}
	}
	return null;
}

async function runProbe(input: {
	readonly allowRun: boolean;
	readonly observedAt?: string;
}): Promise<SideEffectLedgerProbeEvidence> {
	const observedAt = input.observedAt ?? new Date().toISOString();
	if (input.allowRun !== true) {
		return {
			schemaVersion: SIDE_EFFECT_LEDGER_PROBE_SCHEMA_VERSION,
			probeId: "sideeffect.ledger",
			status: "fail",
			ran: false,
			observedAt,
			source: SIDE_EFFECT_LEDGER_PROBE_SOURCE,
			summary: "side-effect ledger harness was not allowed to run",
			checks: [
				{
					name: "ledger.provider.prepare-hashes",
					status: "fail",
					detail: "run with --allow-run to execute the deterministic ledger harness",
				},
			],
			observations: {
				verifierCallCount: 0,
				providerProxyCallCount: 0,
				outboundDeliveryCallCount: 0,
			},
		};
	}

	const checks: ProbeCheck[] = [];
	const observations: SideEffectLedgerProbeEvidence["observations"] = {
		verifierCallCount: 0,
		providerProxyCallCount: 0,
		outboundDeliveryCallCount: 0,
	};
	const jtiDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-hermes-ledger-jti-"));
	const jtiStore = new TelclaudeMcpSideEffectJtiStore(jtiDir);
	try {
		let nowMs = 100_000;
		let nextRef = 0;
		const vault = createProbeVault();
		const verifier = createTelclaudeMcpSideEffectApprovalVerifier({
			vaultClient: vault,
			jtiStore,
			nowSeconds: () => Math.floor(nowMs / 1_000),
		});
		const ledger = createTelclaudeMcpSideEffectLedger({
			nowMs: () => nowMs,
			makeRef: () => `effect-ledger-probe-${++nextRef}`,
			defaultTtlMs: 60_000,
			verifyApproval: async (request) => {
				observations.verifierCallCount += 1;
				return verifier(request);
			},
		});
		const providerProxyCalls: unknown[] = [];
		const providerApprovals = new Map<string, string>();
		const bridge = createProbeBridge(
			ledger,
			providerApprovals,
			observations,
			() => nowMs,
			async (request) => {
				providerProxyCalls.push(request);
				observations.providerProxyCallCount = providerProxyCalls.length;
				return { status: "ok", data: { accepted: true } };
			},
		);

		const provider = ledger.prepare(providerPrepareInput()) as TelclaudeMcpProviderSideEffectRecord;
		const outbound = ledger.prepare(outboundPrepareInput()) as TelclaudeMcpOutboundSideEffectRecord;
		const providerBinding = getTelclaudeMcpSideEffectApprovalBinding(provider);
		const outboundBinding = getTelclaudeMcpSideEffectApprovalBinding(outbound);
		observations.providerRef = provider.ref;
		observations.outboundRef = outbound.ref;
		observations.providerParamsHash = provider.paramsHash;
		observations.providerBodyHash = provider.bodyHash;
		observations.providerContentHash = providerBinding.contentHash;
		observations.outboundParamsHash = outbound.paramsHash;
		observations.outboundBodyHash = outbound.bodyHash;
		observations.outboundContentHash = outboundBinding.contentHash;
		observations.outboundEdgePreparedRef = outbound.edgePreparedRef;

		pushCheck(
			checks,
			"ledger.provider.prepare-hashes",
			isSha256(provider.paramsHash) &&
				isSha256(provider.bodyHash) &&
				provider.paramsHash !== provider.bodyHash &&
				provider.status === "prepared",
			"provider prepared ref has immutable canonical params/body hashes",
		);
		pushCheck(
			checks,
			"ledger.outbound.prepare-hashes",
			isSha256(outbound.paramsHash) &&
				isSha256(outbound.bodyHash) &&
				outbound.paramsHash !== outbound.bodyHash &&
				outbound.status === "prepared",
			"outbound prepared ref has immutable canonical params/body hashes",
		);
		pushCheck(
			checks,
			"ledger.approval-binding.content-hash",
			isSha256(providerBinding.contentHash) &&
				isSha256(outboundBinding.contentHash) &&
				providerBinding.contentHash !== provider.bodyHash &&
				outboundBinding.contentHash !== outbound.bodyHash,
			"approval bindings are domain-separated from body hashes",
		);

		const providerToken = await generateProbeToken(provider, vault, "provider-jti");
		const outboundToken = await generateProbeToken(outbound, vault, "outbound-jti");
		const hermesTokenInputResult = await bridge
			.tc_provider_execute_write({
				actionRef: provider.ref,
				approvalToken: providerToken,
			})
			.then(
				(result) => resultShape(result),
				(error) => ({
					ok: false,
					code: "schema_rejected",
					detail: error instanceof Error ? error.message : String(error),
				}),
			);
		pushCheck(
			checks,
			"ledger.provider.hermes-approval-token-input-denied",
			hermesTokenInputResult.ok === false &&
				hermesTokenInputResult.code === "schema_rejected" &&
				observations.verifierCallCount === 0 &&
				providerProxyCalls.length === 0 &&
				ledger.get(provider.ref)?.status === "prepared",
			"Hermes-facing provider execute rejects approvalToken input before verifier or proxy use",
		);
		providerApprovals.set(provider.ref, providerToken);
		const providerResult = resultShape(
			await bridge.tc_provider_execute_write({
				actionRef: provider.ref,
			}),
		);
		providerApprovals.set(outbound.ref, outboundToken);
		const outboundResult = resultShape(
			await bridge.tc_outbound_execute({
				outboundRef: outbound.ref,
			}),
		);
		pushCheck(
			checks,
			"ledger.provider.execute-authorized",
			providerResult.ok === true &&
				providerResult.record?.ref === provider.ref &&
				providerResult.record?.status === "executed" &&
				providerResult.record?.approvalId === "provider-jti",
			"provider write executes once after vault-signed approval verification",
		);
		pushCheck(
			checks,
			"ledger.outbound.execute-authorized",
			outboundResult.ok === true &&
				outboundResult.record?.ref === outbound.ref &&
				outboundResult.record?.status === "executed" &&
				outboundResult.record?.approvalId === "outbound-jti" &&
				observations.outboundDeliveryCallCount === 1 &&
				observations.outboundDeliveryOutboundRef === outbound.edgePreparedRef &&
				observations.outboundDeliveryIdempotencyKey === outbound.idempotencyKey,
			"outbound delivery executes once after vault-signed approval verification",
		);
		pushCheck(
			checks,
			"ledger.provider.proxy-relay",
			providerProxyCalls.length === 1 &&
				providerProxyCalls.some((call) =>
					providerProxyCallPassed(call, provider, sidecarApprovalTokenFor(provider)),
				),
			"provider sidecar execution is routed through the relay proxy with a sidecar approval token",
		);

		const originalForMutation = ledger.prepare(
			providerPrepareInput({ params: { amount: 100, currency: "ILS" } }),
		);
		const mutated = ledger.prepare(
			providerPrepareInput({ params: { amount: 101, currency: "ILS" } }),
		);
		observations.mutatedProviderContentHash =
			getTelclaudeMcpSideEffectApprovalBinding(mutated).contentHash;
		const mutationToken = await generateProbeToken(originalForMutation, vault, "mutation-jti");
		providerApprovals.set(mutated.ref, mutationToken);
		const mutationResult = resultShape(
			await bridge.tc_provider_execute_write({
				actionRef: mutated.ref,
			}),
		);
		pushCheck(
			checks,
			"ledger.mutated-binding-denied",
			mutationResult.ok === false &&
				mutationResult.code === "approval_mismatch" &&
				mutationResult.retryable === true &&
				mutationResult.record?.status === "prepared" &&
				getTelclaudeMcpSideEffectApprovalBinding(originalForMutation).contentHash !==
					observations.mutatedProviderContentHash,
			"token bound to original params is denied without consuming the mutated prepared ref",
		);

		const replayResult = resultShape(
			await bridge.tc_provider_execute_write({
				actionRef: provider.ref,
			}),
		);
		pushCheck(
			checks,
			"ledger.replay-denied",
			replayResult.ok === false &&
				replayResult.code === "effect_already_executed" &&
				replayResult.retryable === false,
			"executed refs remain terminal and cannot be replayed",
		);

		const revoked = ledger.prepare(outboundPrepareInput());
		ledger.revoke(revoked.ref, "operator cancelled");
		const revokedResult = resultShape(
			await bridge.tc_outbound_execute({
				outboundRef: revoked.ref,
			}),
		);
		pushCheck(
			checks,
			"ledger.revoked-denied",
			revokedResult.ok === false &&
				revokedResult.code === "effect_revoked" &&
				revokedResult.retryable === false &&
				revokedResult.record?.status === "revoked",
			"revoked refs fail closed before approval verification",
		);

		const expired = ledger.prepare(providerPrepareInput({ ttlMs: 1 }));
		nowMs = 100_002;
		const expiredResult = resultShape(
			await bridge.tc_provider_execute_write({
				actionRef: expired.ref,
			}),
		);
		nowMs = 100_000;
		pushCheck(
			checks,
			"ledger.expired-denied",
			expiredResult.ok === false &&
				expiredResult.code === "effect_expired" &&
				expiredResult.retryable === false &&
				expiredResult.record?.status === "prepared",
			"expired refs fail closed before approval verification",
		);

		const kindMismatch = ledger.prepare(outboundPrepareInput());
		const kindMismatchResult = resultShape(
			await bridge.tc_provider_execute_write({
				actionRef: kindMismatch.ref,
			}),
		);
		pushCheck(
			checks,
			"ledger.kind-mismatch-denied",
			kindMismatchResult.ok === false &&
				kindMismatchResult.code === "effect_kind_mismatch" &&
				kindMismatchResult.retryable === false &&
				ledger.get(kindMismatch.ref)?.status === "prepared",
			"provider execution cannot consume outbound prepared refs",
		);

		const authorityMismatch = ledger.prepare(providerPrepareInput({ actorId: "other-actor" }));
		const authorityMismatchResult = resultShape(
			await bridge.tc_provider_execute_write({
				actionRef: authorityMismatch.ref,
			}),
		);
		pushCheck(
			checks,
			"ledger.authority-mismatch-denied",
			authorityMismatchResult.ok === false &&
				authorityMismatchResult.code === "effect_authority_mismatch" &&
				authorityMismatchResult.retryable === false &&
				ledger.get(authorityMismatch.ref)?.status === "prepared",
			"authority stamps must match the prepared side-effect owner before verification",
		);

		const providerScopeMismatch = ledger.prepare(
			providerPrepareInput({
				providerId: "clalit",
				service: "clalit",
				action: "appointments.cancel",
				params: { appointmentId: "appt_123" },
				providerAccountRef: "clalit:primary",
				approvalRequestId: "approval-provider-scope-probe",
				idempotencyKey: "idem-provider-scope-probe",
				wysiwysRender: "Cancel Clalit appointment appt_123",
			}),
		);
		const providerScopeToken = await generateProbeToken(
			providerScopeMismatch,
			vault,
			"provider-scope-jti",
		);
		providerApprovals.set(providerScopeMismatch.ref, providerScopeToken);
		const verifierCallsBeforeScopeMismatch = observations.verifierCallCount;
		const providerScopeMismatchResult = resultShape(
			await bridge.tc_provider_execute_write({
				actionRef: providerScopeMismatch.ref,
			}),
		);
		const recordAfterProviderScopeMismatch = ledger.get(providerScopeMismatch.ref);
		const verifierCallsAfterScopeMismatch = observations.verifierCallCount;
		const clalitBridge = createProbeBridge(
			ledger,
			providerApprovals,
			observations,
			() => nowMs,
			undefined,
			{
				providerScopes: ["clalit"],
			},
		);
		const providerScopeAllowedResult = resultShape(
			await clalitBridge.tc_provider_execute_write({
				actionRef: providerScopeMismatch.ref,
			}),
		);
		pushCheck(
			checks,
			"ledger.provider-scope-mismatch-denied",
			providerScopeMismatchResult.ok === false &&
				providerScopeMismatchResult.code === "effect_authority_mismatch" &&
				providerScopeMismatchResult.retryable === false &&
				recordAfterProviderScopeMismatch?.status === "prepared" &&
				verifierCallsAfterScopeMismatch === verifierCallsBeforeScopeMismatch &&
				providerScopeAllowedResult.ok === true &&
				providerScopeAllowedResult.record?.status === "executed",
			"provider scopes must match the prepared provider before approval verification or JTI use",
		);
		await runHouseholdReplyProbe({
			ledger,
			vault,
			checks,
			observations,
			nowMs: () => nowMs,
		});
		await runHouseholdClalitProbe({
			ledger,
			vault,
			checks,
			observations,
			nowMs: () => nowMs,
			setNowMs: (value) => {
				nowMs = value;
			},
		});
		await runProviderChallengeProbe({ checks, observations, nowMs: () => nowMs });
	} catch (error) {
		checks.push({
			name: "ledger.probe.exception",
			status: "fail",
			detail: error instanceof Error ? error.message : String(error),
		});
	} finally {
		jtiStore.close();
		fs.rmSync(jtiDir, { recursive: true, force: true });
	}

	const status =
		checks.length > 0 && checks.every((check) => check.status === "pass") ? "pass" : "fail";
	const evidence: Omit<SideEffectLedgerProbeEvidence, "runnerAttestation"> = {
		schemaVersion: SIDE_EFFECT_LEDGER_PROBE_SCHEMA_VERSION,
		probeId: "sideeffect.ledger",
		status,
		ran: true,
		observedAt,
		source: SIDE_EFFECT_LEDGER_PROBE_SOURCE,
		summary:
			status === "pass"
				? "MCP side-effect ledger probe passed"
				: "MCP side-effect ledger probe failed",
		checks,
		observations,
	};
	return status === "pass"
		? {
				...evidence,
				runnerAttestation: signSideEffectLedgerAttestation(
					evidence,
				) as SideEffectLedgerProbeEvidence["runnerAttestation"],
			}
		: evidence;
}

async function runProviderChallengeProbe(input: {
	readonly checks: ProbeCheck[];
	readonly observations: SideEffectLedgerProbeEvidence["observations"];
	readonly nowMs: () => number;
}): Promise<void> {
	const turnControl = createProviderChallengeTurnControl({ nowMs: input.nowMs });
	const registry = createPendingProviderChallengeRegistry({ nowMs: input.nowMs, turnControl });
	const identity = providerChallengeIdentity("parent-a", "+15550000001");
	const otherIdentity = providerChallengeIdentity("parent-b", "+15550000002");
	const conversation = providerChallengeConversation(identity, "a");
	const binding = providerChallengeBinding(identity, conversation);
	const initiatingTurnRef = `turn_${"c".repeat(32)}`;
	const streamController = new AbortController();
	turnControl.register(initiatingTurnRef, streamController);
	registry.arm({
		origin: "relay_login_coordinator",
		initiationRef: "provider_login_probe_parent_a_1234",
		initiatingTurnRef,
		binding,
		service: "clalit",
		providerChallengeId: "synthetic-provider-challenge-secret",
		challengeType: "sms_otp",
		sidecarExpiresAtMs: input.nowMs() + 60_000,
		nowMs: input.nowMs(),
	});
	pushCheck(
		input.checks,
		"challenge.turn.abort-and-block",
		streamController.signal.aborted && turnControl.isBlocked(initiatingTurnRef, input.nowMs()),
		"coordinator arming aborts the active Hermes stream and blocks the opaque turn ref",
	);

	const controls: unknown[] = [];
	const responderInputs: unknown[] = [];
	const intercept = createWhatsAppProviderChallengeInterceptor({
		registry,
		nowMs: input.nowMs,
		respondToChallenge: async (request) => {
			responderInputs.push(request);
			input.observations.challengeResponderCallCount = responderInputs.length;
			return { status: "success" };
		},
		sendControl: async (request) => {
			controls.push(request);
			input.observations.challengeControlSendCount = controls.length;
		},
	});
	const audioResult = await intercept({
		event: providerChallengeEvent(identity, {
			text: undefined,
			attachments: [{ mediaType: "audio/ogg", bytesBase64: "must-not-decode" }],
		}),
		identity,
		conversation,
	});
	pushCheck(
		input.checks,
		"challenge.audio.stays-armed",
		audioResult.handled &&
			audioResult.templateId === "challenge_type_digits" &&
			registry.peekForInbound(binding, input.nowMs()).status === "armed" &&
			responderInputs.length === 0,
		"armed audio is handled with fixed copy without decode, claim, or provider response",
	);

	const otherResult = await intercept({
		event: providerChallengeEvent(otherIdentity, { text: "862409" }),
		identity: otherIdentity,
		conversation: providerChallengeConversation(otherIdentity, "b"),
	});
	pushCheck(
		input.checks,
		"challenge.parent-isolation",
		otherResult.handled &&
			otherResult.templateId === "challenge_unarmed_safety" &&
			registry.peekForInbound(binding, input.nowMs()).status === "armed" &&
			responderInputs.length === 0,
		"a different household binding cannot observe or consume the pending parent challenge",
	);

	const successResult = await intercept({
		event: providerChallengeEvent(identity, { text: "862409" }),
		identity,
		conversation,
	});
	const replayResult = await intercept({
		event: providerChallengeEvent(identity, { text: "862409", messageId: "challenge-replay" }),
		identity,
		conversation,
	});
	pushCheck(
		input.checks,
		"challenge.claim-one-shot",
		successResult.handled &&
			successResult.templateId === "challenge_success_repeat_request" &&
			replayResult.handled &&
			replayResult.templateId === "challenge_unarmed_safety" &&
			responderInputs.length === 1 &&
			registry.peekForInbound(binding, input.nowMs()).status === "none",
		"a valid OTP deletes before provider response and replay cannot respond again",
	);

	const serialized = JSON.stringify({
		audioResult,
		otherResult,
		successResult,
		replayResult,
		controls,
	});
	pushCheck(
		input.checks,
		"challenge.artifact-redacted",
		!serialized.includes("862409") &&
			!serialized.includes("synthetic-provider-challenge-secret") &&
			redactSecrets(serialized) === serialized,
		"signed challenge observations contain fixed templates and no OTP or provider challenge secret",
	);
}

async function runHouseholdClalitProbe(input: {
	readonly ledger: TelclaudeMcpSideEffectLedger;
	readonly vault: TelclaudeMcpSideEffectApprovalSigner & ProviderSidecarApprovalTokenSigner;
	readonly checks: ProbeCheck[];
	readonly observations: SideEffectLedgerProbeEvidence["observations"];
	readonly nowMs: () => number;
	readonly setNowMs: (value: number) => void;
}): Promise<void> {
	let allowlistEnforced = true;
	try {
		for (const action of HOUSEHOLD_PHASE0_CLALIT_READ_ACTIONS) {
			assertHouseholdPhase0ProviderActionAllowed({
				domain: "household",
				service: "clalit",
				action,
				mode: "read",
			});
		}
		assertHouseholdPhase0ProviderActionAllowed({
			domain: "household",
			service: "clalit",
			action: "prescription_renewal",
			mode: "write",
		});
		for (const [action, mode] of [
			["home", "read"],
			["appointment_booking", "write"],
			["tofes_17", "write"],
		] as const) {
			try {
				assertHouseholdPhase0ProviderActionAllowed({
					domain: "household",
					service: "clalit",
					action,
					mode,
				});
				allowlistEnforced = false;
			} catch {
				// Required denial.
			}
		}
	} catch {
		allowlistEnforced = false;
	}
	pushCheck(
		input.checks,
		"clalit.household.action-allowlist-enforced",
		allowlistEnforced,
		"reviewed reads and prescription renewal pass while home, booking, and Tofes 17 deny",
	);

	const parentA = input.ledger.prepare(
		householdClalitRenewalPrepareInput("parent-a", { prescriptionId: "rx-parent-a" }),
	) as TelclaudeMcpProviderSideEffectRecord;
	const parentB = input.ledger.prepare(
		householdClalitRenewalPrepareInput("parent-b", { prescriptionId: "rx-parent-b" }),
	) as TelclaudeMcpProviderSideEffectRecord;
	const parentABinding = getTelclaudeMcpSideEffectApprovalBinding(parentA);
	const parentBBinding = getTelclaudeMcpSideEffectApprovalBinding(parentB);
	input.observations.householdClalitParentARef = parentA.ref;
	input.observations.householdClalitParentBRef = parentB.ref;
	input.observations.householdClalitParentAContentHash = parentABinding.contentHash;
	input.observations.householdClalitParentBContentHash = parentBBinding.contentHash;
	input.observations.householdClalitWriteCallCount = 0;
	pushCheck(
		input.checks,
		"clalit.household.two-parent-binding-isolated",
		parentA.actorId !== parentB.actorId &&
			parentA.subjectUserId !== parentB.subjectUserId &&
			parentABinding.contentHash !== parentBBinding.contentHash &&
			parentA.paramsHash !== parentB.paramsHash,
		"two synthetic parents produce disjoint actor, subject, params, and approval bindings",
	);

	const approvals = new Map<string, string>();
	const providerProxy = async () => {
		input.observations.householdClalitWriteCallCount =
			(input.observations.householdClalitWriteCallCount ?? 0) + 1;
		return { status: "ok" as const, data: { accepted: true } };
	};
	const parentABridge = createProbeBridge(
		input.ledger,
		approvals,
		input.observations,
		input.nowMs,
		providerProxy,
		householdClalitAuthority("parent-a"),
		createProviderSidecarApprovalTokenIssuer({ vaultClient: input.vault }),
	);
	const parentBBridge = createProbeBridge(
		input.ledger,
		approvals,
		input.observations,
		input.nowMs,
		providerProxy,
		householdClalitAuthority("parent-b"),
		createProviderSidecarApprovalTokenIssuer({ vaultClient: input.vault }),
	);
	approvals.set(parentA.ref, await generateProbeToken(parentA, input.vault, "clalit-parent-a"));
	const wrongParentResult = resultShape(
		await parentBBridge.tc_provider_execute_write({ actionRef: parentA.ref }),
	);
	pushCheck(
		input.checks,
		"clalit.household.wrong-parent-denied",
		wrongParentResult.ok === false &&
			wrongParentResult.code === "effect_authority_mismatch" &&
			input.ledger.get(parentA.ref)?.status === "prepared" &&
			approvals.has(parentA.ref) &&
			input.observations.householdClalitWriteCallCount === 0,
		"parent B cannot consume parent A's renewal approval, ref, or provider call",
	);

	const approvedResult = resultShape(
		await parentABridge.tc_provider_execute_write({ actionRef: parentA.ref }),
	);
	const replayResult = resultShape(
		await parentABridge.tc_provider_execute_write({ actionRef: parentA.ref }),
	);
	pushCheck(
		input.checks,
		"clalit.household.renewal-approved-once",
		approvedResult.ok === true &&
			approvedResult.record?.status === "executed" &&
			replayResult.ok === false &&
			replayResult.code === "effect_already_executed" &&
			input.observations.householdClalitWriteCallCount === 1,
		"the exact approved renewal executes once and replay remains terminal",
	);

	const original = input.ledger.prepare(
		householdClalitRenewalPrepareInput("parent-a", { prescriptionId: "rx-original" }),
	) as TelclaudeMcpProviderSideEffectRecord;
	const changed = input.ledger.prepare(
		householdClalitRenewalPrepareInput("parent-a", { prescriptionId: "rx-changed" }),
	) as TelclaudeMcpProviderSideEffectRecord;
	approvals.set(changed.ref, await generateProbeToken(original, input.vault, "clalit-changed"));
	const changedResult = resultShape(
		await parentABridge.tc_provider_execute_write({ actionRef: changed.ref }),
	);
	pushCheck(
		input.checks,
		"clalit.household.changed-params-denied",
		changedResult.ok === false &&
			changedResult.code === "approval_mismatch" &&
			input.ledger.get(changed.ref)?.status === "prepared" &&
			getTelclaudeMcpSideEffectApprovalBinding(original).contentHash !==
				getTelclaudeMcpSideEffectApprovalBinding(changed).contentHash &&
			input.observations.householdClalitWriteCallCount === 1,
		"an approval for one prescription cannot authorize changed renewal parameters",
	);

	const expired = input.ledger.prepare(
		householdClalitRenewalPrepareInput("parent-a", { prescriptionId: "rx-expired" }, 1),
	) as TelclaudeMcpProviderSideEffectRecord;
	approvals.set(expired.ref, await generateProbeToken(expired, input.vault, "clalit-expired"));
	const originalNowMs = input.nowMs();
	input.setNowMs(originalNowMs + 2);
	const expiredResult = resultShape(
		await parentABridge.tc_provider_execute_write({ actionRef: expired.ref }),
	);
	input.setNowMs(originalNowMs);
	pushCheck(
		input.checks,
		"clalit.household.expired-denied",
		expiredResult.ok === false &&
			expiredResult.code === "effect_expired" &&
			input.ledger.get(expired.ref)?.status === "prepared" &&
			input.observations.householdClalitWriteCallCount === 1,
		"an expired renewal ref fails before approval consumption or provider execution",
	);

	const selfApproved = input.ledger.prepare(
		householdClalitRenewalPrepareInput("parent-a", { prescriptionId: "rx-self" }, undefined, {
			approverActorId: "household:whatsapp:parent-a",
		}),
	) as TelclaudeMcpProviderSideEffectRecord;
	const selfApprovalController = createSideEffectHumanApprovalController({
		nowMs: input.nowMs,
		mintApprovalToken: async () => "must-not-mint",
	});
	const selfApprovalResult = await selfApprovalController.request({
		record: selfApproved,
		chatId: 111,
	});
	pushCheck(
		input.checks,
		"clalit.household.self-approval-denied",
		selfApprovalResult.ok === false &&
			selfApprovalResult.code === "approval_self_approval_denied" &&
			input.ledger.get(selfApproved.ref)?.status === "prepared" &&
			input.observations.householdClalitWriteCallCount === 1,
		"the parent who requested a renewal cannot become its distinct Telegram approver",
	);

	const serialized = JSON.stringify({
		parentA: { ref: parentA.ref, contentHash: parentABinding.contentHash },
		parentB: { ref: parentB.ref, contentHash: parentBBinding.contentHash },
		wrongParentResult,
		approvedResult,
		replayResult,
		changedResult,
		expiredResult,
		selfApprovalResult,
	});
	pushCheck(
		input.checks,
		"clalit.household.artifact-redacted",
		redactSecrets(serialized) === serialized,
		"signed renewal evidence contains only synthetic opaque identifiers and hashes",
	);
}

function providerChallengeIdentity(
	bindingId: string,
	phone: string,
): Extract<WhatsAppIdentityResolution, { domain: "household" }> {
	return {
		domain: "household",
		bindingId,
		addresseeGender: bindingId === "parent-a" ? "f" : "m",
		actorId: `household:whatsapp:${bindingId}`,
		subjectUserId: `household:${bindingId}`,
		profileId: bindingId,
		principalId: `whatsapp:${phone}`,
		identityAssurance: "strong_link",
		authorizationScopes: [],
		actorScopes: [],
		humanPairingProvenance: true,
		memorySource: `household:${bindingId}`,
		writableNamespace: `household:${bindingId}`,
		replyAddressRef: `whatsapp:${phone}`,
		expectedConversationKey: `whatsapp:${phone}`,
		conversationId: `whatsapp:household:${bindingId}`,
	};
}

function providerChallengeConversation(
	identity: Extract<WhatsAppIdentityResolution, { domain: "household" }>,
	hex: string,
): RelayConversation {
	return {
		token: `conv_${hex.repeat(32)}`,
		channel: "whatsapp",
		conversationId: identity.conversationId,
		threadId: identity.replyAddressRef,
		profileId: identity.profileId,
		domain: "household",
		mcpDomain: "household",
		edgeDomain: "household",
		routingSession: { sessionId: "challenge-probe", routeKey: "challenge-probe" },
		authorizationState: "authorized",
		humanPairingProvenance: true,
		authorizationScopes: [],
		members: [],
		threadMessageIds: [],
		inboundCursor: null,
		auditIds: [],
		createdAtMs: 100_000,
		expiresAtMs: null,
		revokedAtMs: null,
		revokeReason: null,
		updatedAtMs: 100_000,
	};
}

function providerChallengeBinding(
	identity: Extract<WhatsAppIdentityResolution, { domain: "household" }>,
	conversation: RelayConversation,
): PendingProviderChallengeBindingEvidence {
	return {
		bindingId: identity.bindingId,
		actorId: identity.actorId,
		subjectUserId: identity.subjectUserId,
		profileId: identity.profileId,
		conversationToken: conversation.token,
		conversationId: conversation.conversationId,
		senderPrincipalHash: `sha256:${crypto.createHash("sha256").update(identity.principalId).digest("hex")}`,
	};
}

function providerChallengeEvent(
	identity: Extract<WhatsAppIdentityResolution, { domain: "household" }>,
	overrides: Partial<{
		readonly text: string | undefined;
		readonly messageId: string;
		readonly attachments: { mediaType: string; bytesBase64: string }[];
	}> = {},
) {
	return {
		schemaVersion: "telclaude.edge.whatsapp.inbound.v1" as const,
		eventId: "provider-challenge-probe",
		messageId: "provider-challenge-message",
		cursorSequence: 1,
		chatKind: "direct" as const,
		senderAddressRef: identity.principalId,
		conversationKey: identity.expectedConversationKey,
		text: "hello",
		attachments: [],
		receivedAtMs: 100_000,
		...overrides,
	};
}

async function runHouseholdReplyProbe(input: {
	readonly ledger: TelclaudeMcpSideEffectLedger;
	readonly vault: TelclaudeMcpSideEffectApprovalSigner;
	readonly checks: ProbeCheck[];
	readonly observations: SideEffectLedgerProbeEvidence["observations"];
	readonly nowMs: () => number;
}): Promise<void> {
	const parentA = input.ledger.prepare(
		householdOutboundPrepareInput("parent-a", "whatsapp:+15550000001", "deliver"),
	) as TelclaudeMcpOutboundSideEffectRecord;
	const parentB = input.ledger.prepare(
		householdOutboundPrepareInput("parent-b", "whatsapp:+15550000002", "concurrent"),
	) as TelclaudeMcpOutboundSideEffectRecord;
	const parentABinding = getTelclaudeMcpSideEffectApprovalBinding(parentA);
	const parentBBinding = getTelclaudeMcpSideEffectApprovalBinding(parentB);
	input.observations.householdParentARef = parentA.ref;
	input.observations.householdParentBRef = parentB.ref;
	input.observations.householdParentAContentHash = parentABinding.contentHash;
	input.observations.householdParentBContentHash = parentBBinding.contentHash;
	input.observations.householdDeliveryCallCount = 0;
	input.observations.householdBindingResolverCallCount = 0;
	pushCheck(
		input.checks,
		"ledger.household.binding-evidence-hash-bound",
		parentA.subjectUserId === "household:parent-a" &&
			parentA.householdReplyBinding?.bindingId === "parent-a" &&
			parentA.householdReplyBinding.subjectUserId === parentA.subjectUserId &&
			parentA.householdReplyBinding.senderPrincipalHash ===
				parentA.householdReplyBinding.recipientPrincipalHash &&
			parentABinding.contentHash !== parentBBinding.contentHash &&
			parentA.paramsHash !== parentB.paramsHash &&
			parentA.bodyHash !== parentB.bodyHash,
		"household subject and principal evidence is immutable and parent-specific in every hash",
	);

	const controller = createSideEffectHumanApprovalController({
		nowMs: input.nowMs,
		autoGrant: { enabled: true },
		mintApprovalToken: ({ binding, jti, ttlMs, nowMs }) =>
			generateTelclaudeMcpSideEffectApprovalToken(binding, input.vault, {
				nowSeconds: () => Math.floor(nowMs / 1_000),
				ttlSeconds: Math.max(1, Math.ceil(ttlMs / 1_000)),
				jti,
			}),
	});
	const parentARequest = await controller.request({ record: parentA, chatId: 111 });
	const parentABridge = createHouseholdProbeBridge({
		record: parentA,
		controller,
		ledger: input.ledger,
		observations: input.observations,
		nowMs: input.nowMs,
		resolveBinding: () => resolvedHouseholdReplyBinding("parent-a", "whatsapp:+15550000001"),
	});
	const parentAResult = resultShape(
		await parentABridge.tc_outbound_execute({ outboundRef: parentA.ref }),
	);
	pushCheck(
		input.checks,
		"ledger.household.same-subject-delivery",
		parentARequest.ok === true &&
			parentARequest.autoGranted === true &&
			parentAResult.ok === true &&
			parentAResult.record?.status === "executed" &&
			input.observations.householdDeliveryCallCount === 1,
		"the current strongly-linked parent reply auto-grants and delivers exactly once",
	);

	const crossParent = input.ledger.prepare(
		householdOutboundPrepareInput("parent-a", "whatsapp:+15550000001", "cross-parent"),
	) as TelclaudeMcpOutboundSideEffectRecord;
	const crossRequest = await controller.request({ record: crossParent, chatId: 111 });
	const crossResult = resultShape(
		await createHouseholdProbeBridge({
			record: crossParent,
			controller,
			ledger: input.ledger,
			observations: input.observations,
			nowMs: input.nowMs,
			resolveBinding: () => resolvedHouseholdReplyBinding("parent-b", "whatsapp:+15550000002"),
		}).tc_outbound_execute({ outboundRef: crossParent.ref }),
	);
	pushCheck(
		input.checks,
		"ledger.household.parent-isolation-denied",
		crossRequest.ok === true &&
			crossRequest.autoGranted === true &&
			crossResult.ok === false &&
			crossResult.code === "household_reply_binding_mismatch" &&
			crossResult.record?.status === "prepared" &&
			input.observations.householdDeliveryCallCount === 1,
		"a parent-B binding cannot consume or dispatch a parent-A prepared reply",
	);

	const revoked = input.ledger.prepare(
		householdOutboundPrepareInput("parent-a", "whatsapp:+15550000001", "revoked"),
	) as TelclaudeMcpOutboundSideEffectRecord;
	const revokedRequest = await controller.request({ record: revoked, chatId: 111 });
	const revokedResult = resultShape(
		await createHouseholdProbeBridge({
			record: revoked,
			controller,
			ledger: input.ledger,
			observations: input.observations,
			nowMs: input.nowMs,
			resolveBinding: () => null,
		}).tc_outbound_execute({ outboundRef: revoked.ref }),
	);
	pushCheck(
		input.checks,
		"ledger.household.binding-revocation-denied",
		revokedRequest.ok === true &&
			revokedRequest.autoGranted === true &&
			revokedResult.ok === false &&
			revokedResult.code === "household_reply_binding_unavailable" &&
			revokedResult.record?.status === "prepared" &&
			input.observations.householdDeliveryCallCount === 1,
		"removing the pairing after prepare denies before approval consumption or dispatch",
	);

	const escalated = input.ledger.prepare(
		householdOutboundPrepareInput("parent-a", "whatsapp:+15550000001", "step-up"),
	) as TelclaudeMcpOutboundSideEffectRecord;
	let escalatedMintCalls = 0;
	const escalatedController = createSideEffectHumanApprovalController({
		nowMs: input.nowMs,
		autoGrant: { enabled: true },
		requiresFreshStepUp: () => true,
		createApproval: () => {
			throw new Error("forced step-up must not create a human approval row");
		},
		stepUpVerification: {
			verify: async () => ({
				ok: false,
				code: "fresh_step_up_required",
				reason: "fresh step-up required",
				retryable: false,
			}),
		},
		mintApprovalToken: async () => {
			escalatedMintCalls += 1;
			return "must-not-mint";
		},
	});
	const escalatedResult = await escalatedController.request({ record: escalated, chatId: 111 });
	pushCheck(
		input.checks,
		"ledger.household.step-up-escalation-denied",
		escalatedResult.ok === false &&
			escalatedResult.code === "fresh_step_up_required" &&
			escalatedMintCalls === 0,
		"independent step-up escalation fails closed without token minting or human-row fallback",
	);

	const serialized = JSON.stringify({
		parentA,
		parentB,
		parentAResult,
		crossResult,
		revokedResult,
		escalatedResult,
	});
	pushCheck(
		input.checks,
		"ledger.household.artifact-redacted",
		redactSecrets(serialized) === serialized,
		"signed household probe observations contain synthetic identifiers and no secret-shaped data",
	);
}

function createHouseholdProbeBridge(input: {
	readonly record: TelclaudeMcpOutboundSideEffectRecord;
	readonly controller: ReturnType<typeof createSideEffectHumanApprovalController>;
	readonly ledger: TelclaudeMcpSideEffectLedger;
	readonly observations: SideEffectLedgerProbeEvidence["observations"];
	readonly nowMs: () => number;
	readonly resolveBinding: () => ResolvedWhatsAppHouseholdReplyBinding | null;
}) {
	const record = input.record;
	const authority = householdProbeAuthority(record);
	return createTelclaudeMcpBridge(authority, {
		...baseDependencies(),
		...createTelclaudeMcpLedgerExecuteDependencies({
			ledger: input.ledger,
			sideEffectApprovalTokenResolver: ({ actionRef, record: current }) =>
				input.controller.takeServerSideApproval({
					actionRef,
					record: current,
					nowMs: input.nowMs(),
				}),
			resolveAuthorizedOutboundConversation: () => householdProbeConversation(record),
			resolveAuthorizedInboundTurn: householdProbeTurnResolver(record),
			resolveHouseholdReplyBinding: () => {
				input.observations.householdBindingResolverCallCount =
					(input.observations.householdBindingResolverCallCount ?? 0) + 1;
				return input.resolveBinding();
			},
			outboundDeliveryDispatcher: async (prepared) => {
				input.observations.householdDeliveryCallCount =
					(input.observations.householdDeliveryCallCount ?? 0) + 1;
				return {
					schemaVersion: EdgeAdapterSchemaVersions.deliveryReceipt,
					outboundRef: prepared.outboundRef,
					platformMessageId: "household-probe-message",
					deliveryStatus: "sent",
					timestamps: {
						observedAt: new Date(input.nowMs()).toISOString(),
						sentAt: new Date(input.nowMs()).toISOString(),
					},
					retry: {
						attempt: 1,
						maxAttempts: prepared.retryPolicy.maxAttempts,
						idempotencyKey: prepared.idempotencyKey,
					},
				};
			},
			nowMs: input.nowMs,
		}),
	});
}

function createProbeVault(): TelclaudeMcpSideEffectApprovalSigner &
	TelclaudeMcpSideEffectApprovalSignatureVerifier &
	ProviderSidecarApprovalTokenSigner {
	const secret = "telclaude-hermes-sideeffect-ledger-probe";
	return {
		async signPayload(payload, prefix) {
			return { type: "sign-payload", signature: signature(secret, payload, prefix) };
		},
		async verifyPayload(payload, sig, prefix) {
			return {
				type: "verify-payload",
				valid: safeEqual(sig, signature(secret, payload, prefix)),
			};
		},
	};
}

function signature(secret: string, payload: string, prefix: string): string {
	return crypto
		.createHmac("sha256", secret)
		.update(prefix)
		.update("\0")
		.update(payload)
		.digest("base64url");
}

function safeEqual(left: string, right: string): boolean {
	const leftBytes = Buffer.from(left);
	const rightBytes = Buffer.from(right);
	return leftBytes.length === rightBytes.length && crypto.timingSafeEqual(leftBytes, rightBytes);
}

async function generateProbeToken(
	record: TelclaudeMcpSideEffectRecord,
	vault: TelclaudeMcpSideEffectApprovalSigner,
	jti: string,
): Promise<string> {
	return generateTelclaudeMcpSideEffectApprovalToken(
		getTelclaudeMcpSideEffectApprovalBinding(record),
		vault,
		{
			nowSeconds: () => 100,
			ttlSeconds: 60,
			jti,
		},
	);
}

function createProbeBridge(
	ledger: TelclaudeMcpSideEffectLedger,
	providerApprovals: Map<string, string>,
	observations: SideEffectLedgerProbeEvidence["observations"],
	nowMs: () => number,
	providerProxy: Parameters<typeof createTelclaudeMcpLedgerExecuteDependencies>[0]["providerProxy"],
	authorityOverrides: Partial<TelclaudeMcpAuthority> = {},
	providerApprovalTokenIssuer: Parameters<
		typeof createTelclaudeMcpLedgerExecuteDependencies
	>[0]["providerApprovalTokenIssuer"] = ({ providerId, service, action, approvalNonce }) =>
		`sidecar:${providerId}:${service}:${action}:${approvalNonce}`,
) {
	const authority = { ...probeAuthority(), ...authorityOverrides };
	return createTelclaudeMcpBridge(authority, {
		...baseDependencies(),
		...createTelclaudeMcpLedgerExecuteDependencies({
			ledger,
			providerProxy,
			sideEffectApprovalTokenResolver: ({ actionRef }) => {
				const approvalToken = providerApprovals.get(actionRef);
				if (!approvalToken) {
					return {
						ok: false,
						code: "approval_token_unavailable",
						reason: "server-side approval token is unavailable",
						retryable: true,
					};
				}
				return {
					ok: true,
					approvalToken,
					finalize: () => {
						providerApprovals.delete(actionRef);
					},
				};
			},
			resolveAuthorizedOutboundConversation: (conversationRef) =>
				probeRelayConversation(conversationRef, authority),
			outboundDeliveryDispatcher: async (prepared) => {
				observations.outboundDeliveryCallCount += 1;
				observations.outboundDeliveryOutboundRef = prepared.outboundRef;
				observations.outboundDeliveryIdempotencyKey = prepared.idempotencyKey;
				return {
					schemaVersion: EdgeAdapterSchemaVersions.deliveryReceipt,
					outboundRef: prepared.outboundRef,
					platformMessageId: "probe-outbound-message",
					deliveryStatus: "sent",
					timestamps: {
						observedAt: new Date(nowMs()).toISOString(),
						sentAt: new Date(nowMs()).toISOString(),
					},
					retry: {
						attempt: 1,
						maxAttempts: prepared.retryPolicy.maxAttempts,
						idempotencyKey: prepared.idempotencyKey,
					},
				};
			},
			providerApprovalTokenIssuer,
			nowMs,
		}),
	});
}

function probeAuthority(): TelclaudeMcpAuthority {
	return {
		actorId: "operator",
		profileId: "ops",
		domain: "private",
		memorySource: "telegram:ops",
		writableNamespace: "private:ops",
		providerScopes: ["bank"],
		outboundChannels: ["whatsapp"],
		endpointId: "endpoint-private",
		networkNamespace: "netns-private",
	};
}

function probeRelayConversation(
	conversationRef: string,
	authority: TelclaudeMcpAuthority,
): RelayConversation {
	const conversationId =
		conversationRef === "whatsapp:family-thread" ? "whatsapp:family-conversation" : conversationRef;
	const relayDomain = authority.domain === "social" ? "public-social" : authority.domain;
	return {
		token: conversationRef,
		channel: "whatsapp",
		conversationId,
		threadId: conversationRef,
		profileId: authority.profileId,
		domain: relayDomain,
		mcpDomain: authority.domain,
		edgeDomain: relayDomain === "specialist" ? null : relayDomain,
		routingSession: {
			sessionId: `probe-session:${conversationRef}`,
			routeKey: `probe-route:${conversationRef}`,
		},
		authorizationState: "authorized",
		humanPairingProvenance: false,
		authorizationScopes: ["message:reply"],
		members: [
			{
				actorId: authority.actorId,
				channel: "whatsapp",
				principalId: authority.actorId,
				principalHash: fixtureContentHash(authority.actorId),
				role: "sender",
				identityAssurance: "strong_link",
				scopes: ["message:reply"],
				revoked: false,
			},
		],
		threadMessageIds: [],
		inboundCursor: null,
		auditIds: [],
		createdAtMs: 100_000,
		expiresAtMs: null,
		revokedAtMs: null,
		revokeReason: null,
		updatedAtMs: 100_000,
	};
}

function baseDependencies(): TelclaudeMcpBridgeDependencies {
	return {
		providerRead: async () => ({ ok: true }),
		providerPrepareWrite: async () => ({ actionRef: "prepared-provider-ref" }),
		providerExecuteWrite: async () => ({ ok: true }),
		memorySearch: async () => ({ entries: [] }),
		memoryWrite: async () => ({ accepted: 1 }),
		attachmentGet: async () => ({ bytes: 0 }),
		outboundPrepare: async () => ({ outboundRef: "prepared-outbound-ref" }),
		outboundExecute: async () => ({ ok: true }),
		auditNote: async () => ({ stored: true }),
		...createNotConfiguredTelclaudeMcpCapabilityClients(),
	};
}

function providerPrepareInput(
	overrides: Partial<Omit<TelclaudeMcpProviderSideEffectPrepareInput, "kind">> = {},
): TelclaudeMcpProviderSideEffectPrepareInput {
	return {
		kind: "provider",
		actorId: "operator",
		approverActorId: "operator:provider-approver",
		profileId: "ops",
		domain: "private",
		providerId: "bank",
		service: "bank",
		action: "transfer.prepare",
		params: { amount: 100, currency: "ILS", recipient: "vendor-ref" },
		providerAccountRef: "bank:primary",
		approvalRequestId: "approval-provider-ledger-probe",
		approvalRevision: 1,
		wysiwysRender: "Prepare ILS 100 transfer to vendor-ref",
		idempotencyKey: "idem-provider-ledger-probe",
		...overrides,
	};
}

function householdClalitRenewalPrepareInput(
	parent: "parent-a" | "parent-b",
	params: Record<string, unknown>,
	ttlMs?: number,
	overrides: Partial<Omit<TelclaudeMcpProviderSideEffectPrepareInput, "kind">> = {},
): TelclaudeMcpProviderSideEffectPrepareInput {
	return {
		kind: "provider",
		actorId: `household:whatsapp:${parent}`,
		approverActorId: "telegram:111",
		profileId: parent,
		domain: "household",
		providerId: "clalit",
		service: "clalit",
		action: "prescription_renewal",
		params,
		subjectUserId: `household:${parent}`,
		providerAccountRef: `clalit:household:${parent}`,
		approvalRequestId: `approval-clalit-${parent}-${String(params.prescriptionId)}`,
		approvalRevision: 1,
		wysiwysRender: "clalit.clalit.prescription_renewal",
		idempotencyKey: `idem-clalit-${parent}-${String(params.prescriptionId)}`,
		...(ttlMs === undefined ? {} : { ttlMs }),
		...overrides,
	};
}

function householdClalitAuthority(parent: "parent-a" | "parent-b"): Partial<TelclaudeMcpAuthority> {
	return {
		actorId: `household:whatsapp:${parent}`,
		subjectUserId: `household:${parent}`,
		profileId: parent,
		domain: "household",
		memorySource: `household:${parent}`,
		writableNamespace: `household:${parent}`,
		providerScopes: ["clalit"],
		outboundChannels: ["whatsapp"],
		endpointId: `endpoint-${parent}`,
		networkNamespace: `netns-${parent}`,
	};
}

function outboundPrepareInput(
	overrides: Partial<Omit<TelclaudeMcpOutboundSideEffectPrepareInput, "kind">> = {},
): TelclaudeMcpOutboundSideEffectPrepareInput {
	const channel = "whatsapp";
	const resolvedDestination = {
		kind: "thread" as const,
		threadId: "whatsapp:family-thread",
		conversationId: "whatsapp:family-conversation",
	};
	const requestedBody = "The transfer is prepared and waiting for approval.";
	const preparedMediaRefs = [
		{
			quarantineId: "att-clean-ledger-probe",
			contentHash: fixtureContentHash("att-clean-ledger-probe"),
		},
	];
	return {
		kind: "outbound",
		actorId: "operator",
		approverActorId: "operator:outbound-approver",
		profileId: "ops",
		domain: "private",
		channel,
		destination: "whatsapp:family-thread",
		resolvedDestination,
		requestedBody,
		renderedBody: requestedBody,
		mediaRefs: ["att-clean-ledger-probe"],
		preparedMediaRefs,
		conversationRef: "whatsapp:family-thread",
		authorizationState: "authorized",
		edgePreparedRef: "edge-outbound-ledger-probe",
		edgePreparedHash: edgePreparedPayloadHash({
			channel,
			resolvedDestination,
			body: requestedBody,
			mediaRefs: preparedMediaRefs,
		}),
		approvalRequestId: "approval-outbound-ledger-probe",
		approvalRevision: 1,
		approvalMetadata: { reviewer: "operator", scope: "household" },
		idempotencyKey: "idem-outbound-ledger-probe",
		...overrides,
	};
}

function householdOutboundPrepareInput(
	bindingId: string,
	principalId: string,
	caseId: string,
): TelclaudeMcpOutboundSideEffectPrepareInput {
	const channel = "whatsapp";
	const caseHash = crypto
		.createHash("sha256")
		.update(`${bindingId}:${caseId}`, "utf8")
		.digest("hex");
	const conversationId = `whatsapp:household:${bindingId}`;
	const resolvedDestination = {
		kind: "address" as const,
		addressRef: principalId,
		conversationId,
	};
	const requestedBody = `Synthetic household reply ${caseId}`;
	const preparedMediaRefs: readonly [] = [];
	const principalHash = fixtureContentHash(principalId);
	return {
		kind: "outbound",
		actorId: `household:whatsapp:${bindingId}`,
		approverActorId: "telegram:operator",
		profileId: bindingId,
		domain: "household",
		subjectUserId: `household:${bindingId}`,
		householdReplyBinding: {
			bindingId,
			subjectUserId: `household:${bindingId}`,
			senderPrincipalHash: principalHash,
			recipientPrincipalHash: principalHash,
			identityAssurance: "strong_link",
		},
		channel,
		destination: principalId,
		resolvedDestination,
		requestedBody,
		renderedBody: requestedBody,
		mediaRefs: [],
		preparedMediaRefs,
		conversationRef: `conv_${caseHash.slice(0, 32)}`,
		authorizationState: "authorized",
		edgePreparedRef: `edge-household-${bindingId}-${caseId}`,
		edgePreparedHash: edgePreparedPayloadHash({
			channel,
			resolvedDestination,
			body: requestedBody,
			mediaRefs: preparedMediaRefs,
		}),
		approvalRequestId: `approval-household-${bindingId}-${caseId}`,
		approvalRevision: 1,
		approvalMetadata: {
			source: "hermes-live-mcp",
			pairedProvenance: true,
			replyCapableActorSeat: true,
			actorIdentityAssurance: "strong_link",
		},
		turnConversationRef: `turn_${caseHash.slice(0, 32)}`,
		idempotencyKey: `idem-household-${bindingId}-${caseId}`,
	};
}

function householdProbeAuthority(
	record: TelclaudeMcpOutboundSideEffectRecord,
): TelclaudeMcpAuthority {
	return {
		actorId: record.actorId,
		subjectUserId: record.subjectUserId,
		profileId: record.profileId,
		domain: "household",
		memorySource: record.subjectUserId ?? "household:unbound",
		writableNamespace: record.subjectUserId ?? "household:unbound",
		providerScopes: [],
		outboundChannels: ["whatsapp"],
		endpointId: "endpoint-household-probe",
		networkNamespace: "netns-household-probe",
		turnConversationRef: record.turnConversationRef,
	};
}

function householdProbeConversation(
	record: TelclaudeMcpOutboundSideEffectRecord,
): RelayConversation {
	const binding = record.householdReplyBinding;
	const addressRef =
		record.resolvedDestination.kind === "address"
			? record.resolvedDestination.addressRef
			: undefined;
	if (!binding || !addressRef) {
		throw new Error("household probe record is missing reply evidence");
	}
	return {
		token: record.conversationRef,
		channel: "whatsapp",
		conversationId: record.resolvedDestination.conversationId ?? "",
		threadId: addressRef,
		profileId: record.profileId,
		domain: "household",
		mcpDomain: "household",
		edgeDomain: "household",
		routingSession: {
			sessionId: `probe-session:${binding.bindingId}`,
			routeKey: `probe-route:${binding.bindingId}`,
		},
		authorizationState: "authorized",
		humanPairingProvenance: true,
		authorizationScopes: ["message:reply"],
		members: [
			{
				actorId: record.actorId,
				channel: "whatsapp",
				principalId: addressRef,
				principalHash: binding.senderPrincipalHash,
				role: "sender",
				identityAssurance: "strong_link",
				scopes: ["message:reply"],
				revoked: false,
			},
		],
		threadMessageIds: [],
		inboundCursor: null,
		auditIds: [],
		createdAtMs: 100_000,
		expiresAtMs: null,
		revokedAtMs: null,
		revokeReason: null,
		updatedAtMs: 100_000,
	};
}

function householdProbeTurnResolver(
	record: TelclaudeMcpOutboundSideEffectRecord,
): TelclaudeMcpInboundTurnAuthorityResolver {
	return (): RelayConversationInboundTurn => {
		const addressRef =
			record.resolvedDestination.kind === "address"
				? record.resolvedDestination.addressRef
				: undefined;
		if (!addressRef || !record.turnConversationRef) {
			throw new Error("household probe turn evidence is missing");
		}
		return {
			ref: record.turnConversationRef,
			conversationToken: record.conversationRef,
			channel: "whatsapp",
			conversationId: record.resolvedDestination.conversationId ?? "",
			threadId: addressRef,
			profileId: record.profileId,
			domain: "household",
			mcpDomain: "household",
			inboundMessageId: `message:${record.householdReplyBinding?.bindingId ?? "unbound"}`,
			senderActorId: record.actorId,
			senderPrincipalId: addressRef,
			createdAtMs: 100_000,
			expiresAtMs: null,
			revokedAtMs: null,
			revokeReason: null,
		};
	};
}

function resolvedHouseholdReplyBinding(
	bindingId: string,
	principalId: string,
): ResolvedWhatsAppHouseholdReplyBinding {
	return {
		bindingId,
		actorId: `household:whatsapp:${bindingId}`,
		subjectUserId: `household:${bindingId}`,
		profileId: bindingId,
		principalId,
		replyPrincipalId: principalId,
		identityAssurance: "strong_link",
		pairingAttested: true,
		revoked: false,
	};
}

function fixtureContentHash(ref: string): `sha256:${string}` {
	return `sha256:${crypto.createHash("sha256").update(ref, "utf8").digest("hex")}`;
}

function pushCheck(
	checks: ProbeCheck[],
	name: ProbeCheck["name"],
	passed: boolean,
	passDetail: string,
	failDetail = passDetail,
): void {
	checks.push({
		name,
		status: passed ? "pass" : "fail",
		detail: passed ? passDetail : failDetail,
	});
}

function resultShape(value: unknown): {
	readonly ok?: unknown;
	readonly code?: unknown;
	readonly retryable?: unknown;
	readonly record?: {
		readonly ref?: unknown;
		readonly status?: unknown;
		readonly approvalId?: unknown;
	};
} {
	if (typeof value !== "object" || value === null) return {};
	const recordValue = (value as { record?: unknown }).record;
	const record =
		typeof recordValue === "object" && recordValue !== null
			? (recordValue as {
					readonly ref?: unknown;
					readonly status?: unknown;
					readonly approvalId?: unknown;
				})
			: undefined;
	return {
		ok: (value as { ok?: unknown }).ok,
		code: (value as { code?: unknown }).code,
		retryable: (value as { retryable?: unknown }).retryable,
		record,
	};
}

function providerProxyCallPassed(
	call: unknown,
	record: TelclaudeMcpSideEffectRecord,
	expectedApprovalToken: string,
): boolean {
	if (record.kind !== "provider" || typeof call !== "object" || call === null) return false;
	const request = call as {
		readonly providerId?: unknown;
		readonly path?: unknown;
		readonly method?: unknown;
		readonly approvalToken?: unknown;
		readonly approvalMode?: unknown;
		readonly body?: unknown;
	};
	if (
		request.providerId !== "bank" ||
		request.path !== "/v1/fetch" ||
		request.method !== "POST" ||
		request.approvalToken !== expectedApprovalToken ||
		request.approvalMode !== "preapproved-ledger" ||
		typeof request.body !== "string"
	) {
		return false;
	}
	try {
		const body = JSON.parse(request.body) as {
			service?: unknown;
			action?: unknown;
			params?: unknown;
		};
		return (
			body.service === record.service &&
			body.action === record.action &&
			JSON.stringify(sortKeysDeep(body.params)) === JSON.stringify(sortKeysDeep(record.params))
		);
	} catch {
		return false;
	}
}

function sidecarApprovalTokenFor(record: TelclaudeMcpSideEffectRecord): string {
	if (record.kind !== "provider") throw new Error("record is not provider");
	return `sidecar:${record.providerId}:${record.service}:${record.action}:${record.approvalRequestId}`;
}

function isSha256(value: string | undefined): boolean {
	return typeof value === "string" && /^sha256:[a-f0-9]{64}$/i.test(value);
}

function duplicates(values: readonly string[]): string[] {
	const seen = new Set<string>();
	const duplicate = new Set<string>();
	for (const value of values) {
		if (seen.has(value)) duplicate.add(value);
		seen.add(value);
	}
	return [...duplicate].sort((left, right) => left.localeCompare(right));
}

function flattenZodError(error: z.ZodError): string {
	return error.issues
		.map((issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`)
		.join("; ");
}
