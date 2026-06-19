import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { z } from "zod";
import { sortKeysDeep } from "../../crypto/canonical-hash.js";
import {
	type HermesSignedEvidenceValidationOptions,
	hermesAllowsStaleAttestations,
	hermesAttestationFreshnessFailure,
} from "../attestation-validation.js";
import { EdgeAdapterSchemaVersions } from "../edge-adapter-contract.js";
import { edgePreparedPayloadHash } from "../edge-adapter-runtime.js";
import type { RelayConversation } from "../relay-conversation-store.js";
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
import { createTelclaudeMcpLedgerExecuteDependencies } from "./ledger-execute.js";
import { createNotConfiguredTelclaudeMcpCapabilityClients } from "./live-relay-clients.js";
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
			})
			.strict(),
		runnerAttestation: SideEffectLedgerAttestationSchema.optional(),
	})
	.strict();

export type SideEffectLedgerProbeEvidence = z.infer<typeof SideEffectLedgerProbeEvidenceSchema>;
type ProbeCheck = z.infer<typeof SideEffectLedgerProbeCheckSchema>;

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
] as const;

export function runTelclaudeMcpSideEffectLedgerProbe(input: {
	readonly allowRun: boolean;
	readonly observedAt?: string;
}): Promise<SideEffectLedgerProbeEvidence> {
	return runProbe(input);
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

function createProbeVault(): TelclaudeMcpSideEffectApprovalSigner &
	TelclaudeMcpSideEffectApprovalSignatureVerifier {
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
			providerApprovalTokenIssuer: ({ providerId, service, action, approvalNonce }) =>
				`sidecar:${providerId}:${service}:${action}:${approvalNonce}`,
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
