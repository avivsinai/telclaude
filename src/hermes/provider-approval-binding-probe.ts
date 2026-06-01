import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { z } from "zod";
import { sortKeysDeep } from "../crypto/canonical-hash.js";
import {
	JtiStore as GoogleSidecarJtiStore,
	canonicalHash as googleSidecarCanonicalHash,
	verifyApprovalToken as verifyGoogleApprovalToken,
} from "../google-services/approval.js";
import type { FetchRequest } from "../google-services/types.js";
import { GOOGLE_APPROVAL_SIGNING_PREFIX } from "../security/approval-domains.js";
import {
	type HermesSignedEvidenceValidationOptions,
	hermesAllowsStaleAttestations,
	hermesAttestationFreshnessFailure,
} from "./attestation-validation.js";
import {
	createTelclaudeMcpSideEffectApprovalVerifier,
	generateTelclaudeMcpSideEffectApprovalToken,
	type TelclaudeMcpSideEffectApprovalSignatureVerifier,
	type TelclaudeMcpSideEffectApprovalSigner,
	TelclaudeMcpSideEffectJtiStore,
} from "./mcp/approval-token.js";
import {
	createTelclaudeMcpBridge,
	type TelclaudeMcpAuthority,
	type TelclaudeMcpBridgeDependencies,
} from "./mcp/bridge.js";
import { createTelclaudeMcpLedgerExecuteDependencies } from "./mcp/ledger-execute.js";
import {
	createGoogleProviderSidecarApprovalTokenIssuer,
	type GoogleProviderSidecarApprovalTokenSigner,
} from "./mcp/provider-sidecar-token.js";
import {
	createTelclaudeMcpSideEffectLedger,
	getTelclaudeMcpSideEffectApprovalBinding,
	type TelclaudeMcpProviderSideEffectPrepareInput,
	type TelclaudeMcpProviderSideEffectRecord,
	type TelclaudeMcpSideEffectLedger,
	type TelclaudeMcpSideEffectRecord,
} from "./mcp/side-effect-ledger.js";
import {
	PROVIDER_APPROVAL_BINDING_ATTESTATION_RUNNER,
	PROVIDER_APPROVAL_BINDING_ATTESTATION_SCHEMA_VERSION,
	PROVIDER_APPROVAL_BINDING_ATTESTATION_SOURCE,
	type ProviderApprovalBindingAttestation,
	providerApprovalBindingAttestationFieldsForEvidence,
	providerApprovalBindingAttestationSignatureFailure,
	signProviderApprovalBindingAttestation,
} from "./provider-approval-binding-attestation.js";

export const DEFAULT_PROVIDER_APPROVAL_BINDING_EVIDENCE_PATH =
	"artifacts/hermes/probes/providers-approval-binding.json";
export const PROVIDER_APPROVAL_BINDING_PROBE_SCHEMA_VERSION =
	"telclaude.hermes.provider-approval-binding-probe.v1";
export const PROVIDER_APPROVAL_BINDING_PROBE_SOURCE = "telclaude-provider-approval-binding-harness";

const NonEmptyString = z.string().trim().min(1);
const Sha256Digest = z.string().regex(/^sha256:[a-f0-9]{64}$/i);
const HexSha256Digest = z.string().regex(/^[a-f0-9]{64}$/);
const PROBE_VAULT_SECRET = "telclaude-hermes-provider-approval-binding-probe";

const ProviderApprovalBindingProbeCheckSchema = z
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

const ProviderApprovalBindingAttestationSchema = z
	.object({
		schemaVersion: z.literal(PROVIDER_APPROVAL_BINDING_ATTESTATION_SCHEMA_VERSION),
		source: z.literal(PROVIDER_APPROVAL_BINDING_ATTESTATION_SOURCE),
		runner: z.literal(PROVIDER_APPROVAL_BINDING_ATTESTATION_RUNNER),
		probeEvidenceSchemaVersion: z.literal(PROVIDER_APPROVAL_BINDING_PROBE_SCHEMA_VERSION),
		probeId: z.literal("providers.approval-binding"),
		status: z.enum(["pass", "fail"]),
		ran: z.boolean(),
		observedAt: NonEmptyString,
		checksSha256: Sha256Digest,
		observationsSha256: Sha256Digest,
		evidenceSha256: Sha256Digest,
		signature: InternalResponseProofSchema,
	})
	.strict();

export const ProviderApprovalBindingProbeEvidenceSchema = z
	.object({
		schemaVersion: z.literal(PROVIDER_APPROVAL_BINDING_PROBE_SCHEMA_VERSION),
		probeId: z.literal("providers.approval-binding"),
		status: z.enum(["pass", "fail"]),
		ran: z.boolean(),
		observedAt: NonEmptyString,
		source: z.literal(PROVIDER_APPROVAL_BINDING_PROBE_SOURCE),
		summary: NonEmptyString,
		checks: z.array(ProviderApprovalBindingProbeCheckSchema).min(1),
		observations: z
			.object({
				actionRef: NonEmptyString.optional(),
				contentHash: Sha256Digest.optional(),
				paramsHash: Sha256Digest.optional(),
				bodyHash: Sha256Digest.optional(),
				verifierCallCount: z.number().int().nonnegative(),
				providerProxyCallCount: z.number().int().nonnegative(),
				googleSidecarParamsHash: Sha256Digest.optional(),
				hermesTokenSidecarRejectCode: NonEmptyString.optional(),
			})
			.strict(),
		runnerAttestation: ProviderApprovalBindingAttestationSchema.optional(),
	})
	.strict();

export type ProviderApprovalBindingProbeEvidence = z.infer<
	typeof ProviderApprovalBindingProbeEvidenceSchema
>;
type ProbeCheck = z.infer<typeof ProviderApprovalBindingProbeCheckSchema>;

const REQUIRED_PROVIDER_APPROVAL_BINDING_CHECKS = [
	"provider.approval-binding.prepare-hashes",
	"provider.approval-binding.content-hash",
	"provider.approval-binding.valid-token-executes",
	"provider.approval-binding.proxy-relay",
	"provider.approval-binding.hermes-approval-token-input-denied",
	"provider.approval-binding.params-mutation-denied",
	"provider.approval-binding.wrong-actor-denied",
	"provider.approval-binding.service-action-mismatch-denied",
	"provider.approval-binding.expired-ref-denied",
	"provider.approval-binding.revoked-ref-denied",
	"provider.approval-binding.executed-ref-replay-denied",
	"provider.approval-binding.duplicate-jti-denied",
	"provider.approval-binding.google-sidecar-token-roundtrip",
	"provider.approval-binding.hermes-token-sidecar-rejected",
] as const;

export async function runTelclaudeProviderApprovalBindingProbe(input: {
	readonly allowRun: boolean;
	readonly observedAt?: string;
}): Promise<ProviderApprovalBindingProbeEvidence> {
	const observedAt = input.observedAt ?? new Date().toISOString();
	if (input.allowRun !== true) {
		return {
			schemaVersion: PROVIDER_APPROVAL_BINDING_PROBE_SCHEMA_VERSION,
			probeId: "providers.approval-binding",
			status: "fail",
			ran: false,
			observedAt,
			source: PROVIDER_APPROVAL_BINDING_PROBE_SOURCE,
			summary: "provider approval-binding harness was not allowed to run",
			checks: [
				{
					name: "provider.approval-binding.prepare-hashes",
					status: "fail",
					detail: "run with --allow-run to execute the deterministic provider harness",
				},
			],
			observations: {
				verifierCallCount: 0,
				providerProxyCallCount: 0,
			},
		};
	}

	const checks: ProbeCheck[] = [];
	const observations: ProviderApprovalBindingProbeEvidence["observations"] = {
		verifierCallCount: 0,
		providerProxyCallCount: 0,
	};
	const jtiDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-provider-approval-jti-"));
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
			makeRef: () => `provider-approval-probe-${++nextRef}`,
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
			() => nowMs,
			async (request) => {
				providerProxyCalls.push(request);
				observations.providerProxyCallCount = providerProxyCalls.length;
				return { status: "ok", data: { accepted: true } };
			},
		);

		const prepared = ledger.prepare(providerPrepareInput());
		const binding = getTelclaudeMcpSideEffectApprovalBinding(prepared);
		observations.actionRef = prepared.ref;
		observations.paramsHash = prepared.paramsHash;
		observations.bodyHash = prepared.bodyHash;
		observations.contentHash = binding.contentHash;

		pushCheck(
			checks,
			"provider.approval-binding.prepare-hashes",
			isSha256(prepared.paramsHash) &&
				isSha256(prepared.bodyHash) &&
				prepared.paramsHash !== prepared.bodyHash &&
				prepared.status === "prepared",
			"prepared provider action has immutable canonical params/body hashes",
		);
		pushCheck(
			checks,
			"provider.approval-binding.content-hash",
			isSha256(binding.contentHash) &&
				binding.kind === "provider" &&
				binding.contentHash !== prepared.bodyHash,
			"provider approval token binding is domain-separated and provider-kind specific",
		);

		const token = await generateProbeToken(prepared, vault, "provider-approval-valid");
		const hermesTokenInputResult = await bridge
			.tc_provider_execute_write({
				actionRef: prepared.ref,
				approvalToken: token,
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
			"provider.approval-binding.hermes-approval-token-input-denied",
			hermesTokenInputResult.ok === false &&
				hermesTokenInputResult.code === "schema_rejected" &&
				observations.verifierCallCount === 0 &&
				providerProxyCalls.length === 0 &&
				ledger.get(prepared.ref)?.status === "prepared",
			"Hermes-facing provider execute rejects approvalToken input before verifier or proxy use",
		);
		providerApprovals.set(prepared.ref, token);
		const executed = resultShape(
			await bridge.tc_provider_execute_write({
				actionRef: prepared.ref,
			}),
		);
		pushCheck(
			checks,
			"provider.approval-binding.valid-token-executes",
			executed.ok === true &&
				executed.record?.ref === prepared.ref &&
				executed.record?.status === "executed" &&
				executed.record?.approvalId === "provider-approval-valid",
			"valid vault-signed one-time provider token executes the prepared action",
		);
		pushCheck(
			checks,
			"provider.approval-binding.proxy-relay",
			providerProxyCalls.length === 1 &&
				providerProxyCalls.some((call) =>
					providerProxyCallPassed(call, prepared, sidecarApprovalTokenFor(prepared)),
				),
			"executed provider action is delivered only through the relay provider proxy",
		);

		const originalForMutation = ledger.prepare(
			providerPrepareInput({ approvalRequestId: "mutation-original" }),
		);
		const mutated = ledger.prepare(
			providerPrepareInput({
				approvalRequestId: "mutation-mutated",
				params: { amount: 101, currency: "ILS", recipient: "vendor-ref" },
			}),
		);
		const mutationToken = await generateProbeToken(
			originalForMutation,
			vault,
			"provider-approval-mutation",
		);
		providerApprovals.set(mutated.ref, mutationToken);
		const mutationResult = resultShape(
			await bridge.tc_provider_execute_write({
				actionRef: mutated.ref,
			}),
		);
		pushCheck(
			checks,
			"provider.approval-binding.params-mutation-denied",
			mutationResult.ok === false &&
				mutationResult.code === "approval_mismatch" &&
				mutationResult.retryable === true &&
				mutationResult.record?.status === "prepared",
			"approval token bound to original params cannot authorize mutated provider params",
		);

		const wrongActor = ledger.prepare(
			providerPrepareInput({ actorId: "other-actor", approvalRequestId: "wrong-actor" }),
		);
		const wrongActorResult = resultShape(
			await bridge.tc_provider_execute_write({
				actionRef: wrongActor.ref,
			}),
		);
		pushCheck(
			checks,
			"provider.approval-binding.wrong-actor-denied",
			wrongActorResult.ok === false &&
				wrongActorResult.code === "effect_authority_mismatch" &&
				wrongActorResult.retryable === false &&
				ledger.get(wrongActor.ref)?.status === "prepared",
			"provider prepared actions are bound to the wrapper-stamped actor/profile/domain",
		);

		const originalForService = ledger.prepare(
			providerPrepareInput({ approvalRequestId: "service-original" }),
		);
		const serviceMismatch = ledger.prepare(
			providerPrepareInput({
				providerId: "clalit",
				service: "clalit",
				action: "booking.prepare",
				providerAccountRef: "clalit:primary",
				approvalRequestId: "service-mismatch",
			}),
		);
		const serviceToken = await generateProbeToken(
			originalForService,
			vault,
			"provider-approval-service",
		);
		providerApprovals.set(serviceMismatch.ref, serviceToken);
		const serviceResult = resultShape(
			await bridge.tc_provider_execute_write({
				actionRef: serviceMismatch.ref,
			}),
		);
		pushCheck(
			checks,
			"provider.approval-binding.service-action-mismatch-denied",
			serviceResult.ok === false &&
				serviceResult.code === "approval_mismatch" &&
				serviceResult.retryable === true &&
				serviceResult.record?.status === "prepared",
			"approval token bound to one service/action cannot authorize another provider action",
		);

		const expired = ledger.prepare(
			providerPrepareInput({ ttlMs: 1, approvalRequestId: "expired-ref" }),
		);
		nowMs = 100_002;
		const expiredResult = resultShape(
			await bridge.tc_provider_execute_write({
				actionRef: expired.ref,
			}),
		);
		nowMs = 100_000;
		pushCheck(
			checks,
			"provider.approval-binding.expired-ref-denied",
			expiredResult.ok === false &&
				expiredResult.code === "effect_expired" &&
				expiredResult.retryable === false,
			"expired provider prepared refs fail closed before approval verification",
		);

		const revoked = ledger.prepare(providerPrepareInput({ approvalRequestId: "revoked-ref" }));
		ledger.revoke(revoked.ref, "operator cancelled");
		const revokedResult = resultShape(
			await bridge.tc_provider_execute_write({
				actionRef: revoked.ref,
			}),
		);
		pushCheck(
			checks,
			"provider.approval-binding.revoked-ref-denied",
			revokedResult.ok === false &&
				revokedResult.code === "effect_revoked" &&
				revokedResult.retryable === false &&
				revokedResult.record?.status === "revoked",
			"revoked provider prepared refs fail closed before approval verification",
		);

		const replayResult = resultShape(
			await bridge.tc_provider_execute_write({
				actionRef: prepared.ref,
			}),
		);
		pushCheck(
			checks,
			"provider.approval-binding.executed-ref-replay-denied",
			replayResult.ok === false &&
				replayResult.code === "effect_already_executed" &&
				replayResult.retryable === false,
			"executed provider refs remain terminal and cannot be replayed",
		);

		const duplicate = ledger.prepare(providerPrepareInput({ approvalRequestId: "duplicate-jti" }));
		const duplicateBinding = getTelclaudeMcpSideEffectApprovalBinding(duplicate);
		const duplicateToken = await generateProbeToken(
			duplicate,
			vault,
			"provider-approval-duplicate",
		);
		observations.verifierCallCount += 1;
		const firstJti = await verifier({
			approvalToken: duplicateToken,
			binding: duplicateBinding,
			record: duplicate,
			nowMs,
		});
		observations.verifierCallCount += 1;
		const secondJti = await verifier({
			approvalToken: duplicateToken,
			binding: duplicateBinding,
			record: duplicate,
			nowMs,
		});
		pushCheck(
			checks,
			"provider.approval-binding.duplicate-jti-denied",
			firstJti.ok === true && secondJti.ok === false && secondJti.code === "approval_replayed",
			"approval verifier atomically rejects duplicate JTI reuse",
		);

		await runGoogleSidecarTokenChecks({
			checks,
			observations,
			ledger,
			vault,
		});
	} catch (error) {
		checks.push({
			name: "provider.approval-binding.exception",
			status: "fail",
			detail: error instanceof Error ? error.message : String(error),
		});
	} finally {
		jtiStore.close();
		fs.rmSync(jtiDir, { recursive: true, force: true });
	}

	const status =
		checks.length > 0 && checks.every((check) => check.status === "pass") ? "pass" : "fail";
	const evidence: Omit<ProviderApprovalBindingProbeEvidence, "runnerAttestation"> = {
		schemaVersion: PROVIDER_APPROVAL_BINDING_PROBE_SCHEMA_VERSION,
		probeId: "providers.approval-binding",
		status,
		ran: true,
		observedAt,
		source: PROVIDER_APPROVAL_BINDING_PROBE_SOURCE,
		summary:
			status === "pass"
				? "Provider approval-binding probe passed"
				: "Provider approval-binding probe failed",
		checks,
		observations,
	};
	return status === "pass"
		? {
				...evidence,
				runnerAttestation: signProviderApprovalBindingAttestation(
					evidence,
				) as ProviderApprovalBindingProbeEvidence["runnerAttestation"],
			}
		: evidence;
}

export function providerApprovalBindingProbeEvidenceFailure(
	evidence: unknown,
	options: HermesSignedEvidenceValidationOptions = {},
): string | null {
	const parsed = ProviderApprovalBindingProbeEvidenceSchema.safeParse(evidence);
	if (!parsed.success) {
		return `invalid provider approval-binding evidence: ${flattenZodError(parsed.error)}`;
	}
	const data = parsed.data;
	const failures: string[] = [];
	if (data.status !== "pass") failures.push(`status is ${data.status}`);
	if (data.ran !== true) failures.push("harness did not run");
	const attestationFailure = providerApprovalBindingRunnerAttestationFailure(data, options);
	if (attestationFailure) failures.push(attestationFailure);
	const checksByName = new Map(data.checks.map((check) => [check.name, check]));
	for (const duplicate of duplicates(data.checks.map((check) => check.name))) {
		failures.push(`duplicate check ${duplicate}`);
	}
	for (const name of REQUIRED_PROVIDER_APPROVAL_BINDING_CHECKS) {
		const check = checksByName.get(name);
		if (!check) {
			failures.push(`check ${name} is missing`);
		} else if (check.status !== "pass") {
			failures.push(`check ${name} is ${check.status}`);
		}
	}
	if (data.observations.verifierCallCount < 5) {
		failures.push("verifierCallCount is too low to prove approval mismatch paths");
	}
	if (data.observations.providerProxyCallCount !== 1) {
		failures.push(`providerProxyCallCount is ${data.observations.providerProxyCallCount}`);
	}
	if (
		!data.observations.paramsHash ||
		!data.observations.bodyHash ||
		!data.observations.contentHash
	) {
		failures.push("provider hash observations are incomplete");
	} else if (
		data.observations.contentHash === data.observations.bodyHash ||
		data.observations.contentHash === data.observations.paramsHash
	) {
		failures.push("provider contentHash is not domain-separated from params/body hashes");
	}
	return failures.length > 0 ? failures.join("; ") : null;
}

function providerApprovalBindingRunnerAttestationFailure(
	evidence: ProviderApprovalBindingProbeEvidence,
	options: HermesSignedEvidenceValidationOptions,
): string | null {
	const attestation = evidence.runnerAttestation as ProviderApprovalBindingAttestation | undefined;
	if (!attestation) return "runnerAttestation is missing";
	const freshnessFailure = hermesAttestationFreshnessFailure(
		"runnerAttestation observedAt",
		attestation.observedAt,
		options,
	);
	if (freshnessFailure) return freshnessFailure;
	const signatureFailure = providerApprovalBindingAttestationSignatureFailure(attestation, {
		allowStale: hermesAllowsStaleAttestations(options),
	});
	if (signatureFailure) return `runnerAttestation signature is invalid: ${signatureFailure}`;
	const expected = providerApprovalBindingAttestationFieldsForEvidence(evidence);
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

async function runGoogleSidecarTokenChecks(input: {
	readonly checks: ProbeCheck[];
	readonly observations: ProviderApprovalBindingProbeEvidence["observations"];
	readonly ledger: TelclaudeMcpSideEffectLedger;
	readonly vault: TelclaudeMcpSideEffectApprovalSigner & GoogleProviderSidecarApprovalTokenSigner;
}): Promise<void> {
	const googleRecord = input.ledger.prepare(
		providerPrepareInput({
			providerId: "google",
			service: "gmail",
			action: "create_draft",
			params: {
				to: "operator@example.com",
				subject: "Hermes sidecar proof",
				body: "approval token roundtrip",
			},
			providerAccountRef: "google:gmail:primary",
			approvalRequestId: "google-sidecar-roundtrip",
			wysiwysRender: "google.gmail.create_draft",
		}),
	) as TelclaudeMcpProviderSideEffectRecord;
	const fetchRequest = fetchRequestForGoogleRecord(googleRecord);
	const sidecarDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-google-sidecar-jti-"));
	const sidecarJtiStore = new GoogleSidecarJtiStore(sidecarDir);
	try {
		const issuer = createGoogleProviderSidecarApprovalTokenIssuer({
			vaultClient: input.vault,
		});
		const sidecarToken = await issuer({
			record: googleRecord,
			providerId: googleRecord.providerId,
			service: googleRecord.service,
			action: googleRecord.action,
			params: googleRecord.params,
			actorUserId: googleRecord.actorId,
			approvalNonce: googleRecord.approvalRequestId,
		});
		const sidecarClaims = tokenClaims(sidecarToken);
		input.observations.googleSidecarParamsHash =
			typeof sidecarClaims.paramsHash === "string" ? sidecarClaims.paramsHash : undefined;
		const sidecarAccepted = verifyGoogleApprovalToken(
			sidecarToken,
			fetchRequest,
			googleRecord.actorId,
			verifyGoogleApprovalSignature,
			sidecarJtiStore,
		);
		const sidecarReplay = verifyGoogleApprovalToken(
			sidecarToken,
			fetchRequest,
			googleRecord.actorId,
			verifyGoogleApprovalSignature,
			sidecarJtiStore,
		);
		pushCheck(
			input.checks,
			"provider.approval-binding.google-sidecar-token-roundtrip",
			sidecarAccepted.ok === true &&
				sidecarReplay.ok === false &&
				sidecarReplay.code === "approval_replayed" &&
				sidecarClaims.paramsHash ===
					verifyGoogleParamsHash(googleRecord, sidecarClaims.subjectUserId),
			"relay-minted Google sidecar token passes sidecar verification and is one-time",
		);

		const hermesToken = await generateProbeToken(
			googleRecord,
			input.vault,
			"provider-approval-hermes-sidecar-reject",
		);
		const hermesRejected = verifyGoogleApprovalToken(
			hermesToken,
			fetchRequest,
			googleRecord.actorId,
			verifyGoogleApprovalSignature,
			sidecarJtiStore,
		);
		input.observations.hermesTokenSidecarRejectCode = hermesRejected.ok
			? "accepted"
			: hermesRejected.code;
		pushCheck(
			input.checks,
			"provider.approval-binding.hermes-token-sidecar-rejected",
			hermesRejected.ok === false && hermesRejected.code === "approval_required",
			"Hermes MCP side-effect tokens are rejected by the Google sidecar approval-v1 verifier",
		);
	} finally {
		sidecarJtiStore.close();
		fs.rmSync(sidecarDir, { recursive: true, force: true });
	}
}

function createProbeVault(): TelclaudeMcpSideEffectApprovalSigner &
	TelclaudeMcpSideEffectApprovalSignatureVerifier &
	GoogleProviderSidecarApprovalTokenSigner {
	return {
		async signPayload(payload, prefix) {
			return {
				type: "sign-payload" as const,
				signature: signature(PROBE_VAULT_SECRET, payload, prefix),
			};
		},
		async verifyPayload(payload, sig, prefix) {
			return {
				type: "verify-payload",
				valid: safeEqual(sig, signature(PROBE_VAULT_SECRET, payload, prefix)),
			};
		},
	};
}

function verifyGoogleApprovalSignature(payload: string, sig: string): boolean {
	return safeEqual(sig, signature(PROBE_VAULT_SECRET, payload, GOOGLE_APPROVAL_SIGNING_PREFIX));
}

function tokenClaims(token: string): Record<string, unknown> {
	const [, claimsB64] = token.split(".");
	if (!claimsB64) return {};
	try {
		return JSON.parse(Buffer.from(claimsB64, "base64url").toString("utf8")) as Record<
			string,
			unknown
		>;
	} catch {
		return {};
	}
}

function fetchRequestForGoogleRecord(record: TelclaudeMcpSideEffectRecord): FetchRequest {
	if (record.kind !== "provider" || record.providerId !== "google") {
		throw new Error("record is not a Google provider action");
	}
	return {
		service: record.service as FetchRequest["service"],
		action: record.action,
		params: record.params,
	};
}

function verifyGoogleParamsHash(
	record: TelclaudeMcpSideEffectRecord,
	subjectUserId: unknown,
): string | null {
	if (record.kind !== "provider" || record.providerId !== "google") return null;
	return googleSidecarCanonicalHash({
		service: record.service,
		action: record.action,
		params: record.params,
		actorUserId: record.actorId,
		subjectUserId: typeof subjectUserId === "string" ? subjectUserId : null,
	});
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
	nowMs: () => number,
	providerProxy: Parameters<typeof createTelclaudeMcpLedgerExecuteDependencies>[0]["providerProxy"],
) {
	return createTelclaudeMcpBridge(probeAuthority(), {
		...baseDependencies(),
		...createTelclaudeMcpLedgerExecuteDependencies({
			ledger,
			providerProxy,
			providerApprovalTokenResolver: ({ actionRef }) => {
				const approvalToken = providerApprovals.get(actionRef);
				if (!approvalToken) {
					return {
						ok: false,
						code: "approval_token_unavailable",
						reason: "server-side approval token is unavailable",
						retryable: true,
					};
				}
				providerApprovals.delete(actionRef);
				return { ok: true, approvalToken };
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
		providerScopes: ["bank", "clalit"],
		outboundChannels: ["whatsapp"],
		endpointId: "endpoint-private",
		networkNamespace: "netns-private",
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
		approvalRequestId: "provider-approval-binding-probe",
		approvalRevision: 1,
		wysiwysRender: "Prepare ILS 100 transfer to vendor-ref",
		idempotencyKey: "provider-approval-binding-probe",
		...overrides,
	};
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
