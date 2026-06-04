import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { z } from "zod";
import { sortKeysDeep } from "../crypto/canonical-hash.js";
import { JtiStore, verifyApprovalToken } from "../google-services/approval.js";
import type { FetchRequest } from "../google-services/types.js";
import type { ProviderProxyRequest } from "../relay/provider-proxy.js";
import { GOOGLE_APPROVAL_SIGNING_PREFIX } from "../security/approval-domains.js";
import type { HermesSignedEvidenceValidationOptions } from "./attestation-validation.js";
import { createTelclaudeMcpBridge, type TelclaudeMcpAuthority } from "./mcp/bridge.js";
import { createTelclaudeMcpLedgerExecuteDependencies } from "./mcp/ledger-execute.js";
import { createTelclaudeLiveMcpRelayClients } from "./mcp/live-relay-clients.js";
import {
	createGoogleProviderSidecarApprovalTokenIssuer,
	type GoogleProviderSidecarApprovalTokenSigner,
} from "./mcp/provider-sidecar-token.js";
import {
	createTelclaudeMcpSideEffectLedger,
	getTelclaudeMcpSideEffectApprovalBinding,
	type TelclaudeMcpProviderSideEffectPrepareInput,
	type TelclaudeMcpProviderSideEffectRecord,
	type TelclaudeMcpSideEffectApprovalVerification,
	type TelclaudeMcpSideEffectLedger,
	type TelclaudeMcpSideEffectRecord,
} from "./mcp/side-effect-ledger.js";
import { networkProbeEvidenceFailure } from "./network-probe-evidence-validation.js";
import { NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION } from "./network-probe-schema.js";

export const DEFAULT_PROVIDER_GOOGLE_EVIDENCE_PATH =
	"artifacts/hermes/probes/providers-google.json";
export const PROVIDER_GOOGLE_PROBE_SCHEMA_VERSION = "telclaude.hermes.provider-google-probe.v1";
export const PROVIDER_GOOGLE_PROBE_SOURCE = "telclaude-google-provider-harness";
export const PROVIDER_GOOGLE_FIXTURE_EVIDENCE_SCHEMA_VERSION =
	"telclaude.hermes.provider-google-fixture-evidence.v1";
export const PROVIDER_GOOGLE_FIXTURE_SOURCE = "machine-observed-google-provider-probe";
export const PROVIDER_GOOGLE_FIXTURE_RUNNER = "telclaude-google-provider-fixture-generator";
export const DEFAULT_PROVIDER_GOOGLE_FIXTURE_EVIDENCE_DIR = "artifacts/hermes/fixtures";
export const DEFAULT_PROVIDER_GOOGLE_DIRECT_NETWORK_EVIDENCE_PATH =
	"artifacts/hermes/network/direct-provider-denied.json";

const NonEmptyString = z.string().trim().min(1);
const Sha256Digest = z.string().regex(/^sha256:[a-f0-9]{64}$/i);
const GOOGLE_PROBE_SECRET = "telclaude-hermes-google-provider-probe";

const GoogleProviderProbeCheckSchema = z
	.object({
		name: NonEmptyString,
		status: z.enum(["pass", "fail"]),
		detail: NonEmptyString,
	})
	.strict();

const GoogleProviderDirectNetworkAttemptSchema = z
	.object({
		name: NonEmptyString,
		kind: z.literal("http"),
		target: NonEmptyString,
		expectation: z.literal("deny"),
		status: z.enum(["pass", "fail"]),
		observed: NonEmptyString,
		detail: NonEmptyString,
	})
	.passthrough();

const GoogleProviderDirectNetworkProbeEvidenceSchema = z
	.object({
		schemaVersion: z.literal(NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION),
		id: z.literal("network.direct-provider-denied"),
		posture: z.enum(["agent-iptables", "contained-internal"]),
		status: z.enum(["pass", "fail", "pending"]),
		ran: z.boolean(),
		summary: NonEmptyString,
		generatedAt: NonEmptyString,
		evidence_path: NonEmptyString,
		attempts: z.array(GoogleProviderDirectNetworkAttemptSchema).min(1),
	})
	.passthrough();

type GoogleProviderDirectNetworkProbeEvidence = z.infer<
	typeof GoogleProviderDirectNetworkProbeEvidenceSchema
>;

export const GoogleProviderProbeEvidenceSchema = z
	.object({
		schemaVersion: z.literal(PROVIDER_GOOGLE_PROBE_SCHEMA_VERSION),
		probeId: z.literal("providers.google"),
		status: z.enum(["pass", "fail"]),
		ran: z.boolean(),
		observedAt: NonEmptyString,
		source: z.literal(PROVIDER_GOOGLE_PROBE_SOURCE),
		summary: NonEmptyString,
		checks: z.array(GoogleProviderProbeCheckSchema).min(1),
		observations: z
			.object({
				actionRef: NonEmptyString.optional(),
				approvalVerifierCallCount: z.number().int().nonnegative(),
				providerProxyCallCount: z.number().int().nonnegative(),
				sidecarVerifierCallCount: z.number().int().nonnegative(),
				ledgerReplayCode: NonEmptyString.optional(),
				sidecarReplayCode: NonEmptyString.optional(),
				readRequestBodyHash: Sha256Digest.optional(),
				writeRequestBodyHash: Sha256Digest.optional(),
				sidecarParamsHash: Sha256Digest.optional(),
				rawOAuthObserved: z.boolean(),
			})
			.strict(),
	})
	.strict();

export type GoogleProviderProbeEvidence = z.infer<typeof GoogleProviderProbeEvidenceSchema>;
type ProbeCheck = z.infer<typeof GoogleProviderProbeCheckSchema>;

const REQUIRED_GOOGLE_PROVIDER_CHECKS = [
	"google.read-through-provider-proxy",
	"google.prepare-write-ledger-bound",
	"google.approved-write-sidecar-token",
	"google.wrong-actor-denied",
	"google.replay-denied",
	"google.raw-oauth-not-observed",
] as const;

type GoogleProviderFixtureRequirement = {
	readonly id: string;
	readonly kind?: "google-provider" | "direct-provider-deny";
	readonly requiredChecks: readonly string[];
	readonly requiredObservationHashes: readonly (keyof Pick<
		GoogleProviderProbeEvidence["observations"],
		"readRequestBodyHash" | "sidecarParamsHash" | "writeRequestBodyHash"
	>)[];
	readonly networkAttemptName?: "provider:google";
};

export const GOOGLE_PROVIDER_FIXTURE_REQUIREMENTS = [
	{
		id: "fixture.providers.google.read",
		requiredChecks: ["google.read-through-provider-proxy", "google.raw-oauth-not-observed"],
		requiredObservationHashes: ["readRequestBodyHash"],
	},
	{
		id: "fixture.providers.google.prepare-write",
		requiredChecks: ["google.prepare-write-ledger-bound", "google.raw-oauth-not-observed"],
		requiredObservationHashes: ["sidecarParamsHash"],
	},
	{
		id: "fixture.providers.google.approved-write",
		requiredChecks: ["google.approved-write-sidecar-token", "google.raw-oauth-not-observed"],
		requiredObservationHashes: ["writeRequestBodyHash", "sidecarParamsHash"],
	},
	{
		id: "fixture.providers.google.wrong-actor-deny",
		requiredChecks: ["google.wrong-actor-denied"],
		requiredObservationHashes: ["sidecarParamsHash"],
	},
	{
		id: "fixture.providers.google.replay-deny",
		requiredChecks: ["google.replay-denied"],
		requiredObservationHashes: ["sidecarParamsHash"],
	},
	{
		id: "fixture.providers.google.direct-provider-deny",
		kind: "direct-provider-deny",
		requiredChecks: [],
		requiredObservationHashes: [],
		networkAttemptName: "provider:google",
	},
] as const satisfies readonly GoogleProviderFixtureRequirement[];

export type GoogleProviderFixtureId = (typeof GOOGLE_PROVIDER_FIXTURE_REQUIREMENTS)[number]["id"];

export async function runTelclaudeGoogleProviderProbe(input: {
	readonly allowRun: boolean;
	readonly observedAt?: string;
}): Promise<GoogleProviderProbeEvidence> {
	const observedAt = input.observedAt ?? new Date().toISOString();
	if (input.allowRun !== true) {
		return {
			schemaVersion: PROVIDER_GOOGLE_PROBE_SCHEMA_VERSION,
			probeId: "providers.google",
			status: "fail",
			ran: false,
			observedAt,
			source: PROVIDER_GOOGLE_PROBE_SOURCE,
			summary: "Google provider harness was not allowed to run",
			checks: [
				{
					name: "google.read-through-provider-proxy",
					status: "fail",
					detail: "run with --allow-run to execute the deterministic Google provider harness",
				},
			],
			observations: {
				approvalVerifierCallCount: 0,
				providerProxyCallCount: 0,
				sidecarVerifierCallCount: 0,
				rawOAuthObserved: false,
			},
		};
	}

	const checks: ProbeCheck[] = [];
	const observations: GoogleProviderProbeEvidence["observations"] = {
		approvalVerifierCallCount: 0,
		providerProxyCallCount: 0,
		sidecarVerifierCallCount: 0,
		rawOAuthObserved: false,
	};
	const providerProxyCalls: ProviderProxyRequest[] = [];
	const harness = createLedgerHarness();
	const vault = createProbeVault();
	const sidecarDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-google-provider-jti-"));
	const sidecarJtiStore = new JtiStore(sidecarDir);

	const providerProxy = async (request: ProviderProxyRequest) => {
		providerProxyCalls.push(request);
		observations.providerProxyCallCount = providerProxyCalls.length;
		if (request.approvalMode === "preapproved-ledger") {
			const body = parseFetchRequest(request.body);
			const sidecarToken = request.approvalToken ?? "";
			const accepted = verifyApprovalToken(
				sidecarToken,
				body,
				request.userId ?? "",
				(payload, signatureValue) =>
					verifyProbeSignature(payload, signatureValue, GOOGLE_APPROVAL_SIGNING_PREFIX),
				sidecarJtiStore,
			);
			observations.sidecarVerifierCallCount += 1;
			const replay = verifyApprovalToken(
				sidecarToken,
				body,
				request.userId ?? "",
				(payload, signatureValue) =>
					verifyProbeSignature(payload, signatureValue, GOOGLE_APPROVAL_SIGNING_PREFIX),
				sidecarJtiStore,
			);
			observations.sidecarVerifierCallCount += 1;
			observations.sidecarReplayCode = replay.ok ? "accepted" : replay.code;
			observations.sidecarParamsHash = sidecarParamsHash(sidecarToken);
			if (!accepted.ok) {
				return {
					status: "error" as const,
					errorCode: accepted.code,
					error: "Google sidecar rejected approval token",
				};
			}
			return { status: "ok" as const, data: { draftId: "draft_probe" } };
		}
		return { status: "ok" as const, data: { messages: [{ id: "msg_probe" }] } };
	};

	try {
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger: harness.ledger,
			makeApprovalRequestId: makeApprovalIds(),
			providerProxy,
			providerWriteApproverActorId: "operator:google-provider-probe-approver",
		});

		const readResult = await clients.providerRead({
			...authorityStamp(),
			providerId: "google",
			service: "google",
			action: "gmail.search",
			params: { q: "from:clinic newer_than:7d" },
		});
		const readCall = providerProxyCalls[0];
		observations.readRequestBodyHash = requestBodyHash(readCall);
		pushCheck(
			checks,
			"google.read-through-provider-proxy",
			providerProxyCalls.length === 1 &&
				googleProviderProxyCallMatches(readCall, {
					service: "gmail",
					action: "search",
					params: { q: "from:clinic newer_than:7d" },
					preapproved: false,
				}) &&
				JSON.stringify(readResult) === JSON.stringify({ messages: [{ id: "msg_probe" }] }),
			"Google read is routed through the relay provider proxy with service/action splitting",
		);

		const prepared = (await clients.providerPrepareWrite({
			...authorityStamp(),
			providerId: "google",
			service: "google",
			action: "gmail.create_draft",
			params: { to: "family@example.com", subject: "Clinic follow-up", body: "Booked." },
			idempotencyKey: "google-provider-probe",
		})) as { actionRef?: string; approvalRequestId?: string };
		const record = harness.ledger.get(prepared.actionRef ?? "");
		const providerRecord = isGoogleProviderRecord(record) ? record : undefined;
		observations.actionRef = providerRecord?.ref ?? record?.ref;
		pushCheck(
			checks,
			"google.prepare-write-ledger-bound",
			providerRecord !== undefined &&
				providerRecord.status === "prepared" &&
				providerRecord.providerId === "google" &&
				providerRecord.service === "gmail" &&
				providerRecord.action === "create_draft" &&
				providerRecord.providerAccountRef === "google:gmail:primary" &&
				prepared.approvalRequestId === "approval-1" &&
				providerProxyCalls.length === 1,
			"Google write preparation creates an unexecuted, ledger-bound provider action",
		);

		if (!providerRecord) {
			throw new Error("Google provider probe failed to prepare a provider record");
		}
		harness.accept("operator-approved-google-write", providerRecord);
		const bridge = createExecuteBridge(harness, providerProxy, vault);
		const executed = resultShape(
			await bridge.tc_provider_execute_write({
				actionRef: providerRecord.ref,
			}),
		);
		observations.approvalVerifierCallCount = harness.verifierCalls.length;
		const writeCall = providerProxyCalls[1];
		observations.writeRequestBodyHash = requestBodyHash(writeCall);
		pushCheck(
			checks,
			"google.approved-write-sidecar-token",
			executed.ok === true &&
				executed.record?.ref === providerRecord.ref &&
				executed.record?.status === "executed" &&
				googleProviderProxyCallMatches(writeCall, {
					service: "gmail",
					action: "create_draft",
					params: providerRecord.params,
					preapproved: true,
				}) &&
				writeCall?.approvalToken !== "operator-approved-google-write" &&
				typeof writeCall?.approvalToken === "string" &&
				writeCall.approvalToken.startsWith("v1.") &&
				observations.sidecarReplayCode === "approval_replayed",
			"Approved Google write is executed through a relay-minted sidecar token that the sidecar verifies as one-time",
		);

		const wrongActorRecord = harness.ledger.prepare({
			...googleProviderPrepareInput(),
			approvalRequestId: "approval-wrong-actor",
		});
		harness.accept("wrong-actor-token", wrongActorRecord);
		const providerCallsBeforeWrongActor = providerProxyCalls.length;
		const wrongActorBridge = createExecuteBridge(harness, providerProxy, vault, {
			actorId: "other-operator",
		});
		const wrongActor = resultShape(
			await wrongActorBridge.tc_provider_execute_write({
				actionRef: wrongActorRecord.ref,
			}),
		);
		pushCheck(
			checks,
			"google.wrong-actor-denied",
			wrongActor.ok === false &&
				wrongActor.code === "effect_authority_mismatch" &&
				providerProxyCalls.length === providerCallsBeforeWrongActor,
			"Google provider writes fail closed when the executing actor does not match the prepared ref",
		);

		const providerCallsBeforeReplay = providerProxyCalls.length;
		const replay = resultShape(
			await bridge.tc_provider_execute_write({
				actionRef: providerRecord.ref,
			}),
		);
		observations.ledgerReplayCode = typeof replay.code === "string" ? replay.code : undefined;
		pushCheck(
			checks,
			"google.replay-denied",
			replay.ok === false &&
				replay.code === "effect_already_executed" &&
				observations.sidecarReplayCode === "approval_replayed" &&
				providerProxyCalls.length === providerCallsBeforeReplay,
			"Google provider replay is denied at the side-effect ledger and sidecar token layers",
		);

		observations.rawOAuthObserved = providerRequestsContainRawCredential(providerProxyCalls);
		pushCheck(
			checks,
			"google.raw-oauth-not-observed",
			observations.rawOAuthObserved === false,
			"Google proxy requests carry no raw OAuth/access/refresh credential material",
		);
	} finally {
		sidecarJtiStore.close();
		fs.rmSync(sidecarDir, { recursive: true, force: true });
	}

	const status = checks.every((check) => check.status === "pass") ? "pass" : "fail";
	return {
		schemaVersion: PROVIDER_GOOGLE_PROBE_SCHEMA_VERSION,
		probeId: "providers.google",
		status,
		ran: true,
		observedAt,
		source: PROVIDER_GOOGLE_PROBE_SOURCE,
		summary: status === "pass" ? "Google provider probe passed" : "Google provider probe failed",
		checks,
		observations,
	};
}

export function googleProviderProbeEvidenceFailure(evidence: unknown): string | null {
	const parsed = GoogleProviderProbeEvidenceSchema.safeParse(evidence);
	if (!parsed.success) {
		return `invalid Google provider evidence: ${flattenZodError(parsed.error)}`;
	}
	const data = parsed.data;
	const failures: string[] = [];
	if (data.status !== "pass") failures.push(`status is ${data.status}`);
	if (data.ran !== true) failures.push("harness did not run");
	const checksByName = new Map(data.checks.map((check) => [check.name, check]));
	for (const duplicate of duplicates(data.checks.map((check) => check.name))) {
		failures.push(`duplicate check ${duplicate}`);
	}
	for (const name of REQUIRED_GOOGLE_PROVIDER_CHECKS) {
		const check = checksByName.get(name);
		if (!check) {
			failures.push(`check ${name} is missing`);
		} else if (check.status !== "pass") {
			failures.push(`check ${name} is ${check.status}`);
		}
	}
	if (data.observations.providerProxyCallCount !== 2) {
		failures.push(`providerProxyCallCount is ${data.observations.providerProxyCallCount}`);
	}
	if (data.observations.approvalVerifierCallCount < 1) {
		failures.push("approvalVerifierCallCount is too low");
	}
	if (data.observations.sidecarVerifierCallCount < 2) {
		failures.push("sidecarVerifierCallCount is too low");
	}
	if (data.observations.ledgerReplayCode !== "effect_already_executed") {
		failures.push(`ledgerReplayCode is ${data.observations.ledgerReplayCode ?? "missing"}`);
	}
	if (data.observations.sidecarReplayCode !== "approval_replayed") {
		failures.push(`sidecarReplayCode is ${data.observations.sidecarReplayCode ?? "missing"}`);
	}
	if (data.observations.rawOAuthObserved) {
		failures.push("raw OAuth credential material was observed");
	}
	if (!data.observations.actionRef) failures.push("actionRef is missing");
	if (!data.observations.readRequestBodyHash || !data.observations.writeRequestBodyHash) {
		failures.push("provider request body hashes are incomplete");
	}
	if (!data.observations.sidecarParamsHash) failures.push("sidecarParamsHash is missing");
	return failures.length > 0 ? failures.join("; ") : null;
}

const GoogleProviderFixtureEvidenceSchema = z
	.object({
		schemaVersion: z.literal(PROVIDER_GOOGLE_FIXTURE_EVIDENCE_SCHEMA_VERSION),
		id: NonEmptyString,
		status: z.enum(["pass", "fail"]),
		ran: z.literal(true),
		evidence_path: NonEmptyString,
		observedAt: NonEmptyString,
		provenance: z
			.object({
				runner: z.literal(PROVIDER_GOOGLE_FIXTURE_RUNNER),
				source: z.literal(PROVIDER_GOOGLE_FIXTURE_SOURCE),
				command: NonEmptyString,
				probeId: z.literal("providers.google"),
				probePath: NonEmptyString,
				probeSha256: Sha256Digest,
			})
			.strict(),
		googleProvider: z
			.object({
				requiredProbeChecks: z.array(NonEmptyString),
				requiredObservationHashes: z.array(NonEmptyString),
			})
			.strict(),
		networkDeny: z
			.object({
				probeId: z.literal("network.direct-provider-denied"),
				probePath: NonEmptyString,
				probeSha256: Sha256Digest,
				requiredAttemptName: z.literal("provider:google"),
				posture: z.enum(["agent-iptables", "contained-internal"]).optional(),
			})
			.strict()
			.optional(),
		checks: z.array(GoogleProviderProbeCheckSchema).min(1),
	})
	.strict();

type GoogleProviderFixtureEvidence = z.infer<typeof GoogleProviderFixtureEvidenceSchema>;

export function buildGoogleProviderFixtureEvidenceBundle(
	input: {
		readonly evidenceDir?: string;
		readonly observedAt?: string;
		readonly probePath?: string;
		readonly networkProbePath?: string;
	} = {},
): {
	readonly schemaVersion: 1;
	readonly results: readonly {
		readonly id: GoogleProviderFixtureId;
		readonly status: "pass" | "fail";
		readonly evidence_path: string;
	}[];
	readonly evidence: readonly GoogleProviderFixtureEvidence[];
} {
	const evidenceDir = input.evidenceDir ?? DEFAULT_PROVIDER_GOOGLE_FIXTURE_EVIDENCE_DIR;
	const probe = readGoogleProviderProbeArtifact(
		input.probePath ?? DEFAULT_PROVIDER_GOOGLE_EVIDENCE_PATH,
	);
	const networkProbe = readGoogleProviderDirectNetworkProbeArtifact(
		input.networkProbePath ?? DEFAULT_PROVIDER_GOOGLE_DIRECT_NETWORK_EVIDENCE_PATH,
	);
	const evidence = GOOGLE_PROVIDER_FIXTURE_REQUIREMENTS.map((requirement) =>
		buildGoogleProviderFixtureEvidence(requirement, {
			evidenceDir,
			observedAt: input.observedAt,
			probe,
			networkProbe,
		}),
	);
	return {
		schemaVersion: 1,
		results: evidence.map((item) => ({
			id: item.id as GoogleProviderFixtureId,
			status: item.status,
			evidence_path: item.evidence_path,
		})),
		evidence,
	};
}

export function googleProviderFixtureEvidenceFailure(
	fixtureId: string,
	evidence: unknown,
	options: HermesSignedEvidenceValidationOptions = {},
): string | null {
	const requirement = GOOGLE_PROVIDER_FIXTURE_REQUIREMENTS.find(
		(candidate) => candidate.id === fixtureId,
	) as GoogleProviderFixtureRequirement | undefined;
	if (!requirement) return null;
	const parsed = GoogleProviderFixtureEvidenceSchema.safeParse(evidence);
	if (!parsed.success) {
		return `invalid Google provider fixture evidence ${fixtureId}: ${flattenZodError(parsed.error)}`;
	}
	const data = parsed.data;
	const failures: string[] = [];
	if (data.id !== fixtureId) failures.push(`fixture evidence id is ${data.id}`);
	if (data.status !== "pass") failures.push(`fixture evidence status is ${data.status}`);
	if (
		JSON.stringify(data.googleProvider.requiredProbeChecks) !==
		JSON.stringify(requirement.requiredChecks)
	) {
		failures.push("fixture requiredProbeChecks do not match Google provider contract");
	}
	if (
		JSON.stringify(data.googleProvider.requiredObservationHashes) !==
		JSON.stringify(requirement.requiredObservationHashes)
	) {
		failures.push("fixture requiredObservationHashes do not match Google provider contract");
	}
	const probe = readGoogleProviderProbeArtifact(data.provenance.probePath);
	if (probe.sha256 !== data.provenance.probeSha256) {
		failures.push("fixture probeSha256 does not match Google provider probe artifact");
	}
	if (probe.failure) {
		failures.push(`fixture probe artifact failed validation: ${probe.failure}`);
	} else if (probe.evidence) {
		failures.push(...googleProviderFixtureContractFailures(requirement, data, probe.evidence));
	}
	if (requirement.kind === "direct-provider-deny") {
		failures.push(...googleProviderDirectNetworkFixtureFailures(requirement, data, options));
	} else if (data.networkDeny) {
		failures.push("Google provider fixture unexpectedly includes direct-provider network evidence");
	}
	return failures.length > 0 ? failures.join("; ") : null;
}

function buildGoogleProviderFixtureEvidence(
	requirement: GoogleProviderFixtureRequirement,
	options: {
		readonly evidenceDir: string;
		readonly observedAt?: string;
		readonly probe: {
			readonly path: string;
			readonly sha256: string;
			readonly evidence?: GoogleProviderProbeEvidence;
			readonly failure?: string;
		};
		readonly networkProbe: {
			readonly path: string;
			readonly sha256: string;
			readonly evidence?: GoogleProviderDirectNetworkProbeEvidence;
			readonly failure?: string;
		};
	},
): GoogleProviderFixtureEvidence {
	const checks =
		requirement.kind === "direct-provider-deny"
			? buildGoogleProviderDirectNetworkFixtureChecks(requirement, options.networkProbe)
			: buildGoogleProviderFixtureChecks(
					requirement,
					options.probe.evidence,
					options.probe.failure,
				);
	const status =
		options.probe.failure === undefined &&
		(requirement.kind !== "direct-provider-deny" || options.networkProbe.failure === undefined) &&
		checks.every((check) => check.status === "pass")
			? "pass"
			: "fail";
	return {
		schemaVersion: PROVIDER_GOOGLE_FIXTURE_EVIDENCE_SCHEMA_VERSION,
		id: requirement.id,
		status,
		ran: true,
		evidence_path: path.join(options.evidenceDir, `${requirement.id}.json`),
		observedAt:
			options.probe.evidence?.observedAt ?? options.observedAt ?? new Date().toISOString(),
		provenance: {
			runner: PROVIDER_GOOGLE_FIXTURE_RUNNER,
			source: PROVIDER_GOOGLE_FIXTURE_SOURCE,
			command: "pnpm dev hermes fixtures --include-provider-domain --write",
			probeId: "providers.google",
			probePath: options.probe.path,
			probeSha256: options.probe.sha256,
		},
		googleProvider: {
			requiredProbeChecks: [...requirement.requiredChecks],
			requiredObservationHashes: [...requirement.requiredObservationHashes],
		},
		...(requirement.kind === "direct-provider-deny"
			? {
					networkDeny: {
						probeId: "network.direct-provider-denied" as const,
						probePath: options.networkProbe.path,
						probeSha256: options.networkProbe.sha256,
						requiredAttemptName: "provider:google" as const,
						...(options.networkProbe.evidence?.posture
							? { posture: options.networkProbe.evidence.posture }
							: {}),
					},
				}
			: {}),
		checks,
	};
}

function buildGoogleProviderFixtureChecks(
	requirement: GoogleProviderFixtureRequirement,
	probe: GoogleProviderProbeEvidence | undefined,
	probeFailure: string | undefined,
): ProbeCheck[] {
	if (!probe || probeFailure) {
		return [
			{
				name: `${requirement.id}.google-provider-probe-valid`,
				status: "fail",
				detail: probeFailure ?? "Google provider probe evidence is missing",
			},
		];
	}
	const checksByName = new Map(probe.checks.map((check) => [check.name, check]));
	return [
		...requirement.requiredChecks.map((name) => {
			const check = checksByName.get(name);
			return {
				name,
				status: check?.status === "pass" ? "pass" : "fail",
				detail: check?.detail ?? "required Google provider probe check is missing",
			} satisfies ProbeCheck;
		}),
		...requirement.requiredObservationHashes.map(
			(field) =>
				({
					name: `${requirement.id}.${field}`,
					status: probe.observations[field] ? "pass" : "fail",
					detail: probe.observations[field]
						? `Google provider probe recorded ${field}`
						: `Google provider probe did not record ${field}`,
				}) satisfies ProbeCheck,
		),
	];
}

function buildGoogleProviderDirectNetworkFixtureChecks(
	requirement: GoogleProviderFixtureRequirement,
	networkProbe: {
		readonly evidence?: GoogleProviderDirectNetworkProbeEvidence;
		readonly failure?: string;
	},
): ProbeCheck[] {
	const attemptName = requirement.networkAttemptName;
	if (!attemptName) {
		return [
			{
				name: `${requirement.id}.network-attempt-configured`,
				status: "fail",
				detail: "direct-provider-deny fixture is missing a required network attempt name",
			},
		];
	}
	if (!networkProbe.evidence || networkProbe.failure) {
		return [
			{
				name: `${requirement.id}.${attemptName}`,
				status: "fail",
				detail: networkProbe.failure ?? "direct provider network evidence is missing",
			},
		];
	}
	const validationFailure = networkProbeEvidenceFailure(networkProbe.evidence, {
		expectedId: "network.direct-provider-denied",
		requiredAttemptNames: [attemptName],
	});
	const passed = validationFailure === null;
	return [
		{
			name: `${requirement.id}.${attemptName}`,
			status: passed ? "pass" : "fail",
			detail: passed
				? "direct Google provider endpoint was denied in the Hermes runtime namespace"
				: validationFailure,
		},
	];
}

function googleProviderFixtureContractFailures(
	requirement: GoogleProviderFixtureRequirement,
	fixture: GoogleProviderFixtureEvidence,
	probe: GoogleProviderProbeEvidence,
): string[] {
	const failures: string[] = [];
	const probeFailure = googleProviderProbeEvidenceFailure(probe);
	if (probeFailure) failures.push(probeFailure);
	const probeChecksByName = new Map(probe.checks.map((check) => [check.name, check]));
	const fixtureChecksByName = new Map(fixture.checks.map((check) => [check.name, check]));
	for (const name of requirement.requiredChecks) {
		const probeCheck = probeChecksByName.get(name);
		const fixtureCheck = fixtureChecksByName.get(name);
		if (probeCheck?.status !== "pass") failures.push(`probe check ${name} is not pass`);
		if (fixtureCheck?.status !== "pass") failures.push(`fixture check ${name} is not pass`);
	}
	for (const field of requirement.requiredObservationHashes) {
		if (!probe.observations[field]) failures.push(`probe observation ${field} is missing`);
		const fixtureCheck = fixtureChecksByName.get(`${requirement.id}.${field}`);
		if (fixtureCheck?.status !== "pass") {
			failures.push(`fixture observation check ${field} is not pass`);
		}
	}
	return failures;
}

function googleProviderDirectNetworkFixtureFailures(
	requirement: GoogleProviderFixtureRequirement,
	fixture: GoogleProviderFixtureEvidence,
	options: HermesSignedEvidenceValidationOptions = {},
): string[] {
	const failures: string[] = [];
	const binding = fixture.networkDeny;
	if (!binding) return ["direct-provider fixture networkDeny binding is missing"];
	if (binding.probeId !== "network.direct-provider-denied") {
		failures.push(`networkDeny probeId is ${binding.probeId}`);
	}
	if (binding.requiredAttemptName !== requirement.networkAttemptName) {
		failures.push("networkDeny requiredAttemptName does not match Google provider contract");
	}
	const network = readGoogleProviderDirectNetworkProbeArtifact(binding.probePath, options);
	if (network.sha256 !== binding.probeSha256) {
		failures.push("networkDeny probeSha256 does not match direct-provider network artifact");
	}
	if (network.failure) {
		failures.push(`networkDeny probe artifact failed validation: ${network.failure}`);
		return failures;
	}
	const signedFailure = networkProbeEvidenceFailure(network.evidence, {
		expectedId: "network.direct-provider-denied",
		requiredAttemptNames: requirement.networkAttemptName ? [requirement.networkAttemptName] : [],
		...options,
	});
	if (signedFailure) {
		failures.push(`networkDeny signed proof failed validation: ${signedFailure}`);
	}
	const fixtureCheck = new Map(fixture.checks.map((check) => [check.name, check])).get(
		`${requirement.id}.${String(requirement.networkAttemptName)}`,
	);
	if (fixtureCheck?.status !== "pass") {
		failures.push(
			`fixture network denial check ${String(requirement.networkAttemptName)} is not pass`,
		);
	}
	return failures;
}

function readGoogleProviderProbeArtifact(probePath: string): {
	readonly path: string;
	readonly sha256: string;
	readonly evidence?: GoogleProviderProbeEvidence;
	readonly failure?: string;
} {
	if (!fs.existsSync(probePath)) {
		return {
			path: probePath,
			sha256: sha256Digest(`${probePath}:missing`),
			failure: `missing Google provider probe artifact ${probePath}`,
		};
	}
	let raw: unknown;
	try {
		raw = JSON.parse(fs.readFileSync(probePath, "utf8")) as unknown;
	} catch (error) {
		return {
			path: probePath,
			sha256: fileSha256(probePath),
			failure: `unreadable Google provider probe artifact: ${
				error instanceof Error ? error.message : String(error)
			}`,
		};
	}
	const parsed = GoogleProviderProbeEvidenceSchema.safeParse(raw);
	if (!parsed.success) {
		return {
			path: probePath,
			sha256: fileSha256(probePath),
			failure: `invalid Google provider probe artifact: ${flattenZodError(parsed.error)}`,
		};
	}
	const semanticFailure = googleProviderProbeEvidenceFailure(parsed.data);
	return {
		path: probePath,
		sha256: fileSha256(probePath),
		evidence: parsed.data,
		...(semanticFailure ? { failure: semanticFailure } : {}),
	};
}

function readGoogleProviderDirectNetworkProbeArtifact(
	probePath: string,
	options: HermesSignedEvidenceValidationOptions = {},
): {
	readonly path: string;
	readonly sha256: string;
	readonly evidence?: GoogleProviderDirectNetworkProbeEvidence;
	readonly failure?: string;
} {
	if (!fs.existsSync(probePath)) {
		return {
			path: probePath,
			sha256: sha256Digest(`${probePath}:missing`),
			failure: `missing direct-provider network artifact ${probePath}`,
		};
	}
	let raw: unknown;
	try {
		raw = JSON.parse(fs.readFileSync(probePath, "utf8")) as unknown;
	} catch (error) {
		return {
			path: probePath,
			sha256: fileSha256(probePath),
			failure: `unreadable direct-provider network artifact: ${
				error instanceof Error ? error.message : String(error)
			}`,
		};
	}
	const parsed = GoogleProviderDirectNetworkProbeEvidenceSchema.safeParse(raw);
	if (!parsed.success) {
		return {
			path: probePath,
			sha256: fileSha256(probePath),
			failure: `invalid direct-provider network artifact: ${flattenZodError(parsed.error)}`,
		};
	}
	const failure = networkProbeEvidenceFailure(parsed.data, {
		expectedId: "network.direct-provider-denied",
		...options,
	});
	return {
		path: probePath,
		sha256: fileSha256(probePath),
		evidence: parsed.data,
		...(failure ? { failure } : {}),
	};
}

function createLedgerHarness(): {
	readonly ledger: TelclaudeMcpSideEffectLedger;
	readonly verifierCalls: TelclaudeMcpSideEffectApprovalVerification[];
	readonly accept: (token: string, record: TelclaudeMcpSideEffectRecord) => void;
	readonly resolveSideEffectApprovalToken: Parameters<
		typeof createTelclaudeMcpLedgerExecuteDependencies
	>[0]["sideEffectApprovalTokenResolver"];
} {
	let refCounter = 0;
	const accepted = new Map<string, string>();
	const serverSideApprovals = new Map<string, string>();
	const verifierCalls: TelclaudeMcpSideEffectApprovalVerification[] = [];
	const ledger = createTelclaudeMcpSideEffectLedger({
		makeRef: () => `google-provider-probe-${++refCounter}`,
		defaultTtlMs: 60_000,
		verifyApproval: async (request) => {
			verifierCalls.push(request);
			const expectedBinding = accepted.get(request.approvalToken);
			if (!expectedBinding || canonicalBinding(request.binding) !== expectedBinding) {
				return {
					ok: false,
					code: "approval_mismatch",
					reason: "approval token not accepted",
				};
			}
			return { ok: true, approvalId: request.approvalToken };
		},
	});
	return {
		ledger,
		verifierCalls,
		accept(token, record) {
			accepted.set(token, canonicalBinding(getTelclaudeMcpSideEffectApprovalBinding(record)));
			serverSideApprovals.set(record.ref, token);
		},
		resolveSideEffectApprovalToken({ actionRef }) {
			const approvalToken = serverSideApprovals.get(actionRef);
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
					serverSideApprovals.delete(actionRef);
				},
			};
		},
	};
}

function createExecuteBridge(
	harness: ReturnType<typeof createLedgerHarness>,
	providerProxy: Parameters<typeof createTelclaudeMcpLedgerExecuteDependencies>[0]["providerProxy"],
	vault: GoogleProviderSidecarApprovalTokenSigner,
	authorityOverrides: Partial<TelclaudeMcpAuthority> = {},
) {
	return createTelclaudeMcpBridge(baseAuthority(authorityOverrides), {
		providerRead: async () => ({ ok: true }),
		providerPrepareWrite: async () => ({ actionRef: "not-used" }),
		memorySearch: async () => ({ entries: [] }),
		memoryWrite: async () => ({ accepted: 1 }),
		attachmentGet: async () => ({ bytes: 0 }),
		outboundPrepare: async () => ({ outboundRef: "not-used" }),
		auditNote: async () => ({ stored: true }),
		...createTelclaudeMcpLedgerExecuteDependencies({
			ledger: harness.ledger,
			providerProxy,
			sideEffectApprovalTokenResolver: harness.resolveSideEffectApprovalToken,
			providerApprovalTokenIssuer: createGoogleProviderSidecarApprovalTokenIssuer({
				vaultClient: vault,
			}),
		}),
	});
}

function baseAuthority(overrides: Partial<TelclaudeMcpAuthority> = {}): TelclaudeMcpAuthority {
	return {
		actorId: "operator",
		profileId: "ops",
		domain: "private",
		memorySource: "telegram:ops",
		writableNamespace: "private:ops",
		providerScopes: ["google"],
		outboundChannels: ["whatsapp"],
		endpointId: "endpoint-private",
		networkNamespace: "netns-private",
		...overrides,
	};
}

function authorityStamp() {
	const authority = baseAuthority();
	return {
		actorId: authority.actorId,
		profileId: authority.profileId,
		domain: authority.domain,
		memorySource: authority.memorySource,
		writableNamespace: authority.writableNamespace,
		endpointId: authority.endpointId,
		networkNamespace: authority.networkNamespace,
	};
}

function googleProviderPrepareInput(): TelclaudeMcpProviderSideEffectPrepareInput {
	return {
		kind: "provider",
		actorId: "operator",
		approverActorId: "operator",
		profileId: "ops",
		domain: "private",
		providerId: "google",
		service: "gmail",
		action: "create_draft",
		params: { to: "family@example.com", subject: "Clinic follow-up", body: "Booked." },
		providerAccountRef: "google:gmail:primary",
		approvalRequestId: "approval-google-provider-probe",
		approvalRevision: 1,
		wysiwysRender: "google.gmail.create_draft",
		idempotencyKey: "google-provider-probe",
	};
}

function makeApprovalIds(): () => string {
	let id = 0;
	return () => `approval-${++id}`;
}

function createProbeVault(): GoogleProviderSidecarApprovalTokenSigner {
	return {
		async signPayload(payload, prefix) {
			return {
				type: "sign-payload" as const,
				signature: signature(GOOGLE_PROBE_SECRET, payload, prefix),
			};
		},
	};
}

function verifyProbeSignature(payload: string, signatureValue: string, prefix: string): boolean {
	return safeEqual(signatureValue, signature(GOOGLE_PROBE_SECRET, payload, prefix));
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

function canonicalBinding(binding: unknown): string {
	return JSON.stringify(sortKeysDeep(binding));
}

function googleProviderProxyCallMatches(
	call: ProviderProxyRequest | undefined,
	expected: {
		readonly service: string;
		readonly action: string;
		readonly params: Record<string, unknown>;
		readonly preapproved: boolean;
	},
): boolean {
	if (
		!call ||
		call.providerId !== "google" ||
		call.path !== "/v1/fetch" ||
		call.method !== "POST"
	) {
		return false;
	}
	if (call.userId !== "operator") return false;
	if (expected.preapproved) {
		if (call.approvalMode !== "preapproved-ledger" || !call.approvalToken) return false;
	} else if (call.approvalToken || call.approvalMode) {
		return false;
	}
	const body = parseFetchRequest(call.body);
	return (
		body.service === expected.service &&
		body.action === expected.action &&
		JSON.stringify(sortKeysDeep(body.params)) === JSON.stringify(sortKeysDeep(expected.params))
	);
}

function parseFetchRequest(value: unknown): FetchRequest {
	if (typeof value !== "string") throw new Error("provider proxy body is not a string");
	return JSON.parse(value) as FetchRequest;
}

function requestBodyHash(call: ProviderProxyRequest | undefined): string | undefined {
	if (!call || typeof call.body !== "string") return undefined;
	return sha256Digest(call.body);
}

function sidecarParamsHash(token: string | undefined): string | undefined {
	if (!token) return undefined;
	const [, claimsB64] = token.split(".");
	if (!claimsB64) return undefined;
	try {
		const claims = JSON.parse(Buffer.from(claimsB64, "base64url").toString("utf8")) as {
			paramsHash?: unknown;
		};
		return typeof claims.paramsHash === "string" ? claims.paramsHash : undefined;
	} catch {
		return undefined;
	}
}

function sha256Digest(value: string): string {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function fileSha256(filePath: string): string {
	return `sha256:${crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex")}`;
}

function providerRequestsContainRawCredential(calls: readonly ProviderProxyRequest[]): boolean {
	return calls.some((call) => {
		const material = JSON.stringify({
			providerId: call.providerId,
			path: call.path,
			method: call.method,
			body: call.body,
			userId: call.userId,
			approvalMode: call.approvalMode,
		});
		return /\b(access_token|refresh_token|oauth_token|client_secret|authorization:|bearer\s+|ya29\.|sk-[a-z0-9])/i.test(
			material,
		);
	});
}

function isGoogleProviderRecord(
	record: TelclaudeMcpSideEffectRecord | null | undefined,
): record is TelclaudeMcpProviderSideEffectRecord {
	return record?.kind === "provider" && record.providerId === "google";
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
	readonly record?: { readonly ref?: unknown; readonly status?: unknown };
} {
	if (typeof value !== "object" || value === null) return {};
	const recordValue = (value as { record?: unknown }).record;
	const record =
		typeof recordValue === "object" && recordValue !== null
			? (recordValue as { readonly ref?: unknown; readonly status?: unknown })
			: undefined;
	return {
		ok: (value as { ok?: unknown }).ok,
		code: (value as { code?: unknown }).code,
		record,
	};
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
