import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { z } from "zod";
import { sortKeysDeep } from "../crypto/canonical-hash.js";
import type { ProviderProxyRequest } from "../relay/provider-proxy.js";
import { createTelclaudeMcpBridge, type TelclaudeMcpAuthority } from "./mcp/bridge.js";
import { createTelclaudeMcpLedgerExecuteDependencies } from "./mcp/ledger-execute.js";
import { createTelclaudeLiveMcpRelayClients } from "./mcp/live-relay-clients.js";
import {
	createTelclaudeMcpSideEffectLedger,
	getTelclaudeMcpSideEffectApprovalBinding,
	type TelclaudeMcpProviderSideEffectRecord,
	type TelclaudeMcpSideEffectRecord,
} from "./mcp/side-effect-ledger.js";
import { networkProbeEvidenceFailure } from "./network-probe-evidence-validation.js";
import { NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION } from "./network-probe-schema.js";

export const PROVIDER_DOMAIN_PROBE_SCHEMA_VERSION = "telclaude.hermes.provider-domain-probe.v1";
export const PROVIDER_DOMAIN_PROBE_SOURCE = "telclaude-provider-domain-harness";
export const PROVIDER_DOMAIN_FIXTURE_EVIDENCE_SCHEMA_VERSION =
	"telclaude.hermes.provider-domain-fixture-evidence.v1";
export const PROVIDER_DOMAIN_FIXTURE_SOURCE = "machine-observed-provider-domain-probe";
export const PROVIDER_DOMAIN_FIXTURE_RUNNER = "telclaude-provider-domain-fixture-generator";
export const DEFAULT_PROVIDER_DOMAIN_FIXTURE_EVIDENCE_DIR = "artifacts/hermes/fixtures";
export const DEFAULT_PROVIDER_DIRECT_NETWORK_EVIDENCE_PATH =
	"artifacts/hermes/network/direct-provider-denied.json";

export const PROVIDER_DOMAIN_SURFACE_IDS = [
	"providers.bank",
	"providers.clalit",
	"providers.government",
] as const;

export type ProviderDomainSurfaceId = (typeof PROVIDER_DOMAIN_SURFACE_IDS)[number];
type ProviderId = "bank" | "clalit" | "government";

export const DEFAULT_PROVIDER_DOMAIN_EVIDENCE_PATHS: Record<ProviderDomainSurfaceId, string> = {
	"providers.bank": "artifacts/hermes/probes/providers-bank.json",
	"providers.clalit": "artifacts/hermes/probes/providers-clalit.json",
	"providers.government": "artifacts/hermes/probes/providers-government.json",
};

type ProviderDomainFixtureRequirement = {
	readonly id: string;
	readonly surfaceId: ProviderDomainSurfaceId;
	readonly providerId: ProviderId;
	readonly kind?: "provider-domain" | "direct-provider-deny";
	readonly requiredChecks: readonly string[];
	readonly requiredObservationHashes: readonly (keyof Pick<
		ProviderDomainProbeEvidence["observations"],
		"bodyHash" | "contentHash" | "paramsHash" | "readRequestBodyHash" | "writeRequestBodyHash"
	>)[];
	readonly networkAttemptName?: `provider:${ProviderId}`;
};

export const PROVIDER_DOMAIN_FIXTURE_REQUIREMENTS = [
	{
		id: "fixture.providers.bank.read",
		surfaceId: "providers.bank",
		providerId: "bank",
		requiredChecks: ["bank.read-through-provider-proxy", "bank.raw-credential-not-observed"],
		requiredObservationHashes: ["readRequestBodyHash"],
	},
	{
		id: "fixture.providers.bank.prepare-transfer",
		surfaceId: "providers.bank",
		providerId: "bank",
		requiredChecks: [
			"bank.prepare-write-ledger-bound",
			"bank.final-render-bound",
			"bank.raw-credential-not-observed",
		],
		requiredObservationHashes: ["paramsHash", "bodyHash", "contentHash"],
	},
	{
		id: "fixture.providers.bank.approved-transfer",
		surfaceId: "providers.bank",
		providerId: "bank",
		requiredChecks: ["bank.approved-write-relay-sidecar-token", "bank.raw-credential-not-observed"],
		requiredObservationHashes: ["writeRequestBodyHash", "contentHash"],
	},
	{
		id: "fixture.providers.bank.wrong-actor-deny",
		surfaceId: "providers.bank",
		providerId: "bank",
		requiredChecks: ["bank.wrong-actor-denied"],
		requiredObservationHashes: ["contentHash"],
	},
	{
		id: "fixture.providers.bank.replay-deny",
		surfaceId: "providers.bank",
		providerId: "bank",
		requiredChecks: ["bank.replay-denied"],
		requiredObservationHashes: ["contentHash"],
	},
	{
		id: "fixture.providers.bank.direct-provider-deny",
		surfaceId: "providers.bank",
		providerId: "bank",
		kind: "direct-provider-deny",
		requiredChecks: [],
		requiredObservationHashes: [],
		networkAttemptName: "provider:bank",
	},
	{
		id: "fixture.providers.clalit.read",
		surfaceId: "providers.clalit",
		providerId: "clalit",
		requiredChecks: ["clalit.read-through-provider-proxy", "clalit.raw-credential-not-observed"],
		requiredObservationHashes: ["readRequestBodyHash"],
	},
	{
		id: "fixture.providers.clalit.prepare-message",
		surfaceId: "providers.clalit",
		providerId: "clalit",
		requiredChecks: ["clalit.prepare-write-ledger-bound", "clalit.raw-credential-not-observed"],
		requiredObservationHashes: ["paramsHash", "bodyHash", "contentHash"],
	},
	{
		id: "fixture.providers.clalit.approved-booking",
		surfaceId: "providers.clalit",
		providerId: "clalit",
		requiredChecks: [
			"clalit.approved-write-relay-sidecar-token",
			"clalit.raw-credential-not-observed",
		],
		requiredObservationHashes: ["writeRequestBodyHash", "contentHash"],
	},
	{
		id: "fixture.providers.clalit.wrong-actor-deny",
		surfaceId: "providers.clalit",
		providerId: "clalit",
		requiredChecks: ["clalit.wrong-actor-denied"],
		requiredObservationHashes: ["contentHash"],
	},
	{
		id: "fixture.providers.clalit.emergency-escalate",
		surfaceId: "providers.clalit",
		providerId: "clalit",
		requiredChecks: ["clalit.emergency-escalation-denied"],
		requiredObservationHashes: ["contentHash"],
	},
	{
		id: "fixture.providers.clalit.direct-provider-deny",
		surfaceId: "providers.clalit",
		providerId: "clalit",
		kind: "direct-provider-deny",
		requiredChecks: [],
		requiredObservationHashes: [],
		networkAttemptName: "provider:clalit",
	},
	{
		id: "fixture.providers.government.read",
		surfaceId: "providers.government",
		providerId: "government",
		requiredChecks: [
			"government.read-through-provider-proxy",
			"government.raw-credential-not-observed",
		],
		requiredObservationHashes: ["readRequestBodyHash"],
	},
	{
		id: "fixture.providers.government.prepare-form",
		surfaceId: "providers.government",
		providerId: "government",
		requiredChecks: [
			"government.prepare-write-ledger-bound",
			"government.final-render-bound",
			"government.raw-credential-not-observed",
		],
		requiredObservationHashes: ["paramsHash", "bodyHash", "contentHash"],
	},
	{
		id: "fixture.providers.government.approved-submit",
		surfaceId: "providers.government",
		providerId: "government",
		requiredChecks: [
			"government.approved-write-relay-sidecar-token",
			"government.raw-credential-not-observed",
		],
		requiredObservationHashes: ["writeRequestBodyHash", "contentHash"],
	},
	{
		id: "fixture.providers.government.wrong-actor-deny",
		surfaceId: "providers.government",
		providerId: "government",
		requiredChecks: ["government.wrong-actor-denied"],
		requiredObservationHashes: ["contentHash"],
	},
	{
		id: "fixture.providers.government.replay-deny",
		surfaceId: "providers.government",
		providerId: "government",
		requiredChecks: ["government.replay-denied"],
		requiredObservationHashes: ["contentHash"],
	},
	{
		id: "fixture.providers.government.direct-provider-deny",
		surfaceId: "providers.government",
		providerId: "government",
		kind: "direct-provider-deny",
		requiredChecks: [],
		requiredObservationHashes: [],
		networkAttemptName: "provider:government",
	},
] as const satisfies readonly ProviderDomainFixtureRequirement[];

export type ProviderDomainFixtureId = (typeof PROVIDER_DOMAIN_FIXTURE_REQUIREMENTS)[number]["id"];

const NonEmptyString = z.string().trim().min(1);
const Sha256Digest = z.string().regex(/^sha256:[a-f0-9]{64}$/i);

const ProviderDomainProbeCheckSchema = z
	.object({
		name: NonEmptyString,
		status: z.enum(["pass", "fail"]),
		detail: NonEmptyString,
	})
	.strict();

const ProviderDirectNetworkAttemptSchema = z
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

const ProviderDirectNetworkProbeEvidenceSchema = z
	.object({
		schemaVersion: z.literal(NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION),
		id: z.literal("network.direct-provider-denied"),
		posture: z.enum(["agent-iptables", "contained-internal"]),
		status: z.enum(["pass", "fail", "pending"]),
		ran: z.boolean(),
		summary: NonEmptyString,
		generatedAt: NonEmptyString,
		evidence_path: NonEmptyString,
		attempts: z.array(ProviderDirectNetworkAttemptSchema).min(1),
	})
	.passthrough();

type ProviderDirectNetworkProbeEvidence = z.infer<typeof ProviderDirectNetworkProbeEvidenceSchema>;

export const ProviderDomainProbeEvidenceSchema = z
	.object({
		schemaVersion: z.literal(PROVIDER_DOMAIN_PROBE_SCHEMA_VERSION),
		probeId: z.enum(PROVIDER_DOMAIN_SURFACE_IDS),
		status: z.enum(["pass", "fail"]),
		ran: z.boolean(),
		observedAt: NonEmptyString,
		source: z.literal(PROVIDER_DOMAIN_PROBE_SOURCE),
		summary: NonEmptyString,
		checks: z.array(ProviderDomainProbeCheckSchema).min(1),
		observations: z
			.object({
				providerId: z.enum(["bank", "clalit", "government"]),
				readAction: NonEmptyString,
				writeAction: NonEmptyString,
				actionRef: NonEmptyString.optional(),
				approvalVerifierCallCount: z.number().int().nonnegative(),
				providerProxyCallCount: z.number().int().nonnegative(),
				sidecarTokenIssuerCallCount: z.number().int().nonnegative(),
				readRequestBodyHash: Sha256Digest.optional(),
				writeRequestBodyHash: Sha256Digest.optional(),
				paramsHash: Sha256Digest.optional(),
				bodyHash: Sha256Digest.optional(),
				contentHash: Sha256Digest.optional(),
				ledgerReplayCode: NonEmptyString.optional(),
				wrongActorCode: NonEmptyString.optional(),
				wrongProviderScopeCode: NonEmptyString.optional(),
				emergencyEscalationCode: NonEmptyString.optional(),
				rawCredentialObserved: z.boolean(),
			})
			.strict(),
	})
	.strict();

export type ProviderDomainProbeEvidence = z.infer<typeof ProviderDomainProbeEvidenceSchema>;
type ProbeCheck = z.infer<typeof ProviderDomainProbeCheckSchema>;

const COMMON_CHECK_SUFFIXES = [
	"read-through-provider-proxy",
	"prepare-write-ledger-bound",
	"approved-write-relay-sidecar-token",
	"wrong-actor-denied",
	"wrong-provider-scope-denied",
	"replay-denied",
	"raw-credential-not-observed",
] as const;

const PROVIDER_CONFIGS: Record<
	ProviderDomainSurfaceId,
	{
		readonly providerId: ProviderId;
		readonly readAction: string;
		readonly readParams: Record<string, unknown>;
		readonly readData: Record<string, unknown>;
		readonly writeAction: string;
		readonly writeParams: Record<string, unknown>;
		readonly expectedProviderAccountRef: string;
		readonly idempotencyKey: string;
		readonly secretCanary: string;
		readonly extraRequiredChecks: readonly string[];
	}
> = {
	"providers.bank": {
		providerId: "bank",
		readAction: "balances.list",
		readParams: { accountRef: "primary" },
		readData: { balances: [{ accountRef: "primary", amount: 1000, currency: "ILS" }] },
		writeAction: "transfer.execute",
		writeParams: { amount: 50, currency: "ILS", recipientRef: "known-recipient" },
		expectedProviderAccountRef: "bank:primary",
		idempotencyKey: "provider-bank-transfer-probe",
		secretCanary: "bank-refresh-token-never-release",
		extraRequiredChecks: ["bank.final-render-bound"],
	},
	"providers.clalit": {
		providerId: "clalit",
		readAction: "appointments.list",
		readParams: { memberRef: "family-member" },
		readData: { appointments: [{ id: "appt_probe", status: "scheduled" }] },
		writeAction: "appointments.book",
		writeParams: { clinicId: "clinic_123", reason: "routine follow-up" },
		expectedProviderAccountRef: "clalit:primary",
		idempotencyKey: "provider-clalit-booking-probe",
		secretCanary: "clalit-oauth-token-never-release",
		extraRequiredChecks: ["clalit.emergency-escalation-denied"],
	},
	"providers.government": {
		providerId: "government",
		readAction: "status.lookup",
		readParams: { caseRef: "case_123" },
		readData: { status: { caseRef: "case_123", state: "received" } },
		writeAction: "form.submit",
		writeParams: { formId: "arnona-discount", applicantRef: "operator" },
		expectedProviderAccountRef: "government:primary",
		idempotencyKey: "provider-government-submit-probe",
		secretCanary: "government-session-cookie-never-release",
		extraRequiredChecks: ["government.final-render-bound"],
	},
};

export function isProviderDomainSurfaceId(value: string): value is ProviderDomainSurfaceId {
	return PROVIDER_DOMAIN_SURFACE_IDS.some((surfaceId) => surfaceId === value);
}

export async function runTelclaudeProviderDomainProbe(input: {
	readonly surfaceId: ProviderDomainSurfaceId;
	readonly allowRun: boolean;
	readonly observedAt?: string;
}): Promise<ProviderDomainProbeEvidence> {
	const observedAt = input.observedAt ?? new Date().toISOString();
	const config = PROVIDER_CONFIGS[input.surfaceId];
	if (input.allowRun !== true) {
		return {
			schemaVersion: PROVIDER_DOMAIN_PROBE_SCHEMA_VERSION,
			probeId: input.surfaceId,
			status: "fail",
			ran: false,
			observedAt,
			source: PROVIDER_DOMAIN_PROBE_SOURCE,
			summary: `${config.providerId} provider-domain harness was not allowed to run`,
			checks: [
				{
					name: `${config.providerId}.read-through-provider-proxy`,
					status: "fail",
					detail: "run with --allow-run to execute the deterministic provider-domain harness",
				},
			],
			observations: emptyObservations(config),
		};
	}

	const checks: ProbeCheck[] = [];
	const observations: ProviderDomainProbeEvidence["observations"] = emptyObservations(config);
	const providerProxyCalls: ProviderProxyRequest[] = [];
	const acceptedApprovals = new Map<string, string>();
	const serverSideApprovals = new Map<string, string>();
	let nowMs = 100_000;
	let nextRef = 0;

	const ledger = createTelclaudeMcpSideEffectLedger({
		nowMs: () => nowMs,
		makeRef: () => `${config.providerId}-provider-probe-${++nextRef}`,
		defaultTtlMs: 60_000,
		verifyApproval: (request) => {
			observations.approvalVerifierCallCount += 1;
			const expectedContentHash = acceptedApprovals.get(request.approvalToken);
			if (!expectedContentHash) {
				return {
					ok: false,
					code: "approval_token_unknown",
					reason: "approval token is not accepted by the probe vault",
				};
			}
			if (expectedContentHash !== request.binding.contentHash) {
				return {
					ok: false,
					code: "approval_content_mismatch",
					reason: "approval token does not match prepared provider action",
				};
			}
			return { ok: true, approvalId: request.approvalToken };
		},
	});

	const providerProxy = async (request: ProviderProxyRequest) => {
		providerProxyCalls.push(request);
		observations.providerProxyCallCount = providerProxyCalls.length;
		if (request.approvalMode === "preapproved-ledger") {
			return { status: "ok" as const, data: { committed: true, providerId: request.providerId } };
		}
		return { status: "ok" as const, data: config.readData };
	};

	const clients = createTelclaudeLiveMcpRelayClients({
		ledger,
		makeApprovalRequestId: makeApprovalIds(),
		providerProxy,
		providerWriteApproverActorId: "operator:provider-probe-approver",
	});
	const executeDeps = createTelclaudeMcpLedgerExecuteDependencies({
		ledger,
		providerProxy,
		providerApprovalTokenResolver: ({ actionRef }) => {
			const approvalToken = serverSideApprovals.get(actionRef);
			if (!approvalToken) {
				return {
					ok: false,
					code: "approval_token_unavailable",
					reason: "server-side approval token is unavailable",
					retryable: true,
				};
			}
			serverSideApprovals.delete(actionRef);
			return { ok: true, approvalToken };
		},
		providerApprovalTokenIssuer: ({ providerId, service, action, approvalNonce, params }) => {
			observations.sidecarTokenIssuerCallCount += 1;
			return `sidecar:${providerId}:${service}:${action}:${approvalNonce}:${hashJson(params)}`;
		},
		nowMs: () => nowMs,
	});
	const bridge = createTelclaudeMcpBridge(authorityFor(config.providerId), {
		...clients,
		...executeDeps,
	});

	const readResult = await bridge.tc_provider_read({
		service: config.providerId,
		action: config.readAction,
		params: config.readParams,
	});
	const readCall = providerProxyCalls[0];
	observations.readRequestBodyHash = requestBodyHash(readCall);
	pushCheck(
		checks,
		`${config.providerId}.read-through-provider-proxy`,
		providerProxyCalls.length === 1 &&
			providerProxyCallMatches(readCall, config, {
				action: config.readAction,
				params: config.readParams,
				preapproved: false,
			}) &&
			JSON.stringify(readResult) === JSON.stringify(config.readData),
		`${config.providerId} read routes through the relay provider proxy without exposing credentials`,
	);

	const prepared = (await bridge.tc_provider_prepare_write({
		service: config.providerId,
		action: config.writeAction,
		params: config.writeParams,
		idempotencyKey: config.idempotencyKey,
	})) as { actionRef?: string; approvalRequestId?: string };
	const record = isProviderRecord(ledger.get(prepared.actionRef ?? ""))
		? (ledger.get(prepared.actionRef ?? "") as TelclaudeMcpProviderSideEffectRecord)
		: null;
	if (!record) throw new Error(`${config.providerId} provider-domain probe failed to prepare`);
	const binding = getTelclaudeMcpSideEffectApprovalBinding(record);
	observations.actionRef = record.ref;
	observations.paramsHash = record.paramsHash;
	observations.bodyHash = record.bodyHash;
	observations.contentHash = binding.contentHash;
	pushCheck(
		checks,
		`${config.providerId}.prepare-write-ledger-bound`,
		record.status === "prepared" &&
			record.providerId === config.providerId &&
			record.service === config.providerId &&
			record.action === config.writeAction &&
			record.providerAccountRef === config.expectedProviderAccountRef &&
			record.approverActorId === "operator:provider-probe-approver" &&
			record.approverActorId !== record.actorId &&
			record.idempotencyKey === config.idempotencyKey &&
			prepared.approvalRequestId === "approval-1" &&
			providerProxyCalls.length === 1,
		`${config.providerId} write preparation creates an unexecuted ledger-bound provider action`,
	);
	pushProviderSpecificRenderCheck(checks, config.providerId, record);

	const approvalToken = `operator-approved-${config.providerId}`;
	acceptedApprovals.set(approvalToken, binding.contentHash);
	serverSideApprovals.set(record.ref, approvalToken);
	const executed = resultShape(
		await bridge.tc_provider_execute_write({
			actionRef: record.ref,
		}),
	);
	const writeCall = providerProxyCalls[1];
	observations.writeRequestBodyHash = requestBodyHash(writeCall);
	pushCheck(
		checks,
		`${config.providerId}.approved-write-relay-sidecar-token`,
		executed.ok === true &&
			executed.record?.ref === record.ref &&
			executed.record?.status === "executed" &&
			providerProxyCallMatches(writeCall, config, {
				action: config.writeAction,
				params: config.writeParams,
				preapproved: true,
			}) &&
			writeCall?.approvalToken !== approvalToken &&
			typeof writeCall?.approvalToken === "string" &&
			writeCall.approvalToken.startsWith(`sidecar:${config.providerId}:`),
		`${config.providerId} approved write executes through relay proxy using a sidecar-scoped token`,
	);

	const wrongActorRecord = prepareRecordForNegative(ledger, config, "wrong-actor");
	const wrongActorToken = `operator-approved-${config.providerId}-wrong-actor`;
	acceptedApprovals.set(
		wrongActorToken,
		getTelclaudeMcpSideEffectApprovalBinding(wrongActorRecord).contentHash,
	);
	serverSideApprovals.set(wrongActorRecord.ref, wrongActorToken);
	const wrongActor = resultShape(
		await createTelclaudeMcpBridge(
			{ ...authorityFor(config.providerId), actorId: "operator:other" },
			{ ...clients, ...executeDeps },
		).tc_provider_execute_write({
			actionRef: wrongActorRecord.ref,
		}),
	);
	observations.wrongActorCode = wrongActor.code;
	pushCheck(
		checks,
		`${config.providerId}.wrong-actor-denied`,
		wrongActor.ok === false && wrongActor.code === "effect_authority_mismatch",
		`${config.providerId} execute denies an actor that did not prepare the provider action`,
	);

	const wrongScopeRecord = prepareRecordForNegative(ledger, config, "wrong-provider-scope");
	const wrongScopeToken = `operator-approved-${config.providerId}-wrong-scope`;
	acceptedApprovals.set(
		wrongScopeToken,
		getTelclaudeMcpSideEffectApprovalBinding(wrongScopeRecord).contentHash,
	);
	serverSideApprovals.set(wrongScopeRecord.ref, wrongScopeToken);
	const wrongProviderScope = resultShape(
		await createTelclaudeMcpBridge(
			{ ...authorityFor(config.providerId), providerScopes: ["google"] },
			{ ...clients, ...executeDeps },
		).tc_provider_execute_write({
			actionRef: wrongScopeRecord.ref,
		}),
	);
	observations.wrongProviderScopeCode = wrongProviderScope.code;
	pushCheck(
		checks,
		`${config.providerId}.wrong-provider-scope-denied`,
		wrongProviderScope.ok === false && wrongProviderScope.code === "effect_authority_mismatch",
		`${config.providerId} execute denies authority that lacks the prepared provider scope`,
	);

	const replay = resultShape(
		await bridge.tc_provider_execute_write({
			actionRef: record.ref,
		}),
	);
	observations.ledgerReplayCode = replay.code;
	pushCheck(
		checks,
		`${config.providerId}.replay-denied`,
		replay.ok === false && replay.code === "effect_already_executed",
		`${config.providerId} executed provider refs cannot be replayed`,
	);

	if (config.providerId === "clalit") {
		let emergencyCode = "not_denied";
		try {
			await bridge.tc_provider_prepare_write({
				service: "clalit",
				action: "appointments.book",
				params: { reason: "urgent chest pain emergency", clinicId: "clinic_123" },
				idempotencyKey: "clalit-emergency-probe",
			});
		} catch (error) {
			emergencyCode = error instanceof Error ? error.message : String(error);
		}
		observations.emergencyEscalationCode = emergencyCode;
		pushCheck(
			checks,
			"clalit.emergency-escalation-denied",
			emergencyCode.includes("urgent_health_escalation_required"),
			"Clalit urgent/emergency language is denied for autonomous provider action and must escalate",
		);
	}

	const rawCredentialObserved = JSON.stringify({
		readResult,
		providerProxyCalls,
		records: ledger.list(),
	}).includes(config.secretCanary);
	observations.rawCredentialObserved = rawCredentialObserved;
	pushCheck(
		checks,
		`${config.providerId}.raw-credential-not-observed`,
		rawCredentialObserved === false,
		`${config.providerId} evidence does not expose provider credentials or session material`,
	);

	const status = checks.every((check) => check.status === "pass") ? "pass" : "fail";
	nowMs += 1;
	return {
		schemaVersion: PROVIDER_DOMAIN_PROBE_SCHEMA_VERSION,
		probeId: input.surfaceId,
		status,
		ran: true,
		observedAt,
		source: PROVIDER_DOMAIN_PROBE_SOURCE,
		summary:
			status === "pass"
				? `${config.providerId} provider-domain probe passed`
				: `${config.providerId} provider-domain probe failed`,
		checks,
		observations,
	};
}

export function providerDomainProbeEvidenceFailure(
	surfaceId: ProviderDomainSurfaceId,
	evidence: unknown,
): string | null {
	const parsed = ProviderDomainProbeEvidenceSchema.safeParse(evidence);
	if (!parsed.success) {
		return `invalid provider-domain evidence: ${flattenZodError(parsed.error)}`;
	}
	const data = parsed.data;
	const config = PROVIDER_CONFIGS[surfaceId];
	const failures: string[] = [];
	if (data.probeId !== surfaceId) failures.push(`probeId is ${data.probeId}`);
	if (data.observations.providerId !== config.providerId) {
		failures.push(`providerId is ${data.observations.providerId}`);
	}
	if (data.status !== "pass") failures.push(`status is ${data.status}`);
	if (data.ran !== true) failures.push("harness did not run");

	const checksByName = new Map(data.checks.map((check) => [check.name, check]));
	for (const duplicate of duplicates(data.checks.map((check) => check.name))) {
		failures.push(`duplicate check ${duplicate}`);
	}
	for (const suffix of COMMON_CHECK_SUFFIXES) {
		const name = `${config.providerId}.${suffix}`;
		const check = checksByName.get(name);
		if (!check) failures.push(`check ${name} is missing`);
		else if (check.status !== "pass") failures.push(`check ${name} is ${check.status}`);
	}
	for (const name of config.extraRequiredChecks) {
		const check = checksByName.get(name);
		if (!check) failures.push(`check ${name} is missing`);
		else if (check.status !== "pass") failures.push(`check ${name} is ${check.status}`);
	}
	if (data.observations.providerProxyCallCount !== 2) {
		failures.push(`providerProxyCallCount is ${data.observations.providerProxyCallCount}`);
	}
	if (data.observations.approvalVerifierCallCount < 1) {
		failures.push(`approvalVerifierCallCount is ${data.observations.approvalVerifierCallCount}`);
	}
	if (data.observations.sidecarTokenIssuerCallCount !== 1) {
		failures.push(
			`sidecarTokenIssuerCallCount is ${data.observations.sidecarTokenIssuerCallCount}`,
		);
	}
	for (const [label, digest] of [
		["readRequestBodyHash", data.observations.readRequestBodyHash],
		["writeRequestBodyHash", data.observations.writeRequestBodyHash],
		["paramsHash", data.observations.paramsHash],
		["bodyHash", data.observations.bodyHash],
		["contentHash", data.observations.contentHash],
	] as const) {
		if (!digest) failures.push(`${label} is missing`);
	}
	if (data.observations.wrongActorCode !== "effect_authority_mismatch") {
		failures.push(`wrongActorCode is ${String(data.observations.wrongActorCode)}`);
	}
	if (data.observations.wrongProviderScopeCode !== "effect_authority_mismatch") {
		failures.push(`wrongProviderScopeCode is ${String(data.observations.wrongProviderScopeCode)}`);
	}
	if (data.observations.ledgerReplayCode !== "effect_already_executed") {
		failures.push(`ledgerReplayCode is ${String(data.observations.ledgerReplayCode)}`);
	}
	if (surfaceId === "providers.clalit") {
		const code = data.observations.emergencyEscalationCode ?? "";
		if (!code.includes("urgent_health_escalation_required")) {
			failures.push(`emergencyEscalationCode is ${String(code)}`);
		}
	}
	if (data.observations.rawCredentialObserved) {
		failures.push("raw provider credential material was observed");
	}
	return failures.length > 0 ? failures.join("; ") : null;
}

const ProviderDomainFixtureEvidenceSchema = z
	.object({
		schemaVersion: z.literal(PROVIDER_DOMAIN_FIXTURE_EVIDENCE_SCHEMA_VERSION),
		id: NonEmptyString,
		status: z.enum(["pass", "fail"]),
		ran: z.literal(true),
		evidence_path: NonEmptyString,
		observedAt: NonEmptyString,
		provenance: z
			.object({
				runner: z.literal(PROVIDER_DOMAIN_FIXTURE_RUNNER),
				source: z.literal(PROVIDER_DOMAIN_FIXTURE_SOURCE),
				command: NonEmptyString,
				probeId: z.enum(PROVIDER_DOMAIN_SURFACE_IDS),
				probePath: NonEmptyString,
				probeSha256: Sha256Digest,
			})
			.strict(),
		providerDomain: z
			.object({
				surfaceId: z.enum(PROVIDER_DOMAIN_SURFACE_IDS),
				providerId: z.enum(["bank", "clalit", "government"]),
				requiredProbeChecks: z.array(NonEmptyString),
				requiredObservationHashes: z.array(NonEmptyString),
			})
			.strict(),
		networkDeny: z
			.object({
				probeId: z.literal("network.direct-provider-denied"),
				probePath: NonEmptyString,
				probeSha256: Sha256Digest,
				requiredAttemptName: NonEmptyString,
				posture: z.enum(["agent-iptables", "contained-internal"]).optional(),
			})
			.strict()
			.optional(),
		checks: z.array(ProviderDomainProbeCheckSchema).min(1),
	})
	.strict();

type ProviderDomainFixtureEvidence = z.infer<typeof ProviderDomainFixtureEvidenceSchema>;

export function isProviderDomainFixtureId(value: string): value is ProviderDomainFixtureId {
	return PROVIDER_DOMAIN_FIXTURE_REQUIREMENTS.some((requirement) => requirement.id === value);
}

export function buildProviderDomainFixtureEvidenceBundle(
	input: {
		readonly evidenceDir?: string;
		readonly observedAt?: string;
		readonly probePaths?: Partial<Record<ProviderDomainSurfaceId, string>>;
		readonly networkProbePath?: string;
	} = {},
): {
	readonly schemaVersion: 1;
	readonly results: readonly {
		readonly id: ProviderDomainFixtureId;
		readonly status: "pass" | "fail";
		readonly evidence_path: string;
	}[];
	readonly evidence: readonly ProviderDomainFixtureEvidence[];
} {
	const evidenceDir = input.evidenceDir ?? DEFAULT_PROVIDER_DOMAIN_FIXTURE_EVIDENCE_DIR;
	const probeCache = new Map<
		ProviderDomainSurfaceId,
		{
			readonly path: string;
			readonly sha256: string;
			readonly evidence?: ProviderDomainProbeEvidence;
			readonly failure?: string;
		}
	>();
	const networkProbe = readProviderDirectNetworkProbeArtifact(
		input.networkProbePath ?? DEFAULT_PROVIDER_DIRECT_NETWORK_EVIDENCE_PATH,
	);
	const evidence = PROVIDER_DOMAIN_FIXTURE_REQUIREMENTS.map((requirement) =>
		buildProviderDomainFixtureEvidence(requirement, {
			evidenceDir,
			observedAt: input.observedAt,
			probePath:
				input.probePaths?.[requirement.surfaceId] ??
				DEFAULT_PROVIDER_DOMAIN_EVIDENCE_PATHS[requirement.surfaceId],
			probeCache,
			networkProbe,
		}),
	);
	return {
		schemaVersion: 1,
		results: evidence.map((item) => ({
			id: item.id as ProviderDomainFixtureId,
			status: item.status,
			evidence_path: item.evidence_path,
		})),
		evidence,
	};
}

export function providerDomainFixtureEvidenceFailure(
	fixtureId: string,
	evidence: unknown,
): string | null {
	const requirement = PROVIDER_DOMAIN_FIXTURE_REQUIREMENTS.find(
		(candidate) => candidate.id === fixtureId,
	) as ProviderDomainFixtureRequirement | undefined;
	if (!requirement) return null;
	const parsed = ProviderDomainFixtureEvidenceSchema.safeParse(evidence);
	if (!parsed.success) {
		return `invalid provider-domain fixture evidence ${fixtureId}: ${flattenZodError(parsed.error)}`;
	}
	const data = parsed.data;
	const failures: string[] = [];
	if (data.id !== fixtureId) failures.push(`fixture evidence id is ${data.id}`);
	if (data.status !== "pass") failures.push(`fixture evidence status is ${data.status}`);
	if (data.providerDomain.surfaceId !== requirement.surfaceId) {
		failures.push(`fixture surfaceId is ${data.providerDomain.surfaceId}`);
	}
	if (data.providerDomain.providerId !== requirement.providerId) {
		failures.push(`fixture providerId is ${data.providerDomain.providerId}`);
	}
	if (data.provenance.probeId !== requirement.surfaceId) {
		failures.push(`fixture probeId is ${data.provenance.probeId}`);
	}
	if (
		JSON.stringify(data.providerDomain.requiredProbeChecks) !==
		JSON.stringify(requirement.requiredChecks)
	) {
		failures.push("fixture requiredProbeChecks do not match provider-domain contract");
	}
	if (
		JSON.stringify(data.providerDomain.requiredObservationHashes) !==
		JSON.stringify(requirement.requiredObservationHashes)
	) {
		failures.push("fixture requiredObservationHashes do not match provider-domain contract");
	}
	const probe = readProviderDomainProbeArtifact(data.provenance.probePath, requirement.surfaceId);
	if (probe.sha256 !== data.provenance.probeSha256) {
		failures.push("fixture probeSha256 does not match provider-domain probe artifact");
	}
	if (probe.failure) {
		failures.push(`fixture probe artifact failed validation: ${probe.failure}`);
	} else if (probe.evidence) {
		failures.push(...providerDomainFixtureContractFailures(requirement, data, probe.evidence));
	}
	if (requirement.kind === "direct-provider-deny") {
		failures.push(...providerDirectNetworkFixtureFailures(requirement, data));
	} else if (data.networkDeny) {
		failures.push("provider-domain fixture unexpectedly includes direct-provider network evidence");
	}
	return failures.length > 0 ? failures.join("; ") : null;
}

function buildProviderDomainFixtureEvidence(
	requirement: ProviderDomainFixtureRequirement,
	options: {
		readonly evidenceDir: string;
		readonly observedAt?: string;
		readonly probePath: string;
		readonly probeCache: Map<
			ProviderDomainSurfaceId,
			{
				readonly path: string;
				readonly sha256: string;
				readonly evidence?: ProviderDomainProbeEvidence;
				readonly failure?: string;
			}
		>;
		readonly networkProbe: {
			readonly path: string;
			readonly sha256: string;
			readonly evidence?: ProviderDirectNetworkProbeEvidence;
			readonly failure?: string;
		};
	},
): ProviderDomainFixtureEvidence {
	const probe = cachedProviderDomainProbeArtifact(
		options.probeCache,
		requirement.surfaceId,
		options.probePath,
	);
	const checks =
		requirement.kind === "direct-provider-deny"
			? buildProviderDirectNetworkFixtureChecks(requirement, options.networkProbe)
			: buildProviderDomainFixtureChecks(requirement, probe.evidence, probe.failure);
	const status =
		probe.failure === undefined &&
		(requirement.kind !== "direct-provider-deny" || options.networkProbe.failure === undefined) &&
		checks.every((check) => check.status === "pass")
			? "pass"
			: "fail";
	return {
		schemaVersion: PROVIDER_DOMAIN_FIXTURE_EVIDENCE_SCHEMA_VERSION,
		id: requirement.id,
		status,
		ran: true,
		evidence_path: path.join(options.evidenceDir, `${requirement.id}.json`),
		observedAt: probe.evidence?.observedAt ?? options.observedAt ?? new Date().toISOString(),
		provenance: {
			runner: PROVIDER_DOMAIN_FIXTURE_RUNNER,
			source: PROVIDER_DOMAIN_FIXTURE_SOURCE,
			command: "pnpm dev hermes fixtures --include-provider-domain --write",
			probeId: requirement.surfaceId,
			probePath: options.probePath,
			probeSha256: probe.sha256,
		},
		providerDomain: {
			surfaceId: requirement.surfaceId,
			providerId: requirement.providerId,
			requiredProbeChecks: [...requirement.requiredChecks],
			requiredObservationHashes: [...requirement.requiredObservationHashes],
		},
		...(requirement.kind === "direct-provider-deny" && requirement.networkAttemptName
			? {
					networkDeny: {
						probeId: "network.direct-provider-denied" as const,
						probePath: options.networkProbe.path,
						probeSha256: options.networkProbe.sha256,
						requiredAttemptName: requirement.networkAttemptName,
						...(options.networkProbe.evidence?.posture
							? { posture: options.networkProbe.evidence.posture }
							: {}),
					},
				}
			: {}),
		checks,
	};
}

function buildProviderDomainFixtureChecks(
	requirement: ProviderDomainFixtureRequirement,
	probe: ProviderDomainProbeEvidence | undefined,
	probeFailure: string | undefined,
): ProbeCheck[] {
	if (!probe || probeFailure) {
		return [
			{
				name: `${requirement.id}.provider-domain-probe-valid`,
				status: "fail",
				detail: probeFailure ?? "provider-domain probe evidence is missing",
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
				detail: check?.detail ?? "required provider-domain probe check is missing",
			} satisfies ProbeCheck;
		}),
		...requirement.requiredObservationHashes.map(
			(field) =>
				({
					name: `${requirement.id}.${field}`,
					status: probe.observations[field] ? "pass" : "fail",
					detail: probe.observations[field]
						? `provider-domain probe recorded ${field}`
						: `provider-domain probe did not record ${field}`,
				}) satisfies ProbeCheck,
		),
	];
}

function buildProviderDirectNetworkFixtureChecks(
	requirement: ProviderDomainFixtureRequirement,
	networkProbe: {
		readonly evidence?: ProviderDirectNetworkProbeEvidence;
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
				? `direct ${requirement.providerId} provider endpoint was denied in the Hermes runtime namespace`
				: validationFailure,
		},
	];
}

function providerDomainFixtureContractFailures(
	requirement: ProviderDomainFixtureRequirement,
	fixture: ProviderDomainFixtureEvidence,
	probe: ProviderDomainProbeEvidence,
): string[] {
	const failures: string[] = [];
	const probeFailure = providerDomainProbeEvidenceFailure(requirement.surfaceId, probe);
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

function providerDirectNetworkFixtureFailures(
	requirement: ProviderDomainFixtureRequirement,
	fixture: ProviderDomainFixtureEvidence,
): string[] {
	const failures: string[] = [];
	const binding = fixture.networkDeny;
	if (!binding) return ["direct-provider fixture networkDeny binding is missing"];
	if (binding.probeId !== "network.direct-provider-denied") {
		failures.push(`networkDeny probeId is ${binding.probeId}`);
	}
	if (binding.requiredAttemptName !== requirement.networkAttemptName) {
		failures.push("networkDeny requiredAttemptName does not match provider contract");
	}
	const network = readProviderDirectNetworkProbeArtifact(binding.probePath);
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

function cachedProviderDomainProbeArtifact(
	cache: Map<
		ProviderDomainSurfaceId,
		{
			readonly path: string;
			readonly sha256: string;
			readonly evidence?: ProviderDomainProbeEvidence;
			readonly failure?: string;
		}
	>,
	surfaceId: ProviderDomainSurfaceId,
	probePath: string,
): {
	readonly path: string;
	readonly sha256: string;
	readonly evidence?: ProviderDomainProbeEvidence;
	readonly failure?: string;
} {
	const cached = cache.get(surfaceId);
	if (cached?.path === probePath) return cached;
	const read = readProviderDomainProbeArtifact(probePath, surfaceId);
	cache.set(surfaceId, read);
	return read;
}

function readProviderDomainProbeArtifact(
	probePath: string,
	surfaceId: ProviderDomainSurfaceId,
): {
	readonly path: string;
	readonly sha256: string;
	readonly evidence?: ProviderDomainProbeEvidence;
	readonly failure?: string;
} {
	if (!fs.existsSync(probePath)) {
		return {
			path: probePath,
			sha256: hashText(`${probePath}:missing`),
			failure: `missing provider-domain probe artifact ${probePath}`,
		};
	}
	let raw: unknown;
	try {
		raw = JSON.parse(fs.readFileSync(probePath, "utf8")) as unknown;
	} catch (error) {
		return {
			path: probePath,
			sha256: hashFile(probePath),
			failure: `unreadable provider-domain probe artifact: ${
				error instanceof Error ? error.message : String(error)
			}`,
		};
	}
	const parsed = ProviderDomainProbeEvidenceSchema.safeParse(raw);
	if (!parsed.success) {
		return {
			path: probePath,
			sha256: hashFile(probePath),
			failure: `invalid provider-domain probe artifact: ${flattenZodError(parsed.error)}`,
		};
	}
	const semanticFailure = providerDomainProbeEvidenceFailure(surfaceId, parsed.data);
	return {
		path: probePath,
		sha256: hashFile(probePath),
		evidence: parsed.data,
		...(semanticFailure ? { failure: semanticFailure } : {}),
	};
}

function readProviderDirectNetworkProbeArtifact(probePath: string): {
	readonly path: string;
	readonly sha256: string;
	readonly evidence?: ProviderDirectNetworkProbeEvidence;
	readonly failure?: string;
} {
	if (!fs.existsSync(probePath)) {
		return {
			path: probePath,
			sha256: hashText(`${probePath}:missing`),
			failure: `missing direct-provider network artifact ${probePath}`,
		};
	}
	let raw: unknown;
	try {
		raw = JSON.parse(fs.readFileSync(probePath, "utf8")) as unknown;
	} catch (error) {
		return {
			path: probePath,
			sha256: hashFile(probePath),
			failure: `unreadable direct-provider network artifact: ${
				error instanceof Error ? error.message : String(error)
			}`,
		};
	}
	const parsed = ProviderDirectNetworkProbeEvidenceSchema.safeParse(raw);
	if (!parsed.success) {
		return {
			path: probePath,
			sha256: hashFile(probePath),
			failure: `invalid direct-provider network artifact: ${flattenZodError(parsed.error)}`,
		};
	}
	const failure = networkProbeEvidenceFailure(parsed.data, {
		expectedId: "network.direct-provider-denied",
	});
	return {
		path: probePath,
		sha256: hashFile(probePath),
		evidence: parsed.data,
		...(failure ? { failure } : {}),
	};
}

function emptyObservations(
	config: (typeof PROVIDER_CONFIGS)[ProviderDomainSurfaceId],
): ProviderDomainProbeEvidence["observations"] {
	return {
		providerId: config.providerId,
		readAction: config.readAction,
		writeAction: config.writeAction,
		approvalVerifierCallCount: 0,
		providerProxyCallCount: 0,
		sidecarTokenIssuerCallCount: 0,
		rawCredentialObserved: false,
	};
}

function authorityFor(providerId: ProviderId): TelclaudeMcpAuthority {
	return {
		actorId: "operator:provider-probe",
		profileId: "provider-probe",
		domain: "private",
		memorySource: "telegram:provider-probe",
		writableNamespace: "telegram:provider-probe",
		providerScopes: [providerId],
		outboundChannels: [],
		endpointId: "mcp-provider-probe",
		networkNamespace: "tc-hermes-contained",
	};
}

function makeApprovalIds(): () => string {
	let count = 0;
	return () => `approval-${++count}`;
}

function prepareRecordForNegative(
	ledger: ReturnType<typeof createTelclaudeMcpSideEffectLedger>,
	config: (typeof PROVIDER_CONFIGS)[ProviderDomainSurfaceId],
	label: string,
): TelclaudeMcpProviderSideEffectRecord {
	const record = ledger.prepare({
		kind: "provider",
		actorId: "operator:provider-probe",
		approverActorId: "operator:provider-probe-approver",
		profileId: "provider-probe",
		domain: "private",
		providerId: config.providerId,
		service: config.providerId,
		action: `${label}.${config.writeAction}`,
		params: config.writeParams,
		providerAccountRef: config.expectedProviderAccountRef,
		approvalRequestId: `approval-${label}`,
		approvalRevision: 1,
		wysiwysRender: `${config.providerId}.${config.providerId}.${label}.${config.writeAction}`,
		idempotencyKey: `${config.idempotencyKey}-${label}`,
	});
	if (!isProviderRecord(record)) throw new Error("negative provider record is not provider");
	return record;
}

function providerProxyCallMatches(
	request: ProviderProxyRequest | undefined,
	config: (typeof PROVIDER_CONFIGS)[ProviderDomainSurfaceId],
	expected: {
		readonly action: string;
		readonly params: Record<string, unknown>;
		readonly preapproved: boolean;
	},
): boolean {
	if (!request || request.providerId !== config.providerId || request.path !== "/v1/fetch") {
		return false;
	}
	if (request.method !== "POST" || request.userId !== "operator:provider-probe") return false;
	if (expected.preapproved) {
		if (request.approvalMode !== "preapproved-ledger") return false;
		if (typeof request.approvalToken !== "string" || !request.approvalToken) return false;
	} else if (request.approvalToken || request.approvalMode) {
		return false;
	}
	const body = parseJsonObject(request.body);
	return (
		body?.service === config.providerId &&
		body.action === expected.action &&
		JSON.stringify(sortKeysDeep(body.params)) === JSON.stringify(sortKeysDeep(expected.params))
	);
}

function requestBodyHash(request: ProviderProxyRequest | undefined): string | undefined {
	return request?.body ? hashText(request.body) : undefined;
}

function parseJsonObject(value: string | undefined): Record<string, unknown> | null {
	if (!value) return null;
	try {
		const parsed = JSON.parse(value) as unknown;
		return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
			? (parsed as Record<string, unknown>)
			: null;
	} catch {
		return null;
	}
}

function pushProviderSpecificRenderCheck(
	checks: ProbeCheck[],
	providerId: ProviderId,
	record: TelclaudeMcpProviderSideEffectRecord,
): void {
	if (providerId === "clalit") return;
	pushCheck(
		checks,
		`${providerId}.final-render-bound`,
		record.wysiwysRender === `${record.providerId}.${record.service}.${record.action}` &&
			record.idempotencyKey !== undefined &&
			record.approvalRevision === 1,
		`${providerId} write carries human-readable render, canonical params, revision, and idempotency binding`,
	);
}

function pushCheck(checks: ProbeCheck[], name: string, pass: boolean, detail: string): void {
	checks.push({ name, status: pass ? "pass" : "fail", detail });
}

function resultShape(value: unknown): {
	readonly ok?: boolean;
	readonly code?: string;
	readonly record?: TelclaudeMcpSideEffectRecord;
} {
	if (!value || typeof value !== "object") return {};
	return value as {
		readonly ok?: boolean;
		readonly code?: string;
		readonly record?: TelclaudeMcpSideEffectRecord;
	};
}

function isProviderRecord(value: unknown): value is TelclaudeMcpProviderSideEffectRecord {
	return (
		typeof value === "object" && value !== null && (value as { kind?: unknown }).kind === "provider"
	);
}

function hashJson(value: unknown): string {
	return hashText(JSON.stringify(sortKeysDeep(value)));
}

function hashFile(filePath: string): string {
	return `sha256:${crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex")}`;
}

function hashText(value: string): string {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function flattenZodError(error: z.ZodError): string {
	return error.issues
		.map((issue) => {
			const pathLabel = issue.path.length > 0 ? issue.path.join(".") : "<root>";
			return `${pathLabel}: ${issue.message}`;
		})
		.join("; ");
}

function duplicates(values: readonly string[]): string[] {
	const seen = new Set<string>();
	const duplicated = new Set<string>();
	for (const value of values) {
		if (seen.has(value)) duplicated.add(value);
		seen.add(value);
	}
	return [...duplicated].sort();
}
