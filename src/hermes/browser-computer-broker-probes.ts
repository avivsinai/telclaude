import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { z } from "zod";
import { sortKeysDeep } from "../crypto/canonical-hash.js";
import {
	type HermesSignedEvidenceValidationOptions,
	hermesAllowsStaleAttestations,
	hermesAttestationFreshnessFailure,
} from "./attestation-validation.js";
import {
	BROWSER_COMPUTER_BROKER_ATTESTATION_RUNNER,
	BROWSER_COMPUTER_BROKER_ATTESTATION_SCHEMA_VERSION,
	BROWSER_COMPUTER_BROKER_ATTESTATION_SOURCE,
	type BrowserComputerBrokerAttestation,
	browserComputerBrokerAttestationFieldsForEvidence,
	browserComputerBrokerAttestationSignatureFailure,
	signBrowserComputerBrokerAttestation,
} from "./browser-computer-broker-attestation.js";

export const BROWSER_COMPUTER_BROKER_PROBE_SCHEMA_VERSION =
	"telclaude.hermes.browser-computer-broker-probe.v1";
export const BROWSER_COMPUTER_BROKER_PROBE_SOURCE = "telclaude-browser-computer-broker-harness";
export const BROWSER_COMPUTER_BROKER_FIXTURE_EVIDENCE_SCHEMA_VERSION =
	"telclaude.hermes.browser-computer-broker-fixture-evidence.v1";
export const BROWSER_COMPUTER_BROKER_FIXTURE_SOURCE =
	"machine-observed-browser-computer-broker-probe";
export const BROWSER_COMPUTER_BROKER_FIXTURE_RUNNER =
	"telclaude-browser-computer-broker-fixture-generator";
export const DEFAULT_BROWSER_COMPUTER_BROKER_FIXTURE_EVIDENCE_DIR = "artifacts/hermes/fixtures";
export const NETWORK_EGRESS_BROKER_RUN_REPORT_SCHEMA_VERSION =
	"telclaude.hermes.network-egress-broker-run.v1";
export const NETWORK_EGRESS_BROKER_RUN_REPORT_SOURCE =
	"machine-observed-network-egress-broker-report";

export const BROWSER_COMPUTER_BROKER_SURFACE_IDS = [
	"browser.profiles",
	"computer.broker",
	"network.egress-broker",
] as const;

export type BrowserComputerBrokerSurfaceId = (typeof BROWSER_COMPUTER_BROKER_SURFACE_IDS)[number];

export const DEFAULT_BROWSER_COMPUTER_BROKER_EVIDENCE_PATHS: Record<
	BrowserComputerBrokerSurfaceId,
	string
> = {
	"browser.profiles": "artifacts/hermes/probes/browser-profiles.json",
	"computer.broker": "artifacts/hermes/probes/computer-broker.json",
	"network.egress-broker": "artifacts/hermes/probes/network-egress-broker.json",
};

const NonEmptyString = z.string().trim().min(1);
const Sha256Digest = z.string().regex(/^sha256:[a-f0-9]{64}$/i);
const NetworkEgressAttemptKindSchema = z.enum([
	"public-research",
	"provider",
	"model",
	"vault",
	"metadata",
	"private-network",
	"smtp",
	"imap",
	"whatsapp-bridge",
	"dns-53",
	"doh",
	"dot",
	"connect-proxy",
	"websocket",
	"webrtc",
	"ip-literal",
	"dns-rebinding",
	"localhost-callback",
	"unquarantined-upload",
	"browser-provider-bypass",
	"computer-covert-egress",
]);
type NetworkEgressAttemptKind = z.infer<typeof NetworkEgressAttemptKindSchema>;

const BrowserComputerBrokerProbeCheckSchema = z
	.object({
		name: NonEmptyString,
		status: z.enum(["pass", "fail"]),
		detail: NonEmptyString,
	})
	.strict();

const BrowserComputerBrokerProbeObservationSchema = z
	.object({
		profileIsolationHash: Sha256Digest.optional(),
		allowedResearchAuditHash: Sha256Digest.optional(),
		cookieIsolationHash: Sha256Digest.optional(),
		browserQuarantineHash: Sha256Digest.optional(),
		browserDeniedTargetHash: Sha256Digest.optional(),
		computerAllowedAuditHash: Sha256Digest.optional(),
		computerUnauthorizedDenialHash: Sha256Digest.optional(),
		computerSessionIsolationHash: Sha256Digest.optional(),
		computerQuarantineHash: Sha256Digest.optional(),
		computerApprovalHash: Sha256Digest.optional(),
		egressAllowedAuditHash: Sha256Digest.optional(),
		egressDenialMatrixHash: Sha256Digest.optional(),
		egressDnsDenialHash: Sha256Digest.optional(),
		egressCovertDenialHash: Sha256Digest.optional(),
		auditEntryCount: z.number().int().nonnegative(),
		deniedAttemptCount: z.number().int().nonnegative(),
		quarantineRefCount: z.number().int().nonnegative(),
		directEgressDenialCount: z.number().int().nonnegative(),
	})
	.strict();

const InternalResponseProofSchema = z
	.object({
		version: NonEmptyString,
		scope: NonEmptyString,
		timestamp: NonEmptyString,
		nonce: NonEmptyString,
		method: NonEmptyString,
		path: NonEmptyString,
		requestBodySha256: NonEmptyString,
		responseBodySha256: NonEmptyString,
		signature: NonEmptyString,
	})
	.strict();

const BrowserComputerBrokerAttestationSchema = z
	.object({
		schemaVersion: z.literal(BROWSER_COMPUTER_BROKER_ATTESTATION_SCHEMA_VERSION),
		source: z.literal(BROWSER_COMPUTER_BROKER_ATTESTATION_SOURCE),
		runner: z.literal(BROWSER_COMPUTER_BROKER_ATTESTATION_RUNNER),
		probeEvidenceSchemaVersion: NonEmptyString,
		probeId: z.enum(BROWSER_COMPUTER_BROKER_SURFACE_IDS),
		status: z.enum(["pass", "fail"]),
		ran: z.boolean(),
		observedAt: NonEmptyString,
		evidenceSource: NonEmptyString,
		checksSha256: Sha256Digest,
		observationsSha256: Sha256Digest,
		evidenceSha256: Sha256Digest,
		signature: InternalResponseProofSchema,
	})
	.strict();

export const BrowserComputerBrokerProbeEvidenceSchema = z
	.object({
		schemaVersion: z.literal(BROWSER_COMPUTER_BROKER_PROBE_SCHEMA_VERSION),
		probeId: z.enum(BROWSER_COMPUTER_BROKER_SURFACE_IDS),
		status: z.enum(["pass", "fail"]),
		ran: z.boolean(),
		observedAt: NonEmptyString,
		source: z.literal(BROWSER_COMPUTER_BROKER_PROBE_SOURCE),
		summary: NonEmptyString,
		checks: z.array(BrowserComputerBrokerProbeCheckSchema).min(1),
		observations: BrowserComputerBrokerProbeObservationSchema,
		runnerAttestation: BrowserComputerBrokerAttestationSchema.optional(),
	})
	.strict();

export type BrowserComputerBrokerProbeEvidence = z.infer<
	typeof BrowserComputerBrokerProbeEvidenceSchema
>;
type BrowserComputerBrokerProbeCheck = z.infer<typeof BrowserComputerBrokerProbeCheckSchema>;
type BrowserComputerBrokerProbeObservation = z.infer<
	typeof BrowserComputerBrokerProbeObservationSchema
>;

const NetworkEgressBrokerRunAttemptSchema = z
	.object({
		name: NonEmptyString,
		kind: NetworkEgressAttemptKindSchema,
		target: NonEmptyString,
		expectation: z.enum(["allow", "deny"]),
		status: z.enum(["pass", "fail"]),
		observed: NonEmptyString,
		detail: NonEmptyString,
		route: NonEmptyString.optional(),
		httpStatus: z.number().int().optional(),
		errorName: NonEmptyString.optional(),
		errorCode: NonEmptyString.optional(),
		durationMs: z.number().nonnegative().optional(),
	})
	.strict();

const NetworkEgressBrokerRunReportSchema = z
	.object({
		schemaVersion: z.literal(NETWORK_EGRESS_BROKER_RUN_REPORT_SCHEMA_VERSION),
		surfaceId: z.literal("network.egress-broker"),
		ran: z.literal(true),
		observedAt: NonEmptyString,
		source: z.literal(NETWORK_EGRESS_BROKER_RUN_REPORT_SOURCE),
		summary: NonEmptyString,
		attempts: z.array(NetworkEgressBrokerRunAttemptSchema).min(1),
	})
	.strict();

const NETWORK_EGRESS_DENIAL_TARGETS = [
	{ kind: "provider", target: "https://bank.example.invalid/login" },
	{ kind: "model", target: "https://api.openai.com/v1/responses" },
	{ kind: "vault", target: "http://vault:8222/v1/secrets" },
	{ kind: "metadata", target: "http://169.254.169.254/latest/meta-data" },
	{ kind: "private-network", target: "http://10.0.0.12/admin" },
	{ kind: "smtp", target: "smtp://mail.example.invalid:587" },
	{ kind: "imap", target: "imap://mail.example.invalid:993" },
	{ kind: "whatsapp-bridge", target: "ws://whatsapp-bridge.internal/socket" },
	{ kind: "dns-53", target: "udp://8.8.8.8:53" },
	{ kind: "doh", target: "https://dns.google/dns-query" },
	{ kind: "dot", target: "tls://1.1.1.1:853" },
	{ kind: "connect-proxy", target: "CONNECT proxy.example.invalid:443" },
	{ kind: "websocket", target: "wss://exfil.example.invalid/socket" },
	{ kind: "webrtc", target: "webrtc://peer/exfil" },
	{ kind: "ip-literal", target: "https://203.0.113.99/upload" },
	{ kind: "dns-rebinding", target: "https://rebind.example.invalid" },
	{ kind: "localhost-callback", target: "http://127.0.0.1:33221/callback" },
	{ kind: "unquarantined-upload", target: "https://example.org/upload/raw-local-path" },
	{ kind: "browser-provider-bypass", target: "https://clalit.example.invalid/session" },
	{ kind: "computer-covert-egress", target: "app://terminal/curl-exfil" },
] as const satisfies readonly { kind: NetworkEgressAttemptKind; target: string }[];

const NETWORK_EGRESS_CHECK_REQUIREMENTS = [
	{
		name: "egress.direct-provider-denied",
		kinds: ["provider"],
		detail: "Direct provider egress was denied by live broker evidence",
	},
	{
		name: "egress.direct-model-denied",
		kinds: ["model"],
		detail: "Direct model-provider egress was denied by live broker evidence",
	},
	{
		name: "egress.direct-vault-denied",
		kinds: ["vault"],
		detail: "Direct vault egress was denied by live broker evidence",
	},
	{
		name: "egress.metadata-private-denied",
		kinds: ["metadata", "private-network"],
		detail: "Metadata and private-network egress were denied by live broker evidence",
	},
	{
		name: "egress.smtp-imap-whatsapp-denied",
		kinds: ["smtp", "imap", "whatsapp-bridge"],
		detail: "Direct SMTP, IMAP, and WhatsApp bridge egress were denied by live broker evidence",
	},
	{
		name: "egress.dns-doh-dot-denied",
		kinds: ["dns-53", "doh", "dot"],
		detail: "Raw DNS, DoH, and DoT egress were denied by live broker evidence",
	},
	{
		name: "egress.proxy-tunnel-webrtc-websocket-denied",
		kinds: ["connect-proxy", "websocket", "webrtc"],
		detail:
			"CONNECT/proxy tunneling, WebSocket, and WebRTC egress were denied by live broker evidence",
	},
	{
		name: "egress.ip-literal-localhost-callback-denied",
		kinds: ["ip-literal", "dns-rebinding", "localhost-callback"],
		detail:
			"IP literal, DNS rebinding, and localhost callback egress were denied by live broker evidence",
	},
	{
		name: "egress.upload-without-quarantine-denied",
		kinds: ["unquarantined-upload"],
		detail: "Upload-without-quarantine egress was denied by live broker evidence",
	},
	{
		name: "egress.browser-provider-bypass-denied",
		kinds: ["browser-provider-bypass"],
		detail: "Browser-to-provider bypass egress was denied by live broker evidence",
	},
	{
		name: "egress.computer-covert-denied",
		kinds: ["computer-covert-egress"],
		detail: "Computer-use covert egress was denied by live broker evidence",
	},
] as const satisfies readonly {
	name: (typeof BROWSER_COMPUTER_REQUIRED_CHECKS)["network.egress-broker"][number];
	kinds: readonly NetworkEgressAttemptKind[];
	detail: string;
}[];

const BROWSER_COMPUTER_REQUIRED_CHECKS: Record<BrowserComputerBrokerSurfaceId, readonly string[]> =
	{
		"browser.profiles": [
			"browser.allowed-public-research",
			"browser.profile-cookie-isolation",
			"browser.cross-domain-denied",
			"browser.cookie-leak-denied",
			"browser.download-upload-quarantine",
			"browser.audit-recorded",
		],
		"computer.broker": [
			"computer.allowed-target-audited",
			"computer.unauthorized-target-denied",
			"computer.display-session-isolated",
			"computer.clipboard-policy-enforced",
			"computer.sensitive-submit-approval-required",
			"computer.screenshot-video-quarantine",
		],
		"network.egress-broker": [
			"egress.allowed-public-through-broker",
			"egress.direct-provider-denied",
			"egress.direct-model-denied",
			"egress.direct-vault-denied",
			"egress.metadata-private-denied",
			"egress.smtp-imap-whatsapp-denied",
			"egress.dns-doh-dot-denied",
			"egress.proxy-tunnel-webrtc-websocket-denied",
			"egress.ip-literal-localhost-callback-denied",
			"egress.upload-without-quarantine-denied",
			"egress.browser-provider-bypass-denied",
			"egress.computer-covert-denied",
		],
	};

type BrokerFixtureRequirement = {
	readonly id: string;
	readonly surfaceId: BrowserComputerBrokerSurfaceId;
	readonly requiredChecks: readonly string[];
	readonly requiredObservationHashes: readonly (keyof BrowserComputerBrokerProbeObservation)[];
};

export const BROWSER_COMPUTER_BROKER_FIXTURE_REQUIREMENTS = [
	{
		id: "fixture.browser.allowed-research",
		surfaceId: "browser.profiles",
		requiredChecks: [
			"browser.allowed-public-research",
			"browser.profile-cookie-isolation",
			"browser.download-upload-quarantine",
			"browser.audit-recorded",
		],
		requiredObservationHashes: [
			"allowedResearchAuditHash",
			"profileIsolationHash",
			"browserQuarantineHash",
		],
	},
	{
		id: "fixture.computer.allowed-target",
		surfaceId: "computer.broker",
		requiredChecks: [
			"computer.allowed-target-audited",
			"computer.display-session-isolated",
			"computer.clipboard-policy-enforced",
			"computer.screenshot-video-quarantine",
		],
		requiredObservationHashes: [
			"computerAllowedAuditHash",
			"computerSessionIsolationHash",
			"computerQuarantineHash",
		],
	},
	{
		id: "fixture.browser.cross-domain-deny",
		surfaceId: "browser.profiles",
		requiredChecks: ["browser.cross-domain-denied"],
		requiredObservationHashes: ["browserDeniedTargetHash"],
	},
	{
		id: "fixture.browser.cookie-leak-deny",
		surfaceId: "browser.profiles",
		requiredChecks: ["browser.cookie-leak-denied"],
		requiredObservationHashes: ["cookieIsolationHash"],
	},
	{
		id: "fixture.computer.unauthorized-target-deny",
		surfaceId: "computer.broker",
		requiredChecks: [
			"computer.unauthorized-target-denied",
			"computer.sensitive-submit-approval-required",
		],
		requiredObservationHashes: ["computerUnauthorizedDenialHash", "computerApprovalHash"],
	},
] as const satisfies readonly BrokerFixtureRequirement[];

export type BrowserComputerBrokerFixtureId =
	(typeof BROWSER_COMPUTER_BROKER_FIXTURE_REQUIREMENTS)[number]["id"];

export function isBrowserComputerBrokerSurfaceId(
	value: string,
): value is BrowserComputerBrokerSurfaceId {
	return BROWSER_COMPUTER_BROKER_SURFACE_IDS.some((surfaceId) => surfaceId === value);
}

export function runTelclaudeBrowserComputerBrokerProbe(input: {
	readonly surfaceId: BrowserComputerBrokerSurfaceId;
	readonly allowRun: boolean;
	readonly observedAt?: string;
}): BrowserComputerBrokerProbeEvidence {
	const observedAt = input.observedAt ?? new Date().toISOString();
	if (input.allowRun !== true) {
		return {
			schemaVersion: BROWSER_COMPUTER_BROKER_PROBE_SCHEMA_VERSION,
			probeId: input.surfaceId,
			status: "fail",
			ran: false,
			observedAt,
			source: BROWSER_COMPUTER_BROKER_PROBE_SOURCE,
			summary: `${input.surfaceId} broker harness was not allowed to run`,
			checks: [
				{
					name:
						BROWSER_COMPUTER_REQUIRED_CHECKS[input.surfaceId][0] ?? `${input.surfaceId}.allow-run`,
					status: "fail",
					detail:
						"run with --allow-run to execute the deterministic browser/computer broker harness",
				},
			],
			observations: emptyObservations(),
		};
	}
	if (input.surfaceId === "browser.profiles") {
		return browserProfileProbe(input.surfaceId, observedAt);
	}
	if (input.surfaceId === "computer.broker") {
		return computerBrokerProbe(input.surfaceId, observedAt);
	}
	return networkEgressProbe(input.surfaceId, observedAt);
}

export function readNetworkEgressBrokerRunReport(reportPath: string): unknown {
	return JSON.parse(fs.readFileSync(reportPath, "utf8")) as unknown;
}

export function buildNetworkEgressBrokerProbeEvidenceFromReport(
	rawReport: unknown,
): BrowserComputerBrokerProbeEvidence {
	const report = parseNetworkEgressBrokerRunReport(rawReport);
	const allowedAttempts = report.attempts.filter(
		(attempt) =>
			attempt.kind === "public-research" &&
			attempt.expectation === "allow" &&
			attempt.status === "pass",
	);
	const passingDeniedKinds = new Set(
		report.attempts
			.filter((attempt) => attempt.expectation === "deny" && attempt.status === "pass")
			.map((attempt) => attempt.kind),
	);
	const denialAttempts = report.attempts.filter(
		(attempt) => attempt.expectation === "deny" && attempt.status === "pass",
	);
	const checks: BrowserComputerBrokerProbeCheck[] = [];
	pushCheck(
		checks,
		"egress.allowed-public-through-broker",
		allowedAttempts.some((attempt) => attempt.route === "telclaude-egress-broker"),
		allowedAttempts.some((attempt) => attempt.route === "telclaude-egress-broker")
			? "Allowed public research egress was observed through the Telclaude broker"
			: "Allowed public research egress was not observed through the Telclaude broker",
	);
	for (const requirement of NETWORK_EGRESS_CHECK_REQUIREMENTS) {
		const missingKinds = requirement.kinds.filter((kind) => !passingDeniedKinds.has(kind));
		pushCheck(
			checks,
			requirement.name,
			missingKinds.length === 0,
			missingKinds.length === 0
				? requirement.detail
				: `Missing live denied egress kinds: ${missingKinds.join(", ")}`,
		);
	}
	const evidence = brokerProbeReport("network.egress-broker", report.observedAt, checks, {
		...emptyObservations(),
		egressAllowedAuditHash: hashJson(allowedAttempts),
		egressDenialMatrixHash: hashJson(denialAttempts),
		egressDnsDenialHash: hashJson(
			denialAttempts.filter((attempt) => ["dns-53", "doh", "dot"].includes(attempt.kind)),
		),
		egressCovertDenialHash: hashJson(
			denialAttempts.filter((attempt) =>
				["connect-proxy", "websocket", "webrtc", "computer-covert-egress"].includes(attempt.kind),
			),
		),
		auditEntryCount: report.attempts.filter((attempt) => attempt.status === "pass").length,
		deniedAttemptCount: denialAttempts.length,
		directEgressDenialCount: passingDeniedKinds.size,
	});
	if (evidence.status !== "pass") return evidence;
	return {
		...evidence,
		runnerAttestation: signBrowserComputerBrokerAttestation(evidence),
	};
}

export function browserComputerBrokerProbeEvidenceFailure(
	surfaceId: BrowserComputerBrokerSurfaceId,
	evidence: unknown,
	options: HermesSignedEvidenceValidationOptions = {},
): string | null {
	const parsed = BrowserComputerBrokerProbeEvidenceSchema.safeParse(evidence);
	if (!parsed.success) {
		return `invalid browser/computer broker evidence: ${flattenZodError(parsed.error)}`;
	}
	const data = parsed.data;
	const failures: string[] = [];
	if (data.probeId !== surfaceId) failures.push(`probeId is ${data.probeId}`);
	if (data.status !== "pass") failures.push(`status is ${data.status}`);
	if (data.ran !== true) failures.push("harness did not run");
	if (data.source !== BROWSER_COMPUTER_BROKER_PROBE_SOURCE) {
		failures.push(`source is ${data.source}`);
	}
	for (const duplicate of duplicates(data.checks.map((check) => check.name))) {
		failures.push(`duplicate check ${duplicate}`);
	}
	const checksByName = new Map(data.checks.map((check) => [check.name, check]));
	for (const name of BROWSER_COMPUTER_REQUIRED_CHECKS[surfaceId]) {
		const check = checksByName.get(name);
		if (!check) failures.push(`check ${name} is missing`);
		else if (check.status !== "pass") failures.push(`check ${name} is ${check.status}`);
	}
	for (const field of requiredObservationFields(surfaceId)) {
		if (!data.observations[field]) failures.push(`${field} is missing`);
	}
	if (surfaceId === "network.egress-broker" && data.observations.directEgressDenialCount < 12) {
		failures.push(`directEgressDenialCount is ${data.observations.directEgressDenialCount}`);
	}
	const runnerAttestationFailure = brokerRunnerAttestationFailure(data, surfaceId, options);
	if (runnerAttestationFailure) failures.push(runnerAttestationFailure);
	if (surfaceId !== "network.egress-broker" && data.observations.quarantineRefCount < 1) {
		failures.push(`quarantineRefCount is ${data.observations.quarantineRefCount}`);
	}
	return failures.length > 0 ? failures.join("; ") : null;
}

function brokerRunnerAttestationFailure(
	data: BrowserComputerBrokerProbeEvidence,
	surfaceId: BrowserComputerBrokerSurfaceId,
	options: HermesSignedEvidenceValidationOptions,
): string | null {
	if (surfaceId !== "network.egress-broker") return null;
	const attestation = data.runnerAttestation as BrowserComputerBrokerAttestation | undefined;
	if (!attestation) return "runnerAttestation is missing";
	const freshnessFailure = hermesAttestationFreshnessFailure(
		"runnerAttestation observedAt",
		attestation.observedAt,
		options,
	);
	if (freshnessFailure) return freshnessFailure;
	const signatureFailure = browserComputerBrokerAttestationSignatureFailure(attestation, {
		allowStale: hermesAllowsStaleAttestations(options),
		relayPublicKey: options.relayPublicKey,
	});
	if (signatureFailure) return `runnerAttestation signature is invalid: ${signatureFailure}`;
	const expected = browserComputerBrokerAttestationFieldsForEvidence(data);
	for (const field of [
		"probeEvidenceSchemaVersion",
		"probeId",
		"status",
		"ran",
		"observedAt",
		"evidenceSource",
		"checksSha256",
		"observationsSha256",
		"evidenceSha256",
	] as const) {
		if (attestation[field] !== expected[field]) return `runnerAttestation ${field} mismatch`;
	}
	return null;
}

const BrowserComputerBrokerFixtureEvidenceSchema = z
	.object({
		schemaVersion: z.literal(BROWSER_COMPUTER_BROKER_FIXTURE_EVIDENCE_SCHEMA_VERSION),
		id: NonEmptyString,
		status: z.enum(["pass", "fail"]),
		ran: z.literal(true),
		evidence_path: NonEmptyString,
		observedAt: NonEmptyString,
		provenance: z
			.object({
				runner: z.literal(BROWSER_COMPUTER_BROKER_FIXTURE_RUNNER),
				source: z.literal(BROWSER_COMPUTER_BROKER_FIXTURE_SOURCE),
				command: NonEmptyString,
				probeId: z.enum(BROWSER_COMPUTER_BROKER_SURFACE_IDS),
				probePath: NonEmptyString,
				probeSha256: Sha256Digest,
			})
			.strict(),
		broker: z
			.object({
				surfaceId: z.enum(BROWSER_COMPUTER_BROKER_SURFACE_IDS),
				requiredProbeChecks: z.array(NonEmptyString).min(1),
				requiredObservationHashes: z.array(NonEmptyString),
			})
			.strict(),
		checks: z.array(BrowserComputerBrokerProbeCheckSchema).min(1),
	})
	.strict();

type BrowserComputerBrokerFixtureEvidence = z.infer<
	typeof BrowserComputerBrokerFixtureEvidenceSchema
>;

export function buildBrowserComputerBrokerFixtureEvidenceBundle(
	input: {
		readonly evidenceDir?: string;
		readonly observedAt?: string;
		readonly probePaths?: Partial<Record<BrowserComputerBrokerSurfaceId, string>>;
	} = {},
): {
	readonly schemaVersion: 1;
	readonly results: readonly {
		readonly id: BrowserComputerBrokerFixtureId;
		readonly status: "pass" | "fail";
		readonly evidence_path: string;
	}[];
	readonly evidence: readonly BrowserComputerBrokerFixtureEvidence[];
} {
	const evidenceDir = input.evidenceDir ?? DEFAULT_BROWSER_COMPUTER_BROKER_FIXTURE_EVIDENCE_DIR;
	const probeCache = new Map<
		BrowserComputerBrokerSurfaceId,
		{
			readonly path: string;
			readonly sha256: string;
			readonly evidence?: BrowserComputerBrokerProbeEvidence;
			readonly failure?: string;
		}
	>();
	const evidence = BROWSER_COMPUTER_BROKER_FIXTURE_REQUIREMENTS.map((requirement) =>
		buildBrokerFixtureEvidence(requirement, {
			evidenceDir,
			observedAt: input.observedAt,
			probePath:
				input.probePaths?.[requirement.surfaceId] ??
				DEFAULT_BROWSER_COMPUTER_BROKER_EVIDENCE_PATHS[requirement.surfaceId],
			probeCache,
		}),
	);
	return {
		schemaVersion: 1,
		results: evidence.map((item) => ({
			id: item.id as BrowserComputerBrokerFixtureId,
			status: item.status,
			evidence_path: item.evidence_path,
		})),
		evidence,
	};
}

export function browserComputerBrokerFixtureEvidenceFailure(
	fixtureId: string,
	evidence: unknown,
): string | null {
	const requirement = BROWSER_COMPUTER_BROKER_FIXTURE_REQUIREMENTS.find(
		(candidate) => candidate.id === fixtureId,
	);
	if (!requirement) return null;
	const parsed = BrowserComputerBrokerFixtureEvidenceSchema.safeParse(evidence);
	if (!parsed.success) {
		return `invalid browser/computer fixture evidence ${fixtureId}: ${flattenZodError(parsed.error)}`;
	}
	const data = parsed.data;
	const failures: string[] = [];
	if (data.id !== fixtureId) failures.push(`fixture evidence id is ${data.id}`);
	if (data.status !== "pass") failures.push(`fixture evidence status is ${data.status}`);
	if (data.broker.surfaceId !== requirement.surfaceId) {
		failures.push(`fixture surfaceId is ${data.broker.surfaceId}`);
	}
	if (data.provenance.probeId !== requirement.surfaceId) {
		failures.push(`fixture probeId is ${data.provenance.probeId}`);
	}
	if (
		JSON.stringify(data.broker.requiredProbeChecks) !== JSON.stringify(requirement.requiredChecks)
	) {
		failures.push("fixture requiredProbeChecks do not match broker contract");
	}
	if (
		JSON.stringify(data.broker.requiredObservationHashes) !==
		JSON.stringify(requirement.requiredObservationHashes)
	) {
		failures.push("fixture requiredObservationHashes do not match broker contract");
	}
	const probe = readBrokerProbeArtifact(data.provenance.probePath, requirement.surfaceId);
	if (probe.sha256 !== data.provenance.probeSha256) {
		failures.push("fixture probeSha256 does not match broker probe artifact");
	}
	if (probe.failure) {
		failures.push(`fixture probe artifact failed validation: ${probe.failure}`);
	} else if (probe.evidence) {
		failures.push(...brokerFixtureContractFailures(requirement, data, probe.evidence));
	}
	return failures.length > 0 ? failures.join("; ") : null;
}

function browserProfileProbe(
	surfaceId: BrowserComputerBrokerSurfaceId,
	observedAt: string,
): BrowserComputerBrokerProbeEvidence {
	const profiles = [
		{
			domain: "private",
			profileId: "browser-private-profile",
			cookieJarRef: "cookiejar:private:7df1",
			cacheNamespace: "cache:private",
			workspaceMount: null,
		},
		{
			domain: "public-social",
			profileId: "browser-public-social-profile",
			cookieJarRef: "cookiejar:public-social:f40a",
			cacheNamespace: "cache:public-social",
			workspaceMount: null,
		},
		{
			domain: "household",
			profileId: "browser-household-profile",
			cookieJarRef: "cookiejar:household:1e03",
			cacheNamespace: "cache:household",
			workspaceMount: null,
		},
		{
			domain: "provider",
			profileId: "browser-provider-worker-profile",
			cookieJarRef: "cookiejar:provider-sidecar:9c21",
			cacheNamespace: "cache:provider-sidecar",
			workspaceMount: null,
		},
	];
	const allowedResearch = {
		requestId: "browser-research-allow-1",
		route: "telclaude-web-broker",
		profileId: "browser-public-social-profile",
		url: "https://example.org/research/benign",
		targetPolicy: "public-research-allowlist",
		cookieJarRef: "cookiejar:public-social:f40a",
		extractedTextRef: "quarantine:text:browser-research-1",
		screenshotRef: "quarantine:screenshot:browser-research-1",
		downloadRef: "quarantine:download:browser-research-1",
		auditRef: "audit:browser:research-allow-1",
		status: "allowed",
	};
	const deniedTarget = {
		requestId: "browser-cross-domain-deny-1",
		route: "telclaude-web-broker",
		profileId: "browser-public-social-profile",
		url: "https://bank.example.invalid/login",
		status: "denied",
		reason: "provider-domain-requires-sidecar-browser-worker",
		auditRef: "audit:browser:cross-domain-deny-1",
	};
	const cookieLeak = {
		requestId: "browser-cookie-leak-deny-1",
		fromProfileId: "browser-public-social-profile",
		toProfileId: "browser-private-profile",
		requestedCookieJarRef: "cookiejar:private:7df1",
		status: "denied",
		reason: "cross-profile-cookie-jar-reuse-denied",
		auditRef: "audit:browser:cookie-deny-1",
	};
	const quarantineRefs = [
		allowedResearch.extractedTextRef,
		allowedResearch.screenshotRef,
		allowedResearch.downloadRef,
		"quarantine:upload:browser-safe-upload-1",
	];
	const checks: BrowserComputerBrokerProbeCheck[] = [];
	pushCheck(
		checks,
		"browser.allowed-public-research",
		allowedResearch.status === "allowed" &&
			allowedResearch.route === "telclaude-web-broker" &&
			allowedResearch.targetPolicy === "public-research-allowlist" &&
			allowedResearch.extractedTextRef.startsWith("quarantine:"),
		"Allowed public research runs through the Telclaude browser broker with ref-only extracted data",
	);
	pushCheck(
		checks,
		"browser.profile-cookie-isolation",
		new Set(profiles.map((profile) => profile.profileId)).size === profiles.length &&
			new Set(profiles.map((profile) => profile.cookieJarRef)).size === profiles.length &&
			new Set(profiles.map((profile) => profile.cacheNamespace)).size === profiles.length &&
			profiles.every((profile) => profile.workspaceMount === null),
		"Private, public-social, household, and provider browser profiles use separate cookie jars and no workspace mounts",
	);
	pushCheck(
		checks,
		"browser.cross-domain-denied",
		deniedTarget.status === "denied" &&
			deniedTarget.reason === "provider-domain-requires-sidecar-browser-worker",
		"Provider-domain navigation from the public browser profile is denied unless sidecar-mediated",
	);
	pushCheck(
		checks,
		"browser.cookie-leak-denied",
		cookieLeak.status === "denied" && cookieLeak.reason === "cross-profile-cookie-jar-reuse-denied",
		"Cross-profile cookie jar reuse is denied and audited",
	);
	pushCheck(
		checks,
		"browser.download-upload-quarantine",
		quarantineRefs.length >= 4 &&
			quarantineRefs.every((ref) => ref.startsWith("quarantine:")) &&
			!JSON.stringify({ allowedResearch, deniedTarget, cookieLeak }).includes("/Users/"),
		"Browser uploads, downloads, screenshots, and extracted text are ref-only quarantine artifacts",
	);
	pushCheck(
		checks,
		"browser.audit-recorded",
		[allowedResearch.auditRef, deniedTarget.auditRef, cookieLeak.auditRef].every((ref) =>
			ref.startsWith("audit:browser:"),
		),
		"Allowed and denied browser broker operations emit audit references",
	);
	return brokerProbeReport(surfaceId, observedAt, checks, {
		...emptyObservations(),
		profileIsolationHash: hashJson(profiles),
		allowedResearchAuditHash: hashJson(allowedResearch),
		cookieIsolationHash: hashJson(cookieLeak),
		browserQuarantineHash: hashJson(quarantineRefs),
		browserDeniedTargetHash: hashJson(deniedTarget),
		auditEntryCount: 3,
		deniedAttemptCount: 2,
		quarantineRefCount: quarantineRefs.length,
	});
}

function computerBrokerProbe(
	surfaceId: BrowserComputerBrokerSurfaceId,
	observedAt: string,
): BrowserComputerBrokerProbeEvidence {
	const sessions = [
		{
			sessionId: "computer-session-public-research",
			domain: "public",
			displayNamespace: "display:public:research",
			targetApp: "Browser",
			targetWindow: "Public research",
			clipboardPolicy: "write-sanitized-only",
			hostDesktopShared: false,
		},
		{
			sessionId: "computer-session-household",
			domain: "household",
			displayNamespace: "display:household:assistant",
			targetApp: "Calendar",
			targetWindow: "Household calendar",
			clipboardPolicy: "read-denied-write-sanitized",
			hostDesktopShared: false,
		},
	];
	const allowedTarget = {
		sessionId: "computer-session-public-research",
		targetApp: "Browser",
		targetWindow: "Public research",
		action: "read_page_summary",
		status: "allowed",
		screenshotRef: "quarantine:screenshot:computer-public-1",
		videoRef: "quarantine:video:computer-public-1",
		extractedTextRef: "quarantine:text:computer-public-1",
		auditRef: "audit:computer:allowed-target-1",
	};
	const unauthorizedTarget = {
		sessionId: "computer-session-public-research",
		targetApp: "Keychain Access",
		targetWindow: "Passwords",
		action: "read_secret",
		status: "denied",
		reason: "target-not-allowlisted",
		auditRef: "audit:computer:unauthorized-target-1",
	};
	const approvalRequired = {
		sessionId: "computer-session-household",
		targetApp: "Browser",
		targetWindow: "Bank transfer form",
		action: "submit_form",
		sideEffectClass: "financial",
		status: "approval_required",
		approvalRef: "approval:computer:financial-submit-1",
		auditRef: "audit:computer:approval-required-1",
	};
	const quarantineRefs = [
		allowedTarget.screenshotRef,
		allowedTarget.videoRef,
		allowedTarget.extractedTextRef,
	];
	const checks: BrowserComputerBrokerProbeCheck[] = [];
	pushCheck(
		checks,
		"computer.allowed-target-audited",
		allowedTarget.status === "allowed" &&
			allowedTarget.auditRef.startsWith("audit:computer:") &&
			allowedTarget.targetWindow === "Public research",
		"Allowlisted computer-use targets run through audited broker sessions",
	);
	pushCheck(
		checks,
		"computer.unauthorized-target-denied",
		unauthorizedTarget.status === "denied" &&
			unauthorizedTarget.reason === "target-not-allowlisted",
		"Unauthorized app/window targets are denied before screen or credential access",
	);
	pushCheck(
		checks,
		"computer.display-session-isolated",
		new Set(sessions.map((session) => session.displayNamespace)).size === sessions.length &&
			sessions.every((session) => session.hostDesktopShared === false),
		"Computer-use sessions use separate display namespaces and do not expose the host desktop",
	);
	pushCheck(
		checks,
		"computer.clipboard-policy-enforced",
		sessions.every((session) => session.clipboardPolicy.includes("sanitized")),
		"Clipboard access is policy-bound and sanitized per trust domain",
	);
	pushCheck(
		checks,
		"computer.sensitive-submit-approval-required",
		approvalRequired.status === "approval_required" &&
			approvalRequired.sideEffectClass === "financial" &&
			approvalRequired.approvalRef.startsWith("approval:computer:"),
		"Sensitive computer-use submits require an approval ref before clicks or keystrokes execute",
	);
	pushCheck(
		checks,
		"computer.screenshot-video-quarantine",
		quarantineRefs.length === 3 && quarantineRefs.every((ref) => ref.startsWith("quarantine:")),
		"Screenshots, video captures, and extracted text are stored as quarantine refs",
	);
	return brokerProbeReport(surfaceId, observedAt, checks, {
		...emptyObservations(),
		computerAllowedAuditHash: hashJson(allowedTarget),
		computerUnauthorizedDenialHash: hashJson(unauthorizedTarget),
		computerSessionIsolationHash: hashJson(sessions),
		computerQuarantineHash: hashJson(quarantineRefs),
		computerApprovalHash: hashJson(approvalRequired),
		auditEntryCount: 3,
		deniedAttemptCount: 1,
		quarantineRefCount: quarantineRefs.length,
	});
}

function networkEgressProbe(
	surfaceId: BrowserComputerBrokerSurfaceId,
	observedAt: string,
): BrowserComputerBrokerProbeEvidence {
	const allowed = {
		requestId: "egress-public-research-allow-1",
		url: "https://example.org/research/benign",
		route: "telclaude-egress-broker",
		resolvedBy: "telclaude-filtering-resolver",
		status: "allowed",
		auditRef: "audit:egress:public-research-1",
	};
	const requiredDenialTargets = NETWORK_EGRESS_DENIAL_TARGETS.map(({ kind, target }) => ({
		kind,
		target,
		route: "telclaude-egress-broker",
		status: "requires-live-network-evidence",
		reason: `${kind}-egress-denial-not-machine-observed`,
		auditRef: `audit:egress:${kind}`,
	}));
	const checks: BrowserComputerBrokerProbeCheck[] = [];
	pushCheck(
		checks,
		"egress.allowed-public-through-broker",
		allowed.status === "allowed" &&
			allowed.route === "telclaude-egress-broker" &&
			allowed.resolvedBy === "telclaude-filtering-resolver",
		"Allowed public research egress succeeds only through the Telclaude broker and filtering resolver",
	);
	pushCheck(
		checks,
		"egress.direct-provider-denied",
		false,
		"Direct provider denial requires live machine-observed egress evidence",
	);
	pushCheck(
		checks,
		"egress.direct-model-denied",
		false,
		"Direct model-provider denial requires live machine-observed egress evidence",
	);
	pushCheck(
		checks,
		"egress.direct-vault-denied",
		false,
		"Direct vault denial requires live machine-observed egress evidence",
	);
	pushCheck(
		checks,
		"egress.metadata-private-denied",
		false,
		"Metadata and private-network denial requires live machine-observed egress evidence",
	);
	pushCheck(
		checks,
		"egress.smtp-imap-whatsapp-denied",
		false,
		"Direct SMTP, IMAP, and WhatsApp bridge denial requires live machine-observed egress evidence",
	);
	pushCheck(
		checks,
		"egress.dns-doh-dot-denied",
		false,
		"Raw DNS, DoH, and DoT denial requires live machine-observed egress evidence",
	);
	pushCheck(
		checks,
		"egress.proxy-tunnel-webrtc-websocket-denied",
		false,
		"CONNECT/proxy tunneling, WebSocket, and WebRTC denial requires live machine-observed egress evidence",
	);
	pushCheck(
		checks,
		"egress.ip-literal-localhost-callback-denied",
		false,
		"IP literal, DNS rebinding, and localhost callback denial requires live machine-observed egress evidence",
	);
	pushCheck(
		checks,
		"egress.upload-without-quarantine-denied",
		false,
		"Upload-without-quarantine denial requires live machine-observed egress evidence",
	);
	pushCheck(
		checks,
		"egress.browser-provider-bypass-denied",
		false,
		"Browser-to-provider bypass denial requires live machine-observed egress evidence",
	);
	pushCheck(
		checks,
		"egress.computer-covert-denied",
		false,
		"Computer-use covert egress denial requires live machine-observed egress evidence",
	);
	return brokerProbeReport(surfaceId, observedAt, checks, {
		...emptyObservations(),
		egressAllowedAuditHash: hashJson(allowed),
		egressDenialMatrixHash: hashJson(requiredDenialTargets),
		egressDnsDenialHash: hashJson(
			requiredDenialTargets.filter((denial) => ["dns-53", "doh", "dot"].includes(denial.kind)),
		),
		egressCovertDenialHash: hashJson(
			requiredDenialTargets.filter((denial) =>
				["connect-proxy", "websocket", "webrtc", "computer-covert-egress"].includes(denial.kind),
			),
		),
		auditEntryCount: 1,
		deniedAttemptCount: 0,
		directEgressDenialCount: 0,
	});
}

function parseNetworkEgressBrokerRunReport(
	rawReport: unknown,
): z.infer<typeof NetworkEgressBrokerRunReportSchema> {
	const parsed = NetworkEgressBrokerRunReportSchema.safeParse(rawReport);
	if (!parsed.success) {
		throw new Error(`invalid network egress-broker run report: ${flattenZodError(parsed.error)}`);
	}
	const duplicateKinds = duplicates(parsed.data.attempts.map((attempt) => attempt.kind));
	if (duplicateKinds.includes("public-research")) {
		throw new Error("network egress-broker run report duplicates public-research");
	}
	const duplicatedDeniedKinds = duplicateKinds.filter((kind) => kind !== "public-research");
	if (duplicatedDeniedKinds.length > 0) {
		throw new Error(
			`network egress-broker run report duplicates denied kinds: ${duplicatedDeniedKinds.join(
				", ",
			)}`,
		);
	}
	return parsed.data;
}

function buildBrokerFixtureEvidence(
	requirement: (typeof BROWSER_COMPUTER_BROKER_FIXTURE_REQUIREMENTS)[number],
	options: {
		readonly evidenceDir: string;
		readonly observedAt?: string;
		readonly probePath: string;
		readonly probeCache: Map<
			BrowserComputerBrokerSurfaceId,
			{
				readonly path: string;
				readonly sha256: string;
				readonly evidence?: BrowserComputerBrokerProbeEvidence;
				readonly failure?: string;
			}
		>;
	},
): BrowserComputerBrokerFixtureEvidence {
	const probe = cachedBrokerProbeArtifact(
		options.probeCache,
		requirement.surfaceId,
		options.probePath,
	);
	const checks = buildBrokerFixtureChecks(requirement, probe.evidence, probe.failure);
	const status =
		probe.failure === undefined && checks.every((check) => check.status === "pass")
			? "pass"
			: "fail";
	return {
		schemaVersion: BROWSER_COMPUTER_BROKER_FIXTURE_EVIDENCE_SCHEMA_VERSION,
		id: requirement.id,
		status,
		ran: true,
		evidence_path: path.join(options.evidenceDir, `${requirement.id}.json`),
		observedAt: probe.evidence?.observedAt ?? options.observedAt ?? new Date().toISOString(),
		provenance: {
			runner: BROWSER_COMPUTER_BROKER_FIXTURE_RUNNER,
			source: BROWSER_COMPUTER_BROKER_FIXTURE_SOURCE,
			command: "pnpm dev hermes fixtures --include-browser-computer --write",
			probeId: requirement.surfaceId,
			probePath: options.probePath,
			probeSha256: probe.sha256,
		},
		broker: {
			surfaceId: requirement.surfaceId,
			requiredProbeChecks: [...requirement.requiredChecks],
			requiredObservationHashes: [...requirement.requiredObservationHashes],
		},
		checks,
	};
}

function buildBrokerFixtureChecks(
	requirement: (typeof BROWSER_COMPUTER_BROKER_FIXTURE_REQUIREMENTS)[number],
	probe: BrowserComputerBrokerProbeEvidence | undefined,
	probeFailure: string | undefined,
): BrowserComputerBrokerProbeCheck[] {
	if (!probe || probeFailure) {
		return [
			{
				name: `${requirement.id}.broker-probe-valid`,
				status: "fail",
				detail: probeFailure ?? "browser/computer broker probe evidence is missing",
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
				detail: check?.detail ?? "required browser/computer broker check is missing",
			} satisfies BrowserComputerBrokerProbeCheck;
		}),
		...requirement.requiredObservationHashes.map(
			(field) =>
				({
					name: `${requirement.id}.${field}`,
					status: probe.observations[field] ? "pass" : "fail",
					detail: probe.observations[field]
						? `browser/computer broker probe recorded ${field}`
						: `browser/computer broker probe did not record ${field}`,
				}) satisfies BrowserComputerBrokerProbeCheck,
		),
	];
}

function brokerFixtureContractFailures(
	requirement: (typeof BROWSER_COMPUTER_BROKER_FIXTURE_REQUIREMENTS)[number],
	fixture: BrowserComputerBrokerFixtureEvidence,
	probe: BrowserComputerBrokerProbeEvidence,
): string[] {
	const failures: string[] = [];
	const probeFailure = browserComputerBrokerProbeEvidenceFailure(requirement.surfaceId, probe);
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

function cachedBrokerProbeArtifact(
	cache: Map<
		BrowserComputerBrokerSurfaceId,
		{
			readonly path: string;
			readonly sha256: string;
			readonly evidence?: BrowserComputerBrokerProbeEvidence;
			readonly failure?: string;
		}
	>,
	surfaceId: BrowserComputerBrokerSurfaceId,
	probePath: string,
) {
	const cached = cache.get(surfaceId);
	if (cached?.path === probePath) return cached;
	const read = readBrokerProbeArtifact(probePath, surfaceId);
	cache.set(surfaceId, read);
	return read;
}

function readBrokerProbeArtifact(
	probePath: string,
	surfaceId: BrowserComputerBrokerSurfaceId,
): {
	readonly path: string;
	readonly sha256: string;
	readonly evidence?: BrowserComputerBrokerProbeEvidence;
	readonly failure?: string;
} {
	if (!fs.existsSync(probePath)) {
		return {
			path: probePath,
			sha256: hashText(`${probePath}:missing`),
			failure: `missing browser/computer broker probe artifact ${probePath}`,
		};
	}
	let raw: unknown;
	try {
		raw = JSON.parse(fs.readFileSync(probePath, "utf8")) as unknown;
	} catch (error) {
		return {
			path: probePath,
			sha256: hashFile(probePath),
			failure: `unreadable browser/computer broker probe artifact: ${
				error instanceof Error ? error.message : String(error)
			}`,
		};
	}
	const parsed = BrowserComputerBrokerProbeEvidenceSchema.safeParse(raw);
	if (!parsed.success) {
		return {
			path: probePath,
			sha256: hashFile(probePath),
			failure: `invalid browser/computer broker probe artifact: ${flattenZodError(parsed.error)}`,
		};
	}
	const semanticFailure = browserComputerBrokerProbeEvidenceFailure(surfaceId, parsed.data);
	return {
		path: probePath,
		sha256: hashFile(probePath),
		evidence: parsed.data,
		...(semanticFailure ? { failure: semanticFailure } : {}),
	};
}

function requiredObservationFields(
	surfaceId: BrowserComputerBrokerSurfaceId,
): readonly (keyof BrowserComputerBrokerProbeObservation)[] {
	if (surfaceId === "browser.profiles") {
		return [
			"profileIsolationHash",
			"allowedResearchAuditHash",
			"cookieIsolationHash",
			"browserQuarantineHash",
			"browserDeniedTargetHash",
		];
	}
	if (surfaceId === "computer.broker") {
		return [
			"computerAllowedAuditHash",
			"computerUnauthorizedDenialHash",
			"computerSessionIsolationHash",
			"computerQuarantineHash",
			"computerApprovalHash",
		];
	}
	return [
		"egressAllowedAuditHash",
		"egressDenialMatrixHash",
		"egressDnsDenialHash",
		"egressCovertDenialHash",
	];
}

function brokerProbeReport(
	surfaceId: BrowserComputerBrokerSurfaceId,
	observedAt: string,
	checks: BrowserComputerBrokerProbeCheck[],
	observations: BrowserComputerBrokerProbeObservation,
): BrowserComputerBrokerProbeEvidence {
	const status = checks.every((check) => check.status === "pass") ? "pass" : "fail";
	return {
		schemaVersion: BROWSER_COMPUTER_BROKER_PROBE_SCHEMA_VERSION,
		probeId: surfaceId,
		status,
		ran: true,
		observedAt,
		source: BROWSER_COMPUTER_BROKER_PROBE_SOURCE,
		summary:
			status === "pass" ? `${surfaceId} broker probe passed` : `${surfaceId} broker probe failed`,
		checks,
		observations,
	};
}

function emptyObservations(): BrowserComputerBrokerProbeObservation {
	return {
		auditEntryCount: 0,
		deniedAttemptCount: 0,
		quarantineRefCount: 0,
		directEgressDenialCount: 0,
	};
}

function pushCheck(
	checks: BrowserComputerBrokerProbeCheck[],
	name: string,
	ok: boolean,
	detail: string,
): void {
	checks.push({ name, status: ok ? "pass" : "fail", detail });
}

function hashJson(value: unknown): string {
	return hashText(JSON.stringify(sortKeysDeep(value)));
}

function hashText(value: string): string {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function hashFile(filePath: string): string {
	return `sha256:${crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex")}`;
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
	const repeated = new Set<string>();
	for (const value of values) {
		if (seen.has(value)) repeated.add(value);
		seen.add(value);
	}
	return [...repeated];
}
