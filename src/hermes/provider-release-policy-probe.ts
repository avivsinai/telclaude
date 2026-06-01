import { z } from "zod";
import {
	createTelclaudeEdgeRuntime,
	isTelclaudeEdgeRuntimeDeniedError,
} from "./edge-adapter-runtime.js";

export const DEFAULT_PROVIDER_RELEASE_POLICY_EVIDENCE_PATH =
	"artifacts/hermes/probes/providers-release-policy.json";
export const PROVIDER_RELEASE_POLICY_PROBE_SCHEMA_VERSION =
	"telclaude.hermes.provider-release-policy-probe.v1";
export const PROVIDER_RELEASE_POLICY_PROBE_SOURCE = "telclaude-provider-release-policy-harness";

const NonEmptyString = z.string().trim().min(1);

const ProviderReleasePolicyProbeCheckSchema = z
	.object({
		name: NonEmptyString,
		status: z.enum(["pass", "fail"]),
		detail: NonEmptyString,
	})
	.strict();

export const ProviderReleasePolicyProbeEvidenceSchema = z
	.object({
		schemaVersion: z.literal(PROVIDER_RELEASE_POLICY_PROBE_SCHEMA_VERSION),
		probeId: z.literal("providers.release-policy"),
		status: z.enum(["pass", "fail"]),
		ran: z.boolean(),
		observedAt: NonEmptyString,
		source: z.literal(PROVIDER_RELEASE_POLICY_PROBE_SOURCE),
		summary: NonEmptyString,
		checks: z.array(ProviderReleasePolicyProbeCheckSchema).min(1),
		observations: z
			.object({
				releaseCount: z.number().int().nonnegative(),
				deniedCount: z.number().int().nonnegative(),
				auditCount: z.number().int().nonnegative(),
				rawProviderSecretObserved: z.boolean(),
				deniedControls: z.array(NonEmptyString),
			})
			.strict(),
	})
	.strict();

export type ProviderReleasePolicyProbeEvidence = z.infer<
	typeof ProviderReleasePolicyProbeEvidenceSchema
>;
type ProbeCheck = z.infer<typeof ProviderReleasePolicyProbeCheckSchema>;

const REQUIRED_PROVIDER_RELEASE_POLICY_CHECKS = [
	"provider.release.allowed-read-audited",
	"provider.release.prepare-write-audited",
	"provider.release.wrong-actor-denied",
	"provider.release.wrong-recipient-denied",
	"provider.release.missing-strong-link-denied",
	"provider.release.urgent-health-misclassification-denied",
	"provider.release.private-memory-denied",
	"provider.release.unapproved-sensitive-denied",
	"provider.release.prepare-write-benign-denied",
	"provider.release.raw-secret-not-observed",
] as const;

export function runTelclaudeProviderReleasePolicyProbe(input: {
	readonly allowRun: boolean;
	readonly observedAt?: string;
}): ProviderReleasePolicyProbeEvidence {
	const observedAt = input.observedAt ?? new Date().toISOString();
	if (input.allowRun !== true) {
		return {
			schemaVersion: PROVIDER_RELEASE_POLICY_PROBE_SCHEMA_VERSION,
			probeId: "providers.release-policy",
			status: "fail",
			ran: false,
			observedAt,
			source: PROVIDER_RELEASE_POLICY_PROBE_SOURCE,
			summary: "provider release-policy harness was not allowed to run",
			checks: [
				{
					name: "provider.release.allowed-read-audited",
					status: "fail",
					detail: "run with --allow-run to execute the deterministic release-policy harness",
				},
			],
			observations: {
				releaseCount: 0,
				deniedCount: 0,
				auditCount: 0,
				rawProviderSecretObserved: false,
				deniedControls: [],
			},
		};
	}

	const runtime = createTelclaudeEdgeRuntime({ now: () => observedAt });
	const checks: ProbeCheck[] = [];
	const deniedControls: string[] = [];
	const releases: unknown[] = [];
	const household = runtime.ingest({
		channel: "whatsapp",
		domain: "household",
		actorId: "whatsapp:actor:family-member",
		principalId: "whatsapp:principal:family-member",
		identityAssurance: "strong_link",
		scopes: [
			{
				scope: "message:reply",
				actions: ["read", "send", "reply"],
				grantedAt: observedAt,
			},
			{
				scope: "household:benign",
				actions: ["read", "prepare_write"],
				grantedAt: observedAt,
			},
		],
		text: "Check my appointment, please",
	});

	const readRelease = runtime.authorizeHouseholdProviderAccess({
		actorRef: household.actorRef,
		conversationRef: household.conversationRef,
		providerAccount: "clalit:family-member:oauth-never-released",
		providerAccountBinding: "strong_link",
		action: "read",
		classification: "benign",
	});
	releases.push(readRelease);
	pushCheck(
		checks,
		"provider.release.allowed-read-audited",
		readRelease.releaseRef.startsWith("household-provider:") &&
			readRelease.audit.decision === "allowed" &&
			readRelease.audit.actorId === household.actorRef.actorId &&
			readRelease.audit.domain === "household" &&
			readRelease.audit.action === "read" &&
			readRelease.audit.classification === "benign" &&
			readRelease.audit.providerAccountRef.startsWith("provider-account:") &&
			!JSON.stringify(readRelease).includes("oauth-never-released"),
		"scoped household provider read releases only a ref and non-secret audit metadata",
	);

	const preparedRelease = runtime.authorizeHouseholdProviderAccess({
		actorRef: household.actorRef,
		conversationRef: household.conversationRef,
		providerAccount: "clalit:family-member:oauth-never-released",
		providerAccountBinding: "strong_link",
		action: "prepare_write",
		classification: "sensitive",
		approved: true,
	});
	releases.push(preparedRelease);
	pushCheck(
		checks,
		"provider.release.prepare-write-audited",
		preparedRelease.releaseRef.startsWith("household-provider:") &&
			preparedRelease.audit.action === "prepare_write" &&
			preparedRelease.audit.classification === "sensitive" &&
			preparedRelease.audit.approved === true &&
			!JSON.stringify(preparedRelease).includes("oauth-never-released"),
		"sensitive provider write preparation releases only after approval and records an audit ref",
	);

	pushDeniedCheck(
		checks,
		deniedControls,
		"provider.release.wrong-actor-denied",
		"household.cross-recipient-denied",
		() =>
			runtime.authorizeHouseholdProviderAccess({
				actorRef: { ...household.actorRef, actorId: "whatsapp:actor:other-family-member" },
				conversationRef: household.conversationRef,
				providerAccount: "clalit:family-member",
				providerAccountBinding: "strong_link",
				action: "read",
			}),
		"provider release denies actors that are not bound to the conversation",
	);
	pushDeniedCheck(
		checks,
		deniedControls,
		"provider.release.wrong-recipient-denied",
		"household.cross-recipient-denied",
		() =>
			runtime.authorizeHouseholdProviderAccess({
				actorRef: household.actorRef,
				conversationRef: {
					...household.conversationRef,
					recipients: household.conversationRef.recipients.map((recipient) => ({
						...recipient,
						actorId: "whatsapp:actor:different-recipient",
					})),
				},
				providerAccount: "clalit:family-member",
				providerAccountBinding: "strong_link",
				action: "read",
			}),
		"provider release denies conversations whose recipient binding no longer contains the actor",
	);
	pushDeniedCheck(
		checks,
		deniedControls,
		"provider.release.missing-strong-link-denied",
		"household.strong-link-required",
		() =>
			runtime.authorizeHouseholdProviderAccess({
				actorRef: { ...household.actorRef, identityAssurance: "channel_bound" },
				conversationRef: household.conversationRef,
				providerAccount: "clalit:family-member",
				providerAccountBinding: "strong_link",
				action: "read",
			}),
		"provider release requires a strong identity link",
	);
	pushDeniedCheck(
		checks,
		deniedControls,
		"provider.release.urgent-health-misclassification-denied",
		"provider.urgent-health-misclassification-denied",
		() =>
			runtime.authorizeHouseholdProviderAccess({
				actorRef: household.actorRef,
				conversationRef: household.conversationRef,
				providerAccount: "clalit:family-member",
				providerAccountBinding: "strong_link",
				action: "read",
				classification: "urgent",
			}),
		"urgent health requests cannot be silently treated as ordinary provider reads",
	);
	pushDeniedCheck(
		checks,
		deniedControls,
		"provider.release.private-memory-denied",
		"household.private-memory-denied",
		() =>
			runtime.authorizeHouseholdProviderAccess({
				actorRef: household.actorRef,
				conversationRef: household.conversationRef,
				providerAccount: "clalit:family-member",
				providerAccountBinding: "strong_link",
				action: "read",
				privateMemorySource: "telegram:default",
			}),
		"provider release denies private operator memory leakage into household requests",
	);
	pushDeniedCheck(
		checks,
		deniedControls,
		"provider.release.unapproved-sensitive-denied",
		"provider.sensitive-release-approval-required",
		() =>
			runtime.authorizeHouseholdProviderAccess({
				actorRef: household.actorRef,
				conversationRef: household.conversationRef,
				providerAccount: "clalit:family-member",
				providerAccountBinding: "strong_link",
				action: "prepare_write",
				classification: "sensitive",
				approved: false,
			}),
		"sensitive provider release fails closed until approval is present",
	);
	pushDeniedCheck(
		checks,
		deniedControls,
		"provider.release.prepare-write-benign-denied",
		"provider.sensitive-release-approval-required",
		() =>
			runtime.authorizeHouseholdProviderAccess({
				actorRef: household.actorRef,
				conversationRef: household.conversationRef,
				providerAccount: "clalit:family-member",
				providerAccountBinding: "strong_link",
				action: "prepare_write",
				classification: "benign",
				approved: false,
			}),
		"provider write preparation cannot be downgraded to benign to bypass approval",
	);

	const rawProviderSecretObserved = JSON.stringify(releases).includes("oauth-never-released");
	pushCheck(
		checks,
		"provider.release.raw-secret-not-observed",
		rawProviderSecretObserved === false,
		"provider release artifacts contain no raw provider credential/account material",
	);

	const status = checks.every((check) => check.status === "pass") ? "pass" : "fail";
	return {
		schemaVersion: PROVIDER_RELEASE_POLICY_PROBE_SCHEMA_VERSION,
		probeId: "providers.release-policy",
		status,
		ran: true,
		observedAt,
		source: PROVIDER_RELEASE_POLICY_PROBE_SOURCE,
		summary:
			status === "pass"
				? "Provider release-policy probe passed"
				: "Provider release-policy probe failed",
		checks,
		observations: {
			releaseCount: releases.length,
			deniedCount: deniedControls.length,
			auditCount: releases.filter(hasAudit).length,
			rawProviderSecretObserved,
			deniedControls,
		},
	};
}

export function providerReleasePolicyProbeEvidenceFailure(evidence: unknown): string | null {
	const parsed = ProviderReleasePolicyProbeEvidenceSchema.safeParse(evidence);
	if (!parsed.success) {
		return `invalid provider release-policy evidence: ${flattenZodError(parsed.error)}`;
	}
	const data = parsed.data;
	const failures: string[] = [];
	if (data.status !== "pass") failures.push(`status is ${data.status}`);
	if (data.ran !== true) failures.push("harness did not run");
	const checksByName = new Map(data.checks.map((check) => [check.name, check]));
	for (const duplicate of duplicates(data.checks.map((check) => check.name))) {
		failures.push(`duplicate check ${duplicate}`);
	}
	for (const name of REQUIRED_PROVIDER_RELEASE_POLICY_CHECKS) {
		const check = checksByName.get(name);
		if (!check) {
			failures.push(`check ${name} is missing`);
		} else if (check.status !== "pass") {
			failures.push(`check ${name} is ${check.status}`);
		}
	}
	if (data.observations.releaseCount < 2) {
		failures.push(`releaseCount is ${data.observations.releaseCount}`);
	}
	if (data.observations.auditCount < 2) {
		failures.push(`auditCount is ${data.observations.auditCount}`);
	}
	if (data.observations.deniedCount < 7) {
		failures.push(`deniedCount is ${data.observations.deniedCount}`);
	}
	if (data.observations.rawProviderSecretObserved) {
		failures.push("raw provider secret material was observed");
	}
	for (const control of [
		"household.cross-recipient-denied",
		"household.strong-link-required",
		"provider.urgent-health-misclassification-denied",
		"household.private-memory-denied",
		"provider.sensitive-release-approval-required",
	]) {
		if (!data.observations.deniedControls.includes(control)) {
			failures.push(`denied control ${control} is missing`);
		}
	}
	return failures.length > 0 ? failures.join("; ") : null;
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

function pushDeniedCheck(
	checks: ProbeCheck[],
	deniedControls: string[],
	name: ProbeCheck["name"],
	expectedControl: string,
	operation: () => unknown,
	detail: string,
): void {
	try {
		operation();
		pushCheck(checks, name, false, detail, `${detail}; operation was allowed`);
	} catch (error) {
		const passed = isTelclaudeEdgeRuntimeDeniedError(error, expectedControl);
		if (isTelclaudeEdgeRuntimeDeniedError(error)) deniedControls.push(error.control);
		pushCheck(
			checks,
			name,
			passed,
			detail,
			passed
				? detail
				: `${detail}; denied with ${String((error as { control?: unknown }).control)}`,
		);
	}
}

function hasAudit(value: unknown): boolean {
	return (
		typeof value === "object" &&
		value !== null &&
		"audit" in value &&
		typeof (value as { audit?: unknown }).audit === "object" &&
		(value as { audit?: unknown }).audit !== null
	);
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
