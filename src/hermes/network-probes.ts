import fs from "node:fs";
import path from "node:path";
import { cachedDNSLookup, isBlockedIP, isNonOverridableBlock } from "../sandbox/network-proxy.js";
import { redactSecrets } from "../security/output-filter.js";
import {
	assertHermesArtifactWritesAllowed,
	DEFAULT_NETWORK_PROBES_PATH,
	type HermesArtifactWriteOptions,
	NETWORK_PROBE_POSTURES,
	type ProbeBundle,
	REQUIRED_CUTOVER_NETWORK_PROBE_IDS,
	resolveHermesArtifactPath,
	writeHermesJsonArtifact,
} from "./foundation.js";
import { signNetworkProbeEvidenceAttestation } from "./network-probe-attestation.js";
import {
	assertNetworkProbeEvidence,
	type NetworkProbeAttempt,
	type NetworkProbeEvidence,
	type NetworkProbeId,
	type NetworkProbePosture,
	type NetworkProbeStatus,
} from "./network-probe-evidence-validation.js";
import { NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION } from "./network-probe-schema.js";
import {
	POSITIVE_NETWORK_DENIAL_ERROR_CODES,
	REQUIRED_CONTAINED_PROVIDER_DENY_NAMES,
} from "./network-probe-semantic-proof.js";

export const DEFAULT_NETWORK_PROBE_BUNDLE_PATH = DEFAULT_NETWORK_PROBES_PATH;
export const DEFAULT_NETWORK_PROBE_EVIDENCE_DIR = "artifacts/hermes/network";
export const DEFAULT_FIREWALL_SENTINEL_PATH = "/run/telclaude/firewall-active";
export const DEFAULT_VAULT_SOCKET_PATH = "/run/vault/vault.sock";
export const DEFAULT_MODEL_PROVIDER_PROBE_URL =
	"https://chatgpt.com/backend-api/codex/models?client_version=1.0.0";
export const DEFAULT_CONTAINED_INTERNAL_MODEL_PROVIDER_PROBE_URL = "http://192.0.2.1/";
export const DEFAULT_DNS_EXFIL_PROBE_URLS = [
	"http://169.254.169.254/latest/meta-data/",
	"http://10.0.0.1/",
	"http://100.64.0.1/",
];
export const DEFAULT_DNS_EXFIL_PROBE_URL = DEFAULT_DNS_EXFIL_PROBE_URLS.join(",");
export type {
	NetworkProbeAttempt,
	NetworkProbeEvidence,
	NetworkProbeId,
	NetworkProbePosture,
	NetworkProbeStatus,
} from "./network-probe-evidence-validation.js";
export { networkProbeEvidenceFailure } from "./network-probe-evidence-validation.js";
export { NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION } from "./network-probe-schema.js";

export type NetworkProbeRunnerReport = {
	schemaVersion: "telclaude.hermes.network-probe-run.v1";
	posture: NetworkProbePosture;
	status: NetworkProbeStatus;
	ran: boolean;
	summary: string;
	bundlePath?: string;
	evidenceDir?: string;
	bundle: ProbeBundle;
	evidence: NetworkProbeEvidence[];
};

export type NetworkProbeRunnerOptions = {
	allowRun: boolean;
	signEvidence?: boolean;
	posture?: NetworkProbePosture;
	relayUrl?: string;
	providerUrls: string[];
	vaultUrl?: string;
	vaultSocketPath: string;
	modelProviderUrl: string;
	dnsExfilUrls: string[];
	firewallSentinelPath: string;
	timeoutMs?: number;
	now?: Date;
};

type NetworkProbeWriteOptions = {
	outPath: string;
	evidenceDir: string;
	allowTrackedSeedWrite?: boolean;
};

type NetworkProbeRunReportReadOptions = {
	requireAttestation?: boolean;
};

const DEFAULT_TIMEOUT_MS = 3_000;
const POLICY_DENIAL_HEADER = "x-telclaude-network-policy";

export async function runHermesNetworkProbes(
	options: NetworkProbeRunnerOptions,
): Promise<NetworkProbeRunnerReport> {
	const posture = options.posture ?? "agent-iptables";
	if (!options.allowRun) {
		const evidence = REQUIRED_CUTOVER_NETWORK_PROBE_IDS.map((id) =>
			pendingNetworkProbeEvidence(id, evidencePathFor(id), posture, options.now),
		);
		return networkProbeReport({
			posture,
			status: "pending",
			ran: false,
			summary: "Hermes network probes require --allow-run",
			evidence,
		});
	}

	const evidence = await Promise.all([
		runRelayControlAllowed(options),
		runDirectProviderDenied(options),
		runDirectVaultDenied(options),
		runDirectModelProviderDenied(options),
		runDnsExfilDenied(options),
	]);
	const status = evidence.every((probe) => probe.status === "pass") ? "pass" : "fail";
	const signedEvidence =
		status === "pass" && options.signEvidence !== false
			? evidence.map((probe) => ({
					...probe,
					attestation: signNetworkProbeEvidenceAttestation(probe),
				}))
			: evidence;
	return networkProbeReport({
		posture,
		status,
		ran: true,
		summary:
			status === "pass"
				? "Hermes network denial probes passed"
				: "Hermes network denial probes failed",
		evidence: signedEvidence,
	});
}

export function writeHermesNetworkProbeArtifacts(
	report: NetworkProbeRunnerReport,
	options: NetworkProbeWriteOptions,
): NetworkProbeRunnerReport {
	const evidenceDir = resolveHermesArtifactPath(options.evidenceDir);
	const outPath = resolveHermesArtifactPath(options.outPath);
	const writeOptions: HermesArtifactWriteOptions =
		options.allowTrackedSeedWrite === undefined
			? {}
			: { allowTrackedSeedWrite: options.allowTrackedSeedWrite };
	const evidence = report.evidence.map((probe) =>
		canonicalNetworkProbeEvidence({
			...probe,
			evidence_path: path.join(options.evidenceDir, `${probeFileStem(probe.id)}.json`),
		}),
	);
	const bundle = buildNetworkProbeBundle(evidence);
	const promotedReport = {
		...report,
		bundlePath: outPath,
		evidenceDir,
		bundle,
		evidence,
	};
	if (promotedReport.status === "pass") {
		for (const probe of promotedReport.evidence) {
			assertNetworkProbeEvidence(probe, {
				expectedId: probe.id,
				requiredPosture: promotedReport.posture,
			});
		}
	}
	assertHermesArtifactWritesAllowed(
		[outPath, ...evidence.map((probe) => resolveHermesArtifactPath(probe.evidence_path))],
		writeOptions,
	);
	for (const probe of evidence) {
		writeHermesJsonArtifact(resolveHermesArtifactPath(probe.evidence_path), probe, writeOptions);
	}
	writeHermesJsonArtifact(outPath, bundle, writeOptions);
	return promotedReport;
}

export function readHermesNetworkProbeRunReport(
	reportPath: string,
	options: NetworkProbeRunReportReadOptions = {},
): NetworkProbeRunnerReport {
	const resolvedPath = resolveHermesArtifactPath(reportPath);
	const raw = JSON.parse(fs.readFileSync(resolvedPath, "utf8")) as unknown;
	return assertHermesNetworkProbeRunReport(raw, options);
}

export function assertHermesNetworkProbeRunReport(
	raw: unknown,
	options: NetworkProbeRunReportReadOptions = {},
): NetworkProbeRunnerReport {
	if (!isRecord(raw)) {
		throw new Error("network probe run report must be a JSON object");
	}
	if (raw.schemaVersion !== "telclaude.hermes.network-probe-run.v1") {
		throw new Error("network probe run report has an unsupported schemaVersion");
	}
	if (raw.ran !== true) {
		throw new Error("network probe run report was not machine-observed");
	}
	if (raw.status !== "pass") {
		throw new Error(`network probe run report status is ${String(raw.status)}`);
	}
	if (!NETWORK_PROBE_POSTURES.includes(raw.posture as NetworkProbePosture)) {
		throw new Error(`network probe run report posture is ${String(raw.posture)}`);
	}
	if (!Array.isArray(raw.evidence)) {
		throw new Error("network probe run report is missing evidence");
	}
	const evidenceIds = new Set<string>();
	for (const evidence of raw.evidence) {
		if (!isRecord(evidence)) {
			throw new Error("network probe evidence entry must be a JSON object");
		}
		if (evidence.schemaVersion !== NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION) {
			throw new Error("network probe evidence entry has an unsupported schemaVersion");
		}
		if (!REQUIRED_CUTOVER_NETWORK_PROBE_IDS.includes(evidence.id as NetworkProbeId)) {
			throw new Error(`network probe evidence has unsupported id ${String(evidence.id)}`);
		}
		if (evidenceIds.has(evidence.id as string)) {
			throw new Error(`network probe run report duplicates ${String(evidence.id)}`);
		}
		evidenceIds.add(evidence.id as string);
		if (evidence.ran !== true) {
			throw new Error(`network probe evidence ${String(evidence.id)} was not run`);
		}
		if (evidence.status !== "pass") {
			throw new Error(
				`network probe evidence ${String(evidence.id)} status is ${String(evidence.status)}`,
			);
		}
		if (evidence.posture !== raw.posture) {
			throw new Error(
				`network probe evidence ${String(evidence.id)} posture does not match report`,
			);
		}
		assertNetworkProbeEvidence(evidence, {
			expectedId: evidence.id as NetworkProbeId,
			requiredPosture: raw.posture as NetworkProbePosture,
			requireAttestation: options.requireAttestation,
		});
	}
	for (const id of REQUIRED_CUTOVER_NETWORK_PROBE_IDS) {
		if (!evidenceIds.has(id)) {
			throw new Error(`network probe run report is missing ${id}`);
		}
	}
	return raw as NetworkProbeRunnerReport;
}

function canonicalNetworkProbeEvidence(evidence: NetworkProbeEvidence): NetworkProbeEvidence {
	if (evidence.status === "pass" && !evidence.attestation) {
		return {
			...evidence,
			attestation: signNetworkProbeEvidenceAttestation(evidence),
		};
	}
	return evidence;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function networkProbeReport(input: {
	posture: NetworkProbePosture;
	status: NetworkProbeStatus;
	ran: boolean;
	summary: string;
	evidence: NetworkProbeEvidence[];
}): NetworkProbeRunnerReport {
	return {
		schemaVersion: "telclaude.hermes.network-probe-run.v1",
		posture: input.posture,
		status: input.status,
		ran: input.ran,
		summary: input.summary,
		bundle: buildNetworkProbeBundle(input.evidence),
		evidence: input.evidence,
	};
}

function buildNetworkProbeBundle(evidence: NetworkProbeEvidence[]): ProbeBundle {
	return {
		schemaVersion: 1,
		probes: evidence.map((probe) => ({
			id: probe.id,
			status: probe.status === "pass" ? "pass" : "fail",
			evidence_path: probe.evidence_path,
		})),
	};
}

async function runDirectProviderDenied(
	options: NetworkProbeRunnerOptions,
): Promise<NetworkProbeEvidence> {
	const providerTargets = options.providerUrls.map(parseProviderDenyTarget);
	const attempts = [
		...boundaryProofAttempts(options),
		...containedInternalProviderNameAttempts(options, providerTargets),
		...(options.providerUrls.length === 0
			? [configurationAttempt("providerUrls", "TELCLAUDE_HERMES_NETWORK_PROVIDER_URL")]
			: await Promise.all(
					providerTargets.map((target) =>
						attemptHttpDenied(target.name, target.url, options.timeoutMs),
					),
				)),
	];
	return networkProbeEvidence("network.direct-provider-denied", attempts, options);
}

function parseProviderDenyTarget(entry: string, index: number): { name: string; url: string } {
	const trimmed = entry.trim();
	const named = trimmed.match(/^([A-Za-z][A-Za-z0-9_.-]*)=(.+)$/);
	if (!named) {
		return {
			name: index === 0 ? "provider" : `provider:${index + 1}`,
			url: trimmed,
		};
	}
	return {
		name: `provider:${named[1]}`,
		url: named[2].trim(),
	};
}

function containedInternalProviderNameAttempts(
	options: NetworkProbeRunnerOptions,
	targets: Array<{ name: string; url: string }>,
): NetworkProbeAttempt[] {
	if ((options.posture ?? "agent-iptables") !== "contained-internal") return [];
	const attempts: NetworkProbeAttempt[] = [];
	const configuredNames = new Set<string>();
	for (const target of targets) {
		const match = target.name.match(/^provider:(.+)$/);
		if (match && !/^\d+$/.test(match[1])) {
			configuredNames.add(match[1]);
			continue;
		}
		attempts.push({
			name: `${target.name}.named`,
			kind: "configuration",
			target: redactSecrets(target.url),
			expectation: "configured",
			status: "fail",
			observed: "unnamed",
			detail: "contained-internal provider denial evidence must name each provider as name=url",
		});
	}
	for (const requiredName of REQUIRED_CONTAINED_PROVIDER_DENY_NAMES) {
		if (configuredNames.has(requiredName)) continue;
		attempts.push({
			name: `provider:${requiredName}.configured`,
			kind: "configuration",
			target: `TELCLAUDE_HERMES_NETWORK_PROVIDER_URL:${requiredName}`,
			expectation: "configured",
			status: "fail",
			observed: "missing",
			detail: `contained-internal provider denial evidence is missing provider:${requiredName}`,
		});
	}
	return attempts;
}

async function runRelayControlAllowed(
	options: NetworkProbeRunnerOptions,
): Promise<NetworkProbeEvidence> {
	const attempts = [
		...boundaryProofAttempts(options),
		options.relayUrl
			? await attemptHttpAllowed("relay-control", options.relayUrl, options.timeoutMs)
			: configurationAttempt("relayUrl", "TELCLAUDE_HERMES_NETWORK_RELAY_URL"),
	];
	return networkProbeEvidence("network.relay-control-allowed", attempts, options);
}

async function runDirectVaultDenied(
	options: NetworkProbeRunnerOptions,
): Promise<NetworkProbeEvidence> {
	const attempts = [
		...boundaryProofAttempts(options),
		attemptUnixSocketAbsent("vault-socket", options.vaultSocketPath),
		...(options.vaultUrl
			? [await attemptHttpDenied("vault-url", options.vaultUrl, options.timeoutMs)]
			: []),
	];
	return networkProbeEvidence("network.direct-vault-denied", attempts, options);
}

async function runDirectModelProviderDenied(
	options: NetworkProbeRunnerOptions,
): Promise<NetworkProbeEvidence> {
	const attempts = [
		...boundaryProofAttempts(options),
		await attemptHttpDenied("model-provider", options.modelProviderUrl, options.timeoutMs),
	];
	return networkProbeEvidence("network.direct-model-provider-denied", attempts, options);
}

async function runDnsExfilDenied(
	options: NetworkProbeRunnerOptions,
): Promise<NetworkProbeEvidence> {
	const attempts = [
		...boundaryProofAttempts(options),
		...(options.dnsExfilUrls.length === 0
			? [configurationAttempt("dnsExfilUrls", "TELCLAUDE_HERMES_NETWORK_DNS_URL")]
			: await Promise.all(
					options.dnsExfilUrls.map((url, index) =>
						attemptDnsGuardDenied(`dns-exfil-${index + 1}`, url, options.timeoutMs),
					),
				)),
	];
	return networkProbeEvidence("network.dns-exfil-denied", attempts, options);
}

function boundaryProofAttempts(options: NetworkProbeRunnerOptions): NetworkProbeAttempt[] {
	if ((options.posture ?? "agent-iptables") === "contained-internal") return [];
	return [firewallSentinelAttempt(options.firewallSentinelPath)];
}

function firewallSentinelAttempt(sentinelPath: string): NetworkProbeAttempt {
	const present = fs.existsSync(sentinelPath);
	return {
		name: "firewall-sentinel",
		kind: "firewall_sentinel",
		target: redactSecrets(sentinelPath),
		expectation: "present",
		status: present ? "pass" : "fail",
		observed: present ? "present" : "missing",
		detail: present
			? "firewall sentinel is present"
			: "firewall sentinel is missing; network denial evidence is not valid",
	};
}

function configurationAttempt(name: string, target: string): NetworkProbeAttempt {
	return {
		name,
		kind: "configuration",
		target,
		expectation: "configured",
		status: "fail",
		observed: "missing",
		detail: `${name} is required to prove this network-denial probe`,
	};
}

async function attemptHttpDenied(
	name: string,
	target: string,
	timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<NetworkProbeAttempt> {
	const startedAt = Date.now();
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);
	timer.unref();
	try {
		const response = await fetch(target, {
			method: "GET",
			redirect: "manual",
			signal: controller.signal,
		});
		if (response.status === 403 && response.headers.get(POLICY_DENIAL_HEADER) === "denied") {
			return {
				name,
				kind: "http",
				target: redactSecrets(target),
				expectation: "deny",
				status: "pass",
				observed: "policy_denied",
				detail: "target was denied by the Telclaude network policy proxy",
				durationMs: Date.now() - startedAt,
				httpStatus: response.status,
			};
		}
		return {
			name,
			kind: "http",
			target: redactSecrets(target),
			expectation: "deny",
			status: "fail",
			observed: "reachable",
			detail: `target was reachable with HTTP status ${response.status}`,
			durationMs: Date.now() - startedAt,
			httpStatus: response.status,
		};
	} catch (error) {
		const { name: errorName, code, message } = normalizeNetworkError(error);
		const isTimeout = errorName === "AbortError" || code === "ETIMEDOUT";
		const isPositiveDenial = code !== undefined && POSITIVE_NETWORK_DENIAL_ERROR_CODES.has(code);
		return {
			name,
			kind: "http",
			target: redactSecrets(target),
			expectation: "deny",
			status: isPositiveDenial ? "pass" : "fail",
			observed: isPositiveDenial
				? "denied"
				: isTimeout
					? "inconclusive_timeout"
					: "inconclusive_error",
			detail: isPositiveDenial
				? `target was actively denied with ${code}`
				: `target denial was inconclusive: ${redactSecrets(message)}`,
			durationMs: Date.now() - startedAt,
			errorName,
			...(code ? { errorCode: code } : {}),
		};
	} finally {
		clearTimeout(timer);
	}
}

async function attemptHttpAllowed(
	name: string,
	target: string,
	timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<NetworkProbeAttempt> {
	const startedAt = Date.now();
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);
	timer.unref();
	try {
		const response = await fetch(target, {
			method: "GET",
			redirect: "manual",
			signal: controller.signal,
		});
		return {
			name,
			kind: "http",
			target: redactSecrets(target),
			expectation: "allow",
			status: "pass",
			observed: "reachable",
			detail: `allowed control reached relay with HTTP status ${response.status}`,
			durationMs: Date.now() - startedAt,
			httpStatus: response.status,
		};
	} catch (error) {
		const { name: errorName, code, message } = normalizeNetworkError(error);
		return {
			name,
			kind: "http",
			target: redactSecrets(target),
			expectation: "allow",
			status: "fail",
			observed: errorName === "AbortError" || code === "ETIMEDOUT" ? "timeout" : "unreachable",
			detail: `allowed relay control failed: ${redactSecrets(message)}`,
			durationMs: Date.now() - startedAt,
			errorName,
			...(code ? { errorCode: code } : {}),
		};
	} finally {
		clearTimeout(timer);
	}
}

function attemptUnixSocketAbsent(name: string, target: string): NetworkProbeAttempt {
	const visible = fs.existsSync(target);
	return {
		name,
		kind: "unix_socket",
		target: redactSecrets(target),
		expectation: "deny",
		status: visible ? "fail" : "pass",
		observed: visible ? "visible" : "absent",
		detail: visible
			? "vault socket path is visible in the probe environment"
			: "vault socket path is absent from the probe environment",
	};
}

async function attemptDnsGuardDenied(
	name: string,
	target: string,
	timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<NetworkProbeAttempt> {
	const startedAt = Date.now();
	let url: URL;
	try {
		url = new URL(target);
	} catch (error) {
		return {
			name,
			kind: "dns_guard",
			target: redactSecrets(target),
			expectation: "deny",
			status: "fail",
			observed: "invalid_target",
			detail: `invalid DNS exfil target: ${String(error instanceof Error ? error.message : error)}`,
		};
	}

	const addresses = await cachedDNSLookup(url.hostname);
	const resolvedAddresses = (addresses ?? []).map((address) => ({
		address,
		blocked: isBlockedIP(address),
		nonOverridable: isNonOverridableBlock(address),
	}));
	if (addresses === null) {
		return {
			name,
			kind: "dns_guard",
			target: redactSecrets(target),
			expectation: "deny",
			status: "fail",
			observed: "dns_lookup_failed",
			detail: "DNS exfil target did not resolve; cannot prove all resolved addresses are blocked",
			durationMs: Date.now() - startedAt,
			resolvedAddresses,
		};
	}
	if (resolvedAddresses.length === 0) {
		return {
			name,
			kind: "dns_guard",
			target: redactSecrets(target),
			expectation: "deny",
			status: "fail",
			observed: "dns_no_addresses",
			detail: "DNS exfil target resolved to no addresses; cannot prove private/metadata denial",
			durationMs: Date.now() - startedAt,
			resolvedAddresses,
		};
	}

	if (resolvedAddresses.every((address) => !address.blocked)) {
		return {
			name,
			kind: "dns_guard",
			target: redactSecrets(target),
			expectation: "deny",
			status: "fail",
			observed: "resolved_no_blocked_address",
			detail: "DNS exfil target did not resolve to a private, CGNAT, loopback, or metadata address",
			durationMs: Date.now() - startedAt,
			resolvedAddresses,
		};
	}

	const attempt = await attemptHttpDenied(name, target, timeoutMs);
	return {
		...attempt,
		kind: "dns_guard",
		resolvedAddresses,
	};
}

function networkProbeEvidence(
	id: NetworkProbeId,
	attempts: NetworkProbeAttempt[],
	options: NetworkProbeRunnerOptions,
): NetworkProbeEvidence {
	const status = attempts.every((attempt) => attempt.status === "pass") ? "pass" : "fail";
	const posture = options.posture ?? "agent-iptables";
	const passSummary =
		id === "network.relay-control-allowed"
			? `${id} observed expected relay reachability`
			: `${id} observed only expected denials`;
	return {
		schemaVersion: NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION,
		id,
		posture,
		status,
		ran: true,
		summary:
			status === "pass"
				? passSummary
				: `${id} observed unsafe network reachability or missing proof`,
		generatedAt: (options.now ?? new Date()).toISOString(),
		evidence_path: evidencePathFor(id),
		attempts,
	};
}

function pendingNetworkProbeEvidence(
	id: NetworkProbeId,
	evidencePath: string,
	posture: NetworkProbePosture,
	now = new Date(),
): NetworkProbeEvidence {
	return {
		schemaVersion: NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION,
		id,
		posture,
		status: "pending",
		ran: false,
		summary: "network probe requires --allow-run",
		generatedAt: now.toISOString(),
		evidence_path: evidencePath,
		attempts: [],
	};
}

function evidencePathFor(id: NetworkProbeId): string {
	return path.join(DEFAULT_NETWORK_PROBE_EVIDENCE_DIR, `${probeFileStem(id)}.json`);
}

function probeFileStem(id: NetworkProbeId): string {
	return id.replace(/^network\./, "");
}

function normalizeNetworkError(error: unknown): { name: string; code?: string; message: string } {
	if (error instanceof Error) {
		const cause = "cause" in error ? (error as { cause?: unknown }).cause : undefined;
		const code =
			cause && typeof cause === "object" && "code" in cause
				? String((cause as { code?: unknown }).code)
				: undefined;
		return { name: error.name, ...(code ? { code } : {}), message: error.message };
	}
	return { name: "Error", message: String(error) };
}
