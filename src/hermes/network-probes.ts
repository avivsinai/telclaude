import fs from "node:fs";
import path from "node:path";
import { cachedDNSLookup, isBlockedIP, isNonOverridableBlock } from "../sandbox/network-proxy.js";
import { redactSecrets } from "../security/output-filter.js";
import {
	DEFAULT_NETWORK_PROBES_PATH,
	type ProbeBundle,
	REQUIRED_CUTOVER_NETWORK_PROBE_IDS,
	resolveHermesArtifactPath,
} from "./foundation.js";

export const DEFAULT_NETWORK_PROBE_BUNDLE_PATH = DEFAULT_NETWORK_PROBES_PATH;
export const DEFAULT_NETWORK_PROBE_EVIDENCE_DIR = "artifacts/hermes/network";
export const DEFAULT_FIREWALL_SENTINEL_PATH = "/run/telclaude/firewall-active";
export const DEFAULT_VAULT_SOCKET_PATH = "/run/vault/vault.sock";
export const DEFAULT_MODEL_PROVIDER_PROBE_URL = "https://api.anthropic.com/v1/models";
export const DEFAULT_DNS_EXFIL_PROBE_URLS = [
	"http://169.254.169.254/latest/meta-data/",
	"http://10.0.0.1/",
	"http://100.64.0.1/",
];
export const DEFAULT_DNS_EXFIL_PROBE_URL = DEFAULT_DNS_EXFIL_PROBE_URLS.join(",");
export const NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION = "telclaude.hermes.network-probe.v1";

type NetworkProbeId = (typeof REQUIRED_CUTOVER_NETWORK_PROBE_IDS)[number];

type NetworkProbeStatus = "pass" | "fail" | "pending";

type NetworkProbeAttempt = {
	name: string;
	kind: "http" | "unix_socket" | "dns_guard" | "firewall_sentinel" | "configuration";
	target: string;
	expectation: "allow" | "deny" | "present" | "configured";
	status: "pass" | "fail";
	observed: string;
	detail: string;
	durationMs?: number;
	httpStatus?: number;
	errorName?: string;
	errorCode?: string;
	resolvedAddresses?: Array<{ address: string; blocked: boolean; nonOverridable: boolean }>;
};

export type NetworkProbeEvidence = {
	schemaVersion: typeof NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION;
	id: NetworkProbeId;
	status: NetworkProbeStatus;
	ran: boolean;
	summary: string;
	generatedAt: string;
	evidence_path: string;
	attempts: NetworkProbeAttempt[];
};

export type NetworkProbeRunnerReport = {
	schemaVersion: "telclaude.hermes.network-probe-run.v1";
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
};

const DEFAULT_TIMEOUT_MS = 3_000;
const POSITIVE_DENIAL_ERROR_CODES = new Set([
	"ECONNREFUSED",
	"EHOSTUNREACH",
	"ENETUNREACH",
	"EACCES",
	"EPERM",
]);
const POLICY_DENIAL_HEADER = "x-telclaude-network-policy";

export async function runHermesNetworkProbes(
	options: NetworkProbeRunnerOptions,
): Promise<NetworkProbeRunnerReport> {
	if (!options.allowRun) {
		const evidence = REQUIRED_CUTOVER_NETWORK_PROBE_IDS.map((id) =>
			pendingNetworkProbeEvidence(id, evidencePathFor(id), options.now),
		);
		return networkProbeReport({
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
	return networkProbeReport({
		status,
		ran: true,
		summary:
			status === "pass"
				? "Hermes network denial probes passed"
				: "Hermes network denial probes failed",
		evidence,
	});
}

export function writeHermesNetworkProbeArtifacts(
	report: NetworkProbeRunnerReport,
	options: NetworkProbeWriteOptions,
): NetworkProbeRunnerReport {
	const evidenceDir = resolveHermesArtifactPath(options.evidenceDir);
	const outPath = resolveHermesArtifactPath(options.outPath);
	const evidence = report.evidence.map((probe) => ({
		...probe,
		evidence_path: path.join(evidenceDir, `${probeFileStem(probe.id)}.json`),
	}));
	for (const probe of evidence) {
		writeJsonArtifact(probe.evidence_path, probe);
	}
	const bundle = buildNetworkProbeBundle(evidence);
	writeJsonArtifact(outPath, bundle);
	return {
		...report,
		bundlePath: outPath,
		evidenceDir,
		bundle,
		evidence,
	};
}

function networkProbeReport(input: {
	status: NetworkProbeStatus;
	ran: boolean;
	summary: string;
	evidence: NetworkProbeEvidence[];
}): NetworkProbeRunnerReport {
	return {
		schemaVersion: "telclaude.hermes.network-probe-run.v1",
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
	const attempts = [
		firewallSentinelAttempt(options.firewallSentinelPath),
		...(options.providerUrls.length === 0
			? [configurationAttempt("providerUrls", "TELCLAUDE_HERMES_NETWORK_PROVIDER_URL")]
			: await Promise.all(
					options.providerUrls.map((url) => attemptHttpDenied("provider", url, options.timeoutMs)),
				)),
	];
	return networkProbeEvidence("network.direct-provider-denied", attempts, options.now);
}

async function runRelayControlAllowed(
	options: NetworkProbeRunnerOptions,
): Promise<NetworkProbeEvidence> {
	const attempts = [
		firewallSentinelAttempt(options.firewallSentinelPath),
		options.relayUrl
			? await attemptHttpAllowed("relay-control", options.relayUrl, options.timeoutMs)
			: configurationAttempt("relayUrl", "TELCLAUDE_HERMES_NETWORK_RELAY_URL"),
	];
	return networkProbeEvidence("network.relay-control-allowed", attempts, options.now);
}

async function runDirectVaultDenied(
	options: NetworkProbeRunnerOptions,
): Promise<NetworkProbeEvidence> {
	const attempts = [
		firewallSentinelAttempt(options.firewallSentinelPath),
		attemptUnixSocketAbsent("vault-socket", options.vaultSocketPath),
		...(options.vaultUrl
			? [await attemptHttpDenied("vault-url", options.vaultUrl, options.timeoutMs)]
			: []),
	];
	return networkProbeEvidence("network.direct-vault-denied", attempts, options.now);
}

async function runDirectModelProviderDenied(
	options: NetworkProbeRunnerOptions,
): Promise<NetworkProbeEvidence> {
	const attempts = [
		firewallSentinelAttempt(options.firewallSentinelPath),
		await attemptHttpDenied("model-provider", options.modelProviderUrl, options.timeoutMs),
	];
	return networkProbeEvidence("network.direct-model-provider-denied", attempts, options.now);
}

async function runDnsExfilDenied(
	options: NetworkProbeRunnerOptions,
): Promise<NetworkProbeEvidence> {
	const attempts = [
		firewallSentinelAttempt(options.firewallSentinelPath),
		...(options.dnsExfilUrls.length === 0
			? [configurationAttempt("dnsExfilUrls", "TELCLAUDE_HERMES_NETWORK_DNS_URL")]
			: await Promise.all(
					options.dnsExfilUrls.map((url, index) =>
						attemptDnsGuardDenied(`dns-exfil-${index + 1}`, url, options.timeoutMs),
					),
				)),
	];
	return networkProbeEvidence("network.dns-exfil-denied", attempts, options.now);
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
		const isPositiveDenial = code !== undefined && POSITIVE_DENIAL_ERROR_CODES.has(code);
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
	now = new Date(),
): NetworkProbeEvidence {
	const status = attempts.every((attempt) => attempt.status === "pass") ? "pass" : "fail";
	const passSummary =
		id === "network.relay-control-allowed"
			? `${id} observed expected relay reachability`
			: `${id} observed only expected denials`;
	return {
		schemaVersion: NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION,
		id,
		status,
		ran: true,
		summary:
			status === "pass"
				? passSummary
				: `${id} observed unsafe network reachability or missing proof`,
		generatedAt: now.toISOString(),
		evidence_path: evidencePathFor(id),
		attempts,
	};
}

function pendingNetworkProbeEvidence(
	id: NetworkProbeId,
	evidencePath: string,
	now = new Date(),
): NetworkProbeEvidence {
	return {
		schemaVersion: NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION,
		id,
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

function writeJsonArtifact(filePath: string, value: unknown): void {
	fs.mkdirSync(path.dirname(filePath), { recursive: true });
	const tmpPath = `${filePath}.tmp.${process.pid}`;
	fs.writeFileSync(tmpPath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
	fs.renameSync(tmpPath, filePath);
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
