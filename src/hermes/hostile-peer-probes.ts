export const HOSTILE_PEER_PROBE_SCHEMA_VERSION = "telclaude.hermes.hostile-peer.v1";
export const HOSTILE_PEER_PROBE_ID = "runtime.hostile-peer";
export const HOSTILE_PEER_PROBE_SOURCE = "telclaude-hostile-contained-peer-harness";
export const DEFAULT_HOSTILE_PEER_EVIDENCE_PATH =
	"artifacts/hermes/probes/runtime-hostile-peer.json";

export const HOSTILE_PEER_REQUIRED_CHECKS = [
	"hostile-peer.live-mcp-auth",
	"hostile-peer.model-proxy-token-isolation",
	"hostile-peer.relay-internal-surface-inventory",
	"hostile-peer.token-abuse-canary",
	"hostile-peer.runtime-self-modification-canary",
] as const;

export type HostilePeerProbeCheckName = (typeof HOSTILE_PEER_REQUIRED_CHECKS)[number];

export type HostilePeerProbeCheck = {
	readonly name: HostilePeerProbeCheckName;
	readonly status: "pass" | "fail";
	readonly detail: string;
	readonly evidence?: unknown;
};

export type HostilePeerProbeObservation = Omit<HostilePeerProbeCheck, "name">;

export type HostilePeerProbeRunner = {
	readonly [K in HostilePeerProbeCheckName]: () => Promise<HostilePeerProbeObservation>;
};

export type HostilePeerProbeEvidence = {
	readonly schemaVersion: typeof HOSTILE_PEER_PROBE_SCHEMA_VERSION;
	readonly probeId: typeof HOSTILE_PEER_PROBE_ID;
	readonly status: "pass" | "fail";
	readonly ran: boolean;
	readonly observedAt: string;
	readonly source: typeof HOSTILE_PEER_PROBE_SOURCE;
	readonly summary: string;
	readonly checks: readonly HostilePeerProbeCheck[];
};

export async function runHermesHostilePeerProbe(input: {
	readonly allowRun: boolean;
	readonly runner?: HostilePeerProbeRunner;
	readonly observedAt?: string;
}): Promise<HostilePeerProbeEvidence> {
	const observedAt = input.observedAt ?? new Date().toISOString();
	if (input.allowRun !== true) {
		return buildEvidence({
			ran: false,
			observedAt,
			checks: HOSTILE_PEER_REQUIRED_CHECKS.map((name) =>
				failCheck(name, "run with --allow-run and a live contained-peer runner"),
			),
		});
	}
	if (!input.runner) {
		return buildEvidence({
			ran: false,
			observedAt,
			checks: HOSTILE_PEER_REQUIRED_CHECKS.map((name) =>
				failCheck(name, "no live hostile-peer runner was configured"),
			),
		});
	}

	const checks: HostilePeerProbeCheck[] = [];
	for (const name of HOSTILE_PEER_REQUIRED_CHECKS) {
		try {
			const observation = await input.runner[name]();
			checks.push({
				name,
				status: observation.status,
				detail: observation.detail,
				...(observation.evidence !== undefined ? { evidence: observation.evidence } : {}),
			});
		} catch (error) {
			checks.push(failCheck(name, `hostile-peer check threw: ${errorMessage(error)}`));
		}
	}
	return buildEvidence({ ran: true, observedAt, checks });
}

export function hostilePeerProbeEvidenceFailure(
	surfaceId: string,
	evidence: unknown,
): string | null {
	if (surfaceId !== HOSTILE_PEER_PROBE_ID) {
		return `unsupported hostile-peer surface ${surfaceId}`;
	}
	const failures: string[] = [];
	if (!isRecord(evidence)) return "hostile-peer evidence is not an object";
	if (evidence.schemaVersion !== HOSTILE_PEER_PROBE_SCHEMA_VERSION) {
		failures.push(`schemaVersion is ${String(evidence.schemaVersion)}`);
	}
	if (evidence.probeId !== HOSTILE_PEER_PROBE_ID) {
		failures.push(`probeId is ${String(evidence.probeId)}`);
	}
	if (evidence.status !== "pass") failures.push(`status is ${String(evidence.status)}`);
	if (evidence.ran !== true) failures.push("harness did not run");
	if (evidence.source !== HOSTILE_PEER_PROBE_SOURCE) {
		failures.push(`source is ${String(evidence.source)}`);
	}

	const checks = Array.isArray(evidence.checks) ? evidence.checks : [];
	const checkNames = checks
		.map((check) => (isRecord(check) && typeof check.name === "string" ? check.name : ""))
		.filter((name) => name.length > 0);
	for (const duplicate of duplicates(checkNames)) {
		failures.push(`duplicate check ${duplicate}`);
	}
	const checksByName = new Map(
		checks
			.filter(isRecord)
			.map((check) => [
				typeof check.name === "string" ? check.name : "",
				check as Record<string, unknown>,
			]),
	);
	for (const name of HOSTILE_PEER_REQUIRED_CHECKS) {
		const check = checksByName.get(name);
		if (!check) {
			failures.push(`check ${name} is missing`);
		} else if (check.status !== "pass") {
			failures.push(`check ${name} is ${String(check.status)}`);
		}
	}
	return failures.length > 0 ? failures.join("; ") : null;
}

function buildEvidence(input: {
	readonly ran: boolean;
	readonly observedAt: string;
	readonly checks: readonly HostilePeerProbeCheck[];
}): HostilePeerProbeEvidence {
	const status = input.checks.every((check) => check.status === "pass") ? "pass" : "fail";
	return {
		schemaVersion: HOSTILE_PEER_PROBE_SCHEMA_VERSION,
		probeId: HOSTILE_PEER_PROBE_ID,
		status,
		ran: input.ran,
		observedAt: input.observedAt,
		source: HOSTILE_PEER_PROBE_SOURCE,
		summary:
			status === "pass"
				? "hostile contained-peer boundary checks passed"
				: "hostile contained-peer boundary checks failed",
		checks: input.checks,
	};
}

function failCheck(name: HostilePeerProbeCheckName, detail: string): HostilePeerProbeCheck {
	return { name, status: "fail", detail };
}

function duplicates(values: readonly string[]): string[] {
	const seen = new Set<string>();
	const repeated = new Set<string>();
	for (const value of values) {
		if (seen.has(value)) repeated.add(value);
		seen.add(value);
	}
	return [...repeated].sort();
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}
