// Parity-roster cross-check gate.
//
// The Hermes wrapper spec requires: "Every row of the Complete Parity Matrix
// needs a fixture, expected output, and acceptance proof before cutover."
// `evaluateCutoverCheck` only requires the surfaces/fixtures the scope manifest's
// included workflows happen to declare, so a parity row with no backing surface
// or fixture is never required and cutover can go green without it.
//
// This module turns that prose rule into an enforceable gate: every canonical
// parity row must be backed by a required surface, a required fixture, a present
// required-check, or an evaluated meta-gate — or be explicitly descoped via an
// accepted decision-log entry with id `parity-descope:<row>`. The gate ADDS a
// coverage requirement; it never loosens any existing validator.

export type ParityRowBacking = {
	// "anyOf" backing — when any anyOf kind is declared, the row needs at least one
	// of those backing ids present. A surface here is supplemental evidence, not the
	// acceptance proof.
	/** Feature-probe surface ids; satisfied if any is in requiredSurfaceIds. */
	readonly surfaces?: readonly string[];
	/** Fixture ids; satisfied if any is in requiredFixtureIds. */
	readonly fixtures?: readonly string[];
	/** Required-check names; satisfied if any is in the present required-check set. */
	readonly checks?: readonly string[];
	/** Cutover meta-gate names; satisfied if any is an evaluated gate. */
	readonly metaGates?: readonly string[];
	// "allOf" mandatory backing — EVERY id here must be present for the row to be
	// covered, regardless of anyOf. Use for rows whose acceptance proof is a specific
	// fixture (and/or surface) that must exist, not merely a supplemental one. This is
	// what stops a row from being falsely covered by an adjacent surface while its
	// real proof fixture is still missing (e.g. identity-migration's positive relink
	// fixture: the read-only identity.migration surface already exists and must NOT
	// cover the row on its own).
	readonly requiredSurfaces?: readonly string[];
	readonly requiredFixtures?: readonly string[];
};

/**
 * Canonical roster: every Complete Parity Matrix row mapped to its backing
 * surface(s)/fixture(s)/check(s)/meta-gate(s). Verified against the feature-probe
 * matrix and cutover gates. Rows whose backing ids do not yet exist (memory,
 * skills, chief-of-staff, the positive identity-migration fixture) intentionally
 * fail the gate until they are built or explicitly descoped.
 */
export const HERMES_PARITY_ROW_ROSTER: Readonly<Record<string, ParityRowBacking>> = {
	"private-chat": {
		requiredSurfaces: ["execution.cli_headless"],
		requiredFixtures: ["fixture.private.telegram.basic"],
	},
	"approvals-cards": { fixtures: ["fixture.private.telegram.basic"] },
	providers: {
		surfaces: ["providers.release-policy", "served_mcp.provider-tools", "sideeffect.ledger"],
	},
	banking: { surfaces: ["providers.bank"] },
	"clalit-health": { surfaces: ["providers.clalit"] },
	"government-identity": { surfaces: ["providers.government"] },
	"google-provider": {
		requiredSurfaces: ["providers.google"],
		requiredFixtures: ["fixture.providers.google.approved-write"],
	},
	"approval-tokens": {
		// The write-token binding (actor/content-hash/idempotency) is the acceptance
		// proof and is mandatory; the MCP approval round-trip is supplemental.
		requiredSurfaces: ["providers.approval-binding"],
		surfaces: ["execution.approval_continuation"],
	},
	memory: { surfaces: ["served_mcp.memory"] },
	skills: { surfaces: ["skills.allowlist"] },
	"social-public": { surfaces: ["edge.social", "public.social.isolation"] },
	whatsapp: { surfaces: ["edge.whatsapp", "outbound.policy"] },
	"household-whatsapp": { surfaces: ["edge.whatsapp", "household.scopes"] },
	email: { surfaces: ["edge.email", "outbound.policy"] },
	"household-email": { surfaces: ["edge.email", "household.scopes"] },
	agentmail: { surfaces: ["edge.agentmail"] },
	"identity-migration": {
		requiredSurfaces: ["identity.migration"],
		requiredFixtures: ["fixture.identity.migration.relink"],
	},
	"edge-adapters": {
		surfaces: [
			"edge.whatsapp",
			"edge.email",
			"edge.social",
			"outbound.policy",
			"attachment.quarantine",
		],
	},
	"model-provider-relay": { surfaces: ["model.relay"] },
	cron: {
		requiredSurfaces: ["workflow.cron"],
		requiredFixtures: ["fixture.cron.background.delivery"],
	},
	"long-lived-workflows": {
		requiredSurfaces: ["workflow.longrun"],
		requiredFixtures: ["fixture.longrun.approval-resume"],
	},
	"chief-of-staff": { requiredFixtures: ["fixture.profile.chief-of-staff"] },
	"browser-web-computer": {
		requiredSurfaces: ["browser.profiles", "computer.broker"],
	},
	"web-browser-broker": {
		requiredSurfaces: ["network.egress-broker"],
	},
	redaction: { checks: ["redaction.secret_outputs"] },
	cutover: {
		metaGates: [
			"workflow.scope",
			"decisions.resolved",
			"nofork.clean",
			"networkProbes.pass",
			"queues.owned",
			"rollback.rehearsed",
		],
	},
};

/** Prefix that marks an accepted decision-log entry as descoping a parity row. */
export const PARITY_ROW_DESCOPE_ID_PREFIX = "parity-descope:";

/**
 * Security-critical rows that may NEVER be descoped, regardless of any accepted
 * decision-log entry. An attempt to descope one of these (or a row that is not in
 * the active roster at all) fails the gate loudly rather than silently dropping it.
 */
export const NON_DESCOPABLE_PARITY_ROWS: ReadonlySet<string> = new Set([
	"cutover",
	"redaction",
	"private-chat",
	"approval-tokens",
	"identity-migration",
	// Air-gap (invariant #1) and skill-allowlist (invariant #9): now backed by signed
	// runner attestations plus off-domain-origin and client-source-rejection proofs,
	// so production cutover must require them instead of allowing a silent descope.
	"memory",
	"skills",
]);

export type ParityRosterGateInput = {
	readonly requiredSurfaceIds: Iterable<string>;
	readonly requiredFixtureIds: Iterable<string>;
	/** Required-check names present across collected probe evidence. */
	readonly presentRequiredChecks: Iterable<string>;
	/** Names of gates already evaluated in this cutover report. */
	readonly evaluatedGateNames: Iterable<string>;
	/** Decision-log entries; accepted `parity-descope:<row>` ids descope a row. */
	readonly decisions: ReadonlyArray<{ readonly id: string; readonly status: string }>;
	/** Override roster (defaults to HERMES_PARITY_ROW_ROSTER); for testing. */
	readonly roster?: Readonly<Record<string, ParityRowBacking>>;
};

export type ParityRosterGate = {
	readonly name: "parity.rosterCovered";
	readonly status: "pass" | "fail";
	readonly detail: string;
};

/** Parity rows explicitly descoped via accepted `parity-descope:<row>` decisions. */
export function descopedParityRows(
	decisions: ReadonlyArray<{ readonly id: string; readonly status: string }>,
): Set<string> {
	const rows = new Set<string>();
	for (const decision of decisions) {
		if (decision.status !== "accepted") continue;
		if (!decision.id.startsWith(PARITY_ROW_DESCOPE_ID_PREFIX)) continue;
		const row = decision.id.slice(PARITY_ROW_DESCOPE_ID_PREFIX.length).trim();
		if (row) rows.add(row);
	}
	return rows;
}

function isRowCovered(
	backing: ParityRowBacking,
	required: {
		surfaces: Set<string>;
		fixtures: Set<string>;
		checks: Set<string>;
		gates: Set<string>;
	},
): boolean {
	// allOf: every mandatory backing id must be present (acceptance proofs).
	const allRequiredPresent =
		(backing.requiredSurfaces ?? []).every((s) => required.surfaces.has(s)) &&
		(backing.requiredFixtures ?? []).every((f) => required.fixtures.has(f));
	if (!allRequiredPresent) return false;

	// anyOf: when any supplemental backing kind is declared, at least one must be present.
	const hasAnyOf =
		(backing.surfaces?.length ?? 0) +
			(backing.fixtures?.length ?? 0) +
			(backing.checks?.length ?? 0) +
			(backing.metaGates?.length ?? 0) >
		0;
	const hasAllOf =
		(backing.requiredSurfaces?.length ?? 0) + (backing.requiredFixtures?.length ?? 0) > 0;
	// A row with no backing of ANY kind must never be reported covered — otherwise an
	// empty `{}` backing would pass with zero evidence (fail-open).
	if (!hasAnyOf && !hasAllOf) return false;
	// allOf-only row: allRequiredPresent already held above.
	if (!hasAnyOf) return true;
	return (
		(backing.surfaces ?? []).some((s) => required.surfaces.has(s)) ||
		(backing.fixtures ?? []).some((f) => required.fixtures.has(f)) ||
		(backing.checks ?? []).some((c) => required.checks.has(c)) ||
		(backing.metaGates ?? []).some((g) => required.gates.has(g))
	);
}

/**
 * Evaluate the parity-roster coverage gate. A row passes if any of its backing
 * surfaces/fixtures/checks/meta-gates is present, or it is explicitly descoped.
 * Fails (listing the offending rows) when a non-descoped row has no backing.
 */
export function parityRosterCoverageGate(input: ParityRosterGateInput): ParityRosterGate {
	const roster = input.roster ?? HERMES_PARITY_ROW_ROSTER;
	const required = {
		surfaces: new Set(input.requiredSurfaceIds),
		fixtures: new Set(input.requiredFixtureIds),
		checks: new Set(input.presentRequiredChecks),
		gates: new Set(input.evaluatedGateNames),
	};
	const descoped = descopedParityRows(input.decisions);

	// A descope is only honored for a known, descopable row. Descoping a
	// security-critical row, or a row that is not in the active roster, is an
	// illegal descope and fails the gate loudly (never a silent drop).
	const illegalDescopes: string[] = [];
	for (const row of descoped) {
		if (NON_DESCOPABLE_PARITY_ROWS.has(row)) illegalDescopes.push(`${row} (non-descopable)`);
		else if (!(row in roster)) illegalDescopes.push(`${row} (unknown row)`);
	}
	illegalDescopes.sort();

	// Categorize every row: backed (proof present), descoped (accepted decision),
	// or missing (neither) — so a failure is actionable.
	const backedRows: string[] = [];
	const descopedRows: string[] = [];
	const missingRows: string[] = [];
	for (const [row, backing] of Object.entries(roster)) {
		// Honor a descope only for a known, descopable row.
		if (descoped.has(row) && !NON_DESCOPABLE_PARITY_ROWS.has(row)) {
			descopedRows.push(row);
			continue;
		}
		if (isRowCovered(backing, required)) backedRows.push(row);
		else missingRows.push(row);
	}
	backedRows.sort();
	descopedRows.sort();
	missingRows.sort();

	const ok = illegalDescopes.length === 0 && missingRows.length === 0;
	const detail = ok
		? `every spec parity row is backed (${backedRows.length}) or descoped (${descopedRows.length}): proof OR accepted parity-descope decision`
		: [
				`backed: ${backedRows.length}`,
				`descoped: ${descopedRows.length === 0 ? "none" : descopedRows.join(", ")}`,
				...(missingRows.length > 0
					? [`MISSING (no proof, not descoped): ${missingRows.join(", ")}`]
					: []),
				...(illegalDescopes.length > 0
					? [`ILLEGAL descope attempts: ${illegalDescopes.join(", ")}`]
					: []),
			].join("; ");
	return { name: "parity.rosterCovered", status: ok ? "pass" : "fail", detail };
}
