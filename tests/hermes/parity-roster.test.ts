import { describe, expect, it } from "vitest";
import {
	descopedParityRows,
	HERMES_PARITY_ROW_ROSTER,
	type ParityRowBacking,
	parityRosterCoverageGate,
} from "../../src/hermes/parity-roster.js";

const EMPTY = {
	requiredSurfaceIds: [] as string[],
	requiredFixtureIds: [] as string[],
	presentRequiredChecks: [] as string[],
	evaluatedGateNames: [] as string[],
	decisions: [] as ReadonlyArray<{ id: string; status: string }>,
};

const TINY_ROSTER: Record<string, ParityRowBacking> = {
	"by-surface": { surfaces: ["s.one"] },
	"by-fixture": { fixtures: ["f.one"] },
	"by-check": { checks: ["c.one"] },
	"by-gate": { metaGates: ["g.one"] },
};

describe("parityRosterCoverageGate", () => {
	it("passes when every row is backed by a present surface/fixture/check/gate", () => {
		const gate = parityRosterCoverageGate({
			...EMPTY,
			roster: TINY_ROSTER,
			requiredSurfaceIds: ["s.one"],
			requiredFixtureIds: ["f.one"],
			presentRequiredChecks: ["c.one"],
			evaluatedGateNames: ["g.one"],
		});
		expect(gate.status).toBe("pass");
		expect(gate.name).toBe("parity.rosterCovered");
	});

	it("fails and lists exactly the uncovered, non-descoped rows", () => {
		const gate = parityRosterCoverageGate({
			...EMPTY,
			roster: TINY_ROSTER,
			requiredSurfaceIds: ["s.one"], // covers by-surface only
		});
		expect(gate.status).toBe("fail");
		// sorted, comma-joined; by-surface is covered so absent
		expect(gate.detail).toContain("by-check");
		expect(gate.detail).toContain("by-fixture");
		expect(gate.detail).toContain("by-gate");
		expect(gate.detail).not.toContain("by-surface");
	});

	it("treats an accepted parity-descope decision as covering the row", () => {
		const gate = parityRosterCoverageGate({
			...EMPTY,
			roster: { only: { surfaces: ["never.present"] } },
			decisions: [{ id: "parity-descope:only", status: "accepted" }],
		});
		expect(gate.status).toBe("pass");
	});

	it("ignores a parity-descope decision that is not accepted", () => {
		const gate = parityRosterCoverageGate({
			...EMPTY,
			roster: { only: { surfaces: ["never.present"] } },
			decisions: [{ id: "parity-descope:only", status: "unresolved" }],
		});
		expect(gate.status).toBe("fail");
		expect(gate.detail).toContain("only");
	});

	it("does not let an unrelated surface accidentally cover a row", () => {
		const gate = parityRosterCoverageGate({
			...EMPTY,
			roster: { row: { surfaces: ["needed.surface"] } },
			requiredSurfaceIds: ["some.other.surface"],
		});
		expect(gate.status).toBe("fail");
	});

	it("requires ALL mandatory (allOf) backing, not just one", () => {
		const roster = { row: { requiredSurfaces: ["s.a"], requiredFixtures: ["f.b"] } };
		// only the mandatory surface present -> still uncovered (mandatory fixture missing)
		expect(parityRosterCoverageGate({ ...EMPTY, roster, requiredSurfaceIds: ["s.a"] }).status).toBe(
			"fail",
		);
		// both mandatory ids present -> covered
		expect(
			parityRosterCoverageGate({
				...EMPTY,
				roster,
				requiredSurfaceIds: ["s.a"],
				requiredFixtureIds: ["f.b"],
			}).status,
		).toBe("pass");
	});

	it("does not let an anyOf surface cover a row whose mandatory fixture is absent", () => {
		// A supplemental surface present must NOT satisfy a row that also mandates a fixture.
		const roster = {
			row: { surfaces: ["supp.surface"], requiredFixtures: ["proof.fixture"] },
		};
		expect(
			parityRosterCoverageGate({ ...EMPTY, roster, requiredSurfaceIds: ["supp.surface"] }).status,
		).toBe("fail");
	});

	it("fails an empty-backing row instead of passing it unconditionally", () => {
		const gate = parityRosterCoverageGate({ ...EMPTY, roster: { "ghost-row": {} } });
		expect(gate.status).toBe("fail");
		expect(gate.detail).toContain("ghost-row");
	});

	it("refuses to descope a non-descopable row and fails loudly", () => {
		const gate = parityRosterCoverageGate({
			...EMPTY,
			roster: { cutover: { metaGates: ["never.present"] } },
			decisions: [{ id: "parity-descope:cutover", status: "accepted" }],
		});
		expect(gate.status).toBe("fail");
		expect(gate.detail).toContain("non-descopable");
		expect(gate.detail).toContain("cutover");
	});

	it("fails loudly on a descope decision for an unknown row", () => {
		const gate = parityRosterCoverageGate({
			...EMPTY,
			roster: { "real-row": { surfaces: ["s.x"] } },
			requiredSurfaceIds: ["s.x"],
			decisions: [{ id: "parity-descope:bogus-row", status: "accepted" }],
		});
		expect(gate.status).toBe("fail");
		expect(gate.detail).toContain("unknown row");
		expect(gate.detail).toContain("bogus-row");
	});
});

describe("descopedParityRows", () => {
	it("collects only accepted parity-descope ids, trimmed", () => {
		const rows = descopedParityRows([
			{ id: "parity-descope:memory", status: "accepted" },
			{ id: "parity-descope: skills ", status: "accepted" },
			{ id: "parity-descope:chief", status: "unresolved" },
			{ id: "unrelated:thing", status: "accepted" },
		]);
		expect([...rows].sort()).toEqual(["memory", "skills"]);
	});
});

describe("HERMES_PARITY_ROW_ROSTER contract enforcement", () => {
	it("flags the four known proof-gap rows as uncovered when nothing is required", () => {
		// With no surfaces/fixtures declared, the gate must surface exactly the rows
		// whose backing ids do not yet exist in the system (the proof gaps).
		const gate = parityRosterCoverageGate(EMPTY);
		expect(gate.status).toBe("fail");
		for (const row of ["memory", "skills", "chief-of-staff", "identity-migration"]) {
			expect(gate.detail).toContain(row);
		}
	});

	it("keeps identity-migration uncovered when only the read-only surface exists", () => {
		// The identity.migration surface already exists and is required in-tree; without
		// the positive relink fixture the row must still be reported as a proof gap.
		const gate = parityRosterCoverageGate({
			...EMPTY,
			requiredSurfaceIds: ["identity.migration"],
			// fixture.identity.migration.relink intentionally omitted
		});
		expect(gate.status).toBe("fail");
		expect(gate.detail).toContain("identity-migration");
	});

	it("covers every roster row once its backing ids are all declared", () => {
		const surfaces = new Set<string>();
		const fixtures = new Set<string>();
		const checks = new Set<string>();
		const gates = new Set<string>();
		for (const backing of Object.values(HERMES_PARITY_ROW_ROSTER)) {
			for (const s of backing.surfaces ?? []) surfaces.add(s);
			for (const s of backing.requiredSurfaces ?? []) surfaces.add(s);
			for (const f of backing.fixtures ?? []) fixtures.add(f);
			for (const f of backing.requiredFixtures ?? []) fixtures.add(f);
			for (const c of backing.checks ?? []) checks.add(c);
			for (const g of backing.metaGates ?? []) gates.add(g);
		}
		const gate = parityRosterCoverageGate({
			requiredSurfaceIds: [...surfaces],
			requiredFixtureIds: [...fixtures],
			presentRequiredChecks: [...checks],
			evaluatedGateNames: [...gates],
			decisions: [],
		});
		expect(gate.status).toBe("pass");
	});
});
