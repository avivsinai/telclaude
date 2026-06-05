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

	it("covers every roster row once its backing ids are all declared", () => {
		const surfaces = new Set<string>();
		const fixtures = new Set<string>();
		const checks = new Set<string>();
		const gates = new Set<string>();
		for (const backing of Object.values(HERMES_PARITY_ROW_ROSTER)) {
			for (const s of backing.surfaces ?? []) surfaces.add(s);
			for (const f of backing.fixtures ?? []) fixtures.add(f);
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
