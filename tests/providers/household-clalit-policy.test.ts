import { describe, expect, it } from "vitest";
import {
	assertHouseholdPhase0ProviderActionAllowed,
	filterHouseholdPhase0ProviderActionCatalog,
	HOUSEHOLD_PHASE0_CLALIT_READ_ACTIONS,
	HOUSEHOLD_PHASE0_CLALIT_WRITE_ACTIONS,
} from "../../src/providers/household-clalit-policy.js";
import type { ProviderActionCatalog } from "../../src/providers/provider-action-catalog.js";

describe("household Phase 0 Clalit policy", () => {
	it.each(
		HOUSEHOLD_PHASE0_CLALIT_READ_ACTIONS,
	)("allows list-only household Clalit read %s with empty params", (action) => {
		expect(() =>
			assertHouseholdPhase0ProviderActionAllowed({
				domain: "household",
				service: "clalit",
				action,
				mode: "read",
				params: {},
			}),
		).not.toThrow();
	});

	it.each(
		HOUSEHOLD_PHASE0_CLALIT_READ_ACTIONS,
	)("rejects every param for list-only household Clalit read %s", (action) => {
		expect(() =>
			assertHouseholdPhase0ProviderActionAllowed({
				domain: "household",
				service: "clalit",
				action,
				mode: "read",
				params: { anything: "synthetic" },
			}),
		).toThrowError(new Error("household Phase 0 provider params denied"));
	});

	it("allows only prescriptionId for a household Clalit prescription renewal", () => {
		expect(() =>
			assertHouseholdPhase0ProviderActionAllowed({
				domain: "household",
				service: "clalit",
				action: "prescription_renewal",
				mode: "write",
				params: { prescriptionId: "synthetic-rx" },
			}),
		).not.toThrow();
	});

	it.each([
		{ subjectUserId: "synthetic-subject" },
		{ patientId: "synthetic-patient" },
		{ memberId: "synthetic-member" },
		{ prescriptionId: "synthetic-rx", unexpected: true },
		{ prescriptionId: "synthetic-rx", filter: { subjectId: "synthetic-subject" } },
	])("rejects unexpected household Clalit renewal params with a constant error", (params) => {
		expect(() =>
			assertHouseholdPhase0ProviderActionAllowed({
				domain: "household",
				service: "clalit",
				action: "prescription_renewal",
				mode: "write",
				params,
			}),
		).toThrowError(new Error("household Phase 0 provider params denied"));
	});

	it("keeps the advertised household catalog coherent with the enforcement allowlist", () => {
		const catalog: ProviderActionCatalog = {
			"israel-services": {
				clalit: [
					{ id: "home", write: false },
					{ id: "appointments", write: false },
					{ id: "chronic_meds", write: false },
					{ id: "lab_results", write: false },
					{ id: "prescriptions", write: false },
					{ id: "prescription_renewal", write: true },
					{ id: "appointment_booking", write: true },
				],
				poalim: [{ id: "balance", write: false }],
			},
		};

		const filtered = filterHouseholdPhase0ProviderActionCatalog(catalog);
		expect(filtered).toEqual({
			"israel-services": {
				clalit: [
					{ id: "appointments", write: false },
					{ id: "chronic_meds", write: false },
					{ id: "lab_results", write: false },
					{ id: "prescriptions", write: false },
					{ id: "prescription_renewal", write: true },
				],
			},
		});
		expect(
			filtered["israel-services"]?.clalit
				.filter((action) => !action.write)
				.map((action) => action.id),
		).toEqual([...HOUSEHOLD_PHASE0_CLALIT_READ_ACTIONS]);
		expect(
			filtered["israel-services"]?.clalit
				.filter((action) => action.write)
				.map((action) => action.id),
		).toEqual([...HOUSEHOLD_PHASE0_CLALIT_WRITE_ACTIONS]);
	});
});
