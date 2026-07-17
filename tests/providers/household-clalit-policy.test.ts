import { describe, expect, it } from "vitest";
import {
	filterHouseholdPhase0ProviderActionCatalog,
	HOUSEHOLD_PHASE0_CLALIT_READ_ACTIONS,
	HOUSEHOLD_PHASE0_CLALIT_WRITE_ACTIONS,
} from "../../src/providers/household-clalit-policy.js";
import type { ProviderActionCatalog } from "../../src/providers/provider-action-catalog.js";

describe("household Phase 0 Clalit policy", () => {
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
