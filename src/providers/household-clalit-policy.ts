import type { TelclaudeMcpDomain } from "../hermes/mcp/bridge.js";
import type { ProviderActionCatalog } from "./provider-action-catalog.js";

export const HOUSEHOLD_PHASE0_CLALIT_READ_ACTIONS = [
	"appointments",
	"chronic_meds",
	"lab_results",
	"prescriptions",
] as const;

// Deferred until the M3 media path and the household data-scope review:
// visit_summaries, referrals, messages, vaccines, imaging, and my_doctors.

export const HOUSEHOLD_PHASE0_CLALIT_WRITE_ACTIONS = ["prescription_renewal"] as const;

const READ_ACTIONS = new Set<string>(HOUSEHOLD_PHASE0_CLALIT_READ_ACTIONS);
const WRITE_ACTIONS = new Set<string>(HOUSEHOLD_PHASE0_CLALIT_WRITE_ACTIONS);
const NO_PARAM_KEYS = new Set<string>();
const ALLOWED_PARAM_KEYS = new Map<string, ReadonlySet<string>>([
	...HOUSEHOLD_PHASE0_CLALIT_READ_ACTIONS.map((action) => [action, NO_PARAM_KEYS] as const),
	["prescription_renewal", new Set(["prescriptionId"])],
]);

export function assertHouseholdPhase0ProviderActionAllowed(input: {
	readonly domain: TelclaudeMcpDomain;
	readonly service: string;
	readonly action: string;
	readonly mode: "read" | "write";
	readonly params: Readonly<Record<string, unknown>>;
}): void {
	if (input.domain !== "household") return;
	const allowed = input.mode === "read" ? READ_ACTIONS : WRITE_ACTIONS;
	if (input.service !== "clalit" || !allowed.has(input.action)) {
		throw new Error("household Phase 0 provider action denied");
	}
	const allowedParamKeys = ALLOWED_PARAM_KEYS.get(input.action);
	if (!allowedParamKeys || Object.keys(input.params).some((key) => !allowedParamKeys.has(key))) {
		throw new Error("household Phase 0 provider params denied");
	}
}

/**
 * Keep the household prompt surface identical to the relay-enforced surface.
 * The provider schema remains authoritative for whether an allowlisted action
 * currently exists; this filter can only remove schema actions, never add one.
 */
export function filterHouseholdPhase0ProviderActionCatalog(
	catalog: ProviderActionCatalog,
): ProviderActionCatalog {
	const filtered: ProviderActionCatalog = {};
	for (const [providerId, services] of Object.entries(catalog)) {
		const clalit = services.clalit?.filter((action) =>
			action.write ? WRITE_ACTIONS.has(action.id) : READ_ACTIONS.has(action.id),
		);
		if (!clalit || clalit.length === 0) continue;
		filtered[providerId] = { clalit };
	}
	return filtered;
}
