import {
	type HouseholdEmergencyClass,
	matchHouseholdEmergencyLexicon,
} from "./household-emergency-lexicon.js";

export type HouseholdEmergencyClassification =
	| { readonly emergency: false; readonly class: null; readonly reasonCodes: readonly [] }
	| {
			readonly emergency: true;
			readonly class: HouseholdEmergencyClass;
			readonly reasonCodes: readonly string[];
	  };

export const HOUSEHOLD_EMERGENCY_CLASSIFIER_VERSION = "household_emergency_classifier_v1";

export function classifyHouseholdEmergencyV1(
	text: string | undefined,
	_languageHint?: string,
): HouseholdEmergencyClassification {
	try {
		if (typeof text !== "string" || text.length === 0 || text.length > 8_192) {
			return { emergency: false, class: null, reasonCodes: [] };
		}
		const classes = matchHouseholdEmergencyLexicon(text);
		const primary = classes[0];
		return primary
			? {
					emergency: true,
					class: primary,
					reasonCodes: classes,
				}
			: { emergency: false, class: null, reasonCodes: [] };
	} catch {
		return { emergency: false, class: null, reasonCodes: [] };
	}
}
