import { redactSecrets, type SecretPattern } from "./output-filter.js";

const HOUSEHOLD_PHONE_PATTERN = {
	name: "israeli_phone",
	pattern:
		/(?<![0-9])(?:\+972[ .-]?(?:5[0-9]|[23489])|0(?:5[0-9]|[23489]))[ .-]?(?:[0-9][ .-]?){6}[0-9](?![0-9])/g,
	severity: "high",
	description: "Israeli phone number in a household display sink",
	redactMatchCompletely: true,
} satisfies SecretPattern;

/** Household-only display redaction boundary; never added to global CORE filtering. */
export function redactHouseholdSinkText(text: string): string {
	const result = redactSecrets(text);
	HOUSEHOLD_PHONE_PATTERN.pattern.lastIndex = 0;
	return result.replace(
		HOUSEHOLD_PHONE_PATTERN.pattern,
		`[REDACTED:${HOUSEHOLD_PHONE_PATTERN.name}]`,
	);
}
