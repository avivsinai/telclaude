export const HOUSEHOLD_EMERGENCY_COPY = Object.freeze({
	f: "אם זה מצב חירום רפואי, חייגי עכשיו 101. אני לא שירות חירום ואי אפשר להסתמך עליי במצב חירום.",
	m: "אם זה מצב חירום רפואי, חייג עכשיו 101. אני לא שירות חירום ואי אפשר להסתמך עליי במצב חירום.",
});

export function householdEmergencyCopy(addresseeGender: "f" | "m"): string {
	const copy = HOUSEHOLD_EMERGENCY_COPY[addresseeGender];
	if (!copy) throw new Error("household emergency addressee gender is unavailable");
	return copy;
}
