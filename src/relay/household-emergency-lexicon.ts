export type HouseholdEmergencyClass =
	| "cardiac"
	| "stroke"
	| "breathing"
	| "collapse_or_fall"
	| "bleeding"
	| "suicidal_ideation"
	| "explicit_emergency"
	| "unconscious";

const BIDI_CONTROLS = /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu;
export const HOUSEHOLD_EMERGENCY_LEXICON_VERSION = "household_emergency_lexicon_v1";

const CLASS_PATTERNS: ReadonlyArray<{
	readonly class: HouseholdEmergencyClass;
	readonly patterns: readonly RegExp[];
}> = [
	{
		class: "suicidal_ideation",
		patterns: [
			/\b(?:suicidal|suicide|kill myself|hurt myself|do not want to live|don't want to live)\b/iu,
			/(?:אובדני|לא רוצה לחיות|לפגוע בעצמי|להרוג את עצמי)/u,
		],
	},
	{
		class: "unconscious",
		patterns: [/\b(?:unconscious|unresponsive)\b/iu, /(?:מחוסר(?:ת)? הכרה|לא מגיב(?:ה)?)/u],
	},
	{
		class: "cardiac",
		patterns: [
			/\b(?:chest pain|chest pressure|heart attack|myocardial infarction)\b/iu,
			/(?:כאב(?:ים)? בחזה|לחץ בחזה|התקף לב|אוטם שריר הלב)/u,
		],
	},
	{
		class: "stroke",
		patterns: [
			/\b(?:stroke|slurred speech|one side of (?:my |the )?body|one[- ]sided weakness|half (?:my )?body)\b/iu,
			/(?:שבץ|אירוע מוחי|חצי גוף|דיבור מעורפל)/u,
		],
	},
	{
		class: "breathing",
		patterns: [
			/\b(?:shortness of breath|difficulty breathing|cannot breathe|can't breathe|unable to breathe)\b/iu,
			/(?:קוצר נשימה|קשיי נשימה|לא יכול(?:ה)? לנשום)/u,
		],
	},
	{
		class: "collapse_or_fall",
		patterns: [
			/\b(?:collapsed|fell|fainted|passed out|bad fall)\b/iu,
			/(?:נפלתי|התעלפ(?:תי|ה)?|קרס(?:תי|ה)?)/u,
		],
	},
	{
		class: "bleeding",
		patterns: [
			/\b(?:heavy bleeding|severe bleeding|won't stop bleeding)\b/iu,
			/(?:דימום חזק|דימום כבד|לא מפסיק(?:ה)? לדמם)/u,
		],
	},
	{
		class: "explicit_emergency",
		patterns: [/\b(?:emergency|urgent|help me|call 101)\b/iu, /(?:מקרה חירום|חירום|דחוף|הצילו)/u],
	},
];

const CHEST_NEGATIONS = [
	/\b(?:no|do not have|don't have|not having|without) (?:any )?(?:chest pain|chest pressure)\b/giu,
	/(?:אין לי|בלי) (?:כאב(?:ים)?|לחץ) בחזה/gu,
];
const BREATHING_NEGATIONS = [
	/\b(?:no|do not have|don't have|without) (?:any )?(?:shortness of breath|difficulty breathing)\b/giu,
	/(?:אין לי|בלי) (?:קוצר נשימה|קשיי נשימה)/gu,
];

export function normalizeHouseholdEmergencyText(value: string): string {
	return value
		.normalize("NFKC")
		.replace(BIDI_CONTROLS, "")
		.toLowerCase()
		.replace(/\s+/gu, " ")
		.trim();
}

export function matchHouseholdEmergencyLexicon(value: string): readonly HouseholdEmergencyClass[] {
	const normalized = normalizeHouseholdEmergencyText(value);
	if (!normalized) return [];
	return CLASS_PATTERNS.filter((entry) => {
		const candidate =
			entry.class === "cardiac"
				? stripPhrases(normalized, CHEST_NEGATIONS)
				: entry.class === "breathing"
					? stripPhrases(normalized, BREATHING_NEGATIONS)
					: normalized;
		return entry.patterns.some((pattern) => pattern.test(candidate));
	}).map((entry) => entry.class);
}

export function containsUrgentHealthSignalV1(value: string): boolean {
	try {
		const normalized = normalizeHouseholdEmergencyText(value);
		return CLASS_PATTERNS.some((entry) =>
			entry.patterns.some((pattern) => pattern.test(normalized)),
		);
	} catch {
		return false;
	}
}

export const containsUrgentHealthSignal = containsUrgentHealthSignalV1;

function stripPhrases(value: string, phrases: readonly RegExp[]): string {
	return phrases.reduce((remaining, phrase) => remaining.replace(phrase, " "), value);
}
