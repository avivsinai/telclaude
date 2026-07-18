export const DERIVED_MEDIA_ACTION_CLASSIFIER_VERSION = "derived_media_action_classifier_v1";
export const DERIVED_MEDIA_CLASSIFIER_MAX_SCALARS = 8_000;

export type DerivedMediaActionReasonCode =
	| "explicit_action_verb"
	| "provider_request"
	| "imperative_numbered_instruction"
	| "external_instruction"
	| "classifier_fail_closed";

export type DerivedMediaActionClassification = {
	readonly classifierVersion: typeof DERIVED_MEDIA_ACTION_CLASSIFIER_VERSION;
	readonly actionBearing: boolean;
	readonly reasonCodes: readonly DerivedMediaActionReasonCode[];
};

const HEBREW_FINAL_FORMS: Readonly<Record<string, string>> = {
	ך: "כ",
	ם: "מ",
	ן: "נ",
	ף: "פ",
	ץ: "צ",
};

export const ACTION_VERBS_EN_V1 = new Set([
	"approve",
	"book",
	"call",
	"cancel",
	"change",
	"check",
	"delete",
	"download",
	"fetch",
	"open",
	"order",
	"pay",
	"read",
	"reject",
	"remind",
	"renew",
	"schedule",
	"send",
	"set",
	"show",
	"submit",
]);

export const ACTION_VERBS_HE_V1 = new Set(
	[
		"אשר",
		"אשרי",
		"אשרים",
		"אפתח",
		"בטל",
		"בטלי",
		"בטלו",
		"תבטל",
		"תבטלי",
		"בדוק",
		"בדקי",
		"תבדוק",
		"תבדקי",
		"דחה",
		"דחי",
		"תדחה",
		"תדחי",
		"הבא",
		"הביאי",
		"תביא",
		"תביאי",
		"הורד",
		"הורידי",
		"תוריד",
		"תורידי",
		"הזכר",
		"הזכירי",
		"תזכיר",
		"תזכירי",
		"הזמן",
		"הזמיני",
		"תזמנ",
		"תזמני",
		"הגש",
		"הגישי",
		"תגיש",
		"תגישי",
		"הצג",
		"הציגי",
		"תציג",
		"תציגי",
		"התקשר",
		"התקשרי",
		"תתקשר",
		"תתקשרי",
		"חדש",
		"חדשי",
		"תחדש",
		"תחדשי",
		"מחק",
		"מחקי",
		"תמחק",
		"תמחקי",
		"סדר",
		"סדרי",
		"פתח",
		"פתחי",
		"תפתח",
		"תפתחי",
		"קבע",
		"קבעי",
		"תקבע",
		"תקבעי",
		"קרא",
		"קראי",
		"תקרא",
		"תקראי",
		"שלמ",
		"שלמי",
		"תשלמ",
		"תשלמי",
		"שלח",
		"שלחי",
		"תשלח",
		"תשלחי",
		"שנה",
		"שני",
		"תשנה",
		"תשני",
		"תאשר",
		"תאשרי",
	].map(normalizeHebrewFinals),
);

export const ACTION_ENTITIES_V1 = new Set([
	"appointment",
	"clinic",
	"doctor",
	"provider",
	"prescription",
	"reminder",
	"תור",
	"מרפאה",
	"רופא",
	"רופאה",
	"קופה",
	"כללית",
	"ספק",
	"מרשמ",
	"תזכורת",
]);

const REQUEST_MARKERS_V1: readonly (readonly string[])[] = [
	["please"],
	["can", "you"],
	["i", "need"],
	["i", "want"],
	["בבקשה"],
	["אפשר"],
	["את", "יכולה"],
	["אתה", "יכול"],
	["תוכל"],
	["תוכלי"],
	["אני", "צריכ"],
	["אני", "צריכה"],
	["אני", "רוצה"],
];

const EXTERNAL_INSTRUCTION_PATTERNS_V1 = [
	/\b(?:click|reply|send|dial)\b/u,
	/\bignore\s+(?:all\s+)?previous\b/u,
	/\b(?:system|assistant)\s+(?:prompt|instructions?)\b/u,
	/https?:\/\//u,
	/(?:לחצ|השב|עני|חייג|התעלמ\s+(?:מההוראות|מההנחיות)|הוראות\s+(?:קודמות|מערכת)|הנחיות\s+קודמות|פרומפט|מספר\s+הטלפו)/u,
] as const;

export function classifyDerivedMediaActionV1(
	text: string,
	languageHint: string | undefined,
	options: { readonly truncated?: boolean } = {},
): DerivedMediaActionClassification {
	try {
		if (
			options.truncated ||
			(languageHint !== "he" && languageHint !== "en") ||
			Array.from(text).length > DERIVED_MEDIA_CLASSIFIER_MAX_SCALARS ||
			hasInvalidUnicode(text)
		) {
			return failClosed();
		}
		const normalized = normalizeForMatching(text);
		const tokens = normalized.match(/[\p{L}\p{N}]+/gu) ?? [];
		const reasons: DerivedMediaActionReasonCode[] = [];

		const verbSet = languageHint === "he" ? ACTION_VERBS_HE_V1 : ACTION_VERBS_EN_V1;
		if (tokens.some((token) => verbSet.has(token))) reasons.push("explicit_action_verb");
		if (hasProviderRequest(tokens)) reasons.push("provider_request");
		if (hasNumberedImperative(normalized, tokens)) {
			reasons.push("imperative_numbered_instruction");
		}
		if (EXTERNAL_INSTRUCTION_PATTERNS_V1.some((pattern) => pattern.test(normalized))) {
			reasons.push("external_instruction");
		}

		return {
			classifierVersion: DERIVED_MEDIA_ACTION_CLASSIFIER_VERSION,
			actionBearing: reasons.length > 0,
			reasonCodes: reasons,
		};
	} catch {
		return failClosed();
	}
}

function normalizeForMatching(text: string): string {
	return text
		.normalize("NFKC")
		.replace(/\p{Cf}+/gu, "")
		.toLowerCase()
		.replace(/[ךםןףץ]/gu, normalizeHebrewFinals)
		.replace(/\s+/gu, " ")
		.trim();
}

function normalizeHebrewFinals(character: string): string {
	return character.replace(/[ךםןףץ]/gu, (value) => HEBREW_FINAL_FORMS[value] ?? value);
}

function hasProviderRequest(tokens: readonly string[]): boolean {
	const entityIndexes = tokens.flatMap((token, index) =>
		ACTION_ENTITIES_V1.has(token) ? [index] : [],
	);
	if (entityIndexes.length === 0) return false;
	for (const marker of REQUEST_MARKERS_V1) {
		for (let index = 0; index <= tokens.length - marker.length; index += 1) {
			if (!marker.every((token, offset) => tokens[index + offset] === token)) continue;
			const markerEnd = index + marker.length - 1;
			if (entityIndexes.some((entityIndex) => Math.abs(entityIndex - markerEnd) <= 8)) return true;
		}
	}
	return false;
}

function hasNumberedImperative(normalized: string, tokens: readonly string[]): boolean {
	const markerIndex = tokens.findIndex((token) =>
		["step", "instruction", "instructions", "שלב", "הוראה", "הוראות"].includes(token),
	);
	if (markerIndex < 0) return false;
	if (tokens.slice(markerIndex + 1, markerIndex + 5).some((token) => /^\d+$/u.test(token))) {
		return true;
	}
	return /\b\d{1,2}:\d{2}\b/u.test(normalized);
}

function hasInvalidUnicode(text: string): boolean {
	return /[\uD800-\uDFFF]/u.test(text);
}

function failClosed(): DerivedMediaActionClassification {
	return {
		classifierVersion: DERIVED_MEDIA_ACTION_CLASSIFIER_VERSION,
		actionBearing: true,
		reasonCodes: ["classifier_fail_closed"],
	};
}
